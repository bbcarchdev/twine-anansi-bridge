/* Support for Anansi S3/RADOS caches
 *
 * Author: Mo McRoberts <mo.mcroberts@bbc.co.uk>
 *
 * Copyright (c) 2014-2016 BBC
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "p_anansi-plugin.h"

static AWSS3BUCKET *get_bucket(const char *name);
static AWSS3BUCKET *add_bucket(struct bucketinfo_struct *info, const char *name);

static int urldecode(char *dest, const char *src, size_t len);
static size_t ingest_write(char *ptr, size_t size, size_t nemb, void *userdata);

static struct bucketinfo_struct bucketinfo[8];
static size_t maxbuckets = 8;

int
anansi_s3_init(struct anansi_context_struct *context, URI_INFO *info)
{
	char *p;
	const char *t;
	
	if(!info->host)
	{
		twine_logf(LOG_CRIT, PLUGIN_NAME ": S3 cache URI does not include a bucket name\n");
		return -1;
	}
	if(info->query)
	{
		twine_logf(LOG_WARNING, PLUGIN_NAME ": configured S3 cache URI includes a query-string which will be ignored\n");
	}
	if(info->fragment)
	{
		twine_logf(LOG_WARNING, PLUGIN_NAME ": configured S3 cache URI includes a fragment which will be ignored\n");
	}
	context->bucket = anansi_s3_bucket_create(context, info);
	if(!context->bucket)
	{
		return -1;
	}
	if(info->path)
	{
		aws_s3_set_basepath(context->bucket, info->path);
		twine_logf(LOG_NOTICE, PLUGIN_NAME ": cache URI is <s3://%s%s>\n", info->host, info->path);
	}
	else
	{
		twine_logf(LOG_NOTICE, PLUGIN_NAME ": cache URI is <s3://%s/>\n", info->host);
	}
	return 0;
}

/* Fetch an object from either an explicit <s3://...> URI, or from an
 * <anansi:///...> URI where we already know that the configured cache URI is
 * on S3.
 */
TWINEGRAPH *
anansi_s3_fetch(struct anansi_context_struct *context, const char *uristr, URI_INFO *info)
{
	AWSS3BUCKET *bucket;
	TWINEGRAPH *graph;
	json_t *dict, *loc, *headers;
	const char *location;
	int r;
	
	if(!info->host || !info->path)
	{
		twine_logf(LOG_ERR, PLUGIN_NAME ": <%s> is not a valid S3 resource URL\n", uristr);
		return NULL;
	}
	dict = NULL;
	if(!strcasecmp(info->scheme, "s3"))
	{
		bucket = anansi_s3_bucket(context, info);
		if(!bucket)
		{
			twine_logf(LOG_ERR, PLUGIN_NAME ": failed to obtain S3 bucket object for <%s>\n", uristr);
			return NULL;
		}
	}
	else
	{
		bucket = context->bucket;
	}
	r = anansi_s3_ingest_info_bucket(context, bucket, info->path, &dict);
	if(r || !dict || json_typeof(dict) != JSON_OBJECT)
	{
		twine_logf(LOG_ERR, PLUGIN_NAME ": failed to fetch cache information for <%s>\n", uristr);
		if(dict)
		{
			json_decref(dict);
		}
		return NULL;
	}
	location = NULL;
	loc = json_object_get(dict, "content_location");
	if(loc)
	{
		location = json_string_value(loc);
	}
	if(!loc || !location)
	{
		twine_logf(LOG_ERR, PLUGIN_NAME ": object has no Content-Location\n");
		json_decref(dict);
		return NULL;
	}
	graph = twine_graph_create(context->twine, location);
	if(!graph)
	{
		twine_logf(LOG_CRIT, PLUGIN_NAME ": failed to create new Twine graph object\n");
		json_decref(dict);
		return NULL;
	}
	r = anansi_s3_ingest_payload_bucket(context, graph, bucket, info->path, location);
	if(r)
	{
		twine_logf(LOG_ERR, PLUGIN_NAME ": failed to ingest payload for <%s>\n", uristr);
		twine_graph_destroy(graph);
		json_decref(dict);
		return NULL;
	}
	headers = json_object_get(dict, "headers");
	if(headers && json_typeof(headers) == JSON_OBJECT)
	{
		if(anansi_handler_process_headers(context, graph, headers, location))
		{
			twine_logf(LOG_ERR, PLUGIN_NAME ": failed to process headers\n");
			twine_graph_destroy(graph);
			json_decref(dict);
			return NULL;
		}
	}
	json_decref(dict);
	return graph;
}

/* Create a new AWSS3BUCKET without adding it to the bucket MRU list */
AWSS3BUCKET *
anansi_s3_bucket_create(struct anansi_context_struct *context, URI_INFO *info)
{
	AWSS3BUCKET *bucket;
	const char *t;
	char *p;

	bucket = aws_s3_create(info->host);
	if(!bucket)
	{
		twine_logf(LOG_CRIT, PLUGIN_NAME ": failed to create bucket object for <s3://%s>\n", info->host);
		return NULL;
	}
	if(context->s3endpoint)
	{
		aws_s3_set_endpoint(bucket, context->s3endpoint);
	}
	if(info->auth)
	{
		t = strchr(info->auth, ':');
		if(t)
		{
			p = (char *) calloc(1, t - info->auth + 1);
			if(!p)
			{
				aws_s3_destroy(bucket);
				return NULL;
			}
			urldecode(p, info->auth, t - info->auth);
			p[t - info->auth] = 0;
			aws_s3_set_access(bucket, p);
			free(p);
			t++;
			p = (char *) calloc(1, strlen(t) + 1);
			if(!p)
			{
				aws_s3_destroy(bucket);
				return NULL;
			}
			urldecode(p, t, strlen(t));
			aws_s3_set_secret(bucket, p);
			free(p);
		}
	}
	else
	{
		if(context->s3access)
		{
			aws_s3_set_access(bucket, context->s3access);
		}
		if(context->s3secret)
		{
			aws_s3_set_access(bucket, context->s3secret);
		}
	}
	return bucket;
}

/* Create or locate an AWSS3BUCKET object for the supplied URI */
AWSS3BUCKET *
anansi_s3_bucket(struct anansi_context_struct *context, URI_INFO *info)
{
	size_t c;
	
	for(c = 0; c < maxbuckets; c++)
	{
		if(bucketinfo[c].name && !strcasecmp(bucketinfo[c].name, info->host))
		{
			return bucketinfo[c].bucket;
		}
	}
	for(c = 0; c < maxbuckets; c++)
	{
		if(!bucketinfo[c].name)
		{
			return anansi_s3_bucket_add(context, &(bucketinfo[c]), info);
		}
	}
	/* Recycle the oldest entry */
	free(bucketinfo[0].name);
	aws_s3_destroy(bucketinfo[0].bucket);
	memmove(&(bucketinfo[0]), &(bucketinfo[1]), sizeof(struct bucketinfo_struct) * maxbuckets - 1);
	return anansi_s3_bucket_add(context, &(bucketinfo[maxbuckets - 1]), info);
}

/* Create a new AWSS3BUCKET, populate a bucketinfo_struct with the information,
 * and return it.
 */
AWSS3BUCKET *
anansi_s3_bucket_add(struct anansi_context_struct *context, struct bucketinfo_struct *bucketinfo, URI_INFO *info)
{
	char *t;

	memset(bucketinfo, 0, sizeof(struct bucketinfo_struct));
	bucketinfo->name = strdup(info->host);
	if(!bucketinfo->name)
	{
		return NULL;
	}
	bucketinfo->bucket = anansi_s3_bucket_create(context, info);
	if(!bucketinfo->bucket)
	{
		free(bucketinfo->name);
		bucketinfo->name = NULL;
		return NULL;
	}
	return bucketinfo->bucket;
}

int
anansi_s3_ingest_info_bucket(struct anansi_context_struct *context, AWSS3BUCKET *bucket, const char *resource, json_t **dict)
{
	AWSREQUEST *req;
	CURL *ch;
	struct ingestinfo_struct info;
	long status;
	int r;
	char *urlbuf;
	json_error_t err;
	
	(void) context;
	
	r = 0;
	urlbuf = (char *) malloc(strlen(resource) + 6);
	if(!urlbuf)
	{
		return -1;
	}
	strcpy(urlbuf, resource);
	strcat(urlbuf, ".json");
	memset(&info, 0, sizeof(struct ingestinfo_struct));
	req = aws_s3_request_create(bucket, urlbuf, "GET");
	free(urlbuf);
	ch = aws_request_curl(req);
	curl_easy_setopt(ch, CURLOPT_WRITEFUNCTION, ingest_write);
	curl_easy_setopt(ch, CURLOPT_WRITEDATA, (void *) &info);
	curl_easy_setopt(ch, CURLOPT_VERBOSE, context->s3verbose);
	if(aws_request_perform(req) || !info.buf)
	{
		twine_logf(LOG_ERR, PLUGIN_NAME ": failed to request resource '%s'\n", resource);
		free(info.buf);
		aws_request_destroy(req);
		return -1;
	}
	status = 0;
	curl_easy_getinfo(ch, CURLINFO_RESPONSE_CODE, &status);
	if(status != 200)
	{
		twine_logf(LOG_ERR, PLUGIN_NAME ": failed to request resource '%s' with status %ld\n", resource, status);
		free(info.buf);
		aws_request_destroy(req);
		return -1;
	}
	*dict = json_loads(info.buf, 0, &err);
	if(!*dict)
	{
		twine_logf(LOG_ERR, PLUGIN_NAME ": failed to parse '%s.json': %s at (%d, %d)\n", resource, err.text, err.line, err.column);
		r = -1;
	}
	else if(json_typeof(*dict) != JSON_OBJECT)
	{
		twine_logf(LOG_ERR, PLUGIN_NAME ": '%s.json': not a JSON object\n", resource);
		json_decref(*dict);
		r = -1;
	}
	free(info.buf);
	aws_request_destroy(req);
	return r;
}

int
anansi_s3_ingest_payload_bucket(struct anansi_context_struct *context, TWINEGRAPH *graph, AWSS3BUCKET *bucket, const char *resource, const char *location)
{
	AWSREQUEST *req;
	CURL *ch;
	struct ingestinfo_struct info;
	long status;
	int r;
	char *type;

	memset(&info, 0, sizeof(struct ingestinfo_struct));
	req = aws_s3_request_create(bucket, resource, "GET");
	ch = aws_request_curl(req);
	curl_easy_setopt(ch, CURLOPT_WRITEFUNCTION, ingest_write);
	curl_easy_setopt(ch, CURLOPT_WRITEDATA, (void *) &info);
	curl_easy_setopt(ch, CURLOPT_VERBOSE, context->s3verbose);
	if(aws_request_perform(req) || !info.buf)
	{
		twine_logf(LOG_ERR, PLUGIN_NAME ": failed to request resource '%s'\n", resource);
		free(info.buf);
		aws_request_destroy(req);
		return -1;
	}
	status = 0;
	curl_easy_getinfo(ch, CURLINFO_RESPONSE_CODE, &status);
	if(status != 200)
	{
		twine_logf(LOG_ERR, PLUGIN_NAME ": failed to request resource '%s' with status %ld\n", resource, status);
		free(info.buf);
		aws_request_destroy(req);
		return -1;
	}
	type = NULL;
	curl_easy_getinfo(ch, CURLINFO_CONTENT_TYPE, &type);
	if(!type)
	{
		twine_logf(LOG_ERR, PLUGIN_NAME ": failed to request resource '%s': no Content-Type in response\n", resource, status);
		free(info.buf);
		aws_request_destroy(req);
		return -1;
	}
	r = anansi_handler_process_payload(context, graph, info.buf, info.pos, type, location);
	free(info.buf);
	aws_request_destroy(req);
	return r;
}

static size_t
ingest_write(char *ptr, size_t size, size_t nemb, void *userdata)
{
	struct ingestinfo_struct *info;
	char *p;

	info = (struct ingestinfo_struct *) userdata;
	
	size *= nemb;
	if(size >= (info->size - info->pos))
	{
		p = (char *) realloc(info->buf, info->size + size + 1);
		if(!p)
		{
			twine_logf(LOG_CRIT, PLUGIN_NAME ": failed to reallocate buffer to %lu bytes\n", (unsigned long) (info->size + size + 1));
			return 0;
		}
		info->buf = p;
		info->size += size;
	}
	memcpy(&(info->buf[info->pos]), ptr, size);
	info->pos += size;
	info->buf[info->pos] = 0;
	return size;
}

static int
urldecode(char *dest, const char *src, size_t len)
{
	long l;
	char hbuf[3];

	while(*src && len)
	{
		if(*src == '%' && len >= 3 && isxdigit(src[1]) && isxdigit(src[2]))
		{			
			hbuf[0] = src[1];
			hbuf[1] = src[2];
			hbuf[2] = 0;
			l = strtol(hbuf, NULL, 16);
			*dest = (char) ((unsigned char) l);
			dest++;
			src += 3;
			len -= 3;
		}
		else
		{
			*dest = *src;
			dest++;
			src++;
			len--;
		}
	}
	return 0;
}
