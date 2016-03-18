/* Support for Anansi local disk caches
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

int
anansi_file_init(struct anansi_context_struct *context, URI_INFO *info)
{
	char *p;
	
	if(!info->path || !info->path[0])
	{
		twine_logf(LOG_CRIT, PLUGIN_NAME ": configured file: cache URI does not include a path\n");
		return -1;
	}
	if(info->host && info->host[0])
	{
		twine_logf(LOG_WARNING, PLUGIN_NAME ": configured file: cache URI includes a hostname which will be ignored\n");
	}
	if(info->query && info->query[0])
	{
		twine_logf(LOG_WARNING, PLUGIN_NAME ": configured file: cache URI includes a query-string which will be ignored\n");
	}
	if(info->fragment && info->fragment[0])
	{
		twine_logf(LOG_WARNING, PLUGIN_NAME ": configured file: cache URI includes a fragment which will be ignored\n");
	}
	if(info->auth && info->auth[0])
	{
		twine_logf(LOG_WARNING, PLUGIN_NAME ": configured file: cache URI includes authentication details which will be ignored\n");	
	}
	context->cachepath = (char *) calloc(1, strlen(info->path) + 3);
	if(!context->cachepath)
	{
		twine_logf(LOG_CRIT, PLUGIN_NAME ": failed to allocate memory for cache path string '%s'\n", info->path);
		return -1;
	}
	p = context->cachepath;
	/* Ensure leading and trailing slashes */
	if(info->path[0] != '/')
	{
		*p = '/';
		p++;
	}
	strcpy(p, info->path);
	p = strchr(p, 0);
	if(p > context->cachepath)
	{
		p--;
		if(*p != '/')
		{
			p++;
			*p = '/';
			p++;
			*p = 0;
		}
	}
	twine_logf(LOG_NOTICE, PLUGIN_NAME ": file cache path is '%s'\n", context->cachepath);
	return 0;
}

/* Fetch an object from the Anansi cache when configured to use a disk cache */
TWINEGRAPH *
anansi_file_fetch(struct anansi_context_struct *context, const char *uristr, URI_INFO *info)
{
	json_t *dict, *j, *headers;
	const char *location, *type;
	int r;
	TWINEGRAPH *graph;

	if(!info->path)
	{
		twine_logf(LOG_ERR, PLUGIN_NAME ": <%s> is not a valid Anansi cache resource URL\n", uristr);
		return NULL;
	}
	dict = NULL;
	r = anansi_file_ingest_info(context, info->path, &dict);
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
	type = NULL;
	j = json_object_get(dict, "content_location");
	if(j)
	{
		location = json_string_value(j);
	}
	if(!location)
	{
		twine_logf(LOG_ERR, PLUGIN_NAME ": object has no Content-Location\n");
		json_decref(dict);
		return NULL;
	}
	j = json_object_get(dict, "type");
	if(j)
	{
		type = json_string_value(j);
	}
	if(!type)
	{
		twine_logf(LOG_ERR, PLUGIN_NAME ": object has no Content-Type\n");
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
	r = anansi_file_ingest_payload(context, graph, info->path, type, location);
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

char *
anansi_file_path(struct anansi_context_struct *context, const char *path, const char *type)
{
	size_t needed;
	char *buf;
	
	while(*path == '/')
	{
		path++;
	}
	/* base path + "/" + key[0..1] + "/" + key[2..3] + "/" + key[0..n] + "." + type + NUL */
	needed = strlen(context->cachepath) + 1 + 2 + 1 + 2 + 1 + strlen(path) + 1 + (type ? strlen(type) : 0) + 1;
	buf = (char *) calloc(1, needed);
	if(!buf)
	{
		twine_logf(LOG_CRIT, PLUGIN_NAME ": failed to allocate %lu bytes for cache filename");
		return NULL;
	}
	sprintf(buf, "%s%c%c/%c%c/%s%s%s", context->cachepath, path[0], path[1], path[2], path[3], path, (type && type[0] ? "." : ""), (type ? type : ""));
	return buf;
}

char *
anansi_file_get(struct anansi_context_struct *context, const char *resource, const char *type, size_t *buflen)
{
	char *path, *p, *buffer;
	FILE *f;
	size_t bufsize;
	ssize_t r;
	
	*buflen = 0;
	path = anansi_file_path(context, resource, type);
	if(!path)
	{
		return NULL;
	}
	buffer = NULL;
	bufsize = 0;
	*buflen = 0;
	f = fopen(path, "rb");
	if(!f)
	{
		twine_logf(LOG_ERR, PLUGIN_NAME ": failed to open %s for reading: %s\n", path, strerror(errno));
		free(path);
		return NULL;
	}
	twine_logf(LOG_DEBUG, PLUGIN_NAME ": reading '%s'\n", path);
	while(!feof(f))
	{
		if(bufsize - *buflen < 1024)
		{
			p = (char *) realloc(buffer, bufsize + 1024);
			if(!p)
			{
				twine_logf(LOG_CRIT, PLUGIN_NAME ": failed to reallocate buffer from %u bytes to %u bytes\n", (unsigned) bufsize, (unsigned) bufsize + 1024);
				*buflen = 0;
				fclose(f);
				free(buffer);
				free(path);
				return NULL;
			}
			buffer = p;
			bufsize += 1024;
		}
		r = fread(&(buffer[*buflen]), 1, 1023, f);
		if(r < 0)
		{
			twine_logf(LOG_CRIT, PLUGIN_NAME ": error reading from '%s': %s\n", path, strerror(errno));
			*buflen = 0;
			fclose(f);
			free(buffer);
			free(path);
			return NULL;
		}
		*buflen += r;
		buffer[*buflen] = 0;
	}
	fclose(f);
	free(path);
	return buffer;
}

int
anansi_file_ingest_info(struct anansi_context_struct *context, const char *resource, json_t **dict)
{
	char *buf;
	size_t buflen;
	int r;
	json_error_t err;
	
	r = 0;
	buflen = 0;
	buf = anansi_file_get(context, resource, CACHE_INFO_SUFFIX, &buflen);
	if(!buf)
	{
		return -1;
	}
	*dict = json_loads(buf, 0, &err);
	if(!*dict)
	{
		twine_logf(LOG_ERR, PLUGIN_NAME ": failed to parse '%s" CACHE_INFO_SUFFIX "': %s at (%d, %d)\n", resource, err.text, err.line, err.column);
		r = -1;
	}
	else if(json_typeof(*dict) != JSON_OBJECT)
	{
		twine_logf(LOG_ERR, PLUGIN_NAME ": '%s" CACHE_INFO_SUFFIX "': not a JSON object\n", resource);
		json_decref(*dict);
		r = -1;
	}
	free(buf);
	return r;
}

int
anansi_file_ingest_payload(struct anansi_context_struct *context, TWINEGRAPH *graph, const char *resource, const char *type, const char *location)
{
	char *buf;
	size_t buflen;
	int r;
	
	buflen = 0;
	buf = anansi_file_get(context, resource, CACHE_PAYLOAD_SUFFIX, &buflen);
	if(!buf)
	{
		return -1;
	}
	r = anansi_handler_process_payload(context, graph, buf, buflen, type, location);
	free(buf);
	return r;
}
