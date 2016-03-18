/* Fetch resources from an Anansi cache and process them
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

static int anansi_handler_input(TWINE *restrict context, const char *restrict mime, const unsigned char *restrict buf, size_t buflen, const char *restrict subject, void *data);
static const unsigned char *anansi_handler_bulk(TWINE *restrict context, const char *restrict mime, const unsigned char *restrict buf, size_t buflen, void *data);

static int ingest_link(librdf_world *world, librdf_model *model, const char *value, librdf_uri *resource);
static unsigned char *ustrnchr(const unsigned char *src, int ch, size_t max);

static struct anansi_context_struct anansi_context;

int
anansi_handler_init(TWINE *restrict context, void *restrict handle)
{
	URI *base, *cacheuri;
	URI_INFO *info;
	char *t;
	int r;
	
	memset(&anansi_context, 0, sizeof(struct anansi_context_struct));
	anansi_context.twine = context;
	base = uri_create_cwd();
	if(!base)
	{
		twine_logf(LOG_CRIT, PLUGIN_NAME ": failed to create URI for current working directory\n");
		return -1;
	}
	t = twine_config_geta("anansi:cache", "cache");
	cacheuri = uri_create_str(t, base);
	if(!cacheuri)
	{
		twine_logf(LOG_CRIT, PLUGIN_NAME ": failed to parse URI <%s>\n", t);
		free(t);
		return -1;
	}
	info = uri_info(cacheuri);
	if(!info)
	{
		twine_logf(LOG_CRIT, PLUGIN_NAME ": failed to obtain information about cache URI <%s>\n", t);
		free(t);
		uri_destroy(cacheuri);
		uri_destroy(base);
	}
	anansi_context.s3endpoint = twine_config_geta("s3:endpoint", NULL);
	anansi_context.s3access = twine_config_geta("s3:access", NULL);
	anansi_context.s3secret = twine_config_geta("s3:secret", NULL);
	anansi_context.s3verbose = twine_config_get_bool("s3:verbose", 0);
	if(info->scheme && !strcasecmp(info->scheme, "s3"))
	{
		r = anansi_s3_init(&anansi_context, info);
	}
	else if(info->scheme && !strcasecmp(info->scheme, "file"))
	{
		r = anansi_file_init(&anansi_context, info);
	}
	else
	{
		twine_logf(LOG_CRIT, PLUGIN_NAME ": <%s> is not a supported cache URI\n", t);
		r = -1;
	}
	free(t);
	uri_info_destroy(info);
	uri_destroy(cacheuri);
	uri_destroy(base);
	if(!r)
	{
		twine_plugin_add_input(context, ANANSI_URL_MIME, "Anansi URL", anansi_handler_input, &anansi_context);
		twine_plugin_add_bulk(context, ANANSI_URL_MIME, "Anansi URL", anansi_handler_bulk, &anansi_context);
	}
	return r;
}

int
anansi_handler_process_payload(struct anansi_context_struct *context, TWINEGRAPH *graph, const char *buf, size_t buflen, const char *type, const char *graphuri)
{
	librdf_world *world;
	librdf_uri *base;
	librdf_model *model;
	
	model = twine_graph_model(graph);
	world = twine_rdf_world();
	base = librdf_new_uri(world, (const unsigned char *) graphuri);
	twine_logf(LOG_DEBUG, PLUGIN_NAME ": parsing buffer into model as '%s'\n", type);
	if(twine_rdf_model_parse_base(model, type, buf, buflen, base))
	{
		twine_logf(LOG_ERR, PLUGIN_NAME ": failed to parse string into model\n");
		librdf_free_uri(base);
		return -1;
	}
	librdf_free_uri(base);
	return 0;
}

/* Debian Wheezy ships with libjansson 2.3, which doesn't include
 * json_array_foreach()
 */
#ifndef json_array_foreach
# define json_array_foreach(array, index, value) \
	for(index = 0; index < json_array_size(array) && (value = json_array_get(array, index)); index++)
#endif

int
anansi_handler_process_headers(struct anansi_context_struct *context, TWINEGRAPH *graph, json_t *dict, const char *graphuri)
{
	librdf_model *model;
	json_t *values, *value;
	const char *name;
	size_t index;
	librdf_world *world;
	librdf_uri *resource;
	
	model = twine_graph_model(graph);
	world = twine_rdf_world();
	resource = librdf_new_uri(world, (const unsigned char *) graphuri);
	json_object_foreach(dict, name, values)
	{
		if(json_typeof(values) != JSON_ARRAY)
		{
			continue;
		}
		if(!strcasecmp(name, "link"))
		{
			json_array_foreach(values, index, value)
			{
				if(json_typeof(value) != JSON_STRING)
				{
					continue;
				}
				ingest_link(world, model, json_string_value(value), resource);
			}
		}
	}
	librdf_free_uri(resource);
	return 0;
}

static int
anansi_handler_input(TWINE *restrict context, const char *restrict mime, const unsigned char *restrict buf, size_t buflen, const char *restrict subject, void *data)
{
	char *str, *t;
	URI *uri;
	URI_INFO *info;
	AWSS3BUCKET *bucket;
	int r;
	TWINEGRAPH *graph;
	struct anansi_context_struct *acontext;
	
	(void) mime;
	(void) subject;

	acontext = (struct anansi_context_struct *) data;
	graph = NULL;
	bucket = NULL;
	r = 0;
	/* Impose a hard limit on URL lengths */
	if(buflen > 1024)
	{
		buflen = 1024;
	}
	str = (char *) calloc(1, buflen + 1);
	if(!str)
	{
		return -1;
	}
	memcpy((void *) str, (void *) buf, buflen);
	str[buflen] = 0;
	t = strchr(str, '\n');
	if(t)
	{
		*t = 0;
	}
	twine_logf(LOG_DEBUG, PLUGIN_NAME ": URI is <%s>\n", str);
	uri = uri_create_str(str, NULL);
	if(!uri)
	{
		twine_logf(LOG_ERR, PLUGIN_NAME ": failed to parse <%s>\n", str);
		free(str);
		return -1;
	}
	info = uri_info(uri);
	if(info->scheme && !strcasecmp(info->scheme, "anansi"))
	{
		/* anansi:///UUID */
		if(info->host && info->host[0])
		{
			twine_logf(LOG_WARNING, PLUGIN_NAME ": hostname in URI <%s> will be ignored\n", str);
		}
		if(info->path)
		{
			if(acontext->cachepath)
			{
				graph = anansi_file_fetch(acontext, str, info);
			}
			else
			{
				graph = anansi_s3_fetch(acontext, str, info);
			}
			if(!graph)
			{
				r = -1;
			}
		}
		else
		{
			twine_logf(LOG_ERR, PLUGIN_NAME ": <%s> is not a valid Anansi cache resource URL\n", str);
			r = -1;
		}
	}
	else if(info->scheme && !strcasecmp(info->scheme, "s3"))
	{
		/* s3://BUCKET/UUID */
		graph = anansi_s3_fetch(acontext, str, info);
		if(!graph)
		{
			r = -1;
		}
	}
	else
	{
		twine_logf(LOG_ERR, PLUGIN_NAME ": <%s> is not a valid Anansi URL\n", str);
		r = -1;
	}
	if(!r)
	{
		if(twine_workflow_process_graph(context, graph))
		{
			twine_logf(LOG_ERR, PLUGIN_NAME ": failed to process graph <%s>\n", twine_graph_uri(graph));
			r = -1;
		}
	}
	if(graph)
	{
		twine_graph_destroy(graph);
	}
	uri_info_destroy(info);
	uri_destroy(uri);
	free(str);
	return r;
}

static const unsigned char *
anansi_handler_bulk(TWINE *restrict context, const char *restrict mime, const unsigned char *restrict buf, size_t buflen, void *data)
{
	const unsigned char *start, *t;
	size_t remaining;

	if(!buflen)
	{
		return buf;
	}
	t = buf;
	while((size_t) (t - buf) < buflen)
	{
		start = t;
		remaining = buflen - (t - buf);
		t = ustrnchr(start, '\n', remaining);
		if(t == start)
		{
			continue;
		}
		if(!t)
		{
			return (const unsigned char *) start;
		}
		if(anansi_handler_input(context, mime, start, t - start, NULL, data))
		{
			return NULL;
		}
		t++;
	}
	return t;
}

static int
ingest_link(librdf_world *world, librdf_model *model, const char *value, librdf_uri *resource)
{
	static const char *relbase = NS_XHTML;
	const char *t, *pend, *vstart, *s;
	char *anchorstr, *uristr, *relstr, *p;
	librdf_uri *anchor, *uri, *rel;
	int q, abs;
	librdf_node *subject, *predicate, *object;
	librdf_statement *st;

	rel = NULL;
	while(*value)
	{
		anchorstr = NULL;
		uristr = NULL;
		relstr = NULL;
		t = value;
		while(*t && isspace(*t))
		{
			t++;
		}
		if(*t != '<')
		{
			twine_logf(LOG_NOTICE, PLUGIN_NAME ": ignoring malformed Link header (%s)\n", value);
			return -1;
		}
		value = t + 1;
		while(*t && *t != '>')
		{
			t++;
		}
		if(!*t)
		{
			twine_logf(LOG_NOTICE, PLUGIN_NAME ": ignoring malformed Link header (%s)\n", value);
			return -1;
		}
		uristr = (char *) malloc(t - value + 1);
		if(!uristr)
		{
			twine_logf(LOG_ERR, PLUGIN_NAME ": failed to allocate memory for Link URI\n");
			return -1;
		}
		strncpy(uristr, value, t - value);
		uristr[t - value] = 0;
		value = t + 1;		
		while(*value && *value != ',')
		{
			vstart = NULL;
			q = 0;
			while(*value == ' ' || *value == '\t')
			{
				value++;
			}
			if(!*value)
			{
				break;
			}
			t = value;
			/* Parse a single parameter */
			while(*t)
			{
				if(*t == '=' || *t == ';')
				{
					break;
				}
				if(*t == ' ' || *t == '\t')
				{
					twine_logf(LOG_NOTICE, PLUGIN_NAME ": ignoring link relation with malformed parameters ('%s')\n", value);
					return -1;
				}
				t++;
			}
			if(!*t || *t == ',')
			{
				break;
			}
			if(*t == ';')
			{
				t++;
				value = t;
				continue;
			}
			pend = t;
			t++;
			while(*t == ' ' || *t == '\t')
			{
				t++;
			}
			vstart = t;
			while(*t)
			{
				if(q)
				{
					if(*t == q)
					{
						q = 0;
					}
					t++;
					continue;
				}
				if(*t == '"')
				{
					q = *t;
					t++;
					continue;
				}
				if(*t == ';')
				{
					break;
				}
				if(*t == ',')
				{
					break;
				}
				t++;
			}
			/* Parse a 'rel' parameter */
			if(!relstr && pend - value == 3 && !strncmp(value, "rel", 3))
			{
				/* If the relation is not something that looks like a URI,
				 * create one by concatenating it to relbase; otherwise,
				 * just parse the relation as a URI.
				 */
				relstr = (char *) malloc(t - vstart + strlen(relbase) + 1);
				p = relstr;
				abs = 0;
				for(s = vstart; s < t; s++)
				{
					if(*s == ':' || *s == '/')
					{
						abs = 1;
						break;
					}
				}
				if(!abs)
				{
					strcpy(relstr, relbase);
					p = strchr(relstr, 0);
				}
				for(s = vstart; s < t; s++)
				{
					if(*s == '"')
					{
						continue;
					}
					*p = *s;
					p++;
				}
				*p = 0;
			}
			else if(!anchorstr && pend - value == 6 && !strncmp(value, "anchor", 6))
			{
				anchorstr = (char *) malloc(t - vstart + 1);
				p = anchorstr;
				for(s = vstart; s < t; s++)
				{
					if(*s == '"')
					{
						continue;
					}
					*p = *s;
					p++;
				}
				*p = 0;
			}
			value = t;
			if(!*value || *value == ',')
			{
				break;
			}
			value++;
		}
		/* We have now parsed all parameters */
		anchor = NULL;
		rel = NULL;
		uri = NULL;
		if(anchorstr)
		{
			anchor = librdf_new_uri_relative_to_base(resource, (const unsigned char *) anchorstr);
		}
		else
		{
			anchor = resource;
		}
		if(relstr)
		{
			uri = librdf_new_uri_relative_to_base(anchor, (const unsigned char *) uristr);
			
			/* Only process links which actually have a relation */
			rel = librdf_new_uri(world, (const unsigned char *) relstr);
			twine_logf(LOG_DEBUG, PLUGIN_NAME ": Link <%s> <%s> <%s>\n",
				(const char *) librdf_uri_as_string(anchor),
				(const char *) librdf_uri_as_string(rel),
				(const char *) librdf_uri_as_string(uri));
			/* Create a new triple (content-location, relation, target) */
			subject = librdf_new_node_from_uri(world, anchor);
			predicate = librdf_new_node_from_uri(world, rel);
			object = librdf_new_node_from_uri(world, uri);
			st = librdf_new_statement_from_nodes(world, subject, predicate, object);
			/* Add the triple to the model */
			librdf_model_add_statement(model, st);
			librdf_free_statement(st);
			librdf_free_uri(rel);
			librdf_free_uri(uri);
		}
		if(anchor && anchor != resource)
		{
			librdf_free_uri(anchor);
		}
		free(anchorstr);
		anchorstr = NULL;
		free(relstr);
		relstr = NULL;
		free(uristr);
		uristr = NULL;
		
		if(*value)
		{
			value++;
		}
	}
	return 0;
}

static unsigned char *
ustrnchr(const unsigned char *src, int ch, size_t max)
{
	const unsigned char *t;

	for(t = src; (size_t) (t - src) < max; t++)
	{
		if(!*t)
		{
			break;
		}
		if(*t == ch)
		{
			return (unsigned char *) t;
		}
	}
	return NULL;
}
