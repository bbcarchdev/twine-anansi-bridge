/* Author: Mo McRoberts <mo.mcroberts@bbc.co.uk>
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

#ifndef P_ANANSI_PLUGIN_H_
# define P_ANANSI_PLUGIN_H_            1

# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <unistd.h>
# include <errno.h>
# include <ctype.h>

# include <librdf.h>
# include <jansson.h>

# include "libtwine.h"
# include "liburi.h"
# include "libawsclient.h"
# include "libsql.h"
# include "libmq.h"
# include "libmq-engine.h"
# include "libcluster.h"

# define PLUGIN_NAME                   "Anansi"
# define ANANSI_URL_MIME               "application/x-anansi-url"
# define CACHE_INFO_SUFFIX             "json"
# define CACHE_PAYLOAD_SUFFIX          ""
# define NS_XHTML                      "http://www.w3.org/1999/xhtml/vocab#"

struct bucketinfo_struct
{
	char *name;
	AWSS3BUCKET *bucket;
};

struct ingestinfo_struct
{
	char *buf;
	size_t pos;
	size_t size;
};

struct anansi_context_struct
{
	TWINE *twine;
	/* The cache will either be a disk path or an S3 bucket */
	char *cachepath;
	AWSS3BUCKET *bucket;
	char *s3endpoint;
	char *s3access;
	char *s3secret;
	int s3verbose;
};

int anansi_handler_init(TWINE *restrict context, void *restrict handle);
int anansi_handler_process_payload(struct anansi_context_struct *context, TWINEGRAPH *graph, const char *buf, size_t buflen, const char *type, const char *graphuri);
int anansi_handler_process_headers(struct anansi_context_struct *context, TWINEGRAPH *graph, json_t *dict, const char *graphuri);

int anansi_mq_init(void *handle);

int anansi_file_init(struct anansi_context_struct *context, URI_INFO *info);
TWINEGRAPH *anansi_file_fetch(struct anansi_context_struct *context, const char *uristr, URI_INFO *info);
char *anansi_file_path(struct anansi_context_struct *context, const char *path, const char *type);
char *anansi_file_get(struct anansi_context_struct *context, const char *path, const char *type, size_t *buflen);
int anansi_file_ingest_info(struct anansi_context_struct *context, const char *resource, json_t **dict);
int anansi_file_ingest_payload(struct anansi_context_struct *context, TWINEGRAPH *graph, const char *resource, const char *type, const char *location);

int anansi_s3_init(struct anansi_context_struct *context, URI_INFO *info);
TWINEGRAPH *anansi_s3_fetch(struct anansi_context_struct *context, const char *uristr, URI_INFO *info);
AWSS3BUCKET *anansi_s3_bucket_create(struct anansi_context_struct *context, URI_INFO *info);
AWSS3BUCKET *anansi_s3_bucket(struct anansi_context_struct *context, URI_INFO *info);
AWSS3BUCKET *anansi_s3_bucket_add(struct anansi_context_struct *context, struct bucketinfo_struct *bucketinfo, URI_INFO *info);
int anansi_s3_ingest_info_bucket(struct anansi_context_struct *context, AWSS3BUCKET *bucket, const char *resource, json_t **dict);
int anansi_s3_ingest_payload_bucket(struct anansi_context_struct *context, TWINEGRAPH *graph, AWSS3BUCKET *bucket, const char *resource, const char *location);

#endif /*!P_ANANSI_PLUGIN_H_*/
