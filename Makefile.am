## Twine: A Linked Data workflow engine
##
## Author: Mo McRoberts <mo.mcroberts@bbc.co.uk>
##
## Copyright (c) 2014-2017 BBC
##
##  Licensed under the Apache License, Version 2.0 (the "License");
##  you may not use this file except in compliance with the License.
##  You may obtain a copy of the License at
##
##      http://www.apache.org/licenses/LICENSE-2.0
##
##  Unless required by applicable law or agreed to in writing, software
##  distributed under the License is distributed on an "AS IS" BASIS,
##  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
##  See the License for the specific language governing permissions and
##  limitations under the License.

ACLOCAL_AMFLAGS = -I m4

DIST_SUBDIRS = m4

SUBDIRS = .

AM_CPPFLAGS = @AM_CPPFLAGS@ $(LIBTWINE_CPPFLAGS) \
	$(LIBURI_CPPFLAGS) \
	$(LIBAWSCLIENT_CPPFLAGS) \
	$(LIBMQ_CPPFLAGS) \
	$(LIBCLUSTER_CPPFLAGS) \
	$(LIBJANSSON_CPPFLAGS) \
	$(LIBSQL_CPPFLAGS)


twinemodule_LTLIBRARIES = anansi.la

## anansi.so is a plug-in for Twine which (a) provides a handler for
## application/x-anansi-url messages, and (b) provides an MQ implementation
## allowing Twine to be fed directly from the Anansi database.

anansi_la_SOURCES = p_anansi-plugin.h \
	plugin.c handler.c file.c s3.c

anansi_la_LDFLAGS = -avoid-version -module -no-undefined

anansi_la_LIBADD = $(LIBTWINE_LOCAL_LIBS) $(LIBTWINE_LIBS) \
	$(LIBURI_LOCAL_LIBS) $(LIBURI_LIBS) \
	$(LIBMQ_LOCAL_LIBS) $(LIBMQ_LIBS) \
	$(LIBCLUSTER_LOCAL_LIBS) $(LIBCLUSTER_LIBS) \
	$(LIBAWSCLIENT_LOCAL_LIBS) $(LIBAWSCLIENT_LIBS) \
	$(LIBJANSSON_LOCAL_LIBS) $(LIBJANSSON_LIBS) \
	$(LIBSQL_LOCAL_LIBS) $(LIBSQL_LIBS)

reconf:
	autoreconf -i && $(SHELL) ./config.status --recheck && $(SHELL) ./config.status
