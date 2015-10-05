## Twine: A Linked Data workflow engine
##
## Author: Mo McRoberts <mo.mcroberts@bbc.co.uk>
##
## Copyright (c) 2014 BBC
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

DIST_SUBDIRS = m4 libsupport

SUBDIRS = libsupport .

sbin_PROGRAMS = twine-anansi-bridge

twinemodule_LTLIBRARIES = anansi.la

twine_anansi_bridge_CPPFLAGS = $(LIBTWINE_CPPFLAGS) \
	$(LIBMQ_CPPFLAGS) \
	$(LIBURI_CPPFLAGS) \
	$(LIBSQL_CPPFLAGS) \
	-I$(top_builddir)/libsupport -I$(top_srcdir)/libsupport

twine_anansi_bridge_SOURCES = anansi-bridge.c

twine_anansi_bridge_LDADD = \
	$(LIBSQL_LOCAL_LIBS) $(LIBSQL_LIBS) \
	$(LIBTWINE_LOCAL_LIBS) $(LIBTWINE_LIBS) \
	$(LIBMQ_LOCAL_LIBS) $(LIBMQ_LIBS) \
	$(top_builddir)/libsupport/libsupport.la

anansi_la_CPPFLAGS = $(LIBTWINE_CPPFLAGS) \
	$(LIBURI_CPPFLAGS) \
	$(LIBAWSCLIENT_CPPFLAGS) \
	$(LIBJANSSON_CPPFLAGS)

anansi_la_SOURCES = anansi-handler.c

anansi_la_LDFLAGS = -avoid-version -module

anansi_la_LIBADD = $(LIBTWINE_LOCAL_LIBS) $(LIBTWINE_LIBS) \
	$(LIBURI_LOCAL_LIBS) $(LIBURI_LIBS) \
	$(LIBAWSCLIENT_LOCAL_LIBS) $(LIBAWSCLIENT_LIBS) \
	$(LIBJANSSON_LOCAL_LIBS) $(LIBJANSSON_LIBS)