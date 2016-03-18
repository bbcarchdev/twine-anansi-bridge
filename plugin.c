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

/* Twine plug-in entry-point */
int
twine_entry(TWINE *context, TWINEENTRYTYPE type, void *handle)
{
	switch(type)
	{
		case TWINE_ATTACHED:
			twine_logf(LOG_DEBUG, PLUGIN_NAME " plug-in: initialising\n");
			if(anansi_handler_init(context, handle))
			{
				return -1;
			}
			if(anansi_mq_init(handle))
			{
				return -1;
			}
			break;
		case TWINE_DETACHED:
			twine_logf(LOG_DEBUG, PLUGIN_NAME " plug-in: shutting down\n");
			break;
	}
	return 0;
}
