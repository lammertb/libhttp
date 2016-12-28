/* 
 * Copyright (c) 2016 Lammert Bies
 * Copyright (c) 2013-2016 the Civetweb developers
 * Copyright (c) 2004-2013 Sergey Lyubka
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * ============
 * Release: 2.0
 */

#include "httplib_main.h"

/*
 * Config option name, config types, default value
 */

struct httplib_option XX_httplib_config_options[] = {
	{ "cgi_pattern",                 CONFIG_TYPE_EXT_PATTERN, "**.cgi$|**.pl$|**.php$"                                           },
	{ "put_delete_auth_file",        CONFIG_TYPE_FILE,        NULL                                                               },
	{ "cgi_interpreter",             CONFIG_TYPE_FILE,        NULL                                                               },
	{ "ssi_pattern",                 CONFIG_TYPE_EXT_PATTERN, "**.shtml$|**.shtm$"                                               },
	{ "global_auth_file",            CONFIG_TYPE_FILE,        NULL                                                               },
	{ "document_root",               CONFIG_TYPE_DIRECTORY,   NULL                                                               },
	{ "hide_files_patterns",         CONFIG_TYPE_EXT_PATTERN, NULL                                                               },
	{ "ssl_ca_path",                 CONFIG_TYPE_DIRECTORY,   NULL                                                               },
	{ "websocket_root",              CONFIG_TYPE_DIRECTORY,   NULL                                                               },
	{ "error_pages",                 CONFIG_TYPE_DIRECTORY,   NULL                                                               },
	{ NULL,                          CONFIG_TYPE_UNKNOWN,     NULL                                                               }
};

/* 
 * Check if the XX_httplib_config_options and the corresponding enum have
 * compatible sizes
 */

/*
 * TODO: LJB: Move to test functions
 */

// httplib_static_assert((sizeof(XX_httplib_config_options) / sizeof(XX_httplib_config_options[0])) == (NUM_OPTIONS + 1), "XX_httplib_config_options and enum not sync");
