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
 * void XX_httplib_reset_per_request_attributes( struct lh_con_t *conn );
 *
 * The function XX_httplib_reset_per_request_attributes() resets the request
 * attributes of a connection.
 */

void XX_httplib_reset_per_request_attributes( struct lh_con_t *conn ) {

	if ( conn == NULL ) return;

	conn->path_info                   = NULL;
	conn->num_bytes_sent              = 0;
	conn->consumed_content            = 0;
	conn->status_code                 = -1;
	conn->is_chunked                  = 0;
	conn->must_close                  = false;
	conn->request_len                 = 0;
	conn->throttle                    = 0;
	conn->request_info.content_length = -1;
	conn->request_info.remote_user    = NULL;
	conn->request_info.request_method = NULL;
	conn->request_info.request_uri    = NULL;
	conn->request_info.local_uri      = NULL;
	conn->request_info.uri            = NULL; /* TODO: cleanup uri, local_uri and request_uri */
	conn->request_info.http_version   = NULL;
	conn->request_info.num_headers    = 0;
	conn->data_len                    = 0;
	conn->chunk_remainder             = 0;

}  /* XX_httplib_reset_per_request_attributes */
