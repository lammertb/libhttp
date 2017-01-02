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
#include "httplib_utils.h"

/*
 * void XX_httplib_handle_not_modified_static_file_request( struct lh_ctx_t *ctx, struct lh_con_t *conn, struct file *filep );
 *
 * The function XX_httplib_handle_not_modified_static_file_request() is used to
 * send a 304 response to a client to indicate that the requested resource has
 * not been changed.
 */

void XX_httplib_handle_not_modified_static_file_request( struct lh_ctx_t *ctx, struct lh_con_t *conn, struct file *filep ) {

	char date[64];
	char lm[64];
	char etag[64];
	time_t curtime;

	if ( ctx == NULL  ||  conn == NULL  ||  filep == NULL ) return;

	curtime           = time( NULL );
	conn->status_code = 304;

	XX_httplib_gmt_time_string( date, sizeof(date), & curtime              );
	XX_httplib_gmt_time_string( lm,   sizeof(lm),   & filep->last_modified );
	XX_httplib_construct_etag(  ctx, etag, sizeof(etag), filep             );

	httplib_printf( ctx, conn, "HTTP/1.1 %d %s\r\n" "Date: %s\r\n", conn->status_code, httplib_get_response_code_text( ctx, conn, conn->status_code ), date );
	XX_httplib_send_static_cache_header( ctx, conn );
	httplib_printf( ctx, conn, "Last-Modified: %s\r\n" "Etag: %s\r\n" "Connection: %s\r\n" "\r\n", lm, etag, XX_httplib_suggest_connection_header( ctx, conn ) );

}  /* XX_httplib_handle_not_modified_static_file_request */
