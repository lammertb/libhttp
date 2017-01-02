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
 * void XX_httplib_send_options( const struct lh_ctx_t *ctx, struct lh_con_t *conn );
 *
 * The function XX_httplib_send_options() sends a list of allowed options a
 * client can use to connect to the server.
 */

void XX_httplib_send_options( const struct lh_ctx_t *ctx, struct lh_con_t *conn ) {

	char date[64];
	time_t curtime;

	if ( ctx == NULL  ||  conn == NULL ) return;
	if ( ctx->document_root    == NULL ) return;

	curtime           = time( NULL );
	conn->status_code = 200;
	conn->must_close  = true;

	XX_httplib_gmt_time_string( date, sizeof(date), &curtime );

	httplib_printf( ctx, conn,
	          "HTTP/1.1 200 OK\r\n"
	          "Date: %s\r\n"
	          /* TODO: "Cache-Control" (?) */
	          "Connection: %s\r\n"
	          "Allow: GET, POST, HEAD, CONNECT, PUT, DELETE, OPTIONS, "
	          "PROPFIND, MKCOL\r\n"
	          "DAV: 1\r\n\r\n",
	          date,
	          XX_httplib_suggest_connection_header( ctx, conn ) );

}  /* XX_httplib_send_options */
