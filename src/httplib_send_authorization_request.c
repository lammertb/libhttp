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
 */



#include "libhttp-private.h"



void XX_httplib_send_authorization_request( struct mg_connection *conn ) {

	char date[64];
	time_t curtime;

	if ( conn == NULL  ||  conn->ctx == NULL ) return;

	curtime = time( NULL );

	uint64_t nonce = (uint64_t)(conn->ctx->start_time);

	(void)pthread_mutex_lock(&conn->ctx->nonce_mutex);
	nonce += conn->ctx->nonce_count;
	++conn->ctx->nonce_count;
	(void)pthread_mutex_unlock(&conn->ctx->nonce_mutex);

	nonce ^= conn->ctx->auth_nonce_mask;
	conn->status_code = 401;
	conn->must_close = 1;

	XX_httplib_gmt_time_string(date, sizeof(date), &curtime);

	mg_printf(conn, "HTTP/1.1 401 Unauthorized\r\n");
	XX_httplib_send_no_cache_header(conn);
	mg_printf(conn,
	          "Date: %s\r\n"
	          "Connection: %s\r\n"
	          "Content-Length: 0\r\n"
	          "WWW-Authenticate: Digest qop=\"auth\", realm=\"%s\", "
	          "nonce=\"%" UINT64_FMT "\"\r\n\r\n",
	          date,
	          XX_httplib_suggest_connection_header(conn),
	          conn->ctx->config[AUTHENTICATION_DOMAIN],
	          nonce);

}  /* XX_httplib_send_authorization_request */
