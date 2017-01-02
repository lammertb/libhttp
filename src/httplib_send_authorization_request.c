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
#include "httplib_pthread.h"
#include "httplib_utils.h"

void XX_httplib_send_authorization_request( struct lh_ctx_t *ctx, struct lh_con_t *conn ) {

	char date[64];
	time_t curtime;
	uint64_t nonce;
	const char *auth_domain;

	if ( ctx == NULL  ||  conn == NULL ) return;

	curtime = time( NULL );

	nonce = (uint64_t)ctx->start_time;

	httplib_pthread_mutex_lock( & ctx->nonce_mutex );
	nonce += ctx->nonce_count;
	++ctx->nonce_count;
	httplib_pthread_mutex_unlock( & ctx->nonce_mutex );

	nonce            ^= ctx->auth_nonce_mask;
	conn->status_code = 401;
	conn->must_close  = true;

	XX_httplib_gmt_time_string( date, sizeof(date), &curtime );

	if ( ctx->authentication_domain != NULL ) auth_domain = ctx->authentication_domain;
	else                                      auth_domain = "example.com";

	httplib_printf( ctx, conn, "HTTP/1.1 401 Unauthorized\r\n" );
	XX_httplib_send_no_cache_header( ctx, conn );
	httplib_printf( ctx, conn,
	          "Date: %s\r\n"
	          "Connection: %s\r\n"
	          "Content-Length: 0\r\n"
	          "WWW-Authenticate: Digest qop=\"auth\", realm=\"%s\", "
	          "nonce=\"%" UINT64_FMT "\"\r\n\r\n",
	          date,
	          XX_httplib_suggest_connection_header( ctx, conn ),
	          auth_domain,
	          nonce );

}  /* XX_httplib_send_authorization_request */
