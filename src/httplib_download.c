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
 * struct lh_con_t *httplib_download();
 *
 * The function httplib_download() is used to download a file from a remote location
 * and returns a pointer to the connection on success, or NULL on error.
 */

struct lh_con_t *httplib_download( struct lh_ctx_t *ctx, const char *host, int port, int use_ssl, const char *fmt, ... ) {

	struct lh_con_t *conn;
	va_list ap;
	int i;
	int reqerr;

	if ( ctx == NULL ) return NULL;

	va_start( ap, fmt );

	conn = httplib_connect_client( ctx, host, port, use_ssl );

	if ( conn != NULL ) {

		i = XX_httplib_vprintf( ctx, conn, fmt, ap );

		if ( i <= 0 ) httplib_cry( LH_DEBUG_ERROR, ctx, conn, "%s: error sending request", __func__ );
		
		else {
			XX_httplib_getreq( ctx, conn, &reqerr );

			/*
			 * TODO: 1) uri is deprecated;
			 *       2) here, ri.uri is the http response code
			 */

			conn->request_info.uri = conn->request_info.request_uri;
		}
	}

	else i = 0;

	/*
	 * if an error occured, close the connection
	 */

	if ( i <= 0  &&  conn != NULL ) {

		httplib_close_connection( ctx, conn );
		conn = NULL;
	}

	va_end( ap );

	return conn;

}  /* httplib_download */
