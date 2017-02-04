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
 * int httplib_get_response( const struct lh_ctx_t *ctx, struct lh_con_t *conn, int timeout );
 *
 * The function httplib_get_response() tries to get a response from a remote
 * peer. This function does some dirty action by temporarily replacing the
 * context of the connection with a copy. The only thing which is changed in
 * the copy is the timeout value which is set according to the timeout as it
 * was passed as a parameter to the function call. After the call to the
 * function XX_httplib_getreq() has finished, the old context is put back in
 * place.
 */

int httplib_get_response( const struct lh_ctx_t *ctx, struct lh_con_t *conn, int timeout ) {

	int err;
	int ret;
	struct lh_ctx_t rctx;

	if ( ctx == NULL  ||  conn == NULL ) return -1;

	/*
	 * Replace the connection context with a copy of it where the timeout
	 * value is changed to a parameter passed value.
	 */

	rctx = *ctx;

	if ( timeout >= 0 ) {

		rctx.request_timeout = timeout;
		XX_httplib_set_sock_timeout( conn->client.sock, timeout );
	}
	
	else rctx.request_timeout = 0;

	ret = XX_httplib_getreq( &rctx, conn, &err );

	/*
	 * End of dirty context swap code.
	 */

	/*
	 * TODO: 1) uri is deprecated;
	 *       2) here, ri.uri is the http response code
	 */

	conn->request_info.uri = conn->request_info.request_uri;

	/*
	 * TODO (mid): Define proper return values - maybe return length?
	 * For the first test use <0 for error and >0 for OK
	 */

	return (ret == 0) ? -1 : +1;

}  /* httplib_get_response */
