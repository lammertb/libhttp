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



#include "httplib_main.h"



/*
 * int mg_get_response( struct mg_connection *conn, char *ebuf, size_t ebuf_len, int timeout );
 *
 * The function mg_get_response tries to get a response from a remote peer.
 */

int mg_get_response( struct mg_connection *conn, char *ebuf, size_t ebuf_len, int timeout ) {

	if ( conn == NULL ) return -1;

	/* Implementation of API function for HTTP clients */
	int err, ret;
	struct mg_context *octx = conn->ctx;
	struct mg_context rctx = *(conn->ctx);
	char txt[32]; /* will not overflow */

	if (timeout >= 0) {
		XX_httplib_snprintf(conn, NULL, txt, sizeof(txt), "%i", timeout);
		rctx.config[REQUEST_TIMEOUT] = txt;
		XX_httplib_set_sock_timeout(conn->client.sock, timeout);
	} else {
		rctx.config[REQUEST_TIMEOUT] = NULL;
	}

	conn->ctx = &rctx;
	ret = XX_httplib_getreq(conn, ebuf, ebuf_len, &err);
	conn->ctx = octx;

	/* TODO: 1) uri is deprecated;
	 *       2) here, ri.uri is the http response code */
	conn->request_info.uri = conn->request_info.request_uri;

	/* TODO (mid): Define proper return values - maybe return length?
	 * For the first test use <0 for error and >0 for OK */
	return (ret == 0) ? -1 : +1;

}  /* mg_get_response */
