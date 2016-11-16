/* 
 * Copyright (C) 2016 Lammert Bies
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



/*
 * int XX_httplib_getreq( struct mg_connection *conn, char *ebuf, size_t ebuf_len, int *err );
 *
 * The function XX_httplib_getreq() processes a request from a remote client.
 */

int XX_httplib_getreq( struct mg_connection *conn, char *ebuf, size_t ebuf_len, int *err ) {

	const char *cl;

	if (ebuf_len > 0) ebuf[0] = '\0';
	*err = 0;

	XX_httplib_reset_per_request_attributes(conn);

	if (!conn) {
		XX_httplib_snprintf(conn, NULL, ebuf, ebuf_len, "%s", "Internal error");
		*err = 500;
		return 0;
	}
	/* Set the time the request was received. This value should be used for
	 * timeouts. */
	clock_gettime(CLOCK_MONOTONIC, &(conn->req_time));

	conn->request_len =
	    XX_httplib_read_request(NULL, conn, conn->buf, conn->buf_size, &conn->data_len);
	/* assert(conn->request_len < 0 || conn->data_len >= conn->request_len);
	 */
	if (conn->request_len >= 0 && conn->data_len < conn->request_len) {
		XX_httplib_snprintf(conn, NULL, ebuf, ebuf_len, "%s", "Invalid request size");
		*err = 500;
		return 0;
	}

	if (conn->request_len == 0 && conn->data_len == conn->buf_size) {
		XX_httplib_snprintf(conn, NULL, ebuf, ebuf_len, "%s", "Request Too Large");
		*err = 413;
		return 0;
	} else if (conn->request_len <= 0) {
		if (conn->data_len > 0) {
			XX_httplib_snprintf(conn, NULL, ebuf, ebuf_len, "%s", "Client sent malformed request");
			*err = 400;
		} else {
			/* Server did not send anything -> just close the connection */
			conn->must_close = 1;
			XX_httplib_snprintf(conn, NULL, ebuf, ebuf_len, "%s", "Client did not send a request");
			*err = 0;
		}
		return 0;
	} else if (XX_httplib_parse_http_message(conn->buf, conn->buf_size, &conn->request_info) <= 0) {
		XX_httplib_snprintf(conn, NULL, ebuf, ebuf_len, "%s", "Bad Request");
		*err = 400;
		return 0;
	} else {
		/* Message is a valid request or response */
		if ((cl = XX_httplib_get_header(&conn->request_info, "Content-Length")) != NULL) {
			/* Request/response has content length set */
			char *endptr = NULL;
			conn->content_len = strtoll(cl, &endptr, 10);
			if (endptr == cl) {
				XX_httplib_snprintf(conn, NULL, ebuf, ebuf_len, "%s", "Bad Request");
				*err = 411;
				return 0;
			}
			/* Publish the content length back to the request info. */
			conn->request_info.content_length = conn->content_len;
		} else if ((cl = XX_httplib_get_header(&conn->request_info, "Transfer-Encoding"))
		               != NULL
		           && !mg_strcasecmp(cl, "chunked")) {
			conn->is_chunked = 1;
		} else if (!mg_strcasecmp(conn->request_info.request_method, "POST")
		           || !mg_strcasecmp(conn->request_info.request_method,
		                             "PUT")) {
			/* POST or PUT request without content length set */
			conn->content_len = -1;
		} else if (!mg_strncasecmp(conn->request_info.request_method,
		                           "HTTP/",
		                           5)) {
			/* Response without content length set */
			conn->content_len = -1;
		} else {
			/* Other request */
			conn->content_len = 0;
		}
	}
	return 1;

}  /* XX_httplib_getreq */
