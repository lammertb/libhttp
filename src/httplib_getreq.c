/* 
 * Copyright (c) 2016-2018 Lammert Bies
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
 * bool XX_httplib_getreq( struct lh_ctx_t *ctx, struct lh_con_t *conn, int *err );
 *
 * The function XX_httplib_getreq() processes a request from a remote client.
 */

bool XX_httplib_getreq( struct lh_ctx_t *ctx, struct lh_con_t *conn, int *err ) {

	const char *cl;
	uint32_t remote_ip;
	char remote_ip_str[16];

	if ( ctx == NULL  ||  err == NULL ) return false;

	*err = 0;

	if ( conn == NULL ) {

		httplib_cry( LH_DEBUG_ERROR, ctx, conn, "%s: internal error", __func__ );
		*err = 500;
		return false;
	}

	XX_httplib_reset_per_request_attributes( conn );

	/*
	 * Set the time the request was received. This value should be used for
	 * timeouts.
	 */

	clock_gettime( CLOCK_MONOTONIC, &conn->req_time );

	conn->request_len = XX_httplib_read_request( ctx, NULL, conn, conn->buf, conn->buf_size, &conn->data_len );

	remote_ip = XX_httplib_get_remote_ip( conn );
	snprintf( remote_ip_str, 16, "%d.%d.%d.%d", (remote_ip>>24), (remote_ip>>16)&0xff, (remote_ip>>8)&0xff, remote_ip&0xff );

	/* 
	 * assert(conn->request_len < 0 || conn->data_len >= conn->request_len);
	 */

	if ( conn->request_len >= 0  &&  conn->data_len < conn->request_len ) {

		httplib_cry( LH_DEBUG_ERROR, ctx, conn, "%s: %s invalid request size", __func__, remote_ip_str );
		*err = 500;
		return false;
	}

	if ( conn->request_len == 0  &&  conn->data_len == conn->buf_size ) {

		httplib_cry( LH_DEBUG_ERROR, ctx, conn, "%s: %s request too large", __func__, remote_ip_str );
		*err = 413;
		return false;
	}
	
	else if ( conn->request_len <= 0 ) {

		if ( conn->data_len > 0 ) {

			httplib_cry( LH_DEBUG_ERROR, ctx, conn, "%s: %s client sent malformed request", __func__, remote_ip_str );
			*err = 400;
		}
		
		else {
			/*
			 * Server did not send anything -> just close the connection
			 */

			conn->must_close = true;

			httplib_cry( LH_DEBUG_WARNING, ctx, conn, "%s: %s client did not send a request", __func__, remote_ip_str );
			*err = 0;
		}
		return false;
	}
	
	else if ( XX_httplib_parse_http_message( conn->buf, conn->buf_size, &conn->request_info ) <= 0 ) {

		httplib_cry( LH_DEBUG_ERROR, ctx, conn, "%s: %s bad request", __func__, remote_ip_str );
		*err = 400;
		return false;
	}
	
	else {
		/*
		 * Message is a valid request or response
		 */

		if ( (cl = XX_httplib_get_header( &conn->request_info, "Content-Length")) != NULL ) {

			/*
			 * Request/response has content length set
			 */

			char *endptr = NULL;
			conn->content_len = strtoll( cl, &endptr, 10 );

			if ( endptr == cl ) {

				httplib_cry( LH_DEBUG_ERROR, ctx, conn, "%s: %s bad request", __func__, remote_ip_str );
				*err = 411;
				return false;
			}

			/*
			 * Publish the content length back to the request info.
			 */

			conn->request_info.content_length = conn->content_len;
		}
		
		else if ( (cl = XX_httplib_get_header( &conn->request_info, "Transfer-Encoding" )) != NULL  &&  ! httplib_strcasecmp( cl, "chunked" ) ) {

			conn->is_chunked = 1;
		}
		
		else if ( ! httplib_strcasecmp( conn->request_info.request_method, "POST" )  ||  ! httplib_strcasecmp( conn->request_info.request_method, "PUT" ) ) {

			/*
			 * POST or PUT request without content length set
			 */

			conn->content_len = -1;
		}
		
		else if ( ! httplib_strncasecmp( conn->request_info.request_method, "HTTP/", 5 ) ) {

			/*
			 * Response without content length set
			 */

			conn->content_len = -1;
		} else {

			/*
			 * Other request
			 */

			conn->content_len = 0;
		}
	}

	return true;

}  /* XX_httplib_getreq */
