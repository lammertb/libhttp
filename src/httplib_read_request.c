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
 * int XX_httplib_read_request( const struct lh_ctx_t *ctx, FILE *fp, struct lh_con_t *conn, char *buf, int bufsiz, int *nread );
 *
 * The function XX_httplib_read_request() keeps reading the input (which can
 * either be an opened file descriptor, a socket sock or an SSL descriptor ssl)
 * into buffer buf, until \r\n\r\n appears in the buffer which marks the end
 * of the HTTP request. The buffer buf may already have some data. The length
 * of the data is stored in nread. Upon every read operation the value of nread
 * is incremented by the number of bytes read.
 */

int XX_httplib_read_request( const struct lh_ctx_t *ctx, FILE *fp, struct lh_con_t *conn, char *buf, int bufsiz, int *nread ) {

	int request_len;
	int n;
	struct timespec last_action_time;
	double request_timeout;

	if ( ctx == NULL  ||  conn == NULL ) return 0;

	n = 0;

	memset( & last_action_time, 0, sizeof(last_action_time) );

	request_timeout = ((double)ctx->request_timeout) / 1000.0;
	request_len     = XX_httplib_get_request_len( buf, *nread );

	/*
	 * first time reading from this connection
	 */

	clock_gettime( CLOCK_MONOTONIC, & last_action_time );

	while ( ctx->status == CTX_STATUS_RUNNING  &&
		*nread      <  bufsiz              &&
		request_len == 0                   &&
		((XX_httplib_difftimespec(&last_action_time, &(conn->req_time)) <= request_timeout) || (request_timeout < 0)) &&
		( (n = XX_httplib_pull( ctx, fp, conn, buf + *nread, bufsiz - *nread, request_timeout )) > 0 ) ) {

		*nread += n;
		if ( *nread > bufsiz ) return -2;

		request_len = XX_httplib_get_request_len( buf, *nread );
		if ( request_timeout > 0.0 ) clock_gettime( CLOCK_MONOTONIC, & last_action_time );
	}

	return ( request_len <= 0  &&   n <= 0 ) ? -1 : request_len;

}  /* XX_httplib_read_request */
