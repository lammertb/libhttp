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
 * void XX_httplib_discard_unread_request_data( const struct lh_ctx_t *ctx, struct lh_con_t *conn );
 *
 * The function XX_httplib_discard_unread_request_data() discards any request
 * data on a connection which is not further needed but has alread been
 * received.
 */

void XX_httplib_discard_unread_request_data( const struct lh_ctx_t *ctx, struct lh_con_t *conn ) {

	char buf[MG_BUF_LEN];
	size_t to_read;
	int nread;

	if ( ctx == NULL  ||  conn == NULL ) return;

	to_read = sizeof(buf);

	if ( conn->is_chunked ) {

		/*
		 * Chunked encoding: 1=chunk not read completely, 2=chunk read
		 * completely
		 */

		while ( conn->is_chunked == 1 ) {

			nread = httplib_read( ctx, conn, buf, to_read );
			if ( nread <= 0 ) break;
		}

	}
	
	else {
		/*
		 * Not chunked: content length is known
		 */

		while ( conn->consumed_content < conn->content_len ) {

			if ( to_read > (size_t)(conn->content_len - conn->consumed_content) ) {

				to_read = (size_t)(conn->content_len - conn->consumed_content);
			}

			nread = httplib_read( ctx, conn, buf, to_read );
			if (nread <= 0) break;
		}
	}

}  /* XX_httplib_discard_unread_request_data */
