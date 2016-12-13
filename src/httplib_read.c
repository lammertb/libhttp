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

static int httplib_read_inner(struct httplib_connection *conn, void *buf, size_t len) {

	int64_t n;
	int64_t buffered_len;
	int64_t nread;
	int64_t len64 = (int64_t)((len > INT_MAX) ? INT_MAX : len); /* since the return value is * int, we may not read more * bytes */
	const char *body;

	if (conn == NULL) return 0;

	/* If Content-Length is not set for a PUT or POST request, read until
	 * socket is closed */
	if (conn->consumed_content == 0 && conn->content_len == -1) {
		conn->content_len = INT64_MAX;
		conn->must_close = 1;
	}

	nread = 0;
	if (conn->consumed_content < conn->content_len) {
		/* Adjust number of bytes to read. */
		int64_t left_to_read = conn->content_len - conn->consumed_content;
		if (left_to_read < len64) {
			/* Do not read more than the total content length of the request.
			 */
			len64 = left_to_read;
		}

		/* Return buffered data */
		buffered_len = (int64_t)(conn->data_len) - (int64_t)conn->request_len
		               - conn->consumed_content;
		if (buffered_len > 0) {
			if (len64 < buffered_len) {
				buffered_len = len64;
			}
			body = conn->buf + conn->request_len + conn->consumed_content;
			memcpy(buf, body, (size_t)buffered_len);
			len64 -= buffered_len;
			conn->consumed_content += buffered_len;
			nread += buffered_len;
			buf = (char *)buf + buffered_len;
		}

		/* We have returned all buffered data. Read new data from the remote
		 * socket.
		 */
		if ((n = XX_httplib_pull_all(NULL, conn, (char *)buf, (int)len64)) >= 0) {
			nread += n;
		} else {
			nread = ((nread > 0) ? nread : n);
		}
	}
	return (int)nread;

}  /* httplib_read_inner */


static char httplib_getc(struct httplib_connection *conn) {

	char c;
	if (conn == NULL) return 0;

	conn->content_len++;
	if (httplib_read_inner(conn, &c, 1) <= 0) return (char)0;
	return c;

}  /* httplib_getc */


int httplib_read(struct httplib_connection *conn, void *buf, size_t len) {

	if (len > INT_MAX) len = INT_MAX;

	if (conn == NULL) return 0;

	if (conn->is_chunked) {
		size_t all_read = 0;

		while (len > 0) {

			if (conn->is_chunked == 2) {
				/* No more data left to read */
				return 0;
			}

			if (conn->chunk_remainder) {
				/* copy from the remainder of the last received chunk */
				long read_ret;
				size_t read_now =
				    ((conn->chunk_remainder > len) ? (len)
				                                   : (conn->chunk_remainder));

				conn->content_len += (int)read_now;
				read_ret = httplib_read_inner(conn, (char *)buf + all_read, read_now);
				all_read += (size_t)read_ret;

				conn->chunk_remainder -= read_now;
				len -= read_now;

				if (conn->chunk_remainder == 0) {
					/* the rest of the data in the current chunk has been read
					 */
					if ((httplib_getc(conn) != '\r') || (httplib_getc(conn) != '\n')) {
						/* Protocol violation */
						return -1;
					}
				}

			} else {
				/* fetch a new chunk */
				int i = 0;
				char lenbuf[64];
				char *end = 0;
				unsigned long chunkSize = 0;

				for (i = 0; i < ((int)sizeof(lenbuf) - 1); i++) {
					lenbuf[i] = httplib_getc(conn);
					if (i > 0 && lenbuf[i] == '\r' && lenbuf[i - 1] != '\r') {
						continue;
					}
					if (i > 1 && lenbuf[i] == '\n' && lenbuf[i - 1] == '\r') {
						lenbuf[i + 1] = 0;
						chunkSize = strtoul(lenbuf, &end, 16);
						if (chunkSize == 0) {
							/* regular end of content */
							conn->is_chunked = 2;
						}
						break;
					}
					if (!isalnum(lenbuf[i])) {
						/* illegal character for chunk length */
						return -1;
					}
				}
				if ((end == NULL) || (*end != '\r')) {
					/* chunksize not set correctly */
					return -1;
				}
				if (chunkSize == 0) {
					break;
				}

				conn->chunk_remainder = chunkSize;
			}
		}

		return (int)all_read;
	}
	return httplib_read_inner(conn, buf, len);

}  /* httplib_read */
