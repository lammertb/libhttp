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
 * struct mg_connection *mg_download();
 *
 * The function mg_download() is used to download a file from a remote location
 * and returns a pointer to the connection on success, or NULL on error.
 */

struct mg_connection * mg_download( const char *host, int port, int use_ssl, char *ebuf, size_t ebuf_len, const char *fmt, ... ) {

	struct mg_connection *conn;
	va_list ap;
	int i;
	int reqerr;

	va_start(ap, fmt);
	ebuf[0] = '\0';

	/* open a connection */
	conn = mg_connect_client(host, port, use_ssl, ebuf, ebuf_len);

	if (conn != NULL) {
		i = XX_httplib_vprintf(conn, fmt, ap);
		if (i <= 0) {
			XX_httplib_snprintf(conn, NULL, ebuf, ebuf_len, "%s", "Error sending request");
		} else {
			XX_httplib_getreq(conn, ebuf, ebuf_len, &reqerr);

			/* TODO: 1) uri is deprecated;
			 *       2) here, ri.uri is the http response code */
			conn->request_info.uri = conn->request_info.request_uri;
		}
	}

	/* if an error occured, close the connection */
	if (ebuf[0] != '\0' && conn != NULL) {
		mg_close_connection(conn);
		conn = NULL;
	}

	va_end(ap);
	return conn;

}  /* mg_download */
