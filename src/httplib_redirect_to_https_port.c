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
 * void XX_httplib_redirect_to_https_port( const struct lh_ctx_t *ctx, struct lh_con_t *conn, int ssl_index );
 *
 * The function XX_httplib_redirect_to_https_port() redirects a request to an
 * encrypted connection over HTTPS.
 */

void XX_httplib_redirect_to_https_port( const struct lh_ctx_t *ctx, struct lh_con_t *conn, int ssl_index ) {

	char host[1024+1];
	const char *host_header;
	size_t hostlen;
	char *pos;

	if ( ctx == NULL  ||  conn == NULL ) return;

	host_header = httplib_get_header(conn, "Host");
	hostlen     = sizeof( host );

	if ( host_header != NULL ) {

		httplib_strlcpy( host, host_header, hostlen );
		host[hostlen - 1] = '\0';
		pos = strchr(host, ':');
		if (pos != NULL) *pos = '\0';
	}
	
	else {
		/*
		 * Cannot get host from the Host: header.
		 * Fallback to our IP address.
		 */

		XX_httplib_sockaddr_to_string( host, hostlen, &conn->client.lsa );
	}

	/*
	 * Send host, port, uri and (if it exists) ?query_string
	 */

	httplib_printf( ctx, conn, "HTTP/1.1 302 Found\r\nLocation: https://%s:%d%s%s%s\r\n\r\n",
	          host,
	          (ctx->listening_sockets[ssl_index].lsa.sa.sa_family == AF_INET6)
	              ? (int)ntohs( ctx->listening_sockets[ssl_index].lsa.sin6.sin6_port )
	              : (int)ntohs( ctx->listening_sockets[ssl_index].lsa.sin.sin_port   ),
	          conn->request_info.local_uri,
	          (conn->request_info.query_string == NULL) ? "" : "?",
	          (conn->request_info.query_string == NULL) ? "" : conn->request_info.query_string);

}  /* XX_httplib_redirect_to_https_port */
