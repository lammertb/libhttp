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

int httplib_get_server_ports( const struct lh_ctx_t *ctx, int size, struct lh_slp_t *ports ) {

	int i;
	int cnt;

	if ( ctx == NULL  ||  ports == NULL  ||  size <= 0 ) return -1;

	memset( ports, 0, sizeof(*ports) * (size_t)size );

	if ( ctx->listening_sockets == NULL ) return -1;

	cnt = 0;

	for (i = 0; (i < size) && (i < (int)ctx->num_listening_sockets); i++) {

		ports[cnt].port = (ctx->listening_sockets[i].lsa.sa.sa_family == AF_INET6)
		        ? ntohs( ctx->listening_sockets[i].lsa.sin6.sin6_port )
		        : ntohs( ctx->listening_sockets[i].lsa.sin.sin_port   );

		ports[cnt].has_ssl      = ctx->listening_sockets[i].has_ssl;
		ports[cnt].has_redirect = ctx->listening_sockets[i].has_redir;

		if      ( ctx->listening_sockets[i].lsa.sa.sa_family == AF_INET  ) ports[cnt++].protocol = 1;
		else if ( ctx->listening_sockets[i].lsa.sa.sa_family == AF_INET6 ) ports[cnt++].protocol = 3;
	}

	return cnt;

}  /* httplib_get_server_ports */
