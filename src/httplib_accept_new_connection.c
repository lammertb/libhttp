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
#include "httplib_ssl.h"

/*
 * void XX_httplib_accept_new_connection( const struct socket *lostener, struct lh_ctx_t *ctx );
 *
 * The function XX_httplib_accept_new_connection() is used to process new
 * incoming connections to the server.
 */

void XX_httplib_accept_new_connection( const struct socket *listener, struct lh_ctx_t *ctx ) {

	struct socket so;
	char src_addr[IP_ADDR_STR_LEN];
	char error_string[ERROR_STRING_LEN];
	socklen_t len;
	int on;

	if ( listener == NULL ) return;

	on  = 1;
	len = sizeof(so.rsa);

	so.sock = accept( listener->sock, &so.rsa.sa, &len );
	if ( so.sock == INVALID_SOCKET ) return;

	if ( ! XX_httplib_check_acl( ctx, ntohl(*(uint32_t *)&so.rsa.sin.sin_addr )) ) {

		XX_httplib_sockaddr_to_string( src_addr, sizeof(src_addr), &so.rsa );
		httplib_cry( LH_DEBUG_INFO, ctx, NULL, "%s: %s is not allowed to connect", __func__, src_addr );
		closesocket( so.sock );
		so.sock = INVALID_SOCKET;
	}
	
	else {

		/*
		 * Put so socket structure into the queue
		 */

		XX_httplib_set_close_on_exec( so.sock );

		so.has_ssl   = listener->has_ssl;
		so.has_redir = listener->has_redir;

		if ( getsockname( so.sock, &so.lsa.sa, &len ) != 0 ) {

			httplib_cry( LH_DEBUG_ERROR, ctx, NULL, "%s: getsockname() failed: %s", __func__, httplib_error_string( ERRNO, error_string, ERROR_STRING_LEN ) );
		}

		/*
		 * Set TCP keep-alive. This is needed because if HTTP-level keep-alive
		 * is enabled, and client resets the connection, server won't get
		 * TCP FIN or RST and will keep the connection open forever. With
		 * TCP keep-alive, next keep-alive handshake will figure out that
		 * the client is down and will close the server end.
		 * Thanks to Igor Klopov who suggested the patch.
		 */

		if ( setsockopt( so.sock, SOL_SOCKET, SO_KEEPALIVE, (SOCK_OPT_TYPE)&on, sizeof(on) ) != 0 ) {

			httplib_cry( LH_DEBUG_ERROR, ctx, NULL, "%s: setsockopt(SOL_SOCKET SO_KEEPALIVE) failed: %s", __func__, httplib_error_string( ERRNO, error_string, ERROR_STRING_LEN ) );
		}

		/*
		 * Disable TCP Nagle's algorithm. Normally TCP packets are coalesced
		 * to effectively fill up the underlying IP packet payload and
		 * reduce the overhead of sending lots of small buffers. However
		 * this hurts the server's throughput (ie. operations per second)
		 * when HTTP 1.1 persistent connections are used and the responses
		 * are relatively small (eg. less than 1400 bytes).
		 */

		if ( ctx->tcp_nodelay  &&  XX_httplib_set_tcp_nodelay( so.sock, 1 ) != 0 ) {

			httplib_cry( LH_DEBUG_ERROR, ctx, NULL, "%s: setsockopt(IPPROTO_TCP TCP_NODELAY) failed: %s", __func__, httplib_error_string( ERRNO, error_string, ERROR_STRING_LEN ) );
		}

		if ( ctx->request_timeout > 0 ) XX_httplib_set_sock_timeout( so.sock, ctx->request_timeout );

		XX_httplib_produce_socket( ctx, &so );
	}

}  /* XX_httplib_accept_new_connection */
