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
 * void XX_httplib_close_socket_gracefully( struct lh_ctx_t *ctx, struct lh_con_t *conn );
 *
 * The function XX_httplib_close_socket_gracefully() closes a socket in a
 * graceful way.
 */

void XX_httplib_close_socket_gracefully( struct lh_ctx_t *ctx, struct lh_con_t *conn ) {

#if defined(_WIN32)
	char buf[MG_BUF_LEN];
	int n;
#endif
	char error_string[ERROR_STRING_LEN];
	struct linger linger;
	int error_code;
	socklen_t opt_len;

	if ( ctx == NULL  ||  conn == NULL ) return;

	error_code = 0;
	opt_len    = sizeof(error_code);

	/*
	 * Set linger option to avoid socket hanging out after close. This
	 * prevent ephemeral port exhaust problem under high QPS.
	 */

	linger.l_onoff  = 1;
	linger.l_linger = 1;

	getsockopt( conn->client.sock, SOL_SOCKET, SO_ERROR, (char *)&error_code, &opt_len);

	if (error_code == ECONNRESET) {
		/* Socket already closed by client/peer, close socket without linger */
	}
	
	else {
		if ( setsockopt( conn->client.sock, SOL_SOCKET, SO_LINGER, (char *)&linger, sizeof(linger) ) != 0 ) {

			httplib_cry( LH_DEBUG_ERROR, ctx, conn, "%s: setsockopt(SOL_SOCKET SO_LINGER) failed: %s", __func__, httplib_error_string( ERRNO, error_string, ERROR_STRING_LEN ) );
		}
	}

	/*
	 * Send FIN to the client
	 */

	shutdown( conn->client.sock, SHUTDOWN_WR );
	XX_httplib_set_non_blocking_mode( conn->client.sock );

#if defined(_WIN32)
	/*
	 * Read and discard pending incoming data. If we do not do that and close
	 * the socket, the data in the send buffer may be discarded. This
	 * behaviour is seen on Windows, when client keeps sending data
	 * when server decides to close the connection; then when client
	 * does recv() it gets no data back.
	 */

	do {
		n = XX_httplib_pull( ctx, NULL, conn, buf, sizeof(buf), 1E-10 /* TODO: allow 0 as timeout */ );
	} while ( n > 0 );
#endif

	/*
	 * Now we know that our FIN is ACK-ed, safe to close
	 */

	closesocket( conn->client.sock );

	conn->client.sock = INVALID_SOCKET;

}  /* XX_httplib_close_socket_gracefully */
