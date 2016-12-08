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
 * void XX_httplib_close_connection( struct mg_connection *conn );
 *
 * The function XX_httplib_close_connection() is the internal function which
 * does the heavy lifting to close a connection.
 */

void XX_httplib_close_connection( struct mg_connection *conn ) {

	if ( conn == NULL  ||  conn->ctx == NULL ) return;

	/* call the connection_close callback if assigned */
	if ((conn->ctx->callbacks.connection_close != NULL) && (conn->ctx->context_type == 1)) {
		conn->ctx->callbacks.connection_close(conn);
	}

	mg_lock_connection( conn );

	conn->must_close = 1;

#ifndef NO_SSL
	if (conn->ssl != NULL) {
		/* Run SSL_shutdown twice to ensure completly close SSL connection
		 */
		SSL_shutdown(conn->ssl);
		SSL_free(conn->ssl);
		/* Avoid CRYPTO_cleanup_all_ex_data(); See discussion:
		 * https://wiki.openssl.org/index.php/Talk:Library_Initialization */
		ERR_remove_state(0);
		conn->ssl = NULL;
	}
#endif
	if ( conn->client.sock != INVALID_SOCKET ) {

		XX_httplib_close_socket_gracefully( conn );
		conn->client.sock = INVALID_SOCKET;
	}

	mg_unlock_connection( conn );

}  /* XX_httplib_close_connection */



/*
 * void mg_close_connection( struct mg_connection *conn );
 *
 * The function mg_close_connection() closes the connection passed as a
 * parameter to this function. The function does not return a success or
 * failure value.
 */

void mg_close_connection( struct mg_connection *conn ) {

	struct mg_context *client_ctx = NULL;
	unsigned int i;

	if ( conn == NULL ) return;

	if ( conn->ctx->context_type == 2 ) {

		client_ctx = conn->ctx;
		/* client context: loops must end */
		conn->ctx->stop_flag = 1;
	}

#ifndef NO_SSL
	if (conn->client_ssl_ctx != NULL) SSL_CTX_free((SSL_CTX *)conn->client_ssl_ctx);
#endif
	XX_httplib_close_connection(conn);
	if (client_ctx != NULL) {
		/* join worker thread and free context */
		for (i = 0; i < client_ctx->cfg_worker_threads; i++) {
			if (client_ctx->workerthreadids[i] != 0) XX_httplib_join_thread(client_ctx->workerthreadids[i]);
		}

		XX_httplib_free(client_ctx->workerthreadids);
		XX_httplib_free(client_ctx);
		pthread_mutex_destroy(&conn->mutex);
		XX_httplib_free(conn);
	}

}  /* mg_close_connection */
