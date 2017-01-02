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
#include "httplib_pthread.h"
#include "httplib_ssl.h"

/*
 * void XX_httplib_close_connection( struct lh_ctx_t *ctx, struct lh_con_t *conn );
 *
 * The function XX_httplib_close_connection() is the internal function which
 * does the heavy lifting to close a connection.
 */

void XX_httplib_close_connection( struct lh_ctx_t *ctx, struct lh_con_t *conn ) {

	if ( ctx == NULL  ||  conn == NULL ) return;

	/*
	 * call the connection_close callback if assigned
	 */

	if ( ctx->callbacks.connection_close != NULL  &&  ctx->ctx_type == CTX_TYPE_SERVER ) ctx->callbacks.connection_close( ctx, conn );

	httplib_lock_connection( conn );

	conn->must_close = true;

#ifndef NO_SSL
	if ( conn->ssl != NULL ) {

		/*
		 * Run SSL_shutdown twice to ensure completly close SSL connection
		 */

		SSL_shutdown( conn->ssl );
		SSL_free(     conn->ssl );

		/*
		 * Avoid CRYPTO_cleanup_all_ex_data(); See discussion:
		 * https://wiki.openssl.org/index.php/Talk:Library_Initialization
		 */

		ERR_remove_state( 0 );
		conn->ssl = NULL;
	}
#endif
	if ( conn->client.sock != INVALID_SOCKET ) {

		XX_httplib_close_socket_gracefully( ctx, conn );
		conn->client.sock = INVALID_SOCKET;
	}

	httplib_unlock_connection( conn );

}  /* XX_httplib_close_connection */



/*
 * void httplib_close_connection( const struct lh_ctx_t *ctx, struct lh_con_t *conn );
 *
 * The function httplib_close_connection() closes the connection passed as a
 * parameter to this function. The function does not return a success or
 * failure value.
 */

void httplib_close_connection( struct lh_ctx_t *ctx, struct lh_con_t *conn ) {

	struct lh_ctx_t *client_ctx;
	int i;

	if ( ctx == NULL  ||  conn == NULL ) return;

	if ( ctx->ctx_type == CTX_TYPE_CLIENT ) {

		client_ctx  = ctx;
		ctx->status = CTX_STATUS_STOPPING;
	}

	else client_ctx = NULL;

#ifndef NO_SSL
	if ( conn->client_ssl_ctx != NULL ) {
		
		SSL_CTX_free( (SSL_CTX *)conn->client_ssl_ctx );
		conn->client_ssl_ctx = NULL;
	}
#endif
	XX_httplib_close_connection( ctx, conn );

	if ( client_ctx != NULL ) {

		/*
		 * join worker thread and free context
		 */

		for (i=0; i<client_ctx->num_threads; i++) {

			if ( client_ctx->workerthreadids[i] != 0 ) httplib_pthread_join( client_ctx->workerthreadids[i], NULL );
		}

		client_ctx->workerthreadids = httplib_free( client_ctx->workerthreadids );
		client_ctx                  = httplib_free( client_ctx                  );

		httplib_pthread_mutex_destroy( & conn->mutex );

		conn = httplib_free( conn );
	}

}  /* httplib_close_connection */
