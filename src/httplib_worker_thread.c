/* 
 * Copyright (c) 2016-2019 Lammert Bies
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
#include "httplib_utils.h"

static void	worker_thread_run( struct worker_thread_args *thread_args );

/*
 * ... XX_httplib_worker_thread( void *thread_func_param );
 *
 * The function XX_httplib_worker_thread() is the wrapper function around a
 * worker thread. Calling convention of the function differs depending on the
 * operating system.
 */

LIBHTTP_THREAD XX_httplib_worker_thread( void *thread_func_param ) {

	struct worker_thread_args *pwta;

	if ( thread_func_param != NULL ) {

		pwta = thread_func_param;

		worker_thread_run( pwta );
		thread_func_param = httplib_free( thread_func_param );
	}

	return LIBHTTP_THREAD_RETNULL;

}  /* XX_httplib_worker_thread */



/*
 * static void worker_thread_run( struct worker_thread_args *thread_args );
 *
 * The function worker_thread_run is the function which does the heavy lifting
 * to run a worker thread.
 */

static void worker_thread_run( struct worker_thread_args *thread_args ) {

	struct lh_ctx_t *ctx;
	struct lh_con_t *conn;
	struct httplib_workerTLS tls;
#if !defined(NO_SSL)
	union {
		const void *	con;
		void *		var;
	} ptr;
#endif  /* NO_SSL */

	if ( thread_args == NULL ) return;

	ctx = thread_args->ctx;

	XX_httplib_set_thread_name( ctx, "worker" );

	tls.thread_idx = (unsigned)httplib_atomic_inc( & XX_httplib_thread_idx_max );
#if defined(_WIN32)
	tls.pthread_cond_helper_mutex = CreateEvent( NULL, FALSE, FALSE, NULL );
#endif

	if ( ctx->callbacks.init_thread != NULL ) ctx->callbacks.init_thread( ctx, 1 ); /* call init_thread for a worker thread (type 1) */

	conn = httplib_calloc( 1, sizeof(*conn) + MAX_REQUEST_SIZE );
	if ( conn == NULL ) httplib_cry( LH_DEBUG_ERROR, ctx, NULL, "%s: cannot create new connection struct, OOM", __func__ );
	
	else {
		httplib_pthread_setspecific( XX_httplib_sTlsKey, &tls );

		conn->buf_size               = MAX_REQUEST_SIZE;
		conn->buf                    = (char *)(conn+1);
		conn->thread_index           = thread_args->index;
		conn->request_info.user_data = ctx->user_data;

		/*
		 * Allocate a mutex for this connection to allow communication both
		 * within the request handler and from elsewhere in the application
		 */

		httplib_pthread_mutex_init( & conn->mutex, &XX_httplib_pthread_mutex_attr );

		/*
		 * Call XX_httplib_consume_socket() even when ctx->stop_flag > 0, to let it
		 * signal sq_empty condvar to wake up the master waiting in
		 * produce_socket()
		 */

		while ( XX_httplib_consume_socket( ctx, &conn->client, conn->thread_index ) ) {

			conn->conn_birth_time = time( NULL );

			/*
			 * Fill in IP, port info early so even if SSL setup below fails,
			 * error handler would have the corresponding info.
			 * Thanks to Johannes Winkelmann for the patch.
			 */

			if ( conn->client.rsa.sa.sa_family == AF_INET6 ) conn->request_info.remote_port = ntohs( conn->client.rsa.sin6.sin6_port );
			else                                             conn->request_info.remote_port = ntohs( conn->client.rsa.sin.sin_port   );

			XX_httplib_sockaddr_to_string( conn->request_info.remote_addr, sizeof(conn->request_info.remote_addr), &conn->client.rsa );

			conn->request_info.has_ssl = conn->client.has_ssl;

			if ( conn->client.has_ssl ) {

#ifndef NO_SSL
				if ( XX_httplib_sslize( ctx, conn, ctx->ssl_ctx, SSL_accept ) ) {

					XX_httplib_ssl_get_client_cert_info(    conn );
					XX_httplib_process_new_connection( ctx, conn );

					if ( conn->request_info.client_cert != NULL ) {

						ptr.con = conn->request_info.client_cert->subject; ptr.var = httplib_free( ptr.var );
						ptr.con = conn->request_info.client_cert->issuer;  ptr.var = httplib_free( ptr.var );
						ptr.con = conn->request_info.client_cert->serial;  ptr.var = httplib_free( ptr.var );
						ptr.con = conn->request_info.client_cert->finger;  ptr.var = httplib_free( ptr.var );

						conn->request_info.client_cert = httplib_free( conn->request_info.client_cert );
					}
				}
#endif
			}
			
			else XX_httplib_process_new_connection( ctx, conn );

			XX_httplib_close_connection( ctx, conn );
		}
	}

	httplib_pthread_setspecific( XX_httplib_sTlsKey, NULL );
#if defined(_WIN32)
	CloseHandle( tls.pthread_cond_helper_mutex );
#endif
	httplib_pthread_mutex_destroy( & conn->mutex );
	conn = httplib_free( conn );

}  /* worker_thread_run */
