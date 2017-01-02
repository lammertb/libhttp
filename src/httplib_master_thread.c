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

static void	master_thread_run( void *thread_func_param );

/*
 * LIBHTTP_THREAD XX_httplib_master_thread( void *thread_func_param );
 *
 * The function XX_httplib_master_thread() runs the master thread of the
 * webserver. Due to operating system differences there are two different
 * function headers.
 */

LIBHTTP_THREAD XX_httplib_master_thread( void *thread_func_param ) {

	master_thread_run( thread_func_param );

	return LIBHTTP_THREAD_RETNULL;

}  /* XX_httplib_master_thread */



/*
 * static void master_thread_run( void *thread_func_param );
 *
 * The function master_thread_run() does the heavy lifting to run the master
 * thread of the LibHTTP webserver.
 */

static void master_thread_run(void *thread_func_param) {

	struct lh_ctx_t *ctx = (struct lh_ctx_t *)thread_func_param;
	struct httplib_workerTLS tls;
	struct pollfd *pfd;
	int i;

	if ( ctx == NULL ) return;

	XX_httplib_set_thread_name( ctx, "master" );

/*
 * Increase priority of the master thread
 */

#if defined(_WIN32)
	 SetThreadPriority( GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL );
#elif defined(USE_MASTER_THREAD_PRIORITY)
	int min_prio = sched_get_priority_min( SCHED_RR );
	int max_prio = sched_get_priority_max( SCHED_RR );

	if ((min_prio >= 0) && (max_prio >= 0)
	    && ((USE_MASTER_THREAD_PRIORITY) <= max_prio)
	    && ((USE_MASTER_THREAD_PRIORITY) >= min_prio)) {

		struct sched_param sched_param = {0};
		sched_param.sched_priority = (USE_MASTER_THREAD_PRIORITY);
		pthread_setschedparam( httplib_pthread_self(), SCHED_RR,  & sched_param );
	}
#endif

/*
 * Initialize thread local storage
 */

#if defined(_WIN32)
	tls.pthread_cond_helper_mutex = CreateEvent( NULL, FALSE, FALSE, NULL );
#endif
	httplib_pthread_setspecific( XX_httplib_sTlsKey, &tls );

	if ( ctx->callbacks.init_thread ) {

		/*
		 * Callback for the master thread (type 0)
		 */

		ctx->callbacks.init_thread( ctx, 0 );
	}

	/*
	 * Server starts *now*
	 */

	ctx->start_time = time( NULL );

	/*
	 * Start the server
	 */

	pfd = ctx->listening_socket_fds;

	while ( ctx->status == CTX_STATUS_RUNNING ) {

		for (i=0; i<(int)ctx->num_listening_sockets; i++) {

			pfd[i].fd     = ctx->listening_sockets[i].sock;
			pfd[i].events = POLLIN;
		}

		if ( httplib_poll( pfd, ctx->num_listening_sockets, 200 ) > 0 ) {

			for (i=0; i<(int)ctx->num_listening_sockets; i++) {

				/*
				 * NOTE(lsm): on QNX, poll() returns POLLRDNORM after the
				 * successful poll, and POLLIN is defined as
				 * (POLLRDNORM | POLLRDBAND)
				 * Therefore, we're checking pfd[i].revents & POLLIN, not
				 * pfd[i].revents == POLLIN.
				 */

				if ( ctx->status == CTX_STATUS_RUNNING  &&  (pfd[i].revents & POLLIN)) XX_httplib_accept_new_connection( & ctx->listening_sockets[i], ctx );
			}
		}
	}

	/*
	 * Here status is CTX_STATUS_STOPPING - Initiate shutdown.
	 */

	/*
	 * Stop signal received: somebody called httplib_stop. Quit.
	 */

	XX_httplib_close_all_listening_sockets( ctx );

	/*
	 * Wakeup workers that are waiting for connections to handle.
	 */

	httplib_pthread_mutex_lock( & ctx->thread_mutex );

#if defined(ALTERNATIVE_QUEUE)

	for (i=0; i<ctx->cfg_worker_threads; i++) {

		event_signal( ctx->client_wait_events[i]i );

		/*
		 * Since we know all sockets, we can shutdown the connections.
		 */

		if ( ctx->client_socks[i].in_use ) shutdown( ctx->client_socks[i].sock, SHUTDOWN_BOTH );
	}
#else
	httplib_pthread_cond_broadcast( & ctx->sq_full );
#endif
	httplib_pthread_mutex_unlock( & ctx->thread_mutex );

	/*
	 * Join all worker threads to avoid leaking threads.
	 */

	for (i=0; i<ctx->num_threads; i++) {

		if ( ctx->workerthreadids[i] != 0 ) httplib_pthread_join( ctx->workerthreadids[i], NULL );
	}

#if !defined(NO_SSL)
	if ( ctx->ssl_ctx != NULL ) XX_httplib_uninitialize_ssl( ctx );
#endif

#if defined(_WIN32)
	CloseHandle( tls.pthread_cond_helper_mutex );
#endif
	httplib_pthread_setspecific( XX_httplib_sTlsKey, NULL );

	/*
	 * Signal httplib_stop() that we're done.
	 * WARNING: This must be the very last thing this
	 * thread does, as ctx becomes invalid after this line.
	 */

	ctx->status = CTX_STATUS_TERMINATED;

}  /* master_thread_run */
