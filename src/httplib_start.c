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

/*
 * struct lh_ctx_t *httplib_start( const struct lh_clb_t *callbacks, void *user_data, const struct lh_opt_t *options );
 *
 * The function httplib_start() functions as the main entry point for the LibHTTP
 * server. The function starts all threads and when finished returns the
 * context to the running server for future reference.
 */

struct lh_ctx_t *httplib_start( const struct lh_clb_t *callbacks, void *user_data, const struct lh_opt_t *options ) {

	struct lh_ctx_t *ctx;
	int i;
	void (*exit_callback)(struct lh_ctx_t *ctx);
	struct httplib_workerTLS tls;

	/*
	 * No memory for the ctx structure is the only error which we
	 * don't log through httplib_cry() for the simple reason that we do not
	 * have enough configured yet to make that function working. Having an
	 * OOM in this state of the process though should be noticed by the
	 * calling process in other parts of their execution anyway.
	 */

	exit_callback = NULL;
	ctx           = httplib_calloc( 1, sizeof(struct lh_ctx_t) );

	if ( ctx == NULL ) return NULL;

	/*
	 * Setup callback functions very early. This is necessary to make the
	 * log_message() callback function available in case an error occurs.
	 *
	 * We first set the exit_context() callback to NULL becasue no proper
	 * context is available yet and we do not want to mess up things if the
	 * function exits and that callback is given a half-decent structure to
	 * work on and without a call to init_context() before.
	 */

	if ( callbacks != NULL ) {

		ctx->callbacks              = *callbacks;
		exit_callback               = callbacks->exit_context;
		ctx->callbacks.exit_context = NULL;
	}

	/*
	 * Random number generator will initialize at the first call
	 */

	ctx->auth_nonce_mask = httplib_get_random() ^ (uint64_t)(ptrdiff_t)(options);

	if ( httplib_atomic_inc( & XX_httplib_sTlsInit ) == 1 ) {

#if defined(_WIN32)
		InitializeCriticalSection( & global_log_file_lock );
#else  /* _WIN32 */
		pthread_mutexattr_init(    & XX_httplib_pthread_mutex_attr                          );
		pthread_mutexattr_settype( & XX_httplib_pthread_mutex_attr, PTHREAD_MUTEX_RECURSIVE );
#endif  /* _WIN32 */

#if !defined(NO_SSL)
		if ( httplib_pthread_key_create( & XX_httplib_sTlsKey, XX_httplib_tls_dtor ) != 0 ) {

			/*
			 * Fatal error - abort start. However, this situation should
			 * never occur in practice.
			 */

			httplib_atomic_dec( & XX_httplib_sTlsInit );
			httplib_cry( LH_DEBUG_CRASH, ctx, NULL, "%s: cannot initialize thread local storage", __func__ );
			ctx = httplib_free( ctx );

			return NULL;
		}
#endif  /* NO_SSL */
	}
	
	else {
		/*
		 * TODO (low): istead of sleeping, check if XX_httplib_sTlsKey is already
		 * initialized.
		 */

		httplib_sleep( 1 );
	}

	tls.thread_idx = (unsigned)httplib_atomic_inc( & XX_httplib_thread_idx_max );
#if defined(_WIN32)
	tls.pthread_cond_helper_mutex = NULL;
#endif
	httplib_pthread_setspecific( XX_httplib_sTlsKey, & tls );

	if ( httplib_pthread_mutex_init( & ctx->thread_mutex, &XX_httplib_pthread_mutex_attr )  ) return XX_httplib_abort_start( ctx, "Cannot initialize thread mutex"          );
#if !defined(ALTERNATIVE_QUEUE)
	if ( httplib_pthread_cond_init(  & ctx->sq_empty, NULL )                                ) return XX_httplib_abort_start( ctx, "Cannot initialize empty queue condition" );
	if ( httplib_pthread_cond_init(  & ctx->sq_full,  NULL )                                ) return XX_httplib_abort_start( ctx, "Cannot initialize full queue condition"  );
#endif
	if ( httplib_pthread_mutex_init( & ctx->nonce_mutex,  & XX_httplib_pthread_mutex_attr ) ) return XX_httplib_abort_start( ctx, "Cannot initialize nonce mutex"           );

	ctx->user_data = user_data;
	ctx->handlers  = NULL;

	if ( XX_httplib_init_options( ctx )             ) return NULL;
	if ( XX_httplib_process_options( ctx, options ) ) return NULL;

	XX_httplib_get_system_name( & ctx->systemName );

	/*
	 * NOTE(lsm): order is important here. SSL certificates must
	 * be initialized before listening ports. UID must be set last.
	 */

	if ( ! XX_httplib_set_gpass_option( ctx ) ) return XX_httplib_abort_start( ctx, "Error setting gpass option" );
#if !defined(NO_SSL)
	if ( ! XX_httplib_set_ssl_option(   ctx ) ) return XX_httplib_abort_start( ctx, "Error setting SSL option"   );
#endif
	if ( ! XX_httplib_set_ports_option( ctx ) ) return XX_httplib_abort_start( ctx, "Error setting ports option" );
	if ( ! XX_httplib_set_uid_option(   ctx ) ) return XX_httplib_abort_start( ctx, "Error setting UID option"   );
	if ( ! XX_httplib_set_acl_option(   ctx ) ) return XX_httplib_abort_start( ctx, "Error setting ACL option"   );

#if !defined(_WIN32)

	/*
	 * Ignore SIGPIPE signal, so if browser cancels the request, it
	 * won't kill the whole process.
	 */

	signal( SIGPIPE, SIG_IGN );

#endif /* !_WIN32 */

	if ( ctx->num_threads < 1 ) return XX_httplib_abort_start( ctx, "No worker thread number specified" );

	if ( ctx->num_threads > MAX_WORKER_THREADS ) return XX_httplib_abort_start( ctx, "Too many worker threads" );

	if ( ctx->num_threads > 0 ) {

		ctx->workerthreadids = httplib_calloc( ctx->num_threads, sizeof(pthread_t) );
		if ( ctx->workerthreadids == NULL ) return XX_httplib_abort_start( ctx, "Not enough memory for worker thread ID array" );

#if defined(ALTERNATIVE_QUEUE)

		ctx->client_wait_events = httplib_calloc( sizeof(ctx->client_wait_events[0]), ctx->num_threads );
		if ( ctx->client_wait_events == NULL ) return XX_httplib_abort_start( ctx, "Not enough memory for worker event array" );

		ctx->client_socks = httplib_calloc( sizeof(ctx->client_socks[0]), ctx->num_threads );
		if ( ctx->client_socks == NULL ) return XX_httplib_abort_start( ctx, "Not enough memory for worker socket array" );

		for (i=0; i<ctx->num_threads; i++) {

			ctx->client_wait_events[i] = event_create();
			if ( ctx->client_wait_events[i] == 0 ) return XX_httplib_abort_start( ctx, "Error creating worker event %u", i );
		}
#endif
	}

#if defined(USE_TIMERS)
	if ( timers_init( ctx ) != 0 ) return XX_httplib_abort_start( ctx, "Error creating timers" );
#endif

	/*
	 * Context has been created - init user libraries
	 *
	 * Context has been properly setup. It is now safe to use exit_context
	 * in case the system needs a shutdown.
	 */

	if ( ctx->callbacks.init_context != NULL ) ctx->callbacks.init_context( ctx );

	ctx->callbacks.exit_context = exit_callback;
	ctx->ctx_type               = CTX_TYPE_SERVER;

	/*
	 * Start master (listening) thread
	 */

	XX_httplib_start_thread_with_id( XX_httplib_master_thread, ctx, &ctx->masterthreadid );

	/*
	 * Start worker threads
	 */
	for (i=0; i<ctx->num_threads; i++) {

		struct worker_thread_args *wta;
	       
		wta = httplib_calloc( 1, sizeof(struct worker_thread_args) );

		if ( wta != NULL ) {

			wta->ctx   = ctx;
			wta->index = (int)i;
		}

		if ( wta == NULL  ||  XX_httplib_start_thread_with_id( XX_httplib_worker_thread, wta, &ctx->workerthreadids[i] ) != 0 ) {

			/*
			 * thread was not created
			 */

			wta = httplib_free( wta );

			if ( i > 0 ) httplib_cry( LH_DEBUG_ERROR, ctx, NULL, "%s: cannot start worker thread %i: error %ld", __func__, i+1, (long)ERRNO );
			
			else return XX_httplib_abort_start( ctx, "Cannot create worker threads: error %ld", (long)ERRNO );

			break;
		}
	}

	httplib_pthread_setspecific( XX_httplib_sTlsKey, NULL );

	return ctx;

}  /* httplib_start */
