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
#include "httplib_utils.h"

/*
 * void XX_httplib_free_context( struct httplib_context *ctx );
 *
 * The function XX_httplib_free_context() is used to free the resources
 * associated with a context.
 */

void XX_httplib_free_context( struct httplib_context *ctx ) {

	int i;
	struct httplib_handler_info *tmp_rh;

	if ( ctx == NULL ) return;

	if ( ctx->callbacks.exit_context ) ctx->callbacks.exit_context( ctx );

	/*
	 * All threads exited, no sync is needed. Destroy thread mutex and
	 * condvars
	 */

	httplib_pthread_mutex_destroy( & ctx->thread_mutex );
#if defined(ALTERNATIVE_QUEUE)
	if ( ctx->client_socks != NULL ) {
		
		XX_httplib_free( ctx->client_socks );
		ctx->client_socks = NULL;
	}

	if ( ctx->client_wait_events != NULL ) {

		for (i=0; (unsigned)i < ctx->cfg_worker_threads; i++) event_destroy( ctx->client_wait_events[i] );
		XX_httplib_free( ctx->client_wait_events );

		ctx->client_wait_events = NULL;
	}
#else
	httplib_pthread_cond_destroy( & ctx->sq_empty );
	httplib_pthread_cond_destroy( & ctx->sq_full  );
#endif

	/*
	 * Destroy other context global data structures mutex
	 */

	httplib_pthread_mutex_destroy( & ctx->nonce_mutex );

#if defined(USE_TIMERS)
	timers_exit( ctx );
#endif

	/*
	 * Deallocate config parameters
	 */

	if ( ctx->access_log_file != NULL ) { httplib_free( ctx->access_log_file ); ctx->access_log_file = NULL; }
	if ( ctx->cgi_environment != NULL ) { httplib_free( ctx->cgi_environment ); ctx->cgi_environment = NULL; }
	if ( ctx->error_log_file  != NULL ) { httplib_free( ctx->error_log_file  ); ctx->error_log_file  = NULL; }
	if ( ctx->run_as_user     != NULL ) { httplib_free( ctx->run_as_user     ); ctx->run_as_user     = NULL; }

	for (i = 0; i < NUM_OPTIONS; i++) {

		if (ctx->cfg[i] != NULL) {
			
			httplib_free( ctx->cfg[i] );
			ctx->cfg[i] = NULL;
		}
	}

	/*
	 * Deallocate request handlers
	 */

	while ( ctx->handlers != NULL ) {

		tmp_rh        = ctx->handlers;
		ctx->handlers = tmp_rh->next;

		httplib_free( tmp_rh->uri );
		if ( tmp_rh != NULL ) httplib_free( tmp_rh );
	}

#ifndef NO_SSL

	/*
	 * Deallocate SSL context
	 */

	if ( ctx->ssl_ctx != NULL ) {
		
		SSL_CTX_free( ctx->ssl_ctx );
		ctx->ssl_ctx = NULL;
	}

#endif /* !NO_SSL */

	/*
	 * Deallocate worker thread ID array
	 */

	if ( ctx->workerthreadids != NULL ) {
		
		httplib_free( ctx->workerthreadids );
		ctx->workerthreadids = NULL;
	}

	/*
	 * Deallocate the tls variable
	 */

	if ( httplib_atomic_dec(&XX_httplib_sTlsInit) == 0 ) {
#if defined(_WIN32)
		DeleteCriticalSection( & global_log_file_lock );
#endif /* _WIN32 */
#if !defined(_WIN32)
		pthread_mutexattr_destroy( & XX_httplib_pthread_mutex_attr );
#endif

		httplib_pthread_key_delete( XX_httplib_sTlsKey );
	}

	/*
	 * deallocate system name string
	 */

	httplib_free( ctx->systemName );

	/*
	 * Deallocate context itself
	 */

	httplib_free( ctx );

}  /* XX_httplib_free_context */
