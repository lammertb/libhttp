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
 * void XX_httplib_free_context( struct lh_ctx_t *ctx );
 *
 * The function XX_httplib_free_context() is used to free the resources
 * associated with a context.
 */

void XX_httplib_free_context( struct lh_ctx_t *ctx ) {

	struct httplib_handler_info *tmp_rh;

	if ( ctx == NULL ) return;

	if ( ctx->callbacks.exit_context != NULL ) ctx->callbacks.exit_context( ctx );

	/*
	 * All threads exited, no sync is needed. Destroy thread mutex and
	 * condvars
	 */

	httplib_pthread_mutex_destroy( & ctx->thread_mutex );
#if defined(ALTERNATIVE_QUEUE)
	ctx->client_socks = httplib_free( ctx->client_socks );

	if ( ctx->client_wait_events != NULL ) {

		for (i=0; (unsigned)i < ctx->cfg_worker_threads; i++) event_destroy( ctx->client_wait_events[i] );
		ctx->client_wait_events = httplib_free( ctx->client_wait_events );
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

	XX_httplib_free_config_options( ctx );

	/*
	 * Deallocate request handlers
	 */

	while ( ctx->handlers != NULL ) {

		tmp_rh        = ctx->handlers;
		ctx->handlers = tmp_rh->next;

		tmp_rh->uri = httplib_free( tmp_rh->uri );
		tmp_rh      = httplib_free( tmp_rh      );
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

	ctx->workerthreadids = httplib_free( ctx->workerthreadids );

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

	ctx->systemName = httplib_free( ctx->systemName );

	/*
	 * Deallocate context itself
	 */

	ctx = httplib_free( ctx );

}  /* XX_httplib_free_context */
