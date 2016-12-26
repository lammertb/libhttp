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
#include "httplib_string.h"
#include "httplib_utils.h"

static struct httplib_context *		cleanup( struct httplib_context *ctx, PRINTF_FORMAT_STRING(const char *fmt), ...) PRINTF_ARGS(2, 3);

/*
 * struct httplib_context *httplib_start( const struct httplib_callbacks *callbacks, void *user_data, const char **options );
 *
 * The function httplib_start() functions as the main entry point for the LibHTTP
 * server. The function starts all threads and when finished returns the
 * context to the running server for future reference.
 */

struct httplib_context *httplib_start( const struct httplib_callbacks *callbacks, void *user_data, const char **options ) {

	struct httplib_context *ctx;
	const char *name;
	const char *value;
	const char *default_value;
	int idx;
	int workerthreadcount;
	unsigned int i;
	void (*exit_callback)(const struct httplib_context *ctx) = NULL;
	struct httplib_workerTLS tls;

#if defined(_WIN32)
	WSADATA data;
	WSAStartup(MAKEWORD(2, 2), &data);
#endif /* _WIN32 */

	ctx = httplib_calloc( 1, sizeof(*ctx) );
	if ( ctx == NULL ) return NULL;

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

		if ( httplib_pthread_key_create( & XX_httplib_sTlsKey, XX_httplib_tls_dtor ) != 0 ) {

			/*
			 * Fatal error - abort start. However, this situation should
			 * never occur in practice.
			 */

			httplib_atomic_dec( & XX_httplib_sTlsInit );
			httplib_cry( ctx, NULL, "Cannot initialize thread local storage" );
			httplib_free( ctx );

			return NULL;
		}
	}
	
	else {
		/* TODO (low): istead of sleeping, check if XX_httplib_sTlsKey is already
		 * initialized. */
		httplib_sleep( 1 );
	}

	tls.is_master  = -1;
	tls.thread_idx = (unsigned)httplib_atomic_inc( & XX_httplib_thread_idx_max );
#if defined(_WIN32)
	tls.pthread_cond_helper_mutex = NULL;
#endif
	httplib_pthread_setspecific( XX_httplib_sTlsKey, & tls );

	if ( httplib_pthread_mutex_init( & ctx->thread_mutex, &XX_httplib_pthread_mutex_attr )  ) return cleanup( ctx, "Cannot initialize thread mutex"          );
#if !defined(ALTERNATIVE_QUEUE)
	if ( httplib_pthread_cond_init(  & ctx->sq_empty, NULL )                                ) return cleanup( ctx, "Cannot initialize empty queue condition" );
	if ( httplib_pthread_cond_init(  & ctx->sq_full,  NULL )                                ) return cleanup( ctx, "Cannot initialize full queue condition"  );
#endif
	if ( httplib_pthread_mutex_init( & ctx->nonce_mutex,  & XX_httplib_pthread_mutex_attr ) ) return cleanup( ctx, "Cannot initialize nonce mutex"           );

	if ( callbacks != NULL ) {

		ctx->callbacks              = *callbacks;
		exit_callback               = callbacks->exit_context;
		ctx->callbacks.exit_context = 0;
	}

	ctx->user_data = user_data;
	ctx->handlers  = NULL;

	while ( options  &&  (name = *options++) != NULL ) {

		idx = XX_httplib_get_option_index( name );
		if ( idx                   == -1   ) return cleanup( ctx, "Invalid option: %s",               name );
		if ( (value = *options++)  == NULL ) return cleanup( ctx , "%s: option value cannot be NULL", name );

		if ( ctx->cfg[idx] != NULL ) {

			httplib_cry( ctx, NULL, "warning: %s: duplicate option", name );
			httplib_free( ctx->cfg[idx] );
		}

		ctx->cfg[idx] = httplib_strdup( value );
	}

	/*
	 * Set default value if needed
	 */

	for (i=0; XX_httplib_config_options[i].name != NULL; i++) {

		default_value = XX_httplib_config_options[i].default_value;
		if ( ctx->cfg[i] == NULL  &&  default_value != NULL ) ctx->cfg[i] = httplib_strdup( default_value );
	}

#if defined(NO_FILES)
	if ( ctx->cfg[DOCUMENT_ROOT] != NULL ) return cleanup( ctx, "Document root must not be set" );
#endif

	XX_httplib_get_system_name( & ctx->systemName );

	/*
	 * NOTE(lsm): order is important here. SSL certificates must
	 * be initialized before listening ports. UID must be set last.
	 */

	if ( ! XX_httplib_set_gpass_option( ctx ) ) return cleanup( ctx, "Error setting gpass option" );
#if !defined(NO_SSL)
	if ( ! XX_httplib_set_ssl_option(   ctx ) ) return cleanup( ctx, "Error setting SSL option"   );
#endif
	if ( ! XX_httplib_set_ports_option( ctx ) ) return cleanup( ctx, "Error setting ports option" );
	if ( ! XX_httplib_set_uid_option(   ctx ) ) return cleanup( ctx, "Error setting UID option"   );
	if ( ! XX_httplib_set_acl_option(   ctx ) ) return cleanup( ctx, "Error setting ACL option"   );

#if !defined(_WIN32)

	/*
	 * Ignore SIGPIPE signal, so if browser cancels the request, it
	 * won't kill the whole process.
	 */

	signal( SIGPIPE, SIG_IGN );

#endif /* !_WIN32 */

	if ( ctx->cfg[NUM_THREADS] == NULL ) return cleanup( ctx, "No worker thread number specified" );

	workerthreadcount = atoi( ctx->cfg[NUM_THREADS] );

	if ( workerthreadcount > MAX_WORKER_THREADS ) return cleanup( ctx, "Too many worker threads" );

	if ( workerthreadcount > 0 ) {

		ctx->cfg_worker_threads = (unsigned int)(workerthreadcount);
		ctx->workerthreadids    = httplib_calloc( ctx->cfg_worker_threads, sizeof(pthread_t) );
		if ( ctx->workerthreadids == NULL ) return cleanup( ctx, "Not enough memory for worker thread ID array" );

#if defined(ALTERNATIVE_QUEUE)

		ctx->client_wait_events = httplib_calloc( sizeof(ctx->client_wait_events[0]), ctx->cfg_worker_threads );
		if ( ctx->client_wait_events == NULL ) return cleanup( ctx, "Not enough memory for worker event array" );

		ctx->client_socks = httplib_calloc( sizeof(ctx->client_socks[0]), ctx->cfg_worker_threads );
		if ( ctx->client_socks == NULL ) return cleanup( ctx, "Not enough memory for worker socket array" );

		for (i=0; i<ctx->cfg_worker_threads; i++) {

			ctx->client_wait_events[i] = event_create();
			if ( ctx->client_wait_events[i] == 0 ) return cleanup( ctx, "Error creating worker event %u", i );
		}
#endif
	}

#if defined(USE_TIMERS)
	if ( timers_init( ctx ) != 0 ) return cleanup( ctx, "Error creating timers" );
#endif

	/*
	 * Context has been created - init user libraries
	 */

	if ( ctx->callbacks.init_context != NULL ) ctx->callbacks.init_context( ctx );

	ctx->callbacks.exit_context = exit_callback;
	ctx->context_type           = 1; /* server context */

	/*
	 * Start master (listening) thread
	 */

	XX_httplib_start_thread_with_id( XX_httplib_master_thread, ctx, &ctx->masterthreadid );

	/*
	 * Start worker threads
	 */
	for (i=0; i < ctx->cfg_worker_threads; i++) {

		struct worker_thread_args *wta;
	       
		wta = httplib_malloc( sizeof(struct worker_thread_args) );

		if ( wta != NULL ) {

			wta->ctx   = ctx;
			wta->index = (int)i;
		}

		if ( wta == NULL  ||  XX_httplib_start_thread_with_id( XX_httplib_worker_thread, wta, &ctx->workerthreadids[i] ) != 0 ) {

			/*
			 * thread was not created
			 */

			if ( wta != NULL ) { httplib_free( wta ); wta = NULL; }

			if ( i > 0 ) httplib_cry( ctx, NULL, "Cannot start worker thread %i: error %ld", i + 1, (long)ERRNO );
			
			else return cleanup( ctx, "Cannot create threads: error %ld", (long)ERRNO );

			break;
		}
	}

	httplib_pthread_setspecific( XX_httplib_sTlsKey, NULL );

	return ctx;

}  /* httplib_start */



/* 
 * static struct httplib_context *cleanup( struct httplib_context *ctx, const char *fmt, ... );
 *
 * The function cleanup() is called to do some cleanup work when an error
 * occured initializing a context. The function returns NULL which is then
 * further returned to the calling party.
 */

static struct httplib_context *cleanup( struct httplib_context *ctx, const char *fmt, ... ) {

	va_list ap;
	char buf[MG_BUF_LEN];

	va_start( ap, fmt );
	vsnprintf_impl( buf, sizeof(buf), fmt, ap );
	va_end( ap );
	buf[sizeof(buf)-1] = 0;

	httplib_cry(ctx, NULL, "%s", buf );

	if ( ctx != NULL ) XX_httplib_free_context( ctx );
	httplib_pthread_setspecific( XX_httplib_sTlsKey, NULL );

	return NULL;

}  /* cleanup */
