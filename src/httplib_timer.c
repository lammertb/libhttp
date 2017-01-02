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
 * Release: 1.9
 */

#include "httplib_main.h"

#if defined(USE_TIMERS)

#if !defined(MAX_TIMERS)
#define MAX_TIMERS MAX_WORKER_THREADS
#endif

typedef int (*taction)(void *arg);

struct ttimer {
	double time;
	double period;
	taction action;
	void *arg;
};

struct ttimers {
	pthread_t threadid;			/* Timer thread ID		*/
	pthread_mutex_t mutex;			/* Protects timer lists		*/
	struct ttimer timers[MAX_TIMERS];	/* List of timers		*/
	unsigned timer_count;			/* Current size of timer list	*/
};

static int timer_add( struct lh_ctx_t *ctx, double next_time, double period, int is_relative, taction action, void *arg ) {

	unsigned u;
	unsigned v;
	int error;
	struct timespec now;
	double dt; /* double time */

	if ( ctx == NULL  ||  ctx->stop_flag ) return 0;

	error = 0;

	clock_gettime( CLOCK_MONOTONIC, &now );
	dt  = (double)now.tv_sec;
	dt += now.tv_nsec * 1.0E-9;

	/*
	 * HCP24: if is_relative = 0 and next_time < now
	 *        action will be called so fast as possible
	 *        if additional period > 0
	 *        action will be called so fast as possible
	 *        n times until (next_time + (n * period)) > now
	 *        then the period is working
	 * Solution:
	 *        if next_time < now then we set  next_time = now.
	 *        The first callback will be so fast as possible  (now)
	 *        but the next callback on period
	 */

	if      ( is_relative    ) next_time += dt;
	else if ( next_time < dt ) next_time  = dt;

	httplib_pthread_mutex_lock( & ctx->timers->mutex );
	if ( ctx->timers->timer_count == MAX_TIMERS ) error = 1;
	
	else {
		for (u=0; u<ctx->timers->timer_count; u++) {

			if (ctx->timers->timers[u].time > next_time) {

				/*
				 * HCP24: moving all timers > next_time
				 */

				for (v=ctx->timers->timer_count; v>u; v--) ctx->timers->timers[v] = ctx->timers->timers[v - 1];
				break;
			}
		}

		ctx->timers->timers[u].time   = next_time;
		ctx->timers->timers[u].period = period;
		ctx->timers->timers[u].action = action;
		ctx->timers->timers[u].arg    = arg;
		ctx->timers->timer_count++;
	}

	httplib_pthread_mutex_unlock( & ctx->timers->mutex );

	return error;

}  /* timer_add */

static void timer_thread_run( void *thread_func_param ) {

	struct lh_ctx_t *ctx = (struct lh_ctx_t *)thread_func_param;
	struct timespec now;
	double d;
	unsigned u;
	int re_schedule;
	struct ttimer t;

	httplib_set_thread_name( "timer" );

	if ( ctx->callbacks.init_thread ) ctx->callbacks.init_thread( ctx, 2 );	/* Timer thread */

#if defined(HAVE_CLOCK_NANOSLEEP) /* Linux with librt */
	/* TODO */
	while ( clock_nanosleep( CLOCK_MONOTONIC, TIMER_ABSTIME, &request, &request ) == EINTR ) { /*nop*/ ; }

#else  /* HAVE_CLOCK_NANOSLEEP */

	clock_gettime( CLOCK_MONOTONIC, &now );
	d = (double)now.tv_sec + (double)now.tv_nsec * 1.0E-9;

	while ( ctx->stop_flag == 0 ) {

		httplib_pthread_mutex_lock( & ctx->timers->mutex );

		if ( ctx->timers->timer_count > 0  &&  d >= ctx->timers->timers[0].time ) {

			t = ctx->timers->timers[0];
			for (u=1; u<ctx->timers->timer_count; u++) ctx->timers->timers[u-1] = ctx->timers->timers[u];
			ctx->timers->timer_count--;
			httplib_pthread_mutex_unlock( & ctx->timers->mutex );
			re_schedule = t.action( t.arg );
			if ( re_schedule  &&  t.period > 0 ) timer_add( ctx, t.time + t.period, t.period, 0, t.action, t.arg );

			continue;
		}
		
		else httplib_pthread_mutex_unlock( & ctx->timers->mutex );

		httplib_sleep(1);
		clock_gettime(CLOCK_MONOTONIC, &now);
		d = (double)now.tv_sec + (double)now.tv_nsec * 1.0E-9;
	}

#endif  /* HAVE_CLOCK_NANOSLEEP */

}  /* timer_thread_run */

#ifdef _WIN32
static unsigned __stdcall timer_thread( void *thread_func_param ) {

	timer_thread_run( thread_func_param );
	return 0;

}  /* timer_thread */

#else
static void * timer_thread( void *thread_func_param ) {

	timer_thread_run( thread_func_param );
	return NULL;

}  /* timer_thread */

#endif /* _WIN32 */

static int timers_init( struct lh_ctx_t *ctx ) {

	ctx->timers = httplib_calloc( sizeof(struct ttimers), 1 );
	httplib_pthread_mutex_init( & ctx->timers->mutex, NULL );

	/*
	 * Start timer thread
	 */

	httplib_start_thread_with_id(timer_thread, ctx, &ctx->timers->threadid);

	return 0;

}  /* timers_init */

static void timers_exit( struct lh_ctx_t *ctx ) {

	if ( ctx->timers != NULL ) {

		httplib_pthread_mutex_destroy( & ctx->timers->mutex );
		ctx->timers = httplib_free( ctx->timers );
	}

}  /* timers_exit */

#endif
