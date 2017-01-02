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

/*
 * void XX_httplib_produce_socket( struct lh_ctx_t *ctx, const struct socket *sp );
 *
 * The function XX_httplib_produce_socket() is used to produce a socket.
 */

#if defined(ALTERNATIVE_QUEUE)

void XX_httplib_produce_socket( struct lh_ctx_t *ctx, const struct socket *sp ) {

	unsigned int i;

	for (;;) {

		for (i=0; i<ctx->cfg_worker_threads; i++) {

			/*
			 * find a free worker slot and signal it
			 */

			if ( ctx->client_socks[i].in_use == 0 ) {

				ctx->client_socks[i]        = *sp;
				ctx->client_socks[i].in_use = 1;

				event_signal( ctx->client_wait_events[i] );

				return;
			}
		}

		/*
		 * queue is full
		 */

		httplib_sleep( 1 );
	}

}  /* XX_httplib_produce_socket */

#else /* ALTERNATIVE_QUEUE */

/*
 * Master thread adds accepted socket to a queue
 */

void XX_httplib_produce_socket( struct lh_ctx_t *ctx, const struct socket *sp ) {

#define QUEUE_SIZE(ctx) ((int)(ARRAY_SIZE(ctx->queue)))

	if ( ctx == NULL ) return;

	httplib_pthread_mutex_lock( & ctx->thread_mutex );

	/*
	 * If the queue is full, wait
	 */

	while ( ctx->status == CTX_STATUS_RUNNING  &&  ctx->sq_head-ctx->sq_tail >= QUEUE_SIZE(ctx) ) {

		httplib_pthread_cond_wait( & ctx->sq_empty, & ctx->thread_mutex );
	}

	if ( ctx->sq_head - ctx->sq_tail < QUEUE_SIZE(ctx) ) {

		/*
		 * Copy socket to the queue and increment head
		 */

		ctx->queue[ctx->sq_head % QUEUE_SIZE(ctx)] = *sp;
		ctx->sq_head++;
	}

	httplib_pthread_cond_signal(  & ctx->sq_full      );
	httplib_pthread_mutex_unlock( & ctx->thread_mutex );

}  /* XX_httplib_produce_socket */

#endif /* ALTERNATIVE_QUEUE */
