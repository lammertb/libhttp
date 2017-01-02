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

/*
 * void httplib_stop( struct lh_ctx_t *ctx );
 *
 * The function httplib_stop() is used to stop an instance of a LibHTTP server
 * completely and return all its resources.
 */

void httplib_stop( struct lh_ctx_t *ctx ) {

	pthread_t mt;

	if ( ctx == NULL ) return;

	/*
	 * We don't use a lock here. Calling httplib_stop with the same ctx from
	 * two threads is not allowed.
	 */

	mt = ctx->masterthreadid;
	if ( mt == 0 ) return;

	ctx->masterthreadid = 0;

	/*
	 * Set stop flag, so all threads know they have to exit. If for some
	 * reason the context was already stopping or terminated, we do not set
	 * the stopping request here again, just to be sure that we don't
	 * accidentally reset a terminated state back to a stopping state. In
	 * that case the context would never be flagged as terminated again.
	 */

	if ( ctx->status == CTX_STATUS_RUNNING ) ctx->status = CTX_STATUS_STOPPING;

	/*
	 * Wait until everything has stopped.
	 */

	while ( ctx->status != CTX_STATUS_TERMINATED ) httplib_sleep( 10 );

	httplib_pthread_join( mt, NULL );
	XX_httplib_free_context( ctx );

}  /* httplib_stop */
