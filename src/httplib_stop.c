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
 */

#include "httplib_main.h"

/*
 * void httplib_stop( struct httplib_context *ctx );
 *
 * The function httplib_stop() is used to stop an instance of a LibHTTP server
 * completely and return all its resources.
 */

void httplib_stop( struct httplib_context *ctx ) {

	pthread_t mt;

	if ( ctx == NULL ) return; 
	/* We don't use a lock here. Calling httplib_stop with the same ctx from
	 * two threads is not allowed. */
	mt = ctx->masterthreadid;
	if ( mt == 0 ) return;

	ctx->masterthreadid = 0;

	/* Set stop flag, so all threads know they have to exit. */
	ctx->stop_flag = 1;

	/* Wait until everything has stopped. */
	while ( ctx->stop_flag != 2 ) httplib_sleep(10);

	XX_httplib_join_thread(mt);
	XX_httplib_free_context(ctx);

#if defined(_WIN32)
	WSACleanup();
#endif /* _WIN32 */

}  /* httplib_stop */
