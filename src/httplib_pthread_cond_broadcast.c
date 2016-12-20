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
 * int httplib_pthread_cond_broadcast( pthread_cond_t *cv );
 *
 * The platform independent function httplib_pthread_cond_broadcast() unblocks
 * all threads waiting for a specific condition. If the function is successful
 * the value is returned, otherwise an error code.
 *
 * On systems which support it, the function is a wrapper around the function
 * pthread_cond_broadcast(). On other systems own code is used to emulate the
 * same behaviour.
 */

int httplib_pthread_cond_broadcast( pthread_cond_t *cv ) {

#if defined(_WIN32)

	EnterCriticalSection( & cv->threadIdSec );
	while ( cv->waiting_thread ) httplib_pthread_cond_signal( cv );
	LeaveCriticalSection( & cv->threadIdSec );

	return 0;

#else  /* _WIN32 */

	return pthread_cond_broadcast( cv );

#endif  /* _WIN32 */

}  /* httplib_pthread_cond_broadcast */
