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
 * int httplib_pthread_cond_destroy( pthread_cond_t *cv );
 *
 * The platform indepent function httplib_pthread_cond_destroy() destroys a
 * previously allocated condition variable. The function returns 0 when
 * successful and an error code otherwise. On system which support it, the
 * function is implemented as a wrapper around pthread_cond_destroy(). On other
 * systems the functionality is implemented with own code.
 */

int httplib_pthread_cond_destroy( pthread_cond_t *cv ) {

#if defined(_WIN32)

	int retval;

	EnterCriticalSection( & cv->threadIdSec );
	retval = ( cv->waiting_thread == NULL ) ? 0 : -1;
	LeaveCriticalSection(  & cv->threadIdSec );

	if ( ! retval ) DeleteCriticalSection( & cv->threadIdSec );

	return retval;

#else  /* _WIN32 */

	return pthread_cond_destroy( cv );

#endif  /* _WIN32 */

}  /* httplib_pthread_cond_destroy */
