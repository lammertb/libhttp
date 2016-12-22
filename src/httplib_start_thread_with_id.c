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
 * int XX_httplib_start_thread_with_id( httplib_thread_func_t func, void *param, pthread_t *threadidptr );
 *
 * The function XX_httplib_start_thread_with_id() starts a thread and returns
 * an identifier for the thread back through a parameter. The function returns
 * 0 when successful and a non zero value if a problem occurs.
 */

int XX_httplib_start_thread_with_id( httplib_thread_func_t func, void *param, pthread_t *threadidptr ) {

#if defined(_WIN32)

	uintptr_t uip;
	HANDLE threadhandle;

	uip          = _beginthreadex( NULL, 0, func, param, 0, NULL );
	threadhandle = (HANDLE)uip;

	if ( uip != (uintptr_t)(-1L)  &&   threadidptr != NULL ) {

		*threadidptr = threadhandle;
		return 0;
	}

	return -1;

#else  /* _WIN32 */

	pthread_t thread_id;
	pthread_attr_t attr;
	int result;

	pthread_attr_init( & attr );

#if defined(USE_STACK_SIZE) && (USE_STACK_SIZE > 1)

	/*
	 * Compile-time option to control stack size,
	 * e.g. -DUSE_STACK_SIZE=16384
	 */

	pthread_attr_setstacksize( & attr, USE_STACK_SIZE );
#endif /* defined(USE_STACK_SIZE) && USE_STACK_SIZE > 1 */

	result = pthread_create( & thread_id, &attr, func, param );
	pthread_attr_destroy( & attr );
	if ( result == 0  &&  threadidptr != NULL ) *threadidptr = thread_id;

	return result;

#endif /* _WIN32 */

}  /* XX_httplib_start_thread_with_id */
