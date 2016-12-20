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

#if ! defined(USE_STACK_SIZE)  ||  (USE_STACK_SIZE <= 0)
#undef USE_STACK_SIZE
#define USE_STACK_SIZE		0
#endif  /* USE_STACK_SIZE */

/*
 * int httplib_start_thread( httplib_thread_func_t func, void *param );
 *
 * The functiom httplib_start_thread() is a convenience function to help to
 * start a detached thread. The function returns 0 if successful, or a non-zero
 * value if an error occurs. An optional pointer parameter can be passed to the
 * newly created thread.
 */

int httplib_start_thread( httplib_thread_func_t func, void *param ) {

#if defined(_WIN32)

	return ( (_beginthread( (void(__cdecl *)(void *))func, USE_STACK_SIZE, param ) == ((uintptr_t)(-1L))) ? -1 : 0 );

#else  /* _WIN32 */

	pthread_t thread_id;
	pthread_attr_t attr;
	int result;

	pthread_attr_init( & attr );
	pthread_attr_setdetachstate( & attr, PTHREAD_CREATE_DETACHED );

#if (USE_STACK_SIZE > 1)
	pthread_attr_setstacksize( & attr, USE_STACK_SIZE );
#endif  /* USE_STACK_SIZE > 1 */

	result = pthread_create( & thread_id, &attr, func, param );
	pthread_attr_destroy( & attr );

	return result;

#endif /* _WIN32 */

}  /* httplib_start_thread */
