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

#if defined(_WIN32_WCE)

struct tm		XX_httplib_tm_array[MAX_WORKER_THREADS];
volatile int		XX_httplib_tm_index				= 0;

/*
 * struct tm *localtime( const time_t *ptime );
 *
 * The time conversion function localtime() is not available on all platforms.
 * This implementation provides an equivalent function which can be used on
 * platforms where the native system libraries have no support for localtime().
 * The function is thread safe by using an array with multiple entries to
 * store the outcome of the function. Please note however that the number of
 * entries in the table is equal to the normal number of threads started by
 * LibHTTP, but this still may lead to overwriting results in border cases
 * where the application creates additional threads which also use calls to
 * this localtime implementation().
 *
 * The implementation should therefore use thread local storage in the future.
 */

struct tm *localtime( const time_t *ptime ) {

	int i;
       
	i = XX_httplib_atomic_inc( & XX_httplib_tm_index ) % MAX_WORKER_THREADS;
	return localtime_s( ptime, XX_httplib_tm_array + i );

}  /* localtime */

#endif /* defined(_WIN32_WCE) */
