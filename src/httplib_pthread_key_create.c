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
 * int httplib_pthread_key_create( pthread_key_t *key, void (*destructor)(void *) );
 *
 * The function httplib_pthread_key_create() creates a key which can be used to
 * reference an area for thread dependent storage. The function returns 0 when
 * succesful and a non zero value otherwise. On systems which support it, the
 * function is implemented as a wrapper around pthread_key_create(). On other
 * systems own code is used to emulate the same behavior.
 *
 * Please note that on systems without a native implementation of the function
 * pthread_key_create() that the parameter destructor is ignored.
 */

int httplib_pthread_key_create( pthread_key_t *key, void (*destructor)(void *) ) {

#if defined(_WIN32)

	UNUSED_PARAMETER(destructor);

	if ( key == NULL ) return -2;

	*key = TlsAlloc();
	return ( *key != TLS_OUT_OF_INDEXES ) ? 0 : -1;

#else  /* _WIN32 */

	return pthread_key_create( key, destructor );

#endif  /* _WIN32 */

}  /* httplib_pthread_key_create */
