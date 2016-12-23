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
 * int httplib_pthread_join( pthread_t thread, void **value_ptr );
 *
 * The platform independent function httplib_pthread_join() suspends the
 * current thread and waits until another thread has terminated. Succes is
 * returned with 0, while an error code is returned otherwise. The function is
 * a wrapper around pthread_join() on systems which support it, or own code
 * which emulates the same functionality otherwise.
 *
 * On systems which do not support pthread_join() natively, the value_ptr
 * parameter is ignored.
 */

int httplib_pthread_join( pthread_t thread, void **value_ptr ) {

#if defined(_WIN32)

	int result;
	DWORD dwevent;

	UNUSED_PARAMETER(value_ptr);

	result  = -1;
	dwevent = WaitForSingleObject( thread, INFINITE );

	if ( dwevent == WAIT_FAILED ) {
	}
	
	else if ( dwevent == WAIT_OBJECT_0 ) {

		CloseHandle( thread );
		result = 0;
	}

	return result;

#else  /* _WIN32 */

	return pthread_join( thread, value_ptr );

#endif  /* _WIN32 */

}  /* httplib_pthread_join */
