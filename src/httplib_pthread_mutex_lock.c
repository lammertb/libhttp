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
 * int httplib_pthread_mutex_lock( pthread_mutex_t *mutex );
 *
 * The platform independent function httplib_pthread_mutex_lock() starts a
 * blocking call to lock a mutex. If the mutex is locked by another thread, the
 * function will wait until the mutex has been released. Success is indicated
 * with the return value 0, while another value indicates an error.
 *
 * On systems wshich support it, this function is implemented with a direct
 * call to pthread_mutex_lock(). On other systems own code is used to emulate
 * the same behaviour.
 */

int httplib_pthread_mutex_lock( pthread_mutex_t *mutex ) {

#if defined(_WIN32)

	return ( WaitForSingleObject( *mutex, INFINITE ) == WAIT_OBJECT_0 ) ? 0 : -1;

#else  /* _WIN32 */

	return pthread_mutex_lock( mutex );

#endif  /* _WIN32 */

}  /* httplib_pthread_mutex_lock */
