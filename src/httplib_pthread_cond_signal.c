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
 * int httplib_pthread_cond_signal( pthread_cond_t *cv );
 *
 * The platform independent function httplib_pthread_cond_signal() unlocks a
 * blocking condition for one thread. Of the function is successful, the value
 * 0 will be returned. Otherwise the returned value is an error code.
 *
 * On systems which support it, the function is a wrapper around the function
 * pthread_cond_signal(). In other environments own code is used which emulates
 * the same behaviour.
 */

int httplib_pthread_cond_signal( pthread_cond_t *cv ) {

#if defined(_WIN32)

	HANDLE wkup;
	bool ok;

	wkup = NULL;
	ok   = false;

	EnterCriticalSection( & cv->threadIdSec );

	if ( cv->waiting_thread ) {

		wkup               = cv->waiting_thread->pthread_cond_helper_mutex;
		cv->waiting_thread = cv->waiting_thread->next_waiting_thread;

		ok = SetEvent( wkup );
	}

	LeaveCriticalSection( & cv->threadIdSec );

	return ( ok ) ? 0 : 1;

#else  /* _WIN32 */

	return pthread_cond_signal( cv );

#endif

}  /* httplib_pthread_cond_signal */
