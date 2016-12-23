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
#include "httplib_pthread.h"

/*
 * int httplib_pthread_cond_timedwait( pthread_cond_t *cv, pthread_mutex *mutex, const struct timespec *abstime );
 *
 * The platform independent function httplib_pthread_cond_timedwait() is used
 * to wait until a specified condition is met. If that happens the specified
 * mutex is released. The function stops after a timeout which is provided as a
 * third parameter in the function call.
 *
 * On systems which support it, the call is implemented as a wrapper around the
 * pthread_cond_timedwait() function. On other platforms the functionality is
 * implemented with own code.
 */

int httplib_pthread_cond_timedwait( pthread_cond_t *cv, pthread_mutex_t *mutex, const struct timespec *abstime ) {

#if defined(_WIN32)

	struct httplib_workerTLS **ptls;
	struct httplib_workerTLS *tls;
	bool ok;
	struct timespec tsnow;
	int64_t nsnow;
	int64_t nswaitabs;
	int64_t nswaitrel;
	DWORD mswaitrel;

	tls = httplib_pthread_getspecific( XX_httplib_sTlsKey );

	/* Add this thread to cv's waiting list */
	EnterCriticalSection( & cv->threadIdSec );

	ptls = & cv->waiting_thread;
	while ( *ptls != NULL ) ptls = & (*ptls)->next_waiting_thread;

	tls->next_waiting_thread = NULL;
	*ptls                    = tls;

	LeaveCriticalSection( & cv->threadIdSec );

	if ( abstime ) {

		clock_gettime( CLOCK_REALTIME,  & tsnow );

		nsnow     = (((int64_t)tsnow.tv_sec)    * 1000000000) + tsnow.tv_nsec;
		nswaitabs = (((int64_t)abstime->tv_sec) * 1000000000) + abstime->tv_nsec;

		nswaitrel = nswaitabs - nsnow;
		if ( nswaitrel < 0 ) nswaitrel = 0;

		mswaitrel = (DWORD)(nswaitrel / 1000000);
	}
	
	else mswaitrel = INFINITE;

	httplib_pthread_mutex_unlock( mutex );
	ok = ( WaitForSingleObject( tls->pthread_cond_helper_mutex, mswaitrel ) == WAIT_OBJECT_0 );

	if ( ! ok ) {

		ok = true;

		EnterCriticalSection( & cv->threadIdSec );

		ptls = & cv->waiting_thread;

		while ( *ptls != NULL ) {
		       
			ptls = & (*ptls)->next_waiting_thread;

			if ( *ptls == tls ) {

				*ptls = tls->next_waiting_thread;
				ok    = false;

				break;
			}
		}

		LeaveCriticalSection( & cv->threadIdSec );

		if ( ok ) WaitForSingleObject( tls->pthread_cond_helper_mutex, INFINITE );
	}
	/* This thread has been removed from cv's waiting list */
	httplib_pthread_mutex_lock( mutex );

	return ok ? 0 : -1;

#else  /* _WIN32 */

	return pthread_cond_timedwait( cv, mutex, abstime );

#endif  /* _WIN32 */

}  /* httplib_pthread_cond_timedwait */
