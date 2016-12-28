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

#if !defined(NO_THREAD_NAME)
#if defined(__linux__)

#include <sys/prctl.h>
#include <sys/sendfile.h>
#include <sys/eventfd.h>


#if defined(ALTERNATIVE_QUEUE)

void *event_create( void ) {

	int ret;

	ret = eventfd( 0, EFD_CLOEXEC );

	if ( ret == -1 ) {

		/*
		 * Linux uses -1 on error, Windows NULL.
		 * However, Linux does not return 0 on success either.
		 */

		return NULL;
	}
	return (void *)ret;

}  /* event_create */


int event_wait( void *eventhdl ) {

	uint64_t u;
	int s;

	s = (int)read( (int)eventhdl, &u, sizeof(u) );
	if ( s != sizeof(uint64_t) ) return 0;

	return 1;

}  /* event_wait */


int event_signal( void *eventhdl ) {

	uint64_t u;
	int s;

	u = 1;
	s = (int)write( (int)eventhdl, &u, sizeof(u) );

	if ( s != sizeof(uint64_t) ) return 0;

	return 1;

}  /* event_signal */


void event_destroy( void *eventhdl ) {

	close( (int)eventhdl );

}  /* event_destroy */

#endif  /* ALTERNATIVE_QUEUE */

#endif  /* __linux__*/


#if !defined(__linux__) && !defined(_WIN32) && defined(ALTERNATIVE_QUEUE)

struct posix_event {

	pthread_mutex_t mutex;
	pthread_cond_t cond;
};


void *event_create(void) {

	struct posix_event *ret;
       
	ret = XX_httplib_malloc( sizeof(struct posix_event) );
	if ( ret == NULL ) return NULL;

	if ( httplib_pthread_mutex_init( & ret->mutex, NULL ) != 0 ) {

		/*
		 * pthread mutex not available
		 */

		ret = httplib_free( ret );
		return NULL;
	}
	if ( httplib_pthread_cond_init( & ret->cond, NULL ) != 0 ) {

		/*
		 * pthread cond not available
		 */

		httplib_pthread_mutex_destroy( & ret->mutex );
		ret = httplib_free( ret );
		return NULL;
	}

	return ret;

}  /* event_create */


int event_wait( void *eventhdl ) {

	struct posix_event *ev;
       
	ev = eventhdl;

	httplib_pthread_mutex_lock(            & ev->mutex );
	httplib_pthread_cond_wait( & ev->cond, & ev->mutex );
	httplib_pthread_mutex_unlock(          & ev->mutex );

	return 1;

}  /* event_wait */


int event_signal( void *eventhdl ) {

	struct posix_event *ev;
       
	ev = eventhdl;

	httplib_pthread_mutex_lock(   & ev->mutex );
	httplib_pthread_cond_signal(  & ev->cond  );
	httplib_pthread_mutex_unlock( & ev->mutex );

	return 1;

}  /* event_signal */


void event_destroy( void *eventhdl ) {

	struct posix_event *ev;
       
	ev = eventhdl;

	httplib_pthread_cond_destroy(  & ev->cond  );
	httplib_pthread_mutex_destroy( & ev->mutex );

	ev = httplib_free( ev );

}  /* event_destroy */

#endif  /* ! __linux__  &&  ! _WIN32  && ALTERNATIVE_QUEUE */

#endif  /* NO_THREAD_NAME */


#if defined(_WIN32)  &&  defined(ALTERNATIVE_QUEUE)
void *event_create( void ) {

	return (void *) CreateEvent( NULL, FALSE, FALSE, NULL );

}  /* event_create */


int event_wait( void *eventhdl ) {

	int res;
       
	res = WaitForSingleObject( (HANDLE) eventhdl, INFINITE );
	return ( res == WAIT_OBJECT_0 );

}  /* event_wait */


int event_signal( void *eventhdl ) {

	return (int) SetEvent( (HANDLE) eventhdl );

}  /* event_signal */


void event_destroy( void *eventhdl ) {

	CloseHandle( (HANDLE) eventhdl );

}  /* event_destroy */

#endif  /* _WIN32  &&  ALTERNATIVE_QUEUE */
