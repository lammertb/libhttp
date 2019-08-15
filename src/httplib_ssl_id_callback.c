/* 
 * Copyright (c) 2016-2019 Lammert Bies
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

#if !defined(NO_SSL)

#include "httplib_main.h"
#include "httplib_pthread.h"
#include "httplib_ssl.h"
#include "httplib_utils.h"

/*
 * unsigned long XX_httplib_ssl_id_callback( void );
 *
 * The function XX_httplib_ssl_id_callback() returns a handle representing the
 * thread running the SSL callback.
 */

/* Must be set if sizeof(pthread_t) > sizeof(unsigned long) */
unsigned long XX_httplib_ssl_id_callback( void ) {

#ifdef _WIN32
	return GetCurrentThreadId();
#else  /* _WIN32 */

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunreachable-code"
/*
 * For every compiler, either "sizeof(pthread_t) > sizeof(unsigned long)"
 * or not, so one of the two conditions will be unreachable by construction.
 * Unfortunately the C standard does not define a way to check this at
 * compile time, since the #if preprocessor conditions can not use the sizeof
 * operator as an argument.
 */

#endif /* __clang__ */

	if ( sizeof(pthread_t) > sizeof(unsigned long) ) {

		/*
		 * This is the problematic case for CRYPTO_set_id_callback:
		 * The OS pthread_t can not be cast to unsigned long.
		 */

		struct httplib_workerTLS *tls = httplib_pthread_getspecific( XX_httplib_sTlsKey );

		if ( tls == NULL ) {

			/*
			 * SSL called from an unknown thread: Create some thread index.
			 */

			tls             = httplib_malloc( sizeof(struct httplib_workerTLS) );
			tls->thread_idx = (unsigned) httplib_atomic_inc( & XX_httplib_thread_idx_max );

			httplib_pthread_setspecific( XX_httplib_sTlsKey, tls );
		}

		return tls->thread_idx;
	}
	else {
		/*
		 * pthread_t may be any data type, so a simple cast to unsigned long
		 * can rise a warning/error, depending on the platform.
		 * Here memcpy is used as an anything-to-anything cast.
		 */

		unsigned long ret = 0;
		pthread_t t       = httplib_pthread_self();
		memcpy(&ret, &t, sizeof(pthread_t));
		return ret;
	}

#ifdef __clang__
#pragma clang diagnostic pop
#endif  /* __clang */

#endif  /* _WIN32 */

}  /* XX_httplib_ssl_id_callback */

#endif /* !NO_SSL */
