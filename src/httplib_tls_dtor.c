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
 * Release: 1.8
 */

#include "httplib_main.h"
#include "httplib_memory.h"
#include "httplib_pthread.h"
#include "httplib_ssl.h"

/*
 * void XX_httplib_tls_dtor( void *key );
 *
 * The function XX_httplib_tls_dtor() is used sets the TLS key for the thread.
 * The Thread Local Storage key is used in identifying thread specific storage.
 */

void XX_httplib_tls_dtor( void *key ) {

	struct httplib_workerTLS *tls = (struct httplib_workerTLS *)key;
	/* key == pthread_getspecific( XX_httplib_sTlsKey ); */

	if ( tls != NULL ) {

		if (tls->is_master == 2) {

			tls->is_master = -3; /* Mark memory as dead */
			httplib_free( tls );
		}
	}

	pthread_setspecific( XX_httplib_sTlsKey, NULL );

}  /* XX_httplib_tls_dtor */
