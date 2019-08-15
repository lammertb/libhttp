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

pthread_mutex_t *XX_httplib_ssl_mutexes;

/*
 * void XX_httplib_ssl_locking_callback( int mode, int mutex_num, const char *file, int line );
 *
 * The function XX_httplib_ssl_locking_callback() is used for locking and
 * unlocking mutexes from the SSL routines.
 */

void XX_httplib_ssl_locking_callback( int mode, int mutex_num, const char *file, int line ) {

	UNUSED_PARAMETER(line);
	UNUSED_PARAMETER(file);

	if ( mode & 0x0001 ) httplib_pthread_mutex_lock(   & XX_httplib_ssl_mutexes[mutex_num] );
	else                 httplib_pthread_mutex_unlock( & XX_httplib_ssl_mutexes[mutex_num] );

}  /* XX_httplib_ssl_locking_callback */

#endif /* !NO_SSL */
