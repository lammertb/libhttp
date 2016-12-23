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
 * We can optionally set TCP_USER_TIMEOUT
 *
 * TCP_USER_TIMEOUT/RFC5482 (http://tools.ietf.org/html/rfc5482):
 * max. time waiting for the acknowledged of TCP data before the connection
 * will be forcefully closed and ETIMEDOUT is returned to the application.
 * If this option is not set, the default timeout of 20-30 minutes is used.
 */

// #define TCP_USER_TIMEOUT (18)

/*
 * int XX_httplib_set_sock_timeout( SOCKET sock, int milliseconds );
 *
 * The function XX_httplib_set_sock_timeout() sets the timeout of a socket
 * to the specified nummer of milliseconds.
 */

int XX_httplib_set_sock_timeout( SOCKET sock, int milliseconds ) {

	int r0;
	int r1;
	int r2;

#ifdef _WIN32

	DWORD tv = (DWORD)milliseconds;
	r0       = 0;

#else  /* _WIN32 */

	struct timeval tv;

#if defined(TCP_USER_TIMEOUT)

	unsigned int uto;

	uto = (unsigned int)milliseconds;
	r0  = setsockopt( sock, 6, TCP_USER_TIMEOUT, (const void *)&uto, sizeof(uto) );

#else
	r0  = 0;

#endif  /* TCP_USER_TIMEOUT */

	memset( & tv, 0, sizeof(tv) );
	tv.tv_sec  =  milliseconds / 1000;
	tv.tv_usec = (milliseconds * 1000) % 1000000;

#endif /* _WIN32 */

	r1 = setsockopt( sock, SOL_SOCKET, SO_RCVTIMEO, (SOCK_OPT_TYPE)&tv, sizeof(tv) );
	r2 = setsockopt( sock, SOL_SOCKET, SO_SNDTIMEO, (SOCK_OPT_TYPE)&tv, sizeof(tv) );

	return (r0  ||  r1  ||  r2);

}  /* XX_httplib_set_sock_timeout */
