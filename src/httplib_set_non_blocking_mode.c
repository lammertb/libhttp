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
 * int XX_httplib_set_non_block_mode( SOCKET sock );
 *
 * The function XX_httplib_set_non_blocking_mode() is an internal function to
 * set a socket in non blocking mode, independent of the platform where the
 * program is running on.
 */

int XX_httplib_set_non_blocking_mode( SOCKET sock ) {

#if defined(_WIN32)

	unsigned long on;

	on = 1;
	return ioctlsocket( sock, (long)FIONBIO, & on );

#else  /* _WIN32 */

	int flags;

	flags = fcntl( sock, F_GETFL, 0 );
	fcntl( sock, F_SETFL, flags | O_NONBLOCK );

	return 0;

#endif  /* _WIN32 */

}  /* XX_httplib_set_non_blocking_mode */
