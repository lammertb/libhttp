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

#if ! defined(_WIN32)
#include <sys/poll.h>
#endif  /* _WIN32 */

#include "httplib_main.h"

/*
 * int httplib_poll( struct pollfd *pfd, unsigned int n, int milliseconds );
 *
 * The function poll() executes the Posix system call poll() when available, or
 * en emulated version of the function on other operating systems.
 */

LIBHTTP_API int httplib_poll( struct pollfd *pfd, unsigned int n, int milliseconds ) {

#if defined(_WIN32)

	struct timeval tv;
	fd_set set;
	unsigned int i;
	int result;
	SOCKET maxfd;

	maxfd = 0;

	memset( & tv, 0, sizeof(tv) );
	tv.tv_sec  =  milliseconds / 1000;
	tv.tv_usec = (milliseconds % 1000) * 1000;
	FD_ZERO( & set );

	for (i=0; i<n; i++) {

		FD_SET( (SOCKET)pfd[i].fd, &set );
		pfd[i].revents = 0;

		if ( pfd[i].fd > maxfd ) maxfd = pfd[i].fd;
	}

	if ( (result = select( (int)maxfd + 1, &set, NULL, NULL, &tv)) > 0 ) {

		for (i=0; i<n; i++) if ( FD_ISSET(pfd[i].fd, &set) ) pfd[i].revents = POLLIN;
	}

	return result;

#else  /* _WIN32 */

	return poll( pfd, n, milliseconds );

#endif  /* _WIN32 */

}  /* httplib_poll */
