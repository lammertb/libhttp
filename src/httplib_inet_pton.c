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
#include "httplib_utils.h"

int XX_httplib_inet_pton( int af, const char *src, void *dst, size_t dstlen ) {

	struct addrinfo hints;
	struct addrinfo *res;
	struct addrinfo *ressave;
	int func_ret;
	int gai_ret;

	func_ret = 0;

	memset( & hints, 0, sizeof(struct addrinfo) );
	hints.ai_family = af;

	gai_ret = getaddrinfo( src, NULL, &hints, &res );

	if ( gai_ret != 0 ) {

		/*
		 * gai_strerror could be used to convert gai_ret to a string
		 * POSIX return values: see
		 * http://pubs.opengroup.org/onlinepubs/9699919799/functions/freeaddrinfo.html
		 *
		 * Windows return values: see
		 * https://msdn.microsoft.com/en-us/library/windows/desktop/ms738520%28v=vs.85%29.aspx
		 */

		return 0;
	}

	ressave = res;

	while ( res ) {

		if ( dstlen >= res->ai_addrlen ) {

			memcpy( dst, res->ai_addr, res->ai_addrlen );
			func_ret = 1;
		}
		res = res->ai_next;
	}

	freeaddrinfo( ressave );

	return func_ret;

}  /* XX_httplib_inet_pton */
