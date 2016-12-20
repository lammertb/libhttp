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
 * Check whether full request is buffered. Return:
 * -1  if request is malformed
 *  0  if request is not yet fully buffered
 * >0  actual request length, including last \r\n\r\n
 */

int XX_httplib_get_request_len( const char *buf, int buflen ) {

	const char *s;
	const char *e;
	int len;

	len = 0;
	s   = buf;
	e   = s+buflen-1;

	while ( len <= 0  &&  s < e ) {

		/*
		 * Control characters are not allowed but >=128 is.
		 */

		if ( ! isprint( *(const unsigned char *)s) && *s != '\r'  &&  *s != '\n'  &&  *(const unsigned char *)s < 128 ) return -1;

		if      ( s[0] == '\n'  &&                                   s[1] == '\n') len = (int)(s - buf) + 2;
		else if ( s[0] == '\n'  &&  &s[1] < e  &&  s[1] == '\r'  &&  s[2] == '\n') len = (int)(s - buf) + 3;

		s++;
	}

	return len;

}  /* XX_httplib_get_request_len */
