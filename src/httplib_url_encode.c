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

int httplib_url_encode( const char *src, char *dst, size_t dst_len ) {

	static const char *dont_escape = "._-$,;~()";
	static const char *hex = "0123456789abcdef";
	char *pos;
	const char *end;

	if ( dst == NULL  ||  dst_len < 1 )                  return 0;
	if ( src == NULL                  ) { dst[0] = '\0'; return 0; }

	pos = dst;
	end = dst + dst_len - 1;

	while ( *src != '\0'  &&  pos < end ) {

		if ( isalnum(*(const unsigned char *)src)  ||  strchr( dont_escape, *(const unsigned char *)src ) != NULL ) *pos = *src;
		
		else if ( pos + 2 < end ) {

			pos[0] = '%';
			pos[1] = hex[(*(const unsigned char *)src) >> 4];
			pos[2] = hex[(*(const unsigned char *)src) & 0xf];
			pos   += 2;
		}
		
		else break;

		src++;
		pos++;
	}

	*pos = '\0';
	return (*src == '\0') ? (int)(pos - dst) : -1;

}  /* httplib_url_encode */
