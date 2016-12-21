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

#define HEXTOI(x) (isdigit(x) ? (x - '0') : (x - 'W'))

int httplib_url_decode( const char *src, int src_len, char *dst, int dst_len, int is_form_url_encoded ) {

	int i;
	int j;
	int a;
	int b;

	i = 0;
	j = 0;

	while ( i < src_len  &&  j < dst_len-1 ) {

		if ( i < src_len - 2  &&  src[i] == '%'  &&  isxdigit(*(const unsigned char *)(src + i + 1))  &&  isxdigit(*(const unsigned char *)(src + i + 2)) ) {

			a      = tolower(*(const unsigned char *)(src + i + 1));
			b      = tolower(*(const unsigned char *)(src + i + 2));
			dst[j] = (char)((HEXTOI(a) << 4) | HEXTOI(b));
			i     += 2;
		}

		else if (is_form_url_encoded && src[i] == '+') dst[j] = ' ';
		else                                           dst[j] = src[i];

		i++;
		j++;
	}

	dst[j] = '\0'; /* Null-terminate the destination */

	return (i >= src_len) ? j : -1;

}  /* httplib_url_decode */
