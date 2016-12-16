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

/*
 * int httplib_base64_encode( const unsigned char *src, int src_len, char *dst, int dst_len );
 *
 * The function httplib_base64_encode() converts a binary buffer of given
 * length to its BASE64 equivalent. If an error occurs or the receive buffer is
 * too small, -1 is returned. Otherwise the return value is the length of the
 * data in the receive buffer, including the terminating NUL character.
 */

LIBHTTP_API int httplib_base64_encode( const unsigned char *src, int src_len, char *dst, int dst_len ) {

	static const char *b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	int i;
	int j;
	int a;
	int b;
	int c;

	if ( src == NULL  ||  src_len <= 0  ||  dst == NULL  ||  dst_len < 1 ) return -1;

	j = 0;

	for (i=0; i<src_len; i+=3) {

		a = src[i];

		b = ((i+1) >= src_len) ? 0 : src[i+1];
		c = ((i+2) >= src_len) ? 0 : src[i+2];

		dst[j++] = b64[a >> 2];
		if ( j >= dst_len ) return -1;

		dst[j++] = b64[((a & 3) << 4) | (b >> 4)];
		if ( j >= dst_len ) return -1;

		if (i+1 < src_len) dst[j++] = b64[(b & 15) << 2 | (c >> 6)];
		if ( j >= dst_len ) return -1;

		if (i+2 < src_len) dst[j++] = b64[ c & 63                 ];
		if ( j >= dst_len ) return -1;
	}

	while ( j % 4 != 0 ) {
		
		dst[j++] = '=';
		if ( j >= dst_len ) return -1;
	}

	dst[j++] = 0;

	return j;

}  /* httplib_base64_encode */
