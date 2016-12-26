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
 */

#include "httplib_main.h"

/*
 * void httplib_strlcpy( char *dst, const char *src, size_t len );
 *
 * The function httplib_strlcpy() provides a platform independent safe way to
 * copy a string from one memory location to another. The size of the receiving
 * buffer is provided as a parameter and the function ensures that no more than
 * the number of the characters fitting in that buffer will be copied. The
 * function also ensures that if the destination buffer is not NULL and the
 * size is at least one byte long that the resulting string is terminated with
 * a NUL character.
 *
 * If the source string is longer than will fit in the receiving buffer, the
 * remaining characters will be ignored.
 */

LIBHTTP_API void httplib_strlcpy( char *dst, const char *src, size_t len ) {

	if ( dst == NULL  ||  len == 0 )                return;
	if ( src == NULL               ) { *dst = '\0'; return; }

	while ( len > 1  &&  *src != '\0' ) {
		
		*dst++ = *src++;
		len--;
	}

	*dst = '\0';

}  /* httplib_strlcpy */
