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
 * const char *httplib_strcasestr( const char *big_str, const char *small_str );
 *
 * The function httplib_strcasestr() searches case insensitive for a NUL
 * terminated string in another string and returns a pointer to the first
 * occurrence, or NULL if the substring could not be found.
 */

LIBHTTP_API const char *httplib_strcasestr( const char *big_str, const char *small_str ) {

	size_t i;
	size_t big_len;
	size_t small_len;

	if ( big_str == NULL  ||  small_str == NULL ) return NULL;

	big_len   = strlen( big_str   );
	small_len = strlen( small_str );

	if ( big_len < small_len ) return NULL;

	for (i=0; i<=big_len-small_len; i++) {

		if ( httplib_strncasecmp( big_str+i, small_str, small_len ) == 0 ) return big_str+i;
	}

	return NULL;

}  /* httplib_strcasestr */
