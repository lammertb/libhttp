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
 * Perform case-insensitive match of string against pattern
 */

int XX_httplib_match_prefix(const char *pattern, size_t pattern_len, const char *str) {

	const char *or_str;
	size_t i;
	int j;
	int len;
	int res;

	or_str = (const char *)memchr( pattern, '|', pattern_len );
	if ( or_str != NULL ) {

		res = XX_httplib_match_prefix( pattern, (size_t)(or_str - pattern), str );
		return (res > 0) ? res : XX_httplib_match_prefix(or_str + 1, (size_t)((pattern + pattern_len) - (or_str + 1)), str);
	}

	i = 0;
	j = 0;

	while ( i<pattern_len ) {

		if ( pattern[i] == '?'  &&  str[j] != '\0' ) continue;
		if ( pattern[i] == '$'                     ) return (str[j] == '\0') ? j : -1;
		
		if (pattern[i] == '*') {

			i++;
			if ( pattern[i] == '*' ) {

				i++;
				len = (int)strlen(str + j);
			}
			
			else len = (int)strcspn(str + j, "/");

			if ( i == pattern_len ) return j + len;

			do {
				res = XX_httplib_match_prefix( pattern + i, pattern_len - i, str + j + len );

			} while ( res == -1  &&  len-- > 0 );

			return (res == -1) ? -1 : j + res + len;
		}
		
		else if ( XX_httplib_lowercase(&pattern[i] ) != XX_httplib_lowercase( &str[j] ) ) return -1;

		i++;
		j++;
	}

	return j;

}  /* XX_httplib_match_prefix */
