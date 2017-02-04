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
 * HCP24: some changes to compare hole var_name
 */

int httplib_get_cookie( const char *cookie_header, const char *var_name, char *dst, size_t dst_size ) {

	const char *s;
	const char *p;
	const char *end;
	int name_len;
	int len;

	if ( dst == NULL  ||  dst_size < 1 ) return -2;

	len    = -1;
	dst[0] = '\0';
	if ( var_name == NULL  ||  cookie_header == NULL ) return -1;

	s = cookie_header;

	name_len = (int)strlen( var_name );
	end      = s + strlen( s );

	while ( (s = httplib_strcasestr( s, var_name )) != NULL ) {

		if (s[name_len] == '=') {

			/*
			 * HCP24: now check is it a substring or a full cookie name
			 */

			if ( s == cookie_header  ||  s[-1] == ' ' ) {

				s += name_len + 1;
				if ( (p = strchr(s, ' ')) == NULL ) p = end;
				if ( p[-1] == ';' ) p--;
				if ( *s == '"' && p[-1] == '"' && p > s + 1 ) {
					s++;
					p--;
				}
				if ( (size_t)(p - s) < dst_size ) {

					len = (int)(p - s);
					httplib_strlcpy( dst, s, (size_t)len+1 );
				}
				else len = -3;

				break;
			}
		}

		s += name_len;
	}

	return len;

}  /* httplib_get_cookie */
