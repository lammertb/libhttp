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

int httplib_get_var( const char *data, size_t data_len, const char *name, char *dst, size_t dst_len ) {

	return httplib_get_var2( data, data_len, name, dst, dst_len, 0 );

}  /* httplib_get_var */


int httplib_get_var2( const char *data, size_t data_len, const char *name, char *dst, size_t dst_len, size_t occurrence ) {

	const char *p;
	const char *e;
	const char *s;
	size_t name_len;
	int len;

	if ( dst == NULL  ||  dst_len < 1 ) return -2;

	if ( data == NULL  ||  name == NULL  ||  data_len == 0 ) {

		dst[0] = '\0';
		return -1;
	}
	
	name_len = strlen( name );
	e        = data + data_len;
	len      = -1;
	dst[0]   = '\0';

	/*
	 * data is "var1=val1&var2=val2...". Find variable first
	 */

	for (p=data; p+name_len < e; p++) {

		if ( (p == data || p[-1] == '&')  &&  p[name_len] == '='  &&  ! httplib_strncasecmp( name, p, name_len )  &&  occurrence-- == 0 ) {

			/*
			 * Point p to variable value
			 */

			p += name_len + 1;

			/*
			 * Point s to the end of the value
			 */

			s = (const char *)memchr( p, '&', (size_t)(e - p) );
			if (s == NULL) s = e;

			/*
			 * assert(s >= p);
			 */

			if (s < p) return -3;

			/*
			 * Decode variable into destination buffer
			 */

			len = httplib_url_decode( p, (int)(s - p), dst, (int)dst_len, 1 );

			/*
			 * Redirect error code from -1 to -2 (destination buffer too
			 * small).
			 */

			if (len == -1) len = -2;
			break;
		}
	}

	return len;

}  /* httplib_get_var2 */
