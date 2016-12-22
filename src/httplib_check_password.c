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

/* Check the user's password, return 1 if OK */
bool XX_httplib_check_password( const char *method, const char *ha1, const char *uri, const char *nonce, const char *nc, const char *cnonce, const char *qop, const char *response ) {

	char ha2[32 + 1];
	char expected_response[32 + 1];

	/*
	 * Some of the parameters may be NULL
	 */

	if ( method == NULL  ||  nonce == NULL  ||  nc == NULL  ||  cnonce == NULL  ||  qop == NULL  ||  response == NULL ) return false;

	/*
	 * NOTE(lsm): due to a bug in MSIE, we do not compare the URI
	 */

	if ( strlen(response) != 32 ) return false;

	httplib_md5( ha2, method, ":", uri, NULL );
	httplib_md5( expected_response, ha1, ":", nonce, ":", nc, ":", cnonce, ":", qop, ":", ha2, NULL );

	return ( httplib_strcasecmp( response, expected_response ) == 0 );

}  /* XX_httplib_check_password */
