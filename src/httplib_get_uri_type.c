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
 * enum uri_type_t XX_httplib_get_uri_type( const char *uri );
 *
 * The function XX_httplib_get_uri_type() returns the URI type of an URI. This
 * can be any of the following values:
 */

enum uri_type_t XX_httplib_get_uri_type( const char *uri ) {

	int i;
	char *hostend;
	char *portbegin;
	char *portend;
	unsigned long port;

	/*
	 * According to the HTTP standard
	 * http://www.w3.org/Protocols/rfc2616/rfc2616-sec5.html#sec5.1.2
	 * URI can be an asterisk (*) or should start with slash (relative uri),
	 * or it should start with the protocol (absolute uri).
	 */

	if (uri[0] == '*' && uri[1] == '\0') return URI_TYPE_ASTERISK;

	/*
	 * Valid URIs according to RFC 3986
	 * (https://www.ietf.org/rfc/rfc3986.txt)
	 * must only contain reserved characters :/?#[]@!$&'()*+,;=
	 * and unreserved characters A-Z a-z 0-9 and -._~
	 * and % encoded symbols.
	 */

	for (i = 0; uri[i] != 0; i++) {
		if ( uri[i] < 33  ) return URI_TYPE_UNKNOWN;	/* control characters and spaces are invalid	*/
		if ( uri[i] > 126 ) return URI_TYPE_UNKNOWN;	/* non-ascii characters must be % encoded	*/

		switch ( uri[i] ) {
			case '"':  /*  34 */
			case '<':  /*  60 */
			case '>':  /*  62 */
			case '\\': /*  92 */
			case '^':  /*  94 */
			case '`':  /*  96 */
			case '{':  /* 123 */
			case '|':  /* 124 */
			case '}':  /* 125 */
				return URI_TYPE_UNKNOWN;

			default:
				/*
				 * character is ok
				 */

				break;
		}
	}

	/*
	 * A relative uri starts with a / character
	 */

	if ( uri[0] == '/' ) return URI_TYPE_RELATIVE;		/* relative uri		*/

	/*
	 * It could be an absolute uri:
	 * This function only checks if the uri is valid, not if it is
	 * addressing the current server. So LibHTTP can also be used
	 * as a proxy server.
	 */

	for (i=0; XX_httplib_abs_uri_protocols[i].proto != NULL; i++) {

		if ( httplib_strncasecmp( uri, XX_httplib_abs_uri_protocols[i].proto, XX_httplib_abs_uri_protocols[i].proto_len ) == 0 ) { 

			hostend = strchr( uri + XX_httplib_abs_uri_protocols[i].proto_len, '/' );
			if ( hostend == NULL ) return URI_TYPE_UNKNOWN;

			portbegin = strchr( uri + XX_httplib_abs_uri_protocols[i].proto_len, ':' );
			if ( portbegin == NULL ) return URI_TYPE_ABS_NOPORT;

			port = strtoul( portbegin+1, &portend, 10 );

			if ( portend != hostend  ||  ! port  ||  ! XX_httplib_is_valid_port( port ) ) return URI_TYPE_UNKNOWN;

			return URI_TYPE_ABS_PORT;
		}
	}

	return URI_TYPE_UNKNOWN;

}  /* XX_httplib_get_uri_type */
