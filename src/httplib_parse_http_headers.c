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
 * int XX_httplib_parse_http_headers( char **buf, struct lh_rqi_t *ri );
 *
 * The function XX_httplib_parse_http_headers() parses the HTTP headers from
 * the given buffer. The buf pointer is advanced to the point where parsing
 * stopped. All parameters must be valid pointers (not NULL). The number of
 * headers read is returned, or a negative value if an error occured.
 */

int XX_httplib_parse_http_headers( char **buf, struct lh_rqi_t *ri ) {

	int i;

	ri->num_headers = 0;

	for (i=0; i<(int)ARRAY_SIZE(ri->http_headers); i++) {

		char *dp = *buf;

		while ( *dp != ':'  &&  *dp >= 33  &&  *dp <= 126 ) dp++;

		if (  dp == *buf ) break;	/* End of headers reached.	*/
		if ( *dp != ':'  ) return -1;	/* This is not a valid field.	*/

		/*
		 * End of header key (*dp == ':')
		 * Truncate here and set the key name
		 */

		*dp = 0;
		ri->http_headers[i].name = *buf;
		do {
			dp++;
		} while (*dp == ' ');

		/*
		 * The rest of the line is the value
		 */

		ri->http_headers[i].value = dp;
		*buf                      = dp + strcspn(dp, "\r\n");

		if ( (*buf)[0] != '\r'  ||  (*buf)[1] != '\n' ) *buf = NULL;


		ri->num_headers = i+1;

		if ( *buf ) {

			(*buf)[0] = 0;
			(*buf)[1] = 0;
			*buf     += 2;
		}
		
		else {
			*buf = dp;
			break;
		}

		if ( (*buf)[0] == '\r' ) {

			/*
			 * This is the end of the header
			 */

			break;
		}
	}

	return ri->num_headers;

}  /* XX_httplib_parse_http_headers */
