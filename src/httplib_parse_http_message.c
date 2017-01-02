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
 * int XX_httplib_parse_http_message( char *buf, int len, struct lh_rqi_t *ri );
 *
 * The function XX_httplib_parse_http_message() parses an HTTP request and
 * fills in the lh_rqi_t structure. This function modifies the buffer by
 * NUL terminating HTTP request components, header names and header values.
 * Parameters:
 * 	buf (in/out)	pointer to the HTTP header to parse and split
 * 	len (in)	length of the HTTP header buffer
 * 	ri  (out)	parsed header as a lh_rqi_t structure
 * The parameters buf and ri must be valid pointers (not NULL) with a length
 * larger than zero. On error the function return a negative value, otherwise
 * the length of the request is returned.
 */

int XX_httplib_parse_http_message( char *buf, int len, struct lh_rqi_t *ri ) {

	int is_request;
	int request_length;
	char *start_line;

	request_length = XX_httplib_get_request_len( buf, len );

	if ( request_length > 0 ) {

		/*
		 * Reset attributes. DO NOT TOUCH is_ssl, remote_ip, remote_addr,
		 * remote_port
		 */

		ri->remote_user    = NULL;
		ri->request_method = NULL;
		ri->request_uri    = NULL;
		ri->http_version   = NULL;
		ri->num_headers    = 0;

		buf[request_length - 1] = '\0';

		/*
		 * RFC says that all initial whitespaces should be ingored
		 */

		while (*buf != '\0'  &&  isspace( *(unsigned char *)buf) ) buf++;

		start_line         = XX_httplib_skip( &buf, "\r\n" );
		ri->request_method = XX_httplib_skip( &start_line, " " );
		ri->request_uri    = XX_httplib_skip( &start_line, " " );
		ri->http_version   = start_line;

		/*
		 * HTTP message could be either HTTP request:
		 * "GET / HTTP/1.0 ..."
		 * or a HTTP response:
		 *  "HTTP/1.0 200 OK ..."
		 * otherwise it is invalid.
		 */

		is_request = XX_httplib_is_valid_http_method( ri->request_method );

		if ( (  is_request  &&  memcmp( ri->http_version,   "HTTP/", 5 ) != 0 ) || 
		     ( !is_request  &&  memcmp( ri->request_method, "HTTP/", 5 ) != 0 )   ) {

			/*
			 * Not a valid request or response: invalid
			 */

			return -1;
		}

		if ( is_request ) ri->http_version += 5;
		if ( XX_httplib_parse_http_headers( &buf, ri ) < 0 ) {

			/*
			 * Error while parsing headers
			 */

			return -1;
		}
	}

	return request_length;

}  /* XX_httplib_parse_http_message */
