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

/* Return HTTP header value, or NULL if not found. */
const char *XX_httplib_get_header( const struct lh_rqi_t *ri, const char *name ) {

	int i;

	if ( ri == NULL  ||  name == NULL ) return NULL;

	for (i=0; i<ri->num_headers; i++) {

		if ( ! httplib_strcasecmp( name, ri->http_headers[i].name ) ) return ri->http_headers[i].value;
	}

	return NULL;

}  /* XX_httplib_get_header */


const char *httplib_get_header( const struct lh_con_t *conn, const char *name ) {

	if ( conn == NULL ) return NULL;

	return XX_httplib_get_header( & conn->request_info, name );

}  /* httplib_get_header */
