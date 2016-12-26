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
#include "httplib_string.h"

/* Return 1 if request is authorised, 0 otherwise. */
bool XX_httplib_check_authorization( struct httplib_connection *conn, const char *path ) {

	char fname[PATH_MAX];
	struct vec uri_vec;
	struct vec filename_vec;
	const char *list;
	struct file file = STRUCT_FILE_INITIALIZER;
	bool authorized;
	bool truncated;

	if ( conn == NULL  ||  conn->ctx == NULL ) return false;

	authorized = true;

	list = conn->ctx->cfg[PROTECT_URI];

	while ( (list = XX_httplib_next_option( list, &uri_vec, &filename_vec )) != NULL ) {

		if ( ! memcmp( conn->request_info.local_uri, uri_vec.ptr, uri_vec.len ) ) {

			XX_httplib_snprintf( conn, &truncated, fname, sizeof(fname), "%.*s", (int)filename_vec.len, filename_vec.ptr );

			if ( truncated  ||  ! XX_httplib_fopen( conn, fname, "r", &file ) ) {

				httplib_cry( conn, "%s: cannot open %s: %s", __func__, fname, strerror(errno) );
			}
			break;
		}
	}

	if ( ! XX_httplib_is_file_opened( & file ) ) XX_httplib_open_auth_file( conn, path, & file );

	if ( XX_httplib_is_file_opened( & file ) ) {

		authorized = XX_httplib_authorize( conn, & file );
		XX_httplib_fclose( & file );
	}

	return authorized;

}  /* XX_httplib_check_authorization */
