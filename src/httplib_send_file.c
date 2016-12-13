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
 */

#include "httplib_main.h"

void mg_send_file( struct mg_connection *conn, const char *path ) {

	mg_send_mime_file( conn, path, NULL );

}  /* mg_send_file */


void mg_send_mime_file( struct mg_connection *conn, const char *path, const char *mime_type ) {

	mg_send_mime_file2( conn, path, mime_type, NULL );

}  /* mg_send_mime_file */


void mg_send_mime_file2( struct mg_connection *conn, const char *path, const char *mime_type, const char *additional_headers ) {

	struct file file = STRUCT_FILE_INITIALIZER;

	if (XX_httplib_stat(conn, path, &file)) {
		if (file.is_directory) {
			if ( conn == NULL ) return;
			if (!mg_strcasecmp(conn->ctx->config[ENABLE_DIRECTORY_LISTING], "yes")) {
				XX_httplib_handle_directory_request(conn, path);
			} else {
				XX_httplib_send_http_error(conn, 403, "%s", "Error: Directory listing denied");
			}
		} else {
			XX_httplib_handle_static_file_request( conn, path, &file, mime_type, additional_headers);
		}
	} else XX_httplib_send_http_error(conn, 404, "%s", "Error: File not found");

}  /* mg_send_mime_file2 */
