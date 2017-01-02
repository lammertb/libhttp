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
 * void httplib_send_file( struct lh_ctx_t *ctx, struct lh_con_t *conn, const char *path, const char *mime_type, const char *additional_headers );
 *
 * The function httplib_send_file() sends a file to the other peer. Optionally
 * the MIME type and additional headers can be specified.
 */

void httplib_send_file( struct lh_ctx_t *ctx, struct lh_con_t *conn, const char *path, const char *mime_type, const char *additional_headers ) {

	struct file file = STRUCT_FILE_INITIALIZER;

	if ( ctx == NULL  ||  conn == NULL ) return;

	if ( XX_httplib_stat( ctx, conn, path, &file ) ) {

		if ( file.is_directory ) {

			if ( ctx->enable_directory_listing ) XX_httplib_handle_directory_request( ctx, conn, path );
			else XX_httplib_send_http_error( ctx, conn, 403, "%s", "Error: Directory listing denied" );
		}
		
		else XX_httplib_handle_static_file_request( ctx, conn, path, &file, mime_type, additional_headers );
	}
	
	else XX_httplib_send_http_error( ctx, conn, 404, "%s", "Error: File not found" );

}  /* httplib_send_file */
