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
#include "httplib_utils.h"

/*
 * void XX_httplib_mkcol( struct lh_ctx_t *ctx, struct lh_con_t *conn, const char *path );
 *
 * The function XX_httplib_mkcol() handles a MKCOL command from a remote
 * client. The MKCOL method is used to create a new collection resource at the
 * location specificied by the request URI.
 */

void XX_httplib_mkcol( struct lh_ctx_t *ctx, struct lh_con_t *conn, const char *path ) {

	int rc;
	int body_len;
	struct de de;
	char date[64];
	time_t curtime;
	char error_string[ERROR_STRING_LEN];

	if ( ctx == NULL  ||  conn == NULL ) return;
	if ( ctx->document_root    == NULL ) return;

	curtime = time( NULL );

	/*
	 * TODO (mid): Check the XX_httplib_send_http_error situations in this function
	 */

	memset( & de.file, 0, sizeof(de.file) );

	if ( ! XX_httplib_stat( ctx, conn, path, & de.file ) ) {

		httplib_cry( LH_DEBUG_WARNING, ctx, conn, "%s: XX_httplib_stat(%s) failed: %s", __func__, path, httplib_error_string( ERRNO, error_string, ERROR_STRING_LEN ) );
	}

	if ( de.file.last_modified ) {

		/*
		 * TODO (high): This check does not seem to make any sense !
		 */

		XX_httplib_send_http_error( ctx, conn, 405, "Error: mkcol(%s): %s", path, httplib_error_string( ERRNO, error_string, ERROR_STRING_LEN ) );
		return;
	}

	body_len = conn->data_len - conn->request_len;

	if ( body_len > 0 ) {

		XX_httplib_send_http_error( ctx, conn, 415, "Error: mkcol(%s): %s", path, httplib_error_string( ERRNO, error_string, ERROR_STRING_LEN ) );
		return;
	}

	rc = httplib_mkdir( path, 0755 );

	if ( rc == 0 ) {

		conn->status_code = 201;
		XX_httplib_gmt_time_string( date, sizeof(date), &curtime );
		httplib_printf( ctx, conn, "HTTP/1.1 %d Created\r\n" "Date: %s\r\n", conn->status_code, date );
		XX_httplib_send_static_cache_header( ctx, conn );
		httplib_printf( ctx, conn, "Content-Length: 0\r\n" "Connection: %s\r\n\r\n", XX_httplib_suggest_connection_header( ctx, conn ) );
	}
	
	else if ( rc == -1 ) {

		if      ( errno == EEXIST ) XX_httplib_send_http_error( ctx, conn, 405, "Error: mkcol(%s): %s", path, httplib_error_string( ERRNO, error_string, ERROR_STRING_LEN ) );
		else if ( errno == EACCES ) XX_httplib_send_http_error( ctx, conn, 403, "Error: mkcol(%s): %s", path, httplib_error_string( ERRNO, error_string, ERROR_STRING_LEN ) );
		else if ( errno == ENOENT ) XX_httplib_send_http_error( ctx, conn, 409, "Error: mkcol(%s): %s", path, httplib_error_string( ERRNO, error_string, ERROR_STRING_LEN ) );
		else                        XX_httplib_send_http_error( ctx, conn, 500, "fopen(%s): %s",        path, httplib_error_string( ERRNO, error_string, ERROR_STRING_LEN ) );
	}

}  /* XX_httplib_mkcol */
