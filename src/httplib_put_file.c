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
 * void XX_httplib_put_file( struct lh_ctx_t *ctx, struct lh_con_t *conn, const char *path );
 *
 * The function XX_httplib_put_file() processes a file PUT request coming from
 * a remote client.
 */

void XX_httplib_put_file( struct lh_ctx_t *ctx, struct lh_con_t *conn, const char *path ) {

	struct file file = STRUCT_FILE_INITIALIZER;
	const char *range;
	int64_t r1;
	int64_t r2;
	int rc;
	char date[64];
	char error_string[ERROR_STRING_LEN];
	time_t curtime;

	if ( ctx == NULL  ||  conn == NULL ) return;
	if ( ctx->document_root    == NULL ) return;

	curtime = time( NULL );

	if ( XX_httplib_stat( ctx, conn, path, &file ) ) {

		/*
		 * File already exists
		 */

		conn->status_code = 200;

		if ( file.is_directory ) {

			/*
			 * This is an already existing directory,
			 * so there is nothing to do for the server.
			 */

			rc = 0;

		}
		
		else {
			/*
			 * File exists and is not a directory.
			 * Can it be replaced?
			 */

			if ( file.membuf != NULL ) {

				/*
				 * This is an "in-memory" file, that can not be replaced
				 */

				XX_httplib_send_http_error( ctx, conn, 405, "Error: Put not possible\nReplacing %s is not supported", path );
				return;
			}

			/*
			 * Check if the server may write this file
			 */

			if ( access( path, W_OK ) == 0 ) {

				/*
				 * Access granted
				 */

				conn->status_code = 200;
				rc                = 1;
			}
			
			else {
				XX_httplib_send_http_error( ctx, conn, 403, "Error: Put not possible\nReplacing %s is not allowed", path );
				return;
			}
		}
	}
	
	else {
		/*
		 * File should be created
		 */

		conn->status_code = 201;
		rc                = XX_httplib_put_dir( ctx, conn, path );
	}

	if ( rc == 0 ) {

		/*
		 * XX_httplib_put_dir returns 0 if path is a direct ory
		 */

		XX_httplib_gmt_time_string( date, sizeof(date), &curtime );
		httplib_printf( ctx, conn, "HTTP/1.1 %d %s\r\n", conn->status_code, httplib_get_response_code_text( ctx, NULL, conn->status_code ) );
		XX_httplib_send_no_cache_header( ctx, conn );
		httplib_printf( ctx, conn, "Date: %s\r\n" "Content-Length: 0\r\n" "Connection: %s\r\n\r\n", date, XX_httplib_suggest_connection_header( ctx, conn ) );

		/*
		 * Request to create a directory has been fulfilled successfully.
		 * No need to put a file.
		 */

		return;
	}

	if ( rc == -1 ) {

		/*
		 * XX_httplib_put_dir returns -1 if the path is too long
		 */

		XX_httplib_send_http_error( ctx, conn, 414, "Error: Path too long\nput_dir(%s): %s", path, httplib_error_string( ERRNO, error_string, ERROR_STRING_LEN ) );
		return;
	}

	if ( rc == -2 ) {

		/*
		 * XX_httplib_put_dir returns -2 if the directory can not be created
		 */

		XX_httplib_send_http_error( ctx, conn, 500, "Error: Can not create directory\nput_dir(%s): %s", path, httplib_error_string( ERRNO, error_string, ERROR_STRING_LEN ) );
		return;
	}

	/*
	 * A file should be created or overwritten.
	 */

	if ( ! XX_httplib_fopen( ctx, conn, path, "wb+", &file)  ||  file.fp == NULL ) {

		XX_httplib_fclose( & file );
		XX_httplib_send_http_error( ctx, conn, 500, "Error: Can not create file\nfopen(%s): %s", path, httplib_error_string( ERRNO, error_string, ERROR_STRING_LEN ) );
		return;
	}

	XX_httplib_fclose_on_exec( ctx, &file, conn );

	range = httplib_get_header( conn, "Content-Range" );
	r1    = 0;
	r2    = 0;

	if ( range != NULL  &&  XX_httplib_parse_range_header( range, &r1, &r2 ) > 0 ) {

		conn->status_code = 206; /* Partial content */
		fseeko( file.fp, r1, SEEK_SET );
	}

	if ( ! XX_httplib_forward_body_data( ctx, conn, file.fp, INVALID_SOCKET, NULL ) ) {

		/*
		 * XX_httplib_forward_body_data failed.
		 * The error code has already been sent to the client,
		 * and conn->status_code is already set.
		 */

		XX_httplib_fclose( & file );
		return;
	}

	XX_httplib_gmt_time_string( date, sizeof(date), &curtime );
	httplib_printf( ctx, conn, "HTTP/1.1 %d %s\r\n", conn->status_code, httplib_get_response_code_text( ctx, NULL, conn->status_code ) );
	XX_httplib_send_no_cache_header( ctx, conn );
	httplib_printf( ctx, conn, "Date: %s\r\n" "Content-Length: 0\r\n" "Connection: %s\r\n\r\n", date, XX_httplib_suggest_connection_header( ctx, conn ) );

	XX_httplib_fclose( & file );

}  /* XX_httplib_put_file */
