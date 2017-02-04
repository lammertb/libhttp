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
 * void XX_httplib_handle_static_file_request();
 *
 * The function XX_httplib_handle_static_file_request() handles an incoming
 * request for a static file.
 */

void XX_httplib_handle_static_file_request( struct lh_ctx_t *ctx, struct lh_con_t *conn, const char *path, struct file *filep, const char *mime_type, const char *additional_headers ) {

	char date[64];
	char lm[64];
	char etag[64];
	char range[128]; /* large enough, so there will be no overflow */
	const char *msg;
	const char *hdr;
	time_t curtime;
	int64_t cl;
	int64_t r1;
	int64_t r2;
	struct vec mime_vec;
	int n;
	bool truncated;
	char gz_path[PATH_MAX];
	char error_string[ERROR_STRING_LEN];
	const char *encoding;
	const char *cors1;
	const char *cors2;
	const char *cors3;

	if ( ctx == NULL  ||  conn == NULL  ||  filep == NULL ) return;

	msg      = "OK";
	curtime  = time( NULL );
	encoding = "";

	if ( mime_type == NULL ) XX_httplib_get_mime_type( ctx, path, &mime_vec );
	
	else {
		mime_vec.ptr = mime_type;
		mime_vec.len = strlen( mime_type );
	}

	if ( filep->size > INT64_MAX ) XX_httplib_send_http_error( ctx, conn, 500, "Error: File size is too large to send\n%" INT64_FMT, filep->size );

	cl                = (int64_t)filep->size;
	conn->status_code = 200;
	range[0]          = '\0';

	/*
	 * if this file is in fact a pre-gzipped file, rewrite its filename
	 * it's important to rewrite the filename after resolving
	 * the mime type from it, to preserve the actual file's type
	 */

	if ( filep->gzipped ) {

		XX_httplib_snprintf( ctx, conn, &truncated, gz_path, sizeof(gz_path), "%s.gz", path );

		if ( truncated ) {

			XX_httplib_send_http_error( ctx, conn, 500, "Error: Path of zipped file too long (%s)", path );
			return;
		}

		path     = gz_path;
		encoding = "Content-Encoding: gzip\r\n";
	}

	if ( ! XX_httplib_fopen( ctx, conn, path, "rb", filep ) ) {

		XX_httplib_send_http_error( ctx, conn, 500, "Error: Cannot open file\nfopen(%s): %s", path, httplib_error_string( ERRNO, error_string, ERROR_STRING_LEN ) );
		return;
	}

	XX_httplib_fclose_on_exec( ctx, filep, conn );

	/*
	 * If Range: header specified, act accordingly
	 */

	r1  = 0;
	r2  = 0;
	hdr = httplib_get_header( conn, "Range" );

	if ( hdr != NULL  &&  (n = XX_httplib_parse_range_header( hdr, &r1, &r2 )) > 0  &&  r1 >= 0  &&  r2 >= 0 ) {

		/*
		 * actually, range requests don't play well with a pre-gzipped
		 * file (since the range is specified in the uncompressed space)
		 */

		if ( filep->gzipped ) {

			XX_httplib_send_http_error( ctx, conn, 501, "%s", "Error: Range requests in gzipped files are not supported"); XX_httplib_fclose(filep);
			return;
		}
		conn->status_code = 206;
		cl                = (n == 2) ? (((r2 > cl) ? cl : r2) - r1 + 1) : (cl - r1);

		XX_httplib_snprintf( ctx, conn,
		            NULL, /* range buffer is big enough */
		            range,
		            sizeof(range),
		            "Content-Range: bytes "
		            "%" INT64_FMT "-%" INT64_FMT "/%" INT64_FMT "\r\n",
		            r1,
		            r1 + cl - 1,
		            filep->size );

		msg = "Partial Content";
	}

	hdr = httplib_get_header( conn, "Origin" );

	if ( hdr ) {
		/*
		 * Cross-origin resource sharing (CORS), see
		 * http://www.html5rocks.com/en/tutorials/cors/,
		 * http://www.html5rocks.com/static/images/cors_server_flowchart.png -
		 * preflight is not supported for files.
		 */

		cors1 = "Access-Control-Allow-Origin: ";
		cors2 = ( ctx->access_control_allow_origin != NULL ) ? ctx->access_control_allow_origin : "";
		cors3 = "\r\n";
	}
	else {
		cors1 = "";
		cors2 = "";
		cors3 = "";
	}

	/*
	 * Prepare Etag, Date, Last-Modified headers. Must be in UTC, according to
	 * http://www.w3.org/Protocols/rfc2616/rfc2616-sec3.html#sec3.3
	 */

	XX_httplib_gmt_time_string( date, sizeof(date), & curtime              );
	XX_httplib_gmt_time_string( lm,   sizeof(lm),   & filep->last_modified );
	XX_httplib_construct_etag(  ctx, etag, sizeof(etag), filep             );

	httplib_printf( ctx, conn, "HTTP/1.1 %d %s\r\n" "%s%s%s" "Date: %s\r\n", conn->status_code, msg, cors1, cors2, cors3, date );
	XX_httplib_send_static_cache_header( ctx, conn );
	httplib_printf( ctx, conn,
	                "Last-Modified: %s\r\n"
	                "Etag: %s\r\n"
	                "Content-Type: %.*s\r\n"
	                "Content-Length: %" INT64_FMT "\r\n"
	                "Connection: %s\r\n"
	                "Accept-Ranges: bytes\r\n"
	                "%s%s",
	                lm,
	                etag,
	                (int)mime_vec.len,
	                mime_vec.ptr,
	                cl,
	                XX_httplib_suggest_connection_header( ctx, conn ),
	                range,
	                encoding );

	/*
	 * The previous code must not add any header starting with X- to make
	 * sure no one of the additional_headers is included twice
	 */

	if ( additional_headers != NULL ) httplib_printf( ctx, conn, "%.*s\r\n\r\n", (int)strlen( additional_headers ), additional_headers );
	else                              httplib_printf( ctx, conn, "\r\n"                                                                );

	if ( strcmp( conn->request_info.request_method, "HEAD" ) != 0 ) XX_httplib_send_file_data( ctx, conn, filep, r1, cl );

	XX_httplib_fclose( filep );

}  /* XX_handle_static_file_request */
