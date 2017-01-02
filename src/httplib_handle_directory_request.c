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

void XX_httplib_handle_directory_request( struct lh_ctx_t *ctx, struct lh_con_t *conn, const char *dir ) {

	unsigned int i;
	int sort_direction;
	struct dir_scan_data data = { NULL, 0, 128 };
	char date[64];
	char error_string[ERROR_STRING_LEN];
	time_t curtime;

	if ( ctx == NULL  ||  conn == NULL )                                                                                 return;
	if ( dir  == NULL ) { XX_httplib_send_http_error( ctx, conn, 500, "Internal server error\nOpening NULL directory" ); return; }

	if ( ! XX_httplib_scan_directory( ctx, conn, dir, & data, XX_httplib_dir_scan_callback ) ) {

		XX_httplib_send_http_error( ctx, conn, 500, "Error: Cannot open directory\nopendir(%s): %s", dir, httplib_error_string( ERRNO, error_string, ERROR_STRING_LEN ) );
		return;
	}

	curtime = time( NULL );
	XX_httplib_gmt_time_string( date, sizeof(date), &curtime );

	sort_direction = ( conn->request_info.query_string != NULL  &&  conn->request_info.query_string[1] == 'd' ) ? 'a' : 'd';

	conn->must_close = true;

	httplib_printf( ctx, conn, "HTTP/1.1 200 OK\r\n" );
	XX_httplib_send_static_cache_header( ctx, conn );
	httplib_printf( ctx, conn, "Date: %s\r\n" "Connection: close\r\n" "Content-Type: text/html; charset=utf-8\r\n\r\n", date );

	conn->num_bytes_sent += httplib_printf( ctx, conn,
	              "<html><head><title>Index of %s</title>"
	              "<style>th {text-align: left;}</style></head>"
	              "<body><h1>Index of %s</h1><pre><table cellpadding=\"0\">"
	              "<tr><th><a href=\"?n%c\">Name</a></th>"
	              "<th><a href=\"?d%c\">Modified</a></th>"
	              "<th><a href=\"?s%c\">Size</a></th></tr>"
	              "<tr><td colspan=\"3\"><hr></td></tr>",
	              conn->request_info.local_uri,
	              conn->request_info.local_uri,
	              sort_direction,
	              sort_direction,
	              sort_direction );

	/*
	 * Print first entry - link to a parent directory
	 */

	conn->num_bytes_sent += httplib_printf( ctx, conn,
	              "<tr><td><a href=\"%s%s\">%s</a></td>"
	              "<td>&nbsp;%s</td><td>&nbsp;&nbsp;%s</td></tr>\n",
	              conn->request_info.local_uri,
	              "..",
	              "Parent directory",
	              "-",
	              "-" );

	/*
	 * Sort and print directory entries
	 */

	if ( data.entries != NULL ) {

		qsort( data.entries, (size_t)data.num_entries, sizeof(data.entries[0]), XX_httplib_compare_dir_entries );

		for (i=0; i<data.num_entries; i++) {

			XX_httplib_print_dir_entry( ctx, & data.entries[i] );
			data.entries[i].file_name = httplib_free( data.entries[i].file_name );
		}

		data.entries = httplib_free( data.entries );
	}

	conn->num_bytes_sent += httplib_printf( ctx, conn, "%s", "</table></body></html>" );
	conn->status_code     = 200;

}  /* XX_httplib_handle_directory_request */
