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
 * static void print_props( struct lh_ctx_t *ctx, struct lh_con_t *conn, const char *uri, struct file *filep );
 *
 * The function print_props() writes the PROPFIND properties for a collection
 * event.
 */

static void print_props( struct lh_ctx_t *ctx, struct lh_con_t *conn, const char *uri, struct file *filep ) {

	char mtime[64];

	if ( conn == NULL  ||  uri == NULL  ||  filep == NULL ) return;

	XX_httplib_gmt_time_string( mtime, sizeof(mtime), &filep->last_modified );
	conn->num_bytes_sent += httplib_printf( ctx, conn,
	              "<d:response>"
	              "<d:href>%s</d:href>"
	              "<d:propstat>"
	              "<d:prop>"
	              "<d:resourcetype>%s</d:resourcetype>"
	              "<d:getcontentlength>%" INT64_FMT "</d:getcontentlength>"
	              "<d:getlastmodified>%s</d:getlastmodified>"
	              "</d:prop>"
	              "<d:status>HTTP/1.1 200 OK</d:status>"
	              "</d:propstat>"
	              "</d:response>\n",
	              uri,
	              filep->is_directory ? "<d:collection/>" : "",
	              filep->size,
	              mtime );

}  /* print_props */

/*
 * static void print_dav_dir_entry( struct lh_ctx_t *ctx, struct de *de, void *data );
 *
 * The function print_dav_dir_entry() is used to send the properties of a
 * webdav directory to the remote client.
 */

static void print_dav_dir_entry( struct lh_ctx_t *ctx, struct de *de, void *data ) {

	char href[PATH_MAX];
	char href_encoded[PATH_MAX * 3 /* worst case */];
	bool truncated;
	struct lh_con_t *conn;

	conn = data;

	if ( de == NULL  ||  conn == NULL ) return;

	XX_httplib_snprintf( ctx, conn, &truncated, href, sizeof(href), "%s%s", conn->request_info.local_uri, de->file_name );

	if ( ! truncated ) {

		httplib_url_encode( href, href_encoded, PATH_MAX * 3 );
		print_props( ctx, conn, href_encoded, &de->file );
	}

}  /* print_dav_dir_entry */

/*
 * void XX_httplib_handle_propfind( struct lh_ctx_t *ctx, struct lh_con_t *conn, const char *path, struct file *filep );
 *
 * The function XX_httlib_handle_propfind() handles a propfind request.
 */

void XX_httplib_handle_propfind( struct lh_ctx_t *ctx, struct lh_con_t *conn, const char *path, struct file *filep ) {

	const char *depth;
	char date[64];
	time_t curtime;

	if ( ctx == NULL  ||  conn == NULL  ||  path == NULL  ||  filep == NULL ) return;
	if ( ctx->document_root == NULL ) return;

	depth   = httplib_get_header( conn, "Depth" );
	curtime = time( NULL );

	XX_httplib_gmt_time_string( date, sizeof(date), &curtime );

	conn->must_close  = true;
	conn->status_code = 207;
	httplib_printf( ctx, conn, "HTTP/1.1 207 Multi-Status\r\n" "Date: %s\r\n", date );
	XX_httplib_send_static_cache_header( ctx, conn );
	httplib_printf( ctx, conn, "Connection: %s\r\n" "Content-Type: text/xml; charset=utf-8\r\n\r\n", XX_httplib_suggest_connection_header( ctx, conn ) );

	conn->num_bytes_sent += httplib_printf( ctx, conn, "<?xml version=\"1.0\" encoding=\"utf-8\"?>" "<d:multistatus xmlns:d='DAV:'>\n" );

	/*
	 * Print properties for the requested resource itself
	 */

	print_props( ctx, conn, conn->request_info.local_uri, filep );

	/*
	 * If it is a directory, print directory entries too if Depth is not 0
	 */

	if ( ctx->enable_directory_listing  &&  filep  &&  filep->is_directory  &&  ( depth == NULL  ||  strcmp( depth, "0" ) != 0 ) ) {

		XX_httplib_scan_directory( ctx, conn, path, conn, &print_dav_dir_entry );
	}

	conn->num_bytes_sent += httplib_printf( ctx, conn, "%s\n", "</d:multistatus>" );

}  /* XX_httplib_handle_propfind */
