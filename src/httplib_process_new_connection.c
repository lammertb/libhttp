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
#include "httplib_memory.h"
#include "httplib_string.h"

/*
 * void XX_httplib_process_new_connection( struct httplib_connection *conn );
 *
 * The function XX_httplib_process_new_connection() is used to process a new
 * incoming connection on a socket.
 */

void XX_httplib_process_new_connection( struct httplib_connection *conn ) {

	struct httplib_request_info *ri;
	int keep_alive_enabled;
	int keep_alive;
	int discard_len;
	char ebuf[100];
	const char *hostend;
	int reqerr;
	int uri_type;
	union {
		const void *	con;
		void *		var;
	} ptr;

	if ( conn == NULL  ||  conn->ctx == NULL ) return;

	ri                 = & conn->request_info;
	keep_alive_enabled = ! strcmp( conn->ctx->config[ENABLE_KEEP_ALIVE], "yes" );

	/*
	 * Important: on new connection, reset the receiving buffer. Credit
	 * goes to crule42.
	 */

	conn->data_len = 0;
	do {
		if ( ! XX_httplib_getreq( conn, ebuf, sizeof(ebuf), &reqerr ) ) {

			/*
			 * The request sent by the client could not be understood by
			 * the server, or it was incomplete or a timeout. Send an
			 * error message and close the connection.
			 */

			if ( reqerr > 0 ) {
				/*assert(ebuf[0] != '\0');*/
				XX_httplib_send_http_error( conn, reqerr, "%s", ebuf );
			}
		}
		
		else if ( strcmp( ri->http_version, "1.0" )  &&  strcmp( ri->http_version, "1.1" ) ) {

			XX_httplib_snprintf( conn, NULL, ebuf, sizeof(ebuf), "Bad HTTP version: [%s]", ri->http_version );
			XX_httplib_send_http_error( conn, 505, "%s", ebuf );
		}

		if ( ebuf[0] == '\0' ) {

			uri_type = XX_httplib_get_uri_type( conn->request_info.request_uri );

			switch ( uri_type ) {

				case 1 :
					/*
					 * Asterisk
					 */

					conn->request_info.local_uri = NULL;
					break;

				case 2 :
					/*
					 * relative uri
					 */

					conn->request_info.local_uri = conn->request_info.request_uri;
					break;
				case 3 :
				case 4 :
					/*
					 * absolute uri (with/without port)
					 */

					hostend = XX_httplib_get_rel_url_at_current_server( conn->request_info.request_uri, conn );

					if (hostend) conn->request_info.local_uri = hostend;
					else         conn->request_info.local_uri = NULL;
					break;

				default :
					XX_httplib_snprintf( conn, NULL, ebuf, sizeof(ebuf), "Invalid URI" );
					XX_httplib_send_http_error( conn, 400, "%s", ebuf );
					conn->request_info.local_uri = NULL;
					break;
			}

			/*
			 * TODO: cleanup uri, local_uri and request_uri
			 */
			conn->request_info.uri = conn->request_info.local_uri;
		}

		if ( ebuf[0] == '\0' ) {

			if ( conn->request_info.local_uri ) {

				/*
				 * handle request to local server
				 */

				XX_httplib_handle_request( conn );
				if (conn->ctx->callbacks.end_request != NULL) conn->ctx->callbacks.end_request(conn, conn->status_code);
				XX_httplib_log_access(conn);
			}
			
			else {
				/*
				 * TODO: handle non-local request (PROXY)
				 */
				conn->must_close = 1;
			}
		}
		
		else conn->must_close = 1;

		if ( ri->remote_user != NULL ) {

			ptr.con = ri->remote_user;
			httplib_free( ptr.var );

			/*
			 * Important! When having connections with and without auth
			 * would cause double free and then crash
			 */

			ri->remote_user = NULL;
		}

		/*
		 * NOTE(lsm): order is important here. XX_httplib_should_keep_alive() call is
		 * using parsed request, which will be invalid after memmove's below.
		 * Therefore, memorize XX_httplib_should_keep_alive() result now for later use
		 * in loop exit condition.
		 */

		keep_alive = conn->ctx->stop_flag == 0  &&  keep_alive_enabled  &&  conn->content_len >= 0  &&  XX_httplib_should_keep_alive( conn );

		/*
		 * Discard all buffered data for this request
		 */

		discard_len = ((conn->content_len >= 0) && (conn->request_len > 0)
		               && ((conn->request_len + conn->content_len)
		                   < (int64_t)conn->data_len))
		                  ? (int)(conn->request_len + conn->content_len)
		                  : conn->data_len;

		if ( discard_len < 0 ) break;
		conn->data_len -= discard_len;
		if ( conn->data_len > 0 ) memmove( conn->buf, conn->buf + discard_len, (size_t)conn->data_len );

		if ( conn->data_len < 0  ||  conn->data_len > conn->buf_size ) break;

	} while ( keep_alive );

}  /* XX_httplib_process_new_connection */
