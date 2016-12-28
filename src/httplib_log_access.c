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
#include "httplib_ssl.h"
#include "httplib_string.h"

static const char *header_val( const struct httplib_connection *conn, const char *header );

/*
 * void XX_httplib_log_access( const struct httplib_connection *conn );
 *
 * The function XX_httplib_log_access() logs an access of a client.
 */

void XX_httplib_log_access( const struct httplib_connection *conn ) {

	const struct httplib_request_info *ri;
	struct file fi;
	char date[64];
	char src_addr[IP_ADDR_STR_LEN];
	struct tm *tm;
	const char *referer;
	const char *user_agent;
	char buf[4096];

	if ( conn == NULL  ||  conn->ctx == NULL ) return;

	if ( conn->ctx->access_log_file != NULL ) {

		if ( XX_httplib_fopen( conn, conn->ctx->access_log_file, "a+", &fi ) == 0 ) fi.fp = NULL;
	}
	else fi.fp = NULL;

	/*
	 * Log is written to a file and/or a callback. If both are not set,
	 * executing the rest of the function is pointless.
	 */

	if ( fi.fp == NULL  &&  conn->ctx->callbacks.log_access == NULL ) return;

	tm = localtime( & conn->conn_birth_time );

	if ( tm != NULL ) strftime( date, sizeof(date), "%d/%b/%Y:%H:%M:%S %z", tm );
	else {
		httplib_strlcpy( date, "01/Jan/1970:00:00:00 +0000", sizeof(date) );
		date[sizeof(date) - 1] = '\0';
	}

	ri = & conn->request_info;

	XX_httplib_sockaddr_to_string( src_addr, sizeof(src_addr), &conn->client.rsa );

	referer    = header_val( conn, "Referer"    );
	user_agent = header_val( conn, "User-Agent" );

	XX_httplib_snprintf( conn,
	            NULL, /* Ignore truncation in access log */
	            buf,
	            sizeof(buf),
	            "%s - %s [%s] \"%s %s%s%s HTTP/%s\" %d %" INT64_FMT " %s %s",
	            src_addr,
	            (ri->remote_user == NULL) ? "-" : ri->remote_user,
	            date,
	            ri->request_method ? ri->request_method : "-",
	            ri->request_uri ? ri->request_uri : "-",
	            ri->query_string ? "?" : "",
	            ri->query_string ? ri->query_string : "",
	            ri->http_version,
	            conn->status_code,
	            conn->num_bytes_sent,
	            referer,
	            user_agent );

	if ( conn->ctx->callbacks.log_access != NULL ) conn->ctx->callbacks.log_access( conn, buf );

	if ( fi.fp ) {

		flockfile(   fi.fp              );
		fprintf(     fi.fp, "%s\n", buf );
		fflush(      fi.fp              );
		funlockfile( fi.fp              );

		XX_httplib_fclose( &fi );
	}

}  /* XX_httplib_log_access */



/*
 * static const char *header_val( const struct httplib_connection *conn, const char *header );
 *
 * The function header_val() returns the value of a specific header of a
 * connection.
 */

static const char *header_val( const struct httplib_connection *conn, const char *header ) {

	const char *header_value;

	header_value = httplib_get_header( conn, header );

	if ( header_value == NULL ) return "-";
	else                        return header_value;

}  /* header_val */
