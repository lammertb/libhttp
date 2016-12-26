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
 * void XX_httplib_handle_file_based_request( struct httplib_connection *conn, const char *path, struct file *file );
 *
 * The function XX_httplib_handle_file_based_request() handles a request which
 * involves a file. This can either be a CGI request, an SSI request of a
 * request for a static file.
 */

void XX_httplib_handle_file_based_request( struct httplib_connection *conn, const char *path, struct file *file ) {

#if !defined(NO_CGI)
	const char *cgi_ext;
#endif  /* ! NO_CGI */
	const char *ssi_ext;
	const char *max_age;

	if ( conn == NULL  ||  conn->ctx == NULL ) return;

#if !defined(NO_CGI)
	cgi_ext = conn->ctx->cfg[CGI_EXTENSIONS];
#endif  /* ! NO_CGI */
	ssi_ext = conn->ctx->cfg[SSI_EXTENSIONS];
	max_age = conn->ctx->cfg[STATIC_FILE_MAX_AGE];

	if (0) {
#if !defined(NO_CGI)
	}
	
	else if ( cgi_ext != NULL  &&  XX_httplib_match_prefix( cgi_ext, strlen( cgi_ext ), path ) > 0 ) {
		
		/*
		 * CGI scripts may support all HTTP methods
		 */

		XX_httplib_handle_cgi_request( conn, path );
#endif /* !NO_CGI */
	}
	
	else if ( ssi_ext != NULL  &&  XX_httplib_match_prefix( ssi_ext, strlen( ssi_ext ), path ) > 0 ) {

		XX_httplib_handle_ssi_file_request( conn, path, file );
	}
	
	else if ( max_age != NULL  &&  ! conn->in_error_handler  &&  XX_httplib_is_not_modified( conn, file ) ) {

		XX_httplib_handle_not_modified_static_file_request( conn, file );
	}
	
	else XX_httplib_handle_static_file_request( conn, path, file, NULL, NULL );

}  /* XX_httplib_handle_file_based_request */
