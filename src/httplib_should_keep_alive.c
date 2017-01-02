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

/*
 * bool XX_httplib_should_keep_alive( const struct lh_ctx_t *ctx, const struct lh_con_t *conn );
 *
 * The function XX_httplib_should_keep_alive() returns true if the connection
 * should be kept alive and false if it should be closed.
 *
 * HTTP 1.1 assumes keep alive if "Connection:" header is not set This function
 * must tolerate situations when connection info is not set up, for example if
 * request parsing failed.
 */

bool XX_httplib_should_keep_alive( const struct lh_ctx_t *ctx, const struct lh_con_t *conn ) {

	const char *http_version;
	const char *header;

	if ( ctx == NULL  ||  conn == NULL ) return false;

	http_version = conn->request_info.http_version;
	header       = httplib_get_header( conn, "Connection" );

	if (   conn->must_close                                                                                    ) return false;
	if (   conn->status_code == 401                                                                            ) return false;
	if ( ! ctx->enable_keep_alive                                                                              ) return false;
	if ( header != NULL                             &&  ! XX_httplib_header_has_option( header, "keep-alive" ) ) return false;
	if ( header == NULL  &&  http_version != NULL   &&  strcmp( http_version, "1.1" )                          ) return false;

	return true;

}  /* XX_httplib_should_keep_alive */
