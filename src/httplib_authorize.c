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
 * bool XX_httplib_authorize( struct lh_ctx_t *ctx, struct lh_con_t *conn, struct file *filep );
 *
 * The function XX_httplib_authorize() authorizes agains the open passwords
 * file. It returns 1 if authorized.
 */

bool XX_httplib_authorize( struct lh_ctx_t *ctx, struct lh_con_t *conn, struct file *filep ) {

	struct read_auth_file_struct workdata;
	char buf[MG_BUF_LEN];

	if ( ctx == NULL  ||  conn == NULL ) return false;

	memset( & workdata, 0, sizeof(workdata) );
	workdata.conn = conn;

	if ( ! XX_httplib_parse_auth_header( ctx, conn, buf, sizeof(buf), &workdata.ah ) ) return false;
	workdata.domain = ctx->authentication_domain;

	return XX_httplib_read_auth_file( ctx, filep, &workdata );

}  /* XX_httplib_authorize */
