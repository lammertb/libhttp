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
 * bool XX_httplib_is_authorized_for_put( struct lh_ctx_t *ctx, struct lh_con_t *conn );
 *
 * The function XX_httplib_is_authorized_for_put() returns true, if the client
 * on the connection has authorization to use put and equivalent methods to
 * write information to the server.
 */

bool XX_httplib_is_authorized_for_put( struct lh_ctx_t *ctx, struct lh_con_t *conn ) {

	struct file file = STRUCT_FILE_INITIALIZER;
	const char *passfile;
	bool ret;

	if ( ctx == NULL  ||  conn == NULL ) return false;
	if ( ctx->document_root    == NULL ) return false;

	passfile = ctx->put_delete_auth_file;

	if ( passfile != NULL  &&  XX_httplib_fopen( ctx, conn, passfile, "r", &file ) ) {

		ret = XX_httplib_authorize( ctx, conn, &file );
		XX_httplib_fclose( & file );

		return ret;
	}

	return false;

}  /* XX_httplib_is_authorized_for_put */
