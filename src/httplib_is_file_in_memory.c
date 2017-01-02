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
 * bool XX_httplib_is_file_in_memory( struct lh_ctx_t *ctx, const struct lh_con_t *conn, const char *path, struct file *filep );
 *
 * The function XX_httplib_is_file_in_memory() returns true, if a file defined
 * by a specific path is located in memory.
 */

bool XX_httplib_is_file_in_memory( struct lh_ctx_t *ctx, const struct lh_con_t *conn, const char *path, struct file *filep ) {

	size_t size;

	if ( ctx == NULL  ||  conn == NULL  ||  filep == NULL ) return false;

	size = 0;

	if ( ctx->callbacks.open_file ) {

		filep->membuf = ctx->callbacks.open_file( ctx, conn, path, & size );

		/*
		 * NOTE: override filep->size only on success. Otherwise, it might
		 * break constructs like if (!XX_httplib_stat() || !XX_httplib_fopen()) ...
		 */

		if ( filep->membuf != NULL ) filep->size = size;
	}

	return ( filep->membuf != NULL );

}  /* XX_httplib_is_file_in_memory */
