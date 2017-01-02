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

/* Look at the "path" extension and figure what mime type it has.
 * Store mime type in the vector. */

void XX_httplib_get_mime_type( const struct lh_ctx_t *ctx, const char *path, struct vec *vec ) {

	struct vec ext_vec;
	struct vec mime_vec;
	const char *list;
	const char *ext;
	size_t path_len;

	if ( ctx == NULL  ||  path == NULL  ||  vec == NULL ) return;

	path_len = strlen( path );

	/*
	 * Scan user-defined mime types first, in case user wants to
	 * override default mime types.
	 */

	list = ctx->extra_mime_types;

	while ( (list = XX_httplib_next_option( list, &ext_vec, &mime_vec )) != NULL ) {

		/*
		 * ext now points to the path suffix
		 */

		ext = path + path_len - ext_vec.len;

		if ( httplib_strncasecmp( ext, ext_vec.ptr, ext_vec.len ) == 0 ) {

			*vec = mime_vec;
			return;
		}
	}

	vec->ptr = httplib_get_builtin_mime_type( path );
	vec->len = strlen( vec->ptr );

}  /* XX_httplib_get_mime_type */
