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
 * bool XX_httplib_set_gpass_option( struct lh_ctx_t *ctx );
 *
 * The function XX_httplib_set_gpass_option() sets the global password file
 * option for a context. The function returns false when an error occurs and
 * true when successful.
 */

bool XX_httplib_set_gpass_option( struct lh_ctx_t *ctx ) {

	struct file file = STRUCT_FILE_INITIALIZER;
	const char *path;
	char error_string[ERROR_STRING_LEN];

	if ( ctx == NULL ) return false;

	path = ctx->global_auth_file;

	if ( path != NULL  &&  ! XX_httplib_stat( ctx, NULL, path, &file ) ) {

		httplib_cry( LH_DEBUG_ERROR, ctx, NULL, "%s: cannot open %s: %s", __func__, path, httplib_error_string( ERRNO, error_string, ERROR_STRING_LEN ) );
		return false;
	}
	return true;

}  /* XX_httplib_set_gpass_option */
