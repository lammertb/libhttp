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
 * Use the global passwords file, if specified by auth_gpass option,
 * or search for .htpasswd in the requested directory.
 */

void XX_httplib_open_auth_file( struct lh_ctx_t *ctx, struct lh_con_t *conn, const char *path, struct file *filep ) {

	char name[PATH_MAX];
	char error_string[ERROR_STRING_LEN];
	const char *p;
	const char *e;
	const char *gpass;
	struct file file = STRUCT_FILE_INITIALIZER;
	bool truncated;

	if ( ctx == NULL  ||  conn == NULL ) return;

	gpass = ctx->global_auth_file;

	if ( gpass != NULL ) {

		/*
		 * Use global passwords file
		 */

		if ( ! XX_httplib_fopen( ctx, conn, gpass, "r", filep ) ) {

			httplib_cry( LH_DEBUG_INFO, ctx, conn, "%s: fopen(%s): %s", __func__, gpass, httplib_error_string( ERRNO, error_string, ERROR_STRING_LEN ) );
		}
		/*
		 * Important: using local struct file to test path for is_directory
		 * flag. If filep is used, XX_httplib_stat() makes it appear as if auth file
		 * was opened.
		 */

	}
	
	else if ( XX_httplib_stat( ctx, conn, path, &file )  &&  file.is_directory ) {

		XX_httplib_snprintf( ctx, conn, &truncated, name, sizeof(name), "%s/%s", path, PASSWORDS_FILE_NAME );

		if ( truncated  ||  ! XX_httplib_fopen( ctx, conn, name, "r", filep ) ) {

			httplib_cry( LH_DEBUG_INFO, ctx, conn, "%s: fopen(%s): %s", __func__, name, httplib_error_string( ERRNO, error_string, ERROR_STRING_LEN ) );
		}
	}
	
	else {
		/*
		 * Try to find .htpasswd in requested directory.
		 */

		for (p = path, e = p + strlen(p) - 1; e > p; e--) {
			if (e[0] == '/') break;
		}

		XX_httplib_snprintf( ctx, conn, &truncated, name, sizeof(name), "%.*s/%s", (int)(e - p), p, PASSWORDS_FILE_NAME );

		if ( truncated  ||  ! XX_httplib_fopen( ctx, conn, name, "r", filep ) ) {

			httplib_cry( LH_DEBUG_INFO, ctx, conn, "%s: fopen(%s): %s", __func__, name, httplib_error_string( ERRNO, error_string, ERROR_STRING_LEN ) );
		}
	}

}  /* XX_httplib_open_auth_file */
