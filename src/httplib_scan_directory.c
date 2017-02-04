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

int XX_httplib_scan_directory( struct lh_ctx_t *ctx, struct lh_con_t *conn, const char *dir, void *data, void (*cb)(struct lh_ctx_t *ctx, struct de *, void *) ) {

	char path[PATH_MAX];
	char error_string[ERROR_STRING_LEN];
	struct dirent *dp;
	DIR *dirp;
	struct de de;
	bool truncated;

	if ( ctx == NULL ) return 0;

	dirp = httplib_opendir( dir );
	if ( dirp == NULL ) return 0;

	de.conn = conn;

	while ( (dp = httplib_readdir(dirp)) != NULL ) {

		/*
		 * Do not show current dir and hidden files
		 */

		if ( ! strcmp( dp->d_name, "." )  ||  ! strcmp(dp->d_name, "..")  ||  XX_httplib_must_hide_file( ctx, dp->d_name ) ) continue;

		XX_httplib_snprintf( ctx, conn, &truncated, path, sizeof(path), "%s/%s", dir, dp->d_name );

		/*
		 * If we don't memset stat structure to zero, mtime will have
		 * garbage and strftime() will segfault later on in
		 * XX_httplib_print_dir_entry(). memset is required only if XX_httplib_stat()
		 * fails. For more details, see
		 * http://code.google.com/p/mongoose/issues/detail?id=79
		 */

		memset( &de.file, 0, sizeof(de.file) );

		if ( truncated ) continue; /* If the path is not complete, skip processing. */

		if ( ! XX_httplib_stat( ctx, conn, path, &de.file ) ) {

			httplib_cry( LH_DEBUG_WARNING, ctx, conn, "%s: XX_httplib_stat(%s) failed: %s", __func__, path, httplib_error_string( ERRNO, error_string, ERROR_STRING_LEN ) );
		}

		de.file_name = dp->d_name;
		cb( ctx, &de, data );
	}

	httplib_closedir( dirp );

	return 1;

}  /* XX_httplib_scan_directory */
