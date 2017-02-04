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
 * bool XX_httplib_substitute_index_file( struct lh_ctx_t *ctx, struct lh_con_t *conn, char *path, size_t path_len, struct file *filep );
 *
 * The function XX_httplib_substiture_index_file() tries to find an index file
 * matching a given directory path. The function returns true of an index file
 * has been found and false if the file could not be found. If a file could be
 * located, it's stats are returnd in stp.
 */

int XX_httplib_substitute_index_file( struct lh_ctx_t *ctx, struct lh_con_t *conn, char *path, size_t path_len, struct file *filep ) {

	const char *list;
	struct file file = STRUCT_FILE_INITIALIZER;
	struct vec filename_vec;
	size_t n;
	bool found;

	if ( ctx == NULL  ||  conn == NULL  ||  path == NULL ) return 0;
	if ( ctx->document_root == NULL                      ) return 0;

	list  = ctx->index_files;
	n     = strlen( path );
	found = false;

	/*
	 * The 'path' given to us points to the directory. Remove all trailing
	 * directory separator characters from the end of the path, and
	 * then append single directory separator character.
	 */

	while ( n > 0  &&  path[n - 1] == '/' ) n--;
	path[n] = '/';

	/*
	 * Traverse index files list. For each entry, append it to the given
	 * path and see if the file exists. If it exists, break the loop
	 */

	while ( (list = XX_httplib_next_option( list, &filename_vec, NULL )) != NULL ) {

		/*
		 * Ignore too long entries that may overflow path buffer
		 */

		if ( filename_vec.len > path_len - (n+2) ) continue;

		/*
		 * Prepare full path to the index file
		 */

		httplib_strlcpy( path+n+1, filename_vec.ptr, filename_vec.len + 1 );

		/*
		 * Does it exist?
		 */

		if ( XX_httplib_stat( ctx, conn, path, &file ) ) {

			/*
			 * Yes it does, break the loop
			 */

			*filep = file;
			found  = true;
			break;
		}
	}

	/*
	 * If no index file exists, restore directory path
	 */

	if ( ! found ) path[n] = '\0';

	return found;

}  /* XX_httplib_substitute_index_file */
