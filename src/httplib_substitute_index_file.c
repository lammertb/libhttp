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
#include "httplib_string.h"

/*
 * int XX_httplib_substitute_index_file( struct httplib_connection *conn, char *path, size_t path_len, struct file *filep );
 *
 * The function XX_httplib_substiture_index_file() tries to find an index file
 * matching a given directory path. The function returns 1 of an index file has
 * been found and 0 if the file could not be found. If a file could be located,
 * it's stats are returnd in stp.
 */

#if !defined(NO_FILES)

int XX_httplib_substitute_index_file( struct httplib_connection *conn, char *path, size_t path_len, struct file *filep ) {

	if ( conn == NULL  ||  conn->ctx == NULL ) return 0;

	const char *list = conn->ctx->config[INDEX_FILES];
	struct file file = STRUCT_FILE_INITIALIZER;
	struct vec filename_vec;
	size_t n = strlen(path);
	int found = 0;

	/* The 'path' given to us points to the directory. Remove all trailing
	 * directory separator characters from the end of the path, and
	 * then append single directory separator character. */
	while (n > 0 && path[n - 1] == '/') n--;
	path[n] = '/';

	/* Traverse index files list. For each entry, append it to the given
	 * path and see if the file exists. If it exists, break the loop */
	while ((list = XX_httplib_next_option(list, &filename_vec, NULL)) != NULL) {
		/* Ignore too long entries that may overflow path buffer */
		if (filename_vec.len > path_len - (n + 2)) continue;

		/* Prepare full path to the index file */
		XX_httplib_strlcpy(path + n + 1, filename_vec.ptr, filename_vec.len + 1);

		/* Does it exist? */
		if (XX_httplib_stat(conn, path, &file)) {
			/* Yes it does, break the loop */
			*filep = file;
			found = 1;
			break;
		}
	}

	/* If no index file exists, restore directory path */
	if (!found) path[n] = '\0';

	return found;

}  /* XX_httplib_substitute_index_file */
#endif
