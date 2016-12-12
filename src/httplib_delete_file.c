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
 * void XX_httplib_delete_file( struct mg_connection *conn, const char *path );
 *
 * The function XX_httplib_delete_file() deletes a file after a request over a
 * connection.
 */

#if !defined(NO_FILES)

void XX_httplib_delete_file( struct mg_connection *conn, const char *path ) {

	struct de de;

	memset(&de.file, 0, sizeof(de.file));
	if (!XX_httplib_stat(conn, path, &de.file)) {
		/* XX_httplib_stat returns 0 if the file does not exist */
		XX_httplib_send_http_error(conn, 404, "Error: Cannot delete file\nFile %s not found", path);
		return;
	}

	if (de.file.membuf != NULL) {
		/* the file is cached in memory */
		XX_httplib_send_http_error( conn, 405, "Error: Delete not possible\nDeleting %s is not supported", path);
		return;
	}

	if (de.file.is_directory) {
		if (XX_httplib_remove_directory(conn, path)) {
			/* Delete is successful: Return 204 without content. */
			XX_httplib_send_http_error(conn, 204, "%s", "");
		} else {
			/* Delete is not successful: Return 500 (Server error). */
			XX_httplib_send_http_error(conn, 500, "Error: Could not delete %s", path);
		}
		return;
	}

	/* This is an existing file (not a directory).
	 * Check if write permission is granted. */
	if (access(path, W_OK) != 0) {
		/* File is read only */
		XX_httplib_send_http_error( conn, 403, "Error: Delete not possible\nDeleting %s is not allowed", path);
		return;
	}

	/* Try to delete it. */
	if (XX_httplib_remove(conn, path) == 0) {
		/* Delete was successful: Return 204 without content. */
		XX_httplib_send_http_error(conn, 204, "%s", "");
	} else {
		/* Delete not successful (file locked). */
		XX_httplib_send_http_error(conn, 423, "Error: Cannot delete file\nremove(%s): %s", path, strerror(ERRNO));
	}

}  /* XX_httplib_delete_file */

#endif /* !NO_FILES */
