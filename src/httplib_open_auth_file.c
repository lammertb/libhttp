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



/* Use the global passwords file, if specified by auth_gpass option,
 * or search for .htpasswd in the requested directory. */
void XX_httplib_open_auth_file( struct mg_connection *conn, const char *path, struct file *filep ) {

	if ( conn == NULL  ||  conn->ctx == NULL ) return;

	char name[PATH_MAX];
	const char *p;
	const char *e;
	const char *gpass = conn->ctx->config[GLOBAL_PASSWORDS_FILE];
	struct file file = STRUCT_FILE_INITIALIZER;
	int truncated;

	if (gpass != NULL) {
		/* Use global passwords file */
		if (!XX_httplib_fopen(conn, gpass, "r", filep)) {
#ifdef DEBUG
			mg_cry(conn, "fopen(%s): %s", gpass, strerror(ERRNO));
#endif
		}
		/* Important: using local struct file to test path for is_directory
		 * flag. If filep is used, XX_httplib_stat() makes it appear as if auth file
		 * was opened. */
	} else if (XX_httplib_stat(conn, path, &file) && file.is_directory) {
		XX_httplib_snprintf(conn, &truncated, name, sizeof(name), "%s/%s", path, PASSWORDS_FILE_NAME);

		if (truncated || !XX_httplib_fopen(conn, name, "r", filep)) {
#ifdef DEBUG
			mg_cry(conn, "fopen(%s): %s", name, strerror(ERRNO));
#endif
		}
	} else {
		/* Try to find .htpasswd in requested directory. */
		for (p = path, e = p + strlen(p) - 1; e > p; e--) {
			if (e[0] == '/') break;
		}
		XX_httplib_snprintf(conn, &truncated, name, sizeof(name), "%.*s/%s", (int)(e - p), p, PASSWORDS_FILE_NAME);

		if (truncated || !XX_httplib_fopen(conn, name, "r", filep)) {
#ifdef DEBUG
			mg_cry(conn, "fopen(%s): %s", name, strerror(ERRNO));
#endif
		}
	}

}  /* XX_httplib_open_auth_file */
