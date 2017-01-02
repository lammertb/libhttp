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
 * int XX_httplib_put_dir( struct lh_ctx_t *ctx, struct lh_con_t *conn, const char *path );
 *
 * The function XX_httplib_put_dir() creates a directory mentioned in a PUT
 * request including all intermediate subdirectories. The following values can
 * be returned:
 * Return  0  if the path itself is a directory.
 * Return  1  if the path leads to a file.
 * Return -1  for if the path is too long.
 * Return -2  if path can not be created.
 */

int XX_httplib_put_dir( struct lh_ctx_t *ctx, struct lh_con_t *conn, const char *path ) {

	char buf[PATH_MAX];
	const char *s;
	const char *p;
	struct file file = STRUCT_FILE_INITIALIZER;
	size_t len;
	int res;

	if ( ctx == NULL ) return -2;

	res = 1;

	s   = path+2;
	p   = path+2;

	while ( (p = strchr(s, '/')) != NULL ) {

		len = (size_t)(p - path);

		if ( len >= sizeof(buf) ) {

			/*
			 * path too long
			 */

			res = -1;
			break;
		}
		memcpy(buf, path, len);
		buf[len] = '\0';

		/*
		 * Try to create intermediate directory
		 */

		if ( ! XX_httplib_stat( ctx, conn, buf, &file ) && httplib_mkdir( buf, 0755 ) != 0 ) {

			/*
			 * path does not exixt and can not be created
			 */

			res = -2;
			break;
		}

		/*
		 * Is path itself a directory?
		 */

		if ( p[1] == '\0' ) res = 0;

		s = ++p;
	}

	return res;

}  /* XX_httplib_put_dir */
