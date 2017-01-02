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
 * bool XX_httplib_fopen( struct lh_ctx_t *ctx, const struct lh_con_t *conn, const char *path, const char *mode, struct file *filep );
 *
 * The function XX_httplib_fopen() can be used to open a file which is either
 * in memory or on the disk. The path is in UTF-8 and therefore needs
 * conversion in Windows based sytems which use UTF-16 by default. The mode
 * parameter is identical to the mode parameter used in the standard function
 * fopen().
 *
 * The function will return the information of the file in the struct filep. If
 * open the file was successful the value true is returned. Otherwise false.
 *
 * TODO (high): XX_httplib_fopen should only open a file, while XX_httplib_stat
 * should only get the file status. They should not work on different members
 * of the same structure (bad cohesion).
 */

bool XX_httplib_fopen( struct lh_ctx_t *ctx, const struct lh_con_t *conn, const char *path, const char *mode, struct file *filep ) {

	struct stat st;

	if ( ctx == NULL  ||  filep == NULL ) return false;

	memset( filep, 0, sizeof(*filep) );

	if ( stat( path, &st ) == 0 ) filep->size = (uint64_t)st.st_size;

	if ( ! XX_httplib_is_file_in_memory( ctx, conn, path, filep ) ) {
#ifdef _WIN32
		wchar_t wbuf[PATH_MAX];
		wchar_t wmode[20];

		XX_httplib_path_to_unicode( path, wbuf, ARRAY_SIZE(wbuf) );
		MultiByteToWideChar( CP_UTF8, 0, mode, -1, wmode, ARRAY_SIZE(wmode) );

		filep->fp = _wfopen( wbuf, wmode );

#else  /* _WIN32 */

		filep->fp = fopen( path, mode );

#endif  /* _WIN32 */
	}

	return XX_httplib_is_file_opened( filep );

}  /* XX_httplib_fopen */
