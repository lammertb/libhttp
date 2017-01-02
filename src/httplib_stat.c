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

#if defined(_WIN32)

/*
 * Windows happily opens files with some garbage at the end of file name.
 * For example, fopen("a.cgi    ", "r") on Windows successfully opens
 * "a.cgi", despite one would expect an error back.
 * This function returns non-0 if path ends with some garbage.
 */

static bool path_cannot_disclose_cgi( const char *path ) {

	static const char *allowed_last_characters = "_-";
	int last;

	if ( path == NULL ) return true;

	last = path[strlen(path) - 1];
	return isalnum(last)  ||  strchr( allowed_last_characters, last ) != NULL;
}


int XX_httplib_stat( struct lh_ctx_t *ctx, struct lh_con_t *conn, const char *path, struct file *filep ) {

	wchar_t wbuf[PATH_MAX];
	WIN32_FILE_ATTRIBUTE_DATA info;
	time_t creation_time;

	if ( filep == NULL ) return 0;

	memset( filep, 0, sizeof(*filep) );

	if ( conn != NULL  &&  XX_httplib_is_file_in_memory( ctx, conn, path, filep ) ) {

		/*
		 * filep->is_directory = 0; filep->gzipped = 0; .. already done by
		 * memset
		 */

		filep->last_modified = time( NULL );

		/*
		 * last_modified = now ... assumes the file may change during runtime,
		 * so every XX_httplib_fopen call may return different data
		 *
		 * last_modified = ctx.start_time;
		 * May be used it the data does not change during runtime. This allows
		 * browser caching. Since we do not know, we have to assume the file
		 * in memory may change.
		 */

		return 1;
	}

	XX_httplib_path_to_unicode( path, wbuf, ARRAY_SIZE(wbuf) );

	if ( GetFileAttributesExW( wbuf, GetFileExInfoStandard, &info ) != 0 ) {

		filep->size          = MAKEUQUAD( info.nFileSizeLow, info.nFileSizeHigh );
		filep->last_modified = SYS2UNIX_TIME( info.ftLastWriteTime.dwLowDateTime, info.ftLastWriteTime.dwHighDateTime );

		/*
		 * On Windows, the file creation time can be higher than the
		 * modification time, e.g. when a file is copied.
		 * Since the Last-Modified timestamp is used for caching
		 * it should be based on the most recent timestamp.
		 */

		creation_time = SYS2UNIX_TIME( info.ftCreationTime.dwLowDateTime, info.ftCreationTime.dwHighDateTime );
		if ( creation_time > filep->last_modified ) filep->last_modified = creation_time;

		filep->is_directory = info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY;

		/*
		 * If file name is fishy, reset the file structure and return
		 * error.
		 * Note it is important to reset, not just return the error, cause
		 * functions like XX_httplib_is_file_opened() check the struct.
		 */

		if ( ! filep->is_directory  &&  ! path_cannot_disclose_cgi( path ) ) {

			memset( filep, 0, sizeof(*filep) );
			return 0;
		}

		return 1;
	}

	return 0;

}  /* XX_httplib_stat */

#else

int XX_httplib_stat( struct lh_ctx_t *ctx, struct lh_con_t *conn, const char *path, struct file *filep ) {

	struct stat st;

	if ( filep == NULL ) return 0;

	memset( filep, 0, sizeof(*filep) );

	if ( conn != NULL  &&  ctx != NULL  &&  XX_httplib_is_file_in_memory( ctx, conn, path, filep ) ) return 1;

	if ( stat( path, &st ) == 0 ) {

		filep->size          = (uint64_t)(st.st_size);
		filep->last_modified = st.st_mtime;
		filep->is_directory  = S_ISDIR(st.st_mode);

		return 1;
	}

	return 0;

}  /* XX_httplib_stat */

#endif /* _WIN32 */
