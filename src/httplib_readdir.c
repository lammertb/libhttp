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
 * struct dirent *httplib_readdir( DIR *dir );
 *
 * The function XX_httplib_readdir() returns a pointer to the next entry in a
 * directory or NULL if the end of the directory is reached or an error
 * occured. Where possible the Posix readdir() system call is used. Otherwise
 * the Posix call is emulated.
 */

LIBHTTP_API struct dirent *httplib_readdir( DIR *dir ) {

#if defined(_WIN32)

	struct dirent *result;

	result = NULL;
	
	if ( dir == NULL ) {

		SetLastError( ERROR_BAD_ARGUMENTS );
		return NULL;
	}

	if ( dir->handle != INVALID_HANDLE_VALUE ) {

		result = & dir->result;
		WideCharToMultiByte( CP_UTF8, 0, dir->info.cFileName, -1, result->d_name, sizeof(result->d_name), NULL, NULL );

		if ( ! FindNextFileW( dir->handle, &dir->info ) ) {

			FindClose( dir->handle );
			dir->handle = INVALID_HANDLE_VALUE;
		}
	}
	
	else SetLastError( ERROR_FILE_NOT_FOUND );

	return result;

#else  /* _WIN32 */

	return readdir( dir );

#endif  /* _WIN32 */

}  /* httplib_readdir */
