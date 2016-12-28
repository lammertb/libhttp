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
 * DIR *httplib_opendir( const char *name );
 *
 * The function httplib_opendir() opens a directory and returns a pointer to
 * a structure with the directory information if the function succeeds. When a
 * problem is detected NULL is returned instead.
 *
 * On Windows systems this function emulates a Posix call, otherwise the Posix
 * function is executed directly.
 */

LIBHTTP_API DIR *httplib_opendir( const char *name ) {

#if defined(_WIN32)

	DIR *dir;
	wchar_t wpath[PATH_MAX];
	DWORD attrs;

	dir = NULL;

	if      ( name                                   == NULL ) SetLastError( ERROR_BAD_ARGUMENTS );
	else if ( (dir = httplib_malloc( sizeof(*dir) )) == NULL ) SetLastError( ERROR_NOT_ENOUGH_MEMORY );
	else {
		XX_httplib_path_to_unicode( name, wpath, ARRAY_SIZE(wpath) );
		attrs = GetFileAttributesW( wpath );

		if (attrs != 0xFFFFFFFF  &&  ((attrs & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY) ) {

			wcscat( wpath, L"\\*" );
			dir->handle = FindFirstFileW( wpath, &dir->info );
			dir->result.d_name[0] = '\0';
		}
		else dir = httplib_free( dir );
	}

	return dir;

#else  /* _WIN32 */

	return opendir( name );

#endif  /* _WIN32 */

}  /* httplib_opendir */
