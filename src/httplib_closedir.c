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
 * int httplib_closedir( DIR *dir );
 *
 * The function httplib_closedir() closes a previously opened directory. On
 * systems which support Posix, this is done with a call to the closedir()
 * system fuction. Otherwise the function is emulated.
 */

LIBHTTP_API int httplib_closedir( DIR *dir ) {

#if defined(_WIN32)

	int result;

	result = 0;

	if ( dir != NULL ) {

		if ( dir->handle != INVALID_HANDLE_VALUE ) result = ( FindClose( dir->handle ) ) ? 0 : -1;
		dir = httplib_free( dir );
	}
	else {

		result = -1;
		SetLastError( ERROR_BAD_ARGUMENTS );
	}

	return result;

#else  /* _WIN32 */

	return closedir( dir );

#endif  /* _WIN32 */

}  /* httplib_closedir */
