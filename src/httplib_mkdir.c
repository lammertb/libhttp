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

#if ! defined(_WIN32)
#include <sys/stat.h>
#endif  /* ! _WIN32 */

#include "httplib_main.h"

/*
 * int httplib_mkdir( const char *path, int mode );
 *
 * The function httplib_mkdir() creates a directory. On a Posix compliant
 * system the underlying system call mkdir() is used for this. For systems
 * without mkdir support an emulation function is used with the same
 * functionality.
 */

LIBHTTP_API int httplib_mkdir( const char *path, int mode ) {

#if defined(_WIN32)

	wchar_t wbuf[PATH_MAX];

	UNUSED_PARAMETER(mode);

	XX_httplib_path_to_unicode( path, wbuf, ARRAY_SIZE(wbuf) );
	return ( CreateDirectoryW( wbuf, NULL ) ) ? 0 : -1;

#else  /* _WIN32 */

	return mkdir( path, mode );

#endif

}  /* httplib_mkdir */
