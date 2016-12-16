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
 * int httplib_remove( const char *path );
 *
 * The function httplib_remove() provides a platform independent way to remove
 * an entry from a directory. In Posix compliant environments this function is
 * a wrapper around the Posix remove() function. On other systems the Posix
 * remove functionality is emulated with own code.
 *
 * The function returns 0 when successful and -1 if an error occurs.
 */

LIBHTTP_API int httplib_remove( const char *path ) {

#if defined(_WIN32)

	wchar_t wbuf[PATH_MAX];

	XX_httplib_path_to_unicode( path, wbuf, ARRAY_SIZE(wbuf) );

	return ( DeleteFileW( wbuf ) ) ? 0 : -1;

#else  /* _WIN32 */

	return remove( path );

#endif  /* _WIN32 */

}  /* httplib_remove */
