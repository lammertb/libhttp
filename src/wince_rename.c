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

#if defined(_WIN32_WCE)

/*
 * int rename( const char *a, const char *b );
 *
 * The function rename() provides a Windows CE specific implementation to
 * rename a file. As the kernel does not provide support for the Posix rename()
 * function this emulation function should provide equivalent functionality.
 * If renaming succeeds, 0 is returned, otherwise -1.
 */

int rename( const char *a, const char *b ) {

	wchar_t wa[PATH_MAX];
	wchar_t wb[PATH_MAX];

	XX_httplib_path_to_unicode( NULL, a, wa, ARRAY_SIZE(wa) );
	XX_httplib_path_to_unicode( NULL, b, wb, ARRAY_SIZE(wb) );

	return MoveFileW( wa, wb ) ? 0 : -1;

}  /* rename */

#endif /* defined(_WIN32_WCE) */
