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

struct stat {
	int64_t st_size;
	time_t st_mtime;
};

/*
 * int stat( const char *name, struct stat *st );
 *
 * Windows CE does not provide all of the common system functions available on
 * other platforms. One missing function is the stat() function which is
 * implemented here using other existing functions in the kernel. The
 * functionality should be largely compatible with the Posix stat() version.
 */

int stat( const char *name, struct stat *st ) {

	wchar_t wbuf[PATH_MAX];
	WIN32_FILE_ATTRIBUTE_DATA attr;
	time_t creation_time;
	time_t write_time;

	XX_httplib_path_to_unicode( name, wbuf, ARRAY_SIZE(wbuf) );
	memset( & attr, 0, sizeof(attr) );

	GetFileAttributesExW( wbuf, GetFileExInfoStandard, &attr );
	st->st_size = (((int64_t)attr.nFileSizeHigh) << 32) + (int64_t)attr.nFileSizeLow;

	write_time    = SYS2UNIX_TIME( attr.ftLastWriteTime.dwLowDateTime, attr.ftLastWriteTime.dwHighDateTime );
	creation_time = SYS2UNIX_TIME( attr.ftCreationTime.dwLowDateTime,  attr.ftCreationTime.dwHighDateTime  );

	if ( creation_time > write_time ) st->st_mtime = creation_time;
	else                              st->st_mtime = write_time;

	return 0;

}  /* stat */

#endif /* defined(_WIN32_WCE) */
