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
 * For Windows, change all slashes to backslashes in path names.
 */

static void change_slashes_to_backslashes( char *path ) {

	int i;

	for (i = 0; path[i] != '\0'; i++) {

		if (path[i] == '/') path[i] = '\\';

		/*
		 * remove double backslash (check i > 0 to preserve UNC paths,
		 * like \\server\file.txt)
		 */

		if ( path[i] == '\\'  &&  i > 0 ) {

			while ( path[i+1] == '\\'  ||  path[i+1] == '/' ) memmove( path+i+1, path+i+2, strlen( path+i+1 ) );
		}
	}

}  /* change_slashes_to_backslashes */



static int httplib_wcscasecmp( const wchar_t *s1, const wchar_t *s2 ) {

	int diff;

	do {
		diff = tolower(*s1) - tolower(*s2);
		s1++;
		s2++;

	} while ( diff == 0  &&  s1[-1] != '\0' );

	return diff;

}  /* httplib_wcscasecmp */


/* Encode 'path' which is assumed UTF-8 string, into UNICODE string.
 * wbuf and wbuf_len is a target buffer and its length. */
void XX_httplib_path_to_unicode( const char *path, wchar_t *wbuf, size_t wbuf_len ) {

	char buf[PATH_MAX];
	char buf2[PATH_MAX];
	wchar_t wbuf2[MAX_PATH + 1];
	DWORD long_len;
	DWORD err;
	int (*fcompare)(const wchar_t *, const wchar_t *) = httplib_wcscasecmp;

	httplib_strlcpy( buf, path, sizeof(buf) );
	change_slashes_to_backslashes( buf );

	/*
	 * Convert to Unicode and back. If doubly-converted string does not
	 * match the original, something is fishy, reject.
	 */

	memset( wbuf, 0, wbuf_len * sizeof(wchar_t) );
	MultiByteToWideChar( CP_UTF8, 0, buf,  -1, wbuf, (int)wbuf_len );
	WideCharToMultiByte( CP_UTF8, 0, wbuf, (int)wbuf_len, buf2, sizeof(buf2), NULL, NULL );

	if ( strcmp(buf, buf2) != 0 ) wbuf[0] = L'\0';

	/*
	 * TODO: Add a configuration to switch between case sensitive and
	 * case insensitive URIs for Windows server.
	 */

	/*
	if ( ctx != NULL ) {
	    if (ctx->config[WINDOWS_CASE_SENSITIVE]) {
	        fcompare = wcscmp;
	    }
	}
	*/

#if !defined(_WIN32_WCE)
	/*
	 * Only accept a full file path, not a Windows short (8.3) path.
	 */

	memset( wbuf2, 0, ARRAY_SIZE(wbuf2) * sizeof(wchar_t) );
	long_len = GetLongPathNameW( wbuf, wbuf2, ARRAY_SIZE(wbuf2) - 1 );

	if ( long_len == 0 ) {

		err = GetLastError();
		if ( err == ERROR_FILE_NOT_FOUND ) {

			/*
			 * File does not exist. This is not always a problem here.
			 */

			return;
		}
	}
	if ( long_len >= ARRAY_SIZE(wbuf2)  ||  fcompare( wbuf, wbuf2 ) != 0 ) {

		/*
		 * Short name is used.
		 */

		wbuf[0] = L'\0';
	}
#else
	UNUSED_PARAMETER(long_len);
	UNUSED_PARAMETER(wbuf2);
	UNUSED_PARAMETER(err);

	if ( strchr( path, '~' ) ) wbuf[0] = L'\0';
#endif

}  /* XX_httplib_path_to_unicode */

#endif /* _WIN32 */
