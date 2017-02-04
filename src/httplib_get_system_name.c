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
 * void XX_httplib_get_system_name( char **sysName );
 *
 * The function XX_httplib_get_system_name() tries to determine on which system
 * and version the program is running and stores that information in a caller
 * provided buffer.
 */

void XX_httplib_get_system_name( char **sysName ) {

#if defined(_WIN32)
#if defined(_WIN32_WCE)

	*sysName = httplib_strdup( "WinCE" );

#else  /* _WIN32_WCE */

	char name[128];

	DWORD dwVersion      = 0;
	DWORD dwMajorVersion = 0;
	DWORD dwMinorVersion = 0;
	DWORD dwBuild        = 0;

#ifdef _MSC_VER
#pragma warning(push)
// GetVersion was declared deprecated
#pragma warning(disable : 4996)
#endif  /* _MSC_VER */

	dwVersion = GetVersion();

#ifdef _MSC_VER
#pragma warning(pop)
#endif  /* _MSC_VER */

	dwMajorVersion = (DWORD)(LOBYTE(LOWORD(dwVersion)));
	dwMinorVersion = (DWORD)(HIBYTE(LOWORD(dwVersion)));
	dwBuild        = ((dwVersion < 0x80000000) ? (DWORD)(HIWORD(dwVersion)) : 0);
	(void)dwBuild;

	sprintf( name, "Windows %u.%u", (unsigned)dwMajorVersion, (unsigned)dwMinorVersion );
	*sysName = httplib_strdup( name );

#endif  /* _WIN32_WCE */
#else  /* _WIN32 */

	struct utsname name;

	memset( & name, 0, sizeof(name) );
	uname( & name );
	*sysName = httplib_strdup( name.sysname );

#endif  /* _WIN32 */

}  /* XX_httplib_get_system_name */
