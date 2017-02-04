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

#if !defined(NO_THREAD_NAME)

#if defined(_WIN32) && defined(_MSC_VER)

/*
 * Set the thread name for debugging purposes in Visual Studio
 * http://msdn.microsoft.com/en-us/library/xcb2z8hs.aspx
 */

#pragma pack(push, 8)
typedef struct tagTHREADNAME_INFO {
	DWORD dwType;     /* Must be 0x1000.				*/
	LPCSTR szName;    /* Pointer to name (in user addr space).	*/
	DWORD dwThreadID; /* Thread ID (-1=caller thread).		*/
	DWORD dwFlags;    /* Reserved for future use, must be zero.	*/
} THREADNAME_INFO;
#pragma pack(pop)

#elif defined(__linux__)

#include <sys/prctl.h>
#include <sys/sendfile.h>
#include <sys/eventfd.h>

#endif  /* __linux__ */

void XX_httplib_set_thread_name( struct lh_ctx_t *ctx, const char *name ) {

	char thread_name[16+1]; /* 16 = Max. thread length in Linux/OSX/.. */

	XX_httplib_snprintf( ctx, NULL, NULL, thread_name, sizeof(thread_name), "libhttp-%s", name );

#if defined(_WIN32)

#if defined(_MSC_VER)

	/*
	 * Windows and Visual Studio Compiler
	 */

	__try {
		THREADNAME_INFO info;

		info.dwType     = 0x1000;
		info.szName     = thread_name;
		info.dwThreadID = ~0U;
		info.dwFlags    = 0;

		RaiseException( 0x406D1388, 0, sizeof(info) / sizeof(ULONG_PTR), (ULONG_PTR *)&info );
	}
	__except(EXCEPTION_EXECUTE_HANDLER) {}

#elif defined(__MINGW32__)

	/*
	 * No option known to set thread name for MinGW
	 */

#else  /* _MSC_VER  or  __MINGW32__ */

	/*
	 * Any other Windows compiler like Watcom, Embarcadero etc
	 */

#endif  /* _MSC_VER  or  __MINGW32__ */

#elif defined(__GLIBC__) && ((__GLIBC__ > 2) || ((__GLIBC__ == 2) && (__GLIBC_MINOR__ >= 12)))

	/*
	 * pthread_setname_np first appeared in glibc in version 2.12
	 */

	pthread_setname_np( httplib_pthread_self(), thread_name );

#elif defined(__linux__)

	/*
	 * on linux we can use the old prctl function
	 */

	prctl( PR_SET_NAME, threadName, 0, 0, 0 );

#else

	/*
	 * Other exotic systems or very old glibc versions
	 */

#endif

}  /* XX_httplib_set_thread_name */

#else /* !defined(NO_THREAD_NAME) */

void XX_httplib_set_thread_name( const char *name ) {

	UNUSED_PARAMETER(name);

}  /* XX_httplib_set_thread_name */

#endif  /* !NO_THREAD_NAME */
