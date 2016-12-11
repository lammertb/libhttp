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
 */



#include "libhttp-private.h"


mg_static_assert(MAX_WORKER_THREADS >= 1, "worker threads must be a positive number");

mg_static_assert(sizeof(size_t) == 4 || sizeof(size_t) == 8, "size_t data type size check");

/* va_copy should always be a macro, C99 and C++11 - DTL */
#ifndef va_copy
#define va_copy(x, y) ((x) = (y))
#endif

#ifdef _WIN32
/* Create substitutes for POSIX functions in Win32. */

static CRITICAL_SECTION global_log_file_lock;

 pthread_mutex_undefined_struct *XX_httplib_pthread_mutex_attr = NULL;
#else  /* _WIN32 */
pthread_mutexattr_t XX_httplib_pthread_mutex_attr;
#endif /* _WIN32 */


#if defined(_WIN32_WCE)
/* Create substitutes for POSIX functions in Win32. */



#define _beginthreadex(psec, stack, func, prm, flags, ptid)                    \
	(uintptr_t) CreateThread(psec, stack, func, prm, flags, ptid)

#define remove(f) mg_remove(NULL, f)


#define access(x, a) 1 /* not required anyway */

/* WinCE-TODO: define stat, remove, rename, _rmdir, _lseeki64 */
#define EEXIST 1 /* TODO: See Windows error codes */
#define EACCES 2 /* TODO: See Windows error codes */
#define ENOENT 3 /* TODO: See Windows Error codes */

#endif /* defined(_WIN32_WCE) */


/* Darwin prior to 7.0 and Win32 do not have socklen_t */
#ifdef NO_SOCKLEN_T
typedef int		socklen_t;
#endif /* NO_SOCKLEN_T */
#define _DARWIN_UNLIMITED_SELECT


pthread_key_t XX_httplib_sTlsKey; /* Thread local storage index */
int XX_httplib_sTlsInit = 0;
int XX_httplib_thread_idx_max = 0;





const struct uriprot_tp XX_httplib_abs_uri_protocols[] = {{"http://", 7, 80},
                         {"https://", 8, 443},
                         {"ws://", 5, 80},
                         {"wss://", 6, 443},
                         {NULL, 0, 0}};



#if !defined(NO_THREAD_NAME)
#if defined(_WIN32) && defined(_MSC_VER)
/* Set the thread name for debugging purposes in Visual Studio
 * http://msdn.microsoft.com/en-us/library/xcb2z8hs.aspx
 */
#pragma pack(push, 8)
typedef struct tagTHREADNAME_INFO {
	DWORD dwType;     /* Must be 0x1000. */
	LPCSTR szName;    /* Pointer to name (in user addr space). */
	DWORD dwThreadID; /* Thread ID (-1=caller thread). */
	DWORD dwFlags;    /* Reserved for future use, must be zero. */
} THREADNAME_INFO;
#pragma pack(pop)

#elif defined(__linux__)

#include <sys/prctl.h>
#include <sys/sendfile.h>
#include <sys/eventfd.h>

#endif


#if !defined(__linux__) && !defined(_WIN32) && defined(ALTERNATIVE_QUEUE)
#endif


void XX_httplib_set_thread_name(const char *name) {

	char threadName[16 + 1]; /* 16 = Max. thread length in Linux/OSX/.. */

	XX_httplib_snprintf( NULL, NULL, threadName, sizeof(threadName), "libhttp-%s", name);

#if defined(_WIN32)
#if defined(_MSC_VER)
	/* Windows and Visual Studio Compiler */
	__try
	{
		THREADNAME_INFO info;
		info.dwType = 0x1000;
		info.szName = threadName;
		info.dwThreadID = ~0U;
		info.dwFlags = 0;

		RaiseException(0x406D1388, 0, sizeof(info) / sizeof(ULONG_PTR), (ULONG_PTR *)&info);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
	}
#elif defined(__MINGW32__)
/* No option known to set thread name for MinGW */
#endif
#elif defined(__GLIBC__)                                                       \
    && ((__GLIBC__ > 2) || ((__GLIBC__ == 2) && (__GLIBC_MINOR__ >= 12)))
	/* pthread_setname_np first appeared in glibc in version 2.12*/
	pthread_setname_np(pthread_self(), threadName);
#elif defined(__linux__)
	/* on linux we can use the old prctl function */
	prctl(PR_SET_NAME, threadName, 0, 0, 0);
#endif
}  /* XX_httplib_set_thread_name */

#else /* !defined(NO_THREAD_NAME) */
void XX_httplib_set_thread_name(const char *threadName) {

}  /* XX_httplib_set_thread_name */
#endif  /* !NO_THREAD_NAME */
