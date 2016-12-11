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

