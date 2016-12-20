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
#include "httplib_ssl.h"

#ifdef _WIN32
CRITICAL_SECTION			global_log_file_lock;

struct pthread_mutex_undefined_struct *	XX_httplib_pthread_mutex_attr = NULL;
#else  /* _WIN32 */
pthread_mutexattr_t			XX_httplib_pthread_mutex_attr;
#endif /* _WIN32 */



pthread_key_t XX_httplib_sTlsKey; /* Thread local storage index */

int		XX_httplib_sTlsInit		= 0;
int		XX_httplib_thread_idx_max	= 0;

const struct uriprot_tp XX_httplib_abs_uri_protocols[] = {

	{ "http://",  7,  80 },
	{ "https://", 8, 443 },
	{ "ws://",    5,  80 },
	{ "wss://",   6, 443 },
	{ NULL,       0,   0 }

};  /* XX_httplib_abs_uri_protocols */

