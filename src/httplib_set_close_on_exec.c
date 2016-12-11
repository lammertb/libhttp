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


#if defined(_WIN32)

/* conn parameter may be NULL */
void XX_httplib_set_close_on_exec( SOCKET sock, struct mg_connection *conn ) {

	(void)conn; /* Unused. */
#if defined(_WIN32_WCE)
	(void)sock;
#else
	SetHandleInformation((HANDLE)(intptr_t)sock, HANDLE_FLAG_INHERIT, 0);
#endif

}  /* XX_httplib_set_close_on_exec */


#else

/* conn may be NULL */
void XX_httplib_set_close_on_exec( SOCKET fd, struct mg_connection *conn ) {

	if (fcntl(fd, F_SETFD, FD_CLOEXEC) != 0) {
		if (conn) { mg_cry(conn, "%s: fcntl(F_SETFD FD_CLOEXEC) failed: %s", __func__, strerror(ERRNO)); }
	}

}  /* XX_httplib_set_close_on_exec */

#endif /* _WIN32 */
