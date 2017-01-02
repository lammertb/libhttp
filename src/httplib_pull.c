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
#include "httplib_utils.h"

/*
 * Read from IO channel - opened file descriptor, socket, or SSL descriptor.
 * Return negative value on error, or number of bytes read on success.
 */

int XX_httplib_pull( const struct lh_ctx_t *ctx, FILE *fp, struct lh_con_t *conn, char *buf, int len, double timeout ) {

	int nread;
	int err;
	struct timespec start;
	struct timespec now;

#ifdef _WIN32
	typedef int len_t;
#else
	typedef size_t len_t;
#endif

	if ( timeout > 0 ) {

		memset( &start, 0, sizeof(start) );
		memset( &now,   0, sizeof(now)   );

		clock_gettime( CLOCK_MONOTONIC, &start );
	}

	do {
		if ( fp != NULL ) {
#if !defined(_WIN32_WCE)
			/*
			 * Use read() instead of fread(), because if we're reading from the
			 * CGI pipe, fread() may block until IO buffer is filled up. We
			 * cannot afford to block and must pass all read bytes immediately
			 * to the client.
			 */

			nread = (int)read( fileno(fp), buf, (size_t)len );
#else
			/*
			 * WinCE does not support CGI pipes
			 */

			nread = (int)fread(buf, 1, (size_t)len, fp);
#endif
			err = (nread < 0) ? ERRNO : 0;

#ifndef NO_SSL
		}
		
		else if ( conn->ssl != NULL ) {

			nread = SSL_read( conn->ssl, buf, len );

			if (nread <= 0) {

				err = SSL_get_error( conn->ssl, nread );

				if      ( err == SSL_ERROR_SYSCALL    &&  nread == -1                 ) err   = ERRNO;
				else if ( err == SSL_ERROR_WANT_READ  ||  err == SSL_ERROR_WANT_WRITE ) nread = 0;
				
				else return -1;
			}
			else err = 0;
#endif

		}
		
		else {
			nread = (int)recv( conn->client.sock, buf, (len_t)len, 0 );
			err   = (nread < 0) ? ERRNO : 0;
			if (nread == 0) return -1; /* shutdown of the socket at client side */
		}

		if ( ctx->status != CTX_STATUS_RUNNING ) return -1;

		if ( nread > 0  || (nread == 0 && len == 0) ) {

			/*
			 * some data has been read, or no data was requested
			 */

			return nread;
		}

		if (nread < 0) {

			/*
			 * socket error - check errno
			 */
#ifdef _WIN32
			if ( err == WSAEWOULDBLOCK ) {

				/*
				 * standard case if called from close_socket_gracefully
				 */

				return -1;
			}
			
			else if ( err == WSAETIMEDOUT ) {

				/*
				 * timeout is handled by the while loop
				 */
			}
			
			else return -1;
#else
			/*
			 * TODO: POSIX returns either EAGAIN or EWOULDBLOCK in both cases,
			 * if the timeout is reached and if the socket was set to non-
			 * blocking in close_socket_gracefully, so we can not distinguish
			 * here. We have to wait for the timeout in both cases for now.
			 */

			if ( err == EAGAIN  ||  err == EWOULDBLOCK  ||  err == EINTR ) {

				/*
				 * EAGAIN/EWOULDBLOCK:
				 * standard case if called from close_socket_gracefully
				 * => should return -1
				 * or timeout occured
				 * => the code must stay in the while loop
				 *
				 * EINTR can be generated on a socket with a timeout set even
				 * when SA_RESTART is effective for all relevant signals
				 * (see signal(7)).
				 * => stay in the while loop
				 */

			}
			
			else return -1;
#endif
		}

		if ( timeout > 0 ) clock_gettime( CLOCK_MONOTONIC, &now );

	} while ( timeout <= 0  ||  XX_httplib_difftimespec( & now,  & start ) <= timeout );

	/*
	 * Timeout occured, but no data available.
	 */

	return -1;

}  /* XX_httplib_pull */
