/* 
 * Copyright (c) 2016-2019 Lammert Bies
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

#ifdef _WIN32
	typedef int len_t;
#else
	typedef size_t len_t;
#endif

/*
 * static int64_t push( const struct lh_ctx_t *ctx, FILE *fp, SOCKET sock, SSL *ssl, const char *buf, int64_t len, double timeout );
 *
 * The function push() writes data to the I/O channel, opened file descriptor,
 * socket or SSL descriptor. The function returns the number of bytes which
 * were actually written. A negative value is returned if an error is
 * encountered.
 *
 * Although we specify the number of bytes in a 64 bit integer, the OS functins
 * may not be able to handle that. We therefore cap the amount of bytes to
 * write to the maximum integer and size_t value, whatever is the smallest. The
 * function push() will be called automatically again if not all bytes have
 * been written.
 */

static int64_t push( const struct lh_ctx_t *ctx, FILE *fp, SOCKET sock, SSL *ssl, const char *buf, int64_t len, double timeout ) {

	struct timespec start;
	struct timespec now;
	int n;
	int err;

	if ( ctx == NULL ) return -1;
#ifdef NO_SSL
	if ( ssl != NULL ) return -1;
#endif  /* NO_SSL */

	if ( len > INT_MAX ) len = INT_MAX;

	if ( timeout > 0.0 ) clock_gettime( CLOCK_MONOTONIC, &start );

	do {

#ifndef NO_SSL
		if ( ssl != NULL ) {

			n = SSL_write( ssl, buf, (int)len );

			if ( n <= 0 ) {

				err = SSL_get_error( ssl, n );

				if      ( err == SSL_ERROR_SYSCALL   &&  n   == -1                   ) err = ERRNO;
				else if ( err == SSL_ERROR_WANT_READ ||  err == SSL_ERROR_WANT_WRITE ) n   = 0;
				else return -1;

			}
			
			else err = 0;
		}
		
		else
#endif  /* NO_SSL */
		if ( fp != NULL ) {

			n = (int)fwrite( buf, 1, (size_t)len, fp );
			if ( ferror(fp) ) {

				n   = -1;
				err = ERRNO;
			}
			
			else err = 0;
		}
		
		else {
			n = (int)send( sock, buf, (len_t)len, MSG_NOSIGNAL );
			err = ( n < 0 ) ? ERRNO : 0;

			if ( n == 0 ) {

				/*
				 * shutdown of the socket at client side
				 */

				return -1;
			}
		}

		if ( ctx->status != CTX_STATUS_RUNNING ) return -1;

		if ( n > 0  ||  (n == 0 && len == 0) ) return n;

		if ( n < 0 ) {

			/*
			 * socket error - check errno
			 *
			 * TODO: error handling depending on the error code.
			 * These codes are different between Windows and Linux.
			 */

			return -1;
		}

		/*
		 * This code is not reached in the moment.
		 * ==> Fix the TODOs above first.
		 */

		if ( err ) return -1;

		if ( timeout > 0.0 ) clock_gettime( CLOCK_MONOTONIC, &now );

	} while ( timeout <= 0.0  ||  XX_httplib_difftimespec( &now, &start ) <= timeout );

	return -1;

}  /* push */



/*
 * int64_t XX_httplib_push_all( const struct lh_ctx_t *ctx, FILE *fp, SOCKET sock, SSL *ssl, const char *buf, int64_t len );
 *
 * The function XX_httplib_push_all() pushes all data in a buffer to a socket.
 * The number of bytes written is returned.
 */

int64_t XX_httplib_push_all( const struct lh_ctx_t *ctx, FILE *fp, SOCKET sock, SSL *ssl, const char *buf, int64_t len ) {

	double timeout;
	int64_t n;
	int64_t nwritten;

	if ( ctx == NULL ) return -1;

	nwritten = 0;
	timeout  = ((double)ctx->request_timeout) / 1000.0;

	while ( len > 0  &&  ctx->status == CTX_STATUS_RUNNING ) {

		n = push( ctx, fp, sock, ssl, buf + nwritten, len, timeout );

		if ( n < 0 ) {

			if ( nwritten == 0 ) return n;
			else                 return nwritten;
		}
		
		if ( n == 0 ) return nwritten;
		
		nwritten += n;
		len      -= n;
	}

	return nwritten;

}  /* XX_httplib_push_all */
