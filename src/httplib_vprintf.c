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
 * Alternative alloc_vprintf() for non-compliant C runtimes
 */

static int alloc_vprintf2( char **buf, const char *fmt, va_list ap ) {

	va_list ap_copy;
	size_t size;
	int len;

	if ( buf == NULL  ||  fmt == NULL ) return -1;

	size = MG_BUF_LEN / 4;
	len  = -1;
	*buf = NULL;

	while ( len < 0 ) {

		if ( *buf != NULL ) *buf = httplib_free( *buf );

		size *= 4;
		*buf = httplib_malloc( size );
		if ( *buf == NULL ) break;

		va_copy( ap_copy, ap );
		len = vsnprintf_impl( *buf, size - 1, fmt, ap_copy );
		va_end( ap_copy );

		(*buf)[size-1] = 0;
	}

	return len;
}


/*
 * Print message to buffer. If buffer is large enough to hold the message,
 * return buffer. If buffer is to small, allocate large enough buffer on heap,
 * and return allocated buffer.
 */

static int alloc_vprintf( char **out_buf, char *prealloc_buf, size_t prealloc_size, const char *fmt, va_list ap ) {

	va_list ap_copy;
	int len;

	/*
	 * Windows is not standard-compliant, and vsnprintf() returns -1 if
	 * buffer is too small. Also, older versions of msvcrt.dll do not have
	 * _vscprintf().  However, if size is 0, vsnprintf() behaves correctly.
	 * Therefore, we make two passes: on first pass, get required message
	 * length.
	 * On second pass, actually print the message.
	 */

	va_copy( ap_copy, ap );
	len = vsnprintf_impl( NULL, 0, fmt, ap_copy );
	va_end( ap_copy );

	if ( len < 0 ) {

		/*
		 * C runtime is not standard compliant, vsnprintf() returned -1.
		 * Switch to alternative code path that uses incremental allocations.
		*/

		va_copy( ap_copy, ap );
		len = alloc_vprintf2( out_buf, fmt, ap_copy );
		va_end( ap_copy );

	}
	
	else if ( (size_t)(len) >= prealloc_size ) {

		/*
		 * The pre-allocated buffer not large enough.
		 * Allocate a new buffer.
		 */

		*out_buf = httplib_malloc( (size_t)(len) + 1 );
		if ( *out_buf == NULL ) {

			/*
			 * Allocation failed. Return -1 as "out of memory" error.
			 */

			return -1;
		}

		/*
		 * Buffer allocation successful. Store the string there.
		 */

		va_copy( ap_copy, ap );
		vsnprintf_impl( *out_buf, (size_t)(len) + 1, fmt, ap_copy );
		va_end( ap_copy );

	}
	
	else {
		/*
		 * The pre-allocated buffer is large enough.
		 * Use it to store the string and return the address.
		 */

		va_copy( ap_copy, ap );
		vsnprintf_impl( prealloc_buf, prealloc_size, fmt, ap_copy );
		va_end( ap_copy );

		*out_buf = prealloc_buf;
	}

	return len;

}  /* alloc_vprintf */


int XX_httplib_vprintf( const struct lh_ctx_t *ctx, struct lh_con_t *conn, const char *fmt, va_list ap ) {

	char mem[MG_BUF_LEN];
	char *buf;
	int len;

	buf = NULL;

	if ( (len = alloc_vprintf( &buf, mem, sizeof(mem), fmt, ap )) > 0 ) len = httplib_write( ctx, conn, buf, (size_t)len );
	if ( buf != mem ) buf = httplib_free( buf );

	return len;

}  /* XX_httplib_vprintf */
