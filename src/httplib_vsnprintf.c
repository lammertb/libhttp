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
 * Return null terminated string of given maximum length.
 * Report errors if length is exceeded.
 */

void XX_httplib_vsnprintf( struct lh_ctx_t *ctx, const struct lh_con_t *conn, bool *truncated, char *buf, size_t buflen, const char *fmt, va_list ap ) {

	int n;
	bool ok;

	if ( buf == NULL  ||  buflen < 1 ) return;

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
/* Using fmt as a non-literal is intended here, since it is mostly called
 * indirectly by XX_httplib_snprintf */
#endif

	n  = (int)vsnprintf_impl( buf, buflen, fmt, ap );
	ok = (n >= 0)  &&  ((size_t)n < buflen);

#ifdef __clang__
#pragma clang diagnostic pop
#endif

	if ( ok ) {
		if ( truncated != NULL ) *truncated = false;
	}

	else {
		if ( truncated != NULL ) *truncated = true;
		if ( ctx !=  NULL  &&  conn != NULL ) httplib_cry( LH_DEBUG_WARNING, ctx, conn, "%s: truncating vsnprintf buffer: [%.*s]", __func__, (int)((buflen > 200) ? 200 : (buflen - 1)), buf );
		n = (int)buflen - 1;
	}
	buf[n] = '\0';

}  /* XX_httplib_vsnprintf */
