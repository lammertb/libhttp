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
 * int XX_httlib_send_static_cache_header( const struct lh_ctx_t *ctx, struct lh_con_t *conn );
 *
 * The function XX_httplib_send_static_cache_header() sends cache headers
 * depending on the cache setting of the current context.
 */

int XX_httplib_send_static_cache_header( const struct lh_ctx_t *ctx, struct lh_con_t *conn ) {

	if ( ctx == NULL  ||  conn == NULL ) return 0;

	/*
	 * Read the server config to check how long a file may be cached.
	 * The configuration is in seconds.
	 */

	if ( ctx->static_file_max_age <= 0 ) {

		/*
		 * 0 means "do not cache". All values <0 are reserved
		 * and may be used differently in the future.
		 * If a file should not be cached, do not only send
		 * max-age=0, but also pragmas and Expires headers.
		 */

		return XX_httplib_send_no_cache_header( ctx, conn );
	}

	/*
	 * Use "Cache-Control: max-age" instead of "Expires" header.
	 * Reason: see https://www.mnot.net/blog/2007/05/15/expires_max-age
	 * See also https://www.mnot.net/cache_docs/
	 * According to RFC 2616, Section 14.21, caching times should not exceed
	 * one year. A year with 365 days corresponds to 31536000 seconds, a leap
	 * year to 31622400 seconds. For the moment, we just send whatever has
	 * been configured, still the behavior for >1 year should be considered
	 * as undefined.
	 */

	return httplib_printf( ctx, conn, "Cache-Control: max-age=%d\r\n", ctx->static_file_max_age );

}  /* XX_httplib_send_static_cache_header */
