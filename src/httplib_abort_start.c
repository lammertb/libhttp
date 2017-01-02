/* 
 * Copyright (c) 2016 Lammert Bies
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

#include "httplib_main.h"

/* 
 * struct lh_ctx_t *XX_httplib_abort_start( struct lh_ctx_t *ctx, const char *fmt, ... );
 *
 * The function XX_httplib_abort_start() is called to do some cleanup work when
 * an error occured initializing a context. The function returns NULL which is
 * then further returned to the calling party.
 */

struct lh_ctx_t *XX_httplib_abort_start( struct lh_ctx_t *ctx, const char *fmt, ... ) {

	va_list ap;
	char buf[MG_BUF_LEN];

	if ( ctx == NULL ) return NULL;

	if ( fmt != NULL ) {

		va_start( ap, fmt );
		vsnprintf_impl( buf, sizeof(buf), fmt, ap );
		va_end( ap );
		buf[sizeof(buf)-1] = 0;

		httplib_cry( LH_DEBUG_CRASH, ctx, NULL, "%s: %s", __func__, buf );
	}

	XX_httplib_free_context( ctx );

	httplib_pthread_setspecific( XX_httplib_sTlsKey, NULL );

	return NULL;

}  /* XX_httplib_abort_start */
