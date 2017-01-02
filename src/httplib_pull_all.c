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

int XX_httplib_pull_all( const struct lh_ctx_t *ctx, FILE *fp, struct lh_con_t *conn, char *buf, int len ) {

	int n;
	int nread;
	double timeout;

	if ( ctx == NULL  ||   conn == NULL ) return 0;

	nread   = 0;
	timeout = ((double)ctx->request_timeout) / 1000.0;

	while ( len > 0  &&  ctx->status == CTX_STATUS_RUNNING ) {

		n = XX_httplib_pull( ctx, fp, conn, buf + nread, len, timeout );

		if ( n < 0 ) {

			if ( nread == 0 ) nread = n; /* Propagate the error */
			break;
		}
		
		else if (n == 0) break; /* No more data to read */
		
		else {
			conn->consumed_content += n;
			nread                  += n;
			len                    -= n;
		}
	}

	return nread;

}  /* XX_httplib_pull_all */
