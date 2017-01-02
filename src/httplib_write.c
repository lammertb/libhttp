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

#include "httplib_main.h"

/*
 * int httplib_write( const struct lh_ctx_t *ctx, struct lh_con_t *conn, const void *buffie, size_t lennie );
 *
 * The function httplib_write() writes a number of bytes over a connection.
 * The amount of characters written is returned. If an error occurs
 * the value 0 is returned.
 *
 * The function uses throtteling when necessary for a connection. Throtteling
 * uses the wall clock. Although this can be dangerous in some situations where
 * the value of the wall clock is changed externally, it isn't in this case
 * because the throttle function only looks when the time calue changes, but
 * doesn't take the actual value of the clock in the calculation. In the latter
 * case a monotonic clock with guaranteed increase would be a better choice.
 */

int httplib_write( const struct lh_ctx_t *ctx, struct lh_con_t *conn, const void *buffie, size_t lennie ) {

	time_t now;
	int64_t n;
	int64_t len;
	int64_t total;
	int64_t allowed;
	const char *buf;

	if ( ctx == NULL  ||  conn == NULL  ||  buffie == NULL  ||  lennie == 0 ) return 0;

	buf = buffie;
	len = lennie;

	if ( conn->throttle > 0 ) {

		now = time( NULL );

		if ( now != conn->last_throttle_time ) {

			conn->last_throttle_time  = now;
			conn->last_throttle_bytes = 0;
		}

		allowed = conn->throttle - conn->last_throttle_bytes;
		if ( allowed > len ) allowed = len;

		total = XX_httplib_push_all( ctx, NULL, conn->client.sock, conn->ssl, buf, allowed );

		if ( total == allowed ) {

			buf                        = buf + total;
			conn->last_throttle_bytes += total;

			while ( total < len  &&  ctx->status == CTX_STATUS_RUNNING ) {

				if ( conn->throttle > len-total ) allowed = len-total;
				else                              allowed = conn->throttle;

				n = XX_httplib_push_all( ctx, NULL, conn->client.sock, conn->ssl, buf, allowed );
				if ( n != allowed ) {
				
					if ( n > 0 ) total += n;	
					break;
				}

				sleep( 1 );

				conn->last_throttle_bytes = allowed;
				conn->last_throttle_time  = time( NULL );
				buf                       = buf + n;
				total                    += n;
			}
		}
	}
	
	else total = XX_httplib_push_all( ctx, NULL, conn->client.sock, conn->ssl, buf, len );

	return (int)total;

}  /* httplib_write */
