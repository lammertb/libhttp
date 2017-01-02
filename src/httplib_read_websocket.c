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
 * Release: 1.9
 */

#include "httplib_main.h"

/*
 * void XX_httplib_read_websocket( struct lh_ctx_t *ctx, struct lh_con_t *conn, httplib_websocket_data_handler ws_data_handler, void *calback_data );
 *
 * The function XX_httplib_read_websocket() reads from a websocket connection.
 */

void XX_httplib_read_websocket( struct lh_ctx_t *ctx, struct lh_con_t *conn, httplib_websocket_data_handler ws_data_handler, void *callback_data ) {

	/* Pointer to the beginning of the portion of the incoming websocket
	 * message queue.
	 * The original websocket upgrade request is never removed, so the queue
	 * begins after it. */
	unsigned char *buf = (unsigned char *)conn->buf + conn->request_len;
	int n;
	int error;
	int exit_by_callback;

	/* 
	 * body_len is the length of the entire queue in bytes
	 * len is the length of the current message
	 * data_len is the length of the current message's data payload
	 * header_len is the length of the current message's header
	 */

	size_t i;
	size_t len;
	size_t mask_len = 0;
	size_t data_len = 0;
	size_t header_len;
	size_t body_len;

	/*
	 * "The masking key is a 32-bit value chosen at random by the client."
	 * http://tools.ietf.org/html/draft-ietf-hybi-thewebsocketprotocol-17#section-5
	 */

	unsigned char mask[4];

	/*
	 * data points to the place where the message is stored when passed to
	 * the websocket_data callback.  This is either mem on the stack, or a
	 * dynamically allocated buffer if it is too large.
	 */

	char mem[4096];
	char *data;
	unsigned char mop; /* mask flag and opcode */
	double timeout;

	if ( ctx == NULL  ||   conn == NULL ) return;

	data = mem;

	timeout                       = ((double)ctx->websocket_timeout) / 1000.0;
	if ( timeout <= 0.0 ) timeout = ((double)ctx->request_timeout  ) / 1000.0;

	XX_httplib_set_thread_name( ctx, "wsock" );

	/*
	 * Loop continuously, reading messages from the socket, invoking the
	 * callback, and waiting repeatedly until an error occurs.
	 */

	while ( ctx->status == CTX_STATUS_RUNNING ) {

		header_len = 0;

		if ( conn->data_len < conn->request_len ) {

			httplib_cry( LH_DEBUG_ERROR, ctx, conn, "%s: websocket error: data len less than request len, closing connection", __func__ );
			break;
		}

		body_len = (size_t)(conn->data_len - conn->request_len);

		if ( body_len >= 2 ) {

			len      =  buf[1] & 127;
			mask_len = (buf[1] & 128) ? 4 : 0;

			if ( len < 126  &&  body_len >= mask_len ) {

				data_len   = len;
				header_len = 2 + mask_len;
			}
			
			else if ( len == 126  &&  body_len >= mask_len+4 ) {

				header_len = mask_len+4;
				data_len   = (((size_t)buf[2]) << 8) + buf[3];
			}
			
			else if ( body_len >= 10+mask_len+10 ) {

				header_len = mask_len+10;
				data_len   = (((uint64_t)ntohl(*(uint32_t *)(void *)&buf[2])) << 32) + ntohl(*(uint32_t *)(void *)&buf[6]);
			}
		}

		if ( header_len > 0  &&  body_len >= header_len ) {

			/*
			 * Allocate space to hold websocket payload
			 */

			data = mem;

			if ( data_len > sizeof(mem) ) {

				data = httplib_malloc( data_len );

				if ( data == NULL ) {

					/*
					 * Allocation failed, exit the loop and then close the
					 * connection
					 */

					httplib_cry( LH_DEBUG_ERROR, ctx, conn, "%s: websocket out of memory; closing connection", __func__ );
					break;
				}
			}

			/* Copy the mask before we shift the queue and destroy it */
			if ( mask_len > 0 ) memcpy( mask, buf + header_len - mask_len, sizeof(mask) );
			else                memset( mask, 0,                           sizeof(mask) );

			/*
			 * Read frame payload from the first message in the queue into
			 * data and advance the queue by moving the memory in place.
			 */

			if ( body_len < header_len ) {

				httplib_cry( LH_DEBUG_ERROR, ctx, conn, "%s: websocket error: body len less than header len, closing connection", __func__ );
				break;
			}

			if (data_len + header_len > body_len) {

				 /*
				  * current mask and opcode
				  */

				mop = buf[0];

				/*
				 * Overflow case
				 */

				len = body_len - header_len;
				memcpy( data, buf + header_len, len );
				error = 0;

				while ( len < data_len ) {

					n = XX_httplib_pull( ctx, NULL, conn, data + len, (int)(data_len - len), timeout );
					if ( n <= 0 ) {

						error = 1;
						break;
					}

					len += (size_t)n;
				}
				
				if (error) {

					httplib_cry( LH_DEBUG_ERROR, ctx, conn, "%s: websocket pull failed; closing connection", __func__ );
					break;
				}

				conn->data_len = conn->request_len;
			}
			
			else {
				/*
				 * current mask and opcode, overwritten by
				 * memmove()
				 */

				mop = buf[0];

				/*
				 * Length of the message being read at the front of the
				 * queue
				 */

				len = data_len + header_len;

				/*
				 * Copy the data payload into the data pointer for the
				 * callback
				 */

				memcpy( data, buf + header_len, data_len );

				/*
				 * Move the queue forward len bytes
				 */

				memmove( buf, buf + len, body_len - len );

				/*
				 * Mark the queue as advanced
				 */

				conn->data_len -= (int)len;
			}

			/*
			 * Apply mask if necessary
			 */

			if ( mask_len > 0 ) for (i=0; i<data_len; i++) data[i] ^= mask[i % 4];

			/*
			 * Exit the loop if callback signals to exit (server side),
			 * or "connection close" opcode received (client side).
			 */

			exit_by_callback = 0;
			if ((ws_data_handler != NULL) && !ws_data_handler( ctx, conn, mop, data, data_len, callback_data)) exit_by_callback = 1;

			if ( data != mem ) data = httplib_free( data );

			/*
			 * Opcode == 8, connection close
			 */

			if ( exit_by_callback  ||  (mop & 0xf) == WEBSOCKET_OPCODE_CONNECTION_CLOSE ) break;

			/*
			 * Not breaking the loop, process next websocket frame.
			 */
		}
		
		else {
			/*
			 * Read from the socket into the next available location in the
			 * message queue.
			 */

			n = XX_httplib_pull( ctx, NULL, conn, conn->buf + conn->data_len, conn->buf_size - conn->data_len, timeout );

			/*
			 * Error, no bytes read
			 */

			if ( n <= 0 ) break;

			conn->data_len += n;
		}
	}

	XX_httplib_set_thread_name( ctx, "worker" );

}  /* XX_httplib_read_websocket */
