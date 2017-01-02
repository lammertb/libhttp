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
 * int XX_httplib_websocket_write_exec( const struct lh_ctx_t *ctx, struct lh_con_t *conn, int opcode, const char *data, size_t data_len, uint32_t masking_key );
 *
 * The function XX_httplib_websocket_write_exec() does the heavy lifting in
 * writing data over a websocket connectin to a remote peer.
 */

int XX_httplib_websocket_write_exec( const struct lh_ctx_t *ctx, struct lh_con_t *conn, int opcode, const char *data, size_t data_len, uint32_t masking_key ) {

	unsigned char header[14];
	size_t header_len;
	int retval;
	uint16_t len;
	uint32_t len1;
	uint32_t len2;

	if ( ctx == NULL ) return -1;

	retval     = -1;
	header_len = 1;
	header[0]  = 0x80 + (opcode & 0xF);

	/*
	 * Frame format: http://tools.ietf.org/html/rfc6455#section-5.2
	 */

	if ( data_len < 126 ) {

		/*
		 * inline 7-bit length field
		 */

		header[1]  = (unsigned char)data_len;
		header_len = 2;
	}
	
	else if ( data_len <= 65535 ) {

		/*
		 * 16-bit length field
		 */

		len        = htons( (uint16_t)data_len );
		header[1]  = 126;
		header_len = 4;
		memcpy( header+2, & len, 2 );
	}
	
	else {
		/*
		 * 64-bit length field
		 */

		len1       = htonl( (uint64_t)data_len >> 32 );
		len2       = htonl( data_len & 0xFFFFFFFF );
		header[1]  = 127;
		header_len = 10;
		memcpy( header + 2, & len1, 4 );
		memcpy( header + 6, & len2, 4 );
	}

	if ( masking_key ) {

		/*
		 * add mask
		 */

		header[1] |= 0x80;
		memcpy( header + header_len, & masking_key, 4 );
		header_len += 4;
	}


	/*
	 * Note that POSIX/Winsock's send() is threadsafe
	 * http://stackoverflow.com/questions/1981372/are-parallel-calls-to-send-recv-on-the-same-socket-valid
	 * but LibHTTP's httplib_printf/httplib_write is not (because of the loop in
	 * push(), although that is only a problem if the packet is large or
	 * outgoing buffer is full).
	 */

	httplib_lock_connection( conn );

	retval = httplib_write( ctx, conn, header, header_len );
	if ( data_len > 0 ) retval = httplib_write( ctx, conn, data, data_len );

	httplib_unlock_connection( conn );

	return retval;

}  /* XX_httplib_websocket_write_exec */
