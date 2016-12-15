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
 * Release: 1.8
 */

#include "httplib_main.h"
#include "httplib_memory.h"
#include "httplib_utils.h"

#if defined(USE_WEBSOCKET)

static void mask_data( const char *in, size_t in_len, uint32_t masking_key, char *out );

/*
 * int httplib_websocket_client_write( struct httplib_connection *conn, int opcode, const char *data, size_t dataLen );
 *
 * The function httplib_websocket_client_write() is used to write as a client to a
 * websocket server.
 */

int httplib_websocket_client_write( struct httplib_connection *conn, int opcode, const char *data, size_t dataLen ) {

	int retval = -1;
	char *masked_data = XX_httplib_malloc(((dataLen + 7) / 4) * 4);
	uint32_t masking_key = (uint32_t)XX_httplib_get_random();

	if (masked_data == NULL) {
		/* Return -1 in an error case */
		httplib_cry(conn, "Cannot allocate buffer for masked websocket response: Out of memory");
		return -1;
	}

	mask_data(data, dataLen, masking_key, masked_data);

	retval = XX_httplib_websocket_write_exec( conn, opcode, masked_data, dataLen, masking_key );
	XX_httplib_free(masked_data);

	return retval;

}  /* httplib_websocket_client_write */



/*
 * static void mask_data( const char *in, size_t in_len, uint32_t masking_key, char *out );
 *
 * The function mask_data() is used to mask data when writing data over a
 * websocket client connection.
 */

static void mask_data( const char *in, size_t in_len, uint32_t masking_key, char *out ) {

	size_t i = 0;

	i = 0;
	if ((in_len > 3) && ((ptrdiff_t)in % 4) == 0) {
		/* Convert in 32 bit words, if data is 4 byte aligned */
		while (i < (in_len - 3)) {
			*(uint32_t *)(void *)(out + i) = *(uint32_t *)(void *)(in + i) ^ masking_key;
			i += 4;
		}
	}
	if (i != in_len) {
		/* convert 1-3 remaining bytes if ((dataLen % 4) != 0)*/
		while (i < in_len) {
			*(uint8_t *)(void *)(out + i) = *(uint8_t *)(void *)(in + i) ^ *(((uint8_t *)&masking_key) + (i % 4));
			i++;
		}
	}

}  /* mask_data */


#endif /* !USE_WEBSOCKET */
