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
 * void XX_httplib_handle_websocket_request();
 *
 * The function XX_httplib_handle_websocket_request() processes a websocket
 * request on a connection.
 */

void XX_httplib_handle_websocket_request( struct lh_ctx_t *ctx, struct lh_con_t *conn, const char *path, int is_callback_resource, httplib_websocket_connect_handler ws_connect_handler, httplib_websocket_ready_handler ws_ready_handler, httplib_websocket_data_handler ws_data_handler, httplib_websocket_close_handler ws_close_handler, void *cbData ) {

	const char *websock_key;
	const char *version;
	int lua_websock;
	const char *key1;
	const char *key2;
	char key3[8];

	UNUSED_PARAMETER(path);

	if ( ctx == NULL  ||  conn == NULL ) return;

	websock_key = httplib_get_header( conn, "Sec-WebSocket-Key"     );
	version     = httplib_get_header( conn, "Sec-WebSocket-Version" );
	lua_websock = 0;

	/*
	 * Step 1: Check websocket protocol version.
	 * Step 1.1: Check Sec-WebSocket-Key.
	 */

	if ( websock_key == NULL ) {

		/*
		 * The RFC standard version (https://tools.ietf.org/html/rfc6455)
		 * requires a Sec-WebSocket-Key header.
		 *
		 * It could be the hixie draft version
		 * (http://tools.ietf.org/html/draft-hixie-thewebsocketprotocol-76).
		 */

		key1 = httplib_get_header( conn, "Sec-WebSocket-Key1" );
		key2 = httplib_get_header( conn, "Sec-WebSocket-Key2" );

		if ( key1 != NULL  &&  key2 != NULL ) {

			/*
			 * This version uses 8 byte body data in a GET request
			 */

			conn->content_len = 8;

			if ( httplib_read( ctx, conn, key3, 8 ) == 8 ) {

				/*
				 * This is the hixie version
				 */

				XX_httplib_send_http_error( ctx, conn, 426, "%s", "Protocol upgrade to RFC 6455 required" );
				return;
			}
		}

		/*
		 * This is an unknown version
		 */

		XX_httplib_send_http_error( ctx, conn, 400, "%s", "Malformed websocket request" );
		return;
	}

	/*
	 * Step 1.2: Check websocket protocol version.
	 * The RFC version (https://tools.ietf.org/html/rfc6455) is 13.
	 */

	if (  version == NULL  ||  strcmp( version, "13" ) != 0 ) {

		/*
		 * Reject wrong versions
		 */

		XX_httplib_send_http_error( ctx, conn, 426, "%s", "Protocol upgrade required" );
		return;
	}

	/*
	 * Step 1.3: Could check for "Host", but we do not really nead this
	 * value for anything, so just ignore it.
	 */

	/*
	 * Step 2: If a callback is responsible, call it.
	 */

	if ( is_callback_resource ) {

		if ( ws_connect_handler != NULL  &&  ws_connect_handler( ctx, conn, cbData ) != 0 ) {

			/*
			 * C callback has returned non-zero, do not proceed with
			 * handshake.
			 *
			 * Note that C callbacks are no longer called when Lua is
			 * responsible, so C can no longer filter callbacks for Lua.
			 */

			return;
		}
	}

	/*
	 * Step 4: Check if there is a responsible websocket handler.
	 */

	if ( ! is_callback_resource  &&   ! lua_websock ) {

		/*
		 * There is no callback, an Lua is not responsible either. */
		/* Reply with a 404 Not Found or with nothing at all?
		 * TODO (mid): check the websocket standards, how to reply to
		 * requests to invalid websocket addresses.
		 */

		XX_httplib_send_http_error( ctx, conn, 404, "%s", "Not found" );
		return;
	}

	/*
	 * Step 5: The websocket connection has been accepted
	 */

	if ( ! XX_httplib_send_websocket_handshake( ctx, conn, websock_key ) ) {

		XX_httplib_send_http_error( ctx, conn, 500, "%s", "Websocket handshake failed" );
		return;
	}

	/*
	 * Step 6: Call the ready handler
	 */

	if ( is_callback_resource ) {

		if ( ws_ready_handler != NULL ) ws_ready_handler( ctx, conn, cbData );
	}

	/*
	 * Step 7: Enter the read loop
	 */

	if (is_callback_resource) XX_httplib_read_websocket( ctx, conn, ws_data_handler, cbData );

	/*
	 * Step 8: Call the close handler
	 */

	if ( ws_close_handler != NULL ) ws_close_handler( ctx, conn, cbData );

}  /* XX_httplib_handle_websocket_request */
