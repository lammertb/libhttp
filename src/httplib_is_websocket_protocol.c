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
 * int XX_httplib_is_websocket_protocol( const struct lh_con_t *conn );
 *
 * The function XX_httplib_is_websocket_protocol() checks the request headers
 * to see if the connection is a valid websocket protocol.
 */

bool XX_httplib_is_websocket_protocol( const struct lh_con_t *conn ) {

	const char *upgrade;
	const char *connection;

	/*
	 * A websocket protocol has the following HTTP headers:
	 *
	 * Connection: Upgrade
	 * Upgrade: Websocket
	 */

	upgrade = httplib_get_header( conn, "Upgrade" );
	if ( upgrade == NULL ) return false; /* fail early, don't waste time checking other header * fields */

	if ( httplib_strcasestr(upgrade, "websocket") == NULL ) return false;

	connection = httplib_get_header( conn, "Connection" );
	if ( connection == NULL ) return false;

	if ( httplib_strcasestr( connection, "upgrade" ) == NULL ) return false;

	/*
	 * The headers "Host", "Sec-WebSocket-Key", "Sec-WebSocket-Protocol" and
	 * "Sec-WebSocket-Version" are also required.
	 * Don't check them here, since even an unsupported websocket protocol
	 * request still IS a websocket request (in contrast to a standard HTTP
	 * request). It will fail later in handle_websocket_request.
	 */

	return true;

}  /* XX_httplib_is_websocket_protocol */
