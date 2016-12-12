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
#include "httplib_string.h"

/*
 * int XX_httplib_send_websocket_handshake( struct mg_connection *conn, const char *websock_key );
 *
 * The function XX_httplib_send_websocket_handshake() sends a handshake over
 * a websocket connection.
 */

#if defined(USE_WEBSOCKET)

int XX_httplib_send_websocket_handshake( struct mg_connection *conn, const char *websock_key ) {

	static const char *magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
	const char *protocol = NULL;
	char buf[100];
	char sha[20];
	char b64_sha[sizeof(sha) * 2];
	SHA1_CTX sha_ctx;
	int truncated;

	/* Calculate Sec-WebSocket-Accept reply from Sec-WebSocket-Key. */
	XX_httplib_snprintf(conn, &truncated, buf, sizeof(buf), "%s%s", websock_key, magic);
	if (truncated) {
		conn->must_close = 1;
		return 0;
	}

	SHA1Init(&sha_ctx);
	SHA1Update(&sha_ctx, (unsigned char *)buf, (uint32_t)strlen(buf));
	SHA1Final((unsigned char *)sha, &sha_ctx);

	XX_httplib_base64_encode((unsigned char *)sha, sizeof(sha), b64_sha);
	mg_printf(conn,
	          "HTTP/1.1 101 Switching Protocols\r\n"
	          "Upgrade: websocket\r\n"
	          "Connection: Upgrade\r\n"
	          "Sec-WebSocket-Accept: %s\r\n",
	          b64_sha);
	protocol = mg_get_header(conn, "Sec-WebSocket-Protocol");
	if (protocol) {
		/* The protocol is a comma seperated list of names. */
		/* The server must only return one value from this list. */
		/* First check if it is a list or just a single value. */
		const char *sep = strchr(protocol, ',');
		if (sep == NULL) {
			/* Just a single protocol -> accept it. */
			mg_printf(conn, "Sec-WebSocket-Protocol: %s\r\n\r\n", protocol);
		} else {
			/* Multiple protocols -> accept the first one. */
			/* This is just a quick fix if the client offers multiple
			 * protocols. In order to get the behavior intended by
			 * RFC 6455 (https://tools.ietf.org/rfc/rfc6455.txt), it is
			 * required to have a list of websocket subprotocols accepted
			 * by the server. Then the server must either select a subprotocol
			 * supported by client and server, or the server has to abort the
			 * handshake by not returning a Sec-Websocket-Protocol header if
			 * no subprotocol is acceptable.
			 */
			mg_printf(conn, "Sec-WebSocket-Protocol: %.*s\r\n\r\n", (int)(sep - protocol), protocol);
		}
		/* TODO: Real subprotocol negotiation instead of just taking the first
		 * websocket subprotocol suggested by the client. */
	}
	else mg_printf(conn, "%s", "\r\n");

	return 1;

}  /* XX_httplib_send_websocket_handshake */

#endif /* !USE_WEBSOCKET */
