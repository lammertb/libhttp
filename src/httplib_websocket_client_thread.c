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
 * ... XX_httplib_websocket_client_thread( void *data );
 *
 * The function XX_httplib_websocket_client_thread() is the worker thread which
 * connects as a client to a remote websocket server.
 */

#if defined(USE_WEBSOCKET)
#ifdef _WIN32
unsigned __stdcall XX_httplib_websocket_client_thread( void *data ) {
#else  /* _WIN32 */
void * XX_httplib_websocket_client_thread(void *data) {
#endif  /* _WIN32 */
	struct websocket_client_thread_data *cdata = (struct websocket_client_thread_data *)data;

	XX_httplib_set_thread_name("ws-client");

	if (cdata->conn->ctx) {
		if (cdata->conn->ctx->callbacks.init_thread) {
			/* 3 indicates a websocket client thread */
			/* TODO: check if conn->ctx can be set */
			cdata->conn->ctx->callbacks.init_thread(cdata->conn->ctx, 3);
		}
	}

	XX_httplib_read_websocket(cdata->conn, cdata->data_handler, cdata->callback_data);

	if (cdata->close_handler != NULL) cdata->close_handler(cdata->conn, cdata->callback_data);

	XX_httplib_free((void *)cdata);


#ifdef _WIN32
	return 0;
#else  /* _WIN32 */
	return NULL;
#endif  /* _WIN32 */
}  /* XX_httplib_websocket_client_thread */
#endif
