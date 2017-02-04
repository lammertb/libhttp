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
 * struct lh_con_t *httplib_connect_websocket_client();
 *
 * The function httplib_connect_websocket_client() connects as a client to a
 * websocket on another server. If this succeeds a connection pointer is
 * returned, otherwise NULL.
 */

struct lh_con_t *httplib_connect_websocket_client( struct lh_ctx_t *ctx, const char *host, int port, int use_ssl, const char *path, const char *origin, httplib_websocket_data_handler data_func, httplib_websocket_close_handler close_func, void *user_data ) {

	struct lh_con_t *conn;
	struct websocket_client_thread_data *thread_data;
	static const char *magic = "x3JJHMbDL1EzLkh9GBhXDw==";
	const char *handshake_req;

	if ( ctx == NULL ) return NULL;

	if ( ctx->status != CTX_STATUS_TERMINATED ) {

		httplib_cry( LH_DEBUG_CRASH, ctx, NULL, "%s: client context not in terminated state", __func__ );
		return NULL;
	}

	if ( origin != NULL ) handshake_req = "GET %s HTTP/1.1\r\n"
		                "Host: %s\r\n"
		                "Upgrade: websocket\r\n"
		                "Connection: Upgrade\r\n"
		                "Sec-WebSocket-Key: %s\r\n"
		                "Sec-WebSocket-Version: 13\r\n"
		                "Origin: %s\r\n"
		                "\r\n";
	
	else handshake_req = "GET %s HTTP/1.1\r\n"
		                "Host: %s\r\n"
		                "Upgrade: websocket\r\n"
		                "Connection: Upgrade\r\n"
		                "Sec-WebSocket-Key: %s\r\n"
		                "Sec-WebSocket-Version: 13\r\n"
		                "\r\n";

	/*
	 * Establish the client connection and request upgrade
	 */

	conn = httplib_download( ctx, host, port, use_ssl, handshake_req, path, host, magic, origin );
	if ( conn == NULL ) {

		httplib_cry( LH_DEBUG_ERROR, ctx, NULL, "%s: init of download failed", __func__ );
		return NULL;
	}

	if ( strcmp( conn->request_info.request_uri, "101" ) ) {

		httplib_cry( LH_DEBUG_ERROR, ctx, conn, "%s: unexpected server reply \"%s\"", __func__, conn->request_info.request_uri );

		conn = httplib_free( conn );
		return NULL;
	}

	ctx->user_data       = user_data;
	ctx->ctx_type        = CTX_TYPE_CLIENT;
	ctx->num_threads     = 1;			/* one worker thread will be created	*/
	ctx->workerthreadids = httplib_calloc( ctx->num_threads, sizeof(pthread_t) );

	if ( ctx->workerthreadids == NULL ) {

		httplib_cry( LH_DEBUG_ERROR, ctx, conn, "%s: out of memory allocating worker thread IDs", __func__ );

		ctx->num_threads = 0;
		ctx->user_data   = NULL;
		conn             = httplib_free( conn );

		return NULL;
	}

	thread_data = httplib_calloc( sizeof(struct websocket_client_thread_data), 1 );

	if ( thread_data == NULL ) {

		httplib_cry( LH_DEBUG_ERROR, ctx, conn, "%s: out of memory allocating thread data", __func__ );

		ctx->workerthreadids = httplib_free( ctx->workerthreadids );
		ctx->num_threads     = 0;
		ctx->user_data       = NULL;
		conn                 = httplib_free( conn );

		return NULL;
	}

	thread_data->ctx           = ctx;
	thread_data->conn          = conn;
	thread_data->data_handler  = data_func;
	thread_data->close_handler = close_func;
	thread_data->callback_data = NULL;

	/*
	 * Start a thread to read the websocket client connection
	 * This thread will automatically stop when httplib_disconnect is
	 * called on the client connection
	 */

	if ( XX_httplib_start_thread_with_id( XX_httplib_websocket_client_thread, thread_data, ctx->workerthreadids) != 0 ) {

		httplib_cry( LH_DEBUG_ERROR, ctx, conn, "%s: thread failed to start", __func__ );

		thread_data          = httplib_free( thread_data          );
		conn                 = httplib_free( conn                 );
		ctx->workerthreadids = httplib_free( ctx->workerthreadids );
		ctx->num_threads     = 0;
		ctx->user_data       = NULL;

		return NULL;
	}

	return conn;

}  /* httplib_connect_websocket_client */
