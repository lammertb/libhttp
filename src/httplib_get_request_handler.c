/* 
 * Copyright (C) 2016 Lammert Bies
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



#include "libhttp-private.h"



/*
 * int XX_httplib_get_request_handler();
 *
 * The function XX_httplib_get_request_handler() retrieves the request handlers
 * for a connection.
 */

int XX_httplib_get_request_handler( struct mg_connection *conn, int handler_type, mg_request_handler *handler, mg_websocket_connect_handler *connect_handler, mg_websocket_ready_handler *ready_handler, mg_websocket_data_handler *data_handler, mg_websocket_close_handler *close_handler, mg_authorization_handler *auth_handler, void **cbdata ) {
	const struct mg_request_info *request_info = mg_get_request_info(conn);

	if ( request_info == NULL ) return 0;

	const char *uri = request_info->local_uri;
	size_t urilen = strlen(uri);
	struct mg_handler_info *tmp_rh;

	if ( conn == NULL  ||  conn->ctx == NULL ) return 0;

	mg_lock_context(conn->ctx);

	/* first try for an exact match */
	for (tmp_rh = conn->ctx->handlers; tmp_rh != NULL;
	     tmp_rh = tmp_rh->next) {
		if (tmp_rh->handler_type == handler_type) {
			if (urilen == tmp_rh->uri_len && !strcmp(tmp_rh->uri, uri)) {
				if (handler_type == WEBSOCKET_HANDLER) {
					*connect_handler = tmp_rh->connect_handler;
					*ready_handler = tmp_rh->ready_handler;
					*data_handler = tmp_rh->data_handler;
					*close_handler = tmp_rh->close_handler;
				} else if (handler_type == REQUEST_HANDLER) {
					*handler = tmp_rh->handler;
				} else { /* AUTH_HANDLER */
					*auth_handler = tmp_rh->auth_handler;
				}
				*cbdata = tmp_rh->cbdata;
				mg_unlock_context(conn->ctx);
				return 1;
			}
		}
	}

	/* next try for a partial match, we will accept uri/something */
	for (tmp_rh = conn->ctx->handlers; tmp_rh != NULL;
	     tmp_rh = tmp_rh->next) {
		if (tmp_rh->handler_type == handler_type) {
			if (tmp_rh->uri_len < urilen && uri[tmp_rh->uri_len] == '/'
			    && memcmp(tmp_rh->uri, uri, tmp_rh->uri_len) == 0) {
				if (handler_type == WEBSOCKET_HANDLER) {
					*connect_handler = tmp_rh->connect_handler;
					*ready_handler = tmp_rh->ready_handler;
					*data_handler = tmp_rh->data_handler;
					*close_handler = tmp_rh->close_handler;
				} else if (handler_type == REQUEST_HANDLER) {
					*handler = tmp_rh->handler;
				} else { /* AUTH_HANDLER */
					*auth_handler = tmp_rh->auth_handler;
				}
				*cbdata = tmp_rh->cbdata;
				mg_unlock_context(conn->ctx);
				return 1;
			}
		}
	}

	/* finally try for pattern match */
	for (tmp_rh = conn->ctx->handlers; tmp_rh != NULL;
	     tmp_rh = tmp_rh->next) {
		if (tmp_rh->handler_type == handler_type) {
			if (XX_httplib_match_prefix(tmp_rh->uri, tmp_rh->uri_len, uri) > 0) {
				if (handler_type == WEBSOCKET_HANDLER) {
					*connect_handler = tmp_rh->connect_handler;
					*ready_handler   = tmp_rh->ready_handler;
					*data_handler    = tmp_rh->data_handler;
					*close_handler   = tmp_rh->close_handler;
				} else if (handler_type == REQUEST_HANDLER) {
					*handler = tmp_rh->handler;
				} else { /* AUTH_HANDLER */
					*auth_handler = tmp_rh->auth_handler;
				}
				*cbdata = tmp_rh->cbdata;
				mg_unlock_context(conn->ctx);
				return 1;
			}
		}
	}

	mg_unlock_context(conn->ctx);

	return 0; /* none found */

}  /* XX_httplib_get_request_handler */
