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
 * int XX_httplib_get_request_handler();
 *
 * The function XX_httplib_get_request_handler() retrieves the request handlers
 * for a connection. The function returns 1 if request handlers could be found
 * and 0 otherwise.
 */

int XX_httplib_get_request_handler( struct lh_ctx_t *ctx, struct lh_con_t *conn, int handler_type, httplib_request_handler *handler, httplib_websocket_connect_handler *connect_handler, httplib_websocket_ready_handler *ready_handler, httplib_websocket_data_handler *data_handler, httplib_websocket_close_handler *close_handler, httplib_authorization_handler *auth_handler, void **cbdata ) {

	const struct lh_rqi_t *request_info;
	const char *uri;
	size_t urilen;
	struct httplib_handler_info *tmp_rh;

	if ( ctx == NULL  ||  conn == NULL ) return 0;

	request_info = httplib_get_request_info( conn );
	if ( request_info == NULL ) return 0;

	uri    = request_info->local_uri;
	urilen = strlen( uri );

	httplib_lock_context( ctx );

	/*
	 * first try for an exact match
	 */

	for (tmp_rh = ctx->handlers; tmp_rh != NULL; tmp_rh = tmp_rh->next) {

		if ( tmp_rh->handler_type == handler_type ) {

			if ( urilen == tmp_rh->uri_len  &&  ! strcmp( tmp_rh->uri, uri ) ) {

				if ( handler_type == WEBSOCKET_HANDLER ) {

					*connect_handler = tmp_rh->connect_handler;
					*ready_handler   = tmp_rh->ready_handler;
					*data_handler    = tmp_rh->data_handler;
					*close_handler   = tmp_rh->close_handler;
				}
				else if ( handler_type == REQUEST_HANDLER ) *handler      = tmp_rh->handler;
				else                                        *auth_handler = tmp_rh->auth_handler;

				*cbdata = tmp_rh->cbdata;
				httplib_unlock_context( ctx );

				return 1;
			}
		}
	}

	/*
	 * next try for a partial match, we will accept uri/something
	 */

	for (tmp_rh = ctx->handlers; tmp_rh != NULL; tmp_rh = tmp_rh->next) {

		if ( tmp_rh->handler_type == handler_type ) {

			if ( tmp_rh->uri_len < urilen  &&  uri[tmp_rh->uri_len] == '/'  &&  memcmp( tmp_rh->uri, uri, tmp_rh->uri_len ) == 0 ) {

				if ( handler_type == WEBSOCKET_HANDLER ) {

					*connect_handler = tmp_rh->connect_handler;
					*ready_handler   = tmp_rh->ready_handler;
					*data_handler    = tmp_rh->data_handler;
					*close_handler   = tmp_rh->close_handler;
				}
				
				else if ( handler_type == REQUEST_HANDLER ) *handler      = tmp_rh->handler;
				else                                        *auth_handler = tmp_rh->auth_handler;

				*cbdata = tmp_rh->cbdata;
				httplib_unlock_context( ctx );

				return 1;
			}
		}
	}

	/*
	 * finally try for pattern match
	 */

	for (tmp_rh = ctx->handlers; tmp_rh != NULL; tmp_rh = tmp_rh->next) {

		if ( tmp_rh->handler_type == handler_type ) {

			if ( XX_httplib_match_prefix( tmp_rh->uri, tmp_rh->uri_len, uri ) > 0 ) {

				if ( handler_type == WEBSOCKET_HANDLER ) {

					*connect_handler = tmp_rh->connect_handler;
					*ready_handler   = tmp_rh->ready_handler;
					*data_handler    = tmp_rh->data_handler;
					*close_handler   = tmp_rh->close_handler;
				}
				
				else if ( handler_type == REQUEST_HANDLER ) *handler      = tmp_rh->handler;
				else                                        *auth_handler = tmp_rh->auth_handler;

				*cbdata = tmp_rh->cbdata;
				httplib_unlock_context( ctx );

				return 1;
			}
		}
	}

	httplib_unlock_context( ctx );

	return 0; /* none found */

}  /* XX_httplib_get_request_handler */
