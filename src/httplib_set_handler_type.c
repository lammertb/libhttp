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
 * void XX_httplib_set_handler_type();
 *
 * The function XX_httplib_set_handler_type() is the generic function which
 * sets callback handlers to uri's.
 */

void XX_httplib_set_handler_type( struct lh_ctx_t *ctx, const char *uri, int handler_type, int is_delete_request, httplib_request_handler handler, httplib_websocket_connect_handler connect_handler, httplib_websocket_ready_handler ready_handler, httplib_websocket_data_handler data_handler, httplib_websocket_close_handler close_handler, httplib_authorization_handler auth_handler, void *cbdata ) {

	struct httplib_handler_info *tmp_rh;
	struct httplib_handler_info **lastref;
	size_t urilen;

	if ( uri == NULL ) return;

	urilen = strlen( uri );

	if ( handler_type == WEBSOCKET_HANDLER ) {

		if (   handler != NULL                                                                                                                ) return;
		if ( ! is_delete_request  &&  connect_handler == NULL  &&  ready_handler == NULL  &&  data_handler == NULL  &&  close_handler == NULL ) return;
		if (   auth_handler != NULL                                                                                                           ) return;
	}
	
	else if ( handler_type == REQUEST_HANDLER ) {

		if (   connect_handler != NULL  ||  ready_handler != NULL  ||  data_handler != NULL  ||  close_handler != NULL ) return;
		if ( ! is_delete_request  &&  handler == NULL                                                                  ) return;
		if (   auth_handler != NULL                                                                                    ) return;
	}
	
	else { /* AUTH_HANDLER */
		if (   handler != NULL                                                                                         ) return;
		if (   connect_handler != NULL  ||  ready_handler != NULL  ||  data_handler != NULL  ||  close_handler != NULL ) return;
		if ( ! is_delete_request  &&  auth_handler == NULL                                                             ) return;
	}

	if ( ctx == NULL ) return;

	httplib_lock_context( ctx );

	/*
	 * first try to find an existing handler
	 */

	lastref = & ctx->handlers;

	for ( tmp_rh=ctx->handlers; tmp_rh != NULL; tmp_rh=tmp_rh->next ) {

		if ( tmp_rh->handler_type == handler_type ) {

			if ( urilen == tmp_rh->uri_len  &&  ! strcmp( tmp_rh->uri, uri ) ) {

				if ( ! is_delete_request ) {

					/*
					 * update existing handler
					 */

					if ( handler_type == REQUEST_HANDLER ) {

						tmp_rh->handler = handler;
					}
					
					else if ( handler_type == WEBSOCKET_HANDLER ) {

						tmp_rh->connect_handler = connect_handler;
						tmp_rh->ready_handler   = ready_handler;
						tmp_rh->data_handler    = data_handler;
						tmp_rh->close_handler   = close_handler;
					}
					
					else { /* AUTH_HANDLER */
						tmp_rh->auth_handler = auth_handler;
					}

					tmp_rh->cbdata = cbdata;
				}
				
				else {
					/*
					 * remove existing handler
					 */

					*lastref    = tmp_rh->next;
					tmp_rh->uri = httplib_free( tmp_rh->uri );
					tmp_rh      = httplib_free( tmp_rh      );
				}

				httplib_unlock_context(ctx);
				return;
			}
		}
		lastref = & tmp_rh->next;
	}

	if ( is_delete_request ) {

		/*
		 * no handler to set, this was a remove request to a non-existing
		 * handler
		 */

		httplib_unlock_context( ctx );
		return;
	}

	tmp_rh = httplib_calloc( sizeof(struct httplib_handler_info), 1 );

	if ( tmp_rh == NULL ) {

		httplib_unlock_context( ctx );
		httplib_cry( LH_DEBUG_ERROR, ctx, NULL, "%s: cannot create new request handler struct, OOM", __func__ );

		return;
	}

	tmp_rh->uri = httplib_strdup( uri );

	if ( tmp_rh->uri == NULL ) {

		httplib_unlock_context( ctx );
		tmp_rh = httplib_free( tmp_rh );
		httplib_cry( LH_DEBUG_ERROR, ctx, NULL, "%s: cannot create new request handler struct, OOM", __func__ );

		return;
	}

	tmp_rh->uri_len = urilen;

	if ( handler_type == REQUEST_HANDLER ) {

		tmp_rh->handler = handler;
	}
	
	else if ( handler_type == WEBSOCKET_HANDLER ) {

		tmp_rh->connect_handler = connect_handler;
		tmp_rh->ready_handler   = ready_handler;
		tmp_rh->data_handler    = data_handler;
		tmp_rh->close_handler   = close_handler;
	}
	
	else { /* AUTH_HANDLER */
		tmp_rh->auth_handler = auth_handler;
	}
	tmp_rh->cbdata = cbdata;
	tmp_rh->handler_type = handler_type;
	tmp_rh->next = NULL;

	*lastref = tmp_rh;
	httplib_unlock_context(ctx);

}  /* XX_httplib_set_handler_type */
