/* 
 * Copyright (c) 2016 Lammert Bies
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
 * struct lh_ctx_t *httplib_create_client_context( const struct lh_clb_t *callbacks, const struct lh_opt_t *options );
 *
 * The function httplib_create_client_context() creates a context to be used
 * for one simultaneous client connection. It is not possible to use one client
 * context for multiple connections at the same time, because the contect
 * contains SSL context information which is specific for one connection.
 */

struct lh_ctx_t *httplib_create_client_context( const struct lh_clb_t *callbacks, const struct lh_opt_t *options ) {

	struct lh_ctx_t *ctx;
	void (*exit_callback)(struct lh_ctx_t *ctx);

	exit_callback = NULL;
	ctx           = httplib_calloc( 1, sizeof(struct lh_ctx_t) );
	if ( ctx == NULL ) return NULL;

	if ( callbacks != NULL ) {

		ctx->callbacks              = *callbacks;
		exit_callback               = callbacks->exit_context;
		ctx->callbacks.exit_context = NULL;
	}

	if ( XX_httplib_init_options(    ctx          ) ) return NULL;
	if ( XX_httplib_process_options( ctx, options ) ) return NULL;

	if ( ctx->callbacks.init_context != NULL ) ctx->callbacks.init_context( ctx );

	ctx->callbacks.exit_context = exit_callback;
	ctx->ctx_type               = CTX_TYPE_CLIENT;
	ctx->status                 = CTX_STATUS_TERMINATED;

	return ctx;

}  /* httplib_create_client_context */
