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
 * void httplib_destroy_client_context( struct lh_ctx_t *ctx );
 *
 * The function httplib_destroy_client_context() destroys the context for a
 * client connection. This function should not be called for server contexts.
 * Use httplib_stop() for server contexts instead.
 */

void httplib_destroy_client_context( struct lh_ctx_t *ctx ) {

	if ( ctx == NULL ) return;

	if ( ctx->callbacks.exit_context != NULL ) ctx->callbacks.exit_context( ctx );

	XX_httplib_free_config_options( ctx );

	ctx->workerthreadids = httplib_free( ctx->workerthreadids );
	ctx                  = httplib_free( ctx );

}  /* httplib_destroy_client_context */
