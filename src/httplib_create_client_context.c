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
 * struct httplib_context *httplib_create_client_context( const struct httplib_option_t *options );
 *
 * The function httplib_create_client_context() creates a context to be used
 * for one simultaneous client connection. It is not possible to use one client
 * context for multiple connections at the same time, because the contect
 * contains SSL context information which is specific for one connection.
 */

struct httplib_context *httplib_create_client_context( const struct httplib_option_t *options ) {

	struct httplib_context *ctx;

	ctx = httplib_calloc( 1, sizeof(struct httplib_context) );
	if ( ctx == NULL ) return NULL;

	if ( XX_httplib_init_options(    ctx          ) ) return NULL;
	if ( XX_httplib_process_options( ctx, options ) ) return NULL;

	return ctx;

}  /* httplib_create_client_context */
