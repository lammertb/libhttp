/* 
 * Copyright (c) 2016-2019 Lammert Bies
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

#if !defined(NO_SSL)

#include "httplib_main.h"
#include "httplib_ssl.h"

/*
 * int XX_httplib_get_first_ssl_listener_index( const struct lh_ctx_t *ctx );
 *
 * The function XX_httplib_get_first_ssl_listener_index() returns the first
 * index of a listening socket where SSL encryption is active.
 */

int XX_httplib_get_first_ssl_listener_index( const struct lh_ctx_t *ctx ) {

	unsigned int i;
	int idx;

	idx = -1;

	if ( ctx != NULL ) for (i=0; idx == -1 && i < ctx->num_listening_sockets; i++) idx = (ctx->listening_sockets[i].has_ssl) ? ((int)(i)) : -1;

	return idx;

}  /* XX_httplib_get_first_ssl_listener_index */

#endif  /* !NO_SSL */
