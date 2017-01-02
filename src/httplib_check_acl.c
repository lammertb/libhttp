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
 * int XX_httplib_check_acl( struct lh_ctx_t *ctx, uint32_t remote_ip );
 *
 * The function XX_httplib_check_acl() is used to check of the socket address
 * of a connection is allowed according to the access control list. The
 * function returns -1 if the ACL is malformed, 0 if the address is not
 * allowed and 1 if the address is allowed.
 */

int XX_httplib_check_acl( struct lh_ctx_t *ctx, uint32_t remote_ip ) {

	int allowed;
	int flag;
	uint32_t net;
	uint32_t mask;
	struct vec vec;
	const char *list;

	if ( ctx == NULL ) return -1;

	list = ctx->access_control_list;

	if ( list == NULL ) allowed = '+';
	else                allowed = '-';


	while ( (list = XX_httplib_next_option( list, & vec, NULL )) != NULL ) {

		flag = vec.ptr[0];

		if ( (flag != '+'  &&  flag != '-')  ||  XX_httplib_parse_net( &vec.ptr[1], &net, &mask ) == 0 ) {

			httplib_cry( LH_DEBUG_WARNING, ctx, NULL, "%s: subnet must be [+|-]x.x.x.x[/x]", __func__ );
			return -1;
		}

		if ( (remote_ip & mask) == net ) allowed = flag;
	}

	return (allowed == '+');

}  /* XX_httplib_check_acl */
