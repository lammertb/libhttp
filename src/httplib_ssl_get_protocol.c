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
 * long XX_httplib_ssl_get_protocol( int version_id );
 *
 * The function XX_httplib_ssl_get_protocol() returns a bit mask with the
 * supported SSH protocols based on the version number passed as a parameter.
 */

long XX_httplib_ssl_get_protocol( int version_id ) {

	long ret;

	ret = SSL_OP_ALL;

	if ( version_id > 0 ) ret |= SSL_OP_NO_SSLv2;
	if ( version_id > 1 ) ret |= SSL_OP_NO_SSLv3;
	if ( version_id > 2 ) ret |= SSL_OP_NO_TLSv1;
	if ( version_id > 3 ) ret |= SSL_OP_NO_TLSv1_1;

	return ret;

}  /* XX_httplib_ssl_get_protocol */

#endif /* !NO_SSL */
