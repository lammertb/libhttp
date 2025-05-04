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
#include "httplib_pthread.h"
#include "httplib_ssl.h"
#include "httplib_utils.h"

#if !defined(NO_SSL_DL)
static void *cryptolib_dll_handle; /* Store the crypto library handle. */
#endif  /* NO_SSL_DL */



/*
 * int XX_httplib_initialize_ssl( struct lh_ctx_t *ctx );
 *
 * The function XX_httplib_initialize_ssl() initializes the use of SSL
 * encrypted communication on the given context.
 */

int XX_httplib_initialize_ssl( struct lh_ctx_t *ctx ) {

#if !defined(NO_SSL_DL)
	if ( ! cryptolib_dll_handle ) {

		cryptolib_dll_handle = XX_httplib_load_dll( ctx, CRYPTO_LIB, XX_httplib_crypto_sw );
		if ( ! cryptolib_dll_handle ) return 0;
	}
#endif /* NO_SSL_DL */

	return 1;

}  /* XX_httplib_initialize_ssl */

#endif /* !NO_SSL */
