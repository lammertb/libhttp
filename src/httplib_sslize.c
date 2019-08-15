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
 * int XX_httplib_sslize( lh_con_t *conn, SSL_CTX *s, int (*func)(SSL *) );
 *
 * The fucntion XX_httplib_sslize() initiates SSL on a connection.
 */

int XX_httplib_sslize( struct lh_ctx_t *ctx, struct lh_con_t *conn, SSL_CTX *s, int (*func)(SSL *) ) {

	int ret;
	int err;
	unsigned i;

	if ( ctx == NULL  ||  conn == NULL ) return 0;

	if ( ctx->ssl_short_trust ) {

		int trust_ret = XX_httplib_refresh_trust( ctx, conn );
		if ( ! trust_ret ) return trust_ret;
	}

	conn->ssl = SSL_new( s );
	if ( conn->ssl == NULL ) return 0;

	ret = SSL_set_fd( conn->ssl, conn->client.sock );

	if ( ret != 1 ) {

		err = SSL_get_error( conn->ssl, ret );
		(void)err; /* TODO: set some error message */
		SSL_free( conn->ssl );
		conn->ssl = NULL;

		/*
		 * Avoid CRYPTO_cleanup_all_ex_data(); See discussion:
		 * https://wiki.openssl.org/index.php/Talk:Library_Initialization
		 */

		ERR_remove_state( 0 );
		return 0;
	}

	/*
	 * SSL functions may fail and require to be called again:
	 * see https://www.openssl.org/docs/manmaster/ssl/SSL_get_error.html
	 * Here "func" could be SSL_connect or SSL_accept.
	 */

	for (i = 0; i <= 16; i *= 2) {
		ret = func(conn->ssl);
		if (ret != 1) {
			err = SSL_get_error(conn->ssl, ret);
			if ((err == SSL_ERROR_WANT_CONNECT)
			    || (err == SSL_ERROR_WANT_ACCEPT)) {
				/* Retry */
				httplib_sleep(i);

			} else break; /* This is an error. TODO: set some error message */

		}
		else break;  /* Success */
	}

	if ( ret != 1 ) {

		SSL_free( conn->ssl );
		conn->ssl = NULL;
		/*
		 * Avoid CRYPTO_cleanup_all_ex_data(); See discussion:
		 * https://wiki.openssl.org/index.php/Talk:Library_Initialization
		 */

		ERR_remove_state( 0 );

		return 0;
	}

	return 1;

}  /* XX_httplib_sslize */

#endif /* !NO_SSL */
