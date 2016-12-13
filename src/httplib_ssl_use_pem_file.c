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
 */

#include "httplib_main.h"
#include "httplib_ssl.h"

/*
 * int XX_httplib_ssl_use_pem_file( struct mg_context *ctx, const char *pem );
 *
 * The function XX_httplib_ssl_use_pem_file() tries to use a certificate which
 * is passed as a parameter with the filename of the certificate.
 */

#if ! defined(NO_SSL)

int XX_httplib_ssl_use_pem_file( struct mg_context *ctx, const char *pem ) {

	if (SSL_CTX_use_certificate_file(ctx->ssl_ctx, pem, 1) == 0) {
		mg_cry( XX_httplib_fc(ctx), "%s: cannot open certificate file %s: %s", __func__, pem, XX_httplib_ssl_error());
		return 0;
	}

	/* could use SSL_CTX_set_default_passwd_cb_userdata */
	if (SSL_CTX_use_PrivateKey_file(ctx->ssl_ctx, pem, 1) == 0) {
		mg_cry( XX_httplib_fc(ctx), "%s: cannot open private key file %s: %s", __func__, pem, XX_httplib_ssl_error());
		return 0;
	}

	if (SSL_CTX_check_private_key(ctx->ssl_ctx) == 0) {
		mg_cry( XX_httplib_fc(ctx), "%s: certificate and private key do not match: %s", __func__, pem);
		return 0;
	}

	if (SSL_CTX_use_certificate_chain_file(ctx->ssl_ctx, pem) == 0) {
		mg_cry( XX_httplib_fc(ctx), "%s: cannot use certificate chain file %s: %s", __func__, pem, XX_httplib_ssl_error());
		return 0;
	}
	return 1;

}  /* XX_httplib_ssl_use_pem_file */

#endif /* !NO_SSL */
