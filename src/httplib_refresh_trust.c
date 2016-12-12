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



/*
 * int XX_httplib_refresh_trust( struct mg_connection *conn );
 *
 * The function XX_httplib_refresh_trust() is used to reload a certificate if
 * it only has a short trust span.
 */

#if !defined(NO_SSL)

int XX_httplib_refresh_trust( struct mg_connection *conn ) {

	static int reload_lock = 0;
	static long int data_check = 0;
	volatile int *p_reload_lock = (volatile int *)&reload_lock;

	struct stat cert_buf;
	long int t;
	char *pem;
	int should_verify_peer;

	if ((pem = conn->ctx->config[SSL_CERTIFICATE]) == NULL
	    && conn->ctx->callbacks.init_ssl == NULL) {
		return 0;
	}

	t = data_check;
	if (stat(pem, &cert_buf) != -1) t = (long int)cert_buf.st_mtime;

	if (data_check != t) {
		data_check = t;

		should_verify_peer =
		    (conn->ctx->config[SSL_DO_VERIFY_PEER] != NULL)
		    && (mg_strcasecmp(conn->ctx->config[SSL_DO_VERIFY_PEER], "yes")
		        == 0);

		if (should_verify_peer) {
			char *ca_path = conn->ctx->config[SSL_CA_PATH];
			char *ca_file = conn->ctx->config[SSL_CA_FILE];
			if (SSL_CTX_load_verify_locations(conn->ctx->ssl_ctx, ca_file, ca_path) != 1) {

				mg_cry( XX_httplib_fc(conn->ctx),
				       "SSL_CTX_load_verify_locations error: %s "
				       "ssl_verify_peer requires setting "
				       "either ssl_ca_path or ssl_ca_file. Is any of them "
				       "present in "
				       "the .conf file?",
				       XX_httplib_ssl_error());
				return 0;
			}
		}

		if (1 == XX_httplib_atomic_inc(p_reload_lock)) {
			if (XX_httplib_ssl_use_pem_file(conn->ctx, pem) == 0) return 0;
			*p_reload_lock = 0;
		}
	}
	/* lock while cert is reloading */
	while (*p_reload_lock) sleep(1);

	return 1;

}  /* XX_httplib_refresh_trust */

#endif /* !NO_SSL */
