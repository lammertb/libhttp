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



static void *ssllib_dll_handle;    /* Store the ssl library handle. */



/*
 * int XX_httplib_set_ssl_option( struct mg_context *ctx );
 *
 * The function XX_httplib_set_ssl_option() loads the SSL library in a dynamic
 * way.
 */

#if !defined(NO_SSL)
int XX_httplib_set_ssl_option( struct mg_context *ctx ) {

	const char *pem;
	int callback_ret;
	int should_verify_peer;
	const char *ca_path;
	const char *ca_file;
	int use_default_verify_paths;
	int verify_depth;
	time_t now_rt = time(NULL);
	struct timespec now_mt;
	md5_byte_t ssl_context_id[16];
	md5_state_t md5state;
	int protocol_ver;

	/* If PEM file is not specified and the init_ssl callback
	 * is not specified, skip SSL initialization. */
	if ( ctx == NULL ) return 0;

	if ((pem = ctx->config[SSL_CERTIFICATE]) == NULL && ctx->callbacks.init_ssl == NULL) return 1;

	if (!XX_httplib_initialize_ssl(ctx)) return 0;

#if !defined(NO_SSL_DL)
	if (!ssllib_dll_handle) {
		ssllib_dll_handle = XX_httplib_load_dll(ctx, SSL_LIB, XX_httplib_ssl_sw);
		if (!ssllib_dll_handle) return 0;
	}
#endif /* NO_SSL_DL */

	/* Initialize SSL library */
	SSL_library_init();
	SSL_load_error_strings();

	if ((ctx->ssl_ctx = SSL_CTX_new(SSLv23_server_method())) == NULL) {
		mg_cry( XX_httplib_fc(ctx), "SSL_CTX_new (server) error: %s", XX_httplib_ssl_error());
		return 0;
	}

	SSL_CTX_clear_options(ctx->ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
	protocol_ver = atoi(ctx->config[SSL_PROTOCOL_VERSION]);
	SSL_CTX_set_options(ctx->ssl_ctx, XX_httplib_ssl_get_protocol(protocol_ver));
	SSL_CTX_set_options(ctx->ssl_ctx, SSL_OP_SINGLE_DH_USE);
	SSL_CTX_set_options(ctx->ssl_ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
	SSL_CTX_set_ecdh_auto(ctx->ssl_ctx, 1);

	/* If a callback has been specified, call it. */
	callback_ret = (ctx->callbacks.init_ssl == NULL) ? 0 : (ctx->callbacks.init_ssl(ctx->ssl_ctx, ctx->user_data));

	/* If callback returns 0, LibHTTP sets up the SSL certificate.
	 * If it returns 1, LibHTTP assumes the calback already did this.
	 * If it returns -1, initializing ssl fails. */
	if (callback_ret < 0) {
		mg_cry( XX_httplib_fc(ctx), "SSL callback returned error: %i", callback_ret);
		return 0;
	}
	if (callback_ret > 0) {
		if (pem != NULL) {
			SSL_CTX_use_certificate_chain_file(ctx->ssl_ctx, pem);
		}
		return 1;
	}

	/* Use some UID as session context ID. */
	md5_init(&md5state);
	md5_append(&md5state, (const md5_byte_t *)&now_rt, sizeof(now_rt));
	clock_gettime(CLOCK_MONOTONIC, &now_mt);
	md5_append(&md5state, (const md5_byte_t *)&now_mt, sizeof(now_mt));
	md5_append(&md5state,
	           (const md5_byte_t *)ctx->config[LISTENING_PORTS],
	           strlen(ctx->config[LISTENING_PORTS]));
	md5_append(&md5state, (const md5_byte_t *)ctx, sizeof(*ctx));
	md5_finish(&md5state, ssl_context_id);

	SSL_CTX_set_session_id_context(ctx->ssl_ctx, (const unsigned char *)&ssl_context_id, sizeof(ssl_context_id));

	if (pem != NULL) {
		if (!XX_httplib_ssl_use_pem_file(ctx, pem)) return 0;
	}

	should_verify_peer =
	    (ctx->config[SSL_DO_VERIFY_PEER] != NULL)
	    && (mg_strcasecmp(ctx->config[SSL_DO_VERIFY_PEER], "yes") == 0);

	use_default_verify_paths =
	    (ctx->config[SSL_DEFAULT_VERIFY_PATHS] != NULL)
	    && (mg_strcasecmp(ctx->config[SSL_DEFAULT_VERIFY_PATHS], "yes") == 0);

	if (should_verify_peer) {
		ca_path = ctx->config[SSL_CA_PATH];
		ca_file = ctx->config[SSL_CA_FILE];
		if (SSL_CTX_load_verify_locations(ctx->ssl_ctx, ca_file, ca_path)
		    != 1) {
			mg_cry( XX_httplib_fc(ctx),
			       "SSL_CTX_load_verify_locations error: %s "
			       "ssl_verify_peer requires setting "
			       "either ssl_ca_path or ssl_ca_file. Is any of them "
			       "present in "
			       "the .conf file?",
			       XX_httplib_ssl_error());
			return 0;
		}

		SSL_CTX_set_verify(ctx->ssl_ctx,
		                   SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
		                   NULL);

		if (use_default_verify_paths
		    && SSL_CTX_set_default_verify_paths(ctx->ssl_ctx) != 1) {
			mg_cry( XX_httplib_fc(ctx), "SSL_CTX_set_default_verify_paths error: %s", XX_httplib_ssl_error());
			return 0;
		}

		if (ctx->config[SSL_VERIFY_DEPTH]) {
			verify_depth = atoi(ctx->config[SSL_VERIFY_DEPTH]);
			SSL_CTX_set_verify_depth(ctx->ssl_ctx, verify_depth);
		}
	}

	if (ctx->config[SSL_CIPHER_LIST] != NULL) {
		if (SSL_CTX_set_cipher_list(ctx->ssl_ctx, ctx->config[SSL_CIPHER_LIST]) != 1) {
			mg_cry( XX_httplib_fc(ctx), "SSL_CTX_set_cipher_list error: %s", XX_httplib_ssl_error());
		}
	}

	return 1;

}  /* XX_httplib_set_ssl_option */

#endif /* !NO_SSL */
