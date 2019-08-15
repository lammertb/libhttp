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

static void *ssllib_dll_handle;    /* Store the ssl library handle. */

/*
 * bool XX_httplib_set_ssl_option( struct lh_ctx_t *ctx );
 *
 * The function XX_httplib_set_ssl_option() loads the SSL library in a dynamic
 * way. The function returns false if an error occured, otherwise true.
 */

bool XX_httplib_set_ssl_option( struct lh_ctx_t *ctx ) {

	const char *pem;
	int callback_ret;
	time_t now_rt;
	struct timespec now_mt;
	md5_byte_t ssl_context_id[16];
	md5_state_t md5state;

	/*
	 * If PEM file is not specified and the init_ssl callback
	 * is not specified, skip SSL initialization.
	 */

	if ( ctx == NULL ) return false;

	now_rt = time( NULL );
	pem    = ctx->ssl_certificate;

	if ( pem == NULL  &&  ctx->callbacks.init_ssl == NULL ) return true;

	if ( ! XX_httplib_initialize_ssl( ctx ) ) return false;

#if !defined(NO_SSL_DL)

	if ( ssllib_dll_handle == NULL ) {

		ssllib_dll_handle = XX_httplib_load_dll( ctx, SSL_LIB, XX_httplib_ssl_sw );
		if ( ssllib_dll_handle == NULL ) return false;
	}

#endif /* NO_SSL_DL */

	SSL_library_init();
	SSL_load_error_strings();

	ctx->ssl_ctx = SSL_CTX_new( SSLv23_server_method() );
	if ( ctx->ssl_ctx == NULL ) {

		httplib_cry( LH_DEBUG_CRASH, ctx, NULL, "%s: SSL_CTX_new (server) error: %s", __func__, XX_httplib_ssl_error() );
		return false;
	}

	SSL_CTX_clear_options( ctx->ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 );

	SSL_CTX_set_options(   ctx->ssl_ctx, XX_httplib_ssl_get_protocol( ctx->ssl_protocol_version ) );
	SSL_CTX_set_options(   ctx->ssl_ctx, SSL_OP_SINGLE_DH_USE                                     );
	SSL_CTX_set_options(   ctx->ssl_ctx, SSL_OP_CIPHER_SERVER_PREFERENCE                          );
	SSL_CTX_set_ecdh_auto( ctx->ssl_ctx, 1                                                        );

	/* If a callback has been specified, call it. */

	if ( ctx->callbacks.init_ssl == NULL ) callback_ret = 0;
	else                                   callback_ret = ctx->callbacks.init_ssl( ctx, ctx->ssl_ctx, ctx->user_data );

	/*
	 * If callback returns 0, LibHTTP sets up the SSL certificate.
	 * If it returns 1, LibHTTP assumes the calback already did this.
	 * If it returns -1, initializing ssl fails.
	 */

	if ( callback_ret < 0 ) {

		httplib_cry( LH_DEBUG_CRASH, ctx, NULL, "%s: SSL callback returned error: %i", __func__, callback_ret );
		return false;
	}

	if ( callback_ret > 0 ) {

		if ( pem != NULL ) SSL_CTX_use_certificate_chain_file( ctx->ssl_ctx, pem );
		return true;
	}

	/* Use some UID as session context ID. */
	md5_init(   & md5state );
	md5_append( & md5state, (const md5_byte_t *)&now_rt, sizeof(now_rt) );
	clock_gettime( CLOCK_MONOTONIC, &now_mt );
	md5_append( & md5state, (const md5_byte_t *)&now_mt, sizeof(now_mt) );

	if ( ctx->listening_ports != NULL ) md5_append( & md5state, (const md5_byte_t *)ctx->listening_ports, strlen( ctx->listening_ports ) );

	md5_append( & md5state, (const md5_byte_t *)ctx, sizeof(*ctx) );
	md5_finish( & md5state, ssl_context_id );

	SSL_CTX_set_session_id_context( ctx->ssl_ctx, (const unsigned char *)&ssl_context_id, sizeof(ssl_context_id) );

	if ( pem != NULL  &&  ! XX_httplib_ssl_use_pem_file( ctx, pem ) ) return false;

	if ( ctx->ssl_verify_peer ) {

		if ( SSL_CTX_load_verify_locations( ctx->ssl_ctx, ctx->ssl_ca_file, ctx->ssl_ca_path ) != 1 ) {

			httplib_cry( LH_DEBUG_CRASH, ctx, NULL, "%s: SSL_CTX_load_verify_locations error: %s ssl_verify_peer requires setting either ssl_ca_path or ssl_ca_file. Is any of them present in the .conf file?", __func__, XX_httplib_ssl_error() );

			return false;
		}

		SSL_CTX_set_verify( ctx->ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL );

		if ( ctx->ssl_verify_paths  &&  SSL_CTX_set_default_verify_paths( ctx->ssl_ctx ) != 1 ) {

			httplib_cry( LH_DEBUG_CRASH, ctx, NULL, "%s: SSL_CTX_set_default_verify_paths error: %s", __func__, XX_httplib_ssl_error());
			return false;
		}

		SSL_CTX_set_verify_depth( ctx->ssl_ctx, ctx->ssl_verify_depth );
	}

	if ( ctx->ssl_cipher_list != NULL ) {

		if ( SSL_CTX_set_cipher_list( ctx->ssl_ctx, ctx->ssl_cipher_list ) != 1 ) {

			httplib_cry( LH_DEBUG_WARNING, ctx, NULL, "%s: SSL_CTX_set_cipher_list error: %s", __func__, XX_httplib_ssl_error() );
		}
	}

	return true;

}  /* XX_httplib_set_ssl_option */

#endif /* !NO_SSL */
