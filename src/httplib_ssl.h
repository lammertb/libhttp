/* 
 * Copyright (C) 2016 Lammert Bies
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



#if !defined(NO_SSL)

#if !defined(NO_SSL_DL)

/* SSL loaded dynamically from DLL.
 * I put the prototypes here to be independent from OpenSSL source
 * installation. */

#define SSL_CTRL_OPTIONS (32)
#define SSL_CTRL_CLEAR_OPTIONS (77)
#define SSL_CTRL_SET_ECDH_AUTO (94)

#define SSL_VERIFY_NONE (0)
#define SSL_VERIFY_PEER (1)
#define SSL_VERIFY_FAIL_IF_NO_PEER_CERT (2)
#define SSL_VERIFY_CLIENT_ONCE (4)
#define SSL_OP_ALL ((long)(0x80000BFFUL))
#define SSL_OP_NO_SSLv2 (0x01000000L)
#define SSL_OP_NO_SSLv3 (0x02000000L)
#define SSL_OP_NO_TLSv1 (0x04000000L)
#define SSL_OP_NO_TLSv1_2 (0x08000000L)
#define SSL_OP_NO_TLSv1_1 (0x10000000L)
#define SSL_OP_SINGLE_DH_USE (0x00100000L)
#define SSL_OP_CIPHER_SERVER_PREFERENCE (0x00400000L)
#define SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION (0x00010000L)

#define SSL_ERROR_NONE (0)
#define SSL_ERROR_SSL (1)
#define SSL_ERROR_WANT_READ (2)
#define SSL_ERROR_WANT_WRITE (3)
#define SSL_ERROR_WANT_X509_LOOKUP (4)
#define SSL_ERROR_SYSCALL (5) /* see errno */
#define SSL_ERROR_ZERO_RETURN (6)
#define SSL_ERROR_WANT_CONNECT (7)
#define SSL_ERROR_WANT_ACCEPT (8)


struct ssl_func {
	const char *name;  /* SSL function name */
	void (*ptr)(void); /* Function pointer */
};

#define SSL_free				(*(void (*)(SSL *))XX_httplib_ssl_sw[0].ptr)
#define SSL_accept				(*(int (*)(SSL *))XX_httplib_ssl_sw[1].ptr)
#define SSL_connect				(*(int (*)(SSL *))XX_httplib_ssl_sw[2].ptr)
#define SSL_read				(*(int (*)(SSL *, void *, int))XX_httplib_ssl_sw[3].ptr)
#define SSL_write				(*(int (*)(SSL *, const void *, int))XX_httplib_ssl_sw[4].ptr)
#define SSL_get_error				(*(int (*)(SSL *, int))XX_httplib_ssl_sw[5].ptr)
#define SSL_set_fd				(*(int (*)(SSL *, SOCKET))XX_httplib_ssl_sw[6].ptr)
#define SSL_new					(*(SSL * (*)(SSL_CTX *))XX_httplib_ssl_sw[7].ptr)
#define SSL_CTX_new				(*(SSL_CTX * (*)(SSL_METHOD *))XX_httplib_ssl_sw[8].ptr)
#define SSLv23_server_method			(*(SSL_METHOD * (*)(void))XX_httplib_ssl_sw[9].ptr)
#define SSL_library_init			(*(int (*)(void))XX_httplib_ssl_sw[10].ptr)
#define SSL_CTX_use_PrivateKey_file		(*(int (*)(SSL_CTX *, const char *, int))XX_httplib_ssl_sw[11].ptr)
#define SSL_CTX_use_certificate_file		(*(int (*)(SSL_CTX *, const char *, int))XX_httplib_ssl_sw[12].ptr)
#define SSL_CTX_set_default_passwd_cb		(*(void (*)(SSL_CTX *, httplib_callback_t))XX_httplib_ssl_sw[13].ptr)
#define SSL_CTX_free				(*(void (*)(SSL_CTX *))XX_httplib_ssl_sw[14].ptr)
#define SSL_load_error_strings			(*(void (*)(void))XX_httplib_ssl_sw[15].ptr)
#define SSL_CTX_use_certificate_chain_file	(*(int (*)(SSL_CTX *, const char *))XX_httplib_ssl_sw[16].ptr)
#define SSLv23_client_method			(*(SSL_METHOD * (*)(void))XX_httplib_ssl_sw[17].ptr)
#define SSL_pending				(*(int (*)(SSL *))XX_httplib_ssl_sw[18].ptr)
#define SSL_CTX_set_verify			(*(void (*)(SSL_CTX *, int, int (*verify_callback)(int, X509_STORE_CTX *)))XX_httplib_ssl_sw[19].ptr)
#define SSL_shutdown				(*(int (*)(SSL *))XX_httplib_ssl_sw[20].ptr)
#define SSL_CTX_load_verify_locations		(*(int (*)(SSL_CTX *, const char *, const char *))XX_httplib_ssl_sw[21].ptr)
#define SSL_CTX_set_default_verify_paths	(*(int (*)(SSL_CTX *))XX_httplib_ssl_sw[22].ptr)
#define SSL_CTX_set_verify_depth		(*(void (*)(SSL_CTX *, int))XX_httplib_ssl_sw[23].ptr)
#define SSL_get_peer_certificate		(*(X509 * (*)(SSL *))XX_httplib_ssl_sw[24].ptr)
#define SSL_get_version				(*(const char *(*)(SSL *))XX_httplib_ssl_sw[25].ptr)
#define SSL_get_current_cipher			(*(SSL_CIPHER * (*)(SSL *))XX_httplib_ssl_sw[26].ptr)
#define SSL_CIPHER_get_name			(*(const char *(*)(const SSL_CIPHER *))XX_httplib_ssl_sw[27].ptr)
#define SSL_CTX_check_private_key		(*(int (*)(SSL_CTX *))XX_httplib_ssl_sw[28].ptr)
#define SSL_CTX_set_session_id_context		(*(int (*)(SSL_CTX *, const unsigned char *, unsigned int))XX_httplib_ssl_sw[29].ptr)
#define SSL_CTX_ctrl				(*(long (*)(SSL_CTX *, int, long, void *))XX_httplib_ssl_sw[30].ptr)
#define SSL_CTX_set_cipher_list			(*(int (*)(SSL_CTX *, const char *))XX_httplib_ssl_sw[31].ptr)
#define SSL_CTX_set_options(ctx, op)		SSL_CTX_ctrl((ctx), SSL_CTRL_OPTIONS, (op), NULL)
#define SSL_CTX_clear_options(ctx, op)		SSL_CTX_ctrl((ctx), SSL_CTRL_CLEAR_OPTIONS, (op), NULL)
#define SSL_CTX_set_ecdh_auto(ctx, onoff)	SSL_CTX_ctrl(ctx, SSL_CTRL_SET_ECDH_AUTO, onoff, NULL)

#define X509_get_notBefore(x)			((x)->cert_info->validity->notBefore)
#define X509_get_notAfter(x)			((x)->cert_info->validity->notAfter)


#define CRYPTO_num_locks			(*(int (*)(void))XX_httplib_crypto_sw[0].ptr)
#define CRYPTO_set_locking_callback		(*(void (*)(void (*)(int, int, const char *, int)))XX_httplib_crypto_sw[1].ptr)
#define CRYPTO_set_id_callback			(*(void (*)(unsigned long (*)(void)))XX_httplib_crypto_sw[2].ptr)
#define ERR_get_error				(*(unsigned long (*)(void))XX_httplib_crypto_sw[3].ptr)
#define ERR_error_string			(*(char *(*)(unsigned long, char *))XX_httplib_crypto_sw[4].ptr)
#define ERR_remove_state			(*(void (*)(unsigned long))XX_httplib_crypto_sw[5].ptr)
#define ERR_free_strings			(*(void (*)(void))XX_httplib_crypto_sw[6].ptr)
#define ENGINE_cleanup				(*(void (*)(void))XX_httplib_crypto_sw[7].ptr)
#define CONF_modules_unload			(*(void (*)(int))XX_httplib_crypto_sw[8].ptr)
#define CRYPTO_cleanup_all_ex_data		(*(void (*)(void))XX_httplib_crypto_sw[9].ptr)
#define EVP_cleanup				(*(void (*)(void))XX_httplib_crypto_sw[10].ptr)
#define X509_free				(*(void (*)(X509 *))XX_httplib_crypto_sw[11].ptr)
#define X509_get_subject_name			(*(X509_NAMEX * (*)(X509 *))XX_httplib_crypto_sw[12].ptr)
#define X509_get_issuer_name			(*(X509_NAMEX * (*)(X509 *))XX_httplib_crypto_sw[13].ptr)
#define X509_NAME_oneline			(*(char *(*)(X509_NAMEX *, char *, int))XX_httplib_crypto_sw[14].ptr)
#define X509_get_serialNumber			(*(ASN1_INTEGER * (*)(X509 *))XX_httplib_crypto_sw[15].ptr)
#define i2c_ASN1_INTEGER			(*(int (*)(ASN1_INTEGER *, unsigned char **))XX_httplib_crypto_sw[16].ptr)
#define EVP_get_digestbyname			(*(const EVP_MD *(*)(const char *))XX_httplib_crypto_sw[17].ptr)
#define ASN1_digest				(*(int (*)(int (*)(void *,unsigned char **), const EVP_MD *, char *, unsigned char *, unsigned int *))XX_httplib_crypto_sw[18].ptr)
#define i2d_X509				(*(int (*)(X509 *, unsigned char **))XX_httplib_crypto_sw[19].ptr)

#endif  /* NO_SSL_DL */



int				XX_httplib_get_first_ssl_listener_index( const struct lh_ctx_t *ctx );
int				XX_httplib_initialize_ssl( struct lh_ctx_t *ctx );
bool				XX_httplib_set_ssl_option( struct lh_ctx_t *ctx );
const char *			XX_httplib_ssl_error( void );
void				XX_httplib_ssl_get_client_cert_info( struct lh_con_t *conn );
long				XX_httplib_ssl_get_protocol( int version_id );
unsigned long			XX_httplib_ssl_id_callback( void );
void				XX_httplib_ssl_locking_callback( int mode, int mutex_num, const char *file, int line );
int				XX_httplib_ssl_use_pem_file( struct lh_ctx_t *ctx, const char *pem );
int				XX_httplib_sslize( struct lh_ctx_t *ctx, struct lh_con_t *conn, SSL_CTX *s, int (*func)(SSL *) );
void				XX_httplib_tls_dtor( void *key );
void				XX_httplib_uninitialize_ssl( struct lh_ctx_t *ctx );



extern int			XX_httplib_cryptolib_users;
extern struct ssl_func		XX_httplib_crypto_sw[];
extern struct ssl_func		XX_httplib_ssl_sw[];

#endif  /* NO_SSL */
