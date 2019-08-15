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

#if !defined(NO_SSL)  &&  !defined(NO_SSL_DL)

#include "httplib_main.h"
#include "httplib_ssl.h"

/*
 * struct ssl_func XX_httplib_ssl_sw[];
 *
 * XX_httplib_set_ssl_option() function updates this array.
 * It loads SSL library dynamically and changes NULLs to the actual addresses
 * of respective functions. The macros above (like SSL_connect()) are really
 * just calling these functions indirectly via the pointer.
 */

struct ssl_func XX_httplib_ssl_sw[] = {
	{ "SSL_free",                           NULL },
	{ "SSL_accept",                         NULL },
	{ "SSL_connect",                        NULL },
	{ "SSL_read",                           NULL },
	{ "SSL_write",                          NULL },
	{ "SSL_get_error",                      NULL },
	{ "SSL_set_fd",                         NULL },
	{ "SSL_new",                            NULL },
	{ "SSL_CTX_new",                        NULL },
	{ "SSLv23_server_method",               NULL },
	{ "SSL_library_init",                   NULL },
	{ "SSL_CTX_use_PrivateKey_file",        NULL },
	{ "SSL_CTX_use_certificate_file",       NULL },
	{ "SSL_CTX_set_default_passwd_cb",      NULL },
	{ "SSL_CTX_free",                       NULL },
	{ "SSL_load_error_strings",             NULL },
	{ "SSL_CTX_use_certificate_chain_file", NULL },
	{ "SSLv23_client_method",               NULL },
	{ "SSL_pending",                        NULL },
	{ "SSL_CTX_set_verify",                 NULL },
	{ "SSL_shutdown",                       NULL },
	{ "SSL_CTX_load_verify_locations",      NULL },
	{ "SSL_CTX_set_default_verify_paths",   NULL },
	{ "SSL_CTX_set_verify_depth",           NULL },
	{ "SSL_get_peer_certificate",           NULL },
	{ "SSL_get_version",                    NULL },
	{ "SSL_get_current_cipher",             NULL },
	{ "SSL_CIPHER_get_name",                NULL },
	{ "SSL_CTX_check_private_key",          NULL },
	{ "SSL_CTX_set_session_id_context",     NULL },
	{ "SSL_CTX_ctrl",                       NULL },
	{ "SSL_CTX_set_cipher_list",            NULL },
	{ NULL,                                 NULL }
};


/*
 * struct ssl_func XX_httplib_crypto_sw[];
 *
 * Similar array as XX_httplib_ssl_sw. These functions could be located in different
 * lib.
 */

struct ssl_func XX_httplib_crypto_sw[] = {
	{ "CRYPTO_num_locks",            NULL },
	{ "CRYPTO_set_locking_callback", NULL },
	{ "CRYPTO_set_id_callback",      NULL },
       	{ "ERR_get_error",               NULL },
	{ "ERR_error_string",            NULL },
	{ "ERR_remove_state",            NULL },
	{ "ERR_free_strings",            NULL },
	{ "ENGINE_cleanup",              NULL },
	{ "CONF_modules_unload",         NULL },
	{ "CRYPTO_cleanup_all_ex_data",  NULL },
	{ "EVP_cleanup",                 NULL },
	{ "X509_free",                   NULL },
	{ "X509_get_subject_name",       NULL },
	{ "X509_get_issuer_name",        NULL },
	{ "X509_NAME_oneline",           NULL },
	{ "X509_get_serialNumber",       NULL },
	{ "i2c_ASN1_INTEGER",            NULL },
	{ "EVP_get_digestbyname",        NULL },
	{ "ASN1_digest",                 NULL },
	{ "i2d_X509",                    NULL },
	{ NULL,                          NULL }
};

#endif /* !defined(NO_SSL)  &&  !defined(NO_SSL_DL) */
