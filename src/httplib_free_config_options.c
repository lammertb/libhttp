/* 
 * Copyright (c) 2016 Lammert Bies
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
 * void XX_httplib_free_config_options( struct lh_ctx_t *ctx );
 *
 * The function XX_httplib_free_config_options() returns all the from the heap
 * allocated space to store config options back to the heap.
 */

void XX_httplib_free_config_options( struct lh_ctx_t *ctx ) {

	if ( ctx == NULL ) return;

	ctx->access_control_allow_origin = httplib_free( ctx->access_control_allow_origin );
	ctx->access_control_list         = httplib_free( ctx->access_control_list         );
	ctx->access_log_file             = httplib_free( ctx->access_log_file             );
	ctx->authentication_domain       = httplib_free( ctx->authentication_domain       );
	ctx->cgi_environment             = httplib_free( ctx->cgi_environment             );
	ctx->cgi_interpreter             = httplib_free( ctx->cgi_interpreter             );
	ctx->cgi_pattern                 = httplib_free( ctx->cgi_pattern                 );
	ctx->document_root               = httplib_free( ctx->document_root               );
	ctx->error_log_file              = httplib_free( ctx->error_log_file              );
	ctx->error_pages                 = httplib_free( ctx->error_pages                 );
	ctx->extra_mime_types            = httplib_free( ctx->extra_mime_types            );
	ctx->global_auth_file            = httplib_free( ctx->global_auth_file            );
	ctx->hide_file_pattern           = httplib_free( ctx->hide_file_pattern           );
	ctx->index_files                 = httplib_free( ctx->index_files                 );
	ctx->listening_ports             = httplib_free( ctx->listening_ports             );
	ctx->protect_uri                 = httplib_free( ctx->protect_uri                 );
	ctx->put_delete_auth_file        = httplib_free( ctx->put_delete_auth_file        );
	ctx->run_as_user                 = httplib_free( ctx->run_as_user                 );
	ctx->ssi_pattern                 = httplib_free( ctx->ssi_pattern                 );
	ctx->ssl_ca_file                 = httplib_free( ctx->ssl_ca_file                 );
	ctx->ssl_ca_path                 = httplib_free( ctx->ssl_ca_path                 );
	ctx->ssl_certificate             = httplib_free( ctx->ssl_certificate             );
	ctx->ssl_cipher_list             = httplib_free( ctx->ssl_cipher_list             );
	ctx->throttle                    = httplib_free( ctx->throttle                    );
	ctx->url_rewrite_patterns        = httplib_free( ctx->url_rewrite_patterns        );
	ctx->websocket_root              = httplib_free( ctx->websocket_root              );

}  /* XX_httplib_free_config_options */
