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
 * bool XX_httplib_init_options( struct lh_ctx_t *ctx );
 *
 * The function XX_httplib_init_options() sets the options of a newly created
 * context to reasonablei default values. When succesful, the function returns
 * false. Otherwise true is returned, and the function already performed a
 * cleanup.
 */

bool XX_httplib_init_options( struct lh_ctx_t *ctx ) {

	if ( ctx == NULL ) return true;

	ctx->access_control_allow_origin = NULL;
	ctx->access_control_list         = NULL;
	ctx->access_log_file             = NULL;
	ctx->allow_sendfile_call         = true;
	ctx->authentication_domain       = NULL;
	ctx->cgi_environment             = NULL;
	ctx->cgi_interpreter             = NULL;
	ctx->cgi_pattern                 = NULL;
	ctx->debug_level                 = LH_DEBUG_WARNING;
	ctx->decode_url                  = true;
	ctx->document_root               = NULL;
	ctx->enable_directory_listing    = true;
	ctx->enable_keep_alive           = false;
	ctx->error_log_file              = NULL;
	ctx->error_pages                 = NULL;
	ctx->extra_mime_types            = NULL;
	ctx->global_auth_file            = NULL;
	ctx->hide_file_pattern           = NULL;
	ctx->index_files                 = NULL;
	ctx->listening_ports             = NULL;
	ctx->num_threads                 = 50;
	ctx->protect_uri                 = NULL;
	ctx->put_delete_auth_file        = NULL;
	ctx->request_timeout             = 30000;
	ctx->run_as_user                 = NULL;
	ctx->ssi_include_depth           = 10;
	ctx->ssi_pattern                 = NULL;
	ctx->ssl_ca_file                 = NULL;
	ctx->ssl_ca_path                 = NULL;
	ctx->ssl_certificate             = NULL;
	ctx->ssl_cipher_list             = NULL;
	ctx->ssl_protocol_version        = 0;
	ctx->ssl_short_trust             = false;
	ctx->ssl_verify_depth            = 9;
	ctx->ssl_verify_paths            = true;
	ctx->ssl_verify_peer             = false;
	ctx->static_file_max_age         = 0;
	ctx->throttle                    = NULL;
	ctx->tcp_nodelay                 = false;
	ctx->url_rewrite_patterns        = NULL;
	ctx->websocket_root              = NULL;
	ctx->websocket_timeout           = 30000;

	if ( (ctx->access_control_allow_origin = httplib_strdup( "*" )) == NULL ) {

		XX_httplib_abort_start( ctx, "Out of memory creating context allocating \"access_control_allow_origin\"" );
		return true;
	}

	if ( (ctx->authentication_domain = httplib_strdup( "example.com" )) == NULL ) {

		XX_httplib_abort_start( ctx, "Out of memory creating context allocating \"authentication_domain\"" );
		return true;
	}

	if ( (ctx->cgi_pattern = httplib_strdup( "**.cgi$|**.pl$|**.php$" )) == NULL ) {

		XX_httplib_abort_start( ctx, "Out of memory creating context allocating \"cgi_pattern\"" );
		return true;
	}

	if ( (ctx->index_files = httplib_strdup( "index.xhtml,index.html,index.htm,index.cgi,index.shtml,index.php" )) == NULL ) {

		XX_httplib_abort_start( ctx, "Out of memory creating context allocating \"index_files\"" );
		return true;
	}

	if ( (ctx->listening_ports = httplib_strdup( "8080" )) == NULL ) {

		XX_httplib_abort_start( ctx, "Out of memory creating context allocating \"listening_ports\"" );
		return true;
	}

	if ( (ctx->ssi_pattern = httplib_strdup( "**.shtml$|**.shtm$" )) == NULL ) {

		XX_httplib_abort_start( ctx, "Out of memory creating context allocating \"ssi_pattern\"" );
		return true;
	}

	return false;

}  /* XX_httplib_init_options */
