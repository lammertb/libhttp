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

static const char *	store_bool( char *buffer, size_t buflen, bool value        );
static const char *	store_int(  char *buffer, size_t buflen, int value         );
static const char *	store_str(  char *buffer, size_t buflen, const char *value );

/*
 * const char *httplib_get_option( const struct lh_ctx_t *ctx, const char *name, char *buffer, size_t buflen );
 *
 * The function httplib_get_option() returns the content of an option for a
 * given context. If an error occurs, NULL is returned. If the option is valid
 * but there is no context associated with it, the return value is an empty
 * string.
 */

const char *httplib_get_option( const struct lh_ctx_t *ctx, const char *name, char *buffer, size_t buflen ) {

	if ( name == NULL  ||  buffer == NULL  ||  buflen < 1 ) return NULL;

	buffer[0] = '\0';

	if ( ! httplib_strcasecmp( name, "access_control_allow_origin" ) ) return (ctx == NULL) ? buffer : store_str(  buffer, buflen, ctx->access_control_allow_origin );
	if ( ! httplib_strcasecmp( name, "access_control_list"         ) ) return (ctx == NULL) ? buffer : store_str(  buffer, buflen, ctx->access_control_list         );
	if ( ! httplib_strcasecmp( name, "access_log_file"             ) ) return (ctx == NULL) ? buffer : store_str(  buffer, buflen, ctx->access_log_file             );
	if ( ! httplib_strcasecmp( name, "allow_sendfile_call"         ) ) return (ctx == NULL) ? buffer : store_bool( buffer, buflen, ctx->allow_sendfile_call         );
	if ( ! httplib_strcasecmp( name, "authentication_domain"       ) ) return (ctx == NULL) ? buffer : store_str(  buffer, buflen, ctx->authentication_domain       );
	if ( ! httplib_strcasecmp( name, "cgi_environment"             ) ) return (ctx == NULL) ? buffer : store_str(  buffer, buflen, ctx->cgi_environment             );
	if ( ! httplib_strcasecmp( name, "cgi_interpreter"             ) ) return (ctx == NULL) ? buffer : store_str(  buffer, buflen, ctx->cgi_interpreter             );
	if ( ! httplib_strcasecmp( name, "cgi_pattern"                 ) ) return (ctx == NULL) ? buffer : store_str(  buffer, buflen, ctx->cgi_pattern                 );
	if ( ! httplib_strcasecmp( name, "decode_url"                  ) ) return (ctx == NULL) ? buffer : store_bool( buffer, buflen, ctx->decode_url                  );
	if ( ! httplib_strcasecmp( name, "document_root"               ) ) return (ctx == NULL) ? buffer : store_str(  buffer, buflen, ctx->document_root               );
	if ( ! httplib_strcasecmp( name, "enable_directory_listing"    ) ) return (ctx == NULL) ? buffer : store_bool( buffer, buflen, ctx->enable_directory_listing    );
	if ( ! httplib_strcasecmp( name, "enable_keep_alive"           ) ) return (ctx == NULL) ? buffer : store_bool( buffer, buflen, ctx->enable_keep_alive           );
	if ( ! httplib_strcasecmp( name, "error_log_file"              ) ) return (ctx == NULL) ? buffer : store_str(  buffer, buflen, ctx->error_log_file              );
	if ( ! httplib_strcasecmp( name, "error_pages"                 ) ) return (ctx == NULL) ? buffer : store_str(  buffer, buflen, ctx->error_pages                 );
	if ( ! httplib_strcasecmp( name, "extra_mime_types"            ) ) return (ctx == NULL) ? buffer : store_str(  buffer, buflen, ctx->extra_mime_types            );
	if ( ! httplib_strcasecmp( name, "global_auth_file"            ) ) return (ctx == NULL) ? buffer : store_str(  buffer, buflen, ctx->global_auth_file            );
	if ( ! httplib_strcasecmp( name, "hide_file_pattern"           ) ) return (ctx == NULL) ? buffer : store_str(  buffer, buflen, ctx->hide_file_pattern           );
	if ( ! httplib_strcasecmp( name, "index_files"                 ) ) return (ctx == NULL) ? buffer : store_str(  buffer, buflen, ctx->index_files                 );
	if ( ! httplib_strcasecmp( name, "listening_ports"             ) ) return (ctx == NULL) ? buffer : store_str(  buffer, buflen, ctx->listening_ports             );
	if ( ! httplib_strcasecmp( name, "num_threads"                 ) ) return (ctx == NULL) ? buffer : store_int(  buffer, buflen, ctx->num_threads                 );
	if ( ! httplib_strcasecmp( name, "protect_uri"                 ) ) return (ctx == NULL) ? buffer : store_str(  buffer, buflen, ctx->protect_uri                 );
	if ( ! httplib_strcasecmp( name, "put_delete_auth_file"        ) ) return (ctx == NULL) ? buffer : store_str(  buffer, buflen, ctx->put_delete_auth_file        );
	if ( ! httplib_strcasecmp( name, "request_timeout"             ) ) return (ctx == NULL) ? buffer : store_int(  buffer, buflen, ctx->request_timeout             );
	if ( ! httplib_strcasecmp( name, "run_as_user"                 ) ) return (ctx == NULL) ? buffer : store_str(  buffer, buflen, ctx->run_as_user                 );
	if ( ! httplib_strcasecmp( name, "ssi_include_depth"           ) ) return (ctx == NULL) ? buffer : store_int(  buffer, buflen, ctx->ssi_include_depth           );
	if ( ! httplib_strcasecmp( name, "ssi_pattern"                 ) ) return (ctx == NULL) ? buffer : store_str(  buffer, buflen, ctx->ssi_pattern                 );
	if ( ! httplib_strcasecmp( name, "ssl_ca_file"                 ) ) return (ctx == NULL) ? buffer : store_str(  buffer, buflen, ctx->ssl_ca_file                 );
	if ( ! httplib_strcasecmp( name, "ssl_ca_path"                 ) ) return (ctx == NULL) ? buffer : store_str(  buffer, buflen, ctx->ssl_ca_path                 );
	if ( ! httplib_strcasecmp( name, "ssl_certificate"             ) ) return (ctx == NULL) ? buffer : store_str(  buffer, buflen, ctx->ssl_certificate             );
	if ( ! httplib_strcasecmp( name, "ssl_cipher_list"             ) ) return (ctx == NULL) ? buffer : store_str(  buffer, buflen, ctx->ssl_cipher_list             );
	if ( ! httplib_strcasecmp( name, "ssl_protocol_version"        ) ) return (ctx == NULL) ? buffer : store_int(  buffer, buflen, ctx->ssl_protocol_version        );
	if ( ! httplib_strcasecmp( name, "ssl_short_trust"             ) ) return (ctx == NULL) ? buffer : store_bool( buffer, buflen, ctx->ssl_short_trust             );
	if ( ! httplib_strcasecmp( name, "ssl_verify_depth"            ) ) return (ctx == NULL) ? buffer : store_int(  buffer, buflen, ctx->ssl_verify_depth            );
	if ( ! httplib_strcasecmp( name, "ssl_verify_paths"            ) ) return (ctx == NULL) ? buffer : store_bool( buffer, buflen, ctx->ssl_verify_paths            );
	if ( ! httplib_strcasecmp( name, "ssl_verify_peer"             ) ) return (ctx == NULL) ? buffer : store_bool( buffer, buflen, ctx->ssl_verify_peer             );
	if ( ! httplib_strcasecmp( name, "static_file_max_age"         ) ) return (ctx == NULL) ? buffer : store_int(  buffer, buflen, ctx->static_file_max_age         );
	if ( ! httplib_strcasecmp( name, "throttle"                    ) ) return (ctx == NULL) ? buffer : store_str(  buffer, buflen, ctx->throttle                    );
	if ( ! httplib_strcasecmp( name, "tcp_nodelay"                 ) ) return (ctx == NULL) ? buffer : store_bool( buffer, buflen, ctx->tcp_nodelay                 );
	if ( ! httplib_strcasecmp( name, "url_rewrite_patterns"        ) ) return (ctx == NULL) ? buffer : store_str(  buffer, buflen, ctx->url_rewrite_patterns        );
	if ( ! httplib_strcasecmp( name, "websocket_root"              ) ) return (ctx == NULL) ? buffer : store_str(  buffer, buflen, ctx->websocket_root              );
	if ( ! httplib_strcasecmp( name, "websocket_timeout"           ) ) return (ctx == NULL) ? buffer : store_int(  buffer, buflen, ctx->websocket_timeout           );

	return NULL;

}  /* httplib_get_option */

/*
 * static const char *store_str( char *buffer, size_t buflen, const char *value );
 *
 * The function store_str() returns a pointer to a filled string containing the
 * value of a configuration option. If an error occurs or the option is NULL,
 * the function returns NULL.
 */

static const char *store_str( char *buffer, size_t buflen, const char *value ) {

	if ( value == NULL            ) return NULL;
	if ( buflen < strlen(value)+1 ) return NULL;

	httplib_strlcpy( buffer, value, buflen );
	return buffer;

}  /* store_str */

/*
 * static const char *store_bool( char *buffer, size_t buflen, bool value );
 *
 * The function store_bool() returns a pointer to a filled string containing
 * the value of a boolean configuration option. If an error occurs the function
 * returns NULL.
 */

static const char *store_bool( char *buffer, size_t buflen, bool value ) {

	return store_str( buffer, buflen, (value) ? "yes" : "no" );

}  /* store_bool */

/*
 * static const char *store_int( char *buffer, size_t buflen, int value );
 *
 * The function store_int() returns a pointer to a filled string containing the
 * value of an integer configuration option. If an error occurs the function
 * returns NULL.
 */

static const char *store_int( char *buffer, size_t buflen, int value ) {

	char storage[32];

	snprintf( storage, 32, "%d", value );
	return store_str( buffer, buflen, storage );

}  /* store_int */
