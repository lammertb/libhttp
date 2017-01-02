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

static bool			check_bool( struct lh_ctx_t *ctx, const struct lh_opt_t *option, const char *name, bool *config  );
static bool			check_dbg(  struct lh_ctx_t *ctx, const struct lh_opt_t *option, const char *name, enum lh_dbg_t *config );
static bool			check_dir(  struct lh_ctx_t *ctx, const struct lh_opt_t *option, const char *name, char **config );
static bool			check_file( struct lh_ctx_t *ctx, const struct lh_opt_t *option, const char *name, char **config );
static bool			check_int(  struct lh_ctx_t *ctx, const struct lh_opt_t *option, const char *name, int *config, int minval, int maxval );
static bool			check_patt( struct lh_ctx_t *ctx, const struct lh_opt_t *option, const char *name, char **config );
static bool			check_str(  struct lh_ctx_t *ctx, const struct lh_opt_t *option, const char *name, char **config );

/*
 * bool XX_httplib_process_options( struct lh_ctx_t *ctx, const struct lh_opt_t *options );
 *
 * The function process_options() processes the user supplied options and adds
 * them to the central option list of the context. If en error occurs, the
 * function returns true, otherwise FALSE is returned. In case of an error all
 * cleanup is already done before returning and an error message has been
 * generated.
 */

bool XX_httplib_process_options( struct lh_ctx_t *ctx, const struct lh_opt_t *options ) {

	if ( ctx == NULL ) return true;

	while ( options != NULL  &&  options->name != NULL ) {

		if ( check_str(  ctx, options, "access_control_allow_origin", & ctx->access_control_allow_origin             ) ) return true;
		if ( check_str(  ctx, options, "access_control_list",         & ctx->access_control_list                     ) ) return true;
		if ( check_file( ctx, options, "access_log_file",             & ctx->access_log_file                         ) ) return true;
		if ( check_bool( ctx, options, "allow_sendfile_call",         & ctx->allow_sendfile_call                     ) ) return true;
		if ( check_str(  ctx, options, "authentication_domain",       & ctx->authentication_domain                   ) ) return true;
		if ( check_str(  ctx, options, "cgi_environment",             & ctx->cgi_environment                         ) ) return true;
		if ( check_file( ctx, options, "cgi_interpreter",             & ctx->cgi_interpreter                         ) ) return true;
		if ( check_patt( ctx, options, "cgi_pattern",                 & ctx->cgi_pattern                             ) ) return true;
		if ( check_dbg(  ctx, options, "debug_level",                 & ctx->debug_level                             ) ) return true;
		if ( check_bool( ctx, options, "decode_url",                  & ctx->decode_url                              ) ) return true;
		if ( check_dir(  ctx, options, "document_root",               & ctx->document_root                           ) ) return true;
		if ( check_bool( ctx, options, "enable_directory_listing",    & ctx->enable_directory_listing                ) ) return true;
		if ( check_bool( ctx, options, "enable_keep_alive",           & ctx->enable_keep_alive                       ) ) return true;
		if ( check_file( ctx, options, "error_log_file",              & ctx->error_log_file                          ) ) return true;
		if ( check_dir(  ctx, options, "error_pages",                 & ctx->error_pages                             ) ) return true;
		if ( check_str(  ctx, options, "extra_mime_types",            & ctx->extra_mime_types                        ) ) return true;
		if ( check_file( ctx, options, "global_auth_file",            & ctx->global_auth_file                        ) ) return true;
		if ( check_patt( ctx, options, "hide_file_pattern",           & ctx->hide_file_pattern                       ) ) return true;
		if ( check_str(  ctx, options, "index_files",                 & ctx->index_files                             ) ) return true;
		if ( check_str(  ctx, options, "listening_ports",             & ctx->listening_ports                         ) ) return true;
		if ( check_int(  ctx, options, "num_threads",                 & ctx->num_threads,                 1, INT_MAX ) ) return true;
		if ( check_str(  ctx, options, "protect_uri",                 & ctx->protect_uri                             ) ) return true;
		if ( check_file( ctx, options, "put_delete_auth_file",        & ctx->put_delete_auth_file                    ) ) return true;
		if ( check_int(  ctx, options, "request_timeout",             & ctx->request_timeout,             0, INT_MAX ) ) return true;
		if ( check_str(  ctx, options, "run_as_user",                 & ctx->run_as_user                             ) ) return true;
		if ( check_int(  ctx, options, "ssi_include_depth",           & ctx->ssi_include_depth,           0, 20      ) ) return true;
		if ( check_patt( ctx, options, "ssi_pattern",                 & ctx->ssi_pattern                             ) ) return true;
		if ( check_file( ctx, options, "ssl_ca_file",                 & ctx->ssl_ca_file                             ) ) return true;
		if ( check_dir(  ctx, options, "ssl_ca_path",                 & ctx->ssl_ca_path                             ) ) return true;
		if ( check_file( ctx, options, "ssl_certificate",             & ctx->ssl_certificate                         ) ) return true;
		if ( check_str(  ctx, options, "ssl_cipher_list",             & ctx->ssl_cipher_list                         ) ) return true;
		if ( check_int(  ctx, options, "ssl_protocol_version",        & ctx->ssl_protocol_version,        0, 4       ) ) return true;
		if ( check_bool( ctx, options, "ssl_short_trust",             & ctx->ssl_short_trust                         ) ) return true;
		if ( check_int(  ctx, options, "ssl_verify_depth",            & ctx->ssl_verify_depth,            0, 9       ) ) return true;
		if ( check_bool( ctx, options, "ssl_verify_paths",            & ctx->ssl_verify_paths                        ) ) return true;
		if ( check_bool( ctx, options, "ssl_verify_peer",             & ctx->ssl_verify_peer                         ) ) return true;
		if ( check_int(  ctx, options, "static_file_max_age",         & ctx->static_file_max_age,         0, INT_MAX ) ) return true;
		if ( check_str(  ctx, options, "throttle",                    & ctx->throttle                                ) ) return true;
		if ( check_bool( ctx, options, "tcp_nodelay",                 & ctx->tcp_nodelay                             ) ) return true;
		if ( check_str(  ctx, options, "url_rewrite_patterns",        & ctx->url_rewrite_patterns                    ) ) return true;
		if ( check_dir(  ctx, options, "websocket_root",              & ctx->websocket_root                          ) ) return true;
		if ( check_int(  ctx, options, "websocket_timeout",           & ctx->websocket_timeout,           0, INT_MAX ) ) return true;

		/*
		 * TODO: Currently silently ignoring unrecognized options
		 */

		options++;
	}

	return false;

}  /* XX_httplib_process_options */

/*
 * static bool check_bool( struct lh_ctx_t *ctx, const struct lh_opt_t *option, const char *name, bool *config );
 *
 * The function check_bool() checks if an option is equal to a boolean config
 * parameter and stores the value if that is the case. If the value cannot be
 * recognized, true is returned and the function performs a complete cleanup.
 * If the option name could not be found, the function returns false to
 * indicate that the search should go on. If the value could be found, also
 * false is returned.
 */

static bool check_bool( struct lh_ctx_t *ctx, const struct lh_opt_t *option, const char *name, bool *config ) {

	if ( ctx == NULL  ||  option == NULL  ||  option->name == NULL  ||  name == NULL  ||  config == NULL ) {

		XX_httplib_abort_start( ctx, "Internal error parsing boolean option" );
		return true;
	}

	if (      httplib_strcasecmp(           option->name,  name   ) ) return false;
	if ( ! XX_httplib_option_value_to_bool( option->value, config ) ) return false;
			
	XX_httplib_abort_start( ctx, "Invalid boolean value \"%s\" for option \"%s\"", option->value, option->name );
	return true;

}  /* check_bool */

/*
 * static bool check_dir( struct lh_ctx_t *ctx, const struct lh_opt_t *option, const char *name, char **config );
 *
 * The function check_dir() checks if an option is equal to a directory config
 * parameter and stores the value if that is the case. If the value cannot be
 * recognized, true is returned and the function performs a complete cleanup.
 * If the option name could not be found, the function returns false to
 * indicate that the search should go on. IF the value could be found, also
 * false is returned.
 */

static bool check_dir( struct lh_ctx_t *ctx, const struct lh_opt_t *option, const char *name, char **config ) {

	if ( ctx == NULL  ||  option == NULL  ||  option->name == NULL  ||  name == NULL  ||  config == NULL ) {

		XX_httplib_abort_start( ctx, "Internal error parsing directory option" );
		return true;
	}

	if ( httplib_strcasecmp( option->name, name ) ) return false;

	*config = httplib_free( *config );

	if ( option->value == NULL ) return false;

	*config = httplib_strdup( option->value );
	if ( *config != NULL ) return false;

	XX_httplib_abort_start( ctx, "Out of memory assigning value \"%s\" to option \"%s\"", option->value, option->name );
	return true;

}  /* check_dir */

/*
 * static bool check_patt( struct lh_ctx_t *ctx, const struct lh_opt_t *option, const char *name, char **config );
 *
 * The function check_patt() checks if an option is equal to a pattern config
 * parameter and stores the value if that is the case. If the value cannot be
 * recognized, true is returned and the function performs a complete cleanup.
 * If the option name could not be found, the function returns false to
 * indicate that the search should go on. IF the value could be found, also
 * false is returned.
 */

static bool check_patt( struct lh_ctx_t *ctx, const struct lh_opt_t *option, const char *name, char **config ) {

	if ( ctx == NULL  ||  option == NULL  ||  option->name == NULL  ||  name == NULL  ||  config == NULL ) {

		XX_httplib_abort_start( ctx, "Internal error parsing pattern option" );
		return true;
	}

	if ( httplib_strcasecmp( option->name, name ) ) return false;

	*config = httplib_free( *config );

	if ( option->value == NULL ) return false;

	*config = httplib_strdup( option->value );
	if ( *config != NULL ) return false;

	XX_httplib_abort_start( ctx, "Out of memory assigning value \"%s\" to option \"%s\"", option->value, option->name );
	return true;

}  /* check_patt */

/*
 * static bool check_file( struct lh_ctx_t *ctx, const struct lh_opt_t *option, const char *name, char **config );
 *
 * The function check_file() checks if an option is equal to a filename config
 * parameter and stores the value if that is the case. If the value cannot be
 * recognized, true is returned and the function performs a complete cleanup.
 * If the option name could not be found, the function returns false to
 * indicate that the search should go on. IF the value could be found, also
 * false is returned.
 */

static bool check_file( struct lh_ctx_t *ctx, const struct lh_opt_t *option, const char *name, char **config ) {

	if ( ctx == NULL  ||  option == NULL  ||  option->name == NULL  ||  name == NULL  ||  config == NULL ) {

		XX_httplib_abort_start( ctx, "Internal error parsing file option" );
		return true;
	}

	if ( httplib_strcasecmp( option->name, name ) ) return false;

	*config = httplib_free( *config );

	if ( option->value == NULL ) return false;

	*config = httplib_strdup( option->value );
	if ( *config != NULL ) return false;

	XX_httplib_abort_start( ctx, "Out of memory assigning value \"%s\" to option \"%s\"", option->value, option->name );
	return true;

}  /* check_file */

/*
 * static bool check_str( struct lh_ctx_t *ctx, const struct lh_opt_t *option, const char *name, char **config );
 *
 * The function check_str() checks if an option is equal to a string config
 * parameter and stores the value if that is the case. If the value cannot be
 * recognized, true is returned and the function performs a complete cleanup.
 * If the option name could not be found, the function returns false to
 * indicate that the search should go on. IF the value could be found, also
 * false is returned.
 */

static bool check_str( struct lh_ctx_t *ctx, const struct lh_opt_t *option, const char *name, char **config ) {

	if ( ctx == NULL  ||  option == NULL  ||  option->name == NULL  ||  name == NULL  ||  config == NULL ) {

		XX_httplib_abort_start( ctx, "Internal error parsing string option" );
		return true;
	}

	if ( httplib_strcasecmp( option->name, name ) ) return false;

	*config = httplib_free( *config );

	if ( option->value == NULL ) return false;

	*config = httplib_strdup( option->value );
	if ( *config != NULL ) return false;

	XX_httplib_abort_start( ctx, "Out of memory assigning value \"%s\" to option \"%s\"", option->value, option->name );
	return true;

}  /* check_str */

/*
 * static bool check_int( struct lh_ctx_t *ctx, const struct httplib_opion_t *option, const char *name, int *config, int minval, int maxval );
 *
 * The function check_int() checks in an option is equal to an integer config
 * parameter and stores the value if that is the case. If the value cannot be
 * recognized, true is returned and the function performs a complete cleanup.
 * If the option name could not be found, the function returns false to
 * indicate that the search should go on. If the value could be found and is
 * valud, also false is returned.
 */

static bool check_int( struct lh_ctx_t *ctx, const struct lh_opt_t *option, const char *name, int *config, int minval, int maxval ) {

	int val;

	if ( ctx == NULL  ||  option == NULL  ||  option->name == NULL  ||  name == NULL  ||  config == NULL ) {

		XX_httplib_abort_start( ctx, "Internal error parsing integer option" );
		return true;
	}

	if ( httplib_strcasecmp( option->name, name ) ) return false;

	if ( ! XX_httplib_option_value_to_int( option->value, & val ) ) {

		if ( val < minval ) { XX_httplib_abort_start( ctx, "Integer \"%s\" too small for option \"%s\"", option->value, option->name ); return true; }
		if ( val > maxval ) { XX_httplib_abort_start( ctx, "Integer \"%s\" too large for option \"%s\"", option->value, option->name ); return true; }

		*config = val;
		return false;
	}

	XX_httplib_abort_start( ctx, "Invalid integer value \"%s\" for option \"%s\"", option->value, option->name );
	return true;

}  /* check_int */

/*
 * static bool check_dbg( struct lh_ctx_t *ctx, const struct lh_opt_t *option, const char *name, enum lh_dbg_t *config );
 *
 * The function check_dbg() checks if an option is equal to a debug level
 * config parameter and stores the value if that is the case. If the value
 * cannot be recognized, true is returned and the function performs a complete
 * cleanup. If the option name could not be found, the function returns false
 * to indicate that the search should go on. If the value could be found and is
 * valid, also false is returned.
 */

static bool check_dbg( struct lh_ctx_t *ctx, const struct lh_opt_t *option, const char *name, enum lh_dbg_t *config ) {

	int val;

	if ( ctx == NULL  ||  option == NULL  ||  option->name == NULL  ||  name == NULL  ||  config == NULL ) {

		XX_httplib_abort_start( ctx, "Internal error parsing debug level option" );
		return true;
	}

	if ( httplib_strcasecmp( option->name, name ) ) return false;

	if ( ! XX_httplib_option_value_to_int( option->value, &val ) ) {

		switch ( val ) {

			case LH_DEBUG_NONE    :
			case LH_DEBUG_CRASH   :
			case LH_DEBUG_ERROR   :
			case LH_DEBUG_WARNING :
			case LH_DEBUG_INFO    :
				*config = val;
				return false;
		}
	}

	XX_httplib_abort_start( ctx, "Invalid value \"%s\"  for option \"%s\"", option->value, option->name );
	return true;

}  /* check_dbg */
