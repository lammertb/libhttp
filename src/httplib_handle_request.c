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

#include "httplib_main.h"
#include "httplib_ssl.h"
#include "httplib_utils.h"

/*
 * void XX_httplib_handle_request( const struct lh_ctx_t *ctx, struct lh_con_t *conn );
 *
 * The function XX_httplib_handle_request() handles an incoming request. This
 * is the heart of the LibHTTP's logic. This function is called when the
 * request is read, parsed and validated, and LibHTTP must decide what action
 * to take: serve a file, or a directory, or call embedded function, etcetera.
 */

void XX_httplib_handle_request( struct lh_ctx_t *ctx, struct lh_con_t *conn ) {

	struct lh_rqi_t *ri;
	char path[PATH_MAX];
	int uri_len;

#if !defined(NO_SSL)
	int ssl_index;
#endif  /* NO_SSL */

	bool is_found;
	bool is_script_resource;
	bool is_websocket_request;
	bool is_put_or_delete_request;
	bool is_callback_resource;
	int i;
	struct file file = STRUCT_FILE_INITIALIZER;
	httplib_request_handler callback_handler;
	httplib_websocket_connect_handler ws_connect_handler;
	httplib_websocket_ready_handler ws_ready_handler;
	httplib_websocket_data_handler ws_data_handler;
	httplib_websocket_close_handler ws_close_handler;
	void *callback_data;
	httplib_authorization_handler auth_handler;
	void *auth_callback_data;
	time_t curtime;
	char date[64];
	union {
		const char *	con;
		char *		var;
	} ptr;

	if ( ctx == NULL  ||  conn == NULL ) return;

	ri                       = & conn->request_info;
	is_found                 = false;
	is_script_resource       = false;
	is_websocket_request     = false;
	is_put_or_delete_request = false;
	is_callback_resource     = false;
	callback_handler         = NULL;
	ws_connect_handler       = NULL;
	ws_ready_handler         = NULL;
	ws_data_handler          = NULL;
	ws_close_handler         = NULL;
	callback_data            = NULL;
	auth_handler             = NULL;
	auth_callback_data       = NULL;
	path[0]                  = 0;
	curtime                  = time( NULL );

	if ( ri == NULL ) return;

	/*
	 * 1. get the request url
	 */

	/*
	 * 1.1. split into url and query string
	 */

	ptr.var = strchr( ri->request_uri, '?' );
	if ( ptr.var != NULL ) *(ptr.var++) = '\0';
	ri->query_string = ptr.var;

	/*
	 * 1.2. do a https redirect, if required. Do not decode URIs yet.
	 */

#if !defined(NO_SSL)

	if ( ! conn->client.has_ssl  &&  conn->client.has_redir ) {

		ssl_index = XX_httplib_get_first_ssl_listener_index( ctx );

		if ( ssl_index >= 0 ) XX_httplib_redirect_to_https_port( ctx, conn, ssl_index );
		
		else {
			/*
			 * A http to https forward port has been specified,
			 * but no https port to forward to.
			 */

			XX_httplib_send_http_error( ctx, conn, 503, "%s", "Error: SSL forward not configured properly" );
			httplib_cry( LH_DEBUG_ERROR, ctx, conn, "%s: can not redirect to SSL, no SSL port available", __func__ );
		}

		return;
	}

#endif  /* NO_SSL */

	uri_len = (int)strlen( ri->local_uri );

	/*
	 * 1.3. decode url (if config says so)
	 */

	ptr.con = ri->local_uri;
	if ( XX_httplib_should_decode_url( ctx ) ) httplib_url_decode( ptr.con, uri_len, ptr.var, uri_len + 1, 0 );

	/*
	 * 1.4. clean URIs, so a path like allowed_dir/../forbidden_file is
	 * not possible
	 */

	ptr.con = ri->local_uri;
	XX_httplib_remove_double_dots_and_double_slashes( ptr.var );

	/*
	 * step 1. completed, the url is known now
	 */

	uri_len = (int)strlen( ri->local_uri );

	/*
	 * 3. if this ip has limited speed, set it for this connection
	 */

	conn->throttle = XX_httplib_set_throttle( ctx->throttle, XX_httplib_get_remote_ip( conn ), ri->local_uri );

	/*
	 * 4. call a "handle everything" callback, if registered
	 */

	if ( ctx->callbacks.begin_request != NULL ) {

		/*
		 * Note that since V1.7 the "begin_request" function is called
		 * before an authorization check. If an authorization check is
		 * required, use a request_handler instead.
		 */

		i = ctx->callbacks.begin_request( ctx, conn );

		if ( i > 0 ) {

			/*
			 * callback already processed the request. Store the
			 * return value as a status code for the access log.
			 */

			conn->status_code = i;
			return;

		}
		
		else if ( i == 0 ) {
			/*
			 * LibHTTP should process the request
			 */
		}
		
		else {
			/*
			 * unspecified - may change with the next version
			 */

			return;
		}
	}

	/*
	 * request not yet handled by a handler or redirect, so the request
	 * is processed here
	 */

	/*
	 * 5. interpret the url to find out how the request must be handled
	 *
	 * 5.1. first test, if the request targets the regular http(s)://
	 * protocol namespace or the websocket ws(s):// protocol namespace.
	 */

	is_websocket_request = XX_httplib_is_websocket_protocol( conn );

	/* 
	 * 5.2. check if the request will be handled by a callback
	 */

	if ( XX_httplib_get_request_handler( ctx, conn,
	                        is_websocket_request ? WEBSOCKET_HANDLER : REQUEST_HANDLER,
	                        &callback_handler,
	                        &ws_connect_handler,
	                        &ws_ready_handler,
	                        &ws_data_handler,
	                        &ws_close_handler,
	                        NULL,
	                        &callback_data ) ) {
		/*
		 * 5.2.1. A callback will handle this request. All requests
		 * handled
		 * by a callback have to be considered as requests to a script
		 * resource.
		 */

		is_callback_resource     = true;
		is_script_resource       = true;
		is_put_or_delete_request = XX_httplib_is_put_or_delete_method( conn );
	}
	
	else {

no_callback_resource:

		/*
		 * 5.2.2. No callback is responsible for this request. The URI
		 * addresses a file based resource (static content or Lua/cgi
		 * scripts in the file system).
		 */

		is_callback_resource = false;
		XX_httplib_interpret_uri( ctx, conn, path, sizeof(path), &file, &is_found, &is_script_resource, &is_websocket_request, &is_put_or_delete_request );
	}

	/*
	 * 6. authorization check
	 *
	 * 6.1. a custom authorization handler is installed
	 */

	if ( XX_httplib_get_request_handler( ctx, conn, AUTH_HANDLER, NULL, NULL, NULL, NULL, NULL, &auth_handler, &auth_callback_data ) ) {

		if ( ! auth_handler( ctx, conn, auth_callback_data ) ) return;
	}
	
	else if ( is_put_or_delete_request  &&  ! is_script_resource  &&  ! is_callback_resource ) {

/*
 * 6.2. this request is a PUT/DELETE to a real file
 * 6.2.1. thus, the server must have real files
 */

		if ( ctx->document_root == NULL ) {

			/*
			 * This server does not have any real files, thus the
			 * PUT/DELETE methods are not valid.
			 */

			XX_httplib_send_http_error( ctx, conn, 405, "%s method not allowed", conn->request_info.request_method );
			return;
		}

		/*
		 * 6.2.2. Check if put authorization for static files is
		 * available.
		 */
		if ( ! XX_httplib_is_authorized_for_put( ctx, conn ) ) {

			XX_httplib_send_authorization_request( ctx, conn );
			return;
		}
	}

	else {
		/*
		 * 6.3. This is either a OPTIONS, GET, HEAD or POST request,
		 * or it is a PUT or DELETE request to a resource that does not
		 * correspond to a file. Check authorization.
		 */

		if ( ! XX_httplib_check_authorization( ctx, conn, path ) ) {

			XX_httplib_send_authorization_request( ctx, conn );
			return;
		}
	}

	/*
	 * request is authorized or does not need authorization
	 */

	/*
	 * 7. check if there are request handlers for this uri
	 */

	if ( is_callback_resource ) {

		if ( ! is_websocket_request ) {

			i = callback_handler( ctx, conn, callback_data );
			if ( i > 0 ) {

				/*
				 * Do nothing, callback has served the request. Store the
				 * return value as status code for the log and discard all
				 * data from the client not used by the callback.
				 */

				conn->status_code = i;
				XX_httplib_discard_unread_request_data( ctx, conn );
			}
			
			else {
				/* TODO (high): what if the handler did NOT handle the request
				 * The last version did handle this as a file request, but
				 * since a file request is not always a script resource,
				 * the authorization check might be different
				 */

				XX_httplib_interpret_uri( ctx, conn, path, sizeof(path), &file, &is_found, &is_script_resource, &is_websocket_request, &is_put_or_delete_request );
				callback_handler = NULL;

				goto no_callback_resource;
			}
		}
		
		else {
			XX_httplib_handle_websocket_request( ctx, conn, path, is_callback_resource, ws_connect_handler, ws_ready_handler, ws_data_handler, ws_close_handler, callback_data );
		}

		return;
	}

/*
 * 8. handle websocket requests
 */

	if ( is_websocket_request ) {

		if ( is_script_resource ) {

			/*
			 * Websocket Lua script, the 0 in the third parameter indicates Lua
			 */

			XX_httplib_handle_websocket_request( ctx, conn, path, 0, NULL, NULL, NULL, NULL, &ctx->callbacks );
		}
		
		else XX_httplib_send_http_error( ctx, conn, 404, "%s", "Not found" );

		return;
	}

	/*
	 * 9. This request is either for a static file or resource handled
	 * by a script file. Thus, a DOCUMENT_ROOT must exist.
	 */

	if ( ctx->document_root == NULL ) {

		XX_httplib_send_http_error( ctx, conn, 404, "%s", "Not Found" );
		return;
	}

	/*
	 * 10. File is handled by a script.
	 */

	if ( is_script_resource ) {

		XX_httplib_handle_file_based_request( ctx, conn, path, &file );
		return;
	}

	/*
	 * 11. Handle put/delete/mkcol requests
	 */

	if ( is_put_or_delete_request ) {

		if ( ! strcmp( ri->request_method, "PUT"    ) ) { XX_httplib_put_file(    ctx, conn, path ); return; }
		if ( ! strcmp( ri->request_method, "DELETE" ) ) { XX_httplib_delete_file( ctx, conn, path ); return; }
		if ( ! strcmp( ri->request_method, "MKCOL"  ) ) { XX_httplib_mkcol(       ctx, conn, path ); return; }

		/*
		 * 11.4. PATCH method
		 * This method is not supported for static resources,
		 * only for scripts (Lua, CGI) and callbacks.
		 */

		XX_httplib_send_http_error( ctx, conn, 405, "%s method not allowed", conn->request_info.request_method );
		return;
	}

	/*
	 * 11. File does not exist, or it was configured that it should be
	 * hidden
	 */

	if ( ! is_found  ||  XX_httplib_must_hide_file( ctx, path ) ) {

		XX_httplib_send_http_error( ctx, conn, 404, "%s", "Not found" );
		return;
	}

	/*
	 * 12. Directory uris should end with a slash
	 */

	if ( file.is_directory  &&  uri_len > 0  &&  ri->local_uri[uri_len - 1] != '/' ) {

		XX_httplib_gmt_time_string( date, sizeof(date), &curtime );
		httplib_printf( ctx, conn,
		          "HTTP/1.1 301 Moved Permanently\r\n"
		          "Location: %s/\r\n"
		          "Date: %s\r\n"
		          /* "Cache-Control: private\r\n" (= default) */
		          "Content-Length: 0\r\n"
		          "Connection: %s\r\n\r\n",
		          ri->request_uri,
		          date,
		          XX_httplib_suggest_connection_header( ctx, conn ) );
		return;
	}

	/*
	 * 13. Handle other methods than GET/HEAD
	 * 13.1. Handle PROPFIND
	 */

	if ( ! strcmp( ri->request_method, "PROPFIND" ) ) {

		XX_httplib_handle_propfind( ctx, conn, path, & file );
		return;
	}

	/*
	 * 13.2. Handle OPTIONS for files
	 */

	if ( ! strcmp( ri->request_method, "OPTIONS" ) ) {

		/*
		 * This standard handler is only used for real files.
		 * Scripts should support the OPTIONS method themselves, to allow a
		 * maximum flexibility.
		 * Lua and CGI scripts may fully support CORS this way (including
		 * preflights).
		 */

		XX_httplib_send_options( ctx, conn );
		return;
	}

	/*
	 * 13.3. everything but GET and HEAD (e.g. POST)
	 */

	if ( strcmp( ri->request_method, "GET" )  &&  strcmp( ri->request_method, "HEAD" ) ) {

		XX_httplib_send_http_error( ctx, conn, 405, "%s method not allowed", conn->request_info.request_method );
		return;
	}

	/*
	 * 14. directories
	 */

	if ( file.is_directory ) {

		if ( XX_httplib_substitute_index_file( ctx, conn, path, sizeof(path), &file ) ) {

			/*
			 * 14.1. use a substitute file
			 * TODO (high): substitute index may be a script resource.
			 * define what should be possible in this case.
			 */
		}
		
		else {
			/*
			 * 14.2. no substitute file
			 */

			if ( ctx->enable_directory_listing ) XX_httplib_handle_directory_request( ctx, conn, path );
			else                                 XX_httplib_send_http_error( ctx, conn, 403, "%s", "Error: Directory listing denied" );

			return;
		}
	}

	XX_httplib_handle_file_based_request( ctx, conn, path, &file );

#if 0
	/*
	 * Perform redirect and auth checks before calling begin_request() handler.
	 * Otherwise, begin_request() would need to perform auth checks and redirects.
	 */
#endif

}  /* XX_httplib_handle_request */
