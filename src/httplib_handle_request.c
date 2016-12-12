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
#include "httplib_ssl.h"



/*
 * void XX_httplib_handle_request( struct mg_connection *conn );
 *
 * The function XX_httplib_handle_request() handles an incoming request. This
 * is the heart of the LibHTTP's logic. This function is called when the
 * request is read, parsed and validated, and LibHTTP must decide what action
 * to take: serve a file, or a directory, or call embedded function, etcetera.
 */

void XX_httplib_handle_request( struct mg_connection *conn ) {

	if ( conn == NULL ) return;

	struct mg_request_info *ri = &conn->request_info;
	char path[PATH_MAX];
	int uri_len;
	int ssl_index;
	int is_found                 = 0;
	int is_script_resource       = 0;
	int is_websocket_request     = 0;
	int is_put_or_delete_request = 0;
	int is_callback_resource     = 0;
	int i;
	struct file file = STRUCT_FILE_INITIALIZER;
	mg_request_handler callback_handler             = NULL;
	mg_websocket_connect_handler ws_connect_handler = NULL;
	mg_websocket_ready_handler ws_ready_handler     = NULL;
	mg_websocket_data_handler ws_data_handler       = NULL;
	mg_websocket_close_handler ws_close_handler     = NULL;
	void *callback_data                             = NULL;
	mg_authorization_handler auth_handler           = NULL;
	void *auth_callback_data                        = NULL;
#if !defined(NO_FILES)
	time_t curtime = time(NULL);
	char date[64];
#endif

	path[0] = 0;

	if (!ri) return;

	/* 1. get the request url */
	/* 1.1. split into url and query string */
	if ((conn->request_info.query_string = strchr(ri->request_uri, '?'))
	    != NULL) {
		*((char *)conn->request_info.query_string++) = '\0';
	}

	/* 1.2. do a https redirect, if required. Do not decode URIs yet. */
	if (!conn->client.is_ssl && conn->client.ssl_redir) {
		ssl_index = XX_httplib_get_first_ssl_listener_index(conn->ctx);
		if (ssl_index >= 0) {
			XX_httplib_redirect_to_https_port(conn, ssl_index);
		} else {
			/* A http to https forward port has been specified,
			 * but no https port to forward to. */
			XX_httplib_send_http_error(conn, 503, "%s", "Error: SSL forward not configured properly");
			mg_cry(conn, "Can not redirect to SSL, no SSL port available");
		}
		return;
	}
	uri_len = (int)strlen(ri->local_uri);

	/* 1.3. decode url (if config says so) */
	if (XX_httplib_should_decode_url(conn)) mg_url_decode( ri->local_uri, uri_len, (char *)ri->local_uri, uri_len + 1, 0);

	/* 1.4. clean URIs, so a path like allowed_dir/../forbidden_file is
	 * not possible */
	XX_httplib_remove_double_dots_and_double_slashes((char *)ri->local_uri);

	/* step 1. completed, the url is known now */
	uri_len = (int)strlen(ri->local_uri);

	/* 3. if this ip has limited speed, set it for this connection */
	conn->throttle = XX_httplib_set_throttle(conn->ctx->config[THROTTLE], XX_httplib_get_remote_ip(conn), ri->local_uri);

	/* 4. call a "handle everything" callback, if registered */
	if (conn->ctx->callbacks.begin_request != NULL) {
		/* Note that since V1.7 the "begin_request" function is called
		 * before an authorization check. If an authorization check is
		 * required, use a request_handler instead. */
		i = conn->ctx->callbacks.begin_request(conn);
		if (i > 0) {
			/* callback already processed the request. Store the
			   return value as a status code for the access log. */
			conn->status_code = i;
			return;
		} else if (i == 0) {
			/* LibHTTP should process the request */
		} else {
			/* unspecified - may change with the next version */
			return;
		}
	}

	/* request not yet handled by a handler or redirect, so the request
	 * is processed here */

	/* 5. interpret the url to find out how the request must be handled
	 */
	/* 5.1. first test, if the request targets the regular http(s)://
	 * protocol namespace or the websocket ws(s):// protocol namespace.
	 */
	is_websocket_request = XX_httplib_is_websocket_protocol(conn);

	/* 5.2. check if the request will be handled by a callback */
	if (XX_httplib_get_request_handler(conn,
	                        is_websocket_request ? WEBSOCKET_HANDLER
	                                             : REQUEST_HANDLER,
	                        &callback_handler,
	                        &ws_connect_handler,
	                        &ws_ready_handler,
	                        &ws_data_handler,
	                        &ws_close_handler,
	                        NULL,
	                        &callback_data)) {
		/* 5.2.1. A callback will handle this request. All requests
		 * handled
		 * by a callback have to be considered as requests to a script
		 * resource. */
		is_callback_resource = 1;
		is_script_resource = 1;
		is_put_or_delete_request = XX_httplib_is_put_or_delete_method(conn);
	} else {
	no_callback_resource:
		/* 5.2.2. No callback is responsible for this request. The URI
		 * addresses a file based resource (static content or Lua/cgi
		 * scripts in the file system). */
		is_callback_resource = 0;
		XX_httplib_interpret_uri(conn,
		              path,
		              sizeof(path),
		              &file,
		              &is_found,
		              &is_script_resource,
		              &is_websocket_request,
		              &is_put_or_delete_request);
	}

	/* 6. authorization check */
	/* 6.1. a custom authorization handler is installed */
	if (XX_httplib_get_request_handler(conn, AUTH_HANDLER, NULL, NULL, NULL, NULL, NULL, &auth_handler, &auth_callback_data)) {
		if (!auth_handler(conn, auth_callback_data)) return;
	} else if (is_put_or_delete_request && !is_script_resource && !is_callback_resource) {
/* 6.2. this request is a PUT/DELETE to a real file */
/* 6.2.1. thus, the server must have real files */
#if defined(NO_FILES)
		if (1) {
#else
		if (conn->ctx->config[DOCUMENT_ROOT] == NULL) {
#endif
			/* This server does not have any real files, thus the
			 * PUT/DELETE methods are not valid. */
			XX_httplib_send_http_error(conn, 405, "%s method not allowed", conn->request_info.request_method);
			return;
		}

#if !defined(NO_FILES)
		/* 6.2.2. Check if put authorization for static files is
		 * available.
		 */
		if (!XX_httplib_is_authorized_for_put(conn)) {
			XX_httplib_send_authorization_request(conn);
			return;
		}
#endif

	} else {
		/* 6.3. This is either a OPTIONS, GET, HEAD or POST request,
		 * or it is a PUT or DELETE request to a resource that does not
		 * correspond to a file. Check authorization. */
		if (!XX_httplib_check_authorization(conn, path)) {
			XX_httplib_send_authorization_request(conn);
			return;
		}
	}

	/* request is authorized or does not need authorization */

	/* 7. check if there are request handlers for this uri */
	if (is_callback_resource) {
		if (!is_websocket_request) {
			i = callback_handler(conn, callback_data);
			if (i > 0) {
				/* Do nothing, callback has served the request. Store
				 * the
				 * return value as status code for the log and discard
				 * all
				 * data from the client not used by the callback. */
				conn->status_code = i;
				XX_httplib_discard_unread_request_data(conn);
			} else {
				/* TODO (high): what if the handler did NOT handle the
				 * request */
				/* The last version did handle this as a file request,
				 * but
				 * since a file request is not always a script resource,
				 * the authorization check might be different */
				XX_httplib_interpret_uri(conn,
				              path,
				              sizeof(path),
				              &file,
				              &is_found,
				              &is_script_resource,
				              &is_websocket_request,
				              &is_put_or_delete_request);
				callback_handler = NULL;

				/* TODO (very low): goto is deprecated but for the
				 * moment,
				 * a goto is simpler than some curious loop. */
				/* The situation "callback does not handle the request"
				 * needs to be reconsidered anyway. */
				goto no_callback_resource;
			}
		} else {
#if defined(USE_WEBSOCKET)
			XX_httplib_handle_websocket_request(conn,
			                         path,
			                         is_callback_resource,
			                         ws_connect_handler,
			                         ws_ready_handler,
			                         ws_data_handler,
			                         ws_close_handler,
			                         callback_data);
#endif
		}
		return;
	}

/* 8. handle websocket requests */
#if defined(USE_WEBSOCKET)
	if (is_websocket_request) {
		if (is_script_resource) {
			/* Websocket Lua script, the 0 in the third parameter indicates Lua */
			XX_httplib_handle_websocket_request(conn, path, 0, NULL, NULL, NULL, NULL, &conn->ctx->callbacks);
		} else {
			XX_httplib_send_http_error(conn, 404, "%s", "Not found");
		}
		return;
	} else
#endif

#if defined(NO_FILES)
		/* 9a. In case the server uses only callbacks, this uri is
		 * unknown.
		 * Then, all request handling ends here. */
		XX_httplib_send_http_error(conn, 404, "%s", "Not Found");

#else
	/* 9b. This request is either for a static file or resource handled
	 * by a script file. Thus, a DOCUMENT_ROOT must exist. */
	if (conn->ctx->config[DOCUMENT_ROOT] == NULL) {
		XX_httplib_send_http_error(conn, 404, "%s", "Not Found");
		return;
	}

	/* 10. File is handled by a script. */
	if (is_script_resource) {
		XX_httplib_handle_file_based_request(conn, path, &file);
		return;
	}

	/* 11. Handle put/delete/mkcol requests */
	if (is_put_or_delete_request) {
		/* 11.1. PUT method */
		if (!strcmp(ri->request_method, "PUT")) {
			XX_httplib_put_file(conn, path);
			return;
		}
		/* 11.2. DELETE method */
		if (!strcmp(ri->request_method, "DELETE")) {
			XX_httplib_delete_file(conn, path);
			return;
		}
		/* 11.3. MKCOL method */
		if (!strcmp(ri->request_method, "MKCOL")) {
			XX_httplib_mkcol(conn, path);
			return;
		}
		/* 11.4. PATCH method
		 * This method is not supported for static resources,
		 * only for scripts (Lua, CGI) and callbacks. */
		XX_httplib_send_http_error(conn, 405, "%s method not allowed", conn->request_info.request_method);
		return;
	}

	/* 11. File does not exist, or it was configured that it should be
	 * hidden */
	if (!is_found || (XX_httplib_must_hide_file(conn, path))) {
		XX_httplib_send_http_error(conn, 404, "%s", "Not found");
		return;
	}

	/* 12. Directory uris should end with a slash */
	if (file.is_directory && (uri_len > 0)
	    && (ri->local_uri[uri_len - 1] != '/')) {
		XX_httplib_gmt_time_string(date, sizeof(date), &curtime);
		mg_printf(conn,
		          "HTTP/1.1 301 Moved Permanently\r\n"
		          "Location: %s/\r\n"
		          "Date: %s\r\n"
		          /* "Cache-Control: private\r\n" (= default) */
		          "Content-Length: 0\r\n"
		          "Connection: %s\r\n\r\n",
		          ri->request_uri,
		          date,
		          XX_httplib_suggest_connection_header(conn));
		return;
	}

	/* 13. Handle other methods than GET/HEAD */
	/* 13.1. Handle PROPFIND */
	if (!strcmp(ri->request_method, "PROPFIND")) {
		XX_httplib_handle_propfind(conn, path, &file);
		return;
	}
	/* 13.2. Handle OPTIONS for files */
	if (!strcmp(ri->request_method, "OPTIONS")) {
		/* This standard handler is only used for real files.
		 * Scripts should support the OPTIONS method themselves, to allow a
		 * maximum flexibility.
		 * Lua and CGI scripts may fully support CORS this way (including
		 * preflights). */
		XX_httplib_send_options(conn);
		return;
	}
	/* 13.3. everything but GET and HEAD (e.g. POST) */
	if (0 != strcmp(ri->request_method, "GET")
	    && 0 != strcmp(ri->request_method, "HEAD")) {
		XX_httplib_send_http_error(conn, 405, "%s method not allowed", conn->request_info.request_method);
		return;
	}

	/* 14. directories */
	if (file.is_directory) {
		if (XX_httplib_substitute_index_file(conn, path, sizeof(path), &file)) {
			/* 14.1. use a substitute file */
			/* TODO (high): substitute index may be a script resource.
			 * define what should be possible in this case. */
		} else {
			/* 14.2. no substitute file */
			if (!mg_strcasecmp(conn->ctx->config[ENABLE_DIRECTORY_LISTING], "yes")) XX_httplib_handle_directory_request(conn, path);
			else XX_httplib_send_http_error(conn, 403, "%s", "Error: Directory listing denied");
			return;
		}
	}

	XX_httplib_handle_file_based_request(conn, path, &file);
#endif /* !defined(NO_FILES) */

#if 0
	/* Perform redirect and auth checks before calling begin_request()
	 * handler.
	 * Otherwise, begin_request() would need to perform auth checks and
	 * redirects.
	 */
#endif

}  /* XX_httplib_handle_request */
