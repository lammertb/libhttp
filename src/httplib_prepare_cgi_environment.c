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
 *
 * ============
 * Release: 2.0
 */

#include "httplib_main.h"
#include "httplib_memory.h"
#include "httplib_ssl.h"
#include "httplib_string.h"
#include "httplib_utils.h"

/*
 * void XX_httplib_prepare_cgi_environment( struct httplib_connection *conn, const char *prog, struct cgi_environment *env );
 *
 * The function XX_httplib_prepare_cgi_environment() is used to prepare all
 * environment variables before a CGI script is called.
 */

#if !defined(NO_CGI)

void XX_httplib_prepare_cgi_environment( struct httplib_connection *conn, const char *prog, struct cgi_environment *env ) {

	const char *s;
	struct vec var_vec;
	char *p;
	char src_addr[IP_ADDR_STR_LEN];
	char http_var_name[128];
	int i;
	bool truncated;

	if ( conn == NULL  ||  prog == NULL  ||  env == NULL ) return;

	env->conn    = conn;
	env->buflen  = CGI_ENVIRONMENT_SIZE;
	env->bufused = 0;
	env->buf     = httplib_malloc( env->buflen );
	env->varlen  = MAX_CGI_ENVIR_VARS;
	env->varused = 0;
	env->var     = httplib_malloc( env->buflen * sizeof(char *) );

	if ( conn->ctx->cfg[AUTHENTICATION_DOMAIN] != NULL ) XX_httplib_addenv( env, "SERVER_NAME=%s",   conn->ctx->cfg[AUTHENTICATION_DOMAIN] );
	if ( conn->ctx->cfg[DOCUMENT_ROOT]         != NULL ) XX_httplib_addenv( env, "SERVER_ROOT=%s",   conn->ctx->cfg[DOCUMENT_ROOT]         );
	if ( conn->ctx->cfg[DOCUMENT_ROOT]         != NULL ) XX_httplib_addenv( env, "DOCUMENT_ROOT=%s", conn->ctx->cfg[DOCUMENT_ROOT]         );
	XX_httplib_addenv( env, "SERVER_SOFTWARE=%s/%s", "LibHTTP", httplib_version() );

	/*
	 * Prepare the environment block
	 */

	XX_httplib_addenv( env, "%s", "GATEWAY_INTERFACE=CGI/1.1" );
	XX_httplib_addenv( env, "%s", "SERVER_PROTOCOL=HTTP/1.1"  );
	XX_httplib_addenv( env, "%s", "REDIRECT_STATUS=200"       ); /* For PHP */

	if ( conn->client.lsa.sa.sa_family == AF_INET6 ) XX_httplib_addenv( env, "SERVER_PORT=%d", ntohs( conn->client.lsa.sin6.sin6_port ) );
	else                                             XX_httplib_addenv( env, "SERVER_PORT=%d", ntohs( conn->client.lsa.sin.sin_port   ) );

	XX_httplib_sockaddr_to_string( src_addr, sizeof(src_addr), &conn->client.rsa );

	XX_httplib_addenv( env, "REMOTE_ADDR=%s",    src_addr                          );
	XX_httplib_addenv( env, "REQUEST_METHOD=%s", conn->request_info.request_method );
	XX_httplib_addenv( env, "REMOTE_PORT=%d",    conn->request_info.remote_port    );
	XX_httplib_addenv( env, "REQUEST_URI=%s",    conn->request_info.request_uri    );
	XX_httplib_addenv( env, "LOCAL_URI=%s",      conn->request_info.local_uri      );

	/*
	 * SCRIPT_NAME
	 */

	XX_httplib_addenv( env, "SCRIPT_NAME=%.*s", (int)strlen(conn->request_info.local_uri) - ((conn->path_info == NULL) ? 0 : (int)strlen(conn->path_info)), conn->request_info.local_uri);

	XX_httplib_addenv( env, "SCRIPT_FILENAME=%s", prog );

	if      ( conn->ctx->cfg[DOCUMENT_ROOT] == NULL ) XX_httplib_addenv( env, "PATH_TRANSLATED="                                                     );
	else if ( conn->path_info               == NULL ) XX_httplib_addenv( env, "PATH_TRANSLATED=%s",   conn->ctx->cfg[DOCUMENT_ROOT]                  );
	else                                              XX_httplib_addenv( env, "PATH_TRANSLATED=%s%s", conn->ctx->cfg[DOCUMENT_ROOT], conn->path_info );

	XX_httplib_addenv( env, "HTTPS=%s", (conn->ssl == NULL) ? "off" : "on" );

	if ( (s = httplib_get_header( conn, "Content-Type" ) )   != NULL ) XX_httplib_addenv( env, "CONTENT_TYPE=%s",   s                               );
	if ( conn->request_info.query_string                     != NULL ) XX_httplib_addenv( env, "QUERY_STRING=%s",   conn->request_info.query_string );
	if ( (s = httplib_get_header( conn, "Content-Length" ) ) != NULL ) XX_httplib_addenv( env, "CONTENT_LENGTH=%s", s                               );
	if ( (s = getenv( "PATH" ))                              != NULL ) XX_httplib_addenv( env, "PATH=%s",           s                               );
	if ( conn->path_info                                     != NULL ) XX_httplib_addenv( env, "PATH_INFO=%s",      conn->path_info                 );

	if (conn->status_code > 0) {

		/*
		 * CGI error handler should show the status code
		 */

		XX_httplib_addenv( env, "STATUS=%d", conn->status_code );
	}

#if defined(_WIN32)
	if ( (s = getenv( "COMSPEC"           )) != NULL ) XX_httplib_addenv( env, "COMSPEC=%s",           s );
	if ( (s = getenv( "SYSTEMROOT"        )) != NULL ) XX_httplib_addenv( env, "SYSTEMROOT=%s",        s );
	if ( (s = getenv( "SystemDrive"       )) != NULL ) XX_httplib_addenv( env, "SystemDrive=%s",       s );
	if ( (s = getenv( "ProgramFiles"      )) != NULL ) XX_httplib_addenv( env, "ProgramFiles=%s",      s );
	if ( (s = getenv( "ProgramFiles(x86)" )) != NULL ) XX_httplib_addenv( env, "ProgramFiles(x86)=%s", s );
#else
	if ( (s = getenv("LD_LIBRARY_PATH"    )) != NULL ) XX_httplib_addenv( env, "LD_LIBRARY_PATH=%s",   s );
#endif /* _WIN32 */

	if ( (s = getenv("PERLLIB"            )) != NULL ) XX_httplib_addenv( env, "PERLLIB=%s",           s );

	if (conn->request_info.remote_user != NULL) {

		XX_httplib_addenv( env, "REMOTE_USER=%s", conn->request_info.remote_user );
		XX_httplib_addenv( env, "%s",             "AUTH_TYPE=Digest"             );
	}

	/*
	 * Add all headers as HTTP_* variables
	 */

	for (i=0; i<conn->request_info.num_headers; i++) {

		XX_httplib_snprintf( conn, &truncated, http_var_name, sizeof(http_var_name), "HTTP_%s", conn->request_info.http_headers[i].name );

		if ( truncated ) {
			httplib_cry( conn, "%s: HTTP header variable too long [%s]", __func__, conn->request_info.http_headers[i].name );
			continue;
		}

		/*
		 * Convert variable name into uppercase, and change - to _
		 */

		for (p=http_var_name; *p != '\0'; p++) {

			if (*p == '-') *p = '_';
			*p = (char)toupper(*(unsigned char *)p);
		}

		XX_httplib_addenv( env, "%s=%s", http_var_name, conn->request_info.http_headers[i].value );
	}

	/*
	 * Add user-specified variables
	 */

	s = conn->ctx->cfg[CGI_ENVIRONMENT];

	while ( (s = XX_httplib_next_option( s, &var_vec, NULL )) != NULL ) {

		XX_httplib_addenv( env, "%.*s", (int)var_vec.len, var_vec.ptr );
	}

	env->var[env->varused] = NULL;
	env->buf[env->bufused] = '\0';

}  /* XX_httplib_prepare_cgi_environment */

#endif /* !NO_CGI */
