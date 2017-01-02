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

/*
 * const char *XX_httplib_get_rel_url_at_current_server( const struct lh_ctx_t *ctx, const char *uri, const struct lh_con_t *conn );
 *
 * The function XX_httplib_get_rel_url_at_current_server() returns the relative
 * uri at the current server.
 */

const char *XX_httplib_get_rel_url_at_current_server( const struct lh_ctx_t *ctx, const char *uri, const struct lh_con_t *conn ) {

	const char *server_domain;
	size_t server_domain_len;
	size_t request_domain_len;
	unsigned long port;
	int i;
	const char *hostbegin;
	const char *hostend;
	const char *portbegin;
	char *portend;

	if ( ctx == NULL  ||  conn == NULL ) return NULL;

	request_domain_len = 0;
	port               = 0;
	hostbegin          = NULL;
	hostend            = NULL;

	/*
	 * DNS is case insensitive, so use case insensitive string compare here
	 */

	server_domain = ctx->authentication_domain;
	if ( server_domain == NULL ) return NULL;

	server_domain_len = strlen( server_domain );
	if ( server_domain_len == 0 ) return NULL;

	for (i=0; XX_httplib_abs_uri_protocols[i].proto != NULL; i++) {

		if ( httplib_strncasecmp( uri, XX_httplib_abs_uri_protocols[i].proto, XX_httplib_abs_uri_protocols[i].proto_len ) == 0 ) { 

			hostbegin = uri + XX_httplib_abs_uri_protocols[i].proto_len;
			hostend   = strchr( hostbegin, '/' );

			if ( hostend == NULL ) return NULL;

			portbegin = strchr( hostbegin, ':' );

			if ( ! portbegin  ||   portbegin > hostend ) {

				port = XX_httplib_abs_uri_protocols[i].default_port;
				request_domain_len = (size_t)(hostend - hostbegin);
			}
			
			else {
				port = strtoul( portbegin + 1, &portend, 10 );
				if ( portend != hostend  ||  ! port  ||  ! XX_httplib_is_valid_port( port ) ) return NULL;
				request_domain_len = (size_t)(portbegin - hostbegin);
			}

			/*
			 * protocol found, port set
			 */

			break;
		}
	}

	if ( port == 0 ) {
		/*
		 * port remains 0 if the protocol is not found
		 */

		return NULL;
	}

	if ( conn->client.lsa.sa.sa_family == AF_INET6 ) { if ( ntohs( conn->client.lsa.sin6.sin6_port ) != port ) return NULL; }
	else                                             { if ( ntohs( conn->client.lsa.sin.sin_port   ) != port ) return NULL; }

	if ( request_domain_len != server_domain_len  ||  ( memcmp( server_domain, hostbegin, server_domain_len ) != 0 ) ) {

		/*
		 * Request is directed to another server
		 */

		return NULL;
	}

	return hostend;

}  /* XX_httplib_get_rel_url_at_current_server */
