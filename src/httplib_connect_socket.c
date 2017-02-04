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
#include "httplib_ssl.h"
#include "httplib_utils.h"

/*
 * bool XX_httplib_connect_socket();
 *
 * The function XX_httplib_connect_socket() starts a connection over a socket.
 * The context structure may be NULL. The output socket and the socket address
 * may not be null for this function to succeed.
 *
 * The function returns false if an error occured, and true if the connection
 * has been established.
 */

bool XX_httplib_connect_socket( struct lh_ctx_t *ctx, const char *host, int port, int use_ssl, SOCKET *sock, union usa *sa ) {

	int ip_ver;
	char error_string[ERROR_STRING_LEN];

	if ( ctx == NULL ) return false;

	ip_ver = 0;
	*sock  = INVALID_SOCKET;
	memset( sa, 0, sizeof(*sa) );

	if ( host == NULL ) {

		httplib_cry( LH_DEBUG_ERROR, ctx, NULL, "%s: NULL host", __func__ );
		return false;
	}

	if ( port < 0  ||  ! XX_httplib_is_valid_port( (unsigned)port) ) {

		httplib_cry( LH_DEBUG_ERROR, ctx, NULL, "%s: invalid port", __func__ );
		return false;
	}

#if !defined(NO_SSL)

	if ( use_ssl  &&  SSLv23_client_method == NULL ) {

		httplib_cry( LH_DEBUG_ERROR, ctx, NULL, "%s: SSL is not initialized", __func__ );
		return false;
	}
#else  /* NO_SSL */
	UNUSED_PARAMETER(use_ssl);
#endif  /*NO_SSL */

	if (XX_httplib_inet_pton(AF_INET, host, &sa->sin, sizeof(sa->sin))) {

		sa->sin.sin_port = htons((uint16_t)port);
		ip_ver = 4;
	}
	
	else if ( XX_httplib_inet_pton( AF_INET6, host, &sa->sin6, sizeof(sa->sin6) ) ) {

		sa->sin6.sin6_port = htons( (uint16_t)port );
		ip_ver = 6;
	}
	
	else if ( host[0] == '[' ) {

		/*
		 * While getaddrinfo on Windows will work with [::1],
		 * getaddrinfo on Linux only works with ::1 (without []).
		 */

		size_t l = strlen(host+1);
		char *h  = (l > 1) ? httplib_strdup(host+1) : NULL;

		if ( h != NULL ) {

			h[l-1] = 0;

			if ( XX_httplib_inet_pton( AF_INET6, h, &sa->sin6, sizeof(sa->sin6) ) ) {

				sa->sin6.sin6_port = htons( (uint16_t)port );
				ip_ver = 6;
			}
			h = httplib_free( h );
		}
	}

	if ( ip_ver == 0 ) {

		httplib_cry( LH_DEBUG_ERROR, ctx, NULL, "%s: host not found", __func__ );
		return false;
	}

	if      ( ip_ver == 4 ) *sock = socket( PF_INET,  SOCK_STREAM, 0 );
	else if ( ip_ver == 6 ) *sock = socket( PF_INET6, SOCK_STREAM, 0 );

	if ( *sock == INVALID_SOCKET ) {

		httplib_cry( LH_DEBUG_ERROR, ctx, NULL, "%s: socket(): %s", __func__, httplib_error_string( ERRNO, error_string, ERROR_STRING_LEN ) );
		return false;
	}

	XX_httplib_set_close_on_exec( *sock );

	if ( ip_ver == 4  &&  connect( *sock, (struct sockaddr *)&sa->sin,  sizeof(sa->sin)  ) == 0 ) return true;
	if ( ip_ver == 6  &&  connect( *sock, (struct sockaddr *)&sa->sin6, sizeof(sa->sin6) ) == 0 ) return true;

	/*
	 * Not connected
	 */

	httplib_cry( LH_DEBUG_ERROR, ctx, NULL, "%s: connect(%s:%d): %s", __func__, host, port, httplib_error_string( ERRNO, error_string, ERROR_STRING_LEN ) );
	closesocket( *sock );
	*sock = INVALID_SOCKET;

	return false;

}  /* XX_httplib_connect_socket */
