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
#include "httplib_memory.h"
#include "httplib_ssl.h"
#include "httplib_string.h"

/*
 * int XX_httplib_connect_socket();
 *
 * The function XX_httplib_connect_socket() starts a connection over a socket.
 * The context structure may be NULL. The output socket and the socket address
 * may not be null for this function to succeed.
 */

int XX_httplib_connect_socket( struct mg_context *ctx, const char *host, int port, int use_ssl, char *ebuf, size_t ebuf_len, SOCKET *sock, union usa *sa ) {

	int ip_ver = 0;

	*sock = INVALID_SOCKET;
	memset(sa, 0, sizeof(*sa));

	if (ebuf_len > 0) *ebuf = 0;

	if (host == NULL) {
		XX_httplib_snprintf(NULL, NULL, ebuf, ebuf_len, "%s", "NULL host");
		return 0;
	}

	if (port < 0 || !XX_httplib_is_valid_port((unsigned)port)) {
		XX_httplib_snprintf(NULL, NULL, ebuf, ebuf_len, "%s", "invalid port");
		return 0;
	}

#if !defined(NO_SSL)
	if (use_ssl && (SSLv23_client_method == NULL)) {
		XX_httplib_snprintf(NULL, NULL, ebuf, ebuf_len, "%s", "SSL is not initialized");
		return 0;
	}
#else
	(void)use_ssl;
#endif

	if (XX_httplib_inet_pton(AF_INET, host, &sa->sin, sizeof(sa->sin))) {
		sa->sin.sin_port = htons((uint16_t)port);
		ip_ver = 4;
#ifdef USE_IPV6
	} else if (XX_httplib_inet_pton(AF_INET6, host, &sa->sin6, sizeof(sa->sin6))) {
		sa->sin6.sin6_port = htons((uint16_t)port);
		ip_ver = 6;
	} else if (host[0] == '[') {
		/* While getaddrinfo on Windows will work with [::1],
		 * getaddrinfo on Linux only works with ::1 (without []). */
		size_t l = strlen(host + 1);
		char *h = (l > 1) ? XX_httplib_strdup(host + 1) : NULL;
		if (h) {
			h[l - 1] = 0;
			if (XX_httplib_inet_pton(AF_INET6, h, &sa->sin6, sizeof(sa->sin6))) {
				sa->sin6.sin6_port = htons((uint16_t)port);
				ip_ver = 6;
			}
			XX_httplib_free(h);
		}
#endif
	}

	if (ip_ver == 0) {
		XX_httplib_snprintf(NULL, NULL, ebuf, ebuf_len, "%s", "host not found");
		return 0;
	}

	if (ip_ver == 4) { *sock = socket(PF_INET, SOCK_STREAM, 0); }
#ifdef USE_IPV6
	else if (ip_ver == 6) { *sock = socket(PF_INET6, SOCK_STREAM, 0); }
#endif

	if (*sock == INVALID_SOCKET) {
		XX_httplib_snprintf(NULL, NULL, ebuf, ebuf_len, "socket(): %s", strerror(ERRNO));
		return 0;
	}

	XX_httplib_set_close_on_exec(*sock, XX_httplib_fc(ctx));

	if ((ip_ver == 4) && (connect(*sock, (struct sockaddr *)&sa->sin, sizeof(sa->sin)) == 0)) {
		/* connected with IPv4 */
		return 1;
	}

#ifdef USE_IPV6
	if ((ip_ver == 6) && (connect(*sock, (struct sockaddr *)&sa->sin6, sizeof(sa->sin6)) == 0)) {
		/* connected with IPv6 */
		return 1;
	}
#endif

	/* Not connected */
	XX_httplib_snprintf(NULL, NULL, ebuf, ebuf_len, "connect(%s:%d): %s", host, port, strerror(ERRNO));
	closesocket(*sock);
	*sock = INVALID_SOCKET;
	return 0;

}  /* XX_httplib_connect_socket */
