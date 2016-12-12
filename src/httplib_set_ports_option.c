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



static int parse_port_string( const struct vec *vec, struct socket *so, int *ip_version );



/*
 * int XX_httplib_set_ports_option( struct mg_context *ctx );
 *
 * The function XX_httplib_set_ports_option() set the port options for a
 * context.
 */

int XX_httplib_set_ports_option( struct mg_context *ctx ) {

	const char *list;
	int on = 1;
#if defined(USE_IPV6)
	int off = 0;
#endif
	struct vec vec;
	struct socket so, *ptr;

	struct pollfd *pfd;
	union usa usa;
	socklen_t len;
	int ip_version;

	int portsTotal = 0;
	int portsOk = 0;

	if ( ctx == NULL ) return 0;

	memset(&so, 0, sizeof(so));
	memset(&usa, 0, sizeof(usa));
	len = sizeof(usa);
	list = ctx->config[LISTENING_PORTS];

	while ((list = XX_httplib_next_option(list, &vec, NULL)) != NULL) {

		portsTotal++;

		if (!parse_port_string(&vec, &so, &ip_version)) {
			mg_cry( XX_httplib_fc(ctx),
			       "%.*s: invalid port spec (entry %i). Expecting list of: %s",
			       (int)vec.len,
			       vec.ptr,
			       portsTotal,
			       "[IP_ADDRESS:]PORT[s|r]");
			continue;
		}

#if !defined(NO_SSL)
		if (so.is_ssl && ctx->ssl_ctx == NULL) {

			mg_cry( XX_httplib_fc(ctx), "Cannot add SSL socket (entry %i). Is -ssl_certificate option set?", portsTotal);
			continue;
		}
#endif

		if ((so.sock = socket(so.lsa.sa.sa_family, SOCK_STREAM, 6))
		    == INVALID_SOCKET) {

			mg_cry( XX_httplib_fc(ctx), "cannot create socket (entry %i)", portsTotal);
			continue;
		}

#ifdef _WIN32
		/* Windows SO_REUSEADDR lets many procs binds to a
		 * socket, SO_EXCLUSIVEADDRUSE makes the bind fail
		 * if someone already has the socket -- DTL */
		/* NOTE: If SO_EXCLUSIVEADDRUSE is used,
		 * Windows might need a few seconds before
		 * the same port can be used again in the
		 * same process, so a short Sleep may be
		 * required between mg_stop and mg_start.
		 */
		if (setsockopt(so.sock, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (SOCK_OPT_TYPE)&on, sizeof(on)) != 0) {

			/* Set reuse option, but don't abort on errors. */
			mg_cry( XX_httplib_fc(ctx), "cannot set socket option SO_EXCLUSIVEADDRUSE (entry %i)", portsTotal);
		}
#else
		if (setsockopt(so.sock, SOL_SOCKET, SO_REUSEADDR, (SOCK_OPT_TYPE)&on, sizeof(on)) != 0) {

			/* Set reuse option, but don't abort on errors. */
			mg_cry( XX_httplib_fc(ctx), "cannot set socket option SO_REUSEADDR (entry %i)", portsTotal);
		}
#endif

		if (ip_version > 4) {
#if defined(USE_IPV6)
			if (ip_version == 6) {
				if (so.lsa.sa.sa_family == AF_INET6
				    && setsockopt(so.sock, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&off, sizeof(off)) != 0) {

					/* Set IPv6 only option, but don't abort on errors. */
					mg_cry( XX_httplib_fc(ctx), "cannot set socket option IPV6_V6ONLY (entry %i)", portsTotal);
				}
			}
#else
			mg_cry( XX_httplib_fc(ctx), "IPv6 not available");
			closesocket(so.sock);
			so.sock = INVALID_SOCKET;
			continue;
#endif
		}

		if (so.lsa.sa.sa_family == AF_INET) {

			len = sizeof(so.lsa.sin);
			if (bind(so.sock, &so.lsa.sa, len) != 0) {
				mg_cry( XX_httplib_fc(ctx), "cannot bind to %.*s: %d (%s)", (int)vec.len, vec.ptr, (int)ERRNO, strerror(errno));
				closesocket(so.sock);
				so.sock = INVALID_SOCKET;
				continue;
			}
		}
#if defined(USE_IPV6)
		else if (so.lsa.sa.sa_family == AF_INET6) {

			len = sizeof(so.lsa.sin6);
			if (bind(so.sock, &so.lsa.sa, len) != 0) {
				mg_cry( XX_httplib_fc(ctx), "cannot bind to IPv6 %.*s: %d (%s)", (int)vec.len, vec.ptr, (int)ERRNO, strerror(errno));
				closesocket(so.sock);
				so.sock = INVALID_SOCKET;
				continue;
			}
		}
#endif
		else {
			mg_cry( XX_httplib_fc(ctx), "cannot bind: address family not supported (entry %i)", portsTotal);
			continue;
		}

		if (listen(so.sock, SOMAXCONN) != 0) {

			mg_cry( XX_httplib_fc(ctx), "cannot listen to %.*s: %d (%s)", (int)vec.len, vec.ptr, (int)ERRNO, strerror(errno));
			closesocket(so.sock);
			so.sock = INVALID_SOCKET;
			continue;
		}

		if (getsockname(so.sock, &(usa.sa), &len) != 0
		    || usa.sa.sa_family != so.lsa.sa.sa_family) {

			int err = (int)ERRNO;
			mg_cry( XX_httplib_fc(ctx), "call to getsockname failed %.*s: %d (%s)", (int)vec.len, vec.ptr, err, strerror(errno));
			closesocket(so.sock);
			so.sock = INVALID_SOCKET;
			continue;
		}

/* Update lsa port in case of random free ports */
#if defined(USE_IPV6)
		if (so.lsa.sa.sa_family == AF_INET6) {
			so.lsa.sin6.sin6_port = usa.sin6.sin6_port;
		} else
#endif
		{
			so.lsa.sin.sin_port = usa.sin.sin_port;
		}

		if ((ptr = XX_httplib_realloc(ctx->listening_sockets, (ctx->num_listening_sockets + 1) * sizeof(ctx->listening_sockets[0]))) == NULL) {

			mg_cry( XX_httplib_fc(ctx), "%s", "Out of memory");
			closesocket(so.sock);
			so.sock = INVALID_SOCKET;
			continue;
		}

		if ((pfd = XX_httplib_realloc(
		         ctx->listening_socket_fds,
		         (ctx->num_listening_sockets + 1)
		             * sizeof(ctx->listening_socket_fds[0]))) == NULL) {

			mg_cry( XX_httplib_fc(ctx), "%s", "Out of memory");
			closesocket(so.sock);
			so.sock = INVALID_SOCKET;
			XX_httplib_free(ptr);
			continue;
		}

		XX_httplib_set_close_on_exec(so.sock, XX_httplib_fc(ctx));
		ctx->listening_sockets = ptr;
		ctx->listening_sockets[ctx->num_listening_sockets] = so;
		ctx->listening_socket_fds = pfd;
		ctx->num_listening_sockets++;
		portsOk++;
	}

	if (portsOk != portsTotal) {
		XX_httplib_close_all_listening_sockets(ctx);
		portsOk = 0;
	}

	return portsOk;

}  /* XX_httplib_set_ports_option */



/*
 * static int parse_port_string( const struct vec *vec, struct socket *so, int *ip_version );
 *
 * Valid listening port specification is: [ip_address:]port[s]
 * Examples for IPv4: 80, 443s, 127.0.0.1:3128, 192.0.2.3:8080s
 * Examples for IPv6: [::]:80, [::1]:80,
 *   [2001:0db8:7654:3210:FEDC:BA98:7654:3210]:443s
 *   see https://tools.ietf.org/html/rfc3513#section-2.2
 * In order to bind to both, IPv4 and IPv6, you can either add
 * both ports using 8080,[::]:8080, or the short form +8080.
 * Both forms differ in detail: 8080,[::]:8080 create two sockets,
 * one only accepting IPv4 the other only IPv6. +8080 creates
 * one socket accepting IPv4 and IPv6. Depending on the IPv6
 * environment, they might work differently, or might not work
 * at all - it must be tested what options work best in the
 * relevant network environment.
 */

static int parse_port_string( const struct vec *vec, struct socket *so, int *ip_version ) {

	unsigned int a;
	unsigned int b;
	unsigned int c;
	unsigned int d;
	unsigned int port;
	int ch;
	int len;
#if defined(USE_IPV6)
	char buf[100] = {0};
#endif

	/* MacOS needs that. If we do not zero it, subsequent bind() will fail.
	 * Also, all-zeroes in the socket address means binding to all addresses
	 * for both IPv4 and IPv6 (INADDR_ANY and IN6ADDR_ANY_INIT). */
	memset(so, 0, sizeof(*so));
	so->lsa.sin.sin_family = AF_INET;
	*ip_version = 0;

	if (sscanf(vec->ptr, "%u.%u.%u.%u:%u%n", &a, &b, &c, &d, &port, &len)
	    == 5) {
		/* Bind to a specific IPv4 address, e.g. 192.168.1.5:8080 */
		so->lsa.sin.sin_addr.s_addr =
		    htonl((a << 24) | (b << 16) | (c << 8) | d);
		so->lsa.sin.sin_port = htons((uint16_t)port);
		*ip_version = 4;

#if defined(USE_IPV6)
	} else if (sscanf(vec->ptr, "[%49[^]]]:%u%n", buf, &port, &len) == 2
	           && XX_httplib_inet_pton( AF_INET6, buf, &so->lsa.sin6, sizeof(so->lsa.sin6))) {
		/* IPv6 address, examples: see above */
		/* so->lsa.sin6.sin6_family = AF_INET6; already set by mg_inet_pton
		 */
		so->lsa.sin6.sin6_port = htons((uint16_t)port);
		*ip_version = 6;
#endif

	} else if ((vec->ptr[0] == '+')
	           && (sscanf(vec->ptr + 1, "%u%n", &port, &len) == 1)) {

		/* Port is specified with a +, bind to IPv6 and IPv4, INADDR_ANY */
		/* Add 1 to len for the + character we skipped before */
		len++;

#if defined(USE_IPV6)
		/* Set socket family to IPv6, do not use IPV6_V6ONLY */
		so->lsa.sin6.sin6_family = AF_INET6;
		so->lsa.sin6.sin6_port = htons((uint16_t)port);
		*ip_version = 4 + 6;
#else
		/* Bind to IPv4 only, since IPv6 is not built in. */
		so->lsa.sin.sin_port = htons((uint16_t)port);
		*ip_version = 4;
#endif

	} else if (sscanf(vec->ptr, "%u%n", &port, &len) == 1) {
		/* If only port is specified, bind to IPv4, INADDR_ANY */
		so->lsa.sin.sin_port = htons((uint16_t)port);
		*ip_version = 4;

	} else {
		/* Parsing failure. Make port invalid. */
		port = 0;
		len = 0;
	}

	/* sscanf and the option splitting code ensure the following condition
	 */
	if ((len < 0) && ((unsigned)len > (unsigned)vec->len)) {
		*ip_version = 0;
		return 0;
	}
	ch = vec->ptr[len]; /* Next character after the port number */
	so->is_ssl    = (ch == 's');
	so->ssl_redir = (ch == 'r');

	/* Make sure the port is valid and vector ends with 's', 'r' or ',' */
	if (XX_httplib_is_valid_port(port) && (ch == '\0' || ch == 's' || ch == 'r' || ch == ',')) return 1;

	/* Reset ip_version to 0 of there is an error */
	*ip_version = 0;
	return 0;

}  /* parse_port_string */

