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
 * Return 1 on success. Always initializes the ah structure.
 */

int XX_httplib_parse_auth_header( const struct lh_ctx_t *ctx, struct lh_con_t *conn, char *buf, size_t buf_size, struct ah *ah ) {

	char *name;
	char *value;
	char *s;
	const char *auth_header;
	uint64_t nonce;

	if ( ctx == NULL  ||  ah == NULL  ||  conn == NULL ) return 0;

	memset( ah, 0, sizeof(*ah) );
	if ( (auth_header = httplib_get_header( conn, "Authorization" )) == NULL  ||  httplib_strncasecmp( auth_header, "Digest ", 7 ) != 0 ) return 0;

	/*
	 * Make modifiable copy of the auth header
	 */

	httplib_strlcpy( buf, auth_header + 7, buf_size );
	s = buf;

	/*
	 * Parse authorization header
	 */

	for (;;) {

		/*
		 * Gobble initial spaces
		 */

		while ( isspace(*(unsigned char *)s) ) s++;

		name = XX_httplib_skip_quoted( &s, "=", " ", 0 );

		/* 
		 * Value is either quote-delimited, or ends at first comma or space.
		 */

		if (s[0] == '\"') {

			s++;
			value = XX_httplib_skip_quoted( &s, "\"", " ", '\\' );
			if (s[0] == ',') s++;
		}
		
		else value = XX_httplib_skip_quoted( &s, ", ", " ", 0 ); /* IE uses commas, FF uses spaces */
		if (*name == '\0') break;

		if      ( ! strcmp( name, "username" ) ) ah->user     = value;
		else if ( ! strcmp( name, "cnonce"   ) ) ah->cnonce   = value;
		else if ( ! strcmp( name, "response" ) ) ah->response = value;
		else if ( ! strcmp( name, "uri"      ) ) ah->uri      = value;
		else if ( ! strcmp( name, "qop"      ) ) ah->qop      = value;
		else if ( ! strcmp( name, "nc"       ) ) ah->nc       = value;
		else if ( ! strcmp( name, "nonce"    ) ) ah->nonce    = value;
	}

	/*
	 * Read the nonce from the response.
	 */

	if ( ah->nonce == NULL ) return 0;
	s     = NULL;
	nonce = strtoull( ah->nonce, &s, 10 )
		;
	if ( s == NULL  ||  *s != 0 ) return 0;

	/*
	 * Convert the nonce from the client to a number.
	 */

	nonce ^= ctx->auth_nonce_mask;

	/*
	 * The converted number corresponds to the time the nounce has been
	 * created. This should not be earlier than the server start.
	 * Server side nonce check is valuable in all situations but one:
	 * if the server restarts frequently, but the client should not see
	 * that, so the server should accept nonces from previous starts.
	 * However, the reasonable default is to not accept a nonce from a
	 * previous start, so if anyone changed the access rights between
	 * two restarts, a new login is required.
	 */

	if ( nonce < (uint64_t)ctx->start_time ) {

		/*
		 * nonce is from a previous start of the server and no longer valid
		 * (replay attack?)
		 */

		return 0;
	}

	/* Check if the nonce is too high, so it has not (yet) been used by the
	 * server.
	 */

	if ( nonce >= ( (uint64_t)ctx->start_time + ctx->nonce_count ) ) return 0;

	/*
	 * CGI needs it as REMOTE_USER
	 */

	if ( ah->user != NULL ) conn->request_info.remote_user = httplib_strdup( ah->user );
       	else return 0;

	return 1;

}  /* XX_httplib_parse_auth_header */
