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
#include "httplib_utils.h"

/*
 * void XX_httplib_addenv( struct lh_ctx_t *ctx, struct cgi_environment *env, const char *fmt, ... );
 *
 * The function XX_httplib_addenv() adds one item to the environment before
 * a CGI script is called. The environment variable has the form
 * VARIABLE=VALUE\0 an is appended to the buffer. This function assumes that
 * env != NULL and also fmt != NULL.
 *
 * The function assumes that a connection must be present, otherwise calling a
 * CGI script has not much value. Therefore the function will return directly
 * if no connection, or no server context is known.
 */

#if !defined(NO_CGI)

void XX_httplib_addenv( struct lh_ctx_t *ctx, struct cgi_environment *env, const char *fmt, ... ) {

	size_t n;
	size_t space;
	bool truncated;
	char *added;
	va_list ap;

	if ( ctx == NULL  ||  env == NULL  ||  env->conn == NULL ) return;

	/*
	 * Calculate how much space is left in the buffer
	 */

	space = (env->buflen - env->bufused);

	/* Calculate an estimate for the required space */
	n = strlen(fmt) + 2 + 128;

	do {
		if ( space <= n ) {

			/*
			 * Allocate new buffer
			 */

			n     = env->buflen + CGI_ENVIRONMENT_SIZE;
			added = httplib_realloc( env->buf, n );

			if ( added == NULL ) {

				/*
				 * Out of memory
				 */

				httplib_cry( LH_DEBUG_ERROR, ctx, env->conn, "%s: Cannot allocate memory for CGI variable [%s]", __func__, fmt );
				return;
			}

			env->buf    = added;
			env->buflen = n;
			space       = (env->buflen - env->bufused);
		}

		/*
		 * Make a pointer to the free space int the buffer
		 */

		added = env->buf + env->bufused;

		/*
		 * Copy VARIABLE=VALUE\0 string into the free space
		 */

		va_start( ap, fmt );
		XX_httplib_vsnprintf( ctx, env->conn, &truncated, added, (size_t)space, fmt, ap );
		va_end( ap );

		/*
		 * Do not add truncated strings to the environment
		 */

		if ( truncated ) {

			/*
			 * Reallocate the buffer
			 */

			space = 0;
			n     = 1;
		}

	} while ( truncated );

	/*
	 * Calculate number of bytes added to the environment
	 */

	n             = strlen(added) + 1;
	env->bufused += n;

	/*
	 * Now update the variable index
	 */

	space = env->varlen - env->varused;

	if ( space < 2 ) {

		httplib_cry( LH_DEBUG_ERROR, ctx, env->conn, "%s: Cannot register CGI variable [%s]", __func__, fmt );
		return;
	}

	/*
	 * Append a pointer to the added string into the envp array
	 */

	env->var[env->varused] = added;
	env->varused++;

}  /* XX_httplib_addenv */

#endif /* !NO_CGI */
