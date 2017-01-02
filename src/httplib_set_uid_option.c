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
 * bool XX_httplib_set_uid_option( struct lh_ctx_t *ctx );
 *
 * The function XX_httplib_set_uid_option() runs on systems which support it
 * the context in the security environment of a specific user. The function can
 * be called for Windows, but it doesn't do anything because Windows doesn't
 * support the run-as options as available under *nix systems.
 *
 * False is returned in case a problem is detected, true otherwise.
 */

bool XX_httplib_set_uid_option( struct lh_ctx_t *ctx ) {

#if defined(_WIN32)

	return ( ctx != NULL );

#else  /* _WIN32 */

	struct passwd *pw;
	const char *uid;
	char error_string[ERROR_STRING_LEN];

	if ( ctx == NULL ) return false;

	uid = ctx->run_as_user;

	if ( uid == NULL ) return true;

	if      ( (pw = getpwnam(uid)) == NULL ) httplib_cry( LH_DEBUG_CRASH, ctx, NULL, "%s: unknown user [%s]", __func__, uid                  );
	else if ( setgid(pw->pw_gid)   == -1   ) httplib_cry( LH_DEBUG_CRASH, ctx, NULL, "%s: setgid(%s): %s",    __func__, uid, httplib_error_string( ERRNO, error_string, ERROR_STRING_LEN ) );
	else if ( setgroups(0, NULL)           ) httplib_cry( LH_DEBUG_CRASH, ctx, NULL, "%s: setgroups(): %s",   __func__,      httplib_error_string( ERRNO, error_string, ERROR_STRING_LEN ) );
	else if ( setuid(pw->pw_uid)   == -1   ) httplib_cry( LH_DEBUG_CRASH, ctx, NULL, "%s: setuid(%s): %s",    __func__, uid, httplib_error_string( ERRNO, error_string, ERROR_STRING_LEN ) );
	else return true;

	return false;

#endif /* !_WIN32 */

}  /* XX_httplib_set_uid_option */
