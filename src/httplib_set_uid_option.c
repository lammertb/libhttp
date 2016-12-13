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

/*
 * int XX_httplib_set_uid_option( struct mg_contect *ctx );
 *
 * The function XX_httplib_set_uid_option() runs on systems which support it
 * the context in the security environment of a specific user.
 */

#if !defined(_WIN32)

int XX_httplib_set_uid_option( struct mg_context *ctx ) {

	struct passwd *pw;

	if ( ctx != NULL ) {

		const char *uid = ctx->config[RUN_AS_USER];
		int success = 0;

		if (uid == NULL) success = 1;
		else {
			if      ( (pw = getpwnam(uid)) == NULL ) mg_cry( XX_httplib_fc(ctx), "%s: unknown user [%s]", __func__, uid                  );
			else if ( setgid(pw->pw_gid)   == -1   ) mg_cry( XX_httplib_fc(ctx), "%s: setgid(%s): %s",    __func__, uid, strerror(errno) );
			else if ( setgroups(0, NULL)           ) mg_cry( XX_httplib_fc(ctx), "%s: setgroups(): %s",   __func__,      strerror(errno) );
			else if ( setuid(pw->pw_uid)   == -1   ) mg_cry( XX_httplib_fc(ctx), "%s: setuid(%s): %s",    __func__, uid, strerror(errno) );
			else success = 1;
		}

		return success;
	}
	return 0;

}  /* XX_httplib_set_uid_option */

#endif /* !_WIN32 */
