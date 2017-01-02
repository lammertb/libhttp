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
 * bool XX_httplib_must_hide_file( const struct lh_ctx_t *ctx, const char *path );
 *
 * The function XX_httplib_must_hide_file() returns true, if a file must be
 * hidden from browsing by the remote client. A used provided list of file
 * patterns to hide is used. Password files are always hidden, independent of
 * the patterns defined by the user.
 */

bool XX_httplib_must_hide_file( const struct lh_ctx_t *ctx, const char *path ) {

	const char *pw_pattern;
	const char *pattern;

	if ( ctx == NULL ) return false;

	pw_pattern = "**" PASSWORDS_FILE_NAME "$";
	pattern    = ctx->hide_file_pattern;

	return ( pw_pattern != NULL  &&  XX_httplib_match_prefix( pw_pattern, strlen( pw_pattern ), path ) > 0 )  ||
	       ( pattern    != NULL  &&  XX_httplib_match_prefix( pattern,    strlen( pattern ),    path ) > 0 );

}  /* XX_httplib_must_hide_file */
