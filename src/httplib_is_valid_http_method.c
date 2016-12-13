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
 * bool XX_httplib_is_valid_http_method( const char *method );
 *
 * The function XX_httplib_is_valid_http_method() checks if the method in a
 * request is a valid method.
 */

bool XX_httplib_is_valid_http_method( const char *method ) {

	return !strcmp(method, "GET")        /* HTTP (RFC 2616) */
	       || !strcmp(method, "POST")    /* HTTP (RFC 2616) */
	       || !strcmp(method, "HEAD")    /* HTTP (RFC 2616) */
	       || !strcmp(method, "PUT")     /* HTTP (RFC 2616) */
	       || !strcmp(method, "DELETE")  /* HTTP (RFC 2616) */
	       || !strcmp(method, "OPTIONS") /* HTTP (RFC 2616) */
	       /* TRACE method (RFC 2616) is not supported for security reasons */
	       || !strcmp(method, "CONNECT") /* HTTP (RFC 2616) */

	       || !strcmp(method, "PROPFIND") /* WEBDAV (RFC 2518) */
	       || !strcmp(method, "MKCOL")    /* WEBDAV (RFC 2518) */

	       /* Unsupported WEBDAV Methods: */
	       /* PROPPATCH, COPY, MOVE, LOCK, UNLOCK (RFC 2518) */
	       /* + 11 methods from RFC 3253 */
	       /* ORDERPATCH (RFC 3648) */
	       /* ACL (RFC 3744) */
	       /* SEARCH (RFC 5323) */
	       /* + MicroSoft extensions
	        * https://msdn.microsoft.com/en-us/library/aa142917.aspx */

	       /* PATCH method only allowed for CGI/Lua/LSP and callbacks. */
	       || !strcmp(method, "PATCH"); /* PATCH method (RFC 5789) */

}  /* XX_httplib_is_valid_http_method */
