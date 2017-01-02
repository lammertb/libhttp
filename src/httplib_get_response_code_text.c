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
 * const char *httplib_get_response_code_text( struct lh_ctx_t *ctx, struct lh_con_t *conn, int response_code );
 *
 * The function httplib_get_response_code_text() returns a text associated with an
 * HTTP response code.
 */

const char *httplib_get_response_code_text( struct lh_ctx_t *ctx, struct lh_con_t *conn, int response_code ) {

	/*
	 * See IANA HTTP status code assignment:
	 * http://www.iana.org/assignments/http-status-codes/http-status-codes.xhtml
	 */

	switch ( response_code ) {

		case 100 : return "Continue";				/* RFC2616 Section 10.1.1					*/
		case 101 : return "Switching Protocols";		/* RFC2616 Section 10.1.2					*/
		case 102 : return "Processing";				/* RFC2518 Section 10.1						*/

		case 200 : return "OK";					/* RFC2616 Section 10.2.1					*/
		case 201 : return "Created";				/* RFC2616 Section 10.2.2					*/
		case 202 : return "Accepted";				/* RFC2616 Section 10.2.3					*/
		case 203 : return "Non-Authoritative Information";	/* RFC2616 Section 10.2.4					*/
		case 204 : return "No Content";				/* RFC2616 Section 10.2.5					*/
		case 205 : return "Reset Content";			/* RFC2616 Section 10.2.6					*/
		case 206 : return "Partial Content";			/* RFC2616 Section 10.2.7					*/
		case 207 : return "Multi-Status";			/* RFC2518 Section 10.2, RFC4918 Section 11.1			*/
		case 208 : return "Already Reported";			/* RFC5842 Section 7.1						*/
		case 226 : return "IM used";				/* RFC3229 Section 10.4.1					*/

		case 300 : return "Multiple Choices";			/* RFC2616 Section 10.3.1					*/
		case 301 : return "Moved Permanently";			/* RFC2616 Section 10.3.2					*/
		case 302 : return "Found";				/* RFC2616 Section 10.3.3					*/
		case 303 : return "See Other";				/* RFC2616 Section 10.3.4					*/
		case 304 : return "Not Modified";			/* RFC2616 Section 10.3.5					*/
		case 305 : return "Use Proxy";				/* RFC2616 Section 10.3.6					*/
		case 307 : return "Temporary Redirect";			/* RFC2616 Section 10.3.8					*/
		case 308 : return "Permanent Redirect";			/* RFC7238 Section 3						*/

		case 400 : return "Bad Request";			/* RFC2616 Section 10.4.1					*/
		case 401 : return "Unauthorized";			/* RFC2616 Section 10.4.2					*/
		case 402 : return "Payment Required";			/* RFC2616 Section 10.4.3					*/
		case 403 : return "Forbidden";				/* RFC2616 Section 10.4.4					*/
		case 404 : return "Not Found";				/* RFC2616 Section 10.4.5					*/
		case 405 : return "Method Not Allowed";			/* RFC2616 Section 10.4.6					*/
		case 406 : return "Not Acceptable";			/* RFC2616 Section 10.4.7					*/
		case 407 : return "Proxy Authentication Required";	/* RFC2616 Section 10.4.8					*/
		case 408 : return "Request Time-out";			/* RFC2616 Section 10.4.9					*/
		case 409 : return "Conflict";				/* RFC2616 Section 10.4.10					*/
		case 410 : return "Gone";				/* RFC2616 Section 10.4.11					*/
		case 411 : return "Length Required";			/* RFC2616 Section 10.4.12					*/
		case 412 : return "Precondition Failed";		/* RFC2616 Section 10.4.13					*/
		case 413 : return "Request Entity Too Large";		/* RFC2616 Section 10.4.14					*/
		case 414 : return "Request-URI Too Large";		/* RFC2616 Section 10.4.15					*/
		case 415 : return "Unsupported Media Type";		/* RFC2616 Section 10.4.16					*/
		case 416 : return "Requested range not satisfiable";	/* RFC2616 Section 10.4.17					*/
		case 417 : return "Expectation Failed";			/* RFC2616 Section 10.4.18					*/
		case 418 : return "I am a teapot";			/* RFC2324 Section 2.3.2					*/
		case 419 : return "Authentication Timeout";		/* common use							*/
		case 420 : return "Enhance Your Calm";			/* common use							*/
		case 421 : return "Misdirected Request";		/* RFC7540 Section 9.1.2					*/
		case 422 : return "Unproccessable entity";		/* RFC2518 Section 10.3, RFC4918 Section 11.2			*/
		case 423 : return "Locked";				/* RFC2518 Section 10.4, RFC4918 Section 11.3			*/
		case 424 : return "Failed Dependency";			/* RFC2518 Section 10.5, RFC4918 Section 11.4			*/
		case 426 : return "Upgrade Required";			/* RFC 2817 Section 4						*/
		case 428 : return "Precondition Required";		/* RFC 6585, Section 3						*/
		case 429 : return "Too Many Requests";			/* RFC 6585, Section 4						*/
		case 431 : return "Request Header Fields Too Large";	/* RFC 6585, Section 5						*/
		case 440 : return "Login Timeout";			/* common use							*/
		case 451 : return "Unavailable For Legal Reasons";	/* draft-tbray-http-legally-restricted-status-05, Section 3	*/

		case 500 : return "Internal Server Error";		/* RFC2616 Section 10.5.1					*/
		case 501 : return "Not Implemented";			/* RFC2616 Section 10.5.2					*/
		case 502 : return "Bad Gateway";			/* RFC2616 Section 10.5.3					*/
		case 503 : return "Service Unavailable";		/* RFC2616 Section 10.5.4					*/
		case 504 : return "Gateway Time-out";			/* RFC2616 Section 10.5.5					*/
		case 505 : return "HTTP Version not supported";		/* RFC2616 Section 10.5.6					*/
		case 506 : return "Variant Also Negotiates";		/* RFC 2295, Section 8.1					*/
		case 507 : return "Insufficient Storage";		/* RFC2518 Section 10.6, RFC4918 Section 11.5			*/
		case 508 : return "Loop Detected";			/* RFC5842 Section 7.1						*/
		case 509 : return "Bandwidth Limit Exceeded";		/* common use							*/
		case 510 : return "Not Extended";			/* RFC 2774, Section 7						*/
		case 511 : return "Network Authentication Required";	/* RFC 6585, Section 6						*/


	default:
		/*
		 * This error code is unknown. This should not happen.
		 */

		if ( ctx != NULL  &&  conn != NULL ) httplib_cry( LH_DEBUG_INFO, ctx, conn, "%s: unknown HTTP response code: %u", __func__, response_code );

		/*
		 * Return at least a category according to RFC 2616 Section 10.
		 */

		if (response_code >= 100 && response_code < 200) return "Information";
		if (response_code >= 200 && response_code < 300) return "Success";
		if (response_code >= 300 && response_code < 400) return "Redirection";
		if (response_code >= 400 && response_code < 500) return "Client Error";
		if (response_code >= 500 && response_code < 600) return "Server Error";

		return "";
	}

}  /* httplib_get_response_code_text */
