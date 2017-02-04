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
 * void XX_httplib_interpret_uri();
 *
 * The function XX_httplib_interpret_uri() interprets an URI and decides what
 * type of request is involved. The function takes the following parameters:
 *
 * ctx:				in:  The context in which to communicate
 * conn:			in:  The request (must be valid)
 * filename:			out: Filename
 * filename_buf_len:		in:  Size of the filename buffer
 * filep:			out: file structure
 * is_found:			out: file is found (directly)
 * is_script_resource:		out: handled by a script?
 * is_websocket_request:	out: websocket connection?
 * is_put_or_delete_request:	out: put/delete file?
 */

void XX_httplib_interpret_uri( struct lh_ctx_t *ctx, struct lh_con_t *conn, char *filename, size_t filename_buf_len, struct file *filep, bool *is_found, bool *is_script_resource, bool *is_websocket_request, bool *is_put_or_delete_request ) {

/* TODO (high): Restructure this function */

	const char *uri;
	const char *root;
	const char *rewrite;
	struct vec a;
	struct vec b;
	int match_len;
	char gz_path[PATH_MAX];
	char const *accept_encoding;
	bool truncated;
#if !defined(NO_CGI)
	char *p;
	const char *cgi_ext;
#endif  /* !NO_CGI */

	if ( ctx == NULL  ||  conn == NULL  ||  filep == NULL ) return;

	uri  = conn->request_info.local_uri;
	root = ctx->document_root;

	memset( filep, 0, sizeof(*filep) );

	*filename                 = '\0';
	*is_found                 = false;
	*is_script_resource       = false;
	*is_put_or_delete_request = XX_httplib_is_put_or_delete_method( conn );

	*is_websocket_request     = XX_httplib_is_websocket_protocol( conn );

	if ( *is_websocket_request  &&  ctx->websocket_root != NULL ) root = ctx->websocket_root;

	/*
	 * Note that root == NULL is a regular use case here. This occurs,
	 * if all requests are handled by callbacks, so the WEBSOCKET_ROOT
	 * config is not required.
	 */

	if ( root == NULL ) {

		/*
		 * all file related outputs have already been set to 0, just return
		 */

		return;
	}

	/*
	 * Using buf_len - 1 because memmove() for PATH_INFO may shift part
	 * of the path one byte on the right.
	 * If document_root is NULL, leave the file empty.
	 */

	XX_httplib_snprintf( ctx, conn, &truncated, filename, filename_buf_len - 1, "%s%s", root, uri );

	if ( truncated ) goto interpret_cleanup;

	rewrite = ctx->url_rewrite_patterns;

	while ( (rewrite = XX_httplib_next_option( rewrite, &a, &b )) != NULL ) {

		match_len = XX_httplib_match_prefix( a.ptr, a.len, uri );

		if ( match_len > 0 ) {

			XX_httplib_snprintf( ctx, conn, &truncated, filename, filename_buf_len - 1, "%.*s%s", (int)b.len, b.ptr, uri + match_len );
			break;
		}
	}

	if ( truncated ) goto interpret_cleanup;

	/*
	 * Local file path and name, corresponding to requested URI
	 * is now stored in "filename" variable.
	 */

	if ( XX_httplib_stat( ctx, conn, filename, filep ) ) {
#if !defined(NO_CGI)

		/*
		 * File exists. Check if it is a script type.
		 */

		if ( ctx->cgi_pattern != NULL  &&  XX_httplib_match_prefix( ctx->cgi_pattern, strlen( ctx->cgi_pattern ), filename ) > 0 ) {

			/*
			 * The request addresses a CGI script or a Lua script. The URI
			 * corresponds to the script itself (like /path/script.cgi),
			 * and there is no additional resource path
			 * (like /path/script.cgi/something).
			 * Requests that modify (replace or delete) a resource, like
			 * PUT and DELETE requests, should replace/delete the script
			 * file.
			 * Requests that read or write from/to a resource, like GET and
			 * POST requests, should call the script and return the
			 * generated response.
			 */

			*is_script_resource = ! *is_put_or_delete_request;
		}

#endif /* !defined(NO_CGI) */

		*is_found = true;
		return;
	}

	/*
	 * If we can't find the actual file, look for the file
	 * with the same name but a .gz extension. If we find it,
	 * use that and set the gzipped flag in the file struct
	 * to indicate that the response need to have the content-
	 * encoding: gzip header.
	 * We can only do this if the browser declares support.
	 */

	if ( (accept_encoding = httplib_get_header( conn, "Accept-Encoding" )) != NULL ) {

		if ( strstr( accept_encoding, "gzip" ) != NULL ) {

			XX_httplib_snprintf( ctx, conn, &truncated, gz_path, sizeof(gz_path), "%s.gz", filename );

			if ( truncated ) goto interpret_cleanup;

			if ( XX_httplib_stat( ctx, conn, gz_path, filep ) ) {

				if ( filep ) {

					filep->gzipped = 1;
					*is_found      = true;
				}

				/*
				 * Currently gz files can not be scripts.
				 */

				return;
			}
		}
	}

#if !defined(NO_CGI)

	/*
	 * Support PATH_INFO for CGI scripts.
	 */

	for (p = filename+strlen(filename); p > filename + 1; p--) {

		if ( *p == '/' ) {

			*p      = '\0';
			cgi_ext = ctx->cgi_pattern;

			if ( cgi_ext != NULL  &&  XX_httplib_match_prefix( cgi_ext, strlen( cgi_ext ), filename ) > 0  &&  XX_httplib_stat( ctx, conn, filename, filep ) ) {

				/*
				 * Shift PATH_INFO block one character right, e.g.
				 * "/x.cgi/foo/bar\x00" => "/x.cgi\x00/foo/bar\x00"
				 * conn->path_info is pointing to the local variable "path"
				 * declared in XX_httplib_handle_request(), so PATH_INFO is not valid
				 * after XX_httplib_handle_request returns.
				 */

				conn->path_info = p + 1;

				memmove( p + 2, p + 1, strlen(p + 1) + 1 ); /* +1 is for trailing \0 */

				p[1]                = '/';
				*is_script_resource = true;

				break;
			}
			
			else *p = '/';
		}
	}
#endif /* !defined(NO_CGI) */
	return;

/*
 * Reset all outputs
 */

interpret_cleanup:

	memset( filep, 0, sizeof(*filep) );

	*filename                 = 0;
	*is_found                 = false;
	*is_script_resource       = false;
	*is_websocket_request     = false;
	*is_put_or_delete_request = false;

}  /* XX_httplib_interpret_uri */
