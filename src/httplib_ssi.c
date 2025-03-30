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

static void send_ssi_file( struct lh_ctx_t *ctx, struct lh_con_t *conn, const char *, struct file *, int );


static void do_ssi_include( struct lh_ctx_t *ctx, struct lh_con_t *conn, const char *ssi, char *tag, int include_level ) {

	char file_name[MG_BUF_LEN];
	char path[512];
	char error_string[ERROR_STRING_LEN];
	const char *doc_root;
	const char *ssi_ext;
	char *p;
	struct file file = STRUCT_FILE_INITIALIZER;
	size_t len;
	bool truncated;

	if ( ctx == NULL  ||  conn == NULL  ||  ctx->document_root == NULL ) return;

	truncated = false;

	/*
	 * sscanf() is safe here, since send_ssi_file() also uses buffer
	 * of size MG_BUF_LEN to get the tag. So strlen(tag) is
	 * always < MG_BUF_LEN.
	 */

	if ( sscanf( tag, " virtual=\"%511[^\"]\"", file_name ) == 1 ) {

		/*
		 * File name is relative to the webserver root
		 */

		file_name[511] = 0;
		doc_root       = ctx->document_root;

		XX_httplib_snprintf( ctx, conn, &truncated, path, sizeof(path), "%s/%s", doc_root, file_name );

	}
	
	else if ( sscanf( tag, " abspath=\"%511[^\"]\"", file_name ) == 1 ) {

		/*
		 * File name is relative to the webserver working directory
		 * or it is absolute system path
		 */

		file_name[511] = 0;
		XX_httplib_snprintf( ctx, conn, &truncated, path, sizeof(path), "%s", file_name );

	}
	
	else if ( sscanf( tag, " file=\"%511[^\"]\"", file_name ) == 1  ||  sscanf( tag, " \"%511[^\"]\"", file_name ) == 1 ) {

		/*
		 * File name is relative to the currect document
		 */

		file_name[511] = 0;
		XX_httplib_snprintf( ctx, conn, &truncated, path, sizeof(path), "%s", ssi );

		if ( ! truncated ) {

			if ( (p = strrchr( path, '/' )) != NULL) p[1] = '\0';
			len = strlen( path );
			XX_httplib_snprintf( ctx, conn, &truncated, path + len, sizeof(path) - len, "%s", file_name );
		}

	}
	
	else {
		httplib_cry( LH_DEBUG_ERROR, ctx, conn, "%s: bad SSI #include: [%s]", __func__, tag );
		return;
	}

	if ( truncated ) {

		httplib_cry( LH_DEBUG_ERROR, ctx, conn, "%s: SSI #include path length overflow: [%s]", __func__, tag );
		return;
	}

	if ( ! XX_httplib_fopen( ctx, conn, path, "rb", &file ) ) {

		httplib_cry( LH_DEBUG_ERROR, ctx, conn, "%s: cannot open SSI #include: [%s]: fopen(%s): %s", __func__, tag, path, httplib_error_string( ERRNO, error_string, ERROR_STRING_LEN ) );
		return;
	}
	
	XX_httplib_fclose_on_exec( ctx, &file, conn );

	ssi_ext = ctx->ssi_pattern;

	if ( ssi_ext != NULL  &&  XX_httplib_match_prefix( ssi_ext, strlen( ssi_ext ), path ) > 0 ) send_ssi_file( ctx, conn, path, &file, include_level+1 );
	else XX_httplib_send_file_data( ctx, conn, &file, 0, INT64_MAX );

	XX_httplib_fclose( & file );

}  /* do_ssi_include */


#if !defined(NO_POPEN)
static void do_ssi_exec( struct lh_ctx_t *ctx, struct lh_con_t *conn, char *tag ) {

	char cmd[1024] = "";
	char error_string[ERROR_STRING_LEN];
	struct file file = STRUCT_FILE_INITIALIZER;

	if ( sscanf(tag, " \"%1023[^\"]\"", cmd) != 1 ) {

		httplib_cry( LH_DEBUG_ERROR, ctx, conn, "%s: bad SSI #exec: [%s]", __func__, tag );
	}
	
	else {
		cmd[1023] = 0;
		if ( (file.fp = popen( cmd, "r" ) ) == NULL ) {

			httplib_cry( LH_DEBUG_ERROR, ctx, conn, "%s: cannot SSI #exec: [%s]: %s", __func__, cmd, httplib_error_string( ERRNO, error_string, ERROR_STRING_LEN ) );
		}
		
		else {
			XX_httplib_send_file_data( ctx, conn, &file, 0, INT64_MAX );
			pclose( file.fp );
		}
	}
}
#endif /* !NO_POPEN */


static int httplib_fgetc( struct file *filep, int offset ) {

	if ( filep         == NULL                                                              ) return EOF;
	if ( filep->membuf != NULL  &&  offset >= 0  &&  ((unsigned int)(offset)) < filep->size ) return ((const unsigned char *)filep->membuf)[offset];
	if ( filep->fp     != NULL                                                              ) return fgetc( filep->fp );

	return EOF;

}  /* httplib_fgetc */


static void send_ssi_file( struct lh_ctx_t *ctx, struct lh_con_t *conn, const char *path, struct file *filep, int include_level ) {

	char buf[MG_BUF_LEN];
	int ch;
	int offset;
	int len;
	int in_ssi_tag;

	if ( include_level > ctx->ssi_include_depth ) {

		httplib_cry( LH_DEBUG_ERROR, ctx, conn, "%s: SSI #include level is too deep (%s)", __func__, path );
		return;
	}

	in_ssi_tag = 0;
	len        = 0;
	offset     = 0;

	while ( (ch = httplib_fgetc( filep, offset )) != EOF ) {

		if ( in_ssi_tag  &&  ch == '>' ) {

			in_ssi_tag = 0;
			buf[len++] = (char)ch;
			buf[len]   = '\0';

			if ( len > (int)sizeof(buf) ) break;

			if ( len < 6  ||  memcmp( buf, "<!--#", 5 ) != 0 ) {

				/*
				 * Not an SSI tag, pass it
				 */

				httplib_write( ctx, conn, buf, (size_t)len );
			}
			
			else {
				if ( (len > 12) && ! memcmp( buf + 5, "include", 7 ) ) {

					do_ssi_include( ctx, conn, path, buf+12, include_level );
				}
#if !defined(NO_POPEN)
				else if ( (len > 9) &&  ! memcmp( buf+5, "exec", 4 ) ) {

					do_ssi_exec( ctx, conn, buf+9 );
				}
#endif /* !NO_POPEN */
				else httplib_cry( LH_DEBUG_ERROR, ctx, conn, "%s: %s: unknown SSI command: \"%s\"", __func__, path, buf );
			}

			len = 0;
		}
		
		else if ( in_ssi_tag ) {

			if ( len == 5  &&  memcmp( buf, "<!--#", 5 ) != 0 ) {

				/*
				 * Not an SSI tag
				 */

				in_ssi_tag = 0;
			}
			
			else if ( len == (int)sizeof(buf) - 2 ) {

				httplib_cry( LH_DEBUG_ERROR, ctx, conn, "%s: %s: SSI tag is too large", __func__, path );
				len = 0;
			}

			buf[len++] = (char)(ch & 0xff);
		}
		
		else if ( ch == '<' ) {

			in_ssi_tag = 1;

			if ( len > 0 ) httplib_write( ctx, conn, buf, (size_t)len );

			len = 0;
			buf[len++] = (char)(ch & 0xff);
		}
		
		else {
			buf[len++] = (char)(ch & 0xff);

			if (len == (int)sizeof(buf)) {

				httplib_write( ctx, conn, buf, (size_t)len );
				len = 0;
			}
		}
	}

	/*
	 * Send the rest of buffered data
	 */

	if (len > 0) httplib_write( ctx, conn, buf, (size_t)len );

}  /* send_ssi_file */


void XX_httplib_handle_ssi_file_request( struct lh_ctx_t *ctx, struct lh_con_t *conn, const char *path, struct file *filep ) {

	char date[64];
	char error_string[ERROR_STRING_LEN];
	time_t curtime;
	const char *cors1;
	const char *cors2;
	const char *cors3;

	if ( ctx == NULL  ||  conn == NULL  ||  path == NULL  ||  filep == NULL ) return;

	curtime = time( NULL );

	if ( httplib_get_header( conn, "Origin" ) ) {

		/*
		 * Cross-origin resource sharing (CORS).
		 */

		cors1 = "Access-Control-Allow-Origin: ";
		cors2 = ( ctx->access_control_allow_origin != NULL ) ? ctx->access_control_allow_origin : "";
		cors3 = "\r\n";
	}
	
	else {
		cors1 = "";
		cors2 = "";
		cors3 = "";
	}

	if ( ! XX_httplib_fopen( ctx, conn, path, "rb", filep ) ) {

		/*
		 * File exists (precondition for calling this function),
		 * but can not be opened by the server.
		 */

		XX_httplib_send_http_error( ctx, conn, 500, "Error: Cannot read file\nfopen(%s): %s", path, httplib_error_string( ERRNO, error_string, ERROR_STRING_LEN ) );
	}
	
	else {
		conn->must_close = true;

		XX_httplib_gmt_time_string( date, sizeof(date), &curtime );
		XX_httplib_fclose_on_exec( ctx, filep, conn );
		httplib_printf( ctx, conn, "HTTP/1.1 200 OK\r\n" );
		XX_httplib_send_no_cache_header( ctx, conn );
		httplib_printf( ctx, conn, "%s%s%s" "Date: %s\r\n" "Content-Type: text/html\r\n" "Connection: %s\r\n\r\n", cors1, cors2, cors3, date, XX_httplib_suggest_connection_header( ctx, conn ) );
		send_ssi_file( ctx, conn, path, filep, 0 );
		XX_httplib_fclose( filep );
	}

}  /* XX_httplib_handle_ssi_file_request */
