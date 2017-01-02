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
 * bool XX_httplib_read_auth_file( struct lh_ctx_t *ctx, struct file *filep, struct read_auth_file_struct *workdata );
 *
 * The function XX_httpib_read_auth_file() loops over the password file to
 * read its contents. Include statements are honored which lets the routine
 * also open and scan child files.
 */

bool XX_httplib_read_auth_file( struct lh_ctx_t *ctx, struct file *filep, struct read_auth_file_struct *workdata ) {

	int is_authorized;
	struct file fp;
	size_t l;
	union {
		const char *	con;
		char *		var;
	} ptr;

	if ( ctx == NULL  ||  filep == NULL  ||  workdata == NULL ) return false;

	is_authorized = false;

	/*
	 * Loop over passwords file
	 */

	ptr.con = filep->membuf;

	while ( XX_httplib_fgets( workdata->buf, sizeof(workdata->buf), filep, &ptr.var ) != NULL ) {

		l = strlen( workdata->buf );

		while ( l > 0 ) {

			if ( isspace(workdata->buf[l-1])  ||  iscntrl(workdata->buf[l-1]) ) {

				l--;
				workdata->buf[l] = 0;
			}
			
			else break;
		}

		if ( l < 1 ) continue;

		workdata->f_user = workdata->buf;

		if ( workdata->f_user[0] == ':' ) {

			/*
			 * user names may not contain a ':' and may not be empty,
			 * so lines starting with ':' may be used for a special purpose
			 */

			if ( workdata->f_user[1] == '#' ) continue;  /* :# is a comment */
			
			else if ( ! strncmp( workdata->f_user + 1, "include=", 8 ) ) {

				if ( XX_httplib_fopen( ctx, workdata->conn, workdata->f_user + 9, "r", &fp ) ) {

					is_authorized = XX_httplib_read_auth_file( ctx, &fp, workdata );
					XX_httplib_fclose( &fp );
				}
				
				else httplib_cry( LH_DEBUG_ERROR, ctx, workdata->conn, "%s: cannot open authorization file: %s", __func__, workdata->buf );

				continue;
			}
			/*
			 * everything is invalid for the moment (might change in the
			 * future)
			 */

			httplib_cry( LH_DEBUG_ERROR, ctx, workdata->conn, "%s: syntax error in authorization file: %s", __func__, workdata->buf );
			continue;
		}

		workdata->f_domain = strchr( workdata->f_user, ':' );

		if ( workdata->f_domain == NULL ) {

			httplib_cry( LH_DEBUG_ERROR, ctx, workdata->conn, "%s: syntax error in authorization file: %s", __func__, workdata->buf );
			continue;
		}

		*(workdata->f_domain) = 0;
		(workdata->f_domain)++;

		workdata->f_ha1 = strchr( workdata->f_domain, ':' );

		if ( workdata->f_ha1 == NULL ) {

			httplib_cry( LH_DEBUG_ERROR, ctx, workdata->conn, "%s: syntax error in authorization file: %s", __func__, workdata->buf );
			continue;
		}

		*(workdata->f_ha1) = 0;
		(workdata->f_ha1)++;

		if ( ! strcmp( workdata->ah.user, workdata->f_user )  &&  ! strcmp( workdata->domain, workdata->f_domain ) ) {

			return XX_httplib_check_password( workdata->conn->request_info.request_method,
							  workdata->f_ha1,
			                                  workdata->ah.uri,
			                                  workdata->ah.nonce,
			                                  workdata->ah.nc,
			                                  workdata->ah.cnonce,
			                                  workdata->ah.qop,
			                                  workdata->ah.response );
		}
	}

	return is_authorized;

}  /* XX_httplib_read_auth_file */
