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
 * int64_t httplib_store_body( struct lh_ctx_t *ctx, struct lh_con_t *conn, const char *path );
 *
 * The function httplib_store_body() stores in incoming body for future
 * processing. The function returns the number of bytes actually read, or a
 * negative number to indicate a failure.
 */

int64_t httplib_store_body( struct lh_ctx_t *ctx, struct lh_con_t *conn, const char *path ) {

	char buf[MG_BUF_LEN];
	int64_t len;
	int ret;
	int n;
	struct file fi;

	if ( ctx == NULL ) return -1;

	len = 0;

	if ( conn->consumed_content != 0 ) {

		httplib_cry( LH_DEBUG_ERROR, ctx, conn, "%s: Contents already consumed", __func__ );
		return -11;
	}

	ret = XX_httplib_put_dir( ctx, conn, path );
	if ( ret < 0 ) {

		/*
		 * -1 for path too long,
		 * -2 for path can not be created.
		 */

		return ret;
	}

	if ( ret != 1 ) {

		/*
		 * Return 0 means, path itself is a directory.
		 */

		return 0;
	}

	if ( XX_httplib_fopen( ctx, conn, path, "w",  & fi ) == 0 ) return -12;

	ret = httplib_read( ctx, conn, buf, sizeof(buf) );

	while ( ret > 0 )  {

		n = (int)fwrite( buf, 1, (size_t)ret, fi.fp );
		if ( n != ret ) {

			XX_httplib_fclose( & fi );
			XX_httplib_remove_bad_file( ctx, conn, path );
			return -13;
		}
		ret = httplib_read( ctx, conn, buf, sizeof(buf) );
	}

	if ( XX_httplib_fclose( & fi ) != 0 ) {

		XX_httplib_remove_bad_file( ctx, conn, path );
		return -14;
	}

	return len;

}  /* httplib_store_body */
