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

void XX_httplib_print_dir_entry( struct lh_ctx_t *ctx, struct de *de ) {

	char size[64];
	char mod[64];
	char href[PATH_MAX * 3 /* worst case */];
	struct tm tmm;

	if ( ctx == NULL ) return;

	if ( de->file.is_directory ) XX_httplib_snprintf( ctx, de->conn, NULL, size, sizeof(size), "%s", "[DIRECTORY]" );
	else {
		/*
		 * We use (signed) cast below because MSVC 6 compiler cannot
		 * convert unsigned __int64 to double. Sigh.
		 */

		if      ( de->file.size <       1024)  XX_httplib_snprintf( ctx, de->conn, NULL, size, sizeof(size), "%d",     (int)   de->file.size                 );
		else if ( de->file.size <   0x100000 ) XX_httplib_snprintf( ctx, de->conn, NULL, size, sizeof(size), "%.1fk", ((double)de->file.size) / 1024.0       );
		else if ( de->file.size < 0x40000000 ) XX_httplib_snprintf( ctx, de->conn, NULL, size, sizeof(size), "%.1fM", ((double)de->file.size) / 1048576.0    );
		else                                   XX_httplib_snprintf( ctx, de->conn, NULL, size, sizeof(size), "%.1fG", ((double)de->file.size) / 1073741824.0 );
	}

	/*
	 * Note: XX_httplib_snprintf will not cause a buffer overflow above.
	 * So, string truncation checks are not required here.
	 */

	if ( httplib_localtime_r( &de->file.last_modified, &tmm ) != NULL ) strftime( mod, sizeof(mod), "%d-%b-%Y %H:%M", &tmm );
	
	else {
		httplib_strlcpy( mod, "01-Jan-1970 00:00", sizeof(mod) );
		mod[sizeof(mod) - 1] = '\0';
	}

	httplib_url_encode( de->file_name, href, sizeof(href) );
	de->conn->num_bytes_sent += httplib_printf( ctx, de->conn,
	              "<tr><td><a href=\"%s%s%s\">%s%s</a></td>"
	              "<td>&nbsp;%s</td><td>&nbsp;&nbsp;%s</td></tr>\n",
	              de->conn->request_info.local_uri,
	              href,
	              de->file.is_directory ? "/" : "",
	              de->file_name,
	              de->file.is_directory ? "/" : "",
	              mod,
	              size );

}  /* XX_httplib_print_dir_entry */
