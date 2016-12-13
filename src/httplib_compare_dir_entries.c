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

/* This function is called from send_directory() and used for
 * sorting directory entries by size, or name, or modification time.
 * On windows, __cdecl specification is needed in case if project is built
 * with __stdcall convention. qsort always requires __cdels callback. */
int WINCDECL XX_httplib_compare_dir_entries( const void *p1, const void *p2 ) {

	if ( p1 == NULL  ||  p2 == NULL ) return 0;

	int cmp_result;
	const struct de *a = (const struct de *)p1;
	const struct de *b = (const struct de *)p2;
	const char *query_string = a->conn->request_info.query_string;

	if ( query_string == NULL ) query_string = "na";

	if (   a->file.is_directory  &&  ! b->file.is_directory ) return -1; 
	if ( ! a->file.is_directory  &&    b->file.is_directory ) return 1;

	cmp_result = 0;
	if      (query_string[0] == 'n') cmp_result = strcmp( a->file_name, b->file_name );
	else if (query_string[0] == 's') cmp_result = (a->file.size == b->file.size) ? 0 : ((a->file.size > b->file.size) ? 1 : -1);
	else if (query_string[0] == 'd') cmp_result = (a->file.last_modified == b->file.last_modified) ? 0 : ((a->file.last_modified > b->file.last_modified) ? 1 : -1);

	return (query_string[1] == 'd') ? -cmp_result : cmp_result;

}  /* XX_httplib_compare_dir_entries */
