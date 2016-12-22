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
 * This function is called from send_directory() and used for
 * sorting directory entries by size, or name, or modification time.
 * On windows, __cdecl specification is needed in case if project is built
 * with __stdcall convention. qsort always requires __cdels callback.
 */

int WINCDECL XX_httplib_compare_dir_entries( const void *p1, const void *p2 ) {

	int cmp_result;
	const struct de *a;
	const struct de *b;
	const char *query_string;
	bool do_desc;
	bool do_name;
	bool do_size;
	bool do_date;

	if ( p1 == NULL  ||  p2 == NULL ) return 0;

	do_desc      = false;
	do_name      = true;
	do_size      = false;
	do_date      = false;

	a            = p1;
	b            = p2;
	query_string = a->conn->request_info.query_string;

	if ( query_string != NULL ) {

		switch ( query_string[0] ) {

			case 'n' : do_name = true;  do_size = false; do_date = false; break;
			case 's' : do_name = false; do_size = true;  do_date = false; break;
			case 'd' : do_name = false; do_size = false; do_date = true;  break;
		}

		switch ( query_string[1] ) {

			case 'a' : do_desc = false; break;
			case 'd' : do_desc = true;  break;
		}
	}

	if (   a->file.is_directory  &&  ! b->file.is_directory ) return -1; 
	if ( ! a->file.is_directory  &&    b->file.is_directory ) return 1;

	cmp_result = 0;
	if      ( do_name ) cmp_result = strcmp( a->file_name, b->file_name );
	else if ( do_size ) cmp_result = (a->file.size == b->file.size) ? 0 : ((a->file.size > b->file.size) ? 1 : -1);
	else if ( do_date ) cmp_result = (a->file.last_modified == b->file.last_modified) ? 0 : ((a->file.last_modified > b->file.last_modified) ? 1 : -1);

	return ( do_desc ) ? -cmp_result : cmp_result;

}  /* XX_httplib_compare_dir_entries */
