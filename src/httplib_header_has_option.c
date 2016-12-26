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
 * bool XX_httplib_header_has_option( const char *header, const char *option );
 *
 * XX_httplib_header_has_option() is a helper function for checking if a comma
 * separated list of values contains the given option (case insensitvely).
 * 'header' can be NULL, in which case false is returned.
 *
 * Please note that not all characters of the option may be checked against the
 * options found in the header because comparison is only for the length of the
 * retrieved header option. TODO: This may or may not be correct.
 */

bool XX_httplib_header_has_option( const char *header, const char *option ) {

	struct vec opt_vec;
	struct vec eq_vec;

	if ( header == NULL  ||  option == NULL  ||  option[0] == '\0' ) return false;

	while ( (header = XX_httplib_next_option( header, &opt_vec, &eq_vec )) != NULL ) {

		if ( httplib_strncasecmp( option, opt_vec.ptr, opt_vec.len ) == 0 ) return true;
	}

	return false;

}  /* XX_httplib_header_has_option */
