/* 
 * Copyright (c) 2016 Lammert Bies
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

#include <ctype.h>
#include "httplib_main.h"

/*
 * bool XX_httplib_option_value_to_int( const char *value, int *config );
 *
 * The function XX_httplib_option_value_to_bool() returns an integer value
 * represented by an option value in a location pointed to by a parameter.
 * If this succeeds, false is returned. True is returned when an error occured.
 */

bool XX_httplib_option_value_to_int( const char *value, int *config ) {

	const char *ptr;
	int val;
	int sign;

	if ( value == NULL  ||  config == NULL ) return true;

	val  = 0;
	sign = 1;
	ptr  = value;

	if ( *ptr == '-' ) { sign = -1; ptr++; }
	if ( ! isdigit( *ptr ) ) return true;

	while ( isdigit( *ptr ) ) {

		val *= 10;
		val += *ptr - '0';

		ptr++;
	}

	if ( *ptr != '\0' ) return true;

	*config = sign * val;

	return false;

}  /* XX_httplib_option_value_to_int */
