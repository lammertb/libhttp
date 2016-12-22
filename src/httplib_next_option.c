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
 * A helper function for traversing a comma separated list of values.
 * It returns a list pointer shifted to the next value, or NULL if the end
 * of the list found.
 * Value is stored in val vector. If value has form "x=y", then eq_val
 * vector is initialized to point to the "y" part, and val vector length
 * is adjusted to point only to "x".
 */

const char *XX_httplib_next_option( const char *list, struct vec *val, struct vec *eq_val ) {

	int end;

reparse:
	if ( val == NULL  ||  list == NULL  ||  *list == '\0' ) return NULL;
	
	/*
	 * Skip over leading LWS
	 */

	while ( *list == ' '  ||  *list == '\t' ) list++;

	val->ptr = list;
	if ( (list = strchr( val->ptr, ',' )) != NULL ) {

		/*
		 * Comma found. Store length and shift the list ptr
		 */

		val->len = ((size_t)(list - val->ptr));
		list++;
	}
	
	else {

		/*
		 * This value is the last one
		 */

		list     = val->ptr + strlen(val->ptr);
		val->len = ((size_t)(list - val->ptr));
	}

	/*
	 * Adjust length for trailing LWS
	 */

	end = (int)val->len - 1;
	while ( end >= 0  &&  ( val->ptr[end] == ' ' || val->ptr[end] == '\t' ) ) end--;

	val->len = (size_t)(end + 1);

	if ( val->len == 0 ) goto reparse; /* Ignore any empty entries. */

	if ( eq_val != NULL ) {

		/*
		 * Value has form "x=y", adjust pointers and lengths
		 * so that val points to "x", and eq_val points to "y".
		 */

		eq_val->len = 0;
		eq_val->ptr = (const char *)memchr( val->ptr, '=', val->len );

		if ( eq_val->ptr != NULL ) {

			eq_val->ptr++; /* Skip over '=' character */
			eq_val->len = ((size_t)(val->ptr - eq_val->ptr)) + val->len;
			val->len    = ((size_t)(eq_val->ptr - val->ptr)) - 1;
		}
	}

	return list;

}  /* XX_httplib_next_option */
