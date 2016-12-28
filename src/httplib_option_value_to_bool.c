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

#include "httplib_main.h"

/*
 * bool XX_httplib_option_value_to_bool( const char *value, bool *config );
 *
 * The function XX_httplib_option_value_to_bool() tries to convert a string
 * value to its boolean representation. If no boolean representation can be
 * found, the function returns true to indicate that further processing should
 * be aborted. Otherwise false is returned and the bool parameter is set to the
 * determined value.
 */

bool XX_httplib_option_value_to_bool( const char *value, bool *config ) {

	if ( value == NULL  ||  config == NULL ) return true;

	if ( ! httplib_strcasecmp( value, "true"  ) ) { *config = true;  return false; }
	if ( ! httplib_strcasecmp( value, "false" ) ) { *config = false; return false; }
	if ( ! httplib_strcasecmp( value, "on"    ) ) { *config = true;  return false; }
	if ( ! httplib_strcasecmp( value, "off"   ) ) { *config = false; return false; }
	if ( ! httplib_strcasecmp( value, "yes"   ) ) { *config = true;  return false; }
	if ( ! httplib_strcasecmp( value, "no"    ) ) { *config = false; return false; }
	if ( ! httplib_strcasecmp( value, "1"     ) ) { *config = true;  return false; }
	if ( ! httplib_strcasecmp( value, "0"     ) ) { *config = false; return false; }
	if ( ! httplib_strcasecmp( value, "y"     ) ) { *config = true;  return false; }
	if ( ! httplib_strcasecmp( value, "n"     ) ) { *config = false; return false; }

	return true;

}  /* XX_httplib_option_value_to_bool */
