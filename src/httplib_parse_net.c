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

static int	isbyte( int n );

/*
 * int XX_httplib_parse_net( const char *spec, uint32_t *net, uint32_t *mask );
 *
 * The function XX_httplib_parse_net() is used to parse an ASCII representation
 * of a subnet to convert it to a more machine readable binary version.
 */

int XX_httplib_parse_net( const char *spec, uint32_t *net, uint32_t *mask ) {

	int n;
	int a;
	int b;
	int c;
	int d;
	int slash;
	int len;

	slash = 32;
	len   = 0;

	if ( ( sscanf(spec, "%d.%d.%d.%d/%d%n", &a, &b, &c, &d, &slash, &n) == 5  ||
	       sscanf(spec, "%d.%d.%d.%d%n",    &a, &b, &c, &d,         &n) == 4     ) &&
	     isbyte(a)  &&  isbyte(b)  &&  isbyte(c)  &&  isbyte(d)  &&  slash >= 0  &&  slash < 33 ) {

		len   = n;
		*net  = ((uint32_t)a << 24) | ((uint32_t)b << 16) | ((uint32_t)c << 8) | (uint32_t)d;
		*mask = (slash) ? (0xffffffffU << (32 - slash)) : 0;
	}

	return len;

}  /* XX_httplib_parse_net */



/*
 * static int isbyte( int n );
 *
 * The function isbyte() checks if a single value in a decimal IP address
 * representation has a valid value.
 */

static int isbyte( int n ) {

	return n >= 0 && n <= 255;

}  /* isbyte */

