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
 * Stringify binary data. Output buffer must be twice as big as input,
 * because each byte takes 2 bytes in string representation
 */

static void bin2str(char *to, const unsigned char *p, size_t len) {

	static const char *hex = "0123456789abcdef";

	for (; len--; p++) {

		*to++ = hex[p[0] >> 4];
		*to++ = hex[p[0] & 0x0f];
	}

	*to = '\0';

}  /* bin2str */


/*
 * Return stringified MD5 hash for list of strings. Buffer must be 33 bytes.
 */

char * httplib_md5( char buf[33], ... ) {

	md5_byte_t hash[16];
	const char *p;
	va_list ap;
	md5_state_t ctx;

	md5_init( & ctx );

	va_start( ap, buf );
	while ( (p = va_arg( ap, const char *)) != NULL ) md5_append( & ctx, (const md5_byte_t *)p, strlen( p ) );
	va_end( ap );

	md5_finish( & ctx, hash );
	bin2str( buf, hash, sizeof(hash) );
	return buf;

}  /* httplib_md5 */
