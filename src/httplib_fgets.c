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

const char *XX_httplib_fgets( char *buf, size_t size, struct file *filep, char **p ) {

	const char *eof;
	size_t len;
	const char *memend;

	if ( filep == NULL ) return NULL;

	if ( filep->membuf != NULL && *p != NULL ) {

		memend = (const char *)&filep->membuf[filep->size];

		/*
		 * Search for \n from p till the end of stream
		 */

		eof = (char *)memchr(*p, '\n', (size_t)(memend - *p));

		if ( eof != NULL ) eof += 1;		/* Include \n			*/
		else               eof  = memend;	/* Copy remaining data		*/

		len = ((size_t)(eof - *p) > (size - 1)) ? (size - 1) : (size_t)(eof - *p);
		memcpy( buf, *p, len );
		buf[len] = '\0';
		*p      += len;

		return (len) ? eof : NULL;
	}
	
	if ( filep->fp != NULL ) return fgets( buf, (int)size, filep->fp );
	
	return NULL;

}  /* XX_httplib_fgets */
