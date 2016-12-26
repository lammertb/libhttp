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

/*
 * char *httplib_strndup( const char *str, size_t len );
 *
 * The function strndup() duplicates a string with a maximum given length to a
 * new string in a newly allocated block of memory. The function is equivalent
 * to the Posix function strndup() with the difference that LibHTTP memory
 * allocation functions are used which allow for tracking of memory leaks
 * through a monitor hook. The size of the allocated memory block is the given
 * length plus one byte for the terminating NUL character.
 *
 * If the duplicate of the string is no longer used, the allocated memory
 * should be returned to the heap with a call to httplib_free.
 *
 * If the function fails, the value NULL is returned, otherwise a pointer to
 * the duplicate.
 */

LIBHTTP_API char *httplib_strndup( const char *str, size_t len ) {

	char *p;

	if ( str == NULL ) return NULL;

	p = httplib_malloc( len+1 );
	if ( p == NULL ) return NULL;

	httplib_strlcpy( p, str, len+1 );

	return p;

}  /* httplib_strndup */
