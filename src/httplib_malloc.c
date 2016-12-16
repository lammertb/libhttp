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
 * Release: 1.8
 */

#include "httplib_main.h"
#include "httplib_memory.h"

static int64_t				httplib_memory_blocks_used	= 0;
static int64_t				httplib_memory_bytes_used	= 0;

static httplib_alloc_callback_func	alloc_log_func			= NULL;

/*
 * void *XX_httplib_malloc_ex( size_t size, const char *file, unsigned line );
 *
 * The function XX_httplib_malloc_ext() is a hidden function which is
 * substituted for XX_httlib_malloc() with a macro when memory debugging is
 * enabled. The function allocates not only memory, but also updates counters
 * with the total amount of memory allocated. An optional hook function can be
 * called to process information about the memory allocation in the calling
 * program.
 *
 * The first part of the allocated memory is used to store the size to be used
 * later for statistical reasons. The returned pointer is further in the block.
 * The function XX_httplib_malloc_ext() is therefore not compatible with the
 * system free() call to release the memory.
 *
 * The function returns a pointer to the allocated block, or NULL if an error
 * occured.
 */

LIBHTTP_API void *XX_httplib_malloc_ex( size_t size, const char *file, unsigned line ) {

	size_t *data;

	data = malloc( size + sizeof(size_t) );
	if ( data == NULL ) return NULL;

	httplib_memory_bytes_used += size;
	httplib_memory_blocks_used++;

	*data = size;

	if ( alloc_log_func != NULL ) alloc_log_func( file, line, "malloc", size, httplib_memory_blocks_used, httplib_memory_bytes_used );

	return (data+1);

}  /* XX_httplib_malloc_ex */


LIBHTTP_API void *XX_httplib_calloc_ex( size_t count, size_t size, const char *file, unsigned line ) {

	void *data;

	data = XX_httplib_malloc_ex( size*count, file, line );
	if ( data == NULL ) return NULL;

	memset( data, 0x00, size*count );

	return data;

}  /* XX_httplib_calloc_ex */


LIBHTTP_API void XX_httplib_free_ex( void *memory, const char *file, unsigned line ) {

	size_t *data;

	if ( memory == NULL ) return;

	data = ((size_t *)memory) - 1;

	httplib_memory_bytes_used -= *data;
	httplib_memory_blocks_used--;

	if ( alloc_log_func != NULL ) alloc_log_func( file, line, "free", - ((int64_t)*data), httplib_memory_blocks_used, httplib_memory_bytes_used );

	free( data );

}  /* XX_httplib_free_ex */


LIBHTTP_API void *XX_httplib_realloc_ex( void *memory, size_t newsize, const char *file, unsigned line ) {

	size_t *olddata;
	size_t *newdata;
	size_t oldsize;
	int64_t diff;

	if ( newsize == 0 ) {

		if ( memory != NULL ) XX_httplib_free_ex( memory, file, line );
		return NULL;
	}

	if ( memory == NULL ) return XX_httplib_malloc_ex( newsize, file, line );

	olddata = ((size_t *)memory) - 1;
	oldsize = *olddata;
	newdata = realloc( olddata, newsize + sizeof(size_t) );
	if ( newdata == NULL ) return NULL;

	httplib_memory_bytes_used -= oldsize;
	httplib_memory_bytes_used += newsize;

	*newdata = newsize;
	diff     = ((int64_t)newsize) - ((int64_t)oldsize);

	if ( alloc_log_func != NULL ) alloc_log_func( file, line, "realloc", diff, httplib_memory_blocks_used, httplib_memory_bytes_used );

	return (newdata+1);

}  /* XX_httplib_realloc_ex */



/*
 * void httplib_set_alloc_callback_func( httplib_alloc_callback_func log_func );
 *
 * The function httplib_set_alloc_callback_func() sets a callback handler which
 * is called each time memory is allocated from or returned to the heap. In
 * that way the main application can keep track of memory usage and it will be
 * easier to find memory leaks.
 *
 * The callback function may not call any LibHTTP library function as these
 * functions may recursively call internal memory allocation functions causing
 * an infinite loop consuming all available memory.
 *
 * If the parameter NULL is passed as callback function the existing callback
 * is removed.
 */

LIBHTTP_API void httplib_set_alloc_callback_func( httplib_alloc_callback_func log_func ) {

	alloc_log_func = log_func;

}  /* httplib_set_alloc_callback_func */
