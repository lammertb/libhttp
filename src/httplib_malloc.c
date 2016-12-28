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

	if ( size == 0 ) {

		if ( alloc_log_func != NULL ) alloc_log_func( file, line, "malloc", 0, httplib_memory_blocks_used, httplib_memory_bytes_used );
		return NULL;
	}

	data = malloc( size + sizeof(size_t) );

	if ( data == NULL ) {
	
		if ( alloc_log_func != NULL ) alloc_log_func( file, line, "malloc", 0, httplib_memory_blocks_used, httplib_memory_bytes_used );
		return NULL;
	}

	httplib_memory_bytes_used += size;
	httplib_memory_blocks_used++;

	*data = size;

	if ( alloc_log_func != NULL ) alloc_log_func( file, line, "malloc", size, httplib_memory_blocks_used, httplib_memory_bytes_used );

	return (data+1);

}  /* XX_httplib_malloc_ex */



/*
 * void *XX_httplib_calloc_ex( size_t count, size_t size, const char *file, unsigned line );
 *
 * The function XX_httplib_calloc_ex() is a hidden memory allocation function
 * called through a macro which adds the filename and line number from where
 * the function has been called.
 *
 * The function provided memory allocation functionality like the standard
 * calloc() function but with added memory tracking and optional a callback
 * to main application with logging information.
 */

LIBHTTP_API void *XX_httplib_calloc_ex( size_t count, size_t size, const char *file, unsigned line ) {

	void *data;

	data = XX_httplib_malloc_ex( size*count, file, line );
	if ( data == NULL ) return NULL;

	memset( data, 0x00, size*count );

	return data;

}  /* XX_httplib_calloc_ex */



/*
 * void *XX_httplib_free_ex( void *memory, const char *file, unsigned file );
 *
 * The function XX_httplib_free_ex() is a hidden function which frees a
 * previously allocated memory object which was allocated with one of the
 * LibHTTP allocation functions. The function has the option to do memory
 * tracking and memory leak debugging through a callback function which can
 * be registered by the main application.
 *
 * The function returns a (void *)NULL pointer which can be used to reset
 * the value of pointers whose contents has been destroyed.
 *
 * It is allowed to pass a NULL pointer to the function. The function will do
 * effectively nothing in that case and just return NULL. This comes in handy
 * when freeing fields in structures which are optional and NULL if not used.
 */

LIBHTTP_API void *XX_httplib_free_ex( void *memory, const char *file, unsigned line ) {

	size_t *data;

	if ( memory == NULL ) return NULL;

	data = ((size_t *)memory) - 1;

	httplib_memory_bytes_used -= *data;
	httplib_memory_blocks_used--;

	if ( alloc_log_func != NULL ) alloc_log_func( file, line, "free", - ((int64_t)*data), httplib_memory_blocks_used, httplib_memory_bytes_used );

	free( data );

	return NULL;

}  /* XX_httplib_free_ex */



/*
 * void *XX_httplib_realloc_ex( void *memory, size_t newsize, const char *file, unsigned line );
 *
 * The function XX_httplib_realloc_ex() is a hidden function used to resize
 * a memory block which has been previously allocated from the heap. A macro is
 * used to call this function together with the file name and line number
 * where the call originates.
 *
 * The function returns a pointer to the new block, or NULL if an error occurs.
 * If NULL is returned because there was not enough space to reallocate the
 * block, the contents of the original block are preserved.
 *
 * Optionally a registered is called to signal the main application about the
 * current and totally allocated memory. This can be used for debugging
 * purposes and finding memory leaks.
 */

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
	if ( newdata == NULL ) {
		
		if ( alloc_log_func != NULL ) alloc_log_func( file, line, "realloc", 0, httplib_memory_blocks_used, httplib_memory_bytes_used );
		return NULL;
	}

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
