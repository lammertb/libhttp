/* 
 * Copyright (C) 2016 Lammert Bies
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



#if defined(MEMORY_DEBUGGING)

void *			XX_httplib_calloc_ex( size_t count, size_t size, const char *file, unsigned line );
void			XX_httplib_free_ex( void *memory, const char *file, unsigned line );
void *			XX_httplib_malloc_ex( size_t size, const char *file, unsigned line );
void *			XX_httplib_realloc_ex( void *memory, size_t newsize, const char *file, unsigned line );
#define			XX_httplib_calloc(a, b) XX_httplib_calloc_ex(a, b, __FILE__, __LINE__)
#define			XX_httplib_free(a) XX_httplib_free_ex(a, __FILE__, __LINE__)
#define			XX_httplib_malloc(a) XX_httplib_malloc_ex(a, __FILE__, __LINE__)
#define			XX_httplib_realloc(a, b) XX_httplib_realloc_ex(a, b, __FILE__, __LINE__)

#else  /* MEMORY_DEBUGGING */

void *			XX_httplib_calloc( size_t a, size_t b );
void			XX_httplib_free( void *a );
void *			XX_httplib_malloc( size_t a );
void *			XX_httplib_realloc( void *a, size_t b );

#endif  /* MEMORY_DEBUGGING */

void *			XX_httplib_realloc2( void *ptr, size_t size );
