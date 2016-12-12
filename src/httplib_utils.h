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



void			XX_httplib_addenv( struct cgi_environment *env, PRINTF_FORMAT_STRING(const char *fmt), ... ) PRINTF_ARGS(2, 3);
int			XX_httplib_atomic_dec( volatile int *addr );
int			XX_httplib_atomic_inc( volatile int *addr );
void			XX_httplib_base64_encode( const unsigned char *src, int src_len, char *dst );
double			XX_httplib_difftimespec( const struct timespec *ts_now, const struct timespec *ts_before );
uint64_t		XX_httplib_get_random( void );
void			XX_httplib_gmt_time_string( char *buf, size_t buf_len, time_t *t );
int			XX_httplib_inet_pton( int af, const char *src, void *dst, size_t dstlen );
int			XX_httplib_lowercase( const char *s );
