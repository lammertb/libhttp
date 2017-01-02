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

#define LEAP_YEAR(x)	( ((x)%4) == 0  &&  ( ((x)%100) != 0  ||  ((x)%400) == 0 ) )

void			XX_httplib_addenv( struct lh_ctx_t *ctx, struct cgi_environment *env, PRINTF_FORMAT_STRING(const char *fmt), ... ) PRINTF_ARGS(3, 4);
double			XX_httplib_difftimespec( const struct timespec *ts_now, const struct timespec *ts_before );
void			XX_httplib_gmt_time_string( char *buf, size_t buf_len, time_t *t );
int			XX_httplib_inet_pton( int af, const char *src, void *dst, size_t dstlen );
int			XX_httplib_lowercase( const char *s );

extern const int	XX_httplib_days_per_month[];
