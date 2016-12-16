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



void			XX_httplib_snprintf( const struct httplib_connection *conn, int *truncated, char *buf, size_t buflen, PRINTF_FORMAT_STRING(const char *fmt), ... ) PRINTF_ARGS(5, 6);
const char *		XX_httplib_strcasestr( const char *big_str, const char *small_str );
char *			XX_httplib_strdup( const char *str );
int			XX_httplib_vprintf( struct httplib_connection *conn, const char *fmt, va_list ap );
void			XX_httplib_vsnprintf( const struct httplib_connection *conn, int *truncated, char *buf, size_t buflen, const char *fmt, va_list ap );
