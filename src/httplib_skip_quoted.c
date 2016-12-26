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
 * char *XX_httplib_skip_quoted( char **buf, const char *delimiters, const char *whitespace, char quotechar );
 *
 * The function XX_httplib_skip_quoted() skips characters in an input string
 * until one if the delimiter characters is found. The resulting word is NUL
 * terminated. The delimiter and following white space characters are skipped.
 * The pointer is then advanced to the next word. The return value is a pointer
 * to a NUL terminated word. Delimiters can be quoted with a quote character
 * which is also provided as a parameter.
 *
 * If an error occurs, NULL is returned.
 */

char *XX_httplib_skip_quoted( char **buf, const char *delimiters, const char *whitespace, char quotechar ) {

	char *p;
	char *begin_word;
	char *end_word;
	char *end_whitespace;

	if ( buf == NULL  ||  *buf == NULL ) return NULL;

	begin_word = *buf;
	end_word   = begin_word + strcspn( begin_word, delimiters );

	/*
	 * Check for quotechar
	 */

	if ( end_word > begin_word ) {

		p = end_word - 1;

		while ( *p == quotechar ) {

			/*
			 * While the delimiter is quoted, look for the next delimiter.
			 * This happens, e.g., in calls from XX_httplib_parse_auth_header,
			 * if the user name contains a " character.
			 *
			 * If there is anything beyond end_word, copy it.
			 */

			if ( *end_word != '\0' ) {

				size_t end_off = strcspn( end_word + 1, delimiters );
				memmove( p, end_word, end_off + 1 );
				p        += end_off; /* p must correspond to end_word - 1 */
				end_word += end_off + 1;
			}
			
			else {
				*p = '\0';
				break;
			}
		}
		
		for (p++; p<end_word; p++) *p = '\0';
	}

	if (*end_word == '\0') *buf = end_word;
	
	else {
		end_whitespace = end_word+1 + strspn( end_word+1, whitespace );

		for (p=end_word; p<end_whitespace; p++) *p = '\0';

		*buf = end_whitespace;
	}

	return begin_word;

}  /* XX_httplib_skip_quoted */
