/* 
 * Copyright (c) 2016 Lammert Bies
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
 * char *lh_ipt_to_ip4( const struct lh_ip_t *in, char *buffer, size_t buflen, bool hybrid );
 *
 * The function lh_ipt_to_ip4() converts an IP address encoded in a lh_ip_t
 * structure to an IPv4 address. The address must be encoded in ::FFFF:0:0/96
 * format. If an error occurs, NULL is returned, otherwise a string containing
 * the IP address. The caller must supply a buffer which is large enough to
 * hold the resulting string and the NUL terminator character.
 *
 * In hybrid notation, the IP address is returned as ::ffff:aaa.bbb.ccc.ddd
 */

LIBHTTP_API char *lh_ipt_to_ip4( const struct lh_ip_t *in, char *buffer, size_t buflen, bool hybrid ) {

	bool truncated;

	if ( in == NULL  ||  buffer == NULL  ||  buflen < 1                  ) return NULL;
	if (  in->high_quad                         != 0x0000000000000000ull ) return NULL;
	if ( (in->low_quad & 0xFFFFFFFF00000000ull) != 0x0000FFFF00000000ull ) return NULL;


	if ( hybrid ) XX_httplib_snprintf( NULL, NULL, &truncated, buffer, buflen, "::ffff:%u.%u.%u.%u"
					, (unsigned int) ((in->low_quad >> 24) & 0xFFu)
					, (unsigned int) ((in->low_quad >> 16) & 0xFFu)
					, (unsigned int) ((in->low_quad >>  8) & 0xFFu)
					, (unsigned int) ((in->low_quad      ) & 0xFFu) );

	else XX_httplib_snprintf( NULL, NULL, &truncated, buffer, buflen, "%u.%u.%u.%u"
					, (unsigned int) ((in->low_quad >> 24) & 0xFFu)
					, (unsigned int) ((in->low_quad >> 16) & 0xFFu)
					, (unsigned int) ((in->low_quad >>  8) & 0xFFu)
					, (unsigned int) ((in->low_quad      ) & 0xFFu) );

	if ( truncated ) return NULL;

	return buffer;

}  /* lh_ipt_to_ip4 */
