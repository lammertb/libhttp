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
 * char *lh_ipt_to_ip( const struct lh_ip_t *in, char *buffer, size_t buflen )
 *
 * The function lh_ipt_to_ip() converts an IP address encoded in a lh_ip_t
 * structure to a string representation. This can either be an IPv4 or IPv6
 * address, depending on the value of the IP address. Compression of IPv6
 * addresses is controlled with a parameter and another parameter selects if
 * plain IPv4 or hybrid IPv4 notation must be returned if the address is an
 * IPv4 address.
 *
 * If an error occurs, NULL is returned, otherwise a string containing
 * the IP address. The caller must supply a buffer which is large enough to
 * hold the resulting string and the NUL terminator character.
 *
 * In hybrid notation, the IP address is returned as ::ffff:aaa.bbb.ccc.ddd
 */

LIBHTTP_API char *lh_ipt_to_ip( const struct lh_ip_t *in, char *buffer, size_t buflen, bool compress, bool hybrid ) {

	bool ipv4;

	if ( in == NULL  ||  buffer == NULL  ||  buflen < 1 ) return NULL;

	ipv4 = ( (  in->high_quad                         == 0x0000000000000000ull )  &&
	         ( (in->low_quad & 0xFFFFFFFF00000000ull) == 0x0000FFFF00000000ull )      );

	if ( ipv4 ) return lh_ipt_to_ip4( in, buffer, buflen, hybrid   );
	else        return lh_ipt_to_ip6( in, buffer, buflen, compress );

}  /* lh_ipt_to_ip */
