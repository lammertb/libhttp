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

#define BUFLEN		64

/*
 * char *lh_ipt_to_ip6( const struct lh_ip_t *in, char *buffer, size_t buflen, bool compress );
 *
 * The function lh_ipt_to_ip6() converts an IP address encoded in a lh_ip_t
 * structure to an IPv6 address. The function can generate both a version with
 * all zeros, and a compressed version where the maximum possible amount of
 * zero values has been eliminated. If an error occurs, NULL is returned,
 * otherwise a pointer to the string representation of the address. The caller
 * must provide a buffer large enough to store the resulting string and the
 * NUL terminator.
 */

LIBHTTP_API char *lh_ipt_to_ip6( const struct lh_ip_t *in, char *buffer, size_t buflen, bool compress ) {

	int a;
	int cur_loc;
	int max_loc;
	int max_val;
	int count;
	int num_zeroblock;
	int zero_block[8];
	bool truncated;
	char temp[BUFLEN];
	char *p_src;
	char *p_dst;

	if ( in == NULL  ||  buffer == NULL  ||  buflen < 1 ) return NULL;

	if ( ! compress ) {

		if ( buflen < 40 ) return NULL;

		XX_httplib_snprintf( NULL, NULL, &truncated, buffer, buflen, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x"
						, (unsigned int) ((in->high_quad >> 48) & 0xFFFFu)
						, (unsigned int) ((in->high_quad >> 32) & 0xFFFFu)
						, (unsigned int) ((in->high_quad >> 16) & 0xFFFFu)
						, (unsigned int) ((in->high_quad      ) & 0xFFFFu)
						, (unsigned int) ((in->low_quad  >> 48) & 0xFFFFu)
						, (unsigned int) ((in->low_quad  >> 32) & 0xFFFFu)
						, (unsigned int) ((in->low_quad  >> 16) & 0xFFFFu)
						, (unsigned int) ((in->low_quad       ) & 0xFFFFu) );

		if ( truncated ) return NULL;

		return buffer;
	}

	/*
	 * First fill the string with an uncompressed version of the IP
	 * address. We already skip leading zeros by using %x instead of %04x.
	 */

	XX_httplib_snprintf( NULL, NULL, NULL, buffer, buflen, "%x:%x:%x:%x:%x:%x:%x:%x"
						, (unsigned int) ((in->high_quad >> 48) & 0xFFFFu)
						, (unsigned int) ((in->high_quad >> 32) & 0xFFFFu)
						, (unsigned int) ((in->high_quad >> 16) & 0xFFFFu)
						, (unsigned int) ((in->high_quad      ) & 0xFFFFu)
						, (unsigned int) ((in->low_quad  >> 48) & 0xFFFFu)
						, (unsigned int) ((in->low_quad  >> 32) & 0xFFFFu)
						, (unsigned int) ((in->low_quad  >> 16) & 0xFFFFu)
						, (unsigned int) ((in->low_quad       ) & 0xFFFFu) );

	for (a=0; a<8; a++) zero_block[a] = 1;

	p_src         = temp;
	count         = 0;
	num_zeroblock = 8;

	while ( *p_src != '\0'  &&  count < 8 ) {

		/*
		 * Search within the eight blocks and mark those blocks which
		 * contain a nonzero digit. We are not able to reduce those
		 * further and we therefore mark them as non-zero.
		 */

		if ( *p_src == ':'                        ) { count++;                                p_src++; continue; }
		if ( *p_src != '0'  &&  zero_block[count] ) { zero_block[count] = 0; num_zeroblock--; p_src++; continue; }

		p_src++;
	}

	/*
	 * None of the blocks contains the value zero. Further compression is
	 * not possible and we can jump to the end of the function to provide
	 * the caller the string representation of the IP address.
	 */

	if ( num_zeroblock == 0 ) goto end;

	/*
	 * The elements of zero_block[] initially contain the value 1 if the
	 * block contains value 0, and 0 otherwise. We now combine the counters
	 * where the zero_block element of a first zero element contains the
	 * count of sequential blocks which are zero. The counters of other
	 * elements in the same sequence are set to zero.
	 */

	for (a=6; a>=0; a--) { if ( zero_block[a] > 0  &&  zero_block[a+1] > 0 ) { zero_block[a] += zero_block[a+1]; zero_block[a+1] = 0; } }

	/*
	 * Now search the largest sequence of zero blocks. There may be more
	 * than one sequence of zero blocks in an IPv6 address but we can only
	 * convert one to '::'. We want to convert the largest sequence to '..'
	 * because in that way we can compress the most characters.
	 */

	max_loc = 0;
	max_val = 0;

	for (a=0; a<8; a++) { if ( zero_block[a] > max_val ) { max_val = zero_block[a]; max_loc = a; } }

	if ( max_val > 0 ) {

		/*
		 * We have found a location which can be reduced. Let's remove
		 * all zero's from those blocks.
		 */

		cur_loc = 0;
		p_src   = temp;
		p_dst   = temp;
		count   = 0;

		while ( *p_src ) {

			if ( cur_loc >= max_loc  &&  max_val > 0 ) {

				if ( *p_src == '0' ) { p_src++; count++; continue; }
			}

			if ( *p_src == ':' ) {

				if ( cur_loc >= max_loc ) max_val--;
				cur_loc++;
			}

			if ( count > 0 ) *p_dst = *p_src;

			p_src++;
			p_dst++;
		}

		*p_dst = '\0';
		p_src  = temp;
		p_dst  = temp;
		count  = 0;

		/*
		 * Now reduce a possible sequence of more than two colons to ::.
		 */

		while ( *p_src ) {

			if ( *p_src == ':'  &&  *(p_src+1) == ':'  &&  *(p_src+2) == ':' ) { p_src++; count++; continue; }

			if ( count > 0 ) *p_dst = *p_src;

			p_src++;
			p_dst++;
		}

		*p_dst = '\0';
	}

end:
	XX_httplib_snprintf( NULL, NULL, &truncated, buffer, buflen, "%s", temp );

	if ( truncated ) return NULL;

	return buffer;

}  /* lh_ipt_to_ip6 */
