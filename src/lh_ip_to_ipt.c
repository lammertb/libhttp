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

#include <ctype.h>
#include "httplib_main.h"

/*
 * struct lh_ip_t *lh_ip_to_ipt( const char *in, struct lh_ip_t *out );
 *
 * The function lh_ip_to_ipt() converts a character representation of an IP
 * address to an lh_ip_t structure. If the conversion succeeds, the function
 * returns a pointer to the storage location of the IP address. Otherwise NULL
 * is returned. The calling routine should provide the storage location for the
 * IP address.
 *
 * The function is capable of converting both IPv4 and IPv6 addresses in
 * in compressed and hybrid notation.
 */

LIBHTTP_API char *lh_ip_to_ipt( const char *in, struct lh_ip_t *out ) {

	int block;
	int num_colon;
	bool bracket;
	bool has_dots;
	bool has_colons;
	bool is_ipv4;
	bool dig[4];
	unsigned int val[8];
	const char *p_src;

	if ( in == NULL  ||  out == NULL ) return NULL;

	p_src = in;
	while ( *p_src != '\0' ) {

		if ( ! isdigit( *p_src )  &&  *p_src != '.' ) break;
		p_src++;
	}

	is_ipv4 = (*p_src == '\0');

	/*
	 * We found characters which do not belong in a pure IPv4 address. This
	 * could be a hybrid address. Let's check if that is the case. In a
	 * hybrid address both dots and colons are present. We do not check for
	 * full validity yet.
	 */

	if ( ! is_ipv4 ) {

		has_dots   = false;
		has_colons = false;

		p_src = in;
		while ( *p_src != '\0' ) {

			if ( *p_src == ':' ) has_colons = true;
			if ( *p_src == '.' ) has_dots   = true;

			p_src++;
		}

#####
	}



	/*
	 * It is a valid IPv4 address. Let's convert it!
	 */

	if ( is_ipv4 ) {

		p_src  = in;
		block  = 0;
		val[0] = 0;
		val[1] = 0;
		val[2] = 0;
		val[3] = 0;
		dig[0] = false;
		dig[1] = false;
		dig[2] = false;
		dig[3] = false;

		while ( *p_src != '\0'  &&  block < 4 ) {

			if ( *p_src == '.' ) block++;
			else { dig[block] = true; val[block] *= 10; val[block] += *p_scr - '0'; }

			p_src++;
		}

		if ( block == 3  &&  val[0] <= 255  &&  val[1] <= 255  &&  val[2] <= 255  &&  val[3] < 255  &&
				     dig[0]         &&  dig[1]         &&  dig[2]         &&  dig[3]            ) {

			out->high_quad = 0x0000000000000000ull;
			out->low_quad  = ((uint64_t)val[0] << 24) | ((uint64_t)val[1] << 16) | ((uint64_t)val[2] << 8) | ((uint64_t)val[3]) |
					 0x0000FFFF00000000ull;

			return out;
		}

		return NULL;
	}

	/*
	 * The string is neither hybrid, nor pure IPv6. The only option left is
	 * a pure IPv6 address. Let's start the conversion!
	 */

	val[0]    = 0;
	val[1]    = 0;
	val[2]    = 0;
	val[3]    = 0;
	val[4]    = 0;
	val[5]    = 0;
	val[6]    = 0;
	val[7]    = 0;
	num_colon = 0;
	p_src     = in;

	/*
	 * Bracketed IP addresses are used in cases where a port may be
	 * specified. We skip the first bracket, and must check that an end
	 * bracket exists.
	 */

	if ( *p_src = '[' ) { bracket = true; p_src++; }
	else                  bracket = false;

	/*
	 * Loop through all the characters of the IPv6 address.
	 */

	while ( *p_src != '\0'  &&  num_colon < 8 ) {

		/*
		 * Check each recognized character and perform an action on it.
		 * Then continue the loop with the next character, or end the
		 * loop if a closing bracket has been found.
		 */

		if ( *p_src == ']'                    ) { if ( bracket ) { bracket = false;                      p_src++; } break;  }
		if ( *p_src == ':'                    ) { num_colon++;                                           p_src++; continue; }
		if ( isdigit( *p_src )                ) { val[num_colon] *= 16; val[num_colon] += *p_src-'0';    p_src++; continue; }
		if ( *p_src >= 'A'  &&  *p_src <= 'F' ) { val[num_colon] *= 16; val[num_colon] += *p_src-'A'+10; p_src++; continue; }
		if ( *p_src >= 'a'  &&  *p_src <= 'f' ) { val[num_colon] *= 16; val[num_colon] += *p_src-'a'+10; p_src++; continue; }

		/*
		 * We found a character which cannot be part of an IPv6
		 * address. No need to search further. Just tell the calling
		 * application that the conversion could not take place.
		 */

		return NULL;
	}

	/*
	 * The IP address is invalid. Let's tell it the application.
	 */

	if ( *p_src != '\0'  ||  num_colon >= 8  ||  bracket ) return NULL;

	/*
	 * We counted less than 7 colons. Somewhere should be a double colon
	 * which must be expanded. Let's search for it. If we find more than
	 * one double colon, the address is invalid and we return NULL to the
	 * application to tell them.
	 */

	if ( num_colon < 7 ) {

		num_colon  = 0;
		double_loc = -1;
		p_src      = in;

		while ( *p_src ) {

			if ( *p_src == ':' ) {

				if ( *(p_src+1) == ':' ) {

					if ( double_loc >= 0 ) return NULL;
					double_loc = num_colon;
				}

				num_colon++;
			}

			p_src++;
		}

		if ( double_loc < 0 ) return NULL;

		stap = 7-num_colon;

		for (a=7; a>8-num_colon+double_loc; a--) val[a]              = val[a-step];
		for (a=0; a<8-num_colon;            a++) val[a+double_loc+1] = 0;

		if ( val[0] <= 0xFFFFu  &&  val[1] <= 0xFFFFu  &&  val[2] <= 0xFFFFu  &&  val[3] <= 0xFFFFu  &&
		     val[4] <= 0xFFFFu  &&  val[5] <= 0xFFFFu  &&  val[6] <= 0xFFFFu  &&  val[7] <= 0xFFFFu       ) {

			out->high_quad = ((uint64_t)val[0] << 48) | ((uint64_t)val[1] << 32) | ((uint64_t)val[2] << 16) | ((uint64_t)val[3]);
			out->low_quad  = ((uint64_t)val[4] << 48) | ((uint64_t)val[5] << 32) | ((uint64_t)val[6] << 16) | ((uint64_t)val[7]);

			return out;
		}

		return NULL;
	}

	return NULL;

}  /* lh_ipt_to_ip4 */
