/* 
 * Copyright (c) 2016-2018 Lammert Bies
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
#include "httplib_utils.h"

/*
 * uint64_t httplib_get_random( void );
 *
 * The function httplib_get_random() is a pseudo random generator which
 * combines two high resolution random generators and the nano second part
 * of the time to generate 64 bit random numbers.
 */

LIBHTTP_API uint64_t httplib_get_random( void ) {

	static uint64_t lfsr = 0;	/* Linear feedback shift register	*/
	static uint64_t lcg  = 0;	/* Linear congruential generator	*/
	struct timespec now;

	memset( & now, 0, sizeof(now) );
	clock_gettime( CLOCK_MONOTONIC, &now );

	if ( lfsr == 0 ) {

		/*
		 * lfsr will be only 0 if has not been initialized,
		 * so this code is called only once.
		 */

		lfsr = (((uint64_t)now.tv_sec) << 21) ^ ((uint64_t)now.tv_nsec) ^ ((uint64_t)(ptrdiff_t)&now) ^ (((uint64_t)time(NULL)) << 33);
		lcg  = (((uint64_t)now.tv_sec) << 25) +  (uint64_t)now.tv_nsec +   (uint64_t)(ptrdiff_t)&now;
	}
	
	else {
		/*
		 * Get the next step of both random number generators.
		 */

		lfsr = (lfsr >> 1) | ((((lfsr >> 0) ^ (lfsr >> 1) ^ (lfsr >> 3) ^ (lfsr >> 4)) & 1) << 63);
		lcg  = lcg * 6364136223846793005ull + 1442695040888963407ull;
	}

	/*
	 * Combining two pseudo-random number generators and a high resolution part
	 * of the current server time will make it hard (impossible?) to guess the
	 * next number.
	 */

	return (lfsr ^ lcg ^ (uint64_t)now.tv_nsec);

}  /* httplib_get_random */
