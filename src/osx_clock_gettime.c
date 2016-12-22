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
 *
 * ============
 * Release: 2.0
 */

#include "httplib_main.h"

#ifdef __MACH__

/*
 * clock_gettime is not implemented on OSX prior to 10.12
 */

int _civet_clock_gettime( int clk_id, struct timespec *t ) {

	memset( t, 0, sizeof(*t) );

	if ( clk_id == CLOCK_REALTIME ) {

		struct timeval now;
		int rv = gettimeofday( & now, NULL );
		if ( rv ) return rv;

		t->tv_sec  = now.tv_sec;
		t->tv_nsec = now.tv_usec * 1000;

		return 0;

	}
	
	else if (clk_id == CLOCK_MONOTONIC) {

		static uint64_t clock_start_time = 0;
		static mach_timebase_info_data_t timebase_ifo = {0, 0};

		uint64_t now = mach_absolute_time();

		if ( clock_start_time == 0 ) {

			kern_return_t mach_status = mach_timebase_info( & timebase_ifo );
#if defined(DEBUG)
			assert(mach_status == KERN_SUCCESS);
#else  /* DEBUG */
			/* appease "unused variable" warning for release builds */
			(void)mach_status;
#endif  /* DEBUG */
			clock_start_time = now;
		}

		now = (uint64_t)((double)(now - clock_start_time) * (double)timebase_ifo.numer / (double)timebase_ifo.denom);

		t->tv_sec  = now / 1000000000;
		t->tv_nsec = now % 1000000000;

		return 0;
	}
	return -1; /* EINVAL - Clock ID is unknown */

}  /* _civet_clock_gettime */

/*
 * if clock_gettime is declared, then __CLOCK_AVAILABILITY will be defined
 */

#ifdef __CLOCK_AVAILABILITY

/*
 * If we compiled with Mac OSX 10.12 or later, then clock_gettime will be declared
 * but it may be NULL at runtime. So we need to check before using it.
 */

int _civet_safe_clock_gettime( int clk_id, struct timespec *t ) {

	if (clock_gettime) return clock_gettime( clk_id, t );
	return _civet_clock_gettime( clk_id, t );

}  /* _civet_safe_clock_gettime */

#define clock_gettime _civet_safe_clock_gettime
#else  /* __CLOCK_AVAILABILITY */
#define clock_gettime _civet_clock_gettime
#endif  /* __CLOCK_AVAILABILITY */

#endif  /* __MACH__ */
