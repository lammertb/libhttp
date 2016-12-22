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

#if defined(_WIN32)  &&  ! defined(WIN_PTHREADS_TIME_H)

int clock_gettime( clockid_t clk_id, struct timespec *tp ) {

	FILETIME ft;
	ULARGE_INTEGER li;
	double d;
	static double perfcnt_per_sec = 0.0;

	if ( tp == NULL ) return -1;

	memset( tp, 0, sizeof(*tp) );

	if ( clk_id == CLOCK_REALTIME ) {

		GetSystemTimeAsFileTime( & ft );

		li.LowPart   = ft.dwLowDateTime;
		li.HighPart  = ft.dwHighDateTime;
		li.QuadPart -= 116444736000000000;	/* 1.1.1970 in filedate */
		tp->tv_sec   = (time_t)(li.QuadPart / 10000000);
		tp->tv_nsec  = (long)(li.QuadPart % 10000000) * 100;

		return 0;
	}
	
	if (clk_id == CLOCK_MONOTONIC) {

		if ( perfcnt_per_sec == 0.0 ) {

			QueryPerformanceFrequency( (LARGE_INTEGER *) & li );
			perfcnt_per_sec = 1.0 / li.QuadPart;
		}

		if ( perfcnt_per_sec != 0.0 ) {

			QueryPerformanceCounter( (LARGE_INTEGER *) & li );
			d           = li.QuadPart * perfcnt_per_sec;
			tp->tv_sec  = (time_t)d;
			d          -= tp->tv_sec;
			tp->tv_nsec = (long)(d * 1.0E9);

			return 0;
		}
	}

	return -1;

}  /* clock_gettime */

#endif
