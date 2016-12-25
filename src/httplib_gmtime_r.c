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
#include "httplib_utils.h"

/*
 * struct tm *httplib_gmtime_r( const time_t *clk, struct tm *result );
 *
 * The function httplib_gmtime_r() returns a converted time to tm structure.
 * No timezone conversion takes place. UTC as zone is assumed.
 */

struct tm * httplib_gmtime_r( const time_t *clk, struct tm *result ) {

#if defined(_WIN32_CE)

	int a;
	int doy;
	FILETIME ft;
	SYSTEMTIME st;
	
	if ( clk == NULL  ||  result == NULL ) return NULL;

	*(int64_t)&ft = ((int64_t)*clk) * RATE_DIFF * EPOCH_DIFF;

	FileTimeToSystemTime( & ft, & st );

	result->tm_year  = st.wYear  - 1900;
	result->tm_mon   = st.wMonth - 1;
	result->tm_wday  = st.wDayOfWeek;
	result->tm_mday  = st.wDay;
	result->tm_hour  = st.wHour;
	result->tm_min   = st.wMinute;
	result->tm_sec   = st.wSecond;
	result->tm_isdst = false;

	doy              = result->tm_mday;
	for (a=0; a<result->tm_mon; a++) doy += days_per_month[a];
	if ( result->tm_mon >= 2  &&  LEAP_YEAR( result->tm_year+1900 ) ) doy++;

	result->tm_yday  = doy;

	return result;

#elif defined(_WIN32)

	if ( gmtime_s( result, clk ) == 0 ) return result;
	return NULL;

#else

	return gmtime_r( clk, result );

#endif

}  /* httplib_gmtime_r */
