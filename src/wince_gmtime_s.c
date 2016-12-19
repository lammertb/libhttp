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
 * Release: 1.8
 */

#include "httplib_main.h"
#include "httplib_utils.h"

#if defined(_WIN32_WCE)

/*
 * struct tm *gmtime_s( const time_t *ptime, struct tm *ptm );
 *
 * The function gmtime_s() converts a number of seconds since the EPOCH to
 * a tm time structure. This standard function is not available on all
 * platforms and this implementation provides the functionality for Windows CE.
 */

struct tm * gmtime_s( const time_t *ptime, struct tm *ptm ) {

	int a;
	int doy;
	FILETIME ft;
	SYSTEMTIME st;
	
	if ( ptime == NULL  ||  ptm == NULL ) return NULL;

	*(int64_t)&ft = ((int64_t)*ptime) * RATE_DIFF * EPOCH_DIFF;

	FileTimeToSystemTime( & ft, & st );

	ptm->tm_year  = st.wYear  - 1900;
	ptm->tm_mon   = st.wMonth - 1;
	ptm->tm_wday  = st.wDayOfWeek;
	ptm->tm_mday  = st.wDay;
	ptm->tm_hour  = st.wHour;
	ptm->tm_min   = st.wMinute;
	ptm->tm_sec   = st.wSecond;
	ptm->tm_isdst = false;

	doy           = ptm->tm_mday;
	for (a=0; a<ptm->tm_mon; a++) doy += days_per_month[a];
	if ( ptm->tm_mon >= 2  &&  LEAP_YEAR( ptm->tm_year+1900 ) ) doy++;

	ptm->tm_yday  = doy;

	return ptm;

}  /* gmtime_s */

#endif /* defined(_WIN32_WCE) */
