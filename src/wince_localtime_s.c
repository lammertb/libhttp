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

#if defined(_WIN32_WCE)

#define LEAP_YEAR(x)	( ((x)%4 == 0)  &&  ( ((x)%100) != 0  || ((x)%400) == 0 ) )

static const int	days_per_month = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

/*
 * struct tm *localtime_s( const time_t *ptime, struct tm *ptm );
 *
 * The function localtime_s() returns a converted time to tm structure. This
 * function is not available on all operating systems and this version offers
 * a subsitute for use on Windows CE.
 */

struct tm *localtime_s( const time_t *ptime, struct tm *ptm ) {

	int a;
	int doy;
	int64_t t;
	FILETIME ft;
	FILETIME lft;
	SYSTEMTIME st;
	TIME_ZONE_INFORMATION tzinfo;

	if ( ptm == NULL ) return NULL;

	int64_t t       = ((int64_t)*ptime) * RATE_DIFF + EPOCH_DIFF;
	*(int64_t *)&ft = t;

	FileTimeToLocalFileTime( & ft,  & lft );
	FileTimeToSystemTime(    & lft, & st  );

	ptm->tm_year  = st.wYear  - 1900;
	ptm->tm_mon   = st.wMonth - 1;
	ptm->tm_wday  = st.wDayOfWeek;
	ptm->tm_mday  = st.wDay;
	ptm->tm_hour  = st.wHour;
	ptm->tm_min   = st.wMinute;
	ptm->tm_sec   = st.wSecond;
	ptm->tm_isdst = (GetTimeZoneInformation(&tzinfo) == TIME_ZONE_ID_DAYLIGHT) ? 1 : 0;

	doy           = ptm->tm_mday;
	for (a=0; a<ptm->tm_mon; a++) doy += days_per_month[a];
	if ( ptm->tm_mon >= 2  &&  LEAP_YEAR( ptm->tm_year+1900 ) ) doy++;

	ptm->tm_yday  = doy;

	return ptm;

}  /* localtime_s */

#endif /* defined(_WIN32_WCE) */
