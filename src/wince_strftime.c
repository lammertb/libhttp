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

#define BUFLEN		64

static const char *weekday_l[] = { "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday" };
static const char *weekday_s[] = { "Sun",    "Mon",    "Tue",     "Wed",       "Thu",      "Fri",    "Sat"      };

static const char *month_l[] = { "January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December" };
static const char *month_s[] = { "Jan",     "Feb",      "Mar",   "Apr",   "May", "Jun",  "Jul",  "Aug",    "Sep",       "Oct",     "Nov",      "Dec"      };

/*
 * size_t strftime( char *dst, size_t dst_size, const char *fmt, const struct tm *tmm );
 *
 * On Windows CE systems not all common system functions are available. One of
 * the missing functions is strftime() which is emulated here using other
 * functions available in the Windows CE kernel.
 *
 * Note that this is a rudimentary implementation which doesn't take any
 * regional settings into account. It provides more or less the functionality
 * needed in the library but shouldn't be used for other purposes if an
 * accurate strftime implementation is needed.
 */

size_t strftime( char *dst, size_t dst_size, const char *fmt, const struct tm *tmm ) {

	bool neg_offset;
	long sec_offset;
	long min_offset;
	long hour_offset;
	size_t index;
	const char *ptr;
	char buffer[BUFLEN];

	if ( dst == NULL  ||  dst_size == 0  ||  fmt == NULL  || tmm == NULL ) return 0;

	index = 0;
	
	while ( *fmt  &&  index < dst_size ) {

		if ( *fmt != '%' ) { dst[index++] = *fmt++; continue; }

		fmt++;

		switch ( *fmt ) {

			case '%' :
				dst[index++] = *fmt++;

				continue;



			case 'A' :
				if ( tmm.tm_wday < 0  ||  tmm.tm_wday > 6 ) return 0;
				ptr = weekday_l[tmm.tm_wday];

				break;



			case 'a' :
				if ( tmm.tm_wday < 0  ||  tmm.tm_wday > 6 ) return 0;
				ptr = weekday_s[tmm.tm_wday];

				break;



			case 'B' :
				if ( tmm.tm_mon < 0  ||  tmm.tm_mon > 11 ) return 0;
				ptr = month_l[tmm.tm_mon];

				break;



			case 'C' :

				snprintf( buffer, BUFLEN, "%02d", (year+1900) / 100 );
				ptr = buffer;

				break;



			case 'b' :
			case 'h' :
				if ( tmm.tm_mon < 0  ||  tmm.tm_mon > 11 ) return 0;
				ptr = month_s[tmm.tm_mon];

				break;



			case 'd' :

				if ( tmm.tm_mday < 1  ||  tmm.tm_mday > 31 ) return 0;

				snprintf( buffer, BUFLEN, "%02d", tmm.tm_mday );
				ptr = buffer;

				break;



			case 'D' :

				retval = strftime( &dst[index], dst_size-index, "%m/%d/%y", tmm );
				if ( retval == 0 ) return 0;

				index += retval-1;
				if ( index >= dst_size ) return 0;

				fmt++;

				continue;



			case 'e' :

				if ( tmm.tm_mday < 1  ||  tmm.tm_mday > 31 ) return 0;

				snprintf( buffer, BUFLEN, "%2d", tmm.tm_mday );
				ptr = buffer;

				break;



			case 'F' :

				retval = strftime( &dst[index], dst_size-index, "%Y-%m-%d", tmm );
				if ( retval == 0 ) return 0;

				index += retval-1;
				if ( index >= dst_size ) return 0;

				fmt++;

				continue;



			case 'H' :

				if ( tmm.tm_hour < 0  ||  tmm.tm_hour > 23 ) return 0;

				snprintf( buffer, BUFLEN, "%02d", tmm.tm_hour );
				ptr = buffer;

				break;



			case 'I' :

				if ( tmm.tm_hour < 0  ||  tmm.tm_hour > 23 ) return 0;

				snprintf( buffer, BUFLEN, "%02d", ((tmm.tm_hour+11) % 12) + 1 );
				ptr = buffer;

				break;



			case 'j' :

				if ( tmm.tm_yday < 0  ||  tmm.tm_yday > 365 ) return 0;

				snprintf( buffer, BUFLEN, "%03d", tmm.tm_yday+1 );
				ptr = buffer;

				break;



			case 'k' :

				if ( tmm.tm_hour < 0  ||  tmm.tm_hour > 23 ) return 0;

				snprintf( buffer, BUFLEN, "%2d", tmm.tm_hour );
				ptr = buffer;

				break;



			case 'l' :

				if ( tmm.tm_hour < 0  ||  tmm.tm_hour > 23 ) return 0;

				snprintf( buffer, BUFLEN, "%2d", ((tmm.tm_hour+11) % 12) + 1 );
				ptr = buffer;

				break;



			case 'M' :

				if ( tmm.tm_min < 0  ||  tmm.tm_min > 59 ) return 0;
				
				snprintf( buffer, BUFLEN, "%02d", tmm.tm_min );
				ptr = buffer;

				break;



			case 'm' :

				if ( tmm.tm_mon < 0  ||  tmm.tm_mon > 11 ) return 0;

				snprintf( buffer, BUFLEN, "%02d", tmm.tm_mon+1 );
				ptr = buffer;

				break;



			case 'n' :

				dst[index++] = '\n';
				if ( index >= dst_size ) return 0;

				fmt++;

				continue;



			case 'p' :

				if ( tmm.tm_hour < 0  ||  tmm.tm_hour > 23 ) return 0;

				if ( tmm.tm_hour < 12 ) ptr = "AM";
				else                    ptr = "PM";

				break;



			case 'R' :

				retval = strftime( &dst[index], dst_size-index, "%H:%M", tmm );
				if ( retval == 0 ) return 0;

				index += retval-1;
				if ( index >= dst_size ) return 0;

				fmt++;

				continue;



			case 'r' :

				retval = strftime( &dst[index], dst_size-index, "%I:%M:%S %p", tmm );
				if ( retval == 0 ) return 0;

				index += retval-1;
				if ( index >= dst_size ) return 0;

				fmt++;

				continue;



			case 'S' :

				if ( tmm.tm_sec < 0  ||  tmm.tm_sec > 61 ) return 0;

				snprintf( buffer, BUFLEN, "%d", tmm.tm_sec );
				ptr = buffer;

				break;



			case 'T' :

				retval = strftime( &dst[index], dst_size-index, "%H:%M:%S", tmm );
				if ( retval == 0 ) return 0;

				index += retval-1;
				if ( index >= dst_size ) return 0;

				fmt++;

				continue;



			case 't' :

				dst[index++] = '\t';
				if ( index >= dst_size ) return 0;

				fmt++;

				continue;



			case 'u' :

				if ( tmm.tm_wday < 0  ||  tmm.tm_wday > 6 ) return 0;

				snprintf( buffer, BUFLEN, "%d", ((tmm.tm_wday+6) % 7) + 1 );
				ptr = buffer;

				break;



			case 'v' :

				retval = strftime( &dst[index], dst_size-index, "%e-%b-%Y", tmm );
				if ( retval == 0 ) return 0;

				index += retval-1;
				if ( index >= dst_size ) return 0;

				fmt++;

				continue;



			case 'w' :

				if ( tmm.tm_wday < 0  ||  tmm.tm_wday > 6 ) return 0;

				snprintf( buffer, BUFLEN, "%d", tmm.tm_wday );
				ptr = buffer;

				break;



			case 'Y' :
				
				snprintf( buffer, BUFLEN, "%d", tmm.tm_year + 1900 );
				ptr = buffer;

				break;




			case 'y' :

				snprintf( buffer, BUFLEN, "%d", tmm.tm_year % 100 );
				ptr = buffer;

				break;



			case 'Z' :

				if ( tmm.tm_zone == NULL ) return 0;

				ptr = tmm.tm_zone;

				break;



			case 'z' :

				if ( tmm.tm_gmt_off < 0 ) { neg_offset = true;  sec_offset = -tmm.tm_gmt_off; }
				else                      { neg_offset = false; sec_offset =  tmm.tm_gmt_off; }

				sec_offset += 30;
				sec_offset /= 60;
				min_offset  = sec_offset % 60;
				sec_offset /= 60;
				hour_offset = sec_offset;

				if ( hour_offset > 14 ) return 0;

				snprintf( buffer, "%c%02ld%02ld", (neg_offset) ? "-" : "+", hour_offset, min_offset );
				ptr = buffer;

				break;



			default :
				return 0;
		}

		while ( *ptr  &&  index < dst_size ) dst[index++] = *ptr++;
		if ( index >= dst_size ) return 0;

		fmt++;
	}

	if ( index < dst_size ) { dst[index++] = 0; return index; }

	return 0;

}  /* strftime */

#endif /* defined(_WIN32_WCE) */
