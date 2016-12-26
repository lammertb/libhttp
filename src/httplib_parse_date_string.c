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

static const char *month_names[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

/* Convert month to the month number. Return -1 on error, or month number */
static int get_month_index( const char *s ) {

	size_t i;

	for (i = 0; i < ARRAY_SIZE(month_names); i++) {

		if ( ! strcmp( s, month_names[i] ) ) return (int)i;
	}

	return -1;
}

/*
 * Parse UTC date-time string, and return the corresponding time_t value.
 * This function is used in the if-modified-since calculations
 */
time_t XX_httplib_parse_date_string( const char *datetime ) {

	char month_str[32] = {0};
	int second;
	int minute;
	int hour;
	int day;
	int month;
	int year;
	time_t result = (time_t)0;
	struct tm tm;

	if ( ( sscanf(datetime, "%d/%3s/%d %d:%d:%d",       &day, month_str, &year, &hour, &minute, &second ) == 6 ) ||
	     ( sscanf(datetime, "%d %3s %d %d:%d:%d",       &day, month_str, &year, &hour, &minute, &second ) == 6 ) ||
	     ( sscanf(datetime, "%*3s, %d %3s %d %d:%d:%d", &day, month_str, &year, &hour, &minute, &second ) == 6 ) ||
	     ( sscanf(datetime, "%d-%3s-%d %d:%d:%d",       &day, month_str, &year, &hour, &minute, &second ) == 6 )     ) {

		month = get_month_index( month_str );

		if ( month >= 0  &&  year >= 1970 ) {

			memset( &tm, 0, sizeof(tm) );

			tm.tm_year = year - 1900;
			tm.tm_mon  = month;
			tm.tm_mday = day;
			tm.tm_hour = hour;
			tm.tm_min  = minute;
			tm.tm_sec  = second;
			result     = timegm( & tm );
		}
	}

	return result;

}  /* XX_httplib_parse_date_string */
