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
 */



#include "libhttp-private.h"



/*
 * int XX_httplib_set_throttle( const char *spec, uint32_t remote_ip, const char *uri );
 *
 * The function XX_httplib_set_throttle() set throttling on a connection with
 * a specific IP and url.
 */

int XX_httplib_set_throttle( const char *spec, uint32_t remote_ip, const char *uri ) {

	int throttle = 0;
	struct vec vec, val;
	uint32_t net, mask;
	char mult;
	double v;

	while ((spec = XX_httplib_next_option(spec, &vec, &val)) != NULL) {
		mult = ',';
		if ((val.ptr == NULL) || (sscanf(val.ptr, "%lf%c", &v, &mult) < 1)
		    || (v < 0) || ((XX_httplib_lowercase(&mult) != 'k')
		                   && (XX_httplib_lowercase(&mult) != 'm') && (mult != ','))) {
			continue;
		}
		v *= (XX_httplib_lowercase(&mult) == 'k') ? 1024 : ((XX_httplib_lowercase(&mult) == 'm') ? 1048576 : 1);
		if (vec.len == 1 && vec.ptr[0] == '*') {
			throttle = (int)v;
		} else if (XX_httplib_parse_net(vec.ptr, &net, &mask) > 0) {
			if ((remote_ip & mask) == net) {
				throttle = (int)v;
			}
		} else if (XX_httplib_match_prefix(vec.ptr, vec.len, uri) > 0) throttle = (int)v;
	}

	return throttle;

}  /* XX_httplib_set_throttle */
