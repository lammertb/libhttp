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

/*
 * unsigned httplib_check_feature( unsigned feature );
 *
 * The function httplib_check_feature returns an integer indicating if a specific
 * functionality has been compiled in at compile time.
 */

unsigned httplib_check_feature( unsigned feature ) {

	static const unsigned feature_set = 0
/* Set bits for available features according to API documentation.
 * This bit mask is created at compile time, according to the active
 * preprocessor defines. It is a single const value at runtime. */
	                                    | 0x0001u
#if !defined(NO_SSL)
	                                    | 0x0002u
#endif
#if !defined(NO_CGI)
	                                    | 0x0004u
#endif

/* Set some extra bits not defined in the API documentation.
 * These bits may change without further notice. */
#if defined(USE_TIMERS)
	                                    | 0x0200u
#endif
#if !defined(NO_POPEN)
	                                    | 0x0800u
#endif
	    ;
	return (feature & feature_set);

}  /* httplib_check_feature */
