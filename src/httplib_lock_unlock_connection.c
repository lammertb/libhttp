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
 * void mg_lock_connection( struct mg_connection *conn );
 *
 * The function mg_lock_connection() puts a lock on a connection.
 */

void mg_lock_connection( struct mg_connection *conn ) {

	if ( conn != NULL ) pthread_mutex_lock( & conn->mutex );

}  /* mg_lock_connection */



/*
 * void mg_unlock_connection( struct mg_connection *conn );
 *
 * The function mg_unlock_connection() removes the current lock from a
 * connection.
 */

void mg_unlock_connection( struct mg_connection *conn ) {

	if ( conn != NULL ) pthread_mutex_unlock( & conn->mutex );

}  /* mg_unlock_connection */
