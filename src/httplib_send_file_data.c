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

#if defined(__linux__)
#include <sys/sendfile.h>
#endif  /* __linux__ */
#include "httplib_main.h"

/*
 * Send len bytes from the opened file to the client.
 */

void XX_httplib_send_file_data( struct lh_ctx_t *ctx, struct lh_con_t *conn, struct file *filep, int64_t offset, int64_t len ) {

	char buf[MG_BUF_LEN];
	char error_string[ERROR_STRING_LEN];
	int to_read;
	int num_read;
	int num_written;
	int64_t size;
#if defined(__linux__)
	off_t sf_offs;
	ssize_t sf_sent;
	int sf_file;
	int loop_cnt;
#endif  /* __linux__ */

	if ( ctx == NULL  ||  filep == NULL  ||  conn == NULL ) return;

	/*
	 * Sanity check the offset
	 */

	size   = (filep->size > INT64_MAX) ? INT64_MAX : (int64_t)(filep->size);
	offset = (offset < 0) ? 0 : ((offset > size) ? size : offset);

	if ( len > 0  &&  filep->membuf != NULL  &&  size > 0 ) {

		/*
		 * file stored in memory
		 * TODO: LJB: len is 64 bit, but httplib_write may take 32 or
		 * even 16 bit depending on the platform. This can cause
		 * interesting bugs when serving large in-memory files.
		 */

		if (len > size - offset) len = size - offset;
		httplib_write( ctx, conn, filep->membuf + offset, (size_t)len );

	}
	
	else if ( len > 0  &&  filep->fp != NULL ) {

/* file stored on disk */
#if defined(__linux__)

		/*
		 * sendfile is only available for Linux
		 */

		if ( ctx->allow_sendfile_call  &&  conn->ssl == 0  &&  conn->throttle == 0 ) {

			sf_offs  = (off_t)offset;
			sf_file  = fileno( filep->fp );
			loop_cnt = 0;

			do {
				/* 
				 * 2147479552 (0x7FFFF000) is a limit found by experiment on
				 * 64 bit Linux (2^31 minus one memory page of 4k?).
				 */

				size_t sf_tosend = (size_t)((len < 0x7FFFF000) ? len : 0x7FFFF000);
				sf_sent = sendfile(conn->client.sock, sf_file, &sf_offs, sf_tosend);

				if ( sf_sent > 0 ) {

					conn->num_bytes_sent += sf_sent;
					len                  -= sf_sent;
					offset               += sf_sent;

				}

			  	else if ( loop_cnt == 0 ) {
					/*
					 * This file can not be sent using sendfile.
					 * This might be the case for pseudo-files in the
					 * /sys/ and /proc/ file system.
					 * Use the regular user mode copy code instead.
					 */

					break;
				}
				
				else if ( sf_sent == 0 ) {

					/*
					 * No error, but 0 bytes sent. May be EOF?
					 */

					return;
				}
				loop_cnt++;

			} while ( len > 0  &&  sf_sent >= 0 );

			if ( sf_sent > 0 ) return; /* OK */

			/*
			 * sf_sent<0 means error, thus fall back to the classic way
			 * This is always the case, if sf_file is not a "normal" file,
			 * e.g., for sending data from the output of a CGI process.
			 */

			offset = (int64_t)sf_offs;
		}
#endif
		if ( offset > 0  &&  fseeko( filep->fp, offset, SEEK_SET ) != 0 ) {

			httplib_cry( LH_DEBUG_ERROR, ctx, conn, "%s: fseeko() failed: %s", __func__, httplib_error_string( ERRNO, error_string, ERROR_STRING_LEN ) );
			XX_httplib_send_http_error( ctx, conn, 500, "%s", "Error: Unable to access file at requested position." );
		}
		
		else {
			while ( len > 0 ) {

				/*
				 * Calculate how much to read from the file in the buffer
				 */

				to_read = sizeof(buf);
				if ((int64_t)to_read > len) to_read = (int)len;

				/*
				 * Read from file, exit the loop on error
				 */

				if ( (num_read = (int)fread(buf, 1, (size_t)to_read, filep->fp )) <= 0 ) break;

				/*
				 * Send read bytes to the client, exit the loop on error
				 */

				if ( (num_written = httplib_write( ctx, conn, buf, (size_t)num_read )) != num_read ) break;

				/*
				 * Both read and were successful, adjust counters
				 */

				conn->num_bytes_sent += num_written;
				len                  -= num_written;
			}
		}
	}

}  /* XX_httplib_send_file_data */
