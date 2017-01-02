/* 
 * Copyright (c) 2016 Lammert Bies
 * Copyright (c) 2016 the Civetweb developers
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

static int url_encoded_field_found( struct lh_ctx_t *ctx, const struct lh_con_t *conn, const char *key, size_t key_len, const char *filename, size_t filename_len, char *path, size_t path_len, struct httplib_form_data_handler *fdh ) {

	char key_dec[1024];
	char filename_dec[1024];
	int key_dec_len;
	int filename_dec_len;
	int ret;

	key_dec_len = httplib_url_decode(key, (int)key_len, key_dec, (int)sizeof(key_dec), 1);

	if (((size_t)key_dec_len >= (size_t)sizeof(key_dec)) || (key_dec_len < 0)) return FORM_FIELD_STORAGE_SKIP;

	if ( filename != NULL ) {

		filename_dec_len = httplib_url_decode( filename, (int)filename_len, filename_dec, (int)sizeof(filename_dec), 1 );

		if (((size_t)filename_dec_len >= (size_t)sizeof(filename_dec)) || (filename_dec_len < 0)) {

			/*
			 * Log error message and skip this field.
			 */

			httplib_cry( LH_DEBUG_WARNING, ctx, conn, "%s: Cannot decode filename", __func__ );
			return FORM_FIELD_STORAGE_SKIP;
		}

	} else filename_dec[0] = 0;

	ret = fdh->field_found( key_dec, filename_dec, path, path_len, fdh->user_data );

	if ( (ret & 0xF) == FORM_FIELD_STORAGE_GET ) {

		if ( fdh->field_get == NULL ) {

			httplib_cry( LH_DEBUG_WARNING, ctx, conn, "%s: Function \"Get\" not available", __func__ );
			return FORM_FIELD_STORAGE_SKIP;
		}
	}
	if ( (ret & 0xF) == FORM_FIELD_STORAGE_STORE ) {

		if ( fdh->field_store == NULL ) {

			httplib_cry( LH_DEBUG_WARNING, ctx, conn, "%s: Function \"Store\" not available", __func__ );
			return FORM_FIELD_STORAGE_SKIP;
		}
	}

	return ret;
}


static int url_encoded_field_get( struct lh_ctx_t *ctx, const struct lh_con_t *conn, const char *key, size_t key_len, const char *value, size_t value_len, struct httplib_form_data_handler *fdh ) {

	char key_dec[1024];

	char *value_dec = httplib_malloc( value_len+1 );
	int value_dec_len;
	int ret;

	if ( value_dec == NULL ) {

		/*
		 * Log error message and stop parsing the form data.
		 */

		httplib_cry( LH_DEBUG_ERROR, ctx, conn, "%s: Not enough memory (required: %lu)", __func__, (unsigned long)(value_len + 1));
		return FORM_FIELD_STORAGE_ABORT;
	}

	httplib_url_decode( key, (int)key_len, key_dec, (int)sizeof(key_dec), 1 );

	value_dec_len = httplib_url_decode( value, (int)value_len, value_dec, (int)value_len + 1, 1 );
	ret           = fdh->field_get( key_dec, value_dec, (size_t)value_dec_len, fdh->user_data ); 
	value_dec     = httplib_free( value_dec );

	return ret;

}  /* url_encoded_field_get */


static int unencoded_field_get(const struct lh_con_t *conn,
                    const char *key,
                    size_t key_len,
                    const char *value,
                    size_t value_len,
                    struct httplib_form_data_handler *fdh) {

	char key_dec[1024];

	UNUSED_PARAMETER(conn);

	httplib_url_decode( key, (int)key_len, key_dec, (int)sizeof(key_dec), 1 );

	return fdh->field_get( key_dec, value, value_len, fdh->user_data );

}  /* unencoded_field_get */


static int field_stored( const struct lh_con_t *conn, const char *path, int64_t file_size, struct httplib_form_data_handler *fdh ) {

	/*
	 * Equivalent to "upload" callback of "httplib_upload".
	 */

	UNUSED_PARAMETER(conn); /* we do not need httplib_cry here, so conn is currently unused */

	return fdh->field_store( path, file_size, fdh->user_data );
}


static const char * search_boundary(const char *buf, size_t buf_len, const char *boundary, size_t boundary_len) {

	/*
	 * We must do a binary search here, not a string search, since the buffer
	 * may contain '\x00' bytes, if binary data is transferred.
	 */

	int clen = (int)buf_len - (int)boundary_len - 4;
	int i;

	for (i = 0; i <= clen; i++) {
		if (!memcmp(buf + i, "\r\n--", 4)) {
			if (!memcmp(buf + i + 4, boundary, boundary_len)) return buf+i;
		}
	}
	return NULL;
}


int httplib_handle_form_request( struct lh_ctx_t *ctx, struct lh_con_t *conn, struct httplib_form_data_handler *fdh ) {

	const char *content_type;
	char path[512];
	char buf[1024];
	int field_storage;
	int buf_fill = 0;
	int r;
	int field_count = 0;
	struct file fstore = STRUCT_FILE_INITIALIZER;
	int64_t file_size = 0; /* init here, to a avoid a false positive
	                         "uninitialized variable used" warning */

	int has_body_data = (conn->request_info.content_length > 0) || (conn->is_chunked);

	/*
	 * There are three ways to encode data from a HTML form:
	 * 1) method: GET (default)
	 *    The form data is in the HTTP query string.
	 * 2) method: POST, enctype: "application/x-www-form-urlencoded"
	 *    The form data is in the request body.
	 *    The body is url encoded (the default encoding for POST).
	 * 3) method: POST, enctype: "multipart/form-data".
	 *    The form data is in the request body of a multipart message.
	 *    This is the typical way to handle file upload from a form.
	 */

	if ( ! has_body_data ) {

		const char *data;

		if ( strcmp( conn->request_info.request_method, "GET" ) ) {
			/*
			 * No body data, but not a GET request.
			 * This is not a valid form request.
			 */

			return -1;
		}

		/*
		 * GET request: form data is in the query string.
		 * The entire data has already been loaded, so there is no nead to
		 * call httplib_read. We just need to split the query string into key-value
		 * pairs.
		 */

		data = conn->request_info.query_string;
		if ( data == NULL ) return -1; /* No query string. */

		/*
		 * Split data in a=1&b=xy&c=3&c=4 ...
		 */

		while ( *data ) {

			const char *val = strchr(data, '=');
			const char *next;
			ptrdiff_t keylen, vallen;

			if ( val == NULL ) break;
			keylen = val - data;

			/*
			 * In every "field_found" callback we ask what to do with the
			 * data ("field_storage"). This could be:
			 * FORM_FIELD_STORAGE_SKIP (0) ... ignore the value of this field
			 * FORM_FIELD_STORAGE_GET (1) ... read the data and call the get
			 *                              callback function
			 * FORM_FIELD_STORAGE_STORE (2) ... store the data in a file
			 * FORM_FIELD_STORAGE_READ (3) ... let the user read the data
			 *                               (for parsing long data on the fly)
			 *                               (currently not implemented)
			 * FORM_FIELD_STORAGE_ABORT (flag) ... stop parsing
			 */

			memset( path, 0, sizeof(path) );
			field_count++;
			field_storage = url_encoded_field_found( ctx, conn, data, (size_t)keylen, NULL, 0, path, sizeof(path) - 1, fdh );

			val++;
			next = strchr( val, '&' );
			if ( next != NULL ) {

				vallen = next - val;
				next++;
			}
			
			else {
				vallen = (ptrdiff_t)strlen(val);
				next = val + vallen;
			}

			if ( field_storage == FORM_FIELD_STORAGE_GET ) {

				/*
				 * Call callback
				 */

				url_encoded_field_get( ctx, conn, data, (size_t)keylen, val, (size_t)vallen, fdh );
			}

			if ( field_storage == FORM_FIELD_STORAGE_STORE ) {

				/*
				 * Store the content to a file
				 */

				if ( XX_httplib_fopen( ctx, conn, path, "wb", &fstore ) == 0 ) fstore.fp = NULL;
				file_size = 0;

				if ( fstore.fp != NULL ) {

					size_t n = (size_t)fwrite(val, 1, (size_t)vallen, fstore.fp);
					if ((n != (size_t)vallen) || (ferror(fstore.fp))) {
						httplib_cry( LH_DEBUG_ERROR, ctx, conn, "%s: Cannot write file %s", __func__, path );
						fclose( fstore.fp );
						fstore.fp = NULL;
						XX_httplib_remove_bad_file( ctx, conn, path );
					}
					file_size += (int64_t)n;

					if ( fstore.fp ) {

						r = fclose( fstore.fp );

						if (r == 0) {
							/*
							 * stored successfully
							 */

							field_stored( conn, path, file_size, fdh );
						}
						
						else {
							httplib_cry( LH_DEBUG_ERROR, ctx, conn, "%s: Error saving file %s", __func__, path );
							XX_httplib_remove_bad_file( ctx, conn, path );
						}

						fstore.fp = NULL;
					}

				} else httplib_cry( LH_DEBUG_ERROR, ctx, conn, "%s: Cannot create file %s", __func__, path );
			}

			/*
			 * if (field_storage == FORM_FIELD_STORAGE_READ) {
			 * The idea of "field_storage=read" is to let the API user read
			 * data chunk by chunk and to some data processing on the fly.
			 * This should avoid the need to store data in the server:
			 * It should neither be stored in memory, like
			 * "field_storage=get" does, nor in a file like
			 * "field_storage=store".
			 * However, for a "GET" request this does not make any much
			 * sense, since the data is already stored in memory, as it is
			 * part of the query string.
			 *
			 * } */

			if ((field_storage & FORM_FIELD_STORAGE_ABORT) == FORM_FIELD_STORAGE_ABORT) break; /* Stop parsing the request */

			/*
			 * Proceed to next entry
			 */

			data = next;
		}

		return field_count;
	}

	content_type = httplib_get_header( conn, "Content-Type" );

	if ( content_type == NULL
	    || ! httplib_strcasecmp(content_type, "APPLICATION/X-WWW-FORM-URLENCODED")
	    || ! httplib_strcasecmp(content_type, "APPLICATION/WWW-FORM-URLENCODED")) {

		/*
		 * The form data is in the request body data, encoded in key/value
		 * pairs.
		 */

		int all_data_read = 0;

		/*
		 * Read body data and split it in keys and values.
		 * The encoding is like in the "GET" case above: a=1&b&c=3&c=4.
		 * Here we use "POST", and read the data from the request body.
		 * The data read on the fly, so it is not required to buffer the
		 * entire request in memory before processing it.
		 */

		for (;;) {

			const char *val;
			const char *next;
			ptrdiff_t keylen, vallen;
			ptrdiff_t used;
			int end_of_key_value_pair_found = 0;
			int get_block;

			if ((size_t)buf_fill < (sizeof(buf) - 1)) {

				size_t to_read = sizeof(buf) - 1 - (size_t)buf_fill;
				r = httplib_read( ctx, conn, buf + (size_t)buf_fill, to_read );
				if ( r < 0 )  return -1; /* read error */

				if ( r != (int)to_read ) {
					/*
					 * TODO: Create a function to get "all_data_read" from
					 * the conn object. All data is read if the Content-Length
					 * has been reached, or if chunked encoding is used and
					 * the end marker has been read, or if the connection has
					 * been closed.
					 */

					all_data_read = 1;
				}
				buf_fill += r;
				buf[buf_fill] = 0;
				if ( buf_fill < 1 ) break;
			}

			val = strchr(buf, '=');

			if ( val == NULL ) break;
			keylen = val - buf;
			val++;

			/*
			 * Call callback
			 */

			memset( path, 0, sizeof(path) );
			field_count++;
			field_storage = url_encoded_field_found( ctx, conn, buf, (size_t)keylen, NULL, 0, path, sizeof(path) - 1, fdh );

			if ( (field_storage & FORM_FIELD_STORAGE_ABORT) == FORM_FIELD_STORAGE_ABORT ) break; /* Stop parsing the request */

			if ( field_storage == FORM_FIELD_STORAGE_STORE ) {

				if ( XX_httplib_fopen( ctx, conn, path, "wb", &fstore ) == 0 ) fstore.fp = NULL;
				file_size = 0;
				if (!fstore.fp) httplib_cry( LH_DEBUG_ERROR, ctx, conn, "%s: Cannot create file %s", __func__, path);
			}

			get_block = 0;

			/*
			 * Loop to read values larger than sizeof(buf)-keylen-2
			 */

			do {
				next = strchr(val, '&');

				if (next != NULL ) {

					vallen = next - val;
					next++;
					end_of_key_value_pair_found = 1;
				}
				
				else {
					vallen = (ptrdiff_t)strlen(val);
					next = val + vallen;
				}

				if ( field_storage == FORM_FIELD_STORAGE_GET ) {
#if 0
					if (!end_of_key_value_pair_found && !all_data_read) {
						/* This callback will deliver partial contents */
					}
#else
					(void)all_data_read; /* avoid warning */
#endif

					/* Call callback */
					url_encoded_field_get( ctx, conn,
					                      ((get_block > 0) ? NULL : buf),
					                      ((get_block > 0) ? 0    : (size_t)keylen),
					                      val,
					                      (size_t)vallen,
					                      fdh);
					get_block++;
				}
				if ( fstore.fp ) {
					size_t n = (size_t)fwrite(val, 1, (size_t)vallen, fstore.fp);
					if ((n != (size_t)vallen) || (ferror(fstore.fp))) {
						httplib_cry( LH_DEBUG_ERROR, ctx, conn, "%s: Cannot write file %s", __func__, path);
						fclose(fstore.fp);
						fstore.fp = NULL;
						XX_httplib_remove_bad_file( ctx, conn, path );
					}
					file_size += (int64_t)n;
				}

				if ( ! end_of_key_value_pair_found ) {

					used = next - buf;
					memmove( buf, buf + (size_t)used, sizeof(buf) - (size_t)used );
					buf_fill -= (int)used;
					if ((size_t)buf_fill < (sizeof(buf) - 1)) {

						size_t to_read = sizeof(buf) - 1 - (size_t)buf_fill;
						r = httplib_read( ctx, conn, buf + (size_t)buf_fill, to_read );
						if ( r < 0 ) return -1; /* read error */

						if (r != (int)to_read) {

							/*
							 * TODO: Create a function to get "all_data_read"
							 * from the conn object. All data is read if the
							 * Content-Length has been reached, or if chunked
							 * encoding is used and the end marker has been
							 * read, or if the connection has been closed.
							 */

							all_data_read = 1;
						}
						buf_fill += r;
						buf[buf_fill] = 0;
						if (buf_fill < 1) break;
						val = buf;
					}
				}

			} while ( ! end_of_key_value_pair_found );

			if ( fstore.fp ) {
				r = fclose(fstore.fp);
				if ( r == 0 ) {

					/*
					 * stored successfully
					 */
					field_stored( conn, path, file_size, fdh );
				}
				
				else {
					httplib_cry( LH_DEBUG_ERROR, ctx, conn, "%s: Error saving file %s", __func__, path );
					XX_httplib_remove_bad_file( ctx, conn, path );
				}

				fstore.fp = NULL;
			}

			/*
			 * Proceed to next entry
			 */

			used = next - buf;
			memmove( buf, buf + (size_t)used, sizeof(buf) - (size_t)used );
			buf_fill -= (int)used;
		}

		return field_count;
	}

	if ( ! httplib_strncasecmp( content_type, "MULTIPART/FORM-DATA;", 20) ) {

		/*
		 * The form data is in the request body data, encoded as multipart
		 * content (see https://www.ietf.org/rfc/rfc1867.txt,
		 * https://www.ietf.org/rfc/rfc2388.txt).
		 */

		const char *boundary;
		size_t bl;
		ptrdiff_t used;
		struct lh_rqi_t part_header;
		char *hbuf;
		char *hend;
		char *fbeg;
		char *fend;
		char *nbeg;
		char *nend;
		const char *content_disp;
		const char *next;

		memset( & part_header, 0, sizeof(part_header) );

		/*
		 * Skip all spaces between MULTIPART/FORM-DATA; and BOUNDARY=
		 */

		bl = 20;
		while (content_type[bl] == ' ') bl++;

		/*
		 * There has to be a BOUNDARY definition in the Content-Type header
		 */

		if ( httplib_strncasecmp( content_type + bl, "BOUNDARY=", 9 ) ) {

			/*
			 * Malformed request
			 */

			return -1;
		}

		boundary = content_type + bl + 9;
		bl       = strlen( boundary );

		if ( bl + 800 > sizeof(buf) ) {

			/*
			 * Sanity check:  The algorithm can not work if bl >= sizeof(buf),
			 * and it will not work effectively, if the buf is only a few byte
			 * larger than bl, or it buf can not hold the multipart header
			 * plus the boundary.
			 * Check some reasonable number here, that should be fulfilled by
			 * any reasonable request from every browser. If it is not
			 * fulfilled, it might be a hand-made request, intended to
			 * interfere with the algorithm.
			 */

			return -1;
		}

		for (;;) {

			size_t towrite;
			size_t n;
			int get_block;

			r = httplib_read( ctx, conn, buf + (size_t)buf_fill, sizeof(buf) - 1 - (size_t)buf_fill );
			if ( r < 0 ) return -1; /* read error */

			buf_fill     += r;
			buf[buf_fill] = 0;

			if ( buf_fill < 1 ) return -1; /* No data */

			if ( buf[0] != '-'  ||  buf[1] != '-' ) return -1; /* Malformed request */

			if ( strncmp( buf + 2, boundary, bl ) ) return -1; /* Malformed request */

			if ( buf[bl + 2] != '\r'  ||  buf[bl + 3] != '\n' ) {

				/*
				 * Every part must end with \r\n, if there is another part.
				 * The end of the request has an extra --
				 */

				if (((size_t)buf_fill != (size_t)(bl + 6)) || (strncmp(buf + bl + 2, "--\r\n", 4))) return -1; /* Malformed request */

				/*
				 * End of the request
				 */

				break;
			}

			/*
			 * Next, we need to get the part header: Read until \r\n\r\n
			 */

			hbuf = buf + bl + 4;
			hend = strstr(hbuf, "\r\n\r\n");
			if ( hend == NULL ) return -1; /* Malformed request */

			XX_httplib_parse_http_headers( &hbuf, &part_header );
			if ( (hend + 2) != hbuf ) return -1; /* Malformed request */

			/*
			 * Skip \r\n\r\n
			 */

			hend += 4;

			/*
			 * According to the RFC, every part has to have a header field like:
			 * Content-Disposition: form-data; name="..."
			 */

			content_disp = XX_httplib_get_header( & part_header, "Content-Disposition" );
			if ( ! content_disp ) return -1; /* Malformed request */

			/*
			 * Get the mandatory name="..." part of the Content-Disposition
			 * header.
			 */

			nbeg = strstr( content_disp, "name=\"" );
			if ( nbeg == NULL ) return -1; /* Malformed request */

			nbeg += 6;
			nend = strchr(nbeg, '\"');

			if ( nend == NULL ) return -1; /* Malformed request */

			/*
			 * Get the optional filename="..." part of the Content-Disposition
			 * header.
			 */

			fbeg = strstr( content_disp, "filename=\"" );

			if ( fbeg != NULL ) {

				fbeg += 10;
				fend  = strchr(fbeg, '\"');

				if ( fend == NULL ) {

					/*
					 * Malformed request (the filename field is optional, but if
					 * it exists, it needs to be terminated correctly).
					 */

					return -1;
				}

				/*
				 * TODO: check Content-Type
				 * Content-Type: application/octet-stream
				 */

			} else fend = fbeg;

			memset( path, 0, sizeof(path) );
			field_count++;
			field_storage = url_encoded_field_found( ctx, conn, nbeg, (size_t)(nend - nbeg), fbeg, (size_t)(fend - fbeg), path, sizeof(path) - 1, fdh );

			/*
			 * If the boundary is already in the buffer, get the address,
			 * otherwise next will be NULL.
			 */

			next = search_boundary( hbuf, (size_t)((buf - hbuf) + buf_fill), boundary, bl );

			if ( field_storage == FORM_FIELD_STORAGE_STORE ) {

				/*
				 * Store the content to a file
				 */

				if ( XX_httplib_fopen( ctx, conn, path, "wb", &fstore ) == 0 ) fstore.fp = NULL;
				file_size = 0;

				if ( ! fstore.fp ) httplib_cry( LH_DEBUG_ERROR, ctx, conn, "%s: Cannot create file %s", __func__, path );
			}

			get_block = 0;

			while ( ! next ) {

				/*
				 * Set "towrite" to the number of bytes available
				 * in the buffer
				 */

				towrite = (size_t)(buf - hend + buf_fill);

				/*
				 * Subtract the boundary length, to deal with
				 * cases the boundary is only partially stored
				 * in the buffer.
				 */

				towrite -= bl + 4;

				if (field_storage == FORM_FIELD_STORAGE_GET) {
					unencoded_field_get(conn,
					                    ((get_block > 0) ? NULL : nbeg),
					                    ((get_block > 0) ? 0    : (size_t)(nend - nbeg)),
					                    hend,
					                    towrite,
					                    fdh);
					get_block++;
				}

				if ( field_storage == FORM_FIELD_STORAGE_STORE ) {

					if (fstore.fp) {

						/*
						 * Store the content of the buffer.
						 */

						n = (size_t)fwrite( hend, 1, towrite, fstore.fp );

						if ( n != towrite  ||  ferror( fstore.fp ) ) {

							httplib_cry( LH_DEBUG_ERROR, ctx, conn, "%s: Cannot write file %s", __func__, path );
							fclose( fstore.fp );
							fstore.fp = NULL;
							XX_httplib_remove_bad_file( ctx, conn, path );
						}

						file_size += (int64_t)n;
					}
				}

				memmove( buf, hend + towrite, bl + 4 );
				buf_fill = (int)(bl + 4);
				hend = buf;

				/*
				 * Read new data
				 */

				r = httplib_read( ctx, conn, buf + (size_t)buf_fill, sizeof(buf) - 1 - (size_t)buf_fill );
				if ( r < 0 ) return -1; /* read error */

				buf_fill     += r;
				buf[buf_fill] = 0;
				if (buf_fill < 1) return -1; /* No data */

				/*
				 * Find boundary
				 */

				next = search_boundary( buf, (size_t)buf_fill, boundary, bl );
			}

			towrite = (size_t)(next - hend);

			if ( field_storage == FORM_FIELD_STORAGE_GET ) {

				/*
				 * Call callback
				 */

				unencoded_field_get(conn,
				                    ((get_block > 0) ? NULL : nbeg),
				                    ((get_block > 0) ? 0    : (size_t)(nend - nbeg)),
				                    hend,
				                    towrite,
				                    fdh);
			}

			if ( field_storage == FORM_FIELD_STORAGE_STORE ) {

				if ( fstore.fp ) {

					n = (size_t)fwrite( hend, 1, towrite, fstore.fp );

					if ( n != towrite  ||  ferror( fstore.fp ) ) {

						httplib_cry( LH_DEBUG_ERROR, ctx, conn, "%s: Cannot write file %s", __func__, path );
						fclose( fstore.fp );
						fstore.fp = NULL;
						XX_httplib_remove_bad_file( ctx, conn, path );
					}
					file_size += (int64_t)n;
				}
			}

			if ( field_storage == FORM_FIELD_STORAGE_STORE ) {

				if ( fstore.fp ) {

					r = fclose( fstore.fp );
					if ( r == 0 ) {

						/*
						 * stored successfully
						 */

						field_stored( conn, path, file_size, fdh );
					}
					
					else {
						httplib_cry( LH_DEBUG_ERROR, ctx, conn, "%s: Error saving file %s", __func__, path );
						XX_httplib_remove_bad_file( ctx, conn, path );
					}
					fstore.fp = NULL;
				}
			}

			if ( (field_storage & FORM_FIELD_STORAGE_ABORT) == FORM_FIELD_STORAGE_ABORT ) break; /* Stop parsing the request */

			/*
			 * Remove from the buffer
			 */

			used = next - buf + 2;
			memmove(buf, buf + (size_t)used, sizeof(buf) - (size_t)used);
			buf_fill -= (int)used;
		}

		/*
		 * All parts handled
		 */
		return field_count;
	}

	/* Unknown Content-Type */
	return -1;
}
