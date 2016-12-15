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
#include "httplib_memory.h"
#include "httplib_ssl.h"
#include "httplib_string.h"

#if !defined(NO_SSL)

static int	hexdump2string( void *mem, int memlen, char *buf, int buflen );



/*
 * void XX_httplib_ssl_get_client_cert_info( struct httplib_connection *conn );
 *
 * The function XX_httplib_ssl_get_client_cert_info() returns information from
 * a client provided certificate and hooks it up to the connection info.
 */

void XX_httplib_ssl_get_client_cert_info( struct httplib_connection *conn ) {

	X509 *cert = SSL_get_peer_certificate(conn->ssl);

	if ( cert == NULL ) return;

	char str_subject[1024];
	char str_issuer[1024];
	char str_serial[1024];
	char str_finger[1024];
	unsigned char buf[256];
	int len;
	unsigned int ulen;

	/* Handle to algorithm used for fingerprint */
	const EVP_MD *digest = EVP_get_digestbyname("sha1");

	/* Get Subject and issuer */
	X509_NAME *subj = X509_get_subject_name(cert);
	X509_NAME *iss = X509_get_issuer_name(cert);

	/* Get serial number */
	ASN1_INTEGER *serial = X509_get_serialNumber(cert);

	/* Translate subject and issuer to a string */
	X509_NAME_oneline( subj, str_subject, (int)sizeof(str_subject) );
	X509_NAME_oneline( iss,  str_issuer,  (int)sizeof(str_issuer)  );

	/* Translate serial number to a hex string */
	len = i2c_ASN1_INTEGER(serial, NULL);
	if ((len > 0) && ((unsigned)len < (unsigned)sizeof(buf))) {
		unsigned char *pbuf = buf;
		int len2 = i2c_ASN1_INTEGER(serial, &pbuf);
		if (!hexdump2string(
		        buf, len2, str_serial, (int)sizeof(str_serial))) {
			*str_serial = 0;
		}
	} else *str_serial = 0;

	/* Calculate SHA1 fingerprint and store as a hex string */
	ulen = 0;
	ASN1_digest((int (*)())i2d_X509, digest, (char *)cert, buf, &ulen);
	if (!hexdump2string( buf, (int)ulen, str_finger, (int)sizeof(str_finger))) *str_finger = 0;

	conn->request_info.client_cert =
	    (struct client_cert *)XX_httplib_malloc(sizeof(struct client_cert));
	if (conn->request_info.client_cert) {
		conn->request_info.client_cert->subject = XX_httplib_strdup( str_subject );
		conn->request_info.client_cert->issuer  = XX_httplib_strdup( str_issuer  );
		conn->request_info.client_cert->serial  = XX_httplib_strdup( str_serial  );
		conn->request_info.client_cert->finger  = XX_httplib_strdup( str_finger  );
	} else {
		/* TODO: write some OOM message */
	}

	X509_free(cert);

}  /* XX_httplib_ssl_get_client_cert_info */



/*
 * static int hexdump2string( void *mem, int memlen, char *buf, int buflen );
 *
 * The function hexdump2string() takes a binary blob and converts it to a hex
 * encoded string.
 */

static int hexdump2string(void *mem, int memlen, char *buf, int buflen) {

	int i;
	const char hexdigit[] = "0123456789abcdef";

	if (memlen <= 0 || buflen <= 0) return 0;
	if (buflen < (3 * memlen)) return 0;

	for (i = 0; i < memlen; i++) {
		if (i > 0) buf[3*i - 1] = ' ';
		buf[3*i    ] = hexdigit[(((uint8_t *)mem)[i] >> 4) & 0xF];
		buf[3*i + 1] = hexdigit[ ((uint8_t *)mem)[i]       & 0xF];
	}
	buf[3 * memlen - 1] = 0;

	return 1;
}

#endif /* !NO_SSL */
