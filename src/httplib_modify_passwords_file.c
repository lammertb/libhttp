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

int httplib_modify_passwords_file( const char *fname, const char *domain, const char *user, const char *pass ) {

	int found, i;
	char line[512];
	char u[512] = "";
	char d[512] = "";
	char ha1[33];
	char tmp[PATH_MAX + 8];
	FILE *fp;
	FILE *fp2;

	found = 0;
	fp    = NULL;
	fp2   = NULL;

	/*
	 * Regard empty password as no password - remove user record.
	 */

	if ( pass != NULL  &&  pass[0] == '\0' ) pass = NULL;

	/* 
	 * Other arguments must not be empty
	 */

	if ( fname == NULL  ||  domain == NULL  ||  user == NULL ) return 0;

	/*
	 * Using the given file format, user name and domain must not contain ':'
	 */

	if ( strchr( user,   ':' ) != NULL ) return 0;
	if ( strchr( domain, ':' ) != NULL ) return 0;

	/*
	 * Do not allow control characters like newline in user name and domain.
	 * Do not allow excessively long names either.
	 */

	for (i=0; i<255  &&  user[i] != 0; i++) { if (iscntrl(user[i])) return 0; }
	if ( user[i] ) return 0;

	for (i=0; i<255  &&  domain[i] != 0; i++) { if (iscntrl(domain[i])) return 0; }
	if (domain[i]) return 0;

	/*
	 * The maximum length of the path to the password file is limited
	 */

	if ((strlen(fname) + 4) >= PATH_MAX) return 0;

	/*
	 * Create a temporary file name. Length has been checked before.
	 */

	strcpy(tmp, fname);
	strcat(tmp, ".tmp");

	/*
	 * Create the file if does not exist
	 * Use of fopen here is OK, since fname is only ASCII
	 */

	if ( (fp = fopen( fname, "a+" )) != NULL ) fclose(fp);

	/*
	 * Open the given file and temporary file
	 */

	if ( (fp = fopen( fname, "r" )) == NULL ) return 0;
	
	else if ( (fp2 = fopen( tmp, "w+" )) == NULL ) {

		fclose( fp );
		return 0;
	}

	/*
	 * Copy the stuff to temporary file
	 */

	while ( fgets( line, sizeof(line), fp ) != NULL ) {

		if ( sscanf(line, "%255[^:]:%255[^:]:%*s", u, d) != 2 ) continue;

		u[255] = 0;
		d[255] = 0;

		if ( ! strcmp( u, user )  &&  ! strcmp( d, domain ) ) {

			found++;
			if ( pass != NULL ) {

				httplib_md5( ha1, user, ":", domain, ":", pass, NULL );
				fprintf( fp2, "%s:%s:%s\n", user, domain, ha1 );
			}
		}
		
		else fprintf( fp2, "%s", line );
	}

	/*
	 * If new user, just add it
	 */

	if ( ! found  &&  pass != NULL ) {

		httplib_md5( ha1, user, ":", domain, ":", pass, NULL );
		fprintf( fp2, "%s:%s:%s\n", user, domain, ha1 );
	}

	/*
	 * Close files
	 */

	fclose( fp  );
	fclose( fp2 );

	/*
	 * Put the temp file in place of real file
	 */

	remove( fname      );
	rename( tmp, fname );

	return 1;

}  /* httplib_modify_passwords_file */
