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

#if defined(_WIN32)

#if !defined(NO_CGI)

static void trim_trailing_whitespaces( char *s ) {

	char *e = s + strlen(s) - 1;
	while (e > s && isspace(*(unsigned char *)e)) *e-- = '\0';

}  /* trim_trailing_whitespaces */


pid_t XX_httplib_spawn_process( struct lh_ctx_t *ctx, struct lh_con_t *conn, const char *prog, char *envblk, char *envp[], int fdin[2], int fdout[2], int fderr[2], const char *dir ) {

	HANDLE me;
	char *p;
	char *interp;
	char full_interp[PATH_MAX];
	char full_dir[PATH_MAX];
	char cmdline[PATH_MAX];
	char buf[PATH_MAX];
	bool truncated;
	struct file file = STRUCT_FILE_INITIALIZER;
	STARTUPINFOA si;
	PROCESS_INFORMATION pi = {0};

	UNUSED_PARAMETER(envp);

	if ( ctx == NULL  ||  conn == NULL ) return 0;

	memset( &si, 0, sizeof(si) );
	si.cb = sizeof(si);

	si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;

	me = GetCurrentProcess();
	DuplicateHandle( me, (HANDLE)_get_osfhandle(fdin[0]),  me, &si.hStdInput,  0, TRUE, DUPLICATE_SAME_ACCESS );
	DuplicateHandle( me, (HANDLE)_get_osfhandle(fdout[1]), me, &si.hStdOutput, 0, TRUE, DUPLICATE_SAME_ACCESS );
	DuplicateHandle( me, (HANDLE)_get_osfhandle(fderr[1]), me, &si.hStdError,  0, TRUE, DUPLICATE_SAME_ACCESS );

	/*
	 * Mark handles that should not be inherited. See
	 * https://msdn.microsoft.com/en-us/library/windows/desktop/ms682499%28v=vs.85%29.aspx
	 */

	SetHandleInformation( (HANDLE)_get_osfhandle(fdin[1]),  HANDLE_FLAG_INHERIT, 0 );
	SetHandleInformation( (HANDLE)_get_osfhandle(fdout[0]), HANDLE_FLAG_INHERIT, 0 );
	SetHandleInformation( (HANDLE)_get_osfhandle(fderr[0]), HANDLE_FLAG_INHERIT, 0 );

	/*
	 * If CGI file is a script, try to read the interpreter line
	 */

	interp = ctx->cgi_interpreter;

	if ( interp == NULL ) {

		buf[0] = '\0';
		buf[1] = '\0';

		/*
		 * Read the first line of the script into the buffer
		 */

		XX_httplib_snprintf( ctx, conn, &truncated, cmdline, sizeof(cmdline), "%s/%s", dir, prog );

		if ( truncated ) {

			pi.hProcess = (pid_t)-1;
			goto spawn_cleanup;
		}

		if ( XX_httplib_fopen( ctx, conn, cmdline, "r", &file ) ) {
			p = (char *)file.membuf;
			XX_httplib_fgets( buf, sizeof(buf), &file, &p );
			XX_httplib_fclose( & file );
			buf[sizeof(buf) - 1] = '\0';
		}

		if ( buf[0] == '#'  &&  buf[1] == '!' ) trim_trailing_whitespaces( buf + 2 );
		else                                    buf[2] = '\0';

		interp = buf + 2;
	}

	if ( interp[0] != '\0' ) {

		GetFullPathNameA( interp, sizeof(full_interp), full_interp, NULL );
		interp = full_interp;
	}

	GetFullPathNameA( dir, sizeof(full_dir), full_dir, NULL );

	if ( interp[0] != '\0' ) XX_httplib_snprintf( ctx, conn, &truncated, cmdline, sizeof(cmdline), "\"%s\" \"%s\\%s\"", interp, full_dir, prog);
	else                     XX_httplib_snprintf( ctx, conn, &truncated, cmdline, sizeof(cmdline), "\"%s\\%s\"",                full_dir, prog);

	if ( truncated ) {

		pi.hProcess = (pid_t)-1;
		goto spawn_cleanup;
	}

	if ( CreateProcessA( NULL, cmdline, NULL, NULL, TRUE, CREATE_NEW_PROCESS_GROUP, envblk, NULL, &si, &pi ) == 0 ) {

		httplib_cry( LH_DEBUG_ERROR, ctx, conn, "%s: CreateProcess(%s): %ld", __func__, cmdline, (long)ERRNO);
		pi.hProcess = (pid_t)-1;

		/*
		 * goto spawn_cleanup;
		 */
	}

spawn_cleanup:
	CloseHandle( si.hStdOutput );
	CloseHandle( si.hStdError  );
	CloseHandle( si.hStdInput  );

	if ( pi.hThread != NULL ) CloseHandle( pi.hThread );

	return (pid_t)pi.hProcess;

}  /* XX_httplib_spawn_process */

#endif /* !NO_CGI */

#else  /* _WIN32 */

#ifndef NO_CGI
pid_t XX_httplib_spawn_process( struct lh_ctx_t *ctx, struct lh_con_t *conn, const char *prog, char *envblk, char *envp[], int fdin[2], int fdout[2], int fderr[2], const char *dir ) {

	pid_t pid;
	const char *interp;
	char error_string[ERROR_STRING_LEN];

	UNUSED_PARAMETER(envblk);

	if ( ctx == NULL  ||  conn == NULL ) return 0;

	if ( (pid = fork()) == -1 ) {

		/*
		 * Parent
		 */

		XX_httplib_send_http_error( ctx, conn, 500, "Error: Creating CGI process\nfork(): %s", httplib_error_string( ERRNO, error_string, ERROR_STRING_LEN ) );
	}
	
	else if ( pid == 0 ) {

		/*
		 * Child
		 */

		if      ( chdir( dir        ) !=  0 ) httplib_cry( LH_DEBUG_ERROR, ctx, conn, "%s: chdir(%s): %s", __func__,   dir,      httplib_error_string( ERRNO, error_string, ERROR_STRING_LEN ) );
		else if ( dup2( fdin[0], 0  ) == -1 ) httplib_cry( LH_DEBUG_ERROR, ctx, conn, "%s: dup2(%d, 0): %s", __func__, fdin[0],  httplib_error_string( ERRNO, error_string, ERROR_STRING_LEN ) );
		else if ( dup2( fdout[1], 1 ) == -1 ) httplib_cry( LH_DEBUG_ERROR, ctx, conn, "%s: dup2(%d, 1): %s", __func__, fdout[1], httplib_error_string( ERRNO, error_string, ERROR_STRING_LEN ) );
		else if ( dup2( fderr[1], 2 ) == -1 ) httplib_cry( LH_DEBUG_ERROR, ctx, conn, "%s: dup2(%d, 2): %s", __func__, fderr[1], httplib_error_string( ERRNO, error_string, ERROR_STRING_LEN ) );
		else {
			/*
			 * Keep stderr and stdout in two different pipes.
			 * Stdout will be sent back to the client,
			 * stderr should go into a server error log.
			 */

			close( fdin[0]  );
			close( fdout[1] );
			close( fderr[1] );

			/*
			 * Close write end fdin and read end fdout and fderr
			 */

			close( fdin[1]  );
			close( fdout[0] );
			close( fderr[0] );

			/*
			 * After exec, all signal handlers are restored to their default
			 * values, with one exception of SIGCHLD. According to
			 * POSIX.1-2001 and Linux's implementation, SIGCHLD's handler will
			 * leave unchanged after exec if it was set to be ignored. Restore
			 * it to default action.
			 */

			signal( SIGCHLD, SIG_DFL );

			interp = ctx->cgi_interpreter;

			if ( interp == NULL ) {

				execle( prog, prog, NULL, envp );
				httplib_cry( LH_DEBUG_ERROR, ctx, conn, "%s: execle(%s): %s", __func__, prog, httplib_error_string( ERRNO, error_string, ERROR_STRING_LEN ) );
			}
			
			else {
				execle( interp, interp, prog, NULL, envp );
				httplib_cry( LH_DEBUG_ERROR, ctx, conn, "%s: execle(%s %s): %s", __func__, interp, prog, httplib_error_string( ERRNO, error_string, ERROR_STRING_LEN ) );
			}
		}

		exit( EXIT_FAILURE );
	}

	return pid;

}  /* XX_httplib_spawn_process */

#endif /* !NO_CGI */

#endif /* _WIN32 */
