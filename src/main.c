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

#if defined(_WIN32)

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS /* Disable deprecation warning in VS2005 */
#endif
#ifndef _CRT_SECURE_NO_DEPRECATE
#define _CRT_SECURE_NO_DEPRECATE
#endif

#else

#define _XOPEN_SOURCE 600

/*
 * For PATH_MAX on linux
 *
 * This should also be sufficient for "realpath", according to
 * http://man7.org/linux/man-pages/man3/realpath.3.html, but in
 * reality it does not seem to work.
 *
 * In case this causes a problem, disable the warning:
 * #pragma GCC diagnostic ignored "-Wimplicit-function-declaration"
 * #pragma clang diagnostic ignored "-Wimplicit-function-declaration"
 */

#endif

#if defined(__cplusplus) && (__cplusplus >= 201103L)
#define NO_RETURN [[noreturn]]
#elif defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L)
#define NO_RETURN _Noreturn
#else
#define NO_RETURN
#endif

#include <sys/stat.h>
#include <stdio.h>
#include <stdint.h>
#include <limits.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <stddef.h>
#include <stdarg.h>
#include <ctype.h>
#include <assert.h>

#include "libhttp.h"

#define printf DO_NOT_USE_THIS_FUNCTION__USE_fprintf /* Required for unit testing */

#if defined(_WIN32)  /* WINDOWS / UNIX include block */
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501 /* for tdm-gcc so we can use getconsolewindow */
#endif  /* _WIN32_WINNT */
#undef UNICODE
#include <windows.h>
#include <winsvc.h>
#include <shlobj.h>
#include <io.h>

#define getcwd(a, b) (_getcwd(a, b))
#if !defined(__MINGW32__)
extern char *_getcwd(char *buf, size_t size);
#endif
static int guard = 0; /* test if any dialog is already open */

#ifndef PATH_MAX
#define PATH_MAX MAX_PATH
#endif  /* PATH_MAX */

#ifndef S_ISDIR
#define S_ISDIR(x) ((x)&_S_IFDIR)
#endif  /* S_ISDIR */

#define DIRSEP '\\'
#define snprintf _snprintf
#define vsnprintf _vsnprintf
#define sleep(x) (Sleep((x)*1000))
#define WINCDECL __cdecl
#define abs_path(rel, abs, abs_size) (_fullpath((abs), (rel), (abs_size)))

#else /* defined(_WIN32)- WINDOWS / UNIX include   \
         block */

#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>
#define DIRSEP '/'
#define WINCDECL
#define abs_path(rel, abs, abs_size) (realpath((rel), (abs)))

#endif /* defined(_WIN32) - WINDOWS / UNIX include  \
          block */

#ifndef PATH_MAX
#define PATH_MAX (1024)
#endif

#ifndef ERROR_STRING_LEN
#define ERROR_STRING_LEN (256)
#endif

#define MAX_OPTIONS (50)
#define MAX_CONF_FILE_LINE_SIZE (8 * 1024)

struct tuser_data {
	char *first_message;
};

struct httplib_option {
	const char *	name;
	const char *	value;
};

static int g_exit_flag = 0;         /* Main loop should exit */
static char g_server_base_name[40]; /* Set by init_server_name() */
static const char *g_server_name;   /* Set by init_server_name() */
static const char *g_icon_name;     /* Set by init_server_name() */
static char g_config_file_name[PATH_MAX] =
    "";                          /* Set by process_command_line_arguments() */
static struct lh_ctx_t *g_ctx; /* Set by start_libhttp() */
static struct tuser_data
    g_user_data; /* Passed to httplib_start() by start_libhttp() */

#if !defined(CONFIG_FILE)
#define CONFIG_FILE "libhttp.conf"
#endif /* !CONFIG_FILE */

#if !defined(PASSWORDS_FILE_NAME)
#define PASSWORDS_FILE_NAME ".htpasswd"
#endif

/* backup config file */
#if !defined(CONFIG_FILE2) && defined(__linux__)
#define CONFIG_FILE2 "/usr/local/etc/libhttp.conf"
#endif

enum { OPTION_TITLE, OPTION_ICON, NUM_MAIN_OPTIONS };

static struct httplib_option main_config_options[] = {
	{ "title", NULL },
	{ "icon",  NULL },
	{ NULL,    NULL }
};

static void WINCDECL signal_handler(int sig_num) {

	g_exit_flag = sig_num;
}


static NO_RETURN void die(const char *fmt, ...) {

	va_list ap;
	char msg[200] = "";

	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg) - 1, fmt, ap);
	msg[sizeof(msg) - 1] = 0;
	va_end(ap);

#if defined(_WIN32)
	MessageBox(NULL, msg, "Error", MB_OK);
#else  /* _WIN32 */
	fprintf(stderr, "%s\n", msg);
#endif  /* _WIN32 */

	exit(EXIT_FAILURE);
}


#ifdef WIN32
static int MakeConsole(void);
#endif  /* WIN32 */


static void
show_server_name(void)
{
#ifdef WIN32
	(void)MakeConsole();
#endif  /* WIN32 */

	fprintf(stderr, "LibHTTP v%s, built on %s\n", httplib_version(), __DATE__);
}


static NO_RETURN void show_usage_and_exit( const char *exeName ) {

	if ( exeName == NULL  ||  *exeName == '\0' ) exeName = "libhttp";

	show_server_name();

	fprintf(stderr, "\nUsage:\n");
	fprintf(stderr, "  Start server with a set of options:\n");
	fprintf(stderr, "    %s [config_file]\n", exeName);
	fprintf(stderr, "    %s [-option value ...]\n", exeName);
	fprintf(stderr, "  Show system information:\n");
	fprintf(stderr, "    %s -I\n", exeName);
	fprintf(stderr, "  Add user/change password:\n");
	fprintf(stderr,
	        "    %s -A <htpasswd_file> <realm> <user> <passwd>\n",
	        exeName);
	fprintf(stderr, "  Remove user:\n");
	fprintf(stderr, "    %s -R <htpasswd_file> <realm> <user>\n", exeName);
	fprintf(stderr, "\nOPTIONS:\n");

	exit(EXIT_FAILURE);
}


#if defined(_WIN32) || defined(USE_COCOA)  /* GUI */
static const char *config_file_top_comment =
    "# LibHTTP web server configuration file.\n"
    "# For detailed description of every option, visit\n"
    "# https://github.com/lammertb/libhttp/blob/master/doc/UserManual.md\n"
    "# Lines starting with '#' and empty lines are ignored.\n"
    "# To make a change, remove leading '#', modify option's value,\n"
    "# save this file and then restart LibHTTP.\n\n";

static const char * get_url_to_first_open_port(const struct lh_ctx_t *ctx) {

	static char url[100];
	char ports_str[256];
	const char *open_ports = httplib_get_option( ctx, "listening_ports", ports_str, 256 );
	int a;
	int b;
	int c;
	int d;
	int port;
	int n;

	if (sscanf(open_ports, "%d.%d.%d.%d:%d%n", &a, &b, &c, &d, &port, &n) == 5) {
		snprintf(url, sizeof(url), "%s://%d.%d.%d.%d:%d", open_ports[n] == 's' ? "https" : "http", a, b, c, d, port);
	} else if (sscanf(open_ports, "%d%n", &port, &n) == 1) {
		snprintf(url, sizeof(url), "%s://localhost:%d", open_ports[n] == 's' ? "https" : "http", port);
	} else {
		snprintf(url, sizeof(url), "%s", "http://localhost:8080");
	}

	return url;
}


#ifdef ENABLE_CREATE_CONFIG_FILE
static void create_config_file(const struct lh_ctx_t *ctx, const char *path) {

	const struct httplib_option *options;
	const char *value;
	FILE *fp;
	int i;

	/* Create config file if it is not present yet */
	if ((fp = fopen(path, "r")) != NULL) {
		fclose(fp);
	} else if ((fp = fopen(path, "a+")) != NULL) {
		fprintf(fp, "%s", config_file_top_comment);
		options = httplib_get_valid_options();
		for (i = 0; options[i].name != NULL; i++) {
			value = httplib_get_option(ctx, options[i].name);
			fprintf( fp, "# %s %s\n", options[i].name, (value) ? value : "<value>" );
		}
		fclose( fp );
	}
}
#endif  /* ENABLE_CREATE_CONFIG_FILE */
#endif  /* GUI */


static char * sdup(const char *str) {

	size_t len;
	char *p;

	len = strlen(str) + 1;
	if ((p = (char *)malloc(len)) != NULL) {
		memcpy(p, str, len);
	}
	return p;
}


static const char * get_option( struct httplib_option_t *options, const char *option_name ) {

	int i;

	i = 0;

	while ( options[i].name != NULL ) {

		if ( strcmp( options[i].name, option_name ) == 0 ) return options[i].value;
		i++;
	}
	return NULL;
}


static int set_option( struct httplib_option_t *options, const char *name, const char *value ) {

	int i;

	for (i = 0; main_config_options[i].name != NULL; i++) {
		if (0 == strcmp(name, main_config_options[i].name)) {
			/* This option is evaluated by main.c, not libhttp.c - just skip it
			 * and return OK */
			return 1;
		}
	}

	for (i = 0; i < MAX_OPTIONS; i++) {

		if ( options[i].name == NULL ) {

			options[i].name   = sdup( name  );
			options[i].name   = sdup( value );
			options[i+1].name = NULL;

			break;
		}
		
		if ( ! strcmp(options[i].name, name) ) {

			free( (void *)options[i].value );
			options[i].value = sdup( value );

			break;
		}
	}

	if ( i == MAX_OPTIONS ) die( "Too many options specified" );

	if ( options[i].name == NULL  ||  options[i].value == NULL ) die( "Out of memory" );

	/* option set correctly */
	return 1;
}


static int read_config_file( const char *config_file, struct httplib_option_t *options ) {

	char line[MAX_CONF_FILE_LINE_SIZE], *p;
	FILE *fp = NULL;
	size_t i;
	size_t j;
	size_t line_no = 0;

	/* Open the config file */
	fp = fopen(config_file, "r");
	if (fp == NULL) {
		/* Failed to open the file. Keep errno for the caller. */
		return 0;
	}

	/* Load config file settings first */
	if (fp != NULL) {
		fprintf(stderr, "Loading config file %s\n", config_file);

		/* Loop over the lines in config file */
		while (fgets(line, sizeof(line), fp) != NULL) {

			if (!line_no && !memcmp(line, "\xEF\xBB\xBF", 3)) {
				/* strip UTF-8 BOM */
				p = line + 3;
			} else {
				p = line;
			}
			line_no++;

			/* Ignore empty lines and comments */
			for (i = 0; isspace(*(unsigned char *)&line[i]);)
				i++;
			if (p[i] == '#' || p[i] == '\0') {
				continue;
			}

			/* Skip spaces, \r and \n at the end of the line */
			for (j = strlen(line) - 1;
			     isspace(*(unsigned char *)&line[j])
			         || iscntrl(*(unsigned char *)&line[j]);)
				line[j--] = 0;

			/* Find the space character between option name and value */
			for (j = i; !isspace(*(unsigned char *)&line[j]) && (line[j] != 0);)
				j++;

			/* Terminate the string - then the string at (line+i) contains the
			 * option name */
			line[j] = 0;
			j++;

			/* Trim additional spaces between option name and value - then
			 * (line+j) contains the option value */
			while (isspace(line[j]))
				j++;

			/* Set option */
			if (!set_option(options, line + i, line + j)) {
				fprintf(stderr, "%s: line %d is invalid, ignoring it:\n %s", config_file, (int)line_no, p);
			}
		}

		fclose( fp );
	}
	return 1;
}


static void process_command_line_arguments( int argc, char *argv[], struct httplib_option_t *options ) {

	char *p;
	char error_string[ERROR_STRING_LEN];
	size_t i, cmd_line_opts_start = 1;
#ifdef CONFIG_FILE2
	FILE *fp = NULL;
#endif  /* CONFIG_FILE2 */

	/* Should we use a config file ? */
	if ((argc > 1) && (argv[1] != NULL) && (argv[1][0] != '-')
	    && (argv[1][0] != 0)) {
		/* The first command line parameter is a config file name. */
		snprintf(g_config_file_name,
		         sizeof(g_config_file_name) - 1,
		         "%s",
		         argv[1]);
		cmd_line_opts_start = 2;
	} else if ((p = strrchr(argv[0], DIRSEP)) == NULL) {
		/* No config file set. No path in arg[0] found.
		 * Use default file name in the current path. */
		snprintf( g_config_file_name, sizeof(g_config_file_name) - 1, "%s", CONFIG_FILE );
	} else {
		/* No config file set. Path to exe found in arg[0].
		 * Use default file name next to the executable. */
		snprintf(g_config_file_name, sizeof(g_config_file_name) - 1, "%.*s%c%s", (int)(p - argv[0]), argv[0], DIRSEP, CONFIG_FILE);
	}
	g_config_file_name[sizeof(g_config_file_name) - 1] = 0;

#ifdef CONFIG_FILE2
	fp = fopen(g_config_file_name, "r");

	/* try alternate config file */
	if (fp == NULL) {
		fp = fopen(CONFIG_FILE2, "r");
		if (fp != NULL) {
			strcpy(g_config_file_name, CONFIG_FILE2);
		}
	}
	if ( fp != NULL ) fclose(fp);

#endif  /* CONFIG_FILE2 */

	/* read all configurations from a config file */
	if (0 == read_config_file(g_config_file_name, options)) {
		if (cmd_line_opts_start == 2) {
			/* If config file was set in command line and open failed, die. */
			/* Errno will still hold the error from fopen. */
			die( "Cannot open config file %s: %s", g_config_file_name, httplib_error_string( errno, error_string, ERROR_STRING_LEN ) );
		}
		/* Otherwise: LibHTTP can work without a config file */
	}

	/* If we're under MacOS and started by launchd, then the second
	   argument is process serial number, -psn_.....
	   In this case, don't process arguments at all. */
	if (argv[1] == NULL || memcmp(argv[1], "-psn_", 5) != 0) {
		/* Handle command line flags.
		   They override config file and default settings. */
		for (i = cmd_line_opts_start; argv[i] != NULL; i += 2) {
			if (argv[i][0] != '-' || argv[i + 1] == NULL) {
				show_usage_and_exit(argv[0]);
			}
			if (!set_option(options, &argv[i][1], argv[i + 1])) {
				fprintf(
				    stderr,
				    "command line option is invalid, ignoring it:\n %s %s\n",
				    argv[i],
				    argv[i + 1]);
			}
		}
	}
}


static void init_server_name(int argc, const char *argv[]) {

	int i;
	assert(sizeof(main_config_options) / sizeof(main_config_options[0])
	       == NUM_MAIN_OPTIONS + 1);
	assert((strlen(httplib_version()) + 12) < sizeof(g_server_base_name));
	snprintf(g_server_base_name,
	         sizeof(g_server_base_name),
	         "LibHTTP V%s",
	         httplib_version());

	g_server_name = g_server_base_name;
	for (i = 0; i < argc - 1; i++) {
		if ((argv[i][0] == '-')
		    && (0 == strcmp(argv[i] + 1,
		                    main_config_options[OPTION_TITLE].name))) {
			g_server_name = (const char *)(argv[i + 1]);
		}
	}
	g_icon_name = NULL;
	for (i = 0; i < argc - 1; i++) {
		if ((argv[i][0] == '-')
		    && (0 == strcmp(argv[i] + 1,
		                    main_config_options[OPTION_ICON].name))) {
			g_icon_name = (const char *)(argv[i + 1]);
		}
	}
}


static int log_message( const struct lh_ctx_t *ctx, const struct lh_con_t *conn, const char *message ) {

	struct tuser_data *ud;

	UNUSED_PARAMETER(conn);

	fprintf( stderr, "%s\n", message );
       
	ud = httplib_get_user_data( ctx );
	if ( ud != NULL  &&  ud->first_message == NULL ) ud->first_message = sdup( message );

	return 0;

}  /* log_message */


static int is_path_absolute(const char *path) {

#ifdef _WIN32
	return path != NULL
	       && ((path[0] == '\\' && path[1] == '\\') || /* UNC path, e.g.
	                                                      \\server\dir */
	           (isalpha(path[0]) && path[1] == ':'
	            && path[2] == '\\')); /* E.g. X:\dir */
#else  /* _WIN32 */
	return path != NULL && path[0] == '/';
#endif  /* _WIN32 */
}


static void verify_existence( struct httplib_option_t *options, const char *option_name, int must_be_dir) {

	struct stat st;
	char error_string[ERROR_STRING_LEN];
	const char *path = get_option(options, option_name);

#ifdef _WIN32
	wchar_t wbuf[1024];
	char mbbuf[1024];
	int len;

	if (path) {
		memset( wbuf,  0, sizeof(wbuf)  );
		memset( mbbuf, 0, sizeof(mbbuf) );
		len = MultiByteToWideChar(CP_UTF8, 0, path, -1, wbuf, (int)sizeof(wbuf) / sizeof(wbuf[0]) - 1);
		wcstombs(mbbuf, wbuf, sizeof(mbbuf) - 1);
		path = mbbuf;
		(void)len;
	}
#endif  /* _WIN32 */

	if (path != NULL && (stat(path, &st) != 0
	                     || ((S_ISDIR(st.st_mode) ? 1 : 0) != must_be_dir))) {
		die("Invalid path for %s: [%s]: (%s). Make sure that path is either "
		    "absolute, or it is relative to libhttp executable.",
		    option_name,
		    path,
		    httplib_error_string( errno, error_string, ERROR_STRING_LEN ) );
	}
}


static void set_absolute_path( struct httplib_option_t *options, const char *option_name, const char *path_to_libhttp_exe ) {

	char path[PATH_MAX] = "";
	char absolute[PATH_MAX] = "";
	const char *option_value;
	const char *p;

	/* Check whether option is already set */
	option_value = get_option(options, option_name);

	/* If option is already set and it is an absolute path,
	   leave it as it is -- it's already absolute. */
	if (option_value != NULL && !is_path_absolute(option_value)) {
		/* Not absolute. Use the directory where libhttp executable lives
		   be the relative directory for everything.
		   Extract libhttp executable directory into path. */
		if ((p = strrchr(path_to_libhttp_exe, DIRSEP)) == NULL) {
			getcwd(path, sizeof(path));
		} else {
			snprintf(path, sizeof(path) - 1, "%.*s", (int)(p - path_to_libhttp_exe), path_to_libhttp_exe);
			path[sizeof(path) - 1] = 0;
		}

		strncat(path, "/", sizeof(path) - strlen(path) - 1);
		strncat(path, option_value, sizeof(path) - strlen(path) - 1);

		/* Absolutize the path, and set the option */
		abs_path(path, absolute, sizeof(absolute));
		set_option(options, option_name, absolute);
	}
}



#if defined(__MINGW32__) || defined(__MINGW64__)
/* For __MINGW32/64_MAJOR/MINOR_VERSION define */
#include <_mingw.h>
#endif  /* __MINGW32__  ||  __MINGW64__ */


static void start_libhttp( int argc, char *argv[] ) {

	struct httplib_callbacks callbacks;
	struct httplib_option_t options[MAX_OPTIONS+1] = { { NULL, NULL } };
	int i;

	/* Start option -I:
	 * Show system information and exit
	 * This is very useful for diagnosis. */
	if (argc > 1 && !strcmp(argv[1], "-I")) {
		const char *version = httplib_version();
#if defined(_WIN32)
		DWORD dwVersion      = 0;
		DWORD dwMajorVersion = 0;
		DWORD dwMinorVersion = 0;
		SYSTEM_INFO si;

		GetSystemInfo(&si);

#ifdef _MSC_VER
#pragma warning(push)
// GetVersion was declared deprecated
#pragma warning(disable : 4996)
#endif  /* _MSC_VER */
		dwVersion = GetVersion();
#ifdef _MSC_VER
#pragma warning(pop)
#endif  /* _MSC_VER */

		dwMajorVersion = (DWORD)(LOBYTE(LOWORD(dwVersion)));
		dwMinorVersion = (DWORD)(HIBYTE(LOWORD(dwVersion)));

		(void)MakeConsole();
		fprintf( stdout, "\n%s\n", g_server_name );
		fprintf( stdout, "%s - Windows %u.%u\n", g_server_base_name, (unsigned)dwMajorVersion, (unsigned)dwMinorVersion );

		fprintf(stdout,
		        "CPU: type %u, cores %u, mask %x\n",
		        (unsigned)si.wProcessorArchitecture,
		        (unsigned)si.dwNumberOfProcessors,
		        (unsigned)si.dwActiveProcessorMask);

#else  /* _WIN32 */
		fprintf(stdout, "\n%s\n", g_server_name);
		fprintf(stdout, "%s - Symbian\n", g_server_base_name);
#endif  /* _WIN32 */
/*
		struct utsname name;
		memset( &name, 0, sizeof(name) );
		uname( &name );
		fprintf( stdout, "\n%s\n", g_server_name );
		fprintf( stdout, "%s - %s %s (%s) - %s\n", g_server_base_name, name.sysname, name.version, name.release, name.machine );
*/

		fprintf( stdout, "Features:" );
		if ( httplib_check_feature(  1 ) ) fprintf( stdout, " Files"      );
		if ( httplib_check_feature(  2 ) ) fprintf( stdout, " HTTPS"      );
		if ( httplib_check_feature(  4 ) ) fprintf( stdout, " CGI"        );
		if ( httplib_check_feature(  8 ) ) fprintf( stdout, " IPv6"       );
		if ( httplib_check_feature( 16 ) ) fprintf( stdout, " WebSockets" );
		if ( httplib_check_feature( 32 ) ) fprintf( stdout, " Lua"        );
		fprintf( stdout, "\n" );

		fprintf(stdout, "Version: %s\n", version);
		fprintf(stdout, "Build: %s\n", __DATE__);

/* http://sourceforge.net/p/predef/wiki/Compilers/ */
#if defined(_MSC_VER)
		fprintf(stdout, "MSC: %u (%u)\n", (unsigned)_MSC_VER, (unsigned)_MSC_FULL_VER);
#elif defined(__MINGW64__)
		fprintf(stdout, "MinGW64: %u.%u\n", (unsigned)__MINGW64_VERSION_MAJOR, (unsigned)__MINGW64_VERSION_MINOR);
		fprintf(stdout, "MinGW32: %u.%u\n", (unsigned)__MINGW32_MAJOR_VERSION, (unsigned)__MINGW32_MINOR_VERSION);
#elif defined(__MINGW32__)
		fprintf(stdout, "MinGW32: %u.%u\n", (unsigned)__MINGW32_MAJOR_VERSION, (unsigned)__MINGW32_MINOR_VERSION);
#elif defined(__clang__)
		fprintf(stdout, "clang: %u.%u.%u (%s)\n", __clang_major__, __clang_minor__, __clang_patchlevel__, __clang_version__);
#elif defined(__GNUC__)
		fprintf(stdout, "gcc: %u.%u.%u\n", (unsigned)__GNUC__, (unsigned)__GNUC_MINOR__, (unsigned)__GNUC_PATCHLEVEL__);
#elif defined(__INTEL_COMPILER)
		fprintf(stdout, "Intel C/C++: %u\n", (unsigned)__INTEL_COMPILER);
#elif defined(__BORLANDC__)
		fprintf(stdout, "Borland C: 0x%x\n", (unsigned)__BORLANDC__);
#elif defined(__SUNPRO_C)
		fprintf(stdout, "Solaris: 0x%x\n", (unsigned)__SUNPRO_C);
#else
		fprintf(stdout, "Other\n");
#endif  /* Compiler version */
		/* Determine 32/64 bit data mode.
		 * see https://en.wikipedia.org/wiki/64-bit_computing */
		fprintf(stdout,
		        "Data model: i:%u/%u/%u/%u, f:%u/%u/%u, c:%u/%u, "
		        "p:%u, s:%u, t:%u\n",
		        (unsigned)sizeof(short),
		        (unsigned)sizeof(int),
		        (unsigned)sizeof(long),
		        (unsigned)sizeof(long long),
		        (unsigned)sizeof(float),
		        (unsigned)sizeof(double),
		        (unsigned)sizeof(long double),
		        (unsigned)sizeof(char),
		        (unsigned)sizeof(wchar_t),
		        (unsigned)sizeof(void *),
		        (unsigned)sizeof(size_t),
		        (unsigned)sizeof(time_t));

		exit(EXIT_SUCCESS);
	}

	/* Edit passwords file: Add user or change password, if -A option is
	 * specified */
	if (argc > 1 && !strcmp(argv[1], "-A")) {
		if (argc != 6) {
			show_usage_and_exit(argv[0]);
		}
		exit(httplib_modify_passwords_file(argv[2], argv[3], argv[4], argv[5]) ? EXIT_SUCCESS : EXIT_FAILURE);
	}

	/* Edit passwords file: Remove user, if -R option is specified */
	if (argc > 1 && !strcmp(argv[1], "-R")) {
		if (argc != 5) {
			show_usage_and_exit(argv[0]);
		}
		exit(httplib_modify_passwords_file(argv[2], argv[3], argv[4], NULL) ? EXIT_SUCCESS : EXIT_FAILURE);
	}

	/* Show usage if -h or --help options are specified */
	if (argc == 2 && (!strcmp(argv[1], "-h") || !strcmp(argv[1], "-H")
	                  || !strcmp(argv[1], "--help"))) {
		show_usage_and_exit(argv[0]);
	}

	options[0].name = NULL;
	set_option( options, "document_root", "." );

	/* Update config based on command line arguments */
	process_command_line_arguments( argc, argv, options );

	/* Make sure we have absolute paths for files and directories */
	set_absolute_path( options, "document_root",        argv[0] );
	set_absolute_path( options, "put_delete_auth_file", argv[0] );
	set_absolute_path( options, "cgi_interpreter",      argv[0] );
	set_absolute_path( options, "access_log_file",      argv[0] );
	set_absolute_path( options, "error_log_file",       argv[0] );
	set_absolute_path( options, "global_auth_file",     argv[0] );
	set_absolute_path( options, "ssl_certificate",      argv[0] );

	/* Make extra verification for certain options */
	verify_existence( options, "document_root",   1 );
	verify_existence( options, "cgi_interpreter", 0 );
	verify_existence( options, "ssl_certificate", 0 );
	verify_existence( options, "ssl_ca_path",     1 );
	verify_existence( options, "ssl_ca_file",     0 );

	/* Setup signal handler: quit on Ctrl-C */
	signal( SIGTERM, signal_handler );
	signal( SIGINT,  signal_handler );

	/* Initialize user data */
	memset( &g_user_data, 0, sizeof(g_user_data) );

	/* Start LibHTTP */
	memset(&callbacks, 0, sizeof(callbacks));
	callbacks.log_message = &log_message;
	g_ctx = httplib_start( &callbacks, &g_user_data, options );

	/* httplib_start copies all options to an internal buffer.
	 * The options data field here is not required anymore. */
	for (i=0; options[i].name != NULL; i++) {
		
		if ( options[i].name  != NULL ) free( (void *)options[i].name  );
		if ( options[i].value != NULL ) free( (void *)options[i].value );

		options[i].name  = NULL;
		options[i].value = NULL;
	}

	/* If httplib_start fails, it returns NULL */
	if ( g_ctx == NULL ) die("Failed to start %s:\n%s", g_server_name, ((g_user_data.first_message == NULL) ? "unknown reason" : g_user_data.first_message));
}


static void stop_libhttp(void) {

	httplib_stop(g_ctx);
	free(g_user_data.first_message);
	g_user_data.first_message = NULL;
}


#ifdef _WIN32
/* Win32 has a small GUI.
 * Define some GUI elements and Windows message handlers. */

enum {
	ID_ICON = 100,
	ID_QUIT,
	ID_SETTINGS,
	ID_SEPARATOR,
	ID_INSTALL_SERVICE,
	ID_REMOVE_SERVICE,
	ID_STATIC,
	ID_GROUP,
	ID_PASSWORD,
	ID_SAVE,
	ID_RESET_DEFAULTS,
	ID_RESET_FILE,
	ID_RESET_ACTIVE,
	ID_STATUS,
	ID_CONNECT,
	ID_ADD_USER,
	ID_ADD_USER_NAME,
	ID_ADD_USER_REALM,
	ID_INPUT_LINE,

	/* All dynamically created text boxes for options have IDs starting from
   ID_CONTROLS, incremented by one. */
	ID_CONTROLS = 200,

	/* Text boxes for files have "..." buttons to open file browser. These
   buttons have IDs that are ID_FILE_BUTTONS_DELTA higher than associated
   text box ID. */
	ID_FILE_BUTTONS_DELTA = 1000
};


static HICON hIcon;
static SERVICE_STATUS ss;
static SERVICE_STATUS_HANDLE hStatus;
static const char *service_magic_argument = "--";
static NOTIFYICONDATA TrayIcon;


static void WINAPI ControlHandler(DWORD code) {

	if (code == SERVICE_CONTROL_STOP || code == SERVICE_CONTROL_SHUTDOWN) {
		ss.dwWin32ExitCode = 0;
		ss.dwCurrentState = SERVICE_STOPPED;
	}
	SetServiceStatus(hStatus, &ss);
}


static void WINAPI ServiceMain(void) {

	ss.dwServiceType = SERVICE_WIN32;
	ss.dwCurrentState = SERVICE_RUNNING;
	ss.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;

	hStatus = RegisterServiceCtrlHandler(g_server_name, ControlHandler);
	SetServiceStatus(hStatus, &ss);

	while (ss.dwCurrentState == SERVICE_RUNNING) {
		Sleep(1000);
	}
	stop_libhttp();

	ss.dwCurrentState = SERVICE_STOPPED;
	ss.dwWin32ExitCode = (DWORD)-1;
	SetServiceStatus(hStatus, &ss);
}


static void show_error(void) {

	char buf[256];
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
	              NULL,
	              GetLastError(),
	              MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
	              buf,
	              sizeof(buf),
	              NULL);
	MessageBox(NULL, buf, "Error", MB_OK);
}


static void * align(void *ptr, uintptr_t alig) {

	uintptr_t ul = (uintptr_t)ptr;
	ul += alig;
	ul &= ~alig;
	return ((void *)ul);
}


static void save_config(HWND hDlg, FILE *fp) {

	UNUSED_PARAMETER(hDlg);
	UNUSED_PARAMETER(fp);

	/*
	 * No options currently saved
	 */

//	char value[2000] = "";
//	const char *default_value;
//	const struct httplib_option *options;
//	int i;
//	int id;

//	fprintf(fp, "%s", config_file_top_comment);
//	options = httplib_get_valid_options();
//	for (i = 0; options[i].name != NULL; i++) {
//		id = ID_CONTROLS + i;
//		if (options[i].type == CONFIG_TYPE_BOOLEAN) {
//			snprintf(value, sizeof(value) - 1, "%s", IsDlgButtonChecked(hDlg, id) ? "yes" : "no");
//			value[sizeof(value) - 1] = 0;
//		} else {
//			GetDlgItemText(hDlg, id, value, sizeof(value));
//		}
//		default_value =
//		    options[i].default_value == NULL ? "" : options[i].default_value;
//		/* If value is the same as default, skip it */
//		if (strcmp(value, default_value) != 0) {
//			fprintf(fp, "%s %s\n", options[i].name, value);
//		}
//	}

}  /* save_config */


static INT_PTR CALLBACK SettingsDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam) {

	FILE *fp;
	int i, j;
	const char *name;
	const char *value;
	char *file_options[MAX_OPTIONS * 2 + 1] = {0};
	char *title;
	(void)lParam;

	switch (msg) {

	case WM_CLOSE:
		DestroyWindow(hDlg);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam)) {

		case ID_SAVE:
			EnableWindow(GetDlgItem(hDlg, ID_SAVE), FALSE);
			if ((fp = fopen(g_config_file_name, "w+")) != NULL) {
				save_config(hDlg, fp);
				fclose(fp);
				stop_libhttp();
				start_libhttp(__argc, __argv);
			}
			EnableWindow(GetDlgItem(hDlg, ID_SAVE), TRUE);
			break;

		case ID_RESET_DEFAULTS:
			for (i = 0; default_options[i].name != NULL; i++) {
				name = default_options[i].name;
				value = default_options[i].default_value == NULL
				            ? ""
				            : default_options[i].default_value;
				if (default_options[i].type == CONFIG_TYPE_BOOLEAN) {
					CheckDlgButton(hDlg, ID_CONTROLS + i, !strcmp(value, "yes") ? BST_CHECKED : BST_UNCHECKED);
				} else {
					SetWindowText(GetDlgItem(hDlg, ID_CONTROLS + i), value);
				}
			}
			break;

		case ID_RESET_FILE:
			read_config_file(g_config_file_name, file_options);
			for (i = 0; default_options[i].name != NULL; i++) {
				name = default_options[i].name;
				value = default_options[i].default_value;
				for (j = 0; file_options[j * 2] != NULL; j++) {
					if (!strcmp(name, file_options[j * 2])) {
						value = file_options[j * 2 + 1];
					}
				}
				if (value == NULL) {
					value = "";
				}
				if (default_options[i].type == CONFIG_TYPE_BOOLEAN) {
					CheckDlgButton(hDlg, ID_CONTROLS + i, !strcmp(value, "yes") ? BST_CHECKED : BST_UNCHECKED);
				} else {
					SetWindowText(GetDlgItem(hDlg, ID_CONTROLS + i), value);
				}
			}
			for (i = 0; i < MAX_OPTIONS; i++) {
				free(file_options[2 * i]);
				free(file_options[2 * i + 1]);
			}
			break;

		case ID_RESET_ACTIVE:
			for (i = 0; default_options[i].name != NULL; i++) {
				name = default_options[i].name;
				value = httplib_get_option(g_ctx, name);
				if (default_options[i].type == CONFIG_TYPE_BOOLEAN) {
					CheckDlgButton(hDlg, ID_CONTROLS + i, !strcmp(value, "yes") ? BST_CHECKED : BST_UNCHECKED);
				} else {
					SetDlgItemText(hDlg, ID_CONTROLS + i, value == NULL ? "" : value);
				}
			}
			break;
		}

		for (i = 0; default_options[i].name != NULL; i++) {
			name = default_options[i].name;
			if (((default_options[i].type == CONFIG_TYPE_FILE)
			     || (default_options[i].type == CONFIG_TYPE_DIRECTORY))
			    && LOWORD(wParam) == ID_CONTROLS + i + ID_FILE_BUTTONS_DELTA) {
				OPENFILENAME of;
				BROWSEINFO bi;
				char path[PATH_MAX] = "";

				memset(&of, 0, sizeof(of));
				of.lStructSize = sizeof(of);
				of.hwndOwner = (HWND)hDlg;
				of.lpstrFile = path;
				of.nMaxFile = sizeof(path);
				of.lpstrInitialDir = httplib_get_option(g_ctx, "document_root");
				of.Flags = OFN_CREATEPROMPT | OFN_NOCHANGEDIR | OFN_HIDEREADONLY;

				memset(&bi, 0, sizeof(bi));
				bi.hwndOwner = (HWND)hDlg;
				bi.lpszTitle = "Choose WWW root directory:";
				bi.ulFlags = BIF_RETURNONLYFSDIRS;

				if (default_options[i].type == CONFIG_TYPE_DIRECTORY) {
					SHGetPathFromIDList(SHBrowseForFolder(&bi), path);
				} else {
					GetOpenFileName(&of);
				}

				if (path[0] != '\0') {
					SetWindowText(GetDlgItem(hDlg, ID_CONTROLS + i), path);
				}
			}
		}
		break;

	case WM_INITDIALOG:
		SendMessage(hDlg, WM_SETICON, (WPARAM)ICON_SMALL, (LPARAM)hIcon);
		SendMessage(hDlg, WM_SETICON, (WPARAM)ICON_BIG, (LPARAM)hIcon);
		title = malloc(strlen(g_server_name) + 16);
		if (title) {
			strcpy(title, g_server_name);
			strcat(title, " settings");
			SetWindowText(hDlg, title);
			free(title);
		}
		SetFocus(GetDlgItem(hDlg, ID_SAVE));

		/* Init dialog with active settings */
		SendMessage(hDlg, WM_COMMAND, ID_RESET_ACTIVE, 0);
		/* alternative: SendMessage(hDlg, WM_COMMAND, ID_RESET_FILE, 0); */
		break;

	default:
		break;
	}

	return FALSE;
}


struct tstring_input_buf {
	unsigned buflen;
	char *buffer;
};


static INT_PTR CALLBACK
InputDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lP)
{
	static struct tstring_input_buf *inBuf = 0;
	WORD ctrlId;

	switch (msg) {
	case WM_CLOSE:
		inBuf = 0;
		DestroyWindow(hDlg);
		break;

	case WM_COMMAND:
		ctrlId = LOWORD(wParam);
		if (ctrlId == IDOK) {
			/* Add user */
			GetWindowText(GetDlgItem(hDlg, ID_INPUT_LINE),
			              inBuf->buffer,
			              (int)inBuf->buflen);
			if (strlen(inBuf->buffer) > 0) {
				EndDialog(hDlg, IDOK);
			}
		} else if (ctrlId == IDCANCEL) {
			EndDialog(hDlg, IDCANCEL);
		}
		break;

	case WM_INITDIALOG:
		inBuf = (struct tstring_input_buf *)lP;
		assert(inBuf != NULL);
		assert((inBuf->buffer != NULL) && (inBuf->buflen != 0));
		assert(strlen(inBuf->buffer) < inBuf->buflen);
		SendMessage(hDlg, WM_SETICON, (WPARAM)ICON_SMALL, (LPARAM)hIcon);
		SendMessage(hDlg, WM_SETICON, (WPARAM)ICON_BIG, (LPARAM)hIcon);
		SendDlgItemMessage(
		    hDlg, ID_INPUT_LINE, EM_LIMITTEXT, inBuf->buflen - 1, 0);
		SetWindowText(GetDlgItem(hDlg, ID_INPUT_LINE), inBuf->buffer);
		SetWindowText(hDlg, "Modify password");
		SetFocus(GetDlgItem(hDlg, ID_INPUT_LINE));
		break;

	default:
		break;
	}

	return FALSE;
}


static void suggest_passwd(char *passwd) {

	unsigned u;
	char *p;
	union {
		FILETIME ft;
		LARGE_INTEGER li;
	} num;

	/* valid characters are 32 to 126 */
	GetSystemTimeAsFileTime(&num.ft);
	num.li.HighPart |= (LONG)GetCurrentProcessId();
	p = passwd;
	while (num.li.QuadPart) {
		u = (unsigned)(num.li.QuadPart % 95);
		num.li.QuadPart -= u;
		num.li.QuadPart /= 95;
		*p = (char)(u + 32);
		p++;
	}
}


static void add_control(unsigned char **mem,
                        DLGTEMPLATE *dia,
                        WORD type,
                        WORD id,
                        DWORD style,
                        short x,
                        short y,
                        short cx,
                        short cy,
                        const char *caption);


static int get_password(const char *user, const char *realm, char *passwd, unsigned passwd_len) {

#define HEIGHT (15)
#define WIDTH (280)
#define LABEL_WIDTH (90)

	unsigned char mem[4096], *p;
	DLGTEMPLATE *dia = (DLGTEMPLATE *)mem;
	int ok;
	short y;
	struct tstring_input_buf dlgprms;

	static struct {
		DLGTEMPLATE template; /* 18 bytes */
		WORD menu, class;
		wchar_t caption[1];
		WORD fontsiz;
		wchar_t fontface[7];
	} dialog_header = {{WS_CAPTION | WS_POPUP | WS_SYSMENU | WS_VISIBLE | DS_SETFONT | WS_DLGFRAME,
	                    WS_EX_TOOLWINDOW,
	                    0,
	                    200,
	                    200,
	                    WIDTH,
	                    0},
	                   0,
	                   0,
	                   L"",
	                   8,
	                   L"Tahoma"};

	dlgprms.buffer = passwd;
	dlgprms.buflen = passwd_len;

	assert((user != NULL) && (realm != NULL) && (passwd != NULL));

	if (guard < 100) {
		guard += 100;
	} else {
		return 0;
	}

	/* Create a password suggestion */
	memset(passwd, 0, passwd_len);
	suggest_passwd(passwd);

	/* Create the dialog */
	(void)memset(mem, 0, sizeof(mem));
	(void)memcpy(mem, &dialog_header, sizeof(dialog_header));
	p = mem + sizeof(dialog_header);

	y = HEIGHT;
	add_control(&p, dia, 0x82, ID_STATIC, WS_VISIBLE | WS_CHILD, 10, y, LABEL_WIDTH, HEIGHT, "User:");
	add_control(&p, dia, 0x81, ID_CONTROLS + 1, WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL | WS_DISABLED, 15 + LABEL_WIDTH, y, WIDTH - LABEL_WIDTH - 25, HEIGHT, user);

	y += HEIGHT;
	add_control(&p, dia, 0x82, ID_STATIC, WS_VISIBLE | WS_CHILD, 10, y, LABEL_WIDTH, HEIGHT, "Realm:");
	add_control(&p, dia, 0x81, ID_CONTROLS + 2, WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL | WS_DISABLED, 15 + LABEL_WIDTH, y, WIDTH - LABEL_WIDTH - 25, HEIGHT, realm);

	y += HEIGHT;
	add_control(&p, dia, 0x82, ID_STATIC, WS_VISIBLE | WS_CHILD, 10, y, LABEL_WIDTH, HEIGHT, "Password:");
	add_control(&p, dia, 0x81, ID_INPUT_LINE, WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL | WS_TABSTOP, 15 + LABEL_WIDTH, y, WIDTH - LABEL_WIDTH - 25, HEIGHT, "");

	y += (WORD)(HEIGHT * 2);
	add_control(&p, dia, 0x80, IDOK, WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP, 80, y, 55, 12, "Ok");
	add_control(&p, dia, 0x80, IDCANCEL, WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP, 140, y, 55, 12, "Cancel");

	assert((intptr_t)p - (intptr_t)mem < (intptr_t)sizeof(mem));

	dia->cy = y + (WORD)(HEIGHT * 1.5);

	ok = (IDOK == DialogBoxIndirectParam(
	                  NULL, dia, NULL, InputDlgProc, (LPARAM)&dlgprms));

	guard -= 100;

	return ok;

#undef HEIGHT
#undef WIDTH
#undef LABEL_WIDTH
}


static INT_PTR CALLBACK
PasswordDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lP)
{
	static const char *passfile = 0;
	char domain[256], user[256], password[256];
	WORD ctrlId;

	switch (msg) {
	case WM_CLOSE:
		passfile = 0;
		DestroyWindow(hDlg);
		break;

	case WM_COMMAND:
		ctrlId = LOWORD(wParam);
		if (ctrlId == ID_ADD_USER) {
			/* Add user */
			GetWindowText(GetDlgItem(hDlg, ID_ADD_USER_NAME),
			              user,
			              sizeof(user));
			GetWindowText(GetDlgItem(hDlg, ID_ADD_USER_REALM),
			              domain,
			              sizeof(domain));
			if (get_password(user, domain, password, sizeof(password))) {
				httplib_modify_passwords_file(passfile, domain, user, password);
				EndDialog(hDlg, IDOK);
			}
		} else if ((ctrlId >= (ID_CONTROLS + ID_FILE_BUTTONS_DELTA * 3))
		           && (ctrlId < (ID_CONTROLS + ID_FILE_BUTTONS_DELTA * 4))) {
			/* Modify password */
			GetWindowText(GetDlgItem(hDlg, ctrlId - ID_FILE_BUTTONS_DELTA * 3),
			              user,
			              sizeof(user));
			GetWindowText(GetDlgItem(hDlg, ctrlId - ID_FILE_BUTTONS_DELTA * 2),
			              domain,
			              sizeof(domain));
			if (get_password(user, domain, password, sizeof(password))) {
				httplib_modify_passwords_file(passfile, domain, user, password);
				EndDialog(hDlg, IDOK);
			}
		} else if ((ctrlId >= (ID_CONTROLS + ID_FILE_BUTTONS_DELTA * 2))
		           && (ctrlId < (ID_CONTROLS + ID_FILE_BUTTONS_DELTA * 3))) {
			/* Remove user */
			GetWindowText(GetDlgItem(hDlg, ctrlId - ID_FILE_BUTTONS_DELTA * 2),
			              user,
			              sizeof(user));
			GetWindowText(GetDlgItem(hDlg, ctrlId - ID_FILE_BUTTONS_DELTA),
			              domain,
			              sizeof(domain));
			httplib_modify_passwords_file(passfile, domain, user, NULL);
			EndDialog(hDlg, IDOK);
		}
		break;

	case WM_INITDIALOG:
		passfile = (const char *)lP;
		SendMessage(hDlg, WM_SETICON, (WPARAM)ICON_SMALL, (LPARAM)hIcon);
		SendMessage(hDlg, WM_SETICON, (WPARAM)ICON_BIG, (LPARAM)hIcon);
		SetWindowText(hDlg, passfile);
		SetFocus(GetDlgItem(hDlg, ID_ADD_USER_NAME));
		break;

	default:
		break;
	}

	return FALSE;
}


static void
add_control(unsigned char **mem,
            DLGTEMPLATE *dia,
            WORD type,
            WORD id,
            DWORD style,
            short x,
            short y,
            short cx,
            short cy,
            const char *caption)
{
	DLGITEMTEMPLATE *tp;
	LPWORD p;

	dia->cdit++;

	*mem = align(*mem, 3);
	tp = (DLGITEMTEMPLATE *)*mem;

	tp->id = id;
	tp->style = style;
	tp->dwExtendedStyle = 0;
	tp->x = x;
	tp->y = y;
	tp->cx = cx;
	tp->cy = cy;

	p = align(*mem + sizeof(*tp), 1);
	*p++ = 0xffff;
	*p++ = type;

	while (*caption != '\0') {
		*p++ = (WCHAR)*caption++;
	}
	*p++ = 0;
	p = align(p, 1);

	*p++ = 0;
	*mem = (unsigned char *)p;
}


static void show_settings_dialog( void ) {
#define HEIGHT (15)
#define WIDTH (460)
#define LABEL_WIDTH (90)

	unsigned char mem[16 * 1024], *p;
	const struct httplib_option *options;
	DWORD style;
	DLGTEMPLATE *dia = (DLGTEMPLATE *)mem;
	WORD i, cl, nelems = 0;
	short width, x, y;

	static struct {
		DLGTEMPLATE template; /* 18 bytes */
		WORD menu, class;
		wchar_t caption[1];
		WORD fontsiz;
		wchar_t fontface[7];
	} dialog_header = {{WS_CAPTION | WS_POPUP | WS_SYSMENU | WS_VISIBLE | DS_SETFONT | WS_DLGFRAME,
	                    WS_EX_TOOLWINDOW,
	                    0,
	                    200,
	                    200,
	                    WIDTH,
	                    0},
	                   0,
	                   0,
	                   L"",
	                   8,
	                   L"Tahoma"};

	if (guard == 0) {
		guard++;
	} else {
		return;
	}

	(void)memset(mem, 0, sizeof(mem));
	(void)memcpy(mem, &dialog_header, sizeof(dialog_header));
	p = mem + sizeof(dialog_header);

	options = httplib_get_valid_options();
	for (i = 0; options[i].name != NULL; i++) {
		style = WS_CHILD | WS_VISIBLE | WS_TABSTOP;
		x = 10 + (WIDTH / 2) * (nelems % 2);
		y = (nelems / 2 + 1) * HEIGHT + 5;
		width = WIDTH / 2 - 20 - LABEL_WIDTH;
		if (options[i].type == CONFIG_TYPE_NUMBER) {
			style |= ES_NUMBER;
			cl = 0x81;
			style |= WS_BORDER | ES_AUTOHSCROLL;
		} else if (options[i].type == CONFIG_TYPE_BOOLEAN) {
			cl = 0x80;
			style |= BS_AUTOCHECKBOX;
		} else if ((options[i].type == CONFIG_TYPE_FILE)
		           || (options[i].type == CONFIG_TYPE_DIRECTORY)) {
			style |= WS_BORDER | ES_AUTOHSCROLL;
			width -= 20;
			cl = 0x81;
			add_control(&p, dia, 0x80, ID_CONTROLS + i + ID_FILE_BUTTONS_DELTA, WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON, x + width + LABEL_WIDTH + 5, y, 15, 12, "...");
		} else {
			cl = 0x81;
			style |= WS_BORDER | ES_AUTOHSCROLL;
		}
		add_control(&p, dia, 0x82, ID_STATIC, WS_VISIBLE | WS_CHILD, x, y, LABEL_WIDTH, HEIGHT, options[i].name);
		add_control(&p, dia, cl, ID_CONTROLS + i, style, x + LABEL_WIDTH, y, width, 12, "");
		nelems++;

		assert(((intptr_t)p - (intptr_t)mem) < (intptr_t)sizeof(mem));
	}

	y = (((nelems + 1) / 2 + 1) * HEIGHT + 5);
	add_control(&p, dia, 0x80, ID_GROUP, WS_CHILD | WS_VISIBLE | BS_GROUPBOX, 5, 5, WIDTH - 10, y, " Settings ");
	y += 10;
	add_control(&p, dia, 0x80, ID_SAVE, WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP, WIDTH - 70, y, 65, 12, "Save Settings");
	add_control(&p, dia, 0x80, ID_RESET_DEFAULTS, WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP, WIDTH - 140, y, 65, 12, "Reset to defaults");
	add_control(&p, dia, 0x80, ID_RESET_FILE, WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP, WIDTH - 210, y, 65, 12, "Reload from file");
	add_control(&p, dia, 0x80, ID_RESET_ACTIVE, WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP, WIDTH - 280, y, 65, 12, "Reload active");
	add_control(&p, dia, 0x82, ID_STATIC, WS_CHILD | WS_VISIBLE | WS_DISABLED, 5, y, 100, 12, g_server_base_name);

	assert(((intptr_t)p - (intptr_t)mem) < (intptr_t)sizeof(mem));

	dia->cy = ((nelems + 1) / 2 + 1) * HEIGHT + 30;
	DialogBoxIndirectParam(NULL, dia, NULL, SettingsDlgProc, (LPARAM)NULL);
	guard--;

#undef HEIGHT
#undef WIDTH
#undef LABEL_WIDTH
}


static void change_password_file( void ) {

#define HEIGHT (15)
#define WIDTH (320)
#define LABEL_WIDTH (90)

	OPENFILENAME of;
	char path[PATH_MAX] = PASSWORDS_FILE_NAME;
	char strbuf[256];
	char u[256];
	char d[256];
	HWND hDlg = NULL;
	FILE *f;
	short y;
	short nelems;
	unsigned char mem[4096];
	unsigned char *p;
	DLGTEMPLATE *dia = (DLGTEMPLATE *)mem;
	char domain_str[256];
	const char *domain = httplib_get_option( g_ctx, "authentication_domain", domain_str, 256 );

	static struct {
		DLGTEMPLATE template; /* 18 bytes */
		WORD menu, class;
		wchar_t caption[1];
		WORD fontsiz;
		wchar_t fontface[7];
	} dialog_header = {{WS_CAPTION | WS_POPUP | WS_SYSMENU | WS_VISIBLE | DS_SETFONT | WS_DLGFRAME, WS_EX_TOOLWINDOW,
	                    0,
	                    200,
	                    200,
	                    WIDTH,
	                    0},
	                   0,
	                   0,
	                   L"",
	                   8,
	                   L"Tahoma"};

	if (guard == 0) {
		guard++;
	} else {
		return;
	}

	memset(&of, 0, sizeof(of));
	of.lStructSize = sizeof(of);
	of.hwndOwner = (HWND)hDlg;
	of.lpstrFile = path;
	of.nMaxFile = sizeof(path);
	of.lpstrInitialDir = httplib_get_option(g_ctx, "document_root");
	of.Flags = OFN_CREATEPROMPT | OFN_NOCHANGEDIR | OFN_HIDEREADONLY;

	if (IDOK != GetSaveFileName(&of)) {
		guard--;
		return;
	}

	f = fopen(path, "a+");
	if (f) {
		fclose(f);
	} else {
		MessageBox(NULL, path, "Can not open file", MB_ICONERROR);
		guard--;
		return;
	}

	do {
		(void)memset(mem, 0, sizeof(mem));
		(void)memcpy(mem, &dialog_header, sizeof(dialog_header));
		p = mem + sizeof(dialog_header);

		f = fopen(path, "r+");
		if (!f) {
			MessageBox(NULL, path, "Can not open file", MB_ICONERROR);
			guard--;
			return;
		}

		nelems = 0;
		while (fgets(strbuf, sizeof(strbuf), f)) {
			if (sscanf(strbuf, "%255[^:]:%255[^:]:%*s", u, d) != 2) {
				continue;
			}
			u[255] = 0;
			d[255] = 0;
			y = (nelems + 1) * HEIGHT + 5;
			add_control(&p, dia, 0x80, ID_CONTROLS + nelems + ID_FILE_BUTTONS_DELTA * 3, WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP, 10, y, 65, 12, "Modify password");
			add_control(&p, dia, 0x80, ID_CONTROLS + nelems + ID_FILE_BUTTONS_DELTA * 2, WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP, 80, y, 55, 12, "Remove user");
			add_control(&p, dia, 0x81, ID_CONTROLS + nelems + ID_FILE_BUTTONS_DELTA, WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL | WS_DISABLED, 245, y, 60, 12, d);
			add_control(&p, dia, 0x81, ID_CONTROLS + nelems, WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL | WS_DISABLED, 140, y, 100, 12, u);

			nelems++;
			assert(((intptr_t)p - (intptr_t)mem) < (intptr_t)sizeof(mem));
		}
		fclose(f);

		y = (nelems + 1) * HEIGHT + 10;
		add_control(&p, dia, 0x80, ID_ADD_USER, WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP, 80, y, 55, 12, "Add user");
		add_control(&p, dia, 0x81, ID_ADD_USER_NAME, WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL | WS_TABSTOP, 140, y, 100, 12, "");
		add_control(&p, dia, 0x81, ID_ADD_USER_REALM, WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL | WS_TABSTOP, 245, y, 60, 12, domain);

		y = (nelems + 2) * HEIGHT + 10;
		add_control(&p, dia, 0x80, ID_GROUP, WS_CHILD | WS_VISIBLE | BS_GROUPBOX, 5, 5, WIDTH - 10, y, " Users ");

		y += HEIGHT;
		add_control(&p, dia, 0x82, ID_STATIC, WS_CHILD | WS_VISIBLE | WS_DISABLED, 5, y, 100, 12, g_server_base_name);

		assert(((intptr_t)p - (intptr_t)mem) < (intptr_t)sizeof(mem));

		dia->cy = y + 20;
	} while ((IDOK == DialogBoxIndirectParam(
	                      NULL, dia, NULL, PasswordDlgProc, (LPARAM)path))
	         && (!g_exit_flag));

	guard--;

#undef HEIGHT
#undef WIDTH
#undef LABEL_WIDTH
}


static int
manage_service(int action)
{
	const char *service_name = g_server_name;
	SC_HANDLE hSCM = NULL, hService = NULL;
	SERVICE_DESCRIPTION descr;
	char path[PATH_MAX + 20] = ""; /* Path to executable plus magic argument */
	int success = 1;

	descr.lpDescription = (LPSTR)g_server_name;

	if ((hSCM = OpenSCManager(NULL, NULL, action == ID_INSTALL_SERVICE ? GENERIC_WRITE : GENERIC_READ)) == NULL) {
		success = 0;
		show_error();
	} else if (action == ID_INSTALL_SERVICE) {
		path[sizeof(path) - 1] = 0;
		GetModuleFileName(NULL, path, sizeof(path) - 1);
		strncat(path, " ", sizeof(path) - 1);
		strncat(path, service_magic_argument, sizeof(path) - 1);
		hService = CreateService(hSCM,
		                         service_name,
		                         service_name,
		                         SERVICE_ALL_ACCESS,
		                         SERVICE_WIN32_OWN_PROCESS,
		                         SERVICE_AUTO_START,
		                         SERVICE_ERROR_NORMAL,
		                         path,
		                         NULL,
		                         NULL,
		                         NULL,
		                         NULL,
		                         NULL);
		if (hService) {
			ChangeServiceConfig2(hService, SERVICE_CONFIG_DESCRIPTION, &descr);
		} else {
			show_error();
		}
	} else if (action == ID_REMOVE_SERVICE) {
		if ((hService = OpenService(hSCM, service_name, DELETE)) == NULL || !DeleteService(hService)) {
			show_error();
		}
	} else if ((hService = OpenService(hSCM, service_name, SERVICE_QUERY_STATUS)) == NULL) {
		success = 0;
	}

	if (hService)
		CloseServiceHandle(hService);
	if (hSCM)
		CloseServiceHandle(hSCM);

	return success;
}


static LRESULT CALLBACK
WindowProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	static SERVICE_TABLE_ENTRY service_table[2];
	int service_installed;
	char buf[200], *service_argv[2];
	POINT pt;
	HMENU hMenu;
	static UINT s_uTaskbarRestart; /* for taskbar creation */

	service_argv[0] = __argv[0];
	service_argv[1] = NULL;

	memset(service_table, 0, sizeof(service_table));
	service_table[0].lpServiceName = (LPSTR)g_server_name;
	service_table[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)ServiceMain;

	switch (msg) {

	case WM_CREATE:
		if (__argv[1] != NULL && !strcmp(__argv[1], service_magic_argument)) {
			start_libhttp(1, service_argv);
			StartServiceCtrlDispatcher(service_table);
			exit(EXIT_SUCCESS);
		} else {
			start_libhttp(__argc, __argv);
			s_uTaskbarRestart = RegisterWindowMessage(TEXT("TaskbarCreated"));
		}
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam)) {
		case ID_QUIT:
			stop_libhttp();
			Shell_NotifyIcon(NIM_DELETE, &TrayIcon);
			g_exit_flag = 1;
			PostQuitMessage(0);
			return 0;
		case ID_SETTINGS:
			show_settings_dialog();
			break;
		case ID_PASSWORD:
			change_password_file();
			break;
		case ID_INSTALL_SERVICE:
		case ID_REMOVE_SERVICE:
			manage_service(LOWORD(wParam));
			break;
		case ID_CONNECT:
			fprintf(stdout, "[%s]\n", get_url_to_first_open_port(g_ctx));
			ShellExecute(NULL, "open", get_url_to_first_open_port(g_ctx), NULL, NULL, SW_SHOW);
			break;
		}
		break;

	case WM_USER:
		switch (lParam) {
		case WM_RBUTTONUP:
		case WM_LBUTTONUP:
		case WM_LBUTTONDBLCLK:
			hMenu = CreatePopupMenu();
			AppendMenu(hMenu,
			           MF_STRING | MF_GRAYED,
			           ID_SEPARATOR,
			           g_server_name);
			AppendMenu(hMenu, MF_SEPARATOR, ID_SEPARATOR, "");
			service_installed = manage_service(0);
			snprintf(buf,
			         sizeof(buf) - 1,
			         "NT service: %s installed",
			         service_installed ? "" : "not");
			buf[sizeof(buf) - 1] = 0;
			AppendMenu(hMenu, MF_STRING | MF_GRAYED, ID_SEPARATOR, buf);
			AppendMenu(hMenu, MF_STRING | (service_installed ? MF_GRAYED : 0), ID_INSTALL_SERVICE, "Install service");
			AppendMenu(hMenu, MF_STRING | (!service_installed ? MF_GRAYED : 0), ID_REMOVE_SERVICE, "Deinstall service");
			AppendMenu(hMenu, MF_SEPARATOR, ID_SEPARATOR, "");
			AppendMenu(hMenu, MF_STRING, ID_CONNECT, "Start browser");
			AppendMenu(hMenu, MF_STRING, ID_SETTINGS, "Edit settings");
			AppendMenu(hMenu, MF_STRING, ID_PASSWORD, "Modify password file");
			AppendMenu(hMenu, MF_SEPARATOR, ID_SEPARATOR, "");
			AppendMenu(hMenu, MF_STRING, ID_QUIT, "Exit");
			GetCursorPos(&pt);
			SetForegroundWindow(hWnd);
			TrackPopupMenu(hMenu, 0, pt.x, pt.y, 0, hWnd, NULL);
			PostMessage(hWnd, WM_NULL, 0, 0);
			DestroyMenu(hMenu);
			break;
		}
		break;

	case WM_CLOSE:
		stop_libhttp();
		Shell_NotifyIcon(NIM_DELETE, &TrayIcon);
		g_exit_flag = 1;
		PostQuitMessage(0);
		return 0; /* We've just sent our own quit message, with proper hwnd. */

	default:
		if (msg == s_uTaskbarRestart)
			Shell_NotifyIcon(NIM_ADD, &TrayIcon);
	}

	return DefWindowProc(hWnd, msg, wParam, lParam);
}


static int
MakeConsole(void)
{
	DWORD err;
	int ok = (GetConsoleWindow() != NULL);
	if (!ok) {
		if (!AttachConsole(ATTACH_PARENT_PROCESS)) {
			FreeConsole();
			if (!AllocConsole()) {
				err = GetLastError();
				if (err == ERROR_ACCESS_DENIED) {
					MessageBox(NULL, "Insufficient rights to create a console window", "Error", MB_ICONERROR);
				}
			}
			AttachConsole(GetCurrentProcessId());
		}

		ok = (GetConsoleWindow() != NULL);
		if (ok) {
			freopen("CONIN$", "r", stdin);
			freopen("CONOUT$", "w", stdout);
			freopen("CONOUT$", "w", stderr);
		}
	}

	if (ok) {
		SetConsoleTitle(g_server_name);
	}

	return ok;
}


int WINAPI
WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR cmdline, int show)
{
	WNDCLASS cls;
	HWND hWnd;
	MSG msg;

	int i;
	int dataLen = 4;
	char data[256] = {0};
	char masked_data[256] = {0};
	uint32_t masking_key = 0x01020304;

	for (i = 0; i < dataLen - 3; i += 4) {
		*(uint32_t *)(void *)(masked_data + i) =
		    *(uint32_t *)(void *)(data + i) ^ masking_key;
	}
	if (i != dataLen) {
		/* convert 1-3 remaining bytes */
		i -= 4;
		while (i < dataLen) {
			*(uint8_t *)(void *)(masked_data + i) =
			    *(uint8_t *)(void *)(data + i)
			    ^ *(((uint8_t *)&masking_key) + (i % 4));
			i++;
		}
	}

#if 0
    /* http://lomont.org/Math/Papers/2008/Lomont_PRNG_2008.pdf */
	/* initialize state to random bits
	*/
	static unsigned long state[16];
	/* init should also reset this to 0 */
	static unsigned int index = 0;
	/* return 32 bit random number
	*/
	unsigned long WELLRN G512(void)
	{
		unsigned long a, b, c, d;
		a = state[index];
		c = state[(index + 13) & 15];
		b = a ^ c ^ (a << 16) ^ (c << 15);
		c = state[(index + 9) & 15];
		c ^= (c >> 11);
		a = state[index] = b ^ c;
		d = a ^ ((a << 5) & 0xDA442D24 UL);
		index = (index + 15) & 15;
		a = state[index];
		state[index] = a ^ b ^ d ^ (a << 2) ^ (b << 18) ^ (c << 28);
		return state[index];
	}

	uint32_t x, y, z, w;

	uint32_t xorshift128(void)
	{
		uint32_t t = x ^ (x << 11);
		x = y;
		y = z;
		z = w;
		return w = w ^ (w >> 19) ^ t ^ (t >> 8);
	}

	static uint64_t lfsr = 1;
	static uint64_t lcg = 0;
	uint64_t r = 0;

	do {
		lfsr = (lfsr >> 1)
		       | ((((lfsr >> 0) ^ (lfsr >> 1) ^ (lfsr >> 3) ^ (lfsr >> 4)) & 1)
		          << 63);
		lcg = lcg * 6364136223846793005 + 1442695040888963407;
		++r;
	} while (lcg != 0);

	fprintf(stdout, "lfsr = %I64u, lcg = %i64u, r = %i64u\n", lfsr, lcg, r);
#endif

	(void)hInst;
	(void)hPrev;
	(void)cmdline;
	(void)show;

	init_server_name((int)__argc, (const char **)__argv);
	memset(&cls, 0, sizeof(cls));
	cls.lpfnWndProc = (WNDPROC)WindowProc;
	cls.hIcon = LoadIcon(NULL, IDI_APPLICATION);
	cls.lpszClassName = g_server_base_name;

	RegisterClass(&cls);
	hWnd = CreateWindow(cls.lpszClassName, g_server_name, WS_OVERLAPPEDWINDOW, 0, 0, 0, 0, NULL, NULL, NULL, NULL);
	ShowWindow(hWnd, SW_HIDE);

	if (g_icon_name) {
		hIcon =
		    LoadImage(NULL, g_icon_name, IMAGE_ICON, 16, 16, LR_LOADFROMFILE);
	} else {
		hIcon = LoadImage(GetModuleHandle(NULL), MAKEINTRESOURCE(ID_ICON), IMAGE_ICON, 16, 16, 0);
	}

	TrayIcon.cbSize = sizeof(TrayIcon);
	TrayIcon.uID = ID_ICON;
	TrayIcon.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
	TrayIcon.hIcon = hIcon;
	TrayIcon.hWnd = hWnd;
	snprintf(TrayIcon.szTip, sizeof(TrayIcon.szTip), "%s", g_server_name);
	TrayIcon.uCallbackMessage = WM_USER;
	Shell_NotifyIcon(NIM_ADD, &TrayIcon);

	while (GetMessage(&msg, hWnd, 0, 0) > 0) {
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}

	/* Return the WM_QUIT value. */
	return (int)msg.wParam;
}


int
main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	return WinMain(0, 0, 0, 0);
}


#elif defined(USE_COCOA)  /* GUI */
#import <Cocoa/Cocoa.h>

@interface LibHTTP : NSObject <NSApplicationDelegate>
- (void)openBrowser;
- (void)shutDown;
@end

@implementation LibHTTP
- (void)openBrowser
{
	[[NSWorkspace sharedWorkspace]
	    openURL:[NSURL URLWithString:[NSString stringWithUTF8String:
	                                               get_url_to_first_open_port(
	                                                   g_ctx)]]];
}
- (void)editConfig
{
	create_config_file(g_ctx, g_config_file_name);
	NSString *path = [NSString stringWithUTF8String:g_config_file_name];
	if (![[NSWorkspace sharedWorkspace] openFile:path
	                             withApplication:@"TextEdit"]) {
		NSAlert *alert = [[[NSAlert alloc] init] autorelease];
		[alert setAlertStyle:NSWarningAlertStyle];
		[alert setMessageText:NSLocalizedString(@"Unable to open config file.",
		                                        "")];
		[alert setInformativeText:path];
		(void)[alert runModal];
	}
}
- (void)shutDown
{
	[NSApp terminate:nil];
}
@end

int
main(int argc, char *argv[])
{
	init_server_name(argc, (const char **)argv);
	start_libhttp(argc, argv);

	[NSAutoreleasePool new];
	[NSApplication sharedApplication];

	/* Add delegate to process menu item actions */
	LibHTTP *myDelegate = [[LibHTTP alloc] autorelease];
	[NSApp setDelegate:myDelegate];

	/* Run this app as agent */
	ProcessSerialNumber psn = {0, kCurrentProcess};
	TransformProcessType(&psn, kProcessTransformToBackgroundApplication);
	SetFrontProcess(&psn);

	/* Add status bar menu */
	id menu = [[NSMenu new] autorelease];

	/* Add version menu item */
	[menu
	    addItem:
	        [[[NSMenuItem alloc]
	            /*initWithTitle:[NSString stringWithFormat:@"%s", server_name]*/
	            initWithTitle:[NSString stringWithUTF8String:g_server_name]
	                   action:@selector(noexist)
	            keyEquivalent:@""] autorelease]];

	/* Add configuration menu item */
	[menu addItem:[[[NSMenuItem alloc] initWithTitle:@"Edit configuration"
	                                          action:@selector(editConfig)
	                                   keyEquivalent:@""] autorelease]];

	/* Add connect menu item */
	[menu
	    addItem:[[[NSMenuItem alloc] initWithTitle:@"Open web root in a browser"
	                                        action:@selector(openBrowser)
	                                 keyEquivalent:@""] autorelease]];

	/* Separator */
	[menu addItem:[NSMenuItem separatorItem]];

	/* Add quit menu item */
	[menu addItem:[[[NSMenuItem alloc] initWithTitle:@"Quit"
	                                          action:@selector(shutDown)
	                                   keyEquivalent:@"q"] autorelease]];

	/* Attach menu to the status bar */
	id item = [[[NSStatusBar systemStatusBar]
	    statusItemWithLength:NSVariableStatusItemLength] retain];
	[item setHighlightMode:YES];
	[item setImage:[NSImage imageNamed:@"civetweb_22x22.png"]];
	[item setMenu:menu];

	/* Run the app */
	[NSApp activateIgnoringOtherApps:YES];
	[NSApp run];

	stop_libhttp();

	return EXIT_SUCCESS;
}

#else  /* GUI */

int main( int argc, char *argv[] ) {

	char buf1[1024];
	char buf2[1024];

	init_server_name( argc, (const char **)argv );
	start_libhttp(argc, argv);
	fprintf(stdout,
	        "%s started on port(s) %s with web root [%s]\n",
	        g_server_name,
	        httplib_get_option( g_ctx, "listening_ports", buf1, sizeof(buf1) ),
	        httplib_get_option( g_ctx, "document_root",   buf2, sizeof(buf2) ) );
	while (g_exit_flag == 0) {
		sleep(1);
	}
	fprintf(stdout,
	        "Exiting on signal %d, waiting for all threads to finish...",
	        g_exit_flag);
	fflush(stdout);
	stop_libhttp();
	fprintf(stdout, "%s", " done.\n");

	return EXIT_SUCCESS;
}
#endif /* GUI / _WIN32 */
