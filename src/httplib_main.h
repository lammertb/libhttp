/* 
 * Copyright (C) 2016-2019 Lammert Bies
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



#if defined(_WIN32)

#if !defined(_CRT_SECURE_NO_WARNINGS)
#define _CRT_SECURE_NO_WARNINGS /* Disable deprecation warning in VS2005 */
#endif  /* _CRT_SECURE_NO_WARNINGS */


#ifndef _WIN32_WINNT /* defined for tdm-gcc so we can use getnameinfo */
#define _WIN32_WINNT 0x0501
#endif  /* _WIN32_WINNT */

#else  /* _WIN32 */

#if defined(__GNUC__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE /* for setgroups() */
#endif  /* __GNUC__  && ! _GNU_SOURCE */

#if defined(__linux__) && !defined(_XOPEN_SOURCE)
#define _XOPEN_SOURCE 600 /* For flockfile() on Linux */
#endif  /* __linux__  &&  ! _XOPEN_SOURCE */

#ifndef _LARGEFILE_SOURCE
#define _LARGEFILE_SOURCE /* For fseeko(), ftello() */
#endif  /* _LARGEFILE_SOURCE */

#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64 /* Use 64-bit file offsets by default */
#endif  /* _FILE_OFFSET_BITS */

#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS /* <inttypes.h> wants this for C++ */
#endif  /* __STDC_FORMAT_MACROS */

#ifndef __STDC_LIMIT_MACROS
#define __STDC_LIMIT_MACROS /* C++ wants that for INT64_MAX */
#endif  /* __STDC_LIMIT_MACROS */

#ifdef __sun
#define __EXTENSIONS__  /* to expose flockfile and friends in stdio.h */
#define __inline inline /* not recognized on older compiler versions */
#endif  /* __sun */
#endif  /* _WIN32 */

#if defined(_MSC_VER)
/* 'type cast' : conversion from 'int' to 'HANDLE' of greater size */
#pragma warning(disable : 4306)
/* conditional expression is constant: introduced by FD_SET(..) */
#pragma warning(disable : 4127)
#pragma warning(disable : 4548)
/* padding added after data member */
#pragma warning(disable : 4820)
/* not defined as a preprocessor macro, replacing with '0' for '#if/#elif' */
#pragma warning(disable : 4668)
#endif  /* _MSC_VER */


/* This code uses static_assert to check some conditions.
 * Unfortunately some compilers still do not support it, so we have a
 * replacement function here. */
#if defined(_MSC_VER) && (_MSC_VER >= 1600)
#define httplib_static_assert static_assert
#elif defined(__cplusplus) && (__cplusplus >= 201103L)
#define httplib_static_assert static_assert
#elif defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L)
#define httplib_static_assert _Static_assert
#else  /* _MSC_VER  &&  _MSC_VER >= 1600 */
char static_assert_replacement[1];
#define httplib_static_assert(cond, txt) extern char static_assert_replacement[(cond) ? 1 : -1]
#endif  /* _MSC_VER  &&  _MSC_VER >= 1600 */

/*
 * TODO: LJB: Following asserts should not be in this section but in the test routines
 * because older GCC versions (4.4.7) throw errors on this
 */

// httplib_static_assert(sizeof(int) == 4 || sizeof(int) == 8, "int data type size check");
// httplib_static_assert(sizeof(void *) == 4 || sizeof(void *) == 8, "pointer data type size check");
// httplib_static_assert(sizeof(void *) >= sizeof(int), "data type size check");


/* DTL -- including winsock2.h works better if lean and mean */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif  /* WIN32_LEAN_AND_MEAN */

/* Include the header file here, so the LibHTTP interface is defined for the
 * entire implementation, including the following forward definitions. */

#include <stdbool.h>
#include <stdint.h>
#include "libhttp.h"


#ifndef _WIN32_WCE /* Some ANSI #includes are not available on Windows CE */
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#endif /* !_WIN32_WCE */

#ifdef __MACH__

#define CLOCK_MONOTONIC (1)
#define CLOCK_REALTIME (2)

#include <sys/time.h>
#include <mach/clock.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <assert.h>

#endif  /* __MACH__ */

#include <time.h>
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>


#ifndef MAX_WORKER_THREADS
#define MAX_WORKER_THREADS (1024 * 64)
#endif  /* MAX_WORKER_THREADS */

#define SHUTDOWN_RD (0)
#define SHUTDOWN_WR (1)
#define SHUTDOWN_BOTH (2)



#if defined(_WIN32)   /* WINDOWS / UNIX include block */
#include <windows.h>
#include <winsock2.h> /* DTL add for SO_EXCLUSIVE */
#include <ws2tcpip.h>

typedef const char *SOCK_OPT_TYPE;

httplib_static_assert(PATH_MAX >= 1, "path length must be a positive number");

#ifndef _IN_PORT_T
#ifndef in_port_t
#define in_port_t u_short
#endif  /* in_port_t */
#endif  /* _IN_PORT_T */

#ifndef _WIN32_WCE
#include <process.h>
#include <direct.h>
#include <io.h>
#else  /* _WIN32_WCE */
#define NO_CGI   /* WinCE has no pipes */
#define NO_POPEN /* WinCE has no popen */

typedef long off_t;

#define errno ((int)(GetLastError()))
#define strerror(x) (_ultoa(x, (char *)_alloca(sizeof(x) * 3), 10))
#endif /* _WIN32_WCE */

#define MAKEUQUAD(lo, hi)                                                      \
	((uint64_t)(((uint32_t)(lo)) | ((uint64_t)((uint32_t)(hi))) << 32))
#define RATE_DIFF (10000000) /* 100 nsecs */
#define EPOCH_DIFF (MAKEUQUAD(0xd53e8000, 0x019db1de))
#define SYS2UNIX_TIME(lo, hi)                                                  \
	((time_t)((MAKEUQUAD((lo), (hi)) - EPOCH_DIFF) / RATE_DIFF))

/* Visual Studio 6 does not know __func__ or __FUNCTION__
 * The rest of MS compilers use __FUNCTION__, not C99 __func__
 * Also use _strtoui64 on modern M$ compilers */
#if defined(_MSC_VER)
#if (_MSC_VER < 1300)
#define STRX(x) #x
#define STR(x) STRX(x)
#define __func__ __FILE__ ":" STR(__LINE__)
#define strtoull(x, y, z) ((unsigned __int64)_atoi64(x))
#define strtoll(x, y, z) (_atoi64(x))
#else  /* _MSC_VER < 1300 */
#define __func__ __FUNCTION__
#define strtoull(x, y, z) (_strtoui64(x, y, z))
#define strtoll(x, y, z) (_strtoi64(x, y, z))
#endif  /* _MSC_VER < 1300 */
#endif /* _MSC_VER */

#define ERRNO ((int)(GetLastError()))
#define NO_SOCKLEN_T

#if defined(_WIN64) || defined(__MINGW64__)
#define SSL_LIB "ssleay64.dll"
#define CRYPTO_LIB "libeay64.dll"
#else  /* _WIN64  ||  __MINGW64__ */
#define SSL_LIB "ssleay32.dll"
#define CRYPTO_LIB "libeay32.dll"
#endif  /* _WIN64  ||  __MINGW64__ */

#define O_NONBLOCK (0)
#ifndef W_OK
#define W_OK (2) /* http://msdn.microsoft.com/en-us/library/1w06ktdy.aspx */
#endif  /* W_OK */

#if !defined(EWOULDBLOCK)
#define EWOULDBLOCK WSAEWOULDBLOCK
#endif /* !EWOULDBLOCK */

#define _POSIX_
#define INT64_FMT "I64d"
#define UINT64_FMT "I64u"

#define WINCDECL __cdecl
#define vsnprintf_impl _vsnprintf
#define access _access
#define httplib_sleep(x) (Sleep(x))

#define pipe(x) _pipe(x, MG_BUF_LEN, _O_BINARY)
#ifndef popen
#define popen(x, y) (_popen(x, y))
#endif  /* popen */

#ifndef pclose
#define pclose(x) (_pclose(x))
#endif  /* pclose */

#define close(x) (_close(x))
#define dlsym(x, y) (GetProcAddress((HINSTANCE)(x), (y)))
#define RTLD_LAZY (0)
#define fseeko(x, y, z) ((_lseeki64(_fileno(x), (y), (z)) == -1) ? -1 : 0)
#define fdopen(x, y) (_fdopen((x), (y)))
#define write(x, y, z) (_write((x), (y), (unsigned)z))
#define read(x, y, z) (_read((x), (y), (unsigned)z))
#define flockfile(x) (EnterCriticalSection(&global_log_file_lock))
#define funlockfile(x) (LeaveCriticalSection(&global_log_file_lock))
#define sleep(x) (Sleep((x)*1000))
#define rmdir(x) (_rmdir(x))
#define timegm(x) (_mkgmtime(x))

#if !defined(fileno)
#define fileno(x) (_fileno(x))
#endif /* !fileno MINGW #defines fileno */

#ifndef __clockid_t_defined
typedef DWORD clockid_t;
#endif  /* __clockid_t_defined */

#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC (1)
#endif  /* CLOCK_MONOTONIC */

#ifndef CLOCK_REALTIME
#define CLOCK_REALTIME (2)
#endif  /* CLOCK_REALTIME */

#if defined(_MSC_VER) && (_MSC_VER >= 1900)
#define _TIMESPEC_DEFINED
#endif  /* _MSC_VER  &&  _MSC_VER >= 1900 */


/* Mark required libraries */
#if defined(_MSC_VER)
#pragma comment(lib, "Ws2_32.lib")
#endif  /* _MSC_VER */

#else /* defined(_WIN32) -                          \
         WINDOWS / UNIX include block */

#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/tcp.h>
typedef const void *SOCK_OPT_TYPE;

#if defined(ANDROID)
typedef unsigned short int in_port_t;
#endif

#include <pwd.h>
#include <unistd.h>
#include <grp.h>
#include <dirent.h>
#define vsnprintf_impl vsnprintf

#if !defined(NO_SSL_DL) && !defined(NO_SSL)
#include <dlfcn.h>
#endif
#include <pthread.h>
#if defined(__MACH__)
#define SSL_LIB "libssl.dylib"
#define CRYPTO_LIB "libcrypto.dylib"
#else
#if !defined(SSL_LIB)
#define SSL_LIB "libssl.so"
#endif
#if !defined(CRYPTO_LIB)
#define CRYPTO_LIB "libcrypto.so"
#endif
#endif
#ifndef O_BINARY
#define O_BINARY (0)
#endif /* O_BINARY */
#define closesocket(a) (close(a))
#define httplib_sleep(x) (usleep((x)*1000))
#define ERRNO (errno)
#define INVALID_SOCKET (-1)
#define INT64_FMT PRId64
#define UINT64_FMT PRIu64
typedef int SOCKET;
#define WINCDECL

#if defined(__hpux)
/* HPUX 11 does not have monotonic, fall back to realtime */
#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC CLOCK_REALTIME
#endif

/* HPUX defines socklen_t incorrectly as size_t which is 64bit on
 * Itanium.  Without defining _XOPEN_SOURCE or _XOPEN_SOURCE_EXTENDED
 * the prototypes use int* rather than socklen_t* which matches the
 * actual library expectation.  When called with the wrong size arg
 * accept() returns a zero client inet addr and check_acl() always
 * fails.  Since socklen_t is widely used below, just force replace
 * their typedef with int. - DTL
 */
#define socklen_t int
#endif /* hpux */

#endif /* defined(_WIN32) -                         \
          WINDOWS / UNIX include block */

#define IP_ADDR_STR_LEN (50)

#define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))


#if !defined(MSG_NOSIGNAL)
#define MSG_NOSIGNAL (0)
#endif

#if !defined(SOMAXCONN)
#define SOMAXCONN (100)
#endif

/* Size of the accepted socket queue */
#if !defined(MGSQLEN)
#define MGSQLEN (20)
#endif

#ifndef MAX_REQUEST_SIZE
#define MAX_REQUEST_SIZE (16384)
#endif

/* Unified socket address. For IPv6 support, add IPv6 address structure in the
 * union u. */
union usa {
	struct sockaddr sa;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
};

/*
 * enum CTX_STATUS_...
 *
 * A context can be in several states. It can be running, it can be in the
 * process of terminating and it can be terminated.
 */

enum ctx_status_t {
	CTX_STATUS_RUNNING,
	CTX_STATUS_STOPPING,
	CTX_STATUS_TERMINATED
};

enum ctx_type_t {
	CTX_TYPE_SERVER,
	CTX_TYPE_CLIENT
};

enum uri_type_t {
	URI_TYPE_UNKNOWN,
	URI_TYPE_ASTERISK,
	URI_TYPE_RELATIVE,
	URI_TYPE_ABS_NOPORT,
	URI_TYPE_ABS_PORT
};

#if defined(NO_SSL)

typedef struct SSL SSL; /* dummy for SSL argument to push/pull */
typedef struct SSL_CTX SSL_CTX;

#else  /* NO_SSL */

#if defined(NO_SSL_DL)

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/engine.h>
#include <openssl/conf.h>
#include <openssl/dh.h>

#else  /* NO_SSL_DL */

struct ssl_func;
typedef struct ssl_st SSL;
typedef struct ssl_method_st SSL_METHOD;
typedef struct ssl_ctx_st SSL_CTX;
typedef struct x509_store_ctx_st X509_STORE_CTX;
// typedef struct x509_name X509_NAME;
typedef struct asn1_integer ASN1_INTEGER;
typedef struct evp_md EVP_MD;
typedef struct x509 X509;
typedef struct x509_name X509_NAMEX;

#endif  /* NO_SSL_DL */
#endif  /* NO_SSL */

struct httplib_workerTLS {
	unsigned long thread_idx;
#if defined(_WIN32)
	HANDLE pthread_cond_helper_mutex;
	struct httplib_workerTLS *next_waiting_thread;
#endif
};

#if defined(_WIN32)
extern CRITICAL_SECTION			global_log_file_lock;
#endif

#define PASSWORDS_FILE_NAME		".htpasswd"
#define CGI_ENVIRONMENT_SIZE		(4096)
#define MAX_CGI_ENVIR_VARS		(256)
#define MG_BUF_LEN			(8192)
#define ERROR_STRING_LEN		(256)

/*
 * TODO: LJB: Move to test functions
 */

// httplib_static_assert(MAX_REQUEST_SIZE >= 256, "request size length must be a positive number");


/* Describes listening socket, or socket which was accept()-ed by the master
 * thread and queued for future handling by the worker thread. */
struct socket {
	SOCKET sock;			/* Listening socket					*/
	union usa lsa;			/* Local socket address					*/
	union usa rsa;			/* Remote socket address				*/
	bool has_ssl;			/* Is port SSL-ed					*/
	bool has_redir;			/* Is port supposed to redirect everything to SSL port	*/
	unsigned char in_use;		/* Is valid						*/
};


/*
 * struct httplib_handler_info;
 */

struct httplib_handler_info {
	/* Name/Pattern of the URI. */
	char *uri;
	size_t uri_len;

	/* handler type */
	int handler_type;

	/* Handler for http/https or authorization requests. */
	httplib_request_handler handler;

	/* Handler for ws/wss (websocket) requests. */
	httplib_websocket_connect_handler connect_handler;
	httplib_websocket_ready_handler ready_handler;
	httplib_websocket_data_handler data_handler;
	httplib_websocket_close_handler close_handler;

	/* Handler for authorization requests */
	httplib_authorization_handler auth_handler;

	/* User supplied argument for the handler function. */
	void *cbdata;

	/* next handler in a linked list */
	struct httplib_handler_info *next;
};

/*
 * struct lh_ctx_t;
 */

struct lh_ctx_t {

	volatile enum ctx_status_t status;	/* Should we stop event loop								*/
	SSL_CTX *ssl_ctx;			/* SSL context										*/
	struct lh_clb_t callbacks;		/* User-defined callback function							*/
	void *user_data;			/* User-defined data									*/
	enum ctx_type_t ctx_type;		/* CTX_TYPE_SERVER or CTX_TYPE_CLIENT							*/

	struct socket *listening_sockets;
	struct pollfd *listening_socket_fds;
	unsigned int num_listening_sockets;

	pthread_mutex_t thread_mutex;		/* Protects (max|num)_threads								*/

#ifdef ALTERNATIVE_QUEUE
	struct socket *client_socks;
	void **client_wait_events;
#else
	struct socket queue[MGSQLEN];		/* Accepted sockets									*/
	volatile int sq_head;			/* Head of the socket queue								*/
	volatile int sq_tail;			/* Tail of the socket queue								*/
	pthread_cond_t sq_full;			/* Signaled when socket is produced							*/
	pthread_cond_t sq_empty;		/* Signaled when socket is consumed							*/
#endif

	pthread_t masterthreadid;		/* The master thread ID									*/
	pthread_t *workerthreadids;		/* The worker thread IDs								*/

	time_t start_time;			/* Server start time, used for authentication						*/
	uint64_t auth_nonce_mask;		/* Mask for all nonce values								*/
	pthread_mutex_t nonce_mutex;		/* Protects nonce_count									*/
	unsigned long nonce_count;		/* Used nonces, used for authentication							*/

	char *systemName;			/* What operating system is running							*/

	/* linked list of uri handlers */
	struct httplib_handler_info *handlers;

#ifdef USE_TIMERS
	struct ttimers *timers;
#endif

	enum lh_dbg_t	debug_level;

	char *	access_control_allow_origin;
	char *	access_control_list;
	char *	access_log_file;
	char *	authentication_domain;
	char *	cgi_environment;
	char *	cgi_interpreter;
	char *	cgi_pattern;
	char *	document_root;
	char *	error_log_file;
	char *	error_pages;
	char *	extra_mime_types;
	char *	global_auth_file;
	char *	hide_file_pattern;
	char *	index_files;
	char *	listening_ports;
	char *	protect_uri;
	char *	put_delete_auth_file;
	char *	run_as_user;
	char *	ssi_pattern;
	char *	ssl_ca_file;
	char *	ssl_ca_path;
	char *	ssl_certificate;
	char *	ssl_cipher_list;
	char *	throttle;
	char *	url_rewrite_patterns;
	char *	websocket_root;

	int	num_threads;
	int	request_timeout;
	int	ssi_include_depth;
	int	ssl_protocol_version;
	int	ssl_verify_depth;
	int	static_file_max_age;
	int	websocket_timeout;

	bool	allow_sendfile_call;
	bool	decode_url;
	bool	enable_directory_listing;
	bool	enable_keep_alive;
	bool	ssl_short_trust;
	bool	ssl_verify_paths;
	bool	ssl_verify_peer;
	bool	tcp_nodelay;
};

/*
 * struct lh_con_t;
 */

							/************************************************************************************************/
struct lh_con_t {					/*												*/
	struct lh_rqi_t	request_info;			/* The request info of the connection								*/
	SSL *		ssl;				/* SSL descriptor										*/
	SSL_CTX *	client_ssl_ctx;			/* SSL context for client connections								*/
	struct socket	client;				/* Connected client										*/
	time_t		conn_birth_time;		/* Time (wall clock) when connection was established						*/
	struct timespec	req_time;			/* Time (since system start) when the request was received					*/
	int64_t		num_bytes_sent;			/* Total bytes sent to client									*/
	int64_t		content_len;			/* Content-Length header value									*/
	int64_t		consumed_content;		/* How many bytes of content have been read							*/
	int		is_chunked;			/* Transfer-Encoding is chunked: 0=no, 1=yes: data available, 2: all data read			*/
	size_t		chunk_remainder;		/* Unread data from the last chunk								*/
	char *		buf;				/* Buffer for received data									*/
	char *		path_info;			/* PATH_INFO part of the URL									*/
	bool		must_close;			/* true, if connection must be closed								*/
	bool		in_error_handler;		/* true, if in handler for user defined error pages						*/
	int		buf_size;			/* Buffer size											*/
	int		request_len;			/* Size of the request + headers in a buffer							*/
	int		data_len;			/* Total size of data in a buffer								*/
	int		status_code;			/* HTTP reply status code, e.g. 200								*/
	time_t		last_throttle_time;		/* Last time throttled data was sent								*/
	int64_t		throttle;			/* Throttling, bytes/sec. <= 0 means no throttle						*/
	int64_t		last_throttle_bytes;		/* Bytes sent this second									*/
	pthread_mutex_t	mutex;				/* Used by httplib_(un)lock_connection to ensure atomic transmissions for websockets		*/
	int		thread_index;			/* Thread index within ctx									*/
};							/*												*/
							/************************************************************************************************/

							/************************************************************************************************/
							/*												*/
							/* struct lh_ip_t;										*/
							/*												*/
							/* LibHTTP allows both IPv4 and IPv6 communication. The code base doesn't make any difference	*/
							/* between the two by encoding internally both address variations as a structure with two	*/
							/* 64 bit values. IPv6 values will fit in this structure perfectly as they need 128 bits, while	*/
							/* IPv4 addresses are stored as ::FFFF:0:0/96 addresses which is the official dual stack way	*/
							/* of representing IPv4 addresses in IPv6 address space.					*/
struct lh_ip_t {					/*												*/
	uint64_t	high_quad;			/* The high order 64 bits of an IP address							*/
	uint64_t	low_quad;			/* The low order 64 bits of an IP address							*/
};							/*												*/
							/************************************************************************************************/

struct worker_thread_args {
	struct lh_ctx_t *	ctx;
	int			index;
};


struct websocket_client_thread_data {
	struct lh_ctx_t *		ctx;
	struct lh_con_t *		conn;
	httplib_websocket_data_handler	data_handler;
	httplib_websocket_close_handler	close_handler;
	void *				callback_data;
};

struct uriprot_tp {
	const char *	proto;
	size_t		proto_len;
	unsigned	default_port;
};

struct file {
	uint64_t	size;
	time_t		last_modified;
	FILE *		fp;
	const char *	membuf; /* Non-NULL if file data is in memory */
	int		is_directory;
	int		gzipped; /* set to 1 if the content is gzipped in which case we need a content-encoding: gzip header */
};

#define STRUCT_FILE_INITIALIZER    { (uint64_t)0, (time_t)0, NULL, NULL, 0, 0 } 

/* Describes a string (chunk of memory). */
struct vec {
	const char *	ptr;
	size_t		len;
};

enum { REQUEST_HANDLER, WEBSOCKET_HANDLER, AUTH_HANDLER };

/* Directory entry */
struct de {
	struct lh_con_t *	conn;
	char *			file_name;
	struct file		file;
};

struct dir_scan_data {
	struct de *		entries;
	unsigned int		num_entries;
	unsigned int		arr_size;
};


/*
 * This structure helps to create an environment for the spawned CGI program.
 * Environment is an array of "VARIABLE=VALUE\0" ASCIIZ strings,
 * last element must be NULL.
 * However, on Windows there is a requirement that all these VARIABLE=VALUE\0
 * strings must reside in a contiguous buffer. The end of the buffer is
 * marked by two '\0' characters.
 * We satisfy both worlds: we create an envp array (which is vars), all
 * entries are actually pointers inside buf.
 */

struct cgi_environment {
	struct lh_con_t *conn;
	/* Data block */
	char *buf;      /* Environment buffer */
	size_t buflen;  /* Space available in buf */
	size_t bufused; /* Space taken in buf */
	                /* Index block */
	char **var;     /* char **envp */
	size_t varlen;  /* Number of variables available in var */
	size_t varused; /* Number of variables stored in var */
};

/* Parsed Authorization header */
struct ah {
	char *	user;
	char *	uri;
	char *	cnonce;
	char *	response;
	char *	qop;
	char *	nc;
	char *	nonce;
};

struct read_auth_file_struct {
	struct lh_con_t *	conn;
	struct ah 		ah;
	char *			domain;
	char 			buf[256 + 256 + 40];
	char *			f_user;
	char *			f_domain;
	char *			f_ha1;
};

/*
 * Functions local to the server. These functions all begin with XX_httplib to
 * indicate that these are private functions.
 */

typedef struct {
	uint32_t state[5];
	uint32_t count[2];
	unsigned char buffer[64];
} SHA1_CTX;

/*
 * TODO: LJB: Move to test functions
 */

// httplib_static_assert(MAX_WORKER_THREADS >= 1, "worker threads must be a positive number");
// httplib_static_assert(sizeof(size_t) == 4 || sizeof(size_t) == 8, "size_t data type size check");

/* va_copy should always be a macro, C99 and C++11 - DTL */
#ifndef va_copy
#define va_copy(x, y) ((x) = (y))
#endif


#if defined(_WIN32_WCE)
#define _beginthreadex(psec, stack, func, prm, flags, ptid)	(uintptr_t) CreateThread(psec, stack, func, prm, flags, ptid)
#define access(x, a) 1 /* not required anyway */
/* WinCE-TODO: define stat, remove, rename, _rmdir, _lseeki64 */
#define EEXIST 1 /* TODO: See Windows error codes */
#define EACCES 2 /* TODO: See Windows error codes */
#define ENOENT 3 /* TODO: See Windows Error codes */
#endif /* defined(_WIN32_WCE) */


/* Darwin prior to 7.0 and Win32 do not have socklen_t */
#ifdef NO_SOCKLEN_T
typedef int		socklen_t;
#endif /* NO_SOCKLEN_T */
#define _DARWIN_UNLIMITED_SELECT

#if defined(_WIN32)
int		clock_gettime( clockid_t clk_id, struct timespec *tp );
#endif


void			SHA1Final( unsigned char digest[20], SHA1_CTX *context );
void			SHA1Init( SHA1_CTX *context );
void			SHA1Update( SHA1_CTX *context, const unsigned char *data, uint32_t len );

struct lh_ctx_t *	XX_httplib_abort_start( struct lh_ctx_t *ctx, PRINTF_FORMAT_STRING(const char *fmt), ...) PRINTF_ARGS(2, 3);
void			XX_httplib_accept_new_connection( const struct socket *listener, struct lh_ctx_t *ctx );
bool			XX_httplib_authorize( struct lh_ctx_t *ctx, struct lh_con_t *conn, struct file *filep );
const char *		XX_httplib_builtin_mime_ext( int index );
const char *		XX_httplib_builtin_mime_type( int index );
int			XX_httplib_check_acl( struct lh_ctx_t *ctx, uint32_t remote_ip );
bool			XX_httplib_check_authorization( struct lh_ctx_t *ctx, struct lh_con_t *conn, const char *path );
bool			XX_httplib_check_password( const char *method, const char *ha1, const char *uri, const char *nonce, const char *nc, const char *cnonce, const char *qop, const char *response );
void			XX_httplib_close_all_listening_sockets( struct lh_ctx_t *ctx );
void			XX_httplib_close_connection( struct lh_ctx_t *ctx, struct lh_con_t *conn );
void			XX_httplib_close_socket_gracefully( struct lh_ctx_t *ctx, struct lh_con_t *conn );
int WINCDECL		XX_httplib_compare_dir_entries( const void *p1, const void *p2 );
bool			XX_httplib_connect_socket( struct lh_ctx_t *ctx, const char *host, int port, int use_ssl, SOCKET *sock, union usa *sa );
void			XX_httplib_construct_etag( struct lh_ctx_t *ctx, char *buf, size_t buf_len, const struct file *filep );
int			XX_httplib_consume_socket( struct lh_ctx_t *ctx, struct socket *sp, int thread_index );
void			XX_httplib_delete_file( struct lh_ctx_t *ctx, struct lh_con_t *conn, const char *path );
void			XX_httplib_dir_scan_callback( struct lh_ctx_t *ctx, struct de *de, void *data );
void			XX_httplib_discard_unread_request_data( const struct lh_ctx_t *ctx, struct lh_con_t *conn );
int			XX_httplib_fclose( struct file *filep );
void			XX_httplib_fclose_on_exec( struct lh_ctx_t *ctx, struct file *filep, struct lh_con_t *conn );
const char *		XX_httplib_fgets( char *buf, size_t size, struct file *filep, char **p );
bool			XX_httplib_fopen( struct lh_ctx_t *ctx, const struct lh_con_t *conn, const char *path, const char *mode, struct file *filep );
bool			XX_httplib_forward_body_data( struct lh_ctx_t *ctx, struct lh_con_t *conn, FILE *fp, SOCKET sock, SSL *ssl );
void			XX_httplib_free_config_options( struct lh_ctx_t *ctx );
void			XX_httplib_free_context( struct lh_ctx_t *ctx );
const char *		XX_httplib_get_header( const struct lh_rqi_t *ri, const char *name );
void			XX_httplib_get_mime_type( const struct lh_ctx_t *ctx, const char *path, struct vec *vec );
const char *		XX_httplib_get_rel_url_at_current_server( const struct lh_ctx_t *ctx, const char *uri, const struct lh_con_t *conn );
uint32_t		XX_httplib_get_remote_ip( const struct lh_con_t *conn );
int			XX_httplib_get_request_handler( struct lh_ctx_t *ctx, struct lh_con_t *conn, int handler_type, httplib_request_handler *handler, httplib_websocket_connect_handler *connect_handler, httplib_websocket_ready_handler *ready_handler, httplib_websocket_data_handler *data_handler, httplib_websocket_close_handler *close_handler, httplib_authorization_handler *auth_handler, void **cbdata );
int			XX_httplib_get_request_len( const char *buf, int buflen );
void			XX_httplib_get_system_name( char **sysName );
enum uri_type_t		XX_httplib_get_uri_type( const char *uri );
bool			XX_httplib_getreq( struct lh_ctx_t *ctx, struct lh_con_t *conn, int *err );
void			XX_httplib_handle_cgi_request( struct lh_ctx_t *ctx, struct lh_con_t *conn, const char *prog );
void			XX_httplib_handle_directory_request( struct lh_ctx_t *ctx, struct lh_con_t *conn, const char *dir );
void			XX_httplib_handle_file_based_request( struct lh_ctx_t *ctx, struct lh_con_t *conn, const char *path, struct file *filep );
void			XX_httplib_handle_not_modified_static_file_request( struct lh_ctx_t *ctx, struct lh_con_t *conn, struct file *filep );
void			XX_httplib_handle_propfind( struct lh_ctx_t *ctx, struct lh_con_t *conn, const char *path, struct file *filep );
void			XX_httplib_handle_request( struct lh_ctx_t *ctx, struct lh_con_t *conn );
void			XX_httplib_handle_ssi_file_request( struct lh_ctx_t *ctx, struct lh_con_t *conn, const char *path, struct file *filep );
void			XX_httplib_handle_static_file_request( struct lh_ctx_t *ctx, struct lh_con_t *conn, const char *path, struct file *filep, const char *mime_type, const char *additional_headers );
void			XX_httplib_handle_websocket_request( struct lh_ctx_t *ctx, struct lh_con_t *conn, const char *path, int is_callback_resource, httplib_websocket_connect_handler ws_connect_handler, httplib_websocket_ready_handler ws_ready_handler, httplib_websocket_data_handler ws_data_handler, httplib_websocket_close_handler ws_close_handler, void *cbData );
bool			XX_httplib_header_has_option( const char *header, const char *option );
bool			XX_httplib_init_options( struct lh_ctx_t *ctx );
void			XX_httplib_interpret_uri( struct lh_ctx_t *ctx, struct lh_con_t *conn, char *filename, size_t filename_buf_len, struct file *filep, bool *is_found, bool *is_script_resource, bool *is_websocket_request, bool *is_put_or_delete_request );
bool			XX_httplib_is_authorized_for_put( struct lh_ctx_t *ctx, struct lh_con_t *conn );
bool			XX_httplib_is_file_in_memory( struct lh_ctx_t *ctx, const struct lh_con_t *conn, const char *path, struct file *filep );
bool			XX_httplib_is_file_opened( const struct file *filep );
bool			XX_httplib_is_not_modified( struct lh_ctx_t *ctx, const struct lh_con_t *conn, const struct file *filep );
bool			XX_httplib_is_put_or_delete_method( const struct lh_con_t *conn );
bool			XX_httplib_is_valid_http_method( const char *method );
int			XX_httplib_is_valid_port( unsigned long port );
bool			XX_httplib_is_websocket_protocol( const struct lh_con_t *conn );
#if defined(NO_SSL)
void *			XX_httplib_load_dll( struct lh_ctx_t *ctx, const char *dll_name );
#else  /* NO_SSL */
void *			XX_httplib_load_dll( struct lh_ctx_t *ctx, const char *dll_name, struct ssl_func *sw );
#endif
void			XX_httplib_log_access( struct lh_ctx_t *ctx, const struct lh_con_t *conn );
LIBHTTP_THREAD		XX_httplib_master_thread( void *thread_func_param );
int			XX_httplib_match_prefix(const char *pattern, size_t pattern_len, const char *str);
void			XX_httplib_mkcol( struct lh_ctx_t *ctx, struct lh_con_t *conn, const char *path );
bool			XX_httplib_must_hide_file( const struct lh_ctx_t *ctx, const char *path );
const char *		XX_httplib_next_option( const char *list, struct vec *val, struct vec *eq_val );
void			XX_httplib_open_auth_file( struct lh_ctx_t *ctx, struct lh_con_t *conn, const char *path, struct file *filep );
bool			XX_httplib_option_value_to_bool( const char *value, bool *config );
bool			XX_httplib_option_value_to_int( const char *value, int *config );
int			XX_httplib_parse_auth_header( const struct lh_ctx_t *ctx, struct lh_con_t *conn, char *buf, size_t buf_size, struct ah *ah );
time_t			XX_httplib_parse_date_string( const char *datetime );
int			XX_httplib_parse_http_headers( char **buf, struct lh_rqi_t *ri );
int			XX_httplib_parse_http_message( char *buf, int len, struct lh_rqi_t *ri );
int			XX_httplib_parse_net( const char *spec, uint32_t *net, uint32_t *mask );
int			XX_httplib_parse_range_header( const char *header, int64_t *a, int64_t *b );
void			XX_httplib_path_to_unicode( const char *path, wchar_t *wbuf, size_t wbuf_len );
void			XX_httplib_prepare_cgi_environment( struct lh_ctx_t *ctx, struct lh_con_t *conn, const char *prog, struct cgi_environment *env );
void			XX_httplib_print_dir_entry( struct lh_ctx_t *ctx, struct de *de );
void			XX_httplib_process_new_connection( struct lh_ctx_t *ctx, struct lh_con_t *conn );
bool			XX_httplib_process_options( struct lh_ctx_t *ctx, const struct lh_opt_t *options );
void			XX_httplib_produce_socket( struct lh_ctx_t *ctx, const struct socket *sp );
int			XX_httplib_pull( const struct lh_ctx_t *ctx, FILE *fp, struct lh_con_t *conn, char *buf, int len, double timeout );
int			XX_httplib_pull_all( const struct lh_ctx_t *ctx, FILE *fp, struct lh_con_t *conn, char *buf, int len );
int64_t			XX_httplib_push_all( const struct lh_ctx_t *ctx, FILE *fp, SOCKET sock, SSL *ssl, const char *buf, int64_t len );
int			XX_httplib_put_dir( struct lh_ctx_t *ctx, struct lh_con_t *conn, const char *path );
void			XX_httplib_put_file( struct lh_ctx_t *ctx, struct lh_con_t *conn, const char *path );
bool			XX_httplib_read_auth_file( struct lh_ctx_t *ctx, struct file *filep, struct read_auth_file_struct *workdata );
int			XX_httplib_read_request( const struct lh_ctx_t *ctx, FILE *fp, struct lh_con_t *conn, char *buf, int bufsiz, int *nread );
void			XX_httplib_read_websocket( struct lh_ctx_t *ctx, struct lh_con_t *conn, httplib_websocket_data_handler ws_data_handler, void *callback_data );
void			XX_httplib_redirect_to_https_port( const struct lh_ctx_t *ctx, struct lh_con_t *conn, int ssl_index );
int			XX_httplib_refresh_trust( struct lh_ctx_t *ctx, struct lh_con_t *conn );
void			XX_httplib_remove_bad_file( struct lh_ctx_t *ctx, const struct lh_con_t *conn, const char *path );
int			XX_httplib_remove_directory( struct lh_ctx_t *ctx, struct lh_con_t *conn, const char *dir );
void			XX_httplib_remove_double_dots_and_double_slashes( char *s );
void			XX_httplib_reset_per_request_attributes( struct lh_con_t *conn );
int			XX_httplib_scan_directory( struct lh_ctx_t *ctx, struct lh_con_t *conn, const char *dir, void *data, void (*cb)(struct lh_ctx_t *ctx, struct de *, void *) );
void			XX_httplib_send_authorization_request( struct lh_ctx_t *ctx, struct lh_con_t *conn );
void			XX_httplib_send_file_data( struct lh_ctx_t *ctx, struct lh_con_t *conn, struct file *filep, int64_t offset, int64_t len );
void			XX_httplib_send_http_error( struct lh_ctx_t *ctx, struct lh_con_t *, int, PRINTF_FORMAT_STRING(const char *fmt), ... ) PRINTF_ARGS(4, 5);
int			XX_httplib_send_no_cache_header( const struct lh_ctx_t *ctx, struct lh_con_t *conn );
void			XX_httplib_send_options( const struct lh_ctx_t *ctx, struct lh_con_t *conn );
int			XX_httplib_send_static_cache_header( const struct lh_ctx_t *ctx, struct lh_con_t *conn );
int			XX_httplib_send_websocket_handshake( struct lh_ctx_t *ctx, struct lh_con_t *conn, const char *websock_key );
int			XX_httplib_set_acl_option( struct lh_ctx_t *ctx );
void			XX_httplib_set_close_on_exec( SOCKET sock );
bool			XX_httplib_set_gpass_option( struct lh_ctx_t *ctx );
void			XX_httplib_set_handler_type( struct lh_ctx_t *ctx, const char *uri, int handler_type, int is_delete_request, httplib_request_handler handler, httplib_websocket_connect_handler connect_handler, httplib_websocket_ready_handler ready_handler, httplib_websocket_data_handler data_handler, httplib_websocket_close_handler close_handler, httplib_authorization_handler auth_handler, void *cbdata );
int			XX_httplib_set_non_blocking_mode( SOCKET sock );
int			XX_httplib_set_ports_option( struct lh_ctx_t *ctx );
int			XX_httplib_set_sock_timeout( SOCKET sock, int milliseconds );
int			XX_httplib_set_tcp_nodelay( SOCKET sock, bool nodelay_on );
void			XX_httplib_set_thread_name( struct lh_ctx_t *ctx, const char *name );
int			XX_httplib_set_throttle( const char *spec, uint32_t remote_ip, const char *uri );
bool			XX_httplib_set_uid_option( struct lh_ctx_t *ctx );
bool			XX_httplib_should_decode_url( const struct lh_ctx_t *ctx );
bool			XX_httplib_should_keep_alive( const struct lh_ctx_t *ctx, const struct lh_con_t *conn );
char *			XX_httplib_skip( char **buf, const char *delimiters );
char *			XX_httplib_skip_quoted( char **buf, const char *delimiters, const char *whitespace, char quotechar );
void			XX_httplib_snprintf( struct lh_ctx_t *ctx, const struct lh_con_t *conn, bool *truncated, char *buf, size_t buflen, PRINTF_FORMAT_STRING(const char *fmt), ... ) PRINTF_ARGS(6, 7);
void			XX_httplib_sockaddr_to_string(char *buf, size_t len, const union usa *usa );
pid_t			XX_httplib_spawn_process( struct lh_ctx_t *ctx, struct lh_con_t *conn, const char *prog, char *envblk, char *envp[], int fdin[2], int fdout[2], int fderr[2], const char *dir );
int			XX_httplib_start_thread_with_id( httplib_thread_func_t func, void *param, pthread_t *threadidptr );
int			XX_httplib_stat( struct lh_ctx_t *ctx, struct lh_con_t *conn, const char *path, struct file *filep );
int			XX_httplib_substitute_index_file( struct lh_ctx_t *ctx, struct lh_con_t *conn, char *path, size_t path_len, struct file *filep );
const char *		XX_httplib_suggest_connection_header( const struct lh_ctx_t *ctx, const struct lh_con_t *conn );
int			XX_httplib_vprintf( const struct lh_ctx_t *ctx, struct lh_con_t *conn, const char *fmt, va_list ap );
void			XX_httplib_vsnprintf( struct lh_ctx_t *ctx, const struct lh_con_t *conn, bool *truncated, char *buf, size_t buflen, const char *fmt, va_list ap );
LIBHTTP_THREAD		XX_httplib_websocket_client_thread( void *data );
int			XX_httplib_websocket_write_exec( const struct lh_ctx_t *ctx, struct lh_con_t *conn, int opcode, const char *data, size_t dataLen, uint32_t masking_key );
LIBHTTP_THREAD		XX_httplib_worker_thread( void *thread_func_param );



typedef unsigned char	md5_byte_t; /* 8-bit byte */
typedef unsigned int	md5_word_t;  /* 32-bit word */

typedef struct md5_state_s {
	md5_word_t	count[2]; /* message length in bits, lsw first */
	md5_word_t	abcd[4];  /* digest buffer */
	md5_byte_t	buf[64];  /* accumulate block */
} md5_state_t;

void			md5_init( md5_state_t *pms );
void			md5_append( md5_state_t *pms, const md5_byte_t *data, size_t nbytes );
void			md5_finish( md5_state_t *pms, md5_byte_t digest[16] );



#ifdef _WIN32
extern struct pthread_mutex_undefined_struct *	XX_httplib_pthread_mutex_attr;
#else  /* _WIN32 */
extern pthread_mutexattr_t			XX_httplib_pthread_mutex_attr;
#endif /* _WIN32 */

extern const struct uriprot_tp		XX_httplib_abs_uri_protocols[];
extern int				XX_httplib_sTlsInit;
extern pthread_key_t			XX_httplib_sTlsKey;
