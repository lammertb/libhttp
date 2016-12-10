/* 
 * Copyright (C) 2016 Lammert Bies
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
#endif
#ifndef _WIN32_WINNT /* defined for tdm-gcc so we can use getnameinfo */
#define _WIN32_WINNT 0x0501
#endif
#else
#if defined(__GNUC__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE /* for setgroups() */
#endif
#if defined(__linux__) && !defined(_XOPEN_SOURCE)
#define _XOPEN_SOURCE 600 /* For flockfile() on Linux */
#endif
#ifndef _LARGEFILE_SOURCE
#define _LARGEFILE_SOURCE /* For fseeko(), ftello() */
#endif
#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64 /* Use 64-bit file offsets by default */
#endif
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS /* <inttypes.h> wants this for C++ */
#endif
#ifndef __STDC_LIMIT_MACROS
#define __STDC_LIMIT_MACROS /* C++ wants that for INT64_MAX */
#endif
#ifdef __sun
#define __EXTENSIONS__  /* to expose flockfile and friends in stdio.h */
#define __inline inline /* not recognized on older compiler versions */
#endif
#endif

#if defined(_MSC_VER)
/* 'type cast' : conversion from 'int' to 'HANDLE' of greater size */
#pragma warning(disable : 4306)
/* conditional expression is constant: introduced by FD_SET(..) */
#pragma warning(disable : 4127)
/* non-constant aggregate initializer: issued due to missing C99 support */
#pragma warning(disable : 4204)
/* padding added after data member */
#pragma warning(disable : 4820)
/* not defined as a preprocessor macro, replacing with '0' for '#if/#elif' */
#pragma warning(disable : 4668)
/* no function prototype given: converting '()' to '(void)' */
#pragma warning(disable : 4255)
/* function has been selected for automatic inline expansion */
#pragma warning(disable : 4711)
#endif


/* This code uses static_assert to check some conditions.
 * Unfortunately some compilers still do not support it, so we have a
 * replacement function here. */
#if defined(_MSC_VER) && (_MSC_VER >= 1600)
#define mg_static_assert static_assert
#elif defined(__cplusplus) && (__cplusplus >= 201103L)
#define mg_static_assert static_assert
#elif defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L)
#define mg_static_assert _Static_assert
#else
char static_assert_replacement[1];
#define mg_static_assert(cond, txt)                                            \
	extern char static_assert_replacement[(cond) ? 1 : -1]
#endif

mg_static_assert(sizeof(int) == 4 || sizeof(int) == 8, "int data type size check");
mg_static_assert(sizeof(void *) == 4 || sizeof(void *) == 8, "pointer data type size check");
mg_static_assert(sizeof(void *) >= sizeof(int), "data type size check");


/* DTL -- including winsock2.h works better if lean and mean */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

/* Include the header file here, so the LibHTTP interface is defined for the
 * entire implementation, including the following forward definitions. */

#include <stdbool.h>
#include <stdint.h>
#include "libhttp.h"


#ifndef IGNORE_UNUSED_RESULT
#define IGNORE_UNUSED_RESULT(a) ((void)((a) && 1))
#endif

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
#endif

#define SHUTDOWN_RD (0)
#define SHUTDOWN_WR (1)
#define SHUTDOWN_BOTH (2)



#if defined(_WIN32)   /* WINDOWS / UNIX include block */
#include <windows.h>
#include <winsock2.h> /* DTL add for SO_EXCLUSIVE */
#include <ws2tcpip.h>

typedef const char *SOCK_OPT_TYPE;

#if !defined(PATH_MAX)
#define PATH_MAX (MAX_PATH)
#endif  /* PATH_MAX */

#if !defined(PATH_MAX)
#define PATH_MAX (4096)
#endif  /* PATH_MAX */

mg_static_assert(PATH_MAX >= 1, "path length must be a positive number");

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
#else
#define __func__ __FUNCTION__
#define strtoull(x, y, z) (_strtoui64(x, y, z))
#define strtoll(x, y, z) (_strtoi64(x, y, z))
#endif
#endif /* _MSC_VER */

#define ERRNO ((int)(GetLastError()))
#define NO_SOCKLEN_T

#if defined(_WIN64) || defined(__MINGW64__)
#define SSL_LIB "ssleay64.dll"
#define CRYPTO_LIB "libeay64.dll"
#else
#define SSL_LIB "ssleay32.dll"
#define CRYPTO_LIB "libeay32.dll"
#endif

#define O_NONBLOCK (0)
#ifndef W_OK
#define W_OK (2) /* http://msdn.microsoft.com/en-us/library/1w06ktdy.aspx */
#endif
#if !defined(EWOULDBLOCK)
#define EWOULDBLOCK WSAEWOULDBLOCK
#endif /* !EWOULDBLOCK */
#define _POSIX_
#define INT64_FMT "I64d"
#define UINT64_FMT "I64u"

#define WINCDECL __cdecl
#define vsnprintf_impl _vsnprintf
#define access _access
#define mg_sleep(x) (Sleep(x))

#define pipe(x) _pipe(x, MG_BUF_LEN, _O_BINARY)
#ifndef popen
#define popen(x, y) (_popen(x, y))
#endif
#ifndef pclose
#define pclose(x) (_pclose(x))
#endif
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

typedef HANDLE pthread_mutex_t;
typedef DWORD pthread_key_t;
typedef HANDLE pthread_t;
typedef struct {
	CRITICAL_SECTION threadIdSec;
	struct mg_workerTLS *waiting_thread; /* The chain of threads */
} pthread_cond_t;

#ifndef __clockid_t_defined
typedef DWORD clockid_t;
#endif
#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC (1)
#endif
#ifndef CLOCK_REALTIME
#define CLOCK_REALTIME (2)
#endif

#if defined(_MSC_VER) && (_MSC_VER >= 1900)
#define _TIMESPEC_DEFINED
#endif
#ifndef _TIMESPEC_DEFINED
struct timespec {
	time_t tv_sec; /* seconds */
	long tv_nsec;  /* nanoseconds */
};
#endif

#define pid_t HANDLE /* MINGW typedefs pid_t to int. Using #define here. */

static int pthread_mutex_lock(pthread_mutex_t *);
static int pthread_mutex_unlock(pthread_mutex_t *);
static void path_to_unicode(const struct mg_connection *conn, const char *path, wchar_t *wbuf, size_t wbuf_len);
static const char *mg_fgets(char *buf, size_t size, struct file *filep, char **p);


/* POSIX dirent interface */
struct dirent {
	char d_name[PATH_MAX];
};

typedef struct DIR {
	HANDLE handle;
	WIN32_FIND_DATAW info;
	struct dirent result;
} DIR;

#if defined(_WIN32) && !defined(POLLIN)
#ifndef HAVE_POLL
struct pollfd {
	SOCKET fd;
	short events;
	short revents;
};
#define POLLIN (0x0300)
#endif
#endif

/* Mark required libraries */
#if defined(_MSC_VER)
#pragma comment(lib, "Ws2_32.lib")
#endif

#else /* defined(_WIN32) -                          \
         WINDOWS / UNIX include block */

#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/poll.h>
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
#define mg_mkdir(conn, path, mode) (mkdir(path, mode))
#define mg_remove(conn, x) (remove(x))
#define mg_sleep(x) (usleep((x)*1000))
#define mg_opendir(conn, x) (opendir(x))
#define mg_closedir(x) (closedir(x))
#define mg_readdir(x) (readdir(x))
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
#if defined(USE_IPV6)
	struct sockaddr_in6 sin6;
#endif
};

/* NOTE(lsm): this enum shoulds be in sync with the config_options below. */
enum {
	CGI_EXTENSIONS,
	CGI_ENVIRONMENT,
	PUT_DELETE_PASSWORDS_FILE,
	CGI_INTERPRETER,
	PROTECT_URI,
	AUTHENTICATION_DOMAIN,
	SSI_EXTENSIONS,
	THROTTLE,
	ACCESS_LOG_FILE,
	ENABLE_DIRECTORY_LISTING,
	ERROR_LOG_FILE,
	GLOBAL_PASSWORDS_FILE,
	INDEX_FILES,
	ENABLE_KEEP_ALIVE,
	ACCESS_CONTROL_LIST,
	EXTRA_MIME_TYPES,
	LISTENING_PORTS,
	DOCUMENT_ROOT,
	SSL_CERTIFICATE,
	NUM_THREADS,
	RUN_AS_USER,
	REWRITE,
	HIDE_FILES,
	REQUEST_TIMEOUT,
	SSL_DO_VERIFY_PEER,
	SSL_CA_PATH,
	SSL_CA_FILE,
	SSL_VERIFY_DEPTH,
	SSL_DEFAULT_VERIFY_PATHS,
	SSL_CIPHER_LIST,
	SSL_PROTOCOL_VERSION,
	SSL_SHORT_TRUST,

#if defined(USE_WEBSOCKET)
	WEBSOCKET_TIMEOUT,
#endif

	DECODE_URL,

#if defined(USE_WEBSOCKET)
	WEBSOCKET_ROOT,
#endif

	ACCESS_CONTROL_ALLOW_ORIGIN,
	ERROR_PAGES,
	CONFIG_TCP_NODELAY, /* Prepended CONFIG_ to avoid conflict with the
                         * socket option typedef TCP_NODELAY. */
#if !defined(NO_CACHING)
	STATIC_FILE_MAX_AGE,
#endif
#if defined(__linux__)
	ALLOW_SENDFILE_CALL,
#endif

	NUM_OPTIONS
};

#if defined(NO_SSL)
typedef struct SSL SSL; /* dummy for SSL argument to push/pull */
typedef struct SSL_CTX SSL_CTX;
#else
#if defined(NO_SSL_DL)
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/engine.h>
#include <openssl/conf.h>
#include <openssl/dh.h>
#else
/* SSL loaded dynamically from DLL.
 * I put the prototypes here to be independent from OpenSSL source
 * installation. */

typedef struct ssl_st SSL;
typedef struct ssl_method_st SSL_METHOD;
typedef struct ssl_ctx_st SSL_CTX;
typedef struct x509_store_ctx_st X509_STORE_CTX;
typedef struct x509_name X509_NAME;
typedef struct asn1_integer ASN1_INTEGER;
typedef struct evp_md EVP_MD;
typedef struct x509 X509;

#define IP_ADDR_STR_LEN (50) /* IPv6 hex string is 46 chars */


#define SSL_CTRL_OPTIONS (32)
#define SSL_CTRL_CLEAR_OPTIONS (77)
#define SSL_CTRL_SET_ECDH_AUTO (94)

#define SSL_VERIFY_NONE (0)
#define SSL_VERIFY_PEER (1)
#define SSL_VERIFY_FAIL_IF_NO_PEER_CERT (2)
#define SSL_VERIFY_CLIENT_ONCE (4)
#define SSL_OP_ALL ((long)(0x80000BFFUL))
#define SSL_OP_NO_SSLv2 (0x01000000L)
#define SSL_OP_NO_SSLv3 (0x02000000L)
#define SSL_OP_NO_TLSv1 (0x04000000L)
#define SSL_OP_NO_TLSv1_2 (0x08000000L)
#define SSL_OP_NO_TLSv1_1 (0x10000000L)
#define SSL_OP_SINGLE_DH_USE (0x00100000L)
#define SSL_OP_CIPHER_SERVER_PREFERENCE (0x00400000L)
#define SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION (0x00010000L)

#define SSL_ERROR_NONE (0)
#define SSL_ERROR_SSL (1)
#define SSL_ERROR_WANT_READ (2)
#define SSL_ERROR_WANT_WRITE (3)
#define SSL_ERROR_WANT_X509_LOOKUP (4)
#define SSL_ERROR_SYSCALL (5) /* see errno */
#define SSL_ERROR_ZERO_RETURN (6)
#define SSL_ERROR_WANT_CONNECT (7)
#define SSL_ERROR_WANT_ACCEPT (8)


struct ssl_func {
	const char *name;  /* SSL function name */
	void (*ptr)(void); /* Function pointer */
};

#define SSL_free (*(void (*)(SSL *))XX_httplib_ssl_sw[0].ptr)
#define SSL_accept (*(int (*)(SSL *))XX_httplib_ssl_sw[1].ptr)
#define SSL_connect (*(int (*)(SSL *))XX_httplib_ssl_sw[2].ptr)
#define SSL_read (*(int (*)(SSL *, void *, int))XX_httplib_ssl_sw[3].ptr)
#define SSL_write (*(int (*)(SSL *, const void *, int))XX_httplib_ssl_sw[4].ptr)
#define SSL_get_error (*(int (*)(SSL *, int))XX_httplib_ssl_sw[5].ptr)
#define SSL_set_fd (*(int (*)(SSL *, SOCKET))XX_httplib_ssl_sw[6].ptr)
#define SSL_new (*(SSL * (*)(SSL_CTX *))XX_httplib_ssl_sw[7].ptr)
#define SSL_CTX_new (*(SSL_CTX * (*)(SSL_METHOD *))XX_httplib_ssl_sw[8].ptr)
#define SSLv23_server_method (*(SSL_METHOD * (*)(void))XX_httplib_ssl_sw[9].ptr)
#define SSL_library_init (*(int (*)(void))XX_httplib_ssl_sw[10].ptr)
#define SSL_CTX_use_PrivateKey_file                                            \
	(*(int (*)(SSL_CTX *, const char *, int))XX_httplib_ssl_sw[11].ptr)
#define SSL_CTX_use_certificate_file                                           \
	(*(int (*)(SSL_CTX *, const char *, int))XX_httplib_ssl_sw[12].ptr)
#define SSL_CTX_set_default_passwd_cb                                          \
	(*(void (*)(SSL_CTX *, mg_callback_t))XX_httplib_ssl_sw[13].ptr)
#define SSL_CTX_free (*(void (*)(SSL_CTX *))XX_httplib_ssl_sw[14].ptr)
#define SSL_load_error_strings (*(void (*)(void))XX_httplib_ssl_sw[15].ptr)
#define SSL_CTX_use_certificate_chain_file                                     \
	(*(int (*)(SSL_CTX *, const char *))XX_httplib_ssl_sw[16].ptr)
#define SSLv23_client_method (*(SSL_METHOD * (*)(void))XX_httplib_ssl_sw[17].ptr)
#define SSL_pending (*(int (*)(SSL *))XX_httplib_ssl_sw[18].ptr)
#define SSL_CTX_set_verify                                                     \
	(*(void (*)(SSL_CTX *,                                                     \
	            int,                                                           \
	            int (*verify_callback)(int, X509_STORE_CTX *)))XX_httplib_ssl_sw[19].ptr)
#define SSL_shutdown (*(int (*)(SSL *))XX_httplib_ssl_sw[20].ptr)
#define SSL_CTX_load_verify_locations                                          \
	(*(int (*)(SSL_CTX *, const char *, const char *))XX_httplib_ssl_sw[21].ptr)
#define SSL_CTX_set_default_verify_paths (*(int (*)(SSL_CTX *))XX_httplib_ssl_sw[22].ptr)
#define SSL_CTX_set_verify_depth (*(void (*)(SSL_CTX *, int))XX_httplib_ssl_sw[23].ptr)
#define SSL_get_peer_certificate (*(X509 * (*)(SSL *))XX_httplib_ssl_sw[24].ptr)
#define SSL_get_version (*(const char *(*)(SSL *))XX_httplib_ssl_sw[25].ptr)
#define SSL_get_current_cipher (*(SSL_CIPHER * (*)(SSL *))XX_httplib_ssl_sw[26].ptr)
#define SSL_CIPHER_get_name                                                    \
	(*(const char *(*)(const SSL_CIPHER *))XX_httplib_ssl_sw[27].ptr)
#define SSL_CTX_check_private_key (*(int (*)(SSL_CTX *))XX_httplib_ssl_sw[28].ptr)
#define SSL_CTX_set_session_id_context                                         \
	(*(int (*)(SSL_CTX *, const unsigned char *, unsigned int))XX_httplib_ssl_sw[29].ptr)
#define SSL_CTX_ctrl (*(long (*)(SSL_CTX *, int, long, void *))XX_httplib_ssl_sw[30].ptr)


#define SSL_CTX_set_cipher_list                                                \
	(*(int (*)(SSL_CTX *, const char *))XX_httplib_ssl_sw[31].ptr)
#define SSL_CTX_set_options(ctx, op)                                           \
	SSL_CTX_ctrl((ctx), SSL_CTRL_OPTIONS, (op), NULL)
#define SSL_CTX_clear_options(ctx, op)                                         \
	SSL_CTX_ctrl((ctx), SSL_CTRL_CLEAR_OPTIONS, (op), NULL)
#define SSL_CTX_set_ecdh_auto(ctx, onoff)                                      \
	SSL_CTX_ctrl(ctx, SSL_CTRL_SET_ECDH_AUTO, onoff, NULL)

#define X509_get_notBefore(x) ((x)->cert_info->validity->notBefore)
#define X509_get_notAfter(x) ((x)->cert_info->validity->notAfter)


#define CRYPTO_num_locks (*(int (*)(void))XX_httplib_crypto_sw[0].ptr)
#define CRYPTO_set_locking_callback                                            \
	(*(void (*)(void (*)(int, int, const char *, int)))XX_httplib_crypto_sw[1].ptr)
#define CRYPTO_set_id_callback                                                 \
	(*(void (*)(unsigned long (*)(void)))XX_httplib_crypto_sw[2].ptr)
#define ERR_get_error (*(unsigned long (*)(void))XX_httplib_crypto_sw[3].ptr)
#define ERR_error_string (*(char *(*)(unsigned long, char *))XX_httplib_crypto_sw[4].ptr)
#define ERR_remove_state (*(void (*)(unsigned long))XX_httplib_crypto_sw[5].ptr)
#define ERR_free_strings (*(void (*)(void))XX_httplib_crypto_sw[6].ptr)
#define ENGINE_cleanup (*(void (*)(void))XX_httplib_crypto_sw[7].ptr)
#define CONF_modules_unload (*(void (*)(int))XX_httplib_crypto_sw[8].ptr)
#define CRYPTO_cleanup_all_ex_data (*(void (*)(void))XX_httplib_crypto_sw[9].ptr)
#define EVP_cleanup (*(void (*)(void))XX_httplib_crypto_sw[10].ptr)
#define X509_free (*(void (*)(X509 *))XX_httplib_crypto_sw[11].ptr)
#define X509_get_subject_name (*(X509_NAME * (*)(X509 *))XX_httplib_crypto_sw[12].ptr)
#define X509_get_issuer_name (*(X509_NAME * (*)(X509 *))XX_httplib_crypto_sw[13].ptr)
#define X509_NAME_oneline                                                      \
	(*(char *(*)(X509_NAME *, char *, int))XX_httplib_crypto_sw[14].ptr)
#define X509_get_serialNumber (*(ASN1_INTEGER * (*)(X509 *))XX_httplib_crypto_sw[15].ptr)
#define i2c_ASN1_INTEGER                                                       \
	(*(int (*)(ASN1_INTEGER *, unsigned char **))XX_httplib_crypto_sw[16].ptr)
#define EVP_get_digestbyname                                                   \
	(*(const EVP_MD *(*)(const char *))XX_httplib_crypto_sw[17].ptr)
#define ASN1_digest                                                            \
	(*(int (*)(int (*)(),                                                      \
	           const EVP_MD *,                                                 \
	           char *,                                                         \
	           unsigned char *,                                                \
	           unsigned int *))XX_httplib_crypto_sw[18].ptr)
#define i2d_X509 (*(int (*)(X509 *, unsigned char **))XX_httplib_crypto_sw[19].ptr)

#endif  /* NO_SSL_DL */
#endif  /* NO_SSL */

struct mg_workerTLS {
	int is_master;
	unsigned long thread_idx;
#if defined(_WIN32)
	HANDLE pthread_cond_helper_mutex;
	struct mg_workerTLS *next_waiting_thread;
#endif
};


/* Describes listening socket, or socket which was accept()-ed by the master
 * thread and queued for future handling by the worker thread. */
struct socket {
	SOCKET sock;             /* Listening socket */
	union usa lsa;           /* Local socket address */
	union usa rsa;           /* Remote socket address */
	unsigned char is_ssl;    /* Is port SSL-ed */
	unsigned char ssl_redir; /* Is port supposed to redirect everything to SSL
	                          * port */
	unsigned char in_use;    /* Is valid */
};


/*
 * struct mg_handler_info;
 */

struct mg_handler_info {
	/* Name/Pattern of the URI. */
	char *uri;
	size_t uri_len;

	/* handler type */
	int handler_type;

	/* Handler for http/https or authorization requests. */
	mg_request_handler handler;

	/* Handler for ws/wss (websocket) requests. */
	mg_websocket_connect_handler connect_handler;
	mg_websocket_ready_handler ready_handler;
	mg_websocket_data_handler data_handler;
	mg_websocket_close_handler close_handler;

	/* Handler for authorization requests */
	mg_authorization_handler auth_handler;

	/* User supplied argument for the handler function. */
	void *cbdata;

	/* next handler in a linked list */
	struct mg_handler_info *next;
};

/*
 * struct mg_context;
 */

struct mg_context {

	volatile int stop_flag;			/* Should we stop event loop								*/
	SSL_CTX *ssl_ctx;			/* SSL context										*/
	char *config[NUM_OPTIONS];		/* LibHTTP configuration parameters							*/
	struct mg_callbacks callbacks;		/* User-defined callback function							*/
	void *user_data;			/* User-defined data									*/
	int context_type;			/* 1 = server context, 2 = client context						*/

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
	unsigned int
	    cfg_worker_threads;			/* The number of configured worker threads.						*/
	pthread_t *workerthreadids;		/* The worker thread IDs								*/

	time_t start_time;			/* Server start time, used for authentication						*/
	uint64_t auth_nonce_mask;		/* Mask for all nonce values								*/
	pthread_mutex_t nonce_mutex;		/* Protects nonce_count									*/
	unsigned long nonce_count;		/* Used nonces, used for authentication							*/

	char *systemName;			/* What operating system is running							*/

	/* linked list of uri handlers */
	struct mg_handler_info *handlers;

#ifdef USE_TIMERS
	struct ttimers *timers;
#endif
};

/*
 * struct mg_connection;
 */

struct mg_connection {
	struct mg_request_info request_info;
	struct mg_context *ctx;
	SSL *ssl;				/* SSL descriptor									*/
	SSL_CTX *client_ssl_ctx;		/* SSL context for client connections							*/
	struct socket client;			/* Connected client									*/
	time_t conn_birth_time;			/* Time (wall clock) when connection was established					*/
	struct timespec req_time;		/* Time (since system start) when the request was received				*/
	int64_t num_bytes_sent;			/* Total bytes sent to client								*/
	int64_t content_len;			/* Content-Length header value								*/
	int64_t consumed_content;		/* How many bytes of content have been read						*/
	int is_chunked;				/* Transfer-Encoding is chunked: 0=no, 1=yes: data available, 2: all data read		*/
	size_t chunk_remainder;			/* Unread data from the last chunk							*/
	char *buf;				/* Buffer for received data								*/
	char *path_info;			/* PATH_INFO part of the URL								*/

	int must_close;				/* 1 if connection must be closed							*/
	int in_error_handler;			/* 1 if in handler for user defined error pages						*/
	int internal_error;			/* 1 if an error occured while processing the request					*/

	int buf_size;				/* Buffer size										*/
	int request_len;			/* Size of the request + headers in a buffer						*/
	int data_len;				/* Total size of data in a buffer							*/
	int status_code;			/* HTTP reply status code, e.g. 200							*/
	int throttle;				/* Throttling, bytes/sec. <= 0 means no throttle					*/
	time_t last_throttle_time;		/* Last time throttled data was sent							*/
	int64_t last_throttle_bytes;		/* Bytes sent this second								*/
	pthread_mutex_t mutex;			/* Used by mg_(un)lock_connection to ensure atomic transmissions for websockets		*/

	int thread_index;			/* Thread index within ctx								*/
};

struct worker_thread_args {
	struct mg_context *ctx;
	int index;
};


struct websocket_client_thread_data {
	struct mg_connection *conn;
	mg_websocket_data_handler data_handler;
	mg_websocket_close_handler close_handler;
	void *callback_data;
};

struct uriprot_tp {
	const char *proto;
	size_t proto_len;
	unsigned default_port;
};

struct file {
	uint64_t size;
	time_t last_modified;
	FILE *fp;
	const char *membuf; /* Non-NULL if file data is in memory */
	int is_directory;
	int gzipped; /* set to 1 if the content is gzipped in which case we need a content-encoding: gzip header */
};

#define STRUCT_FILE_INITIALIZER    { (uint64_t)0, (time_t)0, (FILE *)NULL, (const char *)NULL, 0, 0 } 

/* Describes a string (chunk of memory). */
struct vec {
	const char *ptr;
	size_t len;
};

enum { REQUEST_HANDLER, WEBSOCKET_HANDLER, AUTH_HANDLER };


/*
 * Functions local to the server. These functions all begin with XX_httplib to
 * indicate that these are private functions.
 */

void			XX_httplib_accept_new_connection( const struct socket *listener, struct mg_context *ctx );
int			XX_httplib_atomic_dec( volatile int *addr );
int			XX_httplib_atomic_inc( volatile int *addr );
int			XX_httplib_check_acl( struct mg_context *ctx, uint32_t remote_ip );
int			XX_httplib_check_authorization( struct mg_connection *conn, const char *path );
void			XX_httplib_close_all_listening_sockets( struct mg_context *ctx );
void			XX_httplib_close_connection( struct mg_connection *conn );
void			XX_httplib_close_socket_gracefully( struct mg_connection *conn );
int			XX_httplib_connect_socket( struct mg_context *ctx, const char *host, int port, int use_ssl, char *ebuf, size_t ebuf_len, SOCKET *sock, union usa *sa );
int			XX_httplib_consume_socket( struct mg_context *ctx, struct socket *sp, int thread_index );
void			XX_httplib_delete_file( struct mg_connection *conn, const char *path );
void			XX_httplib_discard_unread_request_data( struct mg_connection *conn );
struct mg_connection *	XX_httplib_fc( struct mg_context *ctx );
void			XX_httplib_fclose( struct file *filep );
int			XX_httplib_fopen( const struct mg_connection *conn, const char *path, const char *mode, struct file *filep );
void			XX_httplib_free_context( struct mg_context *ctx );
int			XX_httplib_get_first_ssl_listener_index( const struct mg_context *ctx );
const char *		XX_httplib_get_header( const struct mg_request_info *ri, const char *name );
int			XX_httplib_get_option_index( const char *name );
uint64_t		XX_httplib_get_random( void );
const char *		XX_httplib_get_rel_url_at_current_server( const char *uri, const struct mg_connection *conn );
uint32_t		XX_httplib_get_remote_ip( const struct mg_connection *conn );
int XX_httplib_get_request_handler( struct mg_connection *conn, int handler_type, mg_request_handler *handler, mg_websocket_connect_handler *connect_handler, mg_websocket_ready_handler *ready_handler, mg_websocket_data_handler *data_handler, mg_websocket_close_handler *close_handler, mg_authorization_handler *auth_handler, void **cbdata );
void			XX_httplib_get_system_name( char **sysName );
int			XX_httplib_get_uri_type( const char *uri );
int			XX_httplib_getreq( struct mg_connection *conn, char *ebuf, size_t ebuf_len, int *err );
void			XX_httplib_gmt_time_string( char *buf, size_t buf_len, time_t *t );
void			XX_httplib_handle_cgi_request( struct mg_connection *conn, const char *prog );
void			XX_httplib_handle_directory_request( struct mg_connection *conn, const char *dir );
void			XX_httplib_handle_file_based_request( struct mg_connection *conn, const char *path, struct file *filep );
void			XX_httplib_handle_not_modified_static_file_request( struct mg_connection *conn, struct file *filep );
void			XX_httplib_handle_propfind( struct mg_connection *conn, const char *path, struct file *filep );
void			XX_httplib_handle_request( struct mg_connection *conn );
void			XX_httplib_handle_ssi_file_request( struct mg_connection *conn, const char *path, struct file *filep );
void			XX_httplib_handle_static_file_request( struct mg_connection *conn, const char *path, struct file *filep, const char *mime_type, const char *additional_headers );
void			XX_httplib_handle_websocket_request( struct mg_connection *conn, const char *path, int is_callback_resource, mg_websocket_connect_handler ws_connect_handler, mg_websocket_ready_handler ws_ready_handler, mg_websocket_data_handler ws_data_handler, mg_websocket_close_handler ws_close_handler, void *cbData );
int			XX_httplib_initialize_ssl( struct mg_context *ctx );
void XX_httplib_interpret_uri( struct mg_connection *conn, char *filename, size_t filename_buf_len, struct file *filep, int *is_found, int *is_script_resource, int *is_websocket_request, int *is_put_or_delete_request );
int			XX_httplib_is_authorized_for_put( struct mg_connection *conn );
int			XX_httplib_is_not_modified( const struct mg_connection *conn, const struct file *filep );
int			XX_httplib_is_put_or_delete_method( const struct mg_connection *conn );
int			XX_httplib_is_valid_port( unsigned long port );
int			XX_httplib_is_websocket_protocol( const struct mg_connection *conn );
int			XX_httplib_join_thread( pthread_t threadid );
void *			XX_httplib_load_dll( struct mg_context *ctx, const char *dll_name, struct ssl_func *sw );
void			XX_httplib_log_access( const struct mg_connection *conn );
int			XX_httplib_match_prefix(const char *pattern, size_t pattern_len, const char *str);
void			XX_httplib_mkcol( struct mg_connection *conn, const char *path );
int			XX_httplib_must_hide_file( struct mg_connection *conn, const char *path );
const char *		XX_httplib_next_option( const char *list, struct vec *val, struct vec *eq_val );
int			XX_httplib_parse_http_message( char *buf, int len, struct mg_request_info *ri );
int			XX_httplib_parse_net( const char *spec, uint32_t *net, uint32_t *mask );
void			XX_httplib_process_new_connection( struct mg_connection *conn );
void			XX_httplib_produce_socket( struct mg_context *ctx, const struct socket *sp );
void			XX_httplib_put_file( struct mg_connection *conn, const char *path );
int			XX_httplib_read_request( FILE *fp, struct mg_connection *conn, char *buf, int bufsiz, int *nread );
void			XX_httplib_read_websocket( struct mg_connection *conn, mg_websocket_data_handler ws_data_handler, void *callback_data );
void			XX_httplib_redirect_to_https_port( struct mg_connection *conn, int ssl_index );
int			XX_httplib_refresh_trust( struct mg_connection *conn );
void			XX_httplib_remove_double_dots_and_double_slashes( char *s );
void			XX_httplib_reset_per_request_attributes( struct mg_connection *conn );
void			XX_httplib_send_authorization_request( struct mg_connection *conn );
void			XX_httplib_send_http_error( struct mg_connection *, int, PRINTF_FORMAT_STRING(const char *fmt), ... ) PRINTF_ARGS(3, 4); 
void			XX_httplib_send_options( struct mg_connection *conn );
int			XX_httplib_set_acl_option( struct mg_context *ctx );
void			XX_httplib_set_close_on_exec( SOCKET sock, struct mg_connection *conn );
int			XX_httplib_set_gpass_option( struct mg_context *ctx );
int			XX_httplib_set_non_blocking_mode( SOCKET sock );
int			XX_httplib_set_ports_option( struct mg_context *ctx );
int			XX_httplib_set_sock_timeout( SOCKET sock, int milliseconds );
int			XX_httplib_set_ssl_option( struct mg_context *ctx );
int			XX_httplib_set_tcp_nodelay( SOCKET sock, int nodelay_on );
void			XX_httplib_set_thread_name( const char *name );
int			XX_httplib_set_throttle( const char *spec, uint32_t remote_ip, const char *uri );
int			XX_httplib_set_uid_option( struct mg_context *ctx );
int			XX_httplib_should_decode_url( const struct mg_connection *conn );
int			XX_httplib_should_keep_alive( const struct mg_connection *conn );
void			XX_httplib_snprintf( const struct mg_connection *conn, int *truncated, char *buf, size_t buflen, PRINTF_FORMAT_STRING(const char *fmt), ... ) PRINTF_ARGS(5, 6);
void			XX_httplib_sockaddr_to_string(char *buf, size_t len, const union usa *usa );
const char *		XX_httplib_ssl_error( void );
void			XX_httplib_ssl_get_client_cert_info( struct mg_connection *conn );
long			XX_httplib_ssl_get_protocol( int version_id );
unsigned long		XX_httplib_ssl_id_callback( void );
void			XX_httplib_ssl_locking_callback( int mode, int mutex_num, const char *file, int line );
int			XX_httplib_ssl_use_pem_file( struct mg_context *ctx, const char *pem );
int			XX_httplib_sslize( struct mg_connection *conn, SSL_CTX *s, int (*func)(SSL *) );
int			XX_httplib_stat( struct mg_connection *conn, const char *path, struct file *filep );
char *			XX_httplib_strdup( const char *str );
void			XX_httplib_strlcpy( register char *dst, register const char *src, size_t n );
int			XX_httplib_substitute_index_file( struct mg_connection *conn, char *path, size_t path_len, struct file *filep );
const char *		XX_httplib_suggest_connection_header( const struct mg_connection *conn );
void			XX_httplib_tls_dtor( void *key );
void			XX_httplib_uninitialize_ssl( struct mg_context *ctx );
int			XX_httplib_vprintf( struct mg_connection *conn, const char *fmt, va_list ap );



typedef unsigned char md5_byte_t; /* 8-bit byte */
typedef unsigned int md5_word_t;  /* 32-bit word */

typedef struct md5_state_s {
	md5_word_t count[2]; /* message length in bits, lsw first */
	md5_word_t abcd[4];  /* digest buffer */
	md5_byte_t buf[64];  /* accumulate block */
} md5_state_t;

void			md5_init( md5_state_t *pms );
void			md5_append( md5_state_t *pms, const md5_byte_t *data, size_t nbytes );
void			md5_finish( md5_state_t *pms, md5_byte_t digest[16] );



#ifdef _WIN32
unsigned __stdcall	XX_httplib_master_thread( void *thread_func_param );
int			XX_httplib_start_thread_with_id( unsigned(__stdcall *f)(void *), void *p, pthread_t *threadidptr );
unsigned __stdcall	XX_httplib_websocket_client_thread( void *data );
unsigned __stdcall	XX_httplib_worker_thread( void *thread_func_param );

extern struct pthread_mutex_undefined_struct *	XX_httplib_pthread_mutex_attr;
#else  /* _WIN32 */
void *			XX_httplib_master_thread( void *thread_func_param );
int			XX_httplib_start_thread_with_id( mg_thread_func_t func, void *param, pthread_t *threadidptr );
void *			XX_httplib_websocket_client_thread( void *data );
void *			XX_httplib_worker_thread( void *thread_func_param );

extern pthread_mutexattr_t	XX_httplib_pthread_mutex_attr;
#endif /* _WIN32 */

#if defined(MEMORY_DEBUGGING)
void *			XX_httplib_calloc_ex( size_t count, size_t size, const char *file, unsigned line );
void			XX_httplib_free_ex( void *memory, const char *file, unsigned line );
void *			XX_httplib_malloc_ex( size_t size, const char *file, unsigned line );
void *			XX_httplib_realloc_ex( void *memory, size_t newsize, const char *file, unsigned line );
#define			XX_httplib_calloc(a, b) XX_httplib_calloc_ex(a, b, __FILE__, __LINE__)
#define			XX_httplib_free(a) XX_httplib_free_ex(a, __FILE__, __LINE__)
#define			XX_httplib_malloc(a) XX_httplib_malloc_ex(a, __FILE__, __LINE__)
#define			XX_httplib_realloc(a, b) XX_httplib_realloc_ex(a, b, __FILE__, __LINE__)
#else  /* MEMORY_DEBUGGING */
void *			XX_httplib_calloc( size_t a, size_t b );
void			XX_httplib_free( void *a );
void *			XX_httplib_malloc( size_t a );
void *			XX_httplib_realloc( void *a, size_t b );
#endif  /* MEMORY_DEBUGGING */

extern const struct uriprot_tp	XX_httplib_abs_uri_protocols[];
extern struct mg_option		XX_httplib_config_options[];
extern int			XX_httplib_cryptolib_users;
extern struct ssl_func		XX_httplib_crypto_sw[];
extern pthread_mutex_t *	XX_httplib_ssl_mutexes;
extern struct ssl_func		XX_httplib_ssl_sw[];
extern int			XX_httplib_sTlsInit;
extern pthread_key_t		XX_httplib_sTlsKey;
extern int			XX_httplib_thread_idx_max;
