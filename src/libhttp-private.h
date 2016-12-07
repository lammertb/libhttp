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

#if defined(USE_LUA) && defined(USE_WEBSOCKET)
#define USE_TIMERS
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

#if defined(USE_LUA) && defined(USE_WEBSOCKET)
	/* linked list of shared lua websockets */
	struct mg_shared_lua_websocket_list *shared_lua_websockets;
#endif

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
#if defined(USE_LUA) && defined(USE_WEBSOCKET)
	void *lua_websocket_state;		/* Lua_State for a websocket connection							*/
#endif

	int thread_index;			/* Thread index within ctx								*/
};



/*
 * Functions local to the server. These functions all begin with XX_httplib to
 * indicate that these are private functions.
 */

uint64_t		XX_httplib_get_random( void );
void			XX_httplib_get_system_name( char **sysName );
int			XX_httplib_set_acl_option( struct mg_context *ctx );
int			XX_httplib_set_gpass_option( struct mg_context *ctx );
int			XX_httplib_set_ports_option( struct mg_context *ctx );
int			XX_httplib_set_ssl_option( struct mg_context *ctx );
int			XX_httplib_set_uid_option( struct mg_context *ctx );
void			XX_httplib_tls_dtor( void *key );

#ifdef _WIN32

unsigned __stdcall	XX_httplib_master_thread( void *thread_func_param );
unsigned __stdcall	XX_httplib_worker_thread( void *thread_func_param );

#else  /* _WIN32 */

void *			XX_httplib_master_thread( void *thread_func_param );
void *			XX_httplib_worker_thread( void *thread_func_param );

#endif /* _WIN32 */
