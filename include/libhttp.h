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

#ifndef LIBHTTP_HEADER_INCLUDED
#define LIBHTTP_HEADER_INCLUDED

#define LIBHTTP_VERSION "1.9"

#ifndef UNUSED_PARAMETER
#define UNUSED_PARAMETER(x)	(void)(x)
#endif  /* UNUSED_PARAMETER */

#ifndef LIBHTTP_API
#if defined(_WIN32)
#if defined(LIBHTTP_DLL_EXPORTS)
#define LIBHTTP_API __declspec(dllexport)
#elif defined(LIBHTTP_DLL_IMPORTS)
#define LIBHTTP_API __declspec(dllimport)
#else
#define LIBHTTP_API
#endif
#elif __GNUC__ >= 4
#define LIBHTTP_API __attribute__((visibility("default")))
#else
#define LIBHTTP_API
#endif
#endif  /* LIBHTTP_API */

#ifndef LIBHTTP_THREAD

#if defined(_WIN32)
#define LIBHTTP_THREAD			unsigned __stdcall
#define LIBHTTP_THREAD_TYPE		unsigned
#define LIBHTTP_THREAD_CALLING_CONV	__stdcall
#define LIBHTTP_THREAD_RETNULL		0
#else  /* _WIN32 */
#define LIBHTTP_THREAD			void *
#define LIBHTTP_THREAD_TYPE		void *
#define LIBHTTP_THREAD_CALLING_CONV
#define LIBHTTP_THREAD_RETNULL		NULL
#endif  /* _WIN32 */

#endif  /* LIBHTTP_THREAD */

#include <stdio.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#if defined(_WIN32)
#include <winsock2.h>
#include <windows.h>
#endif /* _WIN32 */

/*
 * For our Posix emulation functions to open and close directories we need
 * to know the path length. If this length is not set yet, we set it here based
 * on an educated guess.
 */

#if !defined(PATH_MAX)
#define PATH_MAX (MAX_PATH)
#endif  /* PATH_MAX */

#if !defined(PATH_MAX)
#define PATH_MAX (4096)
#endif  /* PATH_MAX */

#if defined(_WIN32)

/*
 * The OS does not support Posix calls, but we need some of them for the
 * library to function properly. We therefore define some items which makes
 * life easier in the multiple target world.
 */

#define SIGKILL (0)

typedef HANDLE		pthread_t;
typedef HANDLE		pthread_mutex_t;
typedef DWORD		pthread_key_t;
typedef void		pthread_condattr_t;
typedef void		pthread_mutexattr_t;

typedef struct {
	CRITICAL_SECTION		threadIdSec;
	struct httplib_workerTLS *	waiting_thread; /* The chain of threads */
} pthread_cond_t;

#define pid_t HANDLE /* MINGW typedefs pid_t to int. Using #define here. */

#else  /* _WIN32 */

/*
 * For Posix compliant systems we need to read some include files where
 * definitions, structures and prototypes are present.
 */

#include <sys/poll.h>
#include <sys/types.h>
#include <dirent.h>
#include <pthread.h>
#include <signal.h>

#endif  /* _WIN32 */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#if defined(_WIN32)
/*
 * In Windows we emulate the Posix directory functions to make the OS dependent
 * code on the application side as small as possible.
 */
struct dirent {
	char d_name[PATH_MAX];
};

typedef struct DIR {
	HANDLE handle;
	WIN32_FIND_DATAW info;
	struct dirent result;
} DIR;
#endif  /* _WIN32 */

#if defined(_WIN32) && !defined(POLLIN)
/*
 * If we are on Windows without poll(), we emulate this Posix function.
 */
#ifndef HAVE_POLL
struct pollfd {
	SOCKET fd;
	short events;
	short revents;
};
#define POLLIN (0x0300)
#endif  /* HAVE_POLL */
#endif  /* _WIN32  &&  ! POLLIN */

/*
 * Macros for enabling compiler-specific checks for printf-like arguments.
 */

#undef PRINTF_FORMAT_STRING
#if defined(_MSC_VER) && _MSC_VER >= 1400
#include <sal.h>
#if defined(_MSC_VER) && _MSC_VER > 1400
#define PRINTF_FORMAT_STRING(s) _Printf_format_string_ s
#else
#define PRINTF_FORMAT_STRING(s) __format_string s
#endif
#else
#define PRINTF_FORMAT_STRING(s) s
#endif

#ifdef __GNUC__
#define PRINTF_ARGS(x, y) __attribute__((format(printf, x, y)))
#else
#define PRINTF_ARGS(x, y)
#endif

							/************************************************************************************************/
							/*												*/
							/* enum lh_dbg_t;										*/
							/*												*/
							/* Error messages are generated depending on the debug level of a context. Different contexts	*/
							/* can have different debug levels allowing an application to only generate debug messages of	*/
							/* specific servers or client connections.							*/
enum lh_dbg_t {						/*												*/
	LH_DEBUG_NONE                     = 0x00,	/* No error messages are generated at all							*/
	LH_DEBUG_CRASH                    = 0x10,	/* Messages for errors impacting multiple connections in a severe way are generated		*/
	LH_DEBUG_ERROR                    = 0x20,	/* Messages for errors impacting single connections in a severe way are generated (default)	*/
	LH_DEBUG_WARNING                  = 0x30,	/* Messages for errors impacting single connections in a minor way are generated		*/
	LH_DEBUG_INFO                     = 0x40	/* All error, warning and informational messages are generated					*/
};							/*												*/
							/************************************************************************************************/

							/************************************************************************************************/
							/*												*/
							/* Return values definition for the "field_found" callback in httplib_form_data_handler.	*/
enum {							/*												*/
	FORM_FIELD_STORAGE_SKIP           = 0x00,	/* Skip this field (neither get nor store it). Continue with the next field.			*/
	FORM_FIELD_STORAGE_GET            = 0x01,	/* Get the field value.										*/
	FORM_FIELD_STORAGE_STORE          = 0x02,	/* Store the field value into a file.								*/
	FORM_FIELD_STORAGE_ABORT          = 0x10	/* Stop parsing this request. Skip the remaining fields						*/
};							/*												*/
							/************************************************************************************************/

							/************************************************************************************************/
							/*												*/
							/* Opcodes, from http://tools.ietf.org/html/rfc6455						*/
enum {							/*												*/
	WEBSOCKET_OPCODE_CONTINUATION     = 0x00,	/*												*/
	WEBSOCKET_OPCODE_TEXT             = 0x01,	/*												*/	
	WEBSOCKET_OPCODE_BINARY           = 0x02,	/*												*/
	WEBSOCKET_OPCODE_CONNECTION_CLOSE = 0x08,	/*												*/
	WEBSOCKET_OPCODE_PING             = 0x09,	/*												*/
	WEBSOCKET_OPCODE_PONG             = 0x0A	/*												*/
};							/*												*/
							/************************************************************************************************/

							/************************************************************************************************/
							/*												*/
							/* struct lh_ctx_t;										*/
							/* struct lh_con_t;										*/
							/* struct lh_ip_t;										*/
							/*												*/
							/* Hidden structures used by the library to store context and connection information		*/
							/*												*/
struct lh_ctx_t;					/* Handle for an HTTP context									*/
struct lh_con_t;					/* Handle for an individual connection								*/
struct lh_ip_t;						/* Handle for an IPv4/IPv6 ip address								*/
							/*												*/
							/************************************************************************************************/

							/************************************************************************************************/
							/*												*/
							/* struct client_cert;										*/
							/*												*/
							/* Client certificate information (part of lh_rqi_t)						*/
struct client_cert {					/*												*/
	const char *subject;				/* Subject of the certificate									*/
	const char *issuer;				/* Issuer of the certificate									*/
	const char *serial;				/* Serial number of the certificate								*/
	const char *finger;				/* Finger print of the certificate								*/
};							/*												*/
							/************************************************************************************************/

							/************************************************************************************************/
							/*												*/
							/* struct lh_rqi_t;										*/
							/*												*/
							/* This structure contains information about the HTTP request.					*/
struct lh_rqi_t {					/*												*/
	const char *		request_method;		/* "GET", "POST", etc										*/
	const char *		request_uri;		/* URL-decoded URI (absolute or relative, as in the request)					*/
	const char *		local_uri;		/* URL-decoded URI (relative). Can be NULL if request_uri is not a resource at the server host	*/
	const char *		uri;			/* Deprecated: use local_uri instead								*/
	const char *		http_version;		/* E.g. "1.0", "1.1"										*/
	const char *		query_string;		/* URL part after '?', not including '?', or NULL						*/
	const char *		remote_user;		/* Authenticated user, or NULL if no auth used							*/
	char			remote_addr[48];	/* Client's IP address as a string.								*/
	int64_t			content_length;		/* Length (in bytes) of the request body, can be -1 if no length was given.			*/
	int			remote_port;		/* Client's port										*/
	bool			has_ssl;		/* 1 if SSL-ed, 0 if not									*/
	void *			user_data;		/* User data pointer passed to httplib_start()							*/
	void *			conn_data;		/* Connection-specific user data								*/
	int			num_headers;		/* Number of HTTP headers									*/
	struct httplib_header {				/*												*/
		const char *name;			/* HTTP header name										*/
		const char *value;			/* HTTP header value										*/
	}			http_headers[64];	/* Maximum 64 headers										*/
	struct client_cert *	client_cert;		/* Client certificate information								*/
};							/*												*/
							/************************************************************************************************/

							/************************************************************************************************/
							/*												*/
							/* struct lh_clb_t;										*/
							/*												*/
							/* This structure needs to be passed to httplib_start(), to let LibHTTP know which callbacks to	*/
							/* invoke. For a detailed description, see							*/
							/* https://github.com/lammertb/libhttp/blob/master/docs/UserManual.md				*/
struct lh_clb_t {					/*												*/
	int		(*begin_request)(    struct lh_ctx_t *ctx,       struct lh_con_t *conn );					/*		*/
	void		(*end_request)(      struct lh_ctx_t *ctx, const struct lh_con_t *conn, int reply_status_code );		/*		*/
	int		(*log_message)(      struct lh_ctx_t *ctx, const struct lh_con_t *conn, const char *message );			/*		*/
	int		(*log_access)(       struct lh_ctx_t *ctx, const struct lh_con_t *conn, const char *message );			/*		*/
	int		(*init_ssl)(         struct lh_ctx_t *ctx, void *ssl_context, void *user_data );				/*		*/
	void		(*connection_close)( struct lh_ctx_t *ctx, const struct lh_con_t *conn );					/*		*/
	const char *	(*open_file)(        struct lh_ctx_t *ctx, const struct lh_con_t *conn, const char *path, size_t *data_len );	/*		*/
	void		(*init_lua)(         struct lh_ctx_t *ctx, const struct lh_con_t *conn, void *lua_context );			/*		*/
	int		(*http_error)(       struct lh_ctx_t *ctx, struct lh_con_t *, int status );					/*		*/
	void		(*init_context)(     struct lh_ctx_t *ctx );									/*		*/
	void		(*init_thread)(      struct lh_ctx_t *ctx, int thread_type );							/*		*/
	void		(*exit_context)(     struct lh_ctx_t *ctx );									/*		*/
};							/*												*/
							/************************************************************************************************/

							/************************************************************************************************/
							/*												*/
							/* struct lh_opt_t;										*/
							/*												*/
							/* Option record passed in an array of option records when a context is created			*/
struct lh_opt_t {					/*												*/
	const char *	name;				/* name of the option used when creating a context						*/
	const char *	value;				/* value of the option										*/
};							/*												*/
							/************************************************************************************************/

							/************************************************************************************************/
							/*												*/
							/* struct lh_slp_t										*/
							/*												*/
							/* Record of a port a server is listening on							*/
struct lh_slp_t {					/*												*/
	int		protocol;			/* The protocol supported by the port: 1 = IPv4, 2 = IPv6, 3 = both				*/
	int		port;				/* The port number the server is listening on							*/
	bool		has_ssl;			/* Does this port support https encryption: false = no, true = yes				*/
	bool		has_redirect;			/* redirect all requests to a https connection false = no, true = yes				*/
};							/*												*/
							/************************************************************************************************/

/*
 * This structure contains callback functions for handling form fields.
 * It is used as an argument to httplib_handle_form_request.
 */

struct httplib_form_data_handler {
	int 	(*field_found)( const char *key, const char *filename, char *path, size_t pathlen, void *user_data );
	int 	(*field_get)(   const char *key, const char *value, size_t valuelen,               void *user_data );
	int 	(*field_store)( const char *path, int64_t file_size,                               void *user_data );
	void *	user_data;
};

typedef int	(*httplib_request_handler)(           struct lh_ctx_t *ctx, struct lh_con_t *conn,                                   void *cbdata );
typedef int	(*httplib_authorization_handler)(     struct lh_ctx_t *ctx, struct lh_con_t *conn,                                   void *cbdata );
typedef int	(*httplib_websocket_connect_handler)( struct lh_ctx_t *ctx, struct lh_con_t *conn,                                   void *cbdata );
typedef void	(*httplib_websocket_ready_handler)(   struct lh_ctx_t *ctx, struct lh_con_t *conn,                                   void *cbdata );
typedef int	(*httplib_websocket_data_handler)(    struct lh_ctx_t *ctx, struct lh_con_t *conn, int, char *buffer, size_t buflen, void *cbdata );
typedef void	(*httplib_websocket_close_handler)(   struct lh_ctx_t *ctx, struct lh_con_t *conn,                                   void *cbdata );

typedef LIBHTTP_THREAD_TYPE (LIBHTTP_THREAD_CALLING_CONV *httplib_thread_func_t)(void *arg);

struct httplib_client_options {
	const char *host;
	int port;
	const char *client_cert;
	const char *server_cert;
	/* TODO: add more data */
};

enum { TIMEOUT_INFINITE = -1 };


typedef void (*httplib_alloc_callback_func)( const char *file, unsigned line, const char *action, int64_t current_bytes, int64_t total_blocks, int64_t total_bytes );

#define					httplib_calloc(a, b) XX_httplib_calloc_ex(a, b, __FILE__, __LINE__)
#define					httplib_free(a) XX_httplib_free_ex(a, __FILE__, __LINE__)
#define					httplib_malloc(a) XX_httplib_malloc_ex(a, __FILE__, __LINE__)
#define					httplib_realloc(a, b) XX_httplib_realloc_ex(a, b, __FILE__, __LINE__)

LIBHTTP_API void *			XX_httplib_calloc_ex( size_t count, size_t size, const char *file, unsigned line );
LIBHTTP_API void *			XX_httplib_free_ex( void *memory, const char *file, unsigned line );
LIBHTTP_API void *			XX_httplib_malloc_ex( size_t size, const char *file, unsigned line );
LIBHTTP_API void *			XX_httplib_realloc_ex( void *memory, size_t newsize, const char *file, unsigned line );

LIBHTTP_API int				httplib_atomic_dec( volatile int *addr );
LIBHTTP_API int				httplib_atomic_inc( volatile int *addr );
LIBHTTP_API int				httplib_base64_encode( const unsigned char *src, int src_len, char *dst, int dst_len );
LIBHTTP_API unsigned			httplib_check_feature( unsigned feature );
LIBHTTP_API void			httplib_close_connection( struct lh_ctx_t *ctx, struct lh_con_t *conn );
LIBHTTP_API int				httplib_closedir( DIR *dir );
LIBHTTP_API struct lh_con_t *		httplib_connect_client( struct lh_ctx_t *ctx, const char *host, int port, int use_ssl );
LIBHTTP_API struct lh_con_t *		httplib_connect_client_secure( struct lh_ctx_t *ctx, const struct httplib_client_options *client_options );
LIBHTTP_API struct lh_con_t *		httplib_connect_websocket_client( struct lh_ctx_t *ctx, const char *host, int port, int use_ssl, const char *path, const char *origin, httplib_websocket_data_handler data_func, httplib_websocket_close_handler close_func, void *user_data );
LIBHTTP_API struct lh_ctx_t *		httplib_create_client_context( const struct lh_clb_t *callbacks, const struct lh_opt_t *options );
LIBHTTP_API void			httplib_cry( enum lh_dbg_t debug_level, struct lh_ctx_t *ctx, const struct lh_con_t *conn, PRINTF_FORMAT_STRING(const char *fmt), ...) PRINTF_ARGS(4, 5);
LIBHTTP_API void			httplib_destroy_client_context( struct lh_ctx_t *ctx );
LIBHTTP_API struct lh_con_t *		httplib_download( struct lh_ctx_t *ctx, const char *host, int port, int use_ssl, PRINTF_FORMAT_STRING(const char *request_fmt), ...) PRINTF_ARGS(5, 6);
LIBHTTP_API char *			httplib_error_string( int error_code, char *buf, size_t buf_len );
LIBHTTP_API const char *		httplib_get_builtin_mime_type( const char *file_name );
LIBHTTP_API int				httplib_get_cookie( const char *cookie, const char *var_name, char *buf, size_t buf_len );
LIBHTTP_API enum lh_dbg_t		httplib_get_debug_level( struct lh_ctx_t *ctx );
LIBHTTP_API const char *		httplib_get_header( const struct lh_con_t *conn, const char *name );
LIBHTTP_API const char *		httplib_get_option( const struct lh_ctx_t *ctx, const char *name, char *buffer, size_t buflen );
LIBHTTP_API uint64_t			httplib_get_random( void );
LIBHTTP_API const struct lh_rqi_t *	httplib_get_request_info( const struct lh_con_t *conn );
LIBHTTP_API int				httplib_get_response( const struct lh_ctx_t *ctx, struct lh_con_t *conn, int timeout );
LIBHTTP_API const char *		httplib_get_response_code_text( struct lh_ctx_t *ctx, struct lh_con_t *conn, int response_code );
LIBHTTP_API int				httplib_get_server_ports( const struct lh_ctx_t *ctx, int size, struct lh_slp_t *ports );
LIBHTTP_API void *			httplib_get_user_connection_data( const struct lh_con_t *conn );
LIBHTTP_API void *			httplib_get_user_data( const struct lh_ctx_t *ctx );
LIBHTTP_API int				httplib_get_var( const char *data, size_t data_len, const char *var_name, char *dst, size_t dst_len );
LIBHTTP_API int				httplib_get_var2( const char *data, size_t data_len, const char *var_name, char *dst, size_t dst_len, size_t occurrence );
LIBHTTP_API struct tm *			httplib_gmtime_r( const time_t *clock, struct tm *result );
LIBHTTP_API int				httplib_handle_form_request( struct lh_ctx_t *ctx, struct lh_con_t *conn, struct httplib_form_data_handler *fdh );
LIBHTTP_API int				httplib_kill( pid_t pid, int sig_num );
LIBHTTP_API struct tm *			httplib_localtime_r( const time_t *clock, struct tm *result );
LIBHTTP_API void			httplib_lock_connection( struct lh_con_t *conn );
LIBHTTP_API void			httplib_lock_context( struct lh_ctx_t *ctx );
LIBHTTP_API char *			httplib_md5( char buf[33], ... );
LIBHTTP_API int				httplib_mkdir( const char *path, int mode );
LIBHTTP_API int				httplib_modify_passwords_file( const char *passwords_file_name, const char *domain, const char *user, const char *password );
LIBHTTP_API DIR *			httplib_opendir( const char *name );
LIBHTTP_API int				httplib_poll( struct pollfd *pfd, unsigned int nfds, int timeout );
LIBHTTP_API int				httplib_printf( const struct lh_ctx_t *ctx, struct lh_con_t *conn, PRINTF_FORMAT_STRING(const char *fmt), ...) PRINTF_ARGS(3, 4);
LIBHTTP_API int				httplib_pthread_cond_broadcast( pthread_cond_t *cv );
LIBHTTP_API int				httplib_pthread_cond_destroy( pthread_cond_t *cv );
LIBHTTP_API int				httplib_pthread_cond_init( pthread_cond_t *cv, const pthread_condattr_t *attr );
LIBHTTP_API int				httplib_pthread_cond_signal( pthread_cond_t *cv );
LIBHTTP_API int				httplib_pthread_cond_timedwait( pthread_cond_t *cv, pthread_mutex_t *mutex, const struct timespec *abstime );
LIBHTTP_API int				httplib_pthread_cond_wait( pthread_cond_t *cv, pthread_mutex_t *mutex );
LIBHTTP_API void *			httplib_pthread_getspecific( pthread_key_t key );
LIBHTTP_API int				httplib_pthread_join( pthread_t thread, void **value_ptr );
LIBHTTP_API int				httplib_pthread_key_create( pthread_key_t *key, void (*destructor)(void *) );
LIBHTTP_API int				httplib_pthread_key_delete( pthread_key_t key );
LIBHTTP_API int				httplib_pthread_mutex_destroy( pthread_mutex_t *mutex );
LIBHTTP_API int				httplib_pthread_mutex_init( pthread_mutex_t *mutex, const pthread_mutexattr_t *attr );
LIBHTTP_API int				httplib_pthread_mutex_lock( pthread_mutex_t *mutex );
LIBHTTP_API int				httplib_pthread_mutex_trylock( pthread_mutex_t *mutex );
LIBHTTP_API int				httplib_pthread_mutex_unlock( pthread_mutex_t *mutex );
LIBHTTP_API pthread_t			httplib_pthread_self( void );
LIBHTTP_API int				httplib_pthread_setspecific( pthread_key_t key, void *value );
LIBHTTP_API int				httplib_read( const struct lh_ctx_t *ctx, struct lh_con_t *conn, void *buf, size_t len );
LIBHTTP_API struct dirent *		httplib_readdir( DIR *dir );
LIBHTTP_API int				httplib_remove( const char *path );
LIBHTTP_API void			httplib_send_file( struct lh_ctx_t *ctx, struct lh_con_t *conn, const char *path, const char *mime_type, const char *additional_headers );
LIBHTTP_API void			httplib_set_alloc_callback_func( httplib_alloc_callback_func log_func );
LIBHTTP_API void			httplib_set_auth_handler( struct lh_ctx_t *ctx, const char *uri, httplib_authorization_handler handler, void *cbdata );
LIBHTTP_API enum lh_dbg_t		httplib_set_debug_level( struct lh_ctx_t *ctx, enum lh_dbg_t new_level );
LIBHTTP_API void			httplib_set_request_handler( struct lh_ctx_t *ctx, const char *uri, httplib_request_handler handler, void *cbdata );
LIBHTTP_API void			httplib_set_user_connection_data( struct lh_con_t *conn, void *data );
LIBHTTP_API void			httplib_set_websocket_handler( struct lh_ctx_t *ctx, const char *uri, httplib_websocket_connect_handler connect_handler, httplib_websocket_ready_handler ready_handler, httplib_websocket_data_handler data_handler, httplib_websocket_close_handler close_handler, void *cbdata );
LIBHTTP_API struct lh_ctx_t *		httplib_start( const struct lh_clb_t *callbacks, void *user_data, const struct lh_opt_t *options );
LIBHTTP_API int				httplib_start_thread( httplib_thread_func_t func, void *param );
LIBHTTP_API void			httplib_stop( struct lh_ctx_t *ctx );
LIBHTTP_API int64_t			httplib_store_body( struct lh_ctx_t *ctx, struct lh_con_t *conn, const char *path );
LIBHTTP_API int				httplib_strcasecmp( const char *s1, const char *s2 );
LIBHTTP_API const char *		httplib_strcasestr( const char *big_str, const char *small_str );
LIBHTTP_API char *			httplib_strdup( const char *str );
LIBHTTP_API void			httplib_strlcpy( char *dst, const char *src, size_t len );
LIBHTTP_API int				httplib_strncasecmp( const char *s1, const char *s2, size_t len );
LIBHTTP_API char *			httplib_strndup( const char *str, size_t len );
LIBHTTP_API int				httplib_system_exit( void );
LIBHTTP_API int				httplib_system_init( void );
LIBHTTP_API void			httplib_unlock_connection( struct lh_con_t *conn );
LIBHTTP_API void			httplib_unlock_context( struct lh_ctx_t *ctx );
LIBHTTP_API int				httplib_url_decode( const char *src, int src_len, char *dst, int dst_len, int is_form_url_encoded );
LIBHTTP_API int				httplib_url_encode( const char *src, char *dst, size_t dst_len );
LIBHTTP_API const char *		httplib_version( void );
LIBHTTP_API int				httplib_websocket_client_write( struct lh_ctx_t *ctx, struct lh_con_t *conn, int opcode, const char *data, size_t data_len );
LIBHTTP_API int				httplib_websocket_write( const struct lh_ctx_t *ctx, struct lh_con_t *conn, int opcode, const char *data, size_t data_len );
LIBHTTP_API int				httplib_write( const struct lh_ctx_t *ctx, struct lh_con_t * conn, const void *buf, size_t len );

LIBHTTP_API char *			lh_ipt_to_up(  const struct lh_ip_t *in, char *buffwe, size_t buflen, bool compress, bool hybrid );
LIBHTTP_API char *			lh_ipt_to_ip4( const struct lh_ip_t *in, char *buffer, size_t buflen,                bool hybrid );
LIBHTTP_API char *			lh_ipt_to_ip6( const struct lh_ip_t *in, char *buffer, size_t buflen, bool compress              );

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* LIBHTTP_HEADER_INCLUDED */
