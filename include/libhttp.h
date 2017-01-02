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
#endif

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
#endif

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


struct lh_ctx_t;					/* Handle for the HTTP service itself								*/
struct lh_con_t;					/* Handle for the individual connection								*/


							/************************************************************************************************/
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


/* Client certificate information (part of lh_rqi_t) */
struct client_cert {
	const char *subject;
	const char *issuer;
	const char *serial;
	const char *finger;
};


/*
 * This structure needs to be passed to httplib_start(), to let LibHTTP know
 * which callbacks to invoke. For a detailed description, see
 * https://github.com/lammertb/libhttp/blob/master/docs/UserManual.md
 */

struct lh_clb_t {
	int		(*begin_request)(    const struct lh_ctx_t *ctx,       struct lh_con_t *conn );
	void		(*end_request)(      const struct lh_ctx_t *ctx, const struct lh_con_t *conn, int reply_status_code );
	int		(*log_message)(      const struct lh_ctx_t *ctx, const struct lh_con_t *conn, const char *message );
	int		(*log_access)(       const struct lh_ctx_t *ctx, const struct lh_con_t *conn, const char *message );
	int		(*init_ssl)(         const struct lh_ctx_t *ctx, void *ssl_context, void *user_data );
	void		(*connection_close)( const struct lh_ctx_t *ctx, const struct lh_con_t *conn );
	const char *	(*open_file)(        const struct lh_ctx_t *ctx, const struct lh_con_t *conn, const char *path, size_t *data_len );
	void		(*init_lua)(         const struct lh_ctx_t *ctx, const struct lh_con_t *conn, void *lua_context );
	int		(*http_error)(       const struct lh_ctx_t *ctx, struct lh_con_t *, int status);
	void		(*init_context)(     const struct lh_ctx_t *ctx );
	void		(*init_thread)(      const struct lh_ctx_t *ctx, int thread_type );
	void		(*exit_context)(     const struct lh_ctx_t *ctx );
};

							/************************************************************************************************/
struct lh_opt_t {					/*												*/
	const char *	name;				/* name of the option used when creating a context						*/
	const char *	value;				/* value of the option										*/
};							/*												*/
							/************************************************************************************************/


typedef int (*httplib_request_handler)( const struct lh_ctx_t *ctx, struct lh_con_t *conn, void *cbdata );
typedef int (*httplib_authorization_handler)( const struct lh_ctx_t *ctx, struct lh_con_t *conn, void *cbdata );


/* Callback types for websocket handlers in C/C++.

   httplib_websocket_connect_handler
       Is called when the client intends to establish a websocket connection,
       before websocket handshake.
       Return value:
         0: LibHTTP proceeds with websocket handshake.
         1: connection is closed immediately.

   httplib_websocket_ready_handler
       Is called when websocket handshake is successfully completed, and
       connection is ready for data exchange.

   httplib_websocket_data_handler
       Is called when a data frame has been received from the client.
       Parameters:
         bits: first byte of the websocket frame, see websocket RFC at
               http://tools.ietf.org/html/rfc6455, section 5.2
         data, data_len: payload, with mask (if any) already applied.
       Return value:
         1: keep this websocket connection open.
         0: close this websocket connection.

   lh_con_t_close_handler
       Is called, when the connection is closed.*/
typedef int	(*httplib_websocket_connect_handler)( const struct lh_ctx_t *ctx, struct lh_con_t *conn, void *);
typedef void	(*httplib_websocket_ready_handler)(   const struct lh_ctx_t *ctx, struct lh_con_t *conn, void *);
typedef int	(*httplib_websocket_data_handler)(    const struct lh_ctx_t *ctx, struct lh_con_t *conn, int, char *, size_t, void *);
typedef void	(*httplib_websocket_close_handler)(   const struct lh_ctx_t *ctx, struct lh_con_t *conn, void *);


/* httplib_set_auth_handler

   Sets or removes a URI mapping for an authorization handler.
   This function works similar to httplib_set_request_handler - see there. */


/* Get the value of particular configuration parameter.
   The value returned is read-only. LibHTTP does not allow changing
   configuration at run time.
   If given parameter name is not valid, NULL is returned. For valid
   names, return value is guaranteed to be non-NULL. If parameter is not
   set, zero-length string is returned. */



/* Get user data passed to httplib_start from context. */


struct httplib_server_ports {
	int	protocol;		/* 1 = IPv4, 2 = IPv6, 3 = both			*/
	int	port;			/* port number					*/
	bool	has_ssl;		/* https port: 0 = no, 1 = yes			*/
	bool	has_redirect;		/* redirect all requests: 0 = no, 1 = yes	*/
};


/* Get the list of ports that LibHTTP is listening on.
   The parameter size is the size of the ports array in elements.
   The caller is responsibility to allocate the required memory.
   This function returns the number of struct httplib_server_ports elements
   filled in, or <0 in case of an error. */


/* Add, edit or delete the entry in the passwords file.

   This function allows an application to manipulate .htpasswd files on the
   fly by adding, deleting and changing user records. This is one of the
   several ways of implementing authentication on the server side. For another,
   cookie-based way please refer to the examples/chat in the source tree.

   If password is not NULL, entry is added (or modified if already exists).
   If password is NULL, entry is deleted.

   Return:
     1 on success, 0 on error. */


/* Return information associated with the request. */


/* Send data to the client.
   Return:
    0   when the connection has been closed
    -1  on error
    >0  number of bytes written on success */


/* Send data to a websocket client wrapped in a websocket frame.  Uses
   httplib_lock_connection to ensure that the transmission is not interrupted,
   i.e., when the application is proactively communicating and responding to
   a request simultaneously.

   Send data to a websocket client wrapped in a websocket frame.

   Return:
    0   when the connection has been closed
    -1  on error
    >0  number of bytes written on success */


/* Send data to a websocket server wrapped in a masked websocket frame.  Uses
   httplib_lock_connection to ensure that the transmission is not interrupted,
   i.e., when the application is proactively communicating and responding to
   a request simultaneously.

   Send data to a websocket server wrapped in a masked websocket frame.

   Return:
    0   when the connection has been closed
    -1  on error
    >0  number of bytes written on success */




/* Opcodes, from http://tools.ietf.org/html/rfc6455 */
enum {
	WEBSOCKET_OPCODE_CONTINUATION     = 0x0,
	WEBSOCKET_OPCODE_TEXT             = 0x1,
	WEBSOCKET_OPCODE_BINARY           = 0x2,
	WEBSOCKET_OPCODE_CONNECTION_CLOSE = 0x8,
	WEBSOCKET_OPCODE_PING             = 0x9,
	WEBSOCKET_OPCODE_PONG             = 0xA
};


/* Macros for enabling compiler-specific checks for printf-like arguments. */
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


/* Read data from the remote end, return number of bytes read.
   Return:
     0     connection has been closed by peer. No more data could be read.
     < 0   read error. No more data could be read from the connection.
     > 0   number of bytes read into the buffer. */


/* Get the value of particular HTTP header.

   This is a helper function. It traverses request_info->http_headers array,
   and if the header is present in the array, returns its value. If it is
   not present, NULL is returned. */


/* Get a value of particular form variable.

   Parameters:
     data: pointer to form-uri-encoded buffer. This could be either POST data,
           or request_info.query_string.
     data_len: length of the encoded data.
     var_name: variable name to decode from the buffer
     dst: destination buffer for the decoded variable
     dst_len: length of the destination buffer

   Return:
     On success, length of the decoded variable.
     On error:
        -1 (variable not found).
        -2 (destination buffer is NULL, zero length or too small to hold the
            decoded variable).

   Destination buffer is guaranteed to be '\0' - terminated if it is not
   NULL or zero length. */


/* Get a value of particular form variable.

   Parameters:
     data: pointer to form-uri-encoded buffer. This could be either POST data,
           or request_info.query_string.
     data_len: length of the encoded data.
     var_name: variable name to decode from the buffer
     dst: destination buffer for the decoded variable
     dst_len: length of the destination buffer
     occurrence: which occurrence of the variable, 0 is the first, 1 the
                 second...
                this makes it possible to parse a query like
                b=x&a=y&a=z which will have occurrence values b:0, a:0 and a:1

   Return:
     On success, length of the decoded variable.
     On error:
        -1 (variable not found).
        -2 (destination buffer is NULL, zero length or too small to hold the
            decoded variable).

   Destination buffer is guaranteed to be '\0' - terminated if it is not
   NULL or zero length. */


/* Fetch value of certain cookie variable into the destination buffer.

   Destination buffer is guaranteed to be '\0' - terminated. In case of
   failure, dst[0] == '\0'. Note that RFC allows many occurrences of the same
   parameter. This function returns only first occurrence.

   Return:
     On success, value length.
     On error:
        -1 (either "Cookie:" header is not present at all or the requested
            parameter is not found).
        -2 (destination buffer is NULL, zero length or too small to hold the
            value). */


/* Download data from the remote web server.
     host: host name to connect to, e.g. "foo.com", or "10.12.40.1".
     port: port number, e.g. 80.
     use_ssl: wether to use SSL connection.
     error_buffer, error_buffer_size: error message placeholder.
     request_fmt,...: HTTP request.
   Return:
     On success, valid pointer to the new connection, suitable for httplib_read().
     On error, NULL. error_buffer contains error message.
   Example:
     char ebuf[100];
     struct lh_con_t *conn;
     conn = httplib_download("google.com", 80, 0, ebuf, sizeof(ebuf),
                        "%s", "GET / HTTP/1.0\r\nHost: google.com\r\n\r\n");
 */


/* Close the connection opened by httplib_download(). */


/* This structure contains callback functions for handling form fields.
   It is used as an argument to httplib_handle_form_request. */
struct httplib_form_data_handler {
	/* This callback function is called, if a new field has been found.
	 * The return value of this callback is used to define how the field
	 * should be processed.
	 *
	 * Parameters:
	 *   key: Name of the field ("name" property of the HTML input field).
	 *   filename: Name of a file to upload, at the client computer.
	 *             Only set for input fields of type "file", otherwise NULL.
	 *   path: Output parameter: File name (incl. path) to store the file
	 *         at the server computer. Only used if FORM_FIELD_STORAGE_STORE
	 *         is returned by this callback. Existing files will be
	 *         overwritten.
	 *   pathlen: Length of the buffer for path.
	 *   user_data: Value of the member user_data of httplib_form_data_handler
	 *
	 * Return value:
	 *   The callback must return the intended storage for this field
	 *   (See FORM_FIELD_STORAGE_*).
	 */
	int (*field_found)(const char *key, const char *filename, char *path, size_t pathlen, void *user_data);

	/* If the "field_found" callback returned FORM_FIELD_STORAGE_GET,
	 * this callback will receive the field data.
	 *
	 * Parameters:
	 *   key: Name of the field ("name" property of the HTML input field).
	 *   value: Value of the input field.
	 *   user_data: Value of the member user_data of httplib_form_data_handler
	 *
	 * Return value:
	 *   TODO: Needs to be defined.
	 */
	int (*field_get)(const char *key, const char *value, size_t valuelen, void *user_data);

	/* If the "field_found" callback returned FORM_FIELD_STORAGE_STORE,
	 * the data will be stored into a file. If the file has been written
	 * successfully, this callback will be called. This callback will
	 * not be called for only partially uploaded files. The
	 * httplib_handle_form_request function will either store the file completely
	 * and call this callback, or it will remove any partial content and
	 * not call this callback function.
	 *
	 * Parameters:
	 *   path: Path of the file stored at the server.
	 *   file_size: Size of the stored file in bytes.
	 *   user_data: Value of the member user_data of httplib_form_data_handler
	 *
	 * Return value:
	 *   TODO: Needs to be defined.
	 */
	int (*field_store)(const char *path, int64_t file_size, void *user_data);

	/* User supplied argument, passed to all callback functions. */
	void *user_data;
};


/*
 * Return values definition for the "field_found" callback in
 * httplib_form_data_handler.
 */

enum {
	FORM_FIELD_STORAGE_SKIP  = 0x00,	/* Skip this field (neither get nor store it). Continue with the next field.	*/
	FORM_FIELD_STORAGE_GET   = 0x01,	/* Get the field value.								*/
	FORM_FIELD_STORAGE_STORE = 0x02,	/* Store the field value into a file.						*/
	FORM_FIELD_STORAGE_ABORT = 0x10		/* Stop parsing this request. Skip the remaining fields				*/
};


/* Process form data.
 * Returns the number of fields handled, or < 0 in case of an error.
 * Note: It is possible that several fields are already handled successfully
 * (e.g., stored into files), before the request handling is stopped with an
 * error. In this case a number < 0 is returned as well.
 * In any case, it is the duty of the caller to remove files once they are
 * no longer required. */


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

/* Convenience function -- create detached thread.
   Return: 0 on success, non-0 on error. */
typedef LIBHTTP_THREAD_TYPE (LIBHTTP_THREAD_CALLING_CONV *httplib_thread_func_t)(void *);
LIBHTTP_API int httplib_start_thread(httplib_thread_func_t f, void *p);


/* URL-decode input buffer into destination buffer.
   0-terminate the destination buffer.
   form-url-encoded data differs from URI encoding in a way that it
   uses '+' as character for space, see RFC 1866 section 8.2.1
   http://ftp.ics.uci.edu/pub/ietf/html/rfc1866.txt
   Return: length of the decoded data, or -1 if dst buffer is too small. */


struct httplib_client_options {
	const char *host;
	int port;
	const char *client_cert;
	const char *server_cert;
	/* TODO: add more data */
};




enum debug_level_t {
	DEBUG_LEVEL_NONE,
	DEBUG_LEVEL_CRASH,
	DEBUG_LEVEL_ERROR,
	DEBUG_LEVEL_WARNING,
	DEBUG_LEVEL_INFO
};


enum { TIMEOUT_INFINITE = -1 };


typedef void (*httplib_alloc_callback_func)( const char *file, unsigned line, const char *action, int64_t current_bytes, int64_t total_blocks, int64_t total_bytes );

#define				httplib_calloc(a, b) XX_httplib_calloc_ex(a, b, __FILE__, __LINE__)
#define				httplib_free(a) XX_httplib_free_ex(a, __FILE__, __LINE__)
#define				httplib_malloc(a) XX_httplib_malloc_ex(a, __FILE__, __LINE__)
#define				httplib_realloc(a, b) XX_httplib_realloc_ex(a, b, __FILE__, __LINE__)

LIBHTTP_API void *		XX_httplib_calloc_ex( size_t count, size_t size, const char *file, unsigned line );
LIBHTTP_API void *		XX_httplib_free_ex( void *memory, const char *file, unsigned line );
LIBHTTP_API void *		XX_httplib_malloc_ex( size_t size, const char *file, unsigned line );
LIBHTTP_API void *		XX_httplib_realloc_ex( void *memory, size_t newsize, const char *file, unsigned line );

LIBHTTP_API int			httplib_atomic_dec( volatile int *addr );
LIBHTTP_API int			httplib_atomic_inc( volatile int *addr );
LIBHTTP_API int			httplib_base64_encode( const unsigned char *src, int src_len, char *dst, int dst_len );
LIBHTTP_API unsigned		httplib_check_feature( unsigned feature );
LIBHTTP_API void		httplib_close_connection( struct lh_ctx_t *ctx, struct lh_con_t *conn );
LIBHTTP_API int			httplib_closedir( DIR *dir );
LIBHTTP_API struct lh_con_t *	httplib_connect_client( struct lh_ctx_t *ctx, const char *host, int port, int use_ssl );
LIBHTTP_API struct lh_con_t *	httplib_connect_client_secure( struct lh_ctx_t *ctx, const struct httplib_client_options *client_options );
LIBHTTP_API struct lh_con_t *	httplib_connect_websocket_client( struct lh_ctx_t *ctx, const char *host, int port, int use_ssl, const char *path, const char *origin, httplib_websocket_data_handler data_func, httplib_websocket_close_handler close_func, void *user_data );
LIBHTTP_API struct lh_ctx_t *	httplib_create_client_context( const struct lh_clb_t *callbacks, const struct lh_opt_t *options );
LIBHTTP_API void		httplib_cry( enum debug_level_t debug_level, const struct lh_ctx_t *ctx, const struct lh_con_t *conn, PRINTF_FORMAT_STRING(const char *fmt), ...) PRINTF_ARGS(4, 5);
LIBHTTP_API void		httplib_destroy_client_context( struct lh_ctx_t *ctx );
LIBHTTP_API struct lh_con_t *	httplib_download( struct lh_ctx_t *ctx, const char *host, int port, int use_ssl, PRINTF_FORMAT_STRING(const char *request_fmt), ...) PRINTF_ARGS(5, 6);
LIBHTTP_API char *		httplib_error_string( int error_code, char *buf, size_t buf_len );
LIBHTTP_API const char *	httplib_get_builtin_mime_type( const char *file_name );
LIBHTTP_API int			httplib_get_cookie( const char *cookie, const char *var_name, char *buf, size_t buf_len );
LIBHTTP_API enum debug_level_t	httplib_get_debug_level( struct lh_ctx_t *ctx );
LIBHTTP_API const char *	httplib_get_header( const struct lh_con_t *conn, const char *name );
LIBHTTP_API const char *	httplib_get_option( const struct lh_ctx_t *ctx, const char *name, char *buffer, size_t buflen );
LIBHTTP_API uint64_t		httplib_get_random( void );
LIBHTTP_API const struct lh_rqi_t *httplib_get_request_info( const struct lh_con_t *conn );
LIBHTTP_API int			httplib_get_response( const struct lh_ctx_t *ctx, struct lh_con_t *conn, int timeout );
LIBHTTP_API const char *	httplib_get_response_code_text( const struct lh_ctx_t *ctx, struct lh_con_t *conn, int response_code );
LIBHTTP_API int			httplib_get_server_ports( const struct lh_ctx_t *ctx, int size, struct httplib_server_ports *ports );
LIBHTTP_API void *		httplib_get_user_connection_data( const struct lh_con_t *conn );
LIBHTTP_API void *		httplib_get_user_data( const struct lh_ctx_t *ctx );
LIBHTTP_API int			httplib_get_var( const char *data, size_t data_len, const char *var_name, char *dst, size_t dst_len );
LIBHTTP_API int			httplib_get_var2( const char *data, size_t data_len, const char *var_name, char *dst, size_t dst_len, size_t occurrence );
LIBHTTP_API struct tm *		httplib_gmtime_r( const time_t *clock, struct tm *result );
LIBHTTP_API int			httplib_handle_form_request( const struct lh_ctx_t *ctx, struct lh_con_t *conn, struct httplib_form_data_handler *fdh );
LIBHTTP_API int			httplib_kill( pid_t pid, int sig_num );
LIBHTTP_API struct tm *		httplib_localtime_r( const time_t *clock, struct tm *result );
LIBHTTP_API void		httplib_lock_connection( struct lh_con_t *conn );
LIBHTTP_API void		httplib_lock_context( struct lh_ctx_t *ctx );
LIBHTTP_API char *		httplib_md5( char buf[33], ... );
LIBHTTP_API int			httplib_mkdir( const char *path, int mode );
LIBHTTP_API int			httplib_modify_passwords_file( const char *passwords_file_name, const char *domain, const char *user, const char *password );
LIBHTTP_API DIR *		httplib_opendir( const char *name );
LIBHTTP_API int			httplib_poll( struct pollfd *pfd, unsigned int nfds, int timeout );
LIBHTTP_API int			httplib_printf( const struct lh_ctx_t *ctx, struct lh_con_t *conn, PRINTF_FORMAT_STRING(const char *fmt), ...) PRINTF_ARGS(3, 4);
LIBHTTP_API int			httplib_pthread_cond_broadcast( pthread_cond_t *cv );
LIBHTTP_API int			httplib_pthread_cond_destroy( pthread_cond_t *cv );
LIBHTTP_API int			httplib_pthread_cond_init( pthread_cond_t *cv, const pthread_condattr_t *attr );
LIBHTTP_API int			httplib_pthread_cond_signal( pthread_cond_t *cv );
LIBHTTP_API int			httplib_pthread_cond_timedwait( pthread_cond_t *cv, pthread_mutex_t *mutex, const struct timespec *abstime );
LIBHTTP_API int			httplib_pthread_cond_wait( pthread_cond_t *cv, pthread_mutex_t *mutex );
LIBHTTP_API void *		httplib_pthread_getspecific( pthread_key_t key );
LIBHTTP_API int			httplib_pthread_join( pthread_t thread, void **value_ptr );
LIBHTTP_API int			httplib_pthread_key_create( pthread_key_t *key, void (*destructor)(void *) );
LIBHTTP_API int			httplib_pthread_key_delete( pthread_key_t key );
LIBHTTP_API int			httplib_pthread_mutex_destroy( pthread_mutex_t *mutex );
LIBHTTP_API int			httplib_pthread_mutex_init( pthread_mutex_t *mutex, const pthread_mutexattr_t *attr );
LIBHTTP_API int			httplib_pthread_mutex_lock( pthread_mutex_t *mutex );
LIBHTTP_API int			httplib_pthread_mutex_trylock( pthread_mutex_t *mutex );
LIBHTTP_API int			httplib_pthread_mutex_unlock( pthread_mutex_t *mutex );
LIBHTTP_API pthread_t		httplib_pthread_self( void );
LIBHTTP_API int			httplib_pthread_setspecific( pthread_key_t key, void *value );
LIBHTTP_API int			httplib_read( const struct lh_ctx_t *ctx, struct lh_con_t *conn, void *buf, size_t len );
LIBHTTP_API struct dirent *	httplib_readdir( DIR *dir );
LIBHTTP_API int			httplib_remove( const char *path );
LIBHTTP_API void		httplib_send_file( const struct lh_ctx_t *ctx, struct lh_con_t *conn, const char *path, const char *mime_type, const char *additional_headers );
LIBHTTP_API void		httplib_set_alloc_callback_func( httplib_alloc_callback_func log_func );
LIBHTTP_API void		httplib_set_auth_handler( struct lh_ctx_t *ctx, const char *uri, httplib_authorization_handler handler, void *cbdata );
LIBHTTP_API enum debug_level_t	httplib_set_debug_level( struct lh_ctx_t *ctx, enum debug_level_t new_level );
LIBHTTP_API void		httplib_set_request_handler( struct lh_ctx_t *ctx, const char *uri, httplib_request_handler handler, void *cbdata );
LIBHTTP_API void		httplib_set_user_connection_data( struct lh_con_t *conn, void *data );
LIBHTTP_API void		httplib_set_websocket_handler( struct lh_ctx_t *ctx, const char *uri, httplib_websocket_connect_handler connect_handler, httplib_websocket_ready_handler ready_handler, httplib_websocket_data_handler data_handler, httplib_websocket_close_handler close_handler, void *cbdata );
LIBHTTP_API struct lh_ctx_t *	httplib_start( const struct lh_clb_t *callbacks, void *user_data, const struct lh_opt_t *options );
LIBHTTP_API void		httplib_stop( struct lh_ctx_t *ctx );
LIBHTTP_API int64_t		httplib_store_body( const struct lh_ctx_t *ctx, struct lh_con_t *conn, const char *path );
LIBHTTP_API int			httplib_strcasecmp( const char *s1, const char *s2 );
LIBHTTP_API const char *	httplib_strcasestr( const char *big_str, const char *small_str );
LIBHTTP_API char *		httplib_strdup( const char *str );
LIBHTTP_API void		httplib_strlcpy( char *dst, const char *src, size_t len );
LIBHTTP_API int			httplib_strncasecmp( const char *s1, const char *s2, size_t len );
LIBHTTP_API char *		httplib_strndup( const char *str, size_t len );
LIBHTTP_API int			httplib_system_exit( void );
LIBHTTP_API int			httplib_system_init( void );
LIBHTTP_API void		httplib_unlock_connection( struct lh_con_t *conn );
LIBHTTP_API void		httplib_unlock_context( struct lh_ctx_t *ctx );
LIBHTTP_API int			httplib_url_decode( const char *src, int src_len, char *dst, int dst_len, int is_form_url_encoded );
LIBHTTP_API int			httplib_url_encode( const char *src, char *dst, size_t dst_len );
LIBHTTP_API const char *	httplib_version( void );
LIBHTTP_API int			httplib_websocket_client_write( const struct lh_ctx_t *ctx, struct lh_con_t *conn, int opcode, const char *data, size_t data_len );
LIBHTTP_API int			httplib_websocket_write( const struct lh_ctx_t *ctx, struct lh_con_t *conn, int opcode, const char *data, size_t data_len );
LIBHTTP_API int			httplib_write( const struct lh_ctx_t *ctx, struct lh_con_t * conn, const void *buf, size_t len );

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* LIBHTTP_HEADER_INCLUDED */
