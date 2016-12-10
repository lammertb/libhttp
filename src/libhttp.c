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



#include "libhttp-private.h"

#ifdef __MACH__

/* clock_gettime is not implemented on OSX prior to 10.12 */
int _civet_clock_gettime(int clk_id, struct timespec *t);

int _civet_clock_gettime(int clk_id, struct timespec *t) {

	memset(t, 0, sizeof(*t));
	if (clk_id == CLOCK_REALTIME) {
		struct timeval now;
		int rv = gettimeofday(&now, NULL);
		if (rv) return rv;
		t->tv_sec  = now.tv_sec;
		t->tv_nsec = now.tv_usec * 1000;
		return 0;

	} else if (clk_id == CLOCK_MONOTONIC) {
		static uint64_t clock_start_time = 0;
		static mach_timebase_info_data_t timebase_ifo = {0, 0};

		uint64_t now = mach_absolute_time();

		if (clock_start_time == 0) {
			kern_return_t mach_status = mach_timebase_info(&timebase_ifo);
#if defined(DEBUG)
			assert(mach_status == KERN_SUCCESS);
#else  /* DEBUG */
			/* appease "unused variable" warning for release builds */
			(void)mach_status;
#endif  /* DEBUG */
			clock_start_time = now;
		}

		now = (uint64_t)((double)(now - clock_start_time) * (double)timebase_ifo.numer / (double)timebase_ifo.denom);

		t->tv_sec  = now / 1000000000;
		t->tv_nsec = now % 1000000000;
		return 0;
	}
	return -1; /* EINVAL - Clock ID is unknown */

}  /* _civet_clock_gettime */

/* if clock_gettime is declared, then __CLOCK_AVAILABILITY will be defined */
#ifdef __CLOCK_AVAILABILITY
/* If we compiled with Mac OSX 10.12 or later, then clock_gettime will be
 * declared
 * but it may be NULL at runtime. So we need to check before using it. */
int _civet_safe_clock_gettime(int clk_id, struct timespec *t);

int _civet_safe_clock_gettime(int clk_id, struct timespec *t) {

	if (clock_gettime) return clock_gettime(clk_id, t);
	return _civet_clock_gettime(clk_id, t);

}  /* _civet_safe_clock_gettime */

#define clock_gettime _civet_safe_clock_gettime
#else  /* __CLOCK_AVAILABILITY */
#define clock_gettime _civet_clock_gettime
#endif  /* __CLOCK_AVAILABILITY */

#endif  /* __MACH__ */


mg_static_assert(MAX_WORKER_THREADS >= 1, "worker threads must be a positive number");

mg_static_assert(sizeof(size_t) == 4 || sizeof(size_t) == 8, "size_t data type size check");

/* va_copy should always be a macro, C99 and C++11 - DTL */
#ifndef va_copy
#define va_copy(x, y) ((x) = (y))
#endif

#ifdef _WIN32
/* Create substitutes for POSIX functions in Win32. */

#if defined(__MINGW32__)
/* Show no warning in case system functions are not used. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#endif  /* __MINGW32__ */


static CRITICAL_SECTION global_log_file_lock;

static DWORD pthread_self(void) {

	return GetCurrentThreadId();
}


static int pthread_key_create( pthread_key_t *key, void (*_ignored)(void *)) {

	(void)_ignored;

	if ((key != 0)) {
		*key = TlsAlloc();
		return (*key != TLS_OUT_OF_INDEXES) ? 0 : -1;
	}
	return -2;

}  /* pthread_key_create */


static int pthread_key_delete(pthread_key_t key) {

	return TlsFree(key) ? 0 : 1;

}  /* pthread_key_delete */


static int pthread_setspecific(pthread_key_t key, void *value) {

	return TlsSetValue(key, value) ? 0 : 1;

}  /* pthread_setspecific */


static void * pthread_getspecific(pthread_key_t key) {

	return TlsGetValue(key);

}  /* pthread_getspecific */

#if defined(__MINGW32__)
/* Enable unused function warning again */
#pragma GCC diagnostic pop
#endif  /* __MINGW32__ */

struct pthread_mutex_undefined_struct *XX_httplib_pthread_mutex_attr = NULL;
#else  /* _WIN32 */
pthread_mutexattr_t XX_httplib_pthread_mutex_attr;
#endif /* _WIN32 */


#define PASSWORDS_FILE_NAME ".htpasswd"
#define CGI_ENVIRONMENT_SIZE (4096)
#define MAX_CGI_ENVIR_VARS (256)
#define MG_BUF_LEN (8192)

mg_static_assert(MAX_REQUEST_SIZE >= 256, "request size length must be a positive number");

#if !defined(DEBUG_TRACE)
#if defined(DEBUG)


#if defined(_WIN32_WCE)
/* Create substitutes for POSIX functions in Win32. */

#if defined(__MINGW32__)
/* Show no warning in case system functions are not used. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#endif  /* __MINGW32__ */


static time_t time(time_t *ptime) {

	time_t t;
	SYSTEMTIME st;
	FILETIME ft;

	GetSystemTime(&st);
	SystemTimeToFileTime(&st, &ft);
	t = SYS2UNIX_TIME(ft.dwLowDateTime, ft.dwHighDateTime);

	if (ptime != NULL) *ptime = t;

	return t;
}


static struct tm * localtime_s( const time_t *ptime, struct tm *ptm ) {

	int64_t t = ((int64_t)*ptime) * RATE_DIFF + EPOCH_DIFF;
	FILETIME ft;
	FILETIME lft;
	SYSTEMTIME st;
	TIME_ZONE_INFORMATION tzinfo;

	if ( ptm == NULL ) return NULL;

	*(int64_t *)&ft = t;

	FileTimeToLocalFileTime( &ft, &lft );
	FileTimeToSystemTime(   &lft, &st  );

	ptm->tm_year  = st.wYear - 1900;
	ptm->tm_mon   = st.wMonth - 1;
	ptm->tm_wday  = st.wDayOfWeek;
	ptm->tm_mday  = st.wDay;
	ptm->tm_hour  = st.wHour;
	ptm->tm_min   = st.wMinute;
	ptm->tm_sec   = st.wSecond;
	ptm->tm_yday  = 0; /* hope nobody uses this */
	ptm->tm_isdst = (GetTimeZoneInformation(&tzinfo) == TIME_ZONE_ID_DAYLIGHT) ? 1 : 0;

	return ptm;

}  /* localtime_s */


static struct tm * gmtime_s(const time_t *ptime, struct tm *ptm) {
	/* FIXME(lsm): fix this. */
	return localtime_s(ptime, ptm);
}

static struct tm tm_array[MAX_WORKER_THREADS];
static int tm_index = 0;

static struct tm * localtime( const time_t *ptime ) {

	int i = XX_httplib_atomic_inc(&tm_index) % (sizeof(tm_array) / sizeof(tm_array[0]));
	return localtime_s(ptime, tm_array + i);

}  /* localtime */


static struct tm * gmtime(const time_t *ptime) {

	int i = XX_httplib_atomic_inc(&tm_index) % ARRAY_SIZE(tm_array);
	return gmtime_s(ptime, tm_array + i);

}  /* strftime */


static size_t strftime( char *dst, size_t dst_size, const char *fmt, const struct tm *tm ) {

	/* TODO */ //(void)XX_httplib_snprintf(NULL, dst, dst_size, "implement strftime()
	// for WinCE");
	return 0;
}

#define _beginthreadex(psec, stack, func, prm, flags, ptid)                    \
	(uintptr_t) CreateThread(psec, stack, func, prm, flags, ptid)

#define remove(f) mg_remove(NULL, f)

static int rename(const char *a, const char *b) {

	wchar_t wa[PATH_MAX];
	wchar_t wb[PATH_MAX];

	path_to_unicode( NULL, a, wa, ARRAY_SIZE(wa) );
	path_to_unicode( NULL, b, wb, ARRAY_SIZE(wb) );

	return MoveFileW( wa, wb ) ? 0 : -1;

}  /* rename */

struct stat {
	int64_t st_size;
	time_t st_mtime;
};

static int stat(const char *name, struct stat *st) {

	wchar_t wbuf[PATH_MAX];
	WIN32_FILE_ATTRIBUTE_DATA attr;
	time_t creation_time, write_time;

	path_to_unicode(NULL, name, wbuf, ARRAY_SIZE(wbuf));
	memset(&attr, 0, sizeof(attr));

	GetFileAttributesExW(wbuf, GetFileExInfoStandard, &attr);
	st->st_size = (((int64_t)attr.nFileSizeHigh) << 32) + (int64_t)attr.nFileSizeLow;

	write_time    = SYS2UNIX_TIME( attr.ftLastWriteTime.dwLowDateTime, attr.ftLastWriteTime.dwHighDateTime );
	creation_time = SYS2UNIX_TIME( attr.ftCreationTime.dwLowDateTime,  attr.ftCreationTime.dwHighDateTime  );

	if ( creation_time > write_time ) st->st_mtime = creation_time;
	else                              st->st_mtime = write_time;

	return 0;

}  /* stat */

#define access(x, a) 1 /* not required anyway */

/* WinCE-TODO: define stat, remove, rename, _rmdir, _lseeki64 */
#define EEXIST 1 /* TODO: See Windows error codes */
#define EACCES 2 /* TODO: See Windows error codes */
#define ENOENT 3 /* TODO: See Windows Error codes */

#if defined(__MINGW32__)
/* Enable unused function warning again */
#pragma GCC diagnostic pop
#endif  /* __MINGW32__ */

#endif /* defined(_WIN32_WCE) */

#endif /* DEBUG */
#endif /* DEBUG_TRACE */

#if defined(MEMORY_DEBUGGING)
unsigned long mg_memory_debug_blockCount   = 0;
unsigned long mg_memory_debug_totalMemUsed = 0;


void *XX_httplib_malloc_ex( size_t size, const char *file, unsigned line ) {

	void *data = malloc(size + sizeof(size_t));
	void *memory = 0;
	char mallocStr[256];

	if (data) {
		*(size_t *)data = size;
		mg_memory_debug_totalMemUsed += size;
		mg_memory_debug_blockCount++;
		memory = (void *)(((char *)data) + sizeof(size_t));
	}

	return memory;

}  /* XX_httplib_malloc_ex */


void *XX_httplib_calloc_ex( size_t count, size_t size, const char *file, unsigned line ) {

	void *data = XX_httplib_malloc_ex(size * count, file, line);
	if ( data != NULL ) memset( data, 0, size * count );

	return data;

}  /* XX_httplib_calloc_ex */


void XX_httplib_free_ex( void *memory, const char *file, unsigned line ) {

	char mallocStr[256];
	void *data = (void *)(((char *)memory) - sizeof(size_t));
	size_t size;

	if (memory) {
		size = *(size_t *)data;
		mg_memory_debug_totalMemUsed -= size;
		mg_memory_debug_blockCount--;

		free(data);
	}

}  /* XX_httplib_free_ex */


void *XX_httplib_realloc_ex( void *memory, size_t newsize, const char *file, unsigned line ) {

	char mallocStr[256];
	void *data;
	void *_realloc;
	size_t oldsize;

	if (newsize) {
		if (memory) {
			data = (void *)(((char *)memory) - sizeof(size_t));
			oldsize = *(size_t *)data;
			_realloc = realloc(data, newsize + sizeof(size_t));
			if (_realloc) {
				data = _realloc;
				mg_memory_debug_totalMemUsed -= oldsize;
				mg_memory_debug_totalMemUsed += newsize;
				*(size_t *)data = newsize;
				data = (void *)(((char *)data) + sizeof(size_t));
			} else {
				return _realloc;
			}
		} else {
			data = XX_httplib_malloc_ex(newsize, file, line);
		}
	} else {
		data = 0;
		XX_httplib_free_ex(memory, file, line);
	}

	return data;
}


#else  /* MEMORY_DEBUGGING */

void * XX_httplib_malloc( size_t a ) {

	return malloc(a);

}  /* XX_httplib_malloc */

void *XX_httplib_calloc( size_t a, size_t b ) {

	return calloc(a, b);

}  /* XX_httplib_calloc */

void * XX_httplib_realloc(void *a, size_t b) {

	return realloc(a, b);

}  /* XX_httplib_realloc */

void XX_httplib_free( void *a ) {

	free(a);

}  /* XX_httplib_free */

#endif  /* MEMORY_DEBUGGING */


static void mg_vsnprintf(const struct mg_connection *conn, int *truncated, char *buf, size_t buflen, const char *fmt, va_list ap);

/* This following lines are just meant as a reminder to use the mg-functions
 * for memory management */
#ifdef malloc
#undef malloc
#endif
#ifdef calloc
#undef calloc
#endif
#ifdef realloc
#undef realloc
#endif
#ifdef free
#undef free
#endif
#ifdef snprintf
#undef snprintf
#endif
#ifdef vsnprintf
#undef vsnprintf
#endif
#define malloc DO_NOT_USE_THIS_FUNCTION__USE_httplib_malloc
#define calloc DO_NOT_USE_THIS_FUNCTION__USE_httplib_calloc
#define realloc DO_NOT_USE_THIS_FUNCTION__USE_XX_httplib_realloc
#define free DO_NOT_USE_THIS_FUNCTION__USE_httplib_free
#define snprintf DO_NOT_USE_THIS_FUNCTION__USE_httplib_snprintf
#ifdef _WIN32 /* vsnprintf must not be used in any system, * \ \ \             \
               * but this define only works well for Windows. */
#define vsnprintf DO_NOT_USE_THIS_FUNCTION__USE_mg_vsnprintf
#endif

/* Darwin prior to 7.0 and Win32 do not have socklen_t */
#ifdef NO_SOCKLEN_T
typedef int socklen_t;
#endif /* NO_SOCKLEN_T */
#define _DARWIN_UNLIMITED_SELECT


#if !defined(NO_SSL)  &&  !defined(NO_SSL_DL)

/* XX_httplib_set_ssl_option() function updates this array.
 * It loads SSL library dynamically and changes NULLs to the actual addresses
 * of respective functions. The macros above (like SSL_connect()) are really
 * just calling these functions indirectly via the pointer. */
struct ssl_func XX_httplib_ssl_sw[] = {{"SSL_free", NULL},
                                   {"SSL_accept", NULL},
                                   {"SSL_connect", NULL},
                                   {"SSL_read", NULL},
                                   {"SSL_write", NULL},
                                   {"SSL_get_error", NULL},
                                   {"SSL_set_fd", NULL},
                                   {"SSL_new", NULL},
                                   {"SSL_CTX_new", NULL},
                                   {"SSLv23_server_method", NULL},
                                   {"SSL_library_init", NULL},
                                   {"SSL_CTX_use_PrivateKey_file", NULL},
                                   {"SSL_CTX_use_certificate_file", NULL},
                                   {"SSL_CTX_set_default_passwd_cb", NULL},
                                   {"SSL_CTX_free", NULL},
                                   {"SSL_load_error_strings", NULL},
                                   {"SSL_CTX_use_certificate_chain_file", NULL},
                                   {"SSLv23_client_method", NULL},
                                   {"SSL_pending", NULL},
                                   {"SSL_CTX_set_verify", NULL},
                                   {"SSL_shutdown", NULL},
                                   {"SSL_CTX_load_verify_locations", NULL},
                                   {"SSL_CTX_set_default_verify_paths", NULL},
                                   {"SSL_CTX_set_verify_depth", NULL},
                                   {"SSL_get_peer_certificate", NULL},
                                   {"SSL_get_version", NULL},
                                   {"SSL_get_current_cipher", NULL},
                                   {"SSL_CIPHER_get_name", NULL},
                                   {"SSL_CTX_check_private_key", NULL},
                                   {"SSL_CTX_set_session_id_context", NULL},
                                   {"SSL_CTX_ctrl", NULL},
                                   {"SSL_CTX_set_cipher_list", NULL},
                                   {NULL, NULL}};


/* Similar array as XX_httplib_ssl_sw. These functions could be located in different
 * lib. */
struct ssl_func XX_httplib_crypto_sw[] = {{"CRYPTO_num_locks", NULL},
                                      {"CRYPTO_set_locking_callback", NULL},
                                      {"CRYPTO_set_id_callback", NULL},
                                      {"ERR_get_error", NULL},
                                      {"ERR_error_string", NULL},
                                      {"ERR_remove_state", NULL},
                                      {"ERR_free_strings", NULL},
                                      {"ENGINE_cleanup", NULL},
                                      {"CONF_modules_unload", NULL},
                                      {"CRYPTO_cleanup_all_ex_data", NULL},
                                      {"EVP_cleanup", NULL},
                                      {"X509_free", NULL},
                                      {"X509_get_subject_name", NULL},
                                      {"X509_get_issuer_name", NULL},
                                      {"X509_NAME_oneline", NULL},
                                      {"X509_get_serialNumber", NULL},
                                      {"i2c_ASN1_INTEGER", NULL},
                                      {"EVP_get_digestbyname", NULL},
                                      {"ASN1_digest", NULL},
                                      {"i2d_X509", NULL},
                                      {NULL, NULL}};

#endif /* !defined(NO_SSL)  &&  !defined(NO_SSL_DL) */


#if !defined(NO_CACHING)
static const char *month_names[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
#endif /* !NO_CACHING */



/* Config option name, config types, default value */
struct mg_option XX_httplib_config_options[] = {
    {"cgi_pattern", CONFIG_TYPE_EXT_PATTERN, "**.cgi$|**.pl$|**.php$"},
    {"cgi_environment", CONFIG_TYPE_STRING, NULL},
    {"put_delete_auth_file", CONFIG_TYPE_FILE, NULL},
    {"cgi_interpreter", CONFIG_TYPE_FILE, NULL},
    {"protect_uri", CONFIG_TYPE_STRING, NULL},
    {"authentication_domain", CONFIG_TYPE_STRING, "mydomain.com"},
    {"ssi_pattern", CONFIG_TYPE_EXT_PATTERN, "**.shtml$|**.shtm$"},
    {"throttle", CONFIG_TYPE_STRING, NULL},
    {"access_log_file", CONFIG_TYPE_FILE, NULL},
    {"enable_directory_listing", CONFIG_TYPE_BOOLEAN, "yes"},
    {"error_log_file", CONFIG_TYPE_FILE, NULL},
    {"global_auth_file", CONFIG_TYPE_FILE, NULL},
    {"index_files", CONFIG_TYPE_STRING, "index.xhtml,index.html,index.htm,index.cgi,index.shtml,index.php"},
    {"enable_keep_alive", CONFIG_TYPE_BOOLEAN, "no"},
    {"access_control_list", CONFIG_TYPE_STRING, NULL},
    {"extra_mime_types", CONFIG_TYPE_STRING, NULL},
    {"listening_ports", CONFIG_TYPE_STRING, "8080"},
    {"document_root", CONFIG_TYPE_DIRECTORY, NULL},
    {"ssl_certificate", CONFIG_TYPE_FILE, NULL},
    {"num_threads", CONFIG_TYPE_NUMBER, "50"},
    {"run_as_user", CONFIG_TYPE_STRING, NULL},
    {"url_rewrite_patterns", CONFIG_TYPE_STRING, NULL},
    {"hide_files_patterns", CONFIG_TYPE_EXT_PATTERN, NULL},
    {"request_timeout_ms", CONFIG_TYPE_NUMBER, "30000"},
    {"ssl_verify_peer", CONFIG_TYPE_BOOLEAN, "no"},
    {"ssl_ca_path", CONFIG_TYPE_DIRECTORY, NULL},
    {"ssl_ca_file", CONFIG_TYPE_FILE, NULL},
    {"ssl_verify_depth", CONFIG_TYPE_NUMBER, "9"},
    {"ssl_default_verify_paths", CONFIG_TYPE_BOOLEAN, "yes"},
    {"ssl_cipher_list", CONFIG_TYPE_STRING, NULL},
    {"ssl_protocol_version", CONFIG_TYPE_NUMBER, "0"},
    {"ssl_short_trust", CONFIG_TYPE_BOOLEAN, "no"},
#if defined(USE_WEBSOCKET)
    {"websocket_timeout_ms", CONFIG_TYPE_NUMBER, "30000"},
#endif
    {"decode_url", CONFIG_TYPE_BOOLEAN, "yes"},

#if defined(USE_WEBSOCKET)
    {"websocket_root", CONFIG_TYPE_DIRECTORY, NULL},
#endif
    {"access_control_allow_origin", CONFIG_TYPE_STRING, "*"},
    {"error_pages", CONFIG_TYPE_DIRECTORY, NULL},
    {"tcp_nodelay", CONFIG_TYPE_NUMBER, "0"},
#if !defined(NO_CACHING)
    {"static_file_max_age", CONFIG_TYPE_NUMBER, "3600"},
#endif
#if defined(__linux__)
    {"allow_sendfile_call", CONFIG_TYPE_BOOLEAN, "yes"},
#endif

    {NULL, CONFIG_TYPE_UNKNOWN, NULL}};

/* Check if the XX_httplib_config_options and the corresponding enum have compatible
 * sizes. */
mg_static_assert((sizeof(XX_httplib_config_options) / sizeof(XX_httplib_config_options[0]))
                     == (NUM_OPTIONS + 1),
                 "XX_httplib_config_options and enum not sync");



pthread_key_t XX_httplib_sTlsKey; /* Thread local storage index */
int XX_httplib_sTlsInit = 0;
int XX_httplib_thread_idx_max = 0;


/* Directory entry */
struct de {
	struct mg_connection *conn;
	char *file_name;
	struct file file;
};




const struct uriprot_tp XX_httplib_abs_uri_protocols[] = {{"http://", 7, 80},
                         {"https://", 8, 443},
                         {"ws://", 5, 80},
                         {"wss://", 6, 443},
                         {NULL, 0, 0}};


int XX_httplib_atomic_inc( volatile int *addr ) {

	int ret;
#if defined(_WIN32)
	/* Depending on the SDK, this function uses either
	 * (volatile unsigned int *) or (volatile LONG *),
	 * so whatever you use, the other SDK is likely to raise a warning. */
	ret = InterlockedIncrement((volatile long *)addr);
#elif defined(__GNUC__)                                                        \
    && ((__GNUC__ > 4) || ((__GNUC__ == 4) && (__GNUC_MINOR__ > 0)))
	ret = __sync_add_and_fetch(addr, 1);
#else
	ret = (++(*addr));
#endif
	return ret;

}  /* XX_httplib_atomic_inc */


int XX_httplib_atomic_dec( volatile int *addr ) {

	int ret;
#if defined(_WIN32)
	/* Depending on the SDK, this function uses either
	 * (volatile unsigned int *) or (volatile LONG *),
	 * so whatever you use, the other SDK is likely to raise a warning. */
	ret = InterlockedDecrement((volatile long *)addr);
#elif defined(__GNUC__)                                                        \
    && ((__GNUC__ > 4) || ((__GNUC__ == 4) && (__GNUC_MINOR__ > 0)))
	ret = __sync_sub_and_fetch(addr, 1);
#else
	ret = (--(*addr));
#endif
	return ret;

}  /* XX_httplib_atomic_dec */

#if !defined(NO_THREAD_NAME)
#if defined(_WIN32) && defined(_MSC_VER)
/* Set the thread name for debugging purposes in Visual Studio
 * http://msdn.microsoft.com/en-us/library/xcb2z8hs.aspx
 */
#pragma pack(push, 8)
typedef struct tagTHREADNAME_INFO {
	DWORD dwType;     /* Must be 0x1000. */
	LPCSTR szName;    /* Pointer to name (in user addr space). */
	DWORD dwThreadID; /* Thread ID (-1=caller thread). */
	DWORD dwFlags;    /* Reserved for future use, must be zero. */
} THREADNAME_INFO;
#pragma pack(pop)

#elif defined(__linux__)

#include <sys/prctl.h>
#include <sys/sendfile.h>
#include <sys/eventfd.h>


#if defined(ALTERNATIVE_QUEUE)

static void * event_create(void) {

	int ret = eventfd(0, EFD_CLOEXEC);
	if (ret == -1) {
		/* Linux uses -1 on error, Windows NULL. */
		/* However, Linux does not return 0 on success either. */
		return 0;
	}
	return (void *)ret;

}  /* event_create */


static int event_wait(void *eventhdl) {

	uint64_t u;
	int s = (int)read((int)eventhdl, &u, sizeof(u));
	if (s != sizeof(uint64_t)) {
		/* error */
		return 0;
	}
	(void)u; /* the value is not required */
	return 1;

}  /* event_wait */


static int event_signal(void *eventhdl) {

	uint64_t u = 1;
	int s = (int)write((int)eventhdl, &u, sizeof(u));

	if (s != sizeof(uint64_t)) {
		/* error */
		return 0;
	}
	return 1;

}  /* event_signal */


static void event_destroy(void *eventhdl) {

	close((int)eventhdl);
}  /* event_destroy */
#endif

#endif


#if !defined(__linux__) && !defined(_WIN32) && defined(ALTERNATIVE_QUEUE)

struct posix_event {
	pthread_mutex_t mutex;
	pthread_cond_t cond;
};


static void * event_create(void) {

	struct posix_event *ret = XX_httplib_malloc(sizeof(struct posix_event));
	if ( ret == NULL ) return NULL;

	if (0 != pthread_mutex_init(&(ret->mutex), NULL)) {
		/* pthread mutex not available */
		XX_httplib_free(ret);
		return NULL;
	}
	if (0 != pthread_cond_init(&(ret->cond), NULL)) {
		/* pthread cond not available */
		pthread_mutex_destroy(&(ret->mutex));
		XX_httplib_free(ret);
		return NULL;
	}
	return (void *)ret;

}  /* event_create */


static int event_wait(void *eventhdl) {

	struct posix_event *ev = (struct posix_event *)eventhdl;
	pthread_mutex_lock(&(ev->mutex));
	pthread_cond_wait(&(ev->cond), &(ev->mutex));
	pthread_mutex_unlock(&(ev->mutex));
	return 1;

}  /* event_wait */


static int event_signal(void *eventhdl) {

	struct posix_event *ev = (struct posix_event *)eventhdl;
	pthread_mutex_lock(&(ev->mutex));
	pthread_cond_signal(&(ev->cond));
	pthread_mutex_unlock(&(ev->mutex));
	return 1;

}  /* event_signal */


static void event_destroy(void *eventhdl) {

	struct posix_event *ev = (struct posix_event *)eventhdl;
	pthread_cond_destroy(&(ev->cond));
	pthread_mutex_destroy(&(ev->mutex));
	XX_httplib_free(ev);

}  /* event_destroy */

#endif


void XX_httplib_set_thread_name(const char *name) {

	char threadName[16 + 1]; /* 16 = Max. thread length in Linux/OSX/.. */

	XX_httplib_snprintf( NULL, NULL, threadName, sizeof(threadName), "libhttp-%s", name);

#if defined(_WIN32)
#if defined(_MSC_VER)
	/* Windows and Visual Studio Compiler */
	__try
	{
		THREADNAME_INFO info;
		info.dwType = 0x1000;
		info.szName = threadName;
		info.dwThreadID = ~0U;
		info.dwFlags = 0;

		RaiseException(0x406D1388, 0, sizeof(info) / sizeof(ULONG_PTR), (ULONG_PTR *)&info);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
	}
#elif defined(__MINGW32__)
/* No option known to set thread name for MinGW */
#endif
#elif defined(__GLIBC__)                                                       \
    && ((__GLIBC__ > 2) || ((__GLIBC__ == 2) && (__GLIBC_MINOR__ >= 12)))
	/* pthread_setname_np first appeared in glibc in version 2.12*/
	pthread_setname_np(pthread_self(), threadName);
#elif defined(__linux__)
	/* on linux we can use the old prctl function */
	prctl(PR_SET_NAME, threadName, 0, 0, 0);
#endif
}  /* XX_httplib_set_thread_name */

#else /* !defined(NO_THREAD_NAME) */
void XX_httplib_set_thread_name(const char *threadName) {

}  /* XX_httplib_set_thread_name */
#endif


const struct mg_option * mg_get_valid_options(void) {

	return XX_httplib_config_options;

}  /* mg_get_valid_options */


static int is_file_in_memory(const struct mg_connection *conn, const char *path, struct file *filep) {

	size_t size = 0;

	if (!conn || !filep) return 0;

	if (conn->ctx->callbacks.open_file) {
		filep->membuf = conn->ctx->callbacks.open_file(conn, path, &size);
		if (filep->membuf != NULL) {
			/* NOTE: override filep->size only on success. Otherwise, it might
			 * break constructs like if (!XX_httplib_stat() || !XX_httplib_fopen()) ... */
			filep->size = size;
		}
	}

	return filep->membuf != NULL;

}  /* is_file_in_memory */


static bool is_file_opened( const struct file *filep ) {

	if ( filep == NULL ) return false;

	return ( filep->membuf != NULL  ||  filep->fp != NULL );

}  /* is_file_opened */


/* XX_httplib_fopen will open a file either in memory or on the disk.
 * The input parameter path is a string in UTF-8 encoding.
 * The input parameter mode is the same as for fopen.
 * Either fp or membuf will be set in the output struct filep.
 * The function returns 1 on success, 0 on error. */
int XX_httplib_fopen( const struct mg_connection *conn, const char *path, const char *mode, struct file *filep ) {

	struct stat st;

	if (!filep) return 0; 

	/* TODO (high): XX_httplib_fopen should only open a file, while XX_httplib_stat should
	 * only get the file status. They should not work on different members of
	 * the same structure (bad cohesion). */
	memset(filep, 0, sizeof(*filep));

	if (stat(path, &st) == 0) filep->size = (uint64_t)(st.st_size);

	if (!is_file_in_memory(conn, path, filep)) {
#ifdef _WIN32
		wchar_t wbuf[PATH_MAX], wmode[20];
		path_to_unicode(conn, path, wbuf, ARRAY_SIZE(wbuf));
		MultiByteToWideChar(CP_UTF8, 0, mode, -1, wmode, ARRAY_SIZE(wmode));
		filep->fp = _wfopen(wbuf, wmode);
#else
		/* Linux et al already use unicode. No need to convert. */
		filep->fp = fopen(path, mode);
#endif
	}

	return is_file_opened(filep);

}  /* XX_httplib_fopen */



void XX_httplib_fclose( struct file *filep ) {

	if (filep != NULL && filep->fp != NULL) fclose(filep->fp);

}  /* XX_httplib_fclose */


void XX_httplib_strlcpy( register char *dst, register const char *src, size_t n ) {

	for (; *src != '\0' && n > 1; n--) { *dst++ = *src++; }
	*dst = '\0';

}  /* XX_httplib_strlcpy */


static int lowercase(const char *s) {

	return tolower(*(const unsigned char *)s);
}


int mg_strncasecmp(const char *s1, const char *s2, size_t len) {

	int diff = 0;

	if (len > 0) {
		do {
			diff = lowercase(s1++) - lowercase(s2++);
		} while (diff == 0 && s1[-1] != '\0' && --len > 0);
	}

	return diff;
}


int mg_strcasecmp(const char *s1, const char *s2) {

	int diff;

	do {
		diff = lowercase(s1++) - lowercase(s2++);
	} while (diff == 0 && s1[-1] != '\0');

	return diff;
}


static char * mg_strndup(const char *ptr, size_t len) {

	char *p;

	if ((p = (char *)XX_httplib_malloc(len + 1)) != NULL) XX_httplib_strlcpy(p, ptr, len + 1);

	return p;
}


char * XX_httplib_strdup( const char *str ) {

	return mg_strndup(str, strlen(str));
}


static const char * mg_strcasestr(const char *big_str, const char *small_str) {

	size_t i;
	size_t big_len = strlen(big_str);
	size_t small_len = strlen(small_str);

	if (big_len >= small_len) {
		for (i = 0; i <= (big_len - small_len); i++) {
			if (mg_strncasecmp(big_str + i, small_str, small_len) == 0) return big_str + i;
		}
	}

	return NULL;
}


/* Return null terminated string of given maximum length.
 * Report errors if length is exceeded. */
static void mg_vsnprintf(const struct mg_connection *conn, int *truncated, char *buf, size_t buflen, const char *fmt, va_list ap) {

	int n;
	int ok;

	if (buflen == 0) return;

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
/* Using fmt as a non-literal is intended here, since it is mostly called
 * indirectly by XX_httplib_snprintf */
#endif

	n = (int)vsnprintf_impl(buf, buflen, fmt, ap);
	ok = (n >= 0) && ((size_t)n < buflen);

#ifdef __clang__
#pragma clang diagnostic pop
#endif

	if (ok) {
		if (truncated) *truncated = 0;
	} else {
		if (truncated) *truncated = 1;
		mg_cry(conn, "truncating vsnprintf buffer: [%.*s]", (int)((buflen > 200) ? 200 : (buflen - 1)), buf);
		n = (int)buflen - 1;
	}
	buf[n] = '\0';
}


void XX_httplib_snprintf( const struct mg_connection *conn, int *truncated, char *buf, size_t buflen, const char *fmt, ... ) {

	va_list ap;

	va_start(ap, fmt);
	mg_vsnprintf(conn, truncated, buf, buflen, fmt, ap);
	va_end(ap);
}


int XX_httplib_get_option_index( const char *name ) {

	int i;

	for (i = 0; XX_httplib_config_options[i].name != NULL; i++) {
		if (strcmp(XX_httplib_config_options[i].name, name) == 0) return i;
	}
	return -1;

}  /* XX_httplib_get_option_index */


const char *mg_get_option(const struct mg_context *ctx, const char *name) {

	int i;

	if      ( (i = XX_httplib_get_option_index(name)) == -1 ) return NULL;
	else if ( ctx == NULL  ||  ctx->config[i] == NULL       ) return "";
	else                                                      return ctx->config[i];
}


struct mg_context * mg_get_context(const struct mg_connection *conn) {

	return (conn == NULL) ? (struct mg_context *)NULL : (conn->ctx);
}


void * mg_get_user_data(const struct mg_context *ctx) {

	return (ctx == NULL) ? NULL : ctx->user_data;
}


void mg_set_user_connection_data(struct mg_connection *conn, void *data) {

	if (conn != NULL) conn->request_info.conn_data = data;
}


void * mg_get_user_connection_data(const struct mg_connection *conn) {

	if (conn != NULL) return conn->request_info.conn_data;

	return NULL;
}


int mg_get_server_ports(const struct mg_context *ctx, int size, struct mg_server_ports *ports) {

	int i;
	int cnt = 0;

	if (size <= 0) { return -1; }
	memset(ports, 0, sizeof(*ports) * (size_t)size);
	if (!ctx) { return -1; }
	if (!ctx->listening_sockets) { return -1; }

	for (i = 0; (i < size) && (i < (int)ctx->num_listening_sockets); i++) {

		ports[cnt].port =
#if defined(USE_IPV6)
		    (ctx->listening_sockets[i].lsa.sa.sa_family == AF_INET6)
		        ? ntohs(ctx->listening_sockets[i].lsa.sin6.sin6_port)
		        :
#endif
		        ntohs(ctx->listening_sockets[i].lsa.sin.sin_port);
		ports[cnt].is_ssl = ctx->listening_sockets[i].is_ssl;
		ports[cnt].is_redirect = ctx->listening_sockets[i].ssl_redir;

		if (ctx->listening_sockets[i].lsa.sa.sa_family == AF_INET) {
			/* IPv4 */
			ports[cnt].protocol = 1;
			cnt++;
		} else if (ctx->listening_sockets[i].lsa.sa.sa_family == AF_INET6) {
			/* IPv6 */
			ports[cnt].protocol = 3;
			cnt++;
		}
	}

	return cnt;
}


void XX_httplib_sockaddr_to_string(char *buf, size_t len, const union usa *usa) {

	buf[0] = '\0';

	if (!usa) return;

	if (usa->sa.sa_family == AF_INET) {
		getnameinfo(&usa->sa, sizeof(usa->sin), buf, (unsigned)len, NULL, 0, NI_NUMERICHOST);
	}
#if defined(USE_IPV6)
	else if (usa->sa.sa_family == AF_INET6) {
		getnameinfo(&usa->sa, sizeof(usa->sin6), buf, (unsigned)len, NULL, 0, NI_NUMERICHOST);
	}
#endif

}  /* XX_httplib_sockaddr_to_string */


/* Convert time_t to a string. According to RFC2616, Sec 14.18, this must be
 * included in all responses other than 100, 101, 5xx. */
void XX_httplib_gmt_time_string( char *buf, size_t buf_len, time_t *t ) {

	struct tm *tm;

	tm = ((t != NULL) ? gmtime(t) : NULL);
	if (tm != NULL) {
		strftime(buf, buf_len, "%a, %d %b %Y %H:%M:%S GMT", tm);
	} else {
		XX_httplib_strlcpy(buf, "Thu, 01 Jan 1970 00:00:00 GMT", buf_len);
		buf[buf_len - 1] = '\0';
	}

}  /* XX_httplib_gmt_time_string */


/* difftime for struct timespec. Return value is in seconds. */
static double mg_difftimespec(const struct timespec *ts_now, const struct timespec *ts_before) {

	return (double)(ts_now->tv_nsec - ts_before->tv_nsec) * 1.0E-9
	       + (double)(ts_now->tv_sec - ts_before->tv_sec);
}


/* Print error message to the opened error log stream. */
void mg_cry(const struct mg_connection *conn, const char *fmt, ...) {

	char buf[MG_BUF_LEN];
	char src_addr[IP_ADDR_STR_LEN];
	va_list ap;
	struct file fi;
	time_t timestamp;

	va_start(ap, fmt);
	IGNORE_UNUSED_RESULT(vsnprintf_impl(buf, sizeof(buf), fmt, ap));
	va_end(ap);
	buf[sizeof(buf) - 1] = 0;

	if (!conn) {
		puts(buf);
		return;
	}

	/* Do not lock when getting the callback value, here and below.
	 * I suppose this is fine, since function cannot disappear in the
	 * same way string option can. */
	if ((conn->ctx->callbacks.log_message == NULL)
	    || (conn->ctx->callbacks.log_message(conn, buf) == 0)) {

		if (conn->ctx->config[ERROR_LOG_FILE] != NULL) {
			if (XX_httplib_fopen(conn, conn->ctx->config[ERROR_LOG_FILE], "a+", &fi)
			    == 0) {
				fi.fp = NULL;
			}
		} else fi.fp = NULL;

		if (fi.fp != NULL) {
			flockfile(fi.fp);
			timestamp = time(NULL);

			XX_httplib_sockaddr_to_string(src_addr, sizeof(src_addr), &conn->client.rsa);
			fprintf(fi.fp,
			        "[%010lu] [error] [client %s] ",
			        (unsigned long)timestamp,
			        src_addr);

			if (conn->request_info.request_method != NULL) {
				fprintf(fi.fp,
				        "%s %s: ",
				        conn->request_info.request_method,
				        conn->request_info.request_uri);
			}

			fprintf(fi.fp, "%s", buf);
			fputc('\n', fi.fp);
			fflush(fi.fp);
			funlockfile(fi.fp);
			XX_httplib_fclose(&fi);
		}
	}
}


/* Return fake connection structure. Used for logging, if connection
 * is not applicable at the moment of logging. */
struct mg_connection * XX_httplib_fc( struct mg_context *ctx ) {

	static struct mg_connection fake_connection;

	fake_connection.ctx = ctx;
	return &fake_connection;

}  /* XX_httplib_fc */


const struct mg_request_info * mg_get_request_info( const struct mg_connection *conn ) {

	if ( conn == NULL ) return NULL;

	return & conn->request_info;

}  /* mg_get_request_info */


/* Skip the characters until one of the delimiters characters found.
 * 0-terminate resulting word. Skip the delimiter and following whitespaces.
 * Advance pointer to buffer to the next word. Return found 0-terminated word.
 * Delimiters can be quoted with quotechar. */
static char * skip_quoted(char **buf, const char *delimiters, const char *whitespace, char quotechar) {

	char *p;
	char *begin_word;
	char *end_word;
	char *end_whitespace;

	begin_word = *buf;
	end_word = begin_word + strcspn(begin_word, delimiters);

	/* Check for quotechar */
	if (end_word > begin_word) {
		p = end_word - 1;
		while (*p == quotechar) {
			/* While the delimiter is quoted, look for the next delimiter. */
			/* This happens, e.g., in calls from parse_auth_header,
			 * if the user name contains a " character. */

			/* If there is anything beyond end_word, copy it. */
			if (*end_word != '\0') {
				size_t end_off = strcspn(end_word + 1, delimiters);
				memmove(p, end_word, end_off + 1);
				p += end_off; /* p must correspond to end_word - 1 */
				end_word += end_off + 1;
			} else {
				*p = '\0';
				break;
			}
		}
		for (p++; p < end_word; p++) *p = '\0';
	}

	if (*end_word == '\0') {
		*buf = end_word;
	} else {
		end_whitespace = end_word + 1 + strspn(end_word + 1, whitespace);

		for (p = end_word; p < end_whitespace; p++) *p = '\0';

		*buf = end_whitespace;
	}

	return begin_word;
}


/* Simplified version of skip_quoted without quote char
 * and whitespace == delimiters */
static char * skip(char **buf, const char *delimiters) {

	return skip_quoted(buf, delimiters, delimiters, 0);
}


/* Return HTTP header value, or NULL if not found. */
const char * XX_httplib_get_header( const struct mg_request_info *ri, const char *name ) {

	int i;
	if (ri) {
		for (i = 0; i < ri->num_headers; i++) {
			if (!mg_strcasecmp(name, ri->http_headers[i].name)) return ri->http_headers[i].value;
		}
	}

	return NULL;

}  /* XX_httplib_get_header */


const char *mg_get_header( const struct mg_connection *conn, const char *name ) {

	if ( conn == NULL ) return NULL;

	return XX_httplib_get_header( & conn->request_info, name );

}  /* mg_get_header */


/* A helper function for traversing a comma separated list of values.
 * It returns a list pointer shifted to the next value, or NULL if the end
 * of the list found.
 * Value is stored in val vector. If value has form "x=y", then eq_val
 * vector is initialized to point to the "y" part, and val vector length
 * is adjusted to point only to "x". */
const char *XX_httplib_next_option( const char *list, struct vec *val, struct vec *eq_val ) {

	int end;

reparse:
	if (val == NULL || list == NULL || *list == '\0') {
		/* End of the list */
		list = NULL;
	} else {
		/* Skip over leading LWS */
		while (*list == ' ' || *list == '\t') list++;

		val->ptr = list;
		if ((list = strchr(val->ptr, ',')) != NULL) {
			/* Comma found. Store length and shift the list ptr */
			val->len = ((size_t)(list - val->ptr));
			list++;
		} else {
			/* This value is the last one */
			list = val->ptr + strlen(val->ptr);
			val->len = ((size_t)(list - val->ptr));
		}

		/* Adjust length for trailing LWS */
		end = (int)val->len - 1;
		while (end >= 0 && (val->ptr[end] == ' ' || val->ptr[end] == '\t'))
			end--;
		val->len = (size_t)(end + 1);

		if (val->len == 0) {
			/* Ignore any empty entries. */
			goto reparse;
		}

		if (eq_val != NULL) {
			/* Value has form "x=y", adjust pointers and lengths
			 * so that val points to "x", and eq_val points to "y". */
			eq_val->len = 0;
			eq_val->ptr = (const char *)memchr(val->ptr, '=', val->len);
			if (eq_val->ptr != NULL) {
				eq_val->ptr++; /* Skip over '=' character */
				eq_val->len = ((size_t)(val->ptr - eq_val->ptr)) + val->len;
				val->len = ((size_t)(eq_val->ptr - val->ptr)) - 1;
			}
		}
	}

	return list;

}  /* XX_httplib_next_option */



/* A helper function for checking if a comma separated list of values contains
 * the given option (case insensitvely).
 * 'header' can be NULL, in which case false is returned. */
static int header_has_option(const char *header, const char *option) {

	struct vec opt_vec;
	struct vec eq_vec;

	assert(option != NULL);
	assert(option[0] != '\0');

	while ((header = XX_httplib_next_option(header, &opt_vec, &eq_vec)) != NULL) {
		if (mg_strncasecmp(option, opt_vec.ptr, opt_vec.len) == 0) return 1;
	}

	return 0;
}

/* Perform case-insensitive match of string against pattern */
int XX_httplib_match_prefix(const char *pattern, size_t pattern_len, const char *str) {

	const char *or_str;
	size_t i;
	int j;
	int len;
	int res;

	if ((or_str = (const char *)memchr(pattern, '|', pattern_len)) != NULL) {
		res = XX_httplib_match_prefix(pattern, (size_t)(or_str - pattern), str);
		return (res > 0) ? res : XX_httplib_match_prefix(or_str + 1, (size_t)((pattern + pattern_len) - (or_str + 1)), str);
	}

	for (i = 0, j = 0; i < pattern_len; i++, j++) {
		if (pattern[i] == '?' && str[j] != '\0') {
			continue;
		} else if (pattern[i] == '$') {
			return (str[j] == '\0') ? j : -1;
		} else if (pattern[i] == '*') {
			i++;
			if (pattern[i] == '*') {
				i++;
				len = (int)strlen(str + j);
			} else {
				len = (int)strcspn(str + j, "/");
			}
			if (i == pattern_len) return j + len;
			do {
				res = XX_httplib_match_prefix(pattern + i, pattern_len - i, str + j + len);
			} while (res == -1 && len-- > 0);
			return (res == -1) ? -1 : j + res + len;
		} else if (lowercase(&pattern[i]) != lowercase(&str[j])) {
			return -1;
		}
	}
	return j;

}  /* XX_httplib_match_prefix */


/* HTTP 1.1 assumes keep alive if "Connection:" header is not set
 * This function must tolerate situations when connection info is not
 * set up, for example if request parsing failed. */
int XX_httplib_should_keep_alive( const struct mg_connection *conn ) {

	if (conn != NULL) {
		const char *http_version = conn->request_info.http_version;
		const char *header = mg_get_header(conn, "Connection");
		if (conn->must_close || conn->internal_error || conn->status_code == 401
		    || mg_strcasecmp(conn->ctx->config[ENABLE_KEEP_ALIVE], "yes") != 0
		    || (header != NULL && !header_has_option(header, "keep-alive"))
		    || (header == NULL && http_version
		        && 0 != strcmp(http_version, "1.1"))) {
			return 0;
		}
		return 1;
	}
	return 0;

}  /* XX_httplib_should_keep_alive */


int XX_httplib_should_decode_url( const struct mg_connection *conn ) {

	if ( conn == NULL  ||  conn->ctx == NULL ) return 0;

	return (mg_strcasecmp(conn->ctx->config[DECODE_URL], "yes") == 0);

}  /* XX_httplib_should_decode_url */


const char * XX_httplib_suggest_connection_header( const struct mg_connection *conn ) {

	return XX_httplib_should_keep_alive(conn) ? "keep-alive" : "close";

}  /* XX_httplib_suggest_connection_header */


static int send_no_cache_header(struct mg_connection *conn) {

	/* Send all current and obsolete cache opt-out directives. */
	return mg_printf(conn,
	                 "Cache-Control: no-cache, no-store, "
	                 "must-revalidate, private, max-age=0\r\n"
	                 "Pragma: no-cache\r\n"
	                 "Expires: 0\r\n");
}


static int send_static_cache_header(struct mg_connection *conn) {

#if !defined(NO_CACHING)
	/* Read the server config to check how long a file may be cached.
	 * The configuration is in seconds. */
	int max_age = atoi(conn->ctx->config[STATIC_FILE_MAX_AGE]);
	if (max_age <= 0) {
		/* 0 means "do not cache". All values <0 are reserved
		 * and may be used differently in the future. */
		/* If a file should not be cached, do not only send
		 * max-age=0, but also pragmas and Expires headers. */
		return send_no_cache_header(conn);
	}

	/* Use "Cache-Control: max-age" instead of "Expires" header.
	 * Reason: see https://www.mnot.net/blog/2007/05/15/expires_max-age */
	/* See also https://www.mnot.net/cache_docs/ */
	/* According to RFC 2616, Section 14.21, caching times should not exceed
	 * one year. A year with 365 days corresponds to 31536000 seconds, a leap
	 * year to 31622400 seconds. For the moment, we just send whatever has
	 * been configured, still the behavior for >1 year should be considered
	 * as undefined. */
	return mg_printf(conn, "Cache-Control: max-age=%u\r\n", (unsigned)max_age);
#else  /* NO_CACHING */
	return send_no_cache_header(conn);
#endif /* !NO_CACHING */
}


void XX_httplib_send_http_error( struct mg_connection *conn, int status, const char *fmt, ... ) {

	char buf[MG_BUF_LEN];
	va_list ap;
	int len;
	int i;
	int page_handler_found;
	int scope;
	int truncated;
	int has_body;
	char date[64];
	time_t curtime = time(NULL);
	const char *error_handler = NULL;
	struct file error_page_file = STRUCT_FILE_INITIALIZER;
	const char *error_page_file_ext, *tstr;

	const char *status_text = mg_get_response_code_text(conn, status);

	if (conn == NULL) return;

	conn->status_code = status;
	if (conn->in_error_handler || conn->ctx->callbacks.http_error == NULL
	    || conn->ctx->callbacks.http_error(conn, status)) {
		if (!conn->in_error_handler) {
			/* Send user defined error pages, if defined */
			error_handler = conn->ctx->config[ERROR_PAGES];
			error_page_file_ext = conn->ctx->config[INDEX_FILES];
			page_handler_found = 0;
			if (error_handler != NULL) {
				for (scope = 1; (scope <= 3) && !page_handler_found; scope++) {
					switch (scope) {
					case 1: /* Handler for specific error, e.g. 404 error */
						XX_httplib_snprintf(conn, &truncated, buf, sizeof(buf) - 32, "%serror%03u.", error_handler, status);
						break;
					case 2: /* Handler for error group, e.g., 5xx error handler
					         * for all server errors (500-599) */
						XX_httplib_snprintf(conn, &truncated, buf, sizeof(buf) - 32, "%serror%01uxx.", error_handler, status / 100);
						break;
					default: /* Handler for all errors */
						XX_httplib_snprintf(conn, &truncated, buf, sizeof(buf) - 32, "%serror.", error_handler);
						break;
					}

					/* String truncation in buf may only occur if error_handler
					 * is too long. This string is from the config, not from a
					 * client. */
					(void)truncated;

					len = (int)strlen(buf);

					tstr = strchr(error_page_file_ext, '.');

					while (tstr) {
						for (i = 1; i < 32 && tstr[i] != 0 && tstr[i] != ',';
						     i++)
							buf[len + i - 1] = tstr[i];
						buf[len + i - 1] = 0;
						if (XX_httplib_stat(conn, buf, &error_page_file)) {
							page_handler_found = 1;
							break;
						}
						tstr = strchr(tstr + i, '.');
					}
				}
			}

			if (page_handler_found) {
				conn->in_error_handler = 1;
				XX_httplib_handle_file_based_request(conn, buf, &error_page_file);
				conn->in_error_handler = 0;
				return;
			}
		}

		/* No custom error page. Send default error page. */
		XX_httplib_gmt_time_string(date, sizeof(date), &curtime);

		/* Errors 1xx, 204 and 304 MUST NOT send a body */
		has_body = (status > 199 && status != 204 && status != 304);

		conn->must_close = 1;
		mg_printf(conn, "HTTP/1.1 %d %s\r\n", status, status_text);
		send_no_cache_header(conn);
		if (has_body) mg_printf(conn, "%s", "Content-Type: text/plain; charset=utf-8\r\n");
		mg_printf(conn, "Date: %s\r\n" "Connection: close\r\n\r\n", date);

		/* Errors 1xx, 204 and 304 MUST NOT send a body */
		if (has_body) {
			mg_printf(conn, "Error %d: %s\n", status, status_text);

			if (fmt != NULL) {
				va_start(ap, fmt);
				mg_vsnprintf(conn, NULL, buf, sizeof(buf), fmt, ap);
				va_end(ap);
				mg_write(conn, buf, strlen(buf));
			}

		} else {
			/* No body allowed. Close the connection. */
		}
	}

}  /* XX_httplib_send_http_error */

#if defined(_WIN32)
/* Create substitutes for POSIX functions in Win32. */

#if defined(__MINGW32__)
/* Show no warning in case system functions are not used. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#endif


static int pthread_mutex_init(pthread_mutex_t *mutex, void *unused) {

	(void)unused;
	*mutex = CreateMutex(NULL, FALSE, NULL);
	return (*mutex == NULL) ? -1 : 0;
}


static int pthread_mutex_destroy(pthread_mutex_t *mutex) {

	return (CloseHandle(*mutex) == 0) ? -1 : 0;
}


static int pthread_mutex_lock(pthread_mutex_t *mutex) {

	return (WaitForSingleObject(*mutex, INFINITE) == WAIT_OBJECT_0) ? 0 : -1;
}


#ifdef ENABLE_UNUSED_PTHREAD_FUNCTIONS
static int pthread_mutex_trylock(pthread_mutex_t *mutex) {

	switch (WaitForSingleObject(*mutex, 0)) {

		case WAIT_OBJECT_0: return 0;
		case WAIT_TIMEOUT: return -2; /* EBUSY */
	}
	return -1;
}
#endif


static int pthread_mutex_unlock(pthread_mutex_t *mutex) {

	return (ReleaseMutex(*mutex) == 0) ? -1 : 0;
}


#ifndef WIN_PTHREADS_TIME_H
static int clock_gettime(clockid_t clk_id, struct timespec *tp) {

	FILETIME ft;
	ULARGE_INTEGER li;
	BOOL ok = FALSE;
	double d;
	static double perfcnt_per_sec = 0.0;

	if (tp) {
		memset(tp, 0, sizeof(*tp));
		if (clk_id == CLOCK_REALTIME) {
			GetSystemTimeAsFileTime(&ft);
			li.LowPart = ft.dwLowDateTime;
			li.HighPart = ft.dwHighDateTime;
			li.QuadPart -= 116444736000000000; /* 1.1.1970 in filedate */
			tp->tv_sec = (time_t)(li.QuadPart / 10000000);
			tp->tv_nsec = (long)(li.QuadPart % 10000000) * 100;
			ok = TRUE;
		} else if (clk_id == CLOCK_MONOTONIC) {
			if (perfcnt_per_sec == 0.0) {
				QueryPerformanceFrequency((LARGE_INTEGER *)&li);
				perfcnt_per_sec = 1.0 / li.QuadPart;
			}
			if (perfcnt_per_sec != 0.0) {
				QueryPerformanceCounter((LARGE_INTEGER *)&li);
				d = li.QuadPart * perfcnt_per_sec;
				tp->tv_sec = (time_t)d;
				d -= tp->tv_sec;
				tp->tv_nsec = (long)(d * 1.0E9);
				ok = TRUE;
			}
		}
	}

	return ok ? 0 : -1;
}
#endif


static int pthread_cond_init(pthread_cond_t *cv, const void *unused) {

	(void)unused;
	InitializeCriticalSection(&cv->threadIdSec);
	cv->waiting_thread = NULL;
	return 0;
}


static int pthread_cond_timedwait(pthread_cond_t *cv, pthread_mutex_t *mutex, const struct timespec *abstime) {

	struct mg_workerTLS **ptls;
	struct mg_workerTLS *tls = (struct mg_workerTLS *)pthread_getspecific(XX_httplib_sTlsKey);
	int ok;
	struct timespec tsnow;
	int64_t nsnow;
	int64_t nswaitabs;
	int64_t nswaitrel;
	DWORD mswaitrel;

	EnterCriticalSection(&cv->threadIdSec);
	/* Add this thread to cv's waiting list */
	ptls = &cv->waiting_thread;
	for (; *ptls != NULL; ptls = &(*ptls)->next_waiting_thread)
		;
	tls->next_waiting_thread = NULL;
	*ptls = tls;
	LeaveCriticalSection(&cv->threadIdSec);

	if (abstime) {
		clock_gettime(CLOCK_REALTIME, &tsnow);
		nsnow = (((int64_t)tsnow.tv_sec) * 1000000000) + tsnow.tv_nsec;
		nswaitabs =
		    (((int64_t)abstime->tv_sec) * 1000000000) + abstime->tv_nsec;
		nswaitrel = nswaitabs - nsnow;
		if (nswaitrel < 0) {
			nswaitrel = 0;
		}
		mswaitrel = (DWORD)(nswaitrel / 1000000);
	} else mswaitrel = INFINITE;

	pthread_mutex_unlock(mutex);
	ok = (WAIT_OBJECT_0
	      == WaitForSingleObject(tls->pthread_cond_helper_mutex, mswaitrel));
	if (!ok) {
		ok = 1;
		EnterCriticalSection(&cv->threadIdSec);
		ptls = &cv->waiting_thread;
		for (; *ptls != NULL; ptls = &(*ptls)->next_waiting_thread) {
			if (*ptls == tls) {
				*ptls = tls->next_waiting_thread;
				ok = 0;
				break;
			}
		}
		LeaveCriticalSection(&cv->threadIdSec);
		if (ok) WaitForSingleObject(tls->pthread_cond_helper_mutex, INFINITE);
	}
	/* This thread has been removed from cv's waiting list */
	pthread_mutex_lock(mutex);

	return ok ? 0 : -1;
}


static int pthread_cond_wait(pthread_cond_t *cv, pthread_mutex_t *mutex) {

	return pthread_cond_timedwait(cv, mutex, NULL);
}


static int pthread_cond_signal(pthread_cond_t *cv) {

	HANDLE wkup = NULL;
	BOOL ok = FALSE;

	EnterCriticalSection(&cv->threadIdSec);
	if (cv->waiting_thread) {
		wkup = cv->waiting_thread->pthread_cond_helper_mutex;
		cv->waiting_thread = cv->waiting_thread->next_waiting_thread;

		ok = SetEvent(wkup);
		assert(ok);
	}
	LeaveCriticalSection(&cv->threadIdSec);

	return ok ? 0 : 1;
}


static int pthread_cond_broadcast(pthread_cond_t *cv) {

	EnterCriticalSection(&cv->threadIdSec);
	while (cv->waiting_thread) pthread_cond_signal(cv);
	LeaveCriticalSection(&cv->threadIdSec);

	return 0;
}


static int pthread_cond_destroy(pthread_cond_t *cv) {

	EnterCriticalSection(&cv->threadIdSec);
	assert(cv->waiting_thread == NULL);
	LeaveCriticalSection(&cv->threadIdSec);
	DeleteCriticalSection(&cv->threadIdSec);

	return 0;
}


#ifdef ALTERNATIVE_QUEUE
static void * event_create(void) {

	return (void *)CreateEvent(NULL, FALSE, FALSE, NULL);
}


static int event_wait(void *eventhdl) {

	int res = WaitForSingleObject((HANDLE)eventhdl, INFINITE);
	return (res == WAIT_OBJECT_0);
}


static int event_signal(void *eventhdl) {

	return (int)SetEvent((HANDLE)eventhdl);
}


static void event_destroy(void *eventhdl) {

	CloseHandle((HANDLE)eventhdl);
}
#endif


#if defined(__MINGW32__)
/* Enable unused function warning again */
#pragma GCC diagnostic pop
#endif


/* For Windows, change all slashes to backslashes in path names. */
static void change_slashes_to_backslashes(char *path) {

	int i;

	for (i = 0; path[i] != '\0'; i++) {
		if (path[i] == '/') {
			path[i] = '\\';
		}

		/* remove double backslash (check i > 0 to preserve UNC paths,
		 * like \\server\file.txt) */
		if ((path[i] == '\\') && (i > 0)) {
			while (path[i + 1] == '\\' || path[i + 1] == '/') {
				memmove(path + i + 1, path + i + 2, strlen(path + i + 1));
			}
		}
	}
}


static int mg_wcscasecmp(const wchar_t *s1, const wchar_t *s2) {

	int diff;

	do {
		diff = tolower(*s1) - tolower(*s2);
		s1++;
		s2++;
	} while (diff == 0 && s1[-1] != '\0');

	return diff;
}


/* Encode 'path' which is assumed UTF-8 string, into UNICODE string.
 * wbuf and wbuf_len is a target buffer and its length. */
static void path_to_unicode(const struct mg_connection *conn, const char *path, wchar_t *wbuf, size_t wbuf_len) {

	char buf[PATH_MAX];
	char buf2[PATH_MAX];
	wchar_t wbuf2[MAX_PATH + 1];
	DWORD long_len;
	DWORD err;
	int (*fcompare)(const wchar_t *, const wchar_t *) = mg_wcscasecmp;

	XX_httplib_strlcpy(buf, path, sizeof(buf));
	change_slashes_to_backslashes(buf);

	/* Convert to Unicode and back. If doubly-converted string does not
	 * match the original, something is fishy, reject. */
	memset(wbuf, 0, wbuf_len * sizeof(wchar_t));
	MultiByteToWideChar(CP_UTF8, 0, buf, -1, wbuf, (int)wbuf_len);
	WideCharToMultiByte(
	    CP_UTF8, 0, wbuf, (int)wbuf_len, buf2, sizeof(buf2), NULL, NULL);
	if (strcmp(buf, buf2) != 0) {
		wbuf[0] = L'\0';
	}

	/* TODO: Add a configuration to switch between case sensitive and
	 * case insensitive URIs for Windows server. */
	/*
	if (conn) {
	    if (conn->ctx->config[WINDOWS_CASE_SENSITIVE]) {
	        fcompare = wcscmp;
	    }
	}
	*/
	(void)conn; /* conn is currently unused */

#if !defined(_WIN32_WCE)
	/* Only accept a full file path, not a Windows short (8.3) path. */
	memset(wbuf2, 0, ARRAY_SIZE(wbuf2) * sizeof(wchar_t));
	long_len = GetLongPathNameW(wbuf, wbuf2, ARRAY_SIZE(wbuf2) - 1);
	if (long_len == 0) {
		err = GetLastError();
		if (err == ERROR_FILE_NOT_FOUND) {
			/* File does not exist. This is not always a problem here. */
			return;
		}
	}
	if ((long_len >= ARRAY_SIZE(wbuf2)) || (fcompare(wbuf, wbuf2) != 0)) {
		/* Short name is used. */
		wbuf[0] = L'\0';
	}
#else
	(void)long_len;
	(void)wbuf2;
	(void)err;

	if (strchr(path, '~')) wbuf[0] = L'\0';
#endif
}


/* Windows happily opens files with some garbage at the end of file name.
 * For example, fopen("a.cgi    ", "r") on Windows successfully opens
 * "a.cgi", despite one would expect an error back.
 * This function returns non-0 if path ends with some garbage. */
static int path_cannot_disclose_cgi(const char *path) {

	static const char *allowed_last_characters = "_-";
	int last = path[strlen(path) - 1];
	return isalnum(last) || strchr(allowed_last_characters, last) != NULL;
}


int XX_httplib_stat( struct mg_connection *conn, const char *path, struct file *filep ) {

	wchar_t wbuf[PATH_MAX];
	WIN32_FILE_ATTRIBUTE_DATA info;
	time_t creation_time;

	if ( filep == NULL ) return 0;

	memset(filep, 0, sizeof(*filep));

	if (conn && is_file_in_memory(conn, path, filep)) {
		/* filep->is_directory = 0; filep->gzipped = 0; .. already done by
		 * memset */
		filep->last_modified = time(NULL);
		/* last_modified = now ... assumes the file may change during runtime,
		 * so every XX_httplib_fopen call may return different data */
		/* last_modified = conn->ctx.start_time;
		 * May be used it the data does not change during runtime. This allows
		 * browser caching. Since we do not know, we have to assume the file
		 * in memory may change. */
		return 1;
	}

	path_to_unicode(conn, path, wbuf, ARRAY_SIZE(wbuf));
	if (GetFileAttributesExW(wbuf, GetFileExInfoStandard, &info) != 0) {
		filep->size = MAKEUQUAD(info.nFileSizeLow, info.nFileSizeHigh);
		filep->last_modified =
		    SYS2UNIX_TIME(info.ftLastWriteTime.dwLowDateTime,
		                  info.ftLastWriteTime.dwHighDateTime);

		/* On Windows, the file creation time can be higher than the
		 * modification time, e.g. when a file is copied.
		 * Since the Last-Modified timestamp is used for caching
		 * it should be based on the most recent timestamp. */
		creation_time = SYS2UNIX_TIME(info.ftCreationTime.dwLowDateTime,
		                              info.ftCreationTime.dwHighDateTime);
		if (creation_time > filep->last_modified) {
			filep->last_modified = creation_time;
		}

		filep->is_directory = info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY;
		/* If file name is fishy, reset the file structure and return
		 * error.
		 * Note it is important to reset, not just return the error, cause
		 * functions like is_file_opened() check the struct. */
		if (!filep->is_directory && !path_cannot_disclose_cgi(path)) {
			memset(filep, 0, sizeof(*filep));
			return 0;
		}

		return 1;
	}

	return 0;

}  /* XX_httplib_stat */


static int mg_remove(const struct mg_connection *conn, const char *path) {

	wchar_t wbuf[PATH_MAX];
	path_to_unicode(conn, path, wbuf, ARRAY_SIZE(wbuf));
	return DeleteFileW(wbuf) ? 0 : -1;
}


static int mg_mkdir(const struct mg_connection *conn, const char *path, int mode) {

	wchar_t wbuf[PATH_MAX];

	(void)mode;
	path_to_unicode(conn, path, wbuf, ARRAY_SIZE(wbuf));
	return CreateDirectoryW(wbuf, NULL) ? 0 : -1;
}


/* Create substitutes for POSIX functions in Win32. */

#if defined(__MINGW32__)
/* Show no warning in case system functions are not used. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#endif


/* Implementation of POSIX opendir/closedir/readdir for Windows. */
static DIR * mg_opendir(const struct mg_connection *conn, const char *name) {

	DIR *dir = NULL;
	wchar_t wpath[PATH_MAX];
	DWORD attrs;

	if (name == NULL) {
		SetLastError(ERROR_BAD_ARGUMENTS);
	} else if ((dir = (DIR *)XX_httplib_malloc(sizeof(*dir))) == NULL) {
		SetLastError(ERROR_NOT_ENOUGH_MEMORY);
	} else {
		path_to_unicode(conn, name, wpath, ARRAY_SIZE(wpath));
		attrs = GetFileAttributesW(wpath);
		if (attrs != 0xFFFFFFFF && ((attrs & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY)) {

			wcscat(wpath, L"\\*");
			dir->handle = FindFirstFileW(wpath, &dir->info);
			dir->result.d_name[0] = '\0';
		} else {
			XX_http_free(dir);
			dir = NULL;
		}
	}

	return dir;

}  /* mg_opendir */


static int mg_closedir(DIR *dir) {

	int result = 0;

	if (dir != NULL) {
		if (dir->handle != INVALID_HANDLE_VALUE)
			result = FindClose(dir->handle) ? 0 : -1;

		XX_httplib_free(dir);
	} else {
		result = -1;
		SetLastError(ERROR_BAD_ARGUMENTS);
	}

	return result;
}


static struct dirent * mg_readdir(DIR *dir) {

	struct dirent *result = 0;

	if (dir) {
		if (dir->handle != INVALID_HANDLE_VALUE) {
			result = &dir->result;
			WideCharToMultiByte(CP_UTF8, 0, dir->info.cFileName, -1, result->d_name, sizeof(result->d_name), NULL, NULL);

			if (!FindNextFileW(dir->handle, &dir->info)) {

				FindClose(dir->handle);
				dir->handle = INVALID_HANDLE_VALUE;
			}

		} else {
			SetLastError(ERROR_FILE_NOT_FOUND);
		}
	} else SetLastError(ERROR_BAD_ARGUMENTS);

	return result;
}


#ifndef HAVE_POLL
static int poll(struct pollfd *pfd, unsigned int n, int milliseconds) {

	struct timeval tv;
	fd_set set;
	unsigned int i;
	int result;
	SOCKET maxfd = 0;

	memset(&tv, 0, sizeof(tv));
	tv.tv_sec = milliseconds / 1000;
	tv.tv_usec = (milliseconds % 1000) * 1000;
	FD_ZERO(&set);

	for (i = 0; i < n; i++) {
		FD_SET((SOCKET)pfd[i].fd, &set);
		pfd[i].revents = 0;

		if (pfd[i].fd > maxfd) maxfd = pfd[i].fd;
	}

	if ((result = select((int)maxfd + 1, &set, NULL, NULL, &tv)) > 0) {
		for (i = 0; i < n; i++) {
			if (FD_ISSET(pfd[i].fd, &set)) pfd[i].revents = POLLIN;
		}
	}

	return result;
}
#endif /* HAVE_POLL */

#if defined(__MINGW32__)
/* Enable unused function warning again */
#pragma GCC diagnostic pop
#endif

/* conn parameter may be NULL */
void XX_httplib_set_close_on_exec( SOCKET sock, struct mg_connection *conn ) {

	(void)conn; /* Unused. */
#if defined(_WIN32_WCE)
	(void)sock;
#else
	SetHandleInformation((HANDLE)(intptr_t)sock, HANDLE_FLAG_INHERIT, 0);
#endif

}  /* XX_httplib_set_close_on_exec */


int
mg_start_thread(mg_thread_func_t f, void *p)
{
#if defined(USE_STACK_SIZE) && (USE_STACK_SIZE > 1)
	/* Compile-time option to control stack size, e.g. -DUSE_STACK_SIZE=16384
	 */
	return ((_beginthread((void(__cdecl *)(void *))f, USE_STACK_SIZE, p) == ((uintptr_t)(-1L))) ? -1 : 0);
#else
	return ( (_beginthread((void(__cdecl *)(void *))f, 0, p) == ((uintptr_t)(-1L))) ? -1 : 0);
#endif /* defined(USE_STACK_SIZE) && (USE_STACK_SIZE > 1) */
}


/* Start a thread storing the thread context. */
int XX_httplib_start_thread_with_id( unsigned(__stdcall *f)(void *), void *p, pthread_t *threadidptr ) {

	uintptr_t uip;
	HANDLE threadhandle;
	int result = -1;

	uip = _beginthreadex(NULL, 0, (unsigned(__stdcall *)(void *))f, p, 0, NULL);
	threadhandle = (HANDLE)uip;
	if ((uip != (uintptr_t)(-1L)) && (threadidptr != NULL)) {
		*threadidptr = threadhandle;
		result = 0;
	}

	return result;

}  /* XX_httplib_start_thread_with_id */


/* Wait for a thread to finish. */
int XX_httplib_join_thread( pthread_t threadid ) {

	int result;
	DWORD dwevent;

	result = -1;
	dwevent = WaitForSingleObject(threadid, INFINITE);
	if (dwevent == WAIT_FAILED) {
	} else {
		if (dwevent == WAIT_OBJECT_0) {
			CloseHandle(threadid);
			result = 0;
		}
	}

	return result;

}  /* XX_httplib_join_thread */



#if !defined(NO_SSL_DL) && !defined(NO_SSL)
/* If SSL is loaded dynamically, dlopen/dlclose is required. */
/* Create substitutes for POSIX functions in Win32. */

#if defined(__MINGW32__)
/* Show no warning in case system functions are not used. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#endif


static HANDLE dlopen(const char *dll_name, int flags) {

	wchar_t wbuf[PATH_MAX];

	(void)flags;
	path_to_unicode(NULL, dll_name, wbuf, ARRAY_SIZE(wbuf));
	return LoadLibraryW(wbuf);

}  /* dlopen */


static int dlclose(void *handle) {

	int result;

	if ( FreeLibrary((HMODULE)handle) != 0 ) result = 0;
	else                                     result = -1;

	return result;

}  /* dlclose */


#if defined(__MINGW32__)
/* Enable unused function warning again */
#pragma GCC diagnostic pop
#endif

#endif


#if !defined(NO_CGI)
#define SIGKILL (0)

static int kill(pid_t pid, int sig_num) {

	TerminateProcess((HANDLE)pid, (UINT)sig_num);
	CloseHandle((HANDLE)pid);

	return 0;

}  /* kill */


static void trim_trailing_whitespaces( char *s ) {

	char *e = s + strlen(s) - 1;
	while (e > s && isspace(*(unsigned char *)e)) *e-- = '\0';

}  /* trim_trailing_whitespaces */


static pid_t spawn_process(struct mg_connection *conn, const char *prog, char *envblk, char *envp[], int fdin[2], int fdout[2], int fderr[2], const char *dir) {

	HANDLE me;
	char *p;
	char *interp;
	char full_interp[PATH_MAX];
	char full_dir[PATH_MAX];
	char cmdline[PATH_MAX];
	char buf[PATH_MAX];
	int truncated;
	struct file file = STRUCT_FILE_INITIALIZER;
	STARTUPINFOA si;
	PROCESS_INFORMATION pi = {0};

	(void)envp;

	memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);

	si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;

	me = GetCurrentProcess();
	DuplicateHandle( me, (HANDLE)_get_osfhandle(fdin[0]), me, &si.hStdInput, 0, TRUE, DUPLICATE_SAME_ACCESS);
	DuplicateHandle( me, (HANDLE)_get_osfhandle(fdout[1]), me, &si.hStdOutput, 0, TRUE, DUPLICATE_SAME_ACCESS);
	DuplicateHandle( me, (HANDLE)_get_osfhandle(fderr[1]), me, &si.hStdError, 0, TRUE, DUPLICATE_SAME_ACCESS);

	/* Mark handles that should not be inherited. See
	 * https://msdn.microsoft.com/en-us/library/windows/desktop/ms682499%28v=vs.85%29.aspx
	 */
	SetHandleInformation((HANDLE)_get_osfhandle(fdin[1]), HANDLE_FLAG_INHERIT, 0);
	SetHandleInformation((HANDLE)_get_osfhandle(fdout[0]), HANDLE_FLAG_INHERIT, 0);
	SetHandleInformation((HANDLE)_get_osfhandle(fderr[0]), HANDLE_FLAG_INHERIT, 0);

	/* If CGI file is a script, try to read the interpreter line */
	interp = conn->ctx->config[CGI_INTERPRETER];
	if (interp == NULL) {
		buf[0] = buf[1] = '\0';

		/* Read the first line of the script into the buffer */
		XX_httplib_snprintf( conn, &truncated, cmdline, sizeof(cmdline), "%s/%s", dir, prog);

		if (truncated) {
			pi.hProcess = (pid_t)-1;
			goto spawn_cleanup;
		}

		if (XX_httplib_fopen(conn, cmdline, "r", &file)) {
			p = (char *)file.membuf;
			mg_fgets(buf, sizeof(buf), &file, &p);
			XX_httplib_fclose(&file);
			buf[sizeof(buf) - 1] = '\0';
		}

		if (buf[0] == '#' && buf[1] == '!') {
			trim_trailing_whitespaces(buf + 2);
		} else {
			buf[2] = '\0';
		}
		interp = buf + 2;
	}

	if (interp[0] != '\0') {
		GetFullPathNameA(interp, sizeof(full_interp), full_interp, NULL);
		interp = full_interp;
	}
	GetFullPathNameA(dir, sizeof(full_dir), full_dir, NULL);

	if (interp[0] != '\0') {
		XX_httplib_snprintf(conn, &truncated, cmdline, sizeof(cmdline), "\"%s\" \"%s\\%s\"", interp, full_dir, prog);
	} else {
		XX_httplib_snprintf(conn, &truncated, cmdline, sizeof(cmdline), "\"%s\\%s\"", full_dir, prog);
	}

	if (truncated) {
		pi.hProcess = (pid_t)-1;
		goto spawn_cleanup;
	}

	if (CreateProcessA(NULL, cmdline, NULL, NULL, TRUE, CREATE_NEW_PROCESS_GROUP, envblk, NULL, &si, &pi) == 0) {
		mg_cry(
		    conn, "%s: CreateProcess(%s): %ld", __func__, cmdline, (long)ERRNO);
		pi.hProcess = (pid_t)-1;
		/* goto spawn_cleanup; */
	}

spawn_cleanup:
	CloseHandle(si.hStdOutput);
	CloseHandle(si.hStdError);
	CloseHandle(si.hStdInput);

	if (pi.hThread != NULL) (void)CloseHandle(pi.hThread);

	return (pid_t)pi.hProcess;
}
#endif /* !NO_CGI */


int XX_httplib_set_non_blocking_mode( SOCKET sock ) {

	unsigned long on = 1;
	return ioctlsocket(sock, (long)FIONBIO, &on);

}  /* XX_httplib_set_non_blocking_mode */

#else

int XX_httplib_stat( struct mg_connection *conn, const char *path, struct file *filep ) {

	struct stat st;
	if (!filep) return 0;

	memset(filep, 0, sizeof(*filep));

	if (conn && is_file_in_memory(conn, path, filep)) return 1;

	if (0 == stat(path, &st)) {
		filep->size = (uint64_t)(st.st_size);
		filep->last_modified = st.st_mtime;
		filep->is_directory = S_ISDIR(st.st_mode);
		return 1;
	}

	return 0;

}  /* XX_httplib_stat */

/* conn may be NULL */
void XX_httplib_set_close_on_exec( SOCKET fd, struct mg_connection *conn ) {

	if (fcntl(fd, F_SETFD, FD_CLOEXEC) != 0) {
		if (conn) { mg_cry(conn, "%s: fcntl(F_SETFD FD_CLOEXEC) failed: %s", __func__, strerror(ERRNO)); }
	}

}  /* XX_httplib_set_close_on_exec */


int mg_start_thread(mg_thread_func_t func, void *param) {

	pthread_t thread_id;
	pthread_attr_t attr;
	int result;

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

#if defined(USE_STACK_SIZE) && (USE_STACK_SIZE > 1)
	/* Compile-time option to control stack size,
	 * e.g. -DUSE_STACK_SIZE=16384 */
	pthread_attr_setstacksize(&attr, USE_STACK_SIZE);
#endif /* defined(USE_STACK_SIZE) && (USE_STACK_SIZE > 1) */

	result = pthread_create(&thread_id, &attr, func, param);
	pthread_attr_destroy(&attr);

	return result;
}  /* mg_start_thread */


/* Start a thread storing the thread context. */
int XX_httplib_start_thread_with_id( mg_thread_func_t func, void *param, pthread_t *threadidptr ) {

	pthread_t thread_id;
	pthread_attr_t attr;
	int result;

	pthread_attr_init(&attr);

#if defined(USE_STACK_SIZE) && (USE_STACK_SIZE > 1)
	/* Compile-time option to control stack size,
	 * e.g. -DUSE_STACK_SIZE=16384 */
	pthread_attr_setstacksize(&attr, USE_STACK_SIZE);
#endif /* defined(USE_STACK_SIZE) && USE_STACK_SIZE > 1 */

	result = pthread_create(&thread_id, &attr, func, param);
	pthread_attr_destroy(&attr);
	if ((result == 0) && (threadidptr != NULL)) *threadidptr = thread_id;
	return result;

}  /* XX_httplib_start_thread_with_id */


/* Wait for a thread to finish. */
int XX_httplib_join_thread( pthread_t threadid ) {

	int result;

	result = pthread_join(threadid, NULL);
	return result;

}  /* XX_httplib_join_thread */


#ifndef NO_CGI
static pid_t spawn_process(struct mg_connection *conn, const char *prog, char *envblk, char *envp[], int fdin[2], int fdout[2], int fderr[2], const char *dir) {

	pid_t pid;
	const char *interp;

	(void)envblk;

	if ( conn == NULL ) return 0;

	if ((pid = fork()) == -1) {
		/* Parent */
		XX_httplib_send_http_error(conn, 500, "Error: Creating CGI process\nfork(): %s", strerror(ERRNO));
	} else if (pid == 0) {
		/* Child */
		if      ( chdir( dir        ) !=  0 ) mg_cry(conn, "%s: chdir(%s): %s", __func__,   dir,      strerror(ERRNO));
		else if ( dup2( fdin[0], 0  ) == -1 ) mg_cry(conn, "%s: dup2(%d, 0): %s", __func__, fdin[0],  strerror(ERRNO));
		else if ( dup2( fdout[1], 1 ) == -1 ) mg_cry(conn, "%s: dup2(%d, 1): %s", __func__, fdout[1], strerror(ERRNO));
		else if ( dup2( fderr[1], 2 ) == -1 ) mg_cry(conn, "%s: dup2(%d, 2): %s", __func__, fderr[1], strerror(ERRNO));
		else {
			/* Keep stderr and stdout in two different pipes.
			 * Stdout will be sent back to the client,
			 * stderr should go into a server error log. */
			close(fdin[0]);
			close(fdout[1]);
			close(fderr[1]);

			/* Close write end fdin and read end fdout and fderr */
			close(fdin[1]);
			close(fdout[0]);
			close(fderr[0]);

			/* After exec, all signal handlers are restored to their default
			 * values, with one exception of SIGCHLD. According to
			 * POSIX.1-2001 and Linux's implementation, SIGCHLD's handler will
			 * leave unchanged after exec if it was set to be ignored. Restore
			 * it to default action. */
			signal(SIGCHLD, SIG_DFL);

			interp = conn->ctx->config[CGI_INTERPRETER];
			if (interp == NULL) {
				(void)execle(prog, prog, NULL, envp);
				mg_cry(conn, "%s: execle(%s): %s", __func__, prog, strerror(ERRNO));
			} else {
				(void)execle(interp, interp, prog, NULL, envp);
				mg_cry(conn, "%s: execle(%s %s): %s", __func__, interp, prog, strerror(ERRNO));
			}
		}
		exit(EXIT_FAILURE);
	}

	return pid;
}
#endif /* !NO_CGI */


int XX_httplib_set_non_blocking_mode( SOCKET sock ) {

	int flags;

	flags = fcntl(sock, F_GETFL, 0);
	fcntl(sock, F_SETFL, flags | O_NONBLOCK);

	return 0;

}  /* XX_httplib_set_non_blocking_mode */

#endif /* _WIN32 */
/* End of initial operating system specific define block. */


/* Get a random number (independent of C rand function) */
uint64_t XX_httplib_get_random( void ) {

	static uint64_t lfsr = 0; /* Linear feedback shift register */
	static uint64_t lcg = 0;  /* Linear congruential generator */
	struct timespec now;

	memset(&now, 0, sizeof(now));
	clock_gettime(CLOCK_MONOTONIC, &now);

	if (lfsr == 0) {
		/* lfsr will be only 0 if has not been initialized,
		 * so this code is called only once. */
		lfsr = (((uint64_t)now.tv_sec) << 21) ^ ((uint64_t)now.tv_nsec)
		       ^ ((uint64_t)(ptrdiff_t)&now) ^ (((uint64_t)time(NULL)) << 33);
		lcg = (((uint64_t)now.tv_sec) << 25) + (uint64_t)now.tv_nsec
		      + (uint64_t)(ptrdiff_t)&now;
	} else {
		/* Get the next step of both random number generators. */
		lfsr = (lfsr >> 1)
		       | ((((lfsr >> 0) ^ (lfsr >> 1) ^ (lfsr >> 3) ^ (lfsr >> 4)) & 1)
		          << 63);
		lcg = lcg * 6364136223846793005 + 1442695040888963407;
	}

	/* Combining two pseudo-random number generators and a high resolution part
	 * of the current server time will make it hard (impossible?) to guess the
	 * next number. */
	return (lfsr ^ lcg ^ (uint64_t)now.tv_nsec);

}  /* XX_httplib_get_random */


/* Write data to the IO channel - opened file descriptor, socket or SSL
 * descriptor. Return number of bytes written. */
static int push(struct mg_context *ctx, FILE *fp, SOCKET sock, SSL *ssl, const char *buf, int len, double timeout) {

	struct timespec start;
	struct timespec now;
	int n;
	int err;

#ifdef _WIN32
	typedef int len_t;
#else
	typedef size_t len_t;
#endif

	if (timeout > 0) {
		memset(&start, 0, sizeof(start));
		memset(&now, 0, sizeof(now));
		clock_gettime(CLOCK_MONOTONIC, &start);
	}

	if (ctx == NULL) return -1;

#ifdef NO_SSL
	if (ssl) return -1;
#endif

	do {

#ifndef NO_SSL
		if (ssl != NULL) {
			n = SSL_write(ssl, buf, len);
			if (n <= 0) {
				err = SSL_get_error(ssl, n);
				if ((err == SSL_ERROR_SYSCALL) && (n == -1)) {
					err = ERRNO;
				} else if ((err == SSL_ERROR_WANT_READ)
				           || (err == SSL_ERROR_WANT_WRITE)) {
					n = 0;
				} else return -1;
			} else err = 0;
		} else
#endif
		    if (fp != NULL) {
			n = (int)fwrite(buf, 1, (size_t)len, fp);
			if (ferror(fp)) {
				n = -1;
				err = ERRNO;
			} else err = 0;
		} else {
			n = (int)send(sock, buf, (len_t)len, MSG_NOSIGNAL);
			err = (n < 0) ? ERRNO : 0;
			if (n == 0) {
				/* shutdown of the socket at client side */
				return -1;
			}
		}

		if (ctx->stop_flag) return -1;

		if ((n > 0) || (n == 0 && len == 0)) {
			/* some data has been read, or no data was requested */
			return n;
		}
		if (n < 0) {
			/* socket error - check errno */

			/* TODO: error handling depending on the error code.
			 * These codes are different between Windows and Linux.
			 */
			return -1;
		}

		/* This code is not reached in the moment.
		 * ==> Fix the TODOs above first. */

		if (timeout > 0) clock_gettime(CLOCK_MONOTONIC, &now);

	} while ((timeout <= 0) || (mg_difftimespec(&now, &start) <= timeout));

	(void)err; /* Avoid unused warning if NO_SSL is set and DEBUG_TRACE is not
	              used */

	return -1;
}


static int64_t push_all(struct mg_context *ctx, FILE *fp, SOCKET sock, SSL *ssl, const char *buf, int64_t len) {

	double timeout = -1.0;
	int64_t n;
	int64_t nwritten = 0;

	if (ctx == NULL) return -1;

	if (ctx->config[REQUEST_TIMEOUT]) timeout = atoi(ctx->config[REQUEST_TIMEOUT]) / 1000.0;

	while (len > 0 && ctx->stop_flag == 0) {
		n = push(ctx, fp, sock, ssl, buf + nwritten, (int)len, timeout);
		if (n < 0) {
			if (nwritten == 0) {
				nwritten = n; /* Propagate the error */
			}
			break;
		} else if (n == 0) {
			break; /* No more data to write */
		} else {
			nwritten += n;
			len -= n;
		}
	}

	return nwritten;

}  /* push_all */


/* Read from IO channel - opened file descriptor, socket, or SSL descriptor.
 * Return negative value on error, or number of bytes read on success. */
static int pull(FILE *fp, struct mg_connection *conn, char *buf, int len, double timeout) {

	int nread;
	int err;
	struct timespec start;
	struct timespec now;

#ifdef _WIN32
	typedef int len_t;
#else
	typedef size_t len_t;
#endif

	if (timeout > 0) {
		memset(&start, 0, sizeof(start));
		memset(&now, 0, sizeof(now));
		clock_gettime(CLOCK_MONOTONIC, &start);
	}

	do {
		if (fp != NULL) {
#if !defined(_WIN32_WCE)
			/* Use read() instead of fread(), because if we're reading from the
			 * CGI pipe, fread() may block until IO buffer is filled up. We
			 * cannot afford to block and must pass all read bytes immediately
			 * to the client. */
			nread = (int)read(fileno(fp), buf, (size_t)len);
#else
			/* WinCE does not support CGI pipes */
			nread = (int)fread(buf, 1, (size_t)len, fp);
#endif
			err = (nread < 0) ? ERRNO : 0;

#ifndef NO_SSL
		} else if (conn->ssl != NULL) {
			nread = SSL_read(conn->ssl, buf, len);
			if (nread <= 0) {
				err = SSL_get_error(conn->ssl, nread);
				if ((err == SSL_ERROR_SYSCALL) && (nread == -1)) {
					err = ERRNO;
				} else if ((err == SSL_ERROR_WANT_READ) || (err == SSL_ERROR_WANT_WRITE)) {
					nread = 0;
				} else return -1;
			} else err = 0;
#endif

		} else {
			nread = (int)recv(conn->client.sock, buf, (len_t)len, 0);
			err = (nread < 0) ? ERRNO : 0;
			if (nread == 0) {
				/* shutdown of the socket at client side */
				return -1;
			}
		}

		if (conn->ctx->stop_flag) return -1;

		if ((nread > 0) || (nread == 0 && len == 0)) {
			/* some data has been read, or no data was requested */
			return nread;
		}

		if (nread < 0) {
/* socket error - check errno */
#ifdef _WIN32
			if (err == WSAEWOULDBLOCK) {
				/* standard case if called from close_socket_gracefully */
				return -1;
			} else if (err == WSAETIMEDOUT) {
				/* timeout is handled by the while loop  */
			} else return -1;
#else
			/* TODO: POSIX returns either EAGAIN or EWOULDBLOCK in both cases,
			 * if the timeout is reached and if the socket was set to non-
			 * blocking in close_socket_gracefully, so we can not distinguish
			 * here. We have to wait for the timeout in both cases for now.
			 */
			if (err == EAGAIN || err == EWOULDBLOCK || err == EINTR) {
				/* EAGAIN/EWOULDBLOCK:
				 * standard case if called from close_socket_gracefully
				 * => should return -1 */
				/* or timeout occured
				 * => the code must stay in the while loop */

				/* EINTR can be generated on a socket with a timeout set even
				 * when SA_RESTART is effective for all relevant signals
				 * (see signal(7)).
				 * => stay in the while loop */
			} else return -1;
#endif
		}
		if (timeout > 0) clock_gettime(CLOCK_MONOTONIC, &now);
	} while ((timeout <= 0) || (mg_difftimespec(&now, &start) <= timeout));

	/* Timeout occured, but no data available. */
	return -1;
}


static int pull_all(FILE *fp, struct mg_connection *conn, char *buf, int len) {

	int n;
	int nread = 0;
	double timeout = -1.0;

	if (conn->ctx->config[REQUEST_TIMEOUT]) {
		timeout = atoi(conn->ctx->config[REQUEST_TIMEOUT]) / 1000.0;
	}

	while (len > 0 && conn->ctx->stop_flag == 0) {
		n = pull(fp, conn, buf + nread, len, timeout);
		if (n < 0) {
			if (nread == 0) {
				nread = n; /* Propagate the error */
			}
			break;
		} else if (n == 0) {
			break; /* No more data to read */
		} else {
			conn->consumed_content += n;
			nread += n;
			len -= n;
		}
	}

	return nread;
}


void XX_httplib_discard_unread_request_data( struct mg_connection *conn ) {

	char buf[MG_BUF_LEN];
	size_t to_read;
	int nread;

	if (conn == NULL) {
		return;
	}

	to_read = sizeof(buf);

	if (conn->is_chunked) {
		/* Chunked encoding: 1=chunk not read completely, 2=chunk read
		 * completely */
		while (conn->is_chunked == 1) {
			nread = mg_read(conn, buf, to_read);
			if (nread <= 0) {
				break;
			}
		}

	} else {
		/* Not chunked: content length is known */
		while (conn->consumed_content < conn->content_len) {
			if (to_read
			    > (size_t)(conn->content_len - conn->consumed_content)) {
				to_read = (size_t)(conn->content_len - conn->consumed_content);
			}

			nread = mg_read(conn, buf, to_read);
			if (nread <= 0) break;
		}
	}

}  /* XX_httplib_discard_unread_request_data */


static int mg_read_inner(struct mg_connection *conn, void *buf, size_t len) {

	int64_t n;
	int64_t buffered_len;
	int64_t nread;
	int64_t len64 = (int64_t)((len > INT_MAX) ? INT_MAX : len); /* since the return value is * int, we may not read more * bytes */
	const char *body;

	if (conn == NULL) return 0;

	/* If Content-Length is not set for a PUT or POST request, read until
	 * socket is closed */
	if (conn->consumed_content == 0 && conn->content_len == -1) {
		conn->content_len = INT64_MAX;
		conn->must_close = 1;
	}

	nread = 0;
	if (conn->consumed_content < conn->content_len) {
		/* Adjust number of bytes to read. */
		int64_t left_to_read = conn->content_len - conn->consumed_content;
		if (left_to_read < len64) {
			/* Do not read more than the total content length of the request.
			 */
			len64 = left_to_read;
		}

		/* Return buffered data */
		buffered_len = (int64_t)(conn->data_len) - (int64_t)conn->request_len
		               - conn->consumed_content;
		if (buffered_len > 0) {
			if (len64 < buffered_len) {
				buffered_len = len64;
			}
			body = conn->buf + conn->request_len + conn->consumed_content;
			memcpy(buf, body, (size_t)buffered_len);
			len64 -= buffered_len;
			conn->consumed_content += buffered_len;
			nread += buffered_len;
			buf = (char *)buf + buffered_len;
		}

		/* We have returned all buffered data. Read new data from the remote
		 * socket.
		 */
		if ((n = pull_all(NULL, conn, (char *)buf, (int)len64)) >= 0) {
			nread += n;
		} else {
			nread = ((nread > 0) ? nread : n);
		}
	}
	return (int)nread;
}


static char mg_getc(struct mg_connection *conn) {

	char c;
	if (conn == NULL) return 0;

	conn->content_len++;
	if (mg_read_inner(conn, &c, 1) <= 0) return (char)0;
	return c;
}


int mg_read(struct mg_connection *conn, void *buf, size_t len) {

	if (len > INT_MAX) len = INT_MAX;

	if (conn == NULL) return 0;

	if (conn->is_chunked) {
		size_t all_read = 0;

		while (len > 0) {

			if (conn->is_chunked == 2) {
				/* No more data left to read */
				return 0;
			}

			if (conn->chunk_remainder) {
				/* copy from the remainder of the last received chunk */
				long read_ret;
				size_t read_now =
				    ((conn->chunk_remainder > len) ? (len)
				                                   : (conn->chunk_remainder));

				conn->content_len += (int)read_now;
				read_ret =
				    mg_read_inner(conn, (char *)buf + all_read, read_now);
				all_read += (size_t)read_ret;

				conn->chunk_remainder -= read_now;
				len -= read_now;

				if (conn->chunk_remainder == 0) {
					/* the rest of the data in the current chunk has been read
					 */
					if ((mg_getc(conn) != '\r') || (mg_getc(conn) != '\n')) {
						/* Protocol violation */
						return -1;
					}
				}

			} else {
				/* fetch a new chunk */
				int i = 0;
				char lenbuf[64];
				char *end = 0;
				unsigned long chunkSize = 0;

				for (i = 0; i < ((int)sizeof(lenbuf) - 1); i++) {
					lenbuf[i] = mg_getc(conn);
					if (i > 0 && lenbuf[i] == '\r' && lenbuf[i - 1] != '\r') {
						continue;
					}
					if (i > 1 && lenbuf[i] == '\n' && lenbuf[i - 1] == '\r') {
						lenbuf[i + 1] = 0;
						chunkSize = strtoul(lenbuf, &end, 16);
						if (chunkSize == 0) {
							/* regular end of content */
							conn->is_chunked = 2;
						}
						break;
					}
					if (!isalnum(lenbuf[i])) {
						/* illegal character for chunk length */
						return -1;
					}
				}
				if ((end == NULL) || (*end != '\r')) {
					/* chunksize not set correctly */
					return -1;
				}
				if (chunkSize == 0) {
					break;
				}

				conn->chunk_remainder = chunkSize;
			}
		}

		return (int)all_read;
	}
	return mg_read_inner(conn, buf, len);
}


int mg_write(struct mg_connection *conn, const void *buf, size_t len) {

	time_t now;
	int64_t n;
	int64_t total;
	int64_t allowed;

	if (conn == NULL) return 0;

	if (conn->throttle > 0) {
		if ((now = time(NULL)) != conn->last_throttle_time) {
			conn->last_throttle_time = now;
			conn->last_throttle_bytes = 0;
		}
		allowed = conn->throttle - conn->last_throttle_bytes;
		if (allowed > (int64_t)len) allowed = (int64_t)len;
		if ((total = push_all(conn->ctx,
		                      NULL,
		                      conn->client.sock,
		                      conn->ssl,
		                      (const char *)buf,
		                      (int64_t)allowed)) == allowed) {
			buf = (const char *)buf + total;
			conn->last_throttle_bytes += total;
			while (total < (int64_t)len && conn->ctx->stop_flag == 0) {
				allowed = (conn->throttle > ((int64_t)len - total))
				              ? (int64_t)len - total
				              : conn->throttle;
				if ((n = push_all(conn->ctx,
				                  NULL,
				                  conn->client.sock,
				                  conn->ssl,
				                  (const char *)buf,
				                  (int64_t)allowed)) != allowed) {
					break;
				}
				sleep(1);
				conn->last_throttle_bytes = allowed;
				conn->last_throttle_time = time(NULL);
				buf = (const char *)buf + n;
				total += n;
			}
		}
	}
	
	else total = push_all(conn->ctx, NULL, conn->client.sock, conn->ssl, (const char *)buf, (int64_t)len);

	return (int)total;
}


/* Alternative alloc_vprintf() for non-compliant C runtimes */
static int alloc_vprintf2(char **buf, const char *fmt, va_list ap) {

	va_list ap_copy;
	size_t size = MG_BUF_LEN / 4;
	int len = -1;

	*buf = NULL;
	while (len < 0) {
		if (*buf) XX_httplib_free(*buf);

		size *= 4;
		*buf = (char *)XX_httplib_malloc(size);
		if (!*buf) break;

		va_copy(ap_copy, ap);
		len = vsnprintf_impl(*buf, size - 1, fmt, ap_copy);
		va_end(ap_copy);
		(*buf)[size - 1] = 0;
	}

	return len;
}


/* Print message to buffer. If buffer is large enough to hold the message,
 * return buffer. If buffer is to small, allocate large enough buffer on heap,
 * and return allocated buffer. */
static int alloc_vprintf(char **out_buf, char *prealloc_buf, size_t prealloc_size, const char *fmt, va_list ap) {

	va_list ap_copy;
	int len;

	/* Windows is not standard-compliant, and vsnprintf() returns -1 if
	 * buffer is too small. Also, older versions of msvcrt.dll do not have
	 * _vscprintf().  However, if size is 0, vsnprintf() behaves correctly.
	 * Therefore, we make two passes: on first pass, get required message
	 * length.
	 * On second pass, actually print the message. */
	va_copy(ap_copy, ap);
	len = vsnprintf_impl(NULL, 0, fmt, ap_copy);
	va_end(ap_copy);

	if (len < 0) {
		/* C runtime is not standard compliant, vsnprintf() returned -1.
		 * Switch to alternative code path that uses incremental allocations.
		*/
		va_copy(ap_copy, ap);
		len = alloc_vprintf2(out_buf, fmt, ap);
		va_end(ap_copy);

	} else if ((size_t)(len) >= prealloc_size) {
		/* The pre-allocated buffer not large enough. */
		/* Allocate a new buffer. */
		*out_buf = (char *)XX_httplib_malloc((size_t)(len) + 1);
		if (!*out_buf) {
			/* Allocation failed. Return -1 as "out of memory" error. */
			return -1;
		}
		/* Buffer allocation successful. Store the string there. */
		va_copy(ap_copy, ap);
		IGNORE_UNUSED_RESULT(
		    vsnprintf_impl(*out_buf, (size_t)(len) + 1, fmt, ap_copy));
		va_end(ap_copy);

	} else {
		/* The pre-allocated buffer is large enough.
		 * Use it to store the string and return the address. */
		va_copy(ap_copy, ap);
		IGNORE_UNUSED_RESULT(
		    vsnprintf_impl(prealloc_buf, prealloc_size, fmt, ap_copy));
		va_end(ap_copy);
		*out_buf = prealloc_buf;
	}

	return len;
}


int XX_httplib_vprintf( struct mg_connection *conn, const char *fmt, va_list ap ) {

	char mem[MG_BUF_LEN];
	char *buf = NULL;
	int len;

	if ((len = alloc_vprintf(&buf, mem, sizeof(mem), fmt, ap)) > 0) len = mg_write(conn, buf, (size_t)len);
	if (buf != mem && buf != NULL) XX_httplib_free(buf);

	return len;
}  /* XX_httplib_vprintf */


int mg_printf(struct mg_connection *conn, const char *fmt, ...) {

	va_list ap;
	int result;

	va_start(ap, fmt);
	result = XX_httplib_vprintf(conn, fmt, ap);
	va_end(ap);

	return result;
}


int mg_url_decode(const char *src, int src_len, char *dst, int dst_len, int is_form_url_encoded) {

	int i;
	int j;
	int a;
	int b;
#define HEXTOI(x) (isdigit(x) ? (x - '0') : (x - 'W'))

	for (i = j = 0; (i < src_len) && (j < (dst_len - 1)); i++, j++) {
		if (i < src_len - 2 && src[i] == '%'
		    && isxdigit(*(const unsigned char *)(src + i + 1))
		    && isxdigit(*(const unsigned char *)(src + i + 2))) {
			a = tolower(*(const unsigned char *)(src + i + 1));
			b = tolower(*(const unsigned char *)(src + i + 2));
			dst[j] = (char)((HEXTOI(a) << 4) | HEXTOI(b));
			i += 2;
		} else if (is_form_url_encoded && src[i] == '+') {
			dst[j] = ' ';
		} else dst[j] = src[i];
	}

	dst[j] = '\0'; /* Null-terminate the destination */

	return (i >= src_len) ? j : -1;
}


int mg_get_var(const char *data, size_t data_len, const char *name, char *dst, size_t dst_len) {

	return mg_get_var2(data, data_len, name, dst, dst_len, 0);
}


int mg_get_var2(const char *data, size_t data_len, const char *name, char *dst, size_t dst_len, size_t occurrence) {

	const char *p;
	const char *e;
	const char *s;
	size_t name_len;
	int len;

	if (dst == NULL || dst_len == 0) {
		len = -2;
	} else if (data == NULL || name == NULL || data_len == 0) {
		len = -1;
		dst[0] = '\0';
	} else {
		name_len = strlen(name);
		e = data + data_len;
		len = -1;
		dst[0] = '\0';

		/* data is "var1=val1&var2=val2...". Find variable first */
		for (p = data; p + name_len < e; p++) {
			if ((p == data || p[-1] == '&') && p[name_len] == '='
			    && !mg_strncasecmp(name, p, name_len) && 0 == occurrence--) {
				/* Point p to variable value */
				p += name_len + 1;

				/* Point s to the end of the value */
				s = (const char *)memchr(p, '&', (size_t)(e - p));
				if (s == NULL) s = e;
				/* assert(s >= p); */
				if (s < p) return -3;

				/* Decode variable into destination buffer */
				len = mg_url_decode(p, (int)(s - p), dst, (int)dst_len, 1);

				/* Redirect error code from -1 to -2 (destination buffer too
				 * small). */
				if (len == -1) len = -2;
				break;
			}
		}
	}

	return len;
}


/* HCP24: some changes to compare hole var_name */
int mg_get_cookie(const char *cookie_header, const char *var_name, char *dst, size_t dst_size) {

	const char *s;
	const char *p;
	const char *end;
	int name_len;
	int len = -1;

	if (dst == NULL || dst_size == 0) return -2;

	dst[0] = '\0';
	if (var_name == NULL || (s = cookie_header) == NULL) return -1;

	name_len = (int)strlen(var_name);
	end = s + strlen(s);
	for (; (s = mg_strcasestr(s, var_name)) != NULL; s += name_len) {
		if (s[name_len] == '=') {
			/* HCP24: now check is it a substring or a full cookie name */
			if ((s == cookie_header) || (s[-1] == ' ')) {
				s += name_len + 1;
				if ((p = strchr(s, ' ')) == NULL) {
					p = end;
				}
				if (p[-1] == ';') p--;
				if (*s == '"' && p[-1] == '"' && p > s + 1) {
					s++;
					p--;
				}
				if ((size_t)(p - s) < dst_size) {
					len = (int)(p - s);
					XX_httplib_strlcpy(dst, s, (size_t)len + 1);
				} else len = -3;
				break;
			}
		}
	}
	return len;
}


#if defined(USE_WEBSOCKET)
static void base64_encode(const unsigned char *src, int src_len, char *dst) {

	static const char *b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	int i;
	int j;
	int a;
	int b;
	int c;

	for (i = j = 0; i < src_len; i += 3) {
		a = src[i];
		b = ((i + 1) >= src_len) ? 0 : src[i + 1];
		c = ((i + 2) >= src_len) ? 0 : src[i + 2];

		dst[j++] = b64[a >> 2];
		dst[j++] = b64[((a & 3) << 4) | (b >> 4)];
		if (i + 1 < src_len) {
			dst[j++] = b64[(b & 15) << 2 | (c >> 6)];
		}
		if (i + 2 < src_len) dst[j++] = b64[c & 63];
	}
	while (j % 4 != 0) dst[j++] = '=';
	dst[j++] = '\0';
}
#endif


int XX_httplib_is_put_or_delete_method( const struct mg_connection *conn ) {

	if ( conn == NULL ) return 0;

	const char *s = conn->request_info.request_method;

	return s != NULL && (!strcmp(s, "PUT") || !strcmp(s, "DELETE") || !strcmp(s, "MKCOL") || !strcmp(s, "PATCH"));

}  /* X_httplib_is_put_or_delete_method */



/*
 * void XX_httplib_interpret_uri();
 *
 * The function XX_httplib_interpret_uri() interprets an URI and decides what
 * type of request is involved. The function takes the following parameters:
 *
 * conn:		in:  The request (must be valid)
 * filename:		out: Filename
 * filename_buf_len:	in:  Size of the filename buffer
 * filep:		out: file structure
 * is_found:		out: file is found (directly)
 * is_script_resource:	out: handled by a script?
 * is_websocket_request:	out: websocket connection?
 * is_put_or_delete_request:	out: put/delete file?
 */

void XX_httplib_interpret_uri( struct mg_connection *conn, char *filename, size_t filename_buf_len, struct file *filep, int *is_found, int *is_script_resource, int *is_websocket_request, int *is_put_or_delete_request ) {

/* TODO (high): Restructure this function */

#if !defined(NO_FILES)
	const char *uri = conn->request_info.local_uri;
	const char *root = conn->ctx->config[DOCUMENT_ROOT];
	const char *rewrite;
	struct vec a;
	struct vec b;
	int match_len;
	char gz_path[PATH_MAX];
	char const *accept_encoding;
	int truncated;
#if !defined(NO_CGI)
	char *p;
#endif
#else
	(void)filename_buf_len; /* unused if NO_FILES is defined */
#endif

	memset(filep, 0, sizeof(*filep));
	*filename = 0;
	*is_found = 0;
	*is_script_resource = 0;
	*is_put_or_delete_request = XX_httplib_is_put_or_delete_method(conn);

#if defined(USE_WEBSOCKET)
	*is_websocket_request = XX_httplib_is_websocket_protocol(conn);
#if !defined(NO_FILES)
	if (*is_websocket_request && conn->ctx->config[WEBSOCKET_ROOT]) {
		root = conn->ctx->config[WEBSOCKET_ROOT];
	}
#endif /* !NO_FILES */
#else  /* USE_WEBSOCKET */
	*is_websocket_request = 0;
#endif /* USE_WEBSOCKET */

#if !defined(NO_FILES)
	/* Note that root == NULL is a regular use case here. This occurs,
	 * if all requests are handled by callbacks, so the WEBSOCKET_ROOT
	 * config is not required. */
	if (root == NULL) {
		/* all file related outputs have already been set to 0, just return
		 */
		return;
	}

	/* Using buf_len - 1 because memmove() for PATH_INFO may shift part
	 * of the path one byte on the right.
	 * If document_root is NULL, leave the file empty. */
	XX_httplib_snprintf( conn, &truncated, filename, filename_buf_len - 1, "%s%s", root, uri);

	if (truncated) goto interpret_cleanup;

	rewrite = conn->ctx->config[REWRITE];
	while ((rewrite = XX_httplib_next_option(rewrite, &a, &b)) != NULL) {
		if ((match_len = XX_httplib_match_prefix(a.ptr, a.len, uri)) > 0) {
			XX_httplib_snprintf(conn, &truncated, filename, filename_buf_len - 1, "%.*s%s", (int)b.len, b.ptr, uri + match_len);
			break;
		}
	}

	if (truncated) goto interpret_cleanup;

	/* Local file path and name, corresponding to requested URI
	 * is now stored in "filename" variable. */
	if (XX_httplib_stat(conn, filename, filep)) {
#if !defined(NO_CGI)
		/* File exists. Check if it is a script type. */
		if (0
#if !defined(NO_CGI)
		    || XX_httplib_match_prefix(conn->ctx->config[CGI_EXTENSIONS],
		                    strlen(conn->ctx->config[CGI_EXTENSIONS]),
		                    filename) > 0
#endif
		    ) {
			/* The request addresses a CGI script or a Lua script. The URI
			 * corresponds to the script itself (like /path/script.cgi),
			 * and there is no additional resource path
			 * (like /path/script.cgi/something).
			 * Requests that modify (replace or delete) a resource, like
			 * PUT and DELETE requests, should replace/delete the script
			 * file.
			 * Requests that read or write from/to a resource, like GET and
			 * POST requests, should call the script and return the
			 * generated response. */
			*is_script_resource = !*is_put_or_delete_request;
		}
#endif /* !defined(NO_CGI) */
		*is_found = 1;
		return;
	}

	/* If we can't find the actual file, look for the file
	 * with the same name but a .gz extension. If we find it,
	 * use that and set the gzipped flag in the file struct
	 * to indicate that the response need to have the content-
	 * encoding: gzip header.
	 * We can only do this if the browser declares support. */
	if ((accept_encoding = mg_get_header(conn, "Accept-Encoding")) != NULL) {
		if (strstr(accept_encoding, "gzip") != NULL) {
			XX_httplib_snprintf( conn, &truncated, gz_path, sizeof(gz_path), "%s.gz", filename);

			if (truncated) {
				goto interpret_cleanup;
			}

			if (XX_httplib_stat(conn, gz_path, filep)) {
				if (filep) {
					filep->gzipped = 1;
					*is_found = 1;
				}
				/* Currently gz files can not be scripts. */
				return;
			}
		}
	}

#if !defined(NO_CGI)
	/* Support PATH_INFO for CGI scripts. */
	for (p = filename + strlen(filename); p > filename + 1; p--) {
		if (*p == '/') {
			*p = '\0';
			if ((0
#if !defined(NO_CGI)
			     || XX_httplib_match_prefix(conn->ctx->config[CGI_EXTENSIONS],
			                     strlen(conn->ctx->config[CGI_EXTENSIONS]),
			                     filename) > 0
#endif
			     ) && XX_httplib_stat(conn, filename, filep)) {
				/* Shift PATH_INFO block one character right, e.g.
				 * "/x.cgi/foo/bar\x00" => "/x.cgi\x00/foo/bar\x00"
				 * conn->path_info is pointing to the local variable "path"
				 * declared in XX_httplib_handle_request(), so PATH_INFO is not valid
				 * after XX_httplib_handle_request returns. */
				conn->path_info = p + 1;
				memmove(p + 2, p + 1, strlen(p + 1) + 1); /* +1 is for
				                                           * trailing \0 */
				p[1] = '/';
				*is_script_resource = 1;
				break;
			} else *p = '/';
		}
	}
#endif /* !defined(NO_CGI) */
#endif /* !defined(NO_FILES) */
	return;

#if !defined(NO_FILES)
/* Reset all outputs */
interpret_cleanup:
	memset(filep, 0, sizeof(*filep));
	*filename = 0;
	*is_found = 0;
	*is_script_resource = 0;
	*is_websocket_request = 0;
	*is_put_or_delete_request = 0;
#endif /* !defined(NO_FILES) */

}  /* XX_httplib_interpret_uri */


/* Check whether full request is buffered. Return:
 * -1  if request is malformed
 *  0  if request is not yet fully buffered
 * >0  actual request length, including last \r\n\r\n */
static int get_request_len(const char *buf, int buflen) {

	const char *s;
	const char *e;
	int len = 0;

	for (s = buf, e = s + buflen - 1; len <= 0 && s < e; s++)
		/* Control characters are not allowed but >=128 is. */
		if (!isprint(*(const unsigned char *)s) && *s != '\r' && *s != '\n'
		    && *(const unsigned char *)s < 128) {
			len = -1;
			break; /* [i_a] abort scan as soon as one malformed character is
			        * found; */
			/* don't let subsequent \r\n\r\n win us over anyhow */
		} else if (s[0] == '\n' && s[1] == '\n') {
			len = (int)(s - buf) + 2;
		} else if (s[0] == '\n' && &s[1] < e && s[1] == '\r' && s[2] == '\n') {
			len = (int)(s - buf) + 3;
		}

	return len;
}


#if !defined(NO_CACHING)
/* Convert month to the month number. Return -1 on error, or month number */
static int get_month_index(const char *s) {

	size_t i;

	for (i = 0; i < ARRAY_SIZE(month_names); i++) {
		if (!strcmp(s, month_names[i])) return (int)i;
	}

	return -1;
}


/* Parse UTC date-time string, and return the corresponding time_t value. */
static time_t parse_date_string(const char *datetime) {

	char month_str[32] = {0};
	int second;
	int minute;
	int hour;
	int day;
	int month;
	int year;
	time_t result = (time_t)0;
	struct tm tm;

	if ( ( sscanf(datetime, "%d/%3s/%d %d:%d:%d",       &day, month_str, &year, &hour, &minute, &second ) == 6 ) ||
	     ( sscanf(datetime, "%d %3s %d %d:%d:%d",       &day, month_str, &year, &hour, &minute, &second ) == 6 ) ||
	     ( sscanf(datetime, "%*3s, %d %3s %d %d:%d:%d", &day, month_str, &year, &hour, &minute, &second ) == 6 ) ||
	     ( sscanf(datetime, "%d-%3s-%d %d:%d:%d",       &day, month_str, &year, &hour, &minute, &second ) == 6 )     ) {

		month = get_month_index(month_str);
		if ((month >= 0) && (year >= 1970)) {
			memset(&tm, 0, sizeof(tm));
			tm.tm_year = year - 1900;
			tm.tm_mon = month;
			tm.tm_mday = day;
			tm.tm_hour = hour;
			tm.tm_min = minute;
			tm.tm_sec = second;
			result = timegm(&tm);
		}
	}

	return result;
}
#endif /* !NO_CACHING */


/* Protect against directory disclosure attack by removing '..',
 * excessive '/' and '\' characters */
void XX_httplib_remove_double_dots_and_double_slashes( char *s ) {

	char *p = s;

	while ((s[0] == '.') && (s[1] == '.')) s++;

	while (*s != '\0') {
		*p++ = *s++;
		if (s[-1] == '/' || s[-1] == '\\') {
			/* Skip all following slashes, backslashes and double-dots */
			while (s[0] != '\0') {
				if (s[0] == '/' || s[0] == '\\') {
					s++;
				} else if (s[0] == '.' && s[1] == '.') {
					s += 2;
				} else break;
			}
		}
	}
	*p = '\0';

}  /* XX_httplib_remove_double_dots_and_double_slashes */


static const struct {
	const char *extension;
	size_t ext_len;
	const char *mime_type;
} builtin_mime_types[] = {
    /* IANA registered MIME types (http://www.iana.org/assignments/media-types)
     * application types */
    {".doc", 4, "application/msword"},
    {".eps", 4, "application/postscript"},
    {".exe", 4, "application/octet-stream"},
    {".js", 3, "application/javascript"},
    {".json", 5, "application/json"},
    {".pdf", 4, "application/pdf"},
    {".ps", 3, "application/postscript"},
    {".rtf", 4, "application/rtf"},
    {".xhtml", 6, "application/xhtml+xml"},
    {".xsl", 4, "application/xml"},
    {".xslt", 5, "application/xml"},

    /* fonts */
    {".ttf", 4, "application/font-sfnt"},
    {".cff", 4, "application/font-sfnt"},
    {".otf", 4, "application/font-sfnt"},
    {".aat", 4, "application/font-sfnt"},
    {".sil", 4, "application/font-sfnt"},
    {".pfr", 4, "application/font-tdpfr"},
    {".woff", 5, "application/font-woff"},

    /* audio */
    {".mp3", 4, "audio/mpeg"},
    {".oga", 4, "audio/ogg"},
    {".ogg", 4, "audio/ogg"},

    /* image */
    {".gif", 4, "image/gif"},
    {".ief", 4, "image/ief"},
    {".jpeg", 5, "image/jpeg"},
    {".jpg", 4, "image/jpeg"},
    {".jpm", 4, "image/jpm"},
    {".jpx", 4, "image/jpx"},
    {".png", 4, "image/png"},
    {".svg", 4, "image/svg+xml"},
    {".tif", 4, "image/tiff"},
    {".tiff", 5, "image/tiff"},

    /* model */
    {".wrl", 4, "model/vrml"},

    /* text */
    {".css", 4, "text/css"},
    {".csv", 4, "text/csv"},
    {".htm", 4, "text/html"},
    {".html", 5, "text/html"},
    {".sgm", 4, "text/sgml"},
    {".shtm", 5, "text/html"},
    {".shtml", 6, "text/html"},
    {".txt", 4, "text/plain"},
    {".xml", 4, "text/xml"},

    /* video */
    {".mov", 4, "video/quicktime"},
    {".mp4", 4, "video/mp4"},
    {".mpeg", 5, "video/mpeg"},
    {".mpg", 4, "video/mpeg"},
    {".ogv", 4, "video/ogg"},
    {".qt", 3, "video/quicktime"},

    /* not registered types
     * (http://reference.sitepoint.com/html/mime-types-full,
     * http://www.hansenb.pdx.edu/DMKB/dict/tutorials/mime_typ.php, ..) */
    {".arj", 4, "application/x-arj-compressed"},
    {".gz", 3, "application/x-gunzip"},
    {".rar", 4, "application/x-arj-compressed"},
    {".swf", 4, "application/x-shockwave-flash"},
    {".tar", 4, "application/x-tar"},
    {".tgz", 4, "application/x-tar-gz"},
    {".torrent", 8, "application/x-bittorrent"},
    {".ppt", 4, "application/x-mspowerpoint"},
    {".xls", 4, "application/x-msexcel"},
    {".zip", 4, "application/x-zip-compressed"},
    {".aac",
     4,
     "audio/aac"}, /* http://en.wikipedia.org/wiki/Advanced_Audio_Coding */
    {".aif", 4, "audio/x-aif"},
    {".m3u", 4, "audio/x-mpegurl"},
    {".mid", 4, "audio/x-midi"},
    {".ra", 3, "audio/x-pn-realaudio"},
    {".ram", 4, "audio/x-pn-realaudio"},
    {".wav", 4, "audio/x-wav"},
    {".bmp", 4, "image/bmp"},
    {".ico", 4, "image/x-icon"},
    {".pct", 4, "image/x-pct"},
    {".pict", 5, "image/pict"},
    {".rgb", 4, "image/x-rgb"},
    {".webm", 5, "video/webm"}, /* http://en.wikipedia.org/wiki/WebM */
    {".asf", 4, "video/x-ms-asf"},
    {".avi", 4, "video/x-msvideo"},
    {".m4v", 4, "video/x-m4v"},
    {NULL, 0, NULL}};


const char * mg_get_builtin_mime_type(const char *path) {

	const char *ext;
	size_t i;
	size_t path_len;

	path_len = strlen(path);

	for (i = 0; builtin_mime_types[i].extension != NULL; i++) {
		ext = path + (path_len - builtin_mime_types[i].ext_len);
		if (path_len > builtin_mime_types[i].ext_len
		    && mg_strcasecmp(ext, builtin_mime_types[i].extension) == 0) {
			return builtin_mime_types[i].mime_type;
		}
	}

	return "text/plain";
}


/* Look at the "path" extension and figure what mime type it has.
 * Store mime type in the vector. */
static void get_mime_type(struct mg_context *ctx, const char *path, struct vec *vec) {

	struct vec ext_vec;
	struct vec mime_vec;
	const char *list;
	const char *ext;
	size_t path_len;

	path_len = strlen(path);

	if (ctx == NULL || vec == NULL) return;

	/* Scan user-defined mime types first, in case user wants to
	 * override default mime types. */
	list = ctx->config[EXTRA_MIME_TYPES];
	while ((list = XX_httplib_next_option(list, &ext_vec, &mime_vec)) != NULL) {
		/* ext now points to the path suffix */
		ext = path + path_len - ext_vec.len;
		if (mg_strncasecmp(ext, ext_vec.ptr, ext_vec.len) == 0) {
			*vec = mime_vec;
			return;
		}
	}

	vec->ptr = mg_get_builtin_mime_type(path);
	vec->len = strlen(vec->ptr);
}


/* Stringify binary data. Output buffer must be twice as big as input,
 * because each byte takes 2 bytes in string representation */
static void bin2str(char *to, const unsigned char *p, size_t len) {

	static const char *hex = "0123456789abcdef";

	for (; len--; p++) {
		*to++ = hex[p[0] >> 4];
		*to++ = hex[p[0] & 0x0f];
	}
	*to = '\0';

}  /* bin2str */


/* Return stringified MD5 hash for list of strings. Buffer must be 33 bytes. */
char * mg_md5(char buf[33], ...) {

	md5_byte_t hash[16];
	const char *p;
	va_list ap;
	md5_state_t ctx;

	md5_init(&ctx);

	va_start(ap, buf);
	while ((p = va_arg(ap, const char *)) != NULL) md5_append(&ctx, (const md5_byte_t *)p, strlen(p));
	va_end(ap);

	md5_finish(&ctx, hash);
	bin2str(buf, hash, sizeof(hash));
	return buf;
}


/* Check the user's password, return 1 if OK */
static int
check_password(const char *method,
               const char *ha1,
               const char *uri,
               const char *nonce,
               const char *nc,
               const char *cnonce,
               const char *qop,
               const char *response)
{
	char ha2[32 + 1];
	char expected_response[32 + 1];

	/* Some of the parameters may be NULL */
	if (method == NULL || nonce == NULL || nc == NULL || cnonce == NULL || qop == NULL || response == NULL) return 0;

	/* NOTE(lsm): due to a bug in MSIE, we do not compare the URI */
	if (strlen(response) != 32) return 0;

	mg_md5(ha2, method, ":", uri, NULL);
	mg_md5(expected_response, ha1, ":", nonce, ":", nc, ":", cnonce, ":", qop, ":", ha2, NULL);

	return mg_strcasecmp(response, expected_response) == 0;
}


/* Use the global passwords file, if specified by auth_gpass option,
 * or search for .htpasswd in the requested directory. */
static void open_auth_file(struct mg_connection *conn, const char *path, struct file *filep) {

	if ( conn == NULL  ||  conn->ctx == NULL ) return;

	char name[PATH_MAX];
	const char *p;
	const char *e;
	const char *gpass = conn->ctx->config[GLOBAL_PASSWORDS_FILE];
	struct file file = STRUCT_FILE_INITIALIZER;
	int truncated;

	if (gpass != NULL) {
		/* Use global passwords file */
		if (!XX_httplib_fopen(conn, gpass, "r", filep)) {
#ifdef DEBUG
			mg_cry(conn, "fopen(%s): %s", gpass, strerror(ERRNO));
#endif
		}
		/* Important: using local struct file to test path for is_directory
		 * flag. If filep is used, XX_httplib_stat() makes it appear as if auth file
		 * was opened. */
	} else if (XX_httplib_stat(conn, path, &file) && file.is_directory) {
		XX_httplib_snprintf(conn, &truncated, name, sizeof(name), "%s/%s", path, PASSWORDS_FILE_NAME);

		if (truncated || !XX_httplib_fopen(conn, name, "r", filep)) {
#ifdef DEBUG
			mg_cry(conn, "fopen(%s): %s", name, strerror(ERRNO));
#endif
		}
	} else {
		/* Try to find .htpasswd in requested directory. */
		for (p = path, e = p + strlen(p) - 1; e > p; e--) {
			if (e[0] == '/') break;
		}
		XX_httplib_snprintf(conn, &truncated, name, sizeof(name), "%.*s/%s", (int)(e - p), p, PASSWORDS_FILE_NAME);

		if (truncated || !XX_httplib_fopen(conn, name, "r", filep)) {
#ifdef DEBUG
			mg_cry(conn, "fopen(%s): %s", name, strerror(ERRNO));
#endif
		}
	}
}


/* Parsed Authorization header */
struct ah {
	char *user;
	char *uri;
	char *cnonce;
	char *response;
	char *qop;
	char *nc;
	char *nonce;
};


/* Return 1 on success. Always initializes the ah structure. */
static int parse_auth_header(struct mg_connection *conn, char *buf, size_t buf_size, struct ah *ah) {

	char *name;
	char *value;
	char *s;
	const char *auth_header;
	uint64_t nonce;

	if (!ah || !conn) return 0;

	memset(ah, 0, sizeof(*ah));
	if ((auth_header = mg_get_header(conn, "Authorization")) == NULL || mg_strncasecmp(auth_header, "Digest ", 7) != 0) return 0;

	/* Make modifiable copy of the auth header */
	XX_httplib_strlcpy(buf, auth_header + 7, buf_size);
	s = buf;

	/* Parse authorization header */
	for (;;) {
		/* Gobble initial spaces */
		while (isspace(*(unsigned char *)s)) {
			s++;
		}
		name = skip_quoted(&s, "=", " ", 0);
		/* Value is either quote-delimited, or ends at first comma or space. */
		if (s[0] == '\"') {
			s++;
			value = skip_quoted(&s, "\"", " ", '\\');
			if (s[0] == ',') {
				s++;
			}
		} else {
			value = skip_quoted(&s, ", ", " ", 0); /* IE uses commas, FF uses
			                                        * spaces */
		}
		if (*name == '\0') break;

		if      ( ! strcmp( name, "username" ) ) ah->user     = value;
		else if ( ! strcmp( name, "cnonce"   ) ) ah->cnonce   = value;
		else if ( ! strcmp( name, "response" ) ) ah->response = value;
		else if ( ! strcmp( name, "uri"      ) ) ah->uri      = value;
		else if ( ! strcmp( name, "qop"      ) ) ah->qop      = value;
		else if ( ! strcmp( name, "nc"       ) ) ah->nc       = value;
		else if ( ! strcmp( name, "nonce"    ) ) ah->nonce    = value;
	}

#ifndef NO_NONCE_CHECK
	/* Read the nonce from the response. */
	if (ah->nonce == NULL) return 0;
	s = NULL;
	nonce = strtoull(ah->nonce, &s, 10);
	if ((s == NULL) || (*s != 0)) {
		return 0;
	}

	/* Convert the nonce from the client to a number. */
	nonce ^= conn->ctx->auth_nonce_mask;

	/* The converted number corresponds to the time the nounce has been
	 * created. This should not be earlier than the server start. */
	/* Server side nonce check is valuable in all situations but one:
	 * if the server restarts frequently, but the client should not see
	 * that, so the server should accept nonces from previous starts. */
	/* However, the reasonable default is to not accept a nonce from a
	 * previous start, so if anyone changed the access rights between
	 * two restarts, a new login is required. */
	if (nonce < (uint64_t)conn->ctx->start_time) {
		/* nonce is from a previous start of the server and no longer valid
		 * (replay attack?) */
		return 0;
	}
	/* Check if the nonce is too high, so it has not (yet) been used by the
	 * server. */
	if (nonce >= ((uint64_t)conn->ctx->start_time + conn->ctx->nonce_count)) {
		return 0;
	}
#else
	(void)nonce;
#endif

	/* CGI needs it as REMOTE_USER */
	if (ah->user != NULL) {
		conn->request_info.remote_user = XX_httplib_strdup(ah->user);
	} else return 0;

	return 1;
}


static const char * mg_fgets(char *buf, size_t size, struct file *filep, char **p) {

	const char *eof;
	size_t len;
	const char *memend;

	if (!filep) return NULL;

	if (filep->membuf != NULL && *p != NULL) {
		memend = (const char *)&filep->membuf[filep->size];
		/* Search for \n from p till the end of stream */
		eof = (char *)memchr(*p, '\n', (size_t)(memend - *p));
		if (eof != NULL) {
			eof += 1; /* Include \n */
		} else {
			eof = memend; /* Copy remaining data */
		}
		len = ((size_t)(eof - *p) > (size - 1)) ? (size - 1) : (size_t)(eof - *p);
		memcpy(buf, *p, len);
		buf[len] = '\0';
		*p += len;
		return len ? eof : NULL;
	} else if (filep->fp != NULL) {
		return fgets(buf, (int)size, filep->fp);
	} else return NULL;
}

struct read_auth_file_struct {
	struct mg_connection *conn;
	struct ah ah;
	char *domain;
	char buf[256 + 256 + 40];
	char *f_user;
	char *f_domain;
	char *f_ha1;
};


static int read_auth_file(struct file *filep, struct read_auth_file_struct *workdata) {

	char *p;
	int is_authorized = 0;
	struct file fp;
	size_t l;

	if (!filep || !workdata) return 0;

	/* Loop over passwords file */
	p = (char *)filep->membuf;
	while (mg_fgets(workdata->buf, sizeof(workdata->buf), filep, &p) != NULL) {
		l = strlen(workdata->buf);
		while (l > 0) {
			if (isspace(workdata->buf[l - 1])
			    || iscntrl(workdata->buf[l - 1])) {
				l--;
				workdata->buf[l] = 0;
			} else break;
		}
		if (l < 1) continue;

		workdata->f_user = workdata->buf;

		if (workdata->f_user[0] == ':') {
			/* user names may not contain a ':' and may not be empty,
			 * so lines starting with ':' may be used for a special purpose */
			if (workdata->f_user[1] == '#') {
				/* :# is a comment */
				continue;
			} else if (!strncmp(workdata->f_user + 1, "include=", 8)) {
				if (XX_httplib_fopen(workdata->conn, workdata->f_user + 9, "r", &fp)) {
					is_authorized = read_auth_file(&fp, workdata);
					XX_httplib_fclose(&fp);
				} else {
					mg_cry(workdata->conn, "%s: cannot open authorization file: %s", __func__, workdata->buf);
				}
				continue;
			}
			/* everything is invalid for the moment (might change in the
			 * future) */
			mg_cry(workdata->conn, "%s: syntax error in authorization file: %s", __func__, workdata->buf);
			continue;
		}

		workdata->f_domain = strchr(workdata->f_user, ':');
		if (workdata->f_domain == NULL) {
			mg_cry(workdata->conn, "%s: syntax error in authorization file: %s", __func__, workdata->buf);
			continue;
		}
		*(workdata->f_domain) = 0;
		(workdata->f_domain)++;

		workdata->f_ha1 = strchr(workdata->f_domain, ':');
		if (workdata->f_ha1 == NULL) {
			mg_cry(workdata->conn, "%s: syntax error in authorization file: %s", __func__, workdata->buf);
			continue;
		}
		*(workdata->f_ha1) = 0;
		(workdata->f_ha1)++;

		if (!strcmp(workdata->ah.user, workdata->f_user)
		    && !strcmp(workdata->domain, workdata->f_domain)) {
			return check_password(workdata->conn->request_info.request_method,
			                      workdata->f_ha1,
			                      workdata->ah.uri,
			                      workdata->ah.nonce,
			                      workdata->ah.nc,
			                      workdata->ah.cnonce,
			                      workdata->ah.qop,
			                      workdata->ah.response);
		}
	}

	return is_authorized;
}


/* Authorize against the opened passwords file. Return 1 if authorized. */
static int authorize(struct mg_connection *conn, struct file *filep) {

	struct read_auth_file_struct workdata;
	char buf[MG_BUF_LEN];

	if (!conn || !conn->ctx) return 0;

	memset(&workdata, 0, sizeof(workdata));
	workdata.conn = conn;

	if (!parse_auth_header(conn, buf, sizeof(buf), &workdata.ah)) { return 0; }
	workdata.domain = conn->ctx->config[AUTHENTICATION_DOMAIN];

	return read_auth_file(filep, &workdata);
}


/* Return 1 if request is authorised, 0 otherwise. */
int XX_httplib_check_authorization( struct mg_connection *conn, const char *path ) {

	char fname[PATH_MAX];
	struct vec uri_vec;
	struct vec filename_vec;
	const char *list;
	struct file file = STRUCT_FILE_INITIALIZER;
	int authorized = 1;
	int truncated;

	if (!conn || !conn->ctx) return 0;

	list = conn->ctx->config[PROTECT_URI];
	while ((list = XX_httplib_next_option(list, &uri_vec, &filename_vec)) != NULL) {
		if (!memcmp(conn->request_info.local_uri, uri_vec.ptr, uri_vec.len)) {
			XX_httplib_snprintf(conn, &truncated, fname, sizeof(fname), "%.*s", (int)filename_vec.len, filename_vec.ptr);

			if (truncated || !XX_httplib_fopen(conn, fname, "r", &file)) {
				mg_cry(conn, "%s: cannot open %s: %s", __func__, fname, strerror(errno));
			}
			break;
		}
	}

	if (!is_file_opened(&file)) open_auth_file(conn, path, &file);

	if (is_file_opened(&file)) {
		authorized = authorize(conn, &file);
		XX_httplib_fclose(&file);
	}

	return authorized;

}  /* XX_httplib_check_authorization */


void XX_httplib_send_authorization_request( struct mg_connection *conn ) {

	char date[64];
	time_t curtime;

	if ( conn == NULL  ||  conn->ctx == NULL ) return;

	curtime = time( NULL );

	uint64_t nonce = (uint64_t)(conn->ctx->start_time);

	(void)pthread_mutex_lock(&conn->ctx->nonce_mutex);
	nonce += conn->ctx->nonce_count;
	++conn->ctx->nonce_count;
	(void)pthread_mutex_unlock(&conn->ctx->nonce_mutex);

	nonce ^= conn->ctx->auth_nonce_mask;
	conn->status_code = 401;
	conn->must_close = 1;

	XX_httplib_gmt_time_string(date, sizeof(date), &curtime);

	mg_printf(conn, "HTTP/1.1 401 Unauthorized\r\n");
	send_no_cache_header(conn);
	mg_printf(conn,
	          "Date: %s\r\n"
	          "Connection: %s\r\n"
	          "Content-Length: 0\r\n"
	          "WWW-Authenticate: Digest qop=\"auth\", realm=\"%s\", "
	          "nonce=\"%" UINT64_FMT "\"\r\n\r\n",
	          date,
	          XX_httplib_suggest_connection_header(conn),
	          conn->ctx->config[AUTHENTICATION_DOMAIN],
	          nonce);

}  /* XX_httplib_send_authorization_request */


#if !defined(NO_FILES)
int XX_httplib_is_authorized_for_put( struct mg_connection *conn ) {

	if ( conn == NULL ) return 0;

	struct file file = STRUCT_FILE_INITIALIZER;
	const char *passfile = conn->ctx->config[PUT_DELETE_PASSWORDS_FILE];
	int ret = 0;

	if (passfile != NULL && XX_httplib_fopen(conn, passfile, "r", &file)) {
		ret = authorize(conn, &file);
		XX_httplib_fclose(&file);
	}

	return ret;

}  /* XX_httplib_is_authorized_for_put */
#endif


int mg_modify_passwords_file(const char *fname, const char *domain, const char *user, const char *pass) {

	int found, i;
	char line[512];
	char u[512] = "";
	char d[512] = "";
	char ha1[33];
	char tmp[PATH_MAX + 8];
	FILE *fp;
	FILE *fp2;

	found = 0;
	fp = fp2 = NULL;

	/* Regard empty password as no password - remove user record. */
	if (pass != NULL && pass[0] == '\0') pass = NULL;

	/* Other arguments must not be empty */
	if (fname == NULL || domain == NULL || user == NULL) return 0;

	/* Using the given file format, user name and domain must not contain ':'
	 */
	if ( strchr( user,   ':' ) != NULL ) return 0;
	if ( strchr( domain, ':' ) != NULL ) return 0;

	/* Do not allow control characters like newline in user name and domain.
	 * Do not allow excessively long names either. */
	for (i = 0; i < 255 && user[i] != 0; i++) {
		if (iscntrl(user[i])) return 0;
	}
	if (user[i]) { return 0; }
	for (i = 0; i < 255 && domain[i] != 0; i++) {
		if (iscntrl(domain[i])) return 0;
	}
	if (domain[i]) return 0;

	/* The maximum length of the path to the password file is limited */
	if ((strlen(fname) + 4) >= PATH_MAX) return 0;

	/* Create a temporary file name. Length has been checked before. */
	strcpy(tmp, fname);
	strcat(tmp, ".tmp");

	/* Create the file if does not exist */
	/* Use of fopen here is OK, since fname is only ASCII */
	if ((fp = fopen(fname, "a+")) != NULL) { (void)fclose(fp); }

	/* Open the given file and temporary file */
	if ((fp = fopen(fname, "r")) == NULL) {
		return 0;
	} else if ((fp2 = fopen(tmp, "w+")) == NULL) {
		fclose(fp);
		return 0;
	}

	/* Copy the stuff to temporary file */
	while (fgets(line, sizeof(line), fp) != NULL) {
		if (sscanf(line, "%255[^:]:%255[^:]:%*s", u, d) != 2) {
			continue;
		}
		u[255] = 0;
		d[255] = 0;

		if (!strcmp(u, user) && !strcmp(d, domain)) {
			found++;
			if (pass != NULL) {
				mg_md5(ha1, user, ":", domain, ":", pass, NULL);
				fprintf(fp2, "%s:%s:%s\n", user, domain, ha1);
			}
		} else {
			fprintf(fp2, "%s", line);
		}
	}

	/* If new user, just add it */
	if (!found && pass != NULL) {
		mg_md5(ha1, user, ":", domain, ":", pass, NULL);
		fprintf(fp2, "%s:%s:%s\n", user, domain, ha1);
	}

	/* Close files */
	fclose(fp);
	fclose(fp2);

	/* Put the temp file in place of real file */
	IGNORE_UNUSED_RESULT(remove(fname));
	IGNORE_UNUSED_RESULT(rename(tmp, fname));

	return 1;
}


int XX_httplib_is_valid_port(unsigned long port) {

	return (port < 0xffff);

}  /* XX_httplib_is_valid_port */


static int mg_inet_pton(int af, const char *src, void *dst, size_t dstlen) {

	struct addrinfo hints, *res, *ressave;
	int func_ret = 0;
	int gai_ret;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = af;

	gai_ret = getaddrinfo(src, NULL, &hints, &res);
	if (gai_ret != 0) {
		/* gai_strerror could be used to convert gai_ret to a string */
		/* POSIX return values: see
		 * http://pubs.opengroup.org/onlinepubs/9699919799/functions/freeaddrinfo.html
		 */
		/* Windows return values: see
		 * https://msdn.microsoft.com/en-us/library/windows/desktop/ms738520%28v=vs.85%29.aspx
		 */
		return 0;
	}

	ressave = res;

	while (res) {
		if (dstlen >= res->ai_addrlen) {
			memcpy(dst, res->ai_addr, res->ai_addrlen);
			func_ret = 1;
		}
		res = res->ai_next;
	}

	freeaddrinfo(ressave);
	return func_ret;
}



/*
 * int XX_httplib_connect_socket();
 *
 * The function XX_httplib_connect_socket() starts a connection over a socket.
 * The context structure may be NULL. The output socket and the socket address
 * may not be null for this function to succeed.
 */

int XX_httplib_connect_socket( struct mg_context *ctx, const char *host, int port, int use_ssl, char *ebuf, size_t ebuf_len, SOCKET *sock, union usa *sa ) {

	int ip_ver = 0;

	*sock = INVALID_SOCKET;
	memset(sa, 0, sizeof(*sa));

	if (ebuf_len > 0) *ebuf = 0;

	if (host == NULL) {
		XX_httplib_snprintf(NULL, NULL, ebuf, ebuf_len, "%s", "NULL host");
		return 0;
	}

	if (port < 0 || !XX_httplib_is_valid_port((unsigned)port)) {
		XX_httplib_snprintf(NULL, NULL, ebuf, ebuf_len, "%s", "invalid port");
		return 0;
	}

#if !defined(NO_SSL)
	if (use_ssl && (SSLv23_client_method == NULL)) {
		XX_httplib_snprintf(NULL, NULL, ebuf, ebuf_len, "%s", "SSL is not initialized");
		return 0;
	}
#else
	(void)use_ssl;
#endif

	if (mg_inet_pton(AF_INET, host, &sa->sin, sizeof(sa->sin))) {
		sa->sin.sin_port = htons((uint16_t)port);
		ip_ver = 4;
#ifdef USE_IPV6
	} else if (mg_inet_pton(AF_INET6, host, &sa->sin6, sizeof(sa->sin6))) {
		sa->sin6.sin6_port = htons((uint16_t)port);
		ip_ver = 6;
	} else if (host[0] == '[') {
		/* While getaddrinfo on Windows will work with [::1],
		 * getaddrinfo on Linux only works with ::1 (without []). */
		size_t l = strlen(host + 1);
		char *h = (l > 1) ? XX_httplib_strdup(host + 1) : NULL;
		if (h) {
			h[l - 1] = 0;
			if (mg_inet_pton(AF_INET6, h, &sa->sin6, sizeof(sa->sin6))) {
				sa->sin6.sin6_port = htons((uint16_t)port);
				ip_ver = 6;
			}
			XX_httplib_free(h);
		}
#endif
	}

	if (ip_ver == 0) {
		XX_httplib_snprintf(NULL, NULL, ebuf, ebuf_len, "%s", "host not found");
		return 0;
	}

	if (ip_ver == 4) { *sock = socket(PF_INET, SOCK_STREAM, 0); }
#ifdef USE_IPV6
	else if (ip_ver == 6) { *sock = socket(PF_INET6, SOCK_STREAM, 0); }
#endif

	if (*sock == INVALID_SOCKET) {
		XX_httplib_snprintf(NULL, NULL, ebuf, ebuf_len, "socket(): %s", strerror(ERRNO));
		return 0;
	}

	XX_httplib_set_close_on_exec(*sock, XX_httplib_fc(ctx));

	if ((ip_ver == 4) && (connect(*sock, (struct sockaddr *)&sa->sin, sizeof(sa->sin)) == 0)) {
		/* connected with IPv4 */
		return 1;
	}

#ifdef USE_IPV6
	if ((ip_ver == 6) && (connect(*sock, (struct sockaddr *)&sa->sin6, sizeof(sa->sin6)) == 0)) {
		/* connected with IPv6 */
		return 1;
	}
#endif

	/* Not connected */
	XX_httplib_snprintf(NULL, NULL, ebuf, ebuf_len, "connect(%s:%d): %s", host, port, strerror(ERRNO));
	closesocket(*sock);
	*sock = INVALID_SOCKET;
	return 0;

}  /* XX_httplib_connect_socket */


int mg_url_encode(const char *src, char *dst, size_t dst_len) {

	static const char *dont_escape = "._-$,;~()";
	static const char *hex = "0123456789abcdef";
	char *pos = dst;
	const char *end = dst + dst_len - 1;

	for (; *src != '\0' && pos < end; src++, pos++) {
		if (isalnum(*(const unsigned char *)src)
		    || strchr(dont_escape, *(const unsigned char *)src) != NULL) {
			*pos = *src;
		} else if (pos + 2 < end) {
			pos[0] = '%';
			pos[1] = hex[(*(const unsigned char *)src) >> 4];
			pos[2] = hex[(*(const unsigned char *)src) & 0xf];
			pos += 2;
		} else break;
	}

	*pos = '\0';
	return (*src == '\0') ? (int)(pos - dst) : -1;
}


static void print_dir_entry(struct de *de) {

	char size[64];
	char mod[64];
	char href[PATH_MAX * 3 /* worst case */];
	struct tm *tm;

	if ( de->file.is_directory ) XX_httplib_snprintf( de->conn, NULL, size, sizeof(size), "%s", "[DIRECTORY]" );
	else {
		/* We use (signed) cast below because MSVC 6 compiler cannot
		 * convert unsigned __int64 to double. Sigh. */
		if      ( de->file.size <       1024)  XX_httplib_snprintf( de->conn, NULL, size, sizeof(size), "%d",     (int)   de->file.size                 );
		else if ( de->file.size <   0x100000 ) XX_httplib_snprintf( de->conn, NULL, size, sizeof(size), "%.1fk", ((double)de->file.size) / 1024.0       );
		else if ( de->file.size < 0x40000000 ) XX_httplib_snprintf( de->conn, NULL, size, sizeof(size), "%.1fM", ((double)de->file.size) / 1048576.0    );
		else                                   XX_httplib_snprintf( de->conn, NULL, size, sizeof(size), "%.1fG", ((double)de->file.size) / 1073741824.0 );
	}

	/* Note: XX_httplib_snprintf will not cause a buffer overflow above.
	 * So, string truncation checks are not required here. */

	tm = localtime(&de->file.last_modified);
	if (tm != NULL) {
		strftime(mod, sizeof(mod), "%d-%b-%Y %H:%M", tm);
	} else {
		XX_httplib_strlcpy(mod, "01-Jan-1970 00:00", sizeof(mod));
		mod[sizeof(mod) - 1] = '\0';
	}
	mg_url_encode(de->file_name, href, sizeof(href));
	de->conn->num_bytes_sent +=
	    mg_printf(de->conn,
	              "<tr><td><a href=\"%s%s%s\">%s%s</a></td>"
	              "<td>&nbsp;%s</td><td>&nbsp;&nbsp;%s</td></tr>\n",
	              de->conn->request_info.local_uri,
	              href,
	              de->file.is_directory ? "/" : "",
	              de->file_name,
	              de->file.is_directory ? "/" : "",
	              mod,
	              size);
}


/* This function is called from send_directory() and used for
 * sorting directory entries by size, or name, or modification time.
 * On windows, __cdecl specification is needed in case if project is built
 * with __stdcall convention. qsort always requires __cdels callback. */
static int WINCDECL compare_dir_entries( const void *p1, const void *p2 ) {

	if ( p1 == NULL  ||  p2 == NULL ) return 0;

	int cmp_result;
	const struct de *a = (const struct de *)p1;
	const struct de *b = (const struct de *)p2;
	const char *query_string = a->conn->request_info.query_string;

	if ( query_string == NULL ) query_string = "na";

	if (   a->file.is_directory  &&  ! b->file.is_directory ) return -1; 
	if ( ! a->file.is_directory  &&    b->file.is_directory ) return 1;

	cmp_result = 0;
	if      (query_string[0] == 'n') cmp_result = strcmp( a->file_name, b->file_name );
	else if (query_string[0] == 's') cmp_result = (a->file.size == b->file.size) ? 0 : ((a->file.size > b->file.size) ? 1 : -1);
	else if (query_string[0] == 'd') cmp_result = (a->file.last_modified == b->file.last_modified) ? 0 : ((a->file.last_modified > b->file.last_modified) ? 1 : -1);

	return (query_string[1] == 'd') ? -cmp_result : cmp_result;

}  /* compare_dir_entries */


int XX_httplib_must_hide_file( struct mg_connection *conn, const char *path ) {

	if (conn && conn->ctx) {
		const char *pw_pattern = "**" PASSWORDS_FILE_NAME "$";
		const char *pattern = conn->ctx->config[HIDE_FILES];
		return XX_httplib_match_prefix(pw_pattern, strlen(pw_pattern), path) > 0
		       || (pattern != NULL
		           && XX_httplib_match_prefix(pattern, strlen(pattern), path) > 0);
	}
	return 0;

}  /* XX_httplib_must_hide_file */



static int scan_directory(struct mg_connection *conn, const char *dir, void *data, void (*cb)(struct de *, void *)) {

	char path[PATH_MAX];
	struct dirent *dp;
	DIR *dirp;
	struct de de;
	int truncated;

	if ((dirp = mg_opendir(conn, dir)) == NULL) {
		return 0;
	} else {
		de.conn = conn;

		while ((dp = mg_readdir(dirp)) != NULL) {
			/* Do not show current dir and hidden files */
			if (!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, "..") || XX_httplib_must_hide_file(conn, dp->d_name)) continue;

			XX_httplib_snprintf( conn, &truncated, path, sizeof(path), "%s/%s", dir, dp->d_name);

			/* If we don't memset stat structure to zero, mtime will have
			 * garbage and strftime() will segfault later on in
			 * print_dir_entry(). memset is required only if XX_httplib_stat()
			 * fails. For more details, see
			 * http://code.google.com/p/mongoose/issues/detail?id=79 */
			memset(&de.file, 0, sizeof(de.file));

			if (truncated) {
				/* If the path is not complete, skip processing. */
				continue;
			}

			if (!XX_httplib_stat(conn, path, &de.file)) {
				mg_cry(conn, "%s: XX_httplib_stat(%s) failed: %s", __func__, path, strerror(ERRNO));
			}
			de.file_name = dp->d_name;
			cb(&de, data);
		}
		(void)mg_closedir(dirp);
	}
	return 1;
}


#if !defined(NO_FILES)
static int remove_directory(struct mg_connection *conn, const char *dir) {

	char path[PATH_MAX];
	struct dirent *dp;
	DIR *dirp;
	struct de de;
	int truncated;
	int ok = 1;

	if ((dirp = mg_opendir(conn, dir)) == NULL) {
		return 0;
	} else {
		de.conn = conn;

		while ((dp = mg_readdir(dirp)) != NULL) {
			/* Do not show current dir (but show hidden files as they will
			 * also be removed) */
			if (!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, "..")) continue;

			XX_httplib_snprintf( conn, &truncated, path, sizeof(path), "%s/%s", dir, dp->d_name);

			/* If we don't memset stat structure to zero, mtime will have
			 * garbage and strftime() will segfault later on in
			 * print_dir_entry(). memset is required only if XX_httplib_stat()
			 * fails. For more details, see
			 * http://code.google.com/p/mongoose/issues/detail?id=79 */
			memset(&de.file, 0, sizeof(de.file));

			if (truncated) {
				/* Do not delete anything shorter */
				ok = 0;
				continue;
			}

			if (!XX_httplib_stat(conn, path, &de.file)) {
				mg_cry(conn, "%s: XX_httplib_stat(%s) failed: %s", __func__, path, strerror(ERRNO));
				ok = 0;
			}
			if (de.file.membuf == NULL) {
				/* file is not in memory */
				if (de.file.is_directory) {
					if (remove_directory(conn, path) == 0) ok = 0;
				} else {
					if (mg_remove(conn, path) == 0) ok = 0;
				}
			} else {
				/* file is in memory. It can not be deleted. */
				ok = 0;
			}
		}
		mg_closedir(dirp);

		IGNORE_UNUSED_RESULT(rmdir(dir));
	}

	return ok;
}
#endif


struct dir_scan_data {
	struct de *entries;
	unsigned int num_entries;
	unsigned int arr_size;
};


/* Behaves like realloc(), but frees original pointer on failure */
static void * realloc2(void *ptr, size_t size) {

	void *new_ptr = XX_httplib_realloc(ptr, size);
	if (new_ptr == NULL) XX_httplib_free(ptr);

	return new_ptr;
}


static void dir_scan_callback(struct de *de, void *data) {

	struct dir_scan_data *dsd = (struct dir_scan_data *)data;

	if (dsd->entries == NULL || dsd->num_entries >= dsd->arr_size) {
		dsd->arr_size *= 2;
		dsd->entries = (struct de *)realloc2(dsd->entries, dsd->arr_size * sizeof(dsd->entries[0]));
	}
	if (dsd->entries == NULL) {
		/* TODO(lsm, low): propagate an error to the caller */
		dsd->num_entries = 0;
	} else {
		dsd->entries[dsd->num_entries].file_name = XX_httplib_strdup(de->file_name);
		dsd->entries[dsd->num_entries].file = de->file;
		dsd->entries[dsd->num_entries].conn = de->conn;
		dsd->num_entries++;
	}
}


void XX_httplib_handle_directory_request( struct mg_connection *conn, const char *dir ) {

	unsigned int i;
	int sort_direction;
	struct dir_scan_data data = {NULL, 0, 128};
	char date[64];
	time_t curtime = time(NULL);

	if (!scan_directory(conn, dir, &data, dir_scan_callback)) {
		XX_httplib_send_http_error(conn, 500, "Error: Cannot open directory\nopendir(%s): %s", dir, strerror(ERRNO));
		return;
	}

	XX_httplib_gmt_time_string(date, sizeof(date), &curtime);

	if (!conn) return;

	sort_direction = ((conn->request_info.query_string != NULL) && (conn->request_info.query_string[1] == 'd')) ? 'a' : 'd';

	conn->must_close = 1;
	mg_printf(conn, "HTTP/1.1 200 OK\r\n");
	send_static_cache_header(conn);
	mg_printf(conn, "Date: %s\r\n" "Connection: close\r\n" "Content-Type: text/html; charset=utf-8\r\n\r\n", date);

	conn->num_bytes_sent +=
	    mg_printf(conn,
	              "<html><head><title>Index of %s</title>"
	              "<style>th {text-align: left;}</style></head>"
	              "<body><h1>Index of %s</h1><pre><table cellpadding=\"0\">"
	              "<tr><th><a href=\"?n%c\">Name</a></th>"
	              "<th><a href=\"?d%c\">Modified</a></th>"
	              "<th><a href=\"?s%c\">Size</a></th></tr>"
	              "<tr><td colspan=\"3\"><hr></td></tr>",
	              conn->request_info.local_uri,
	              conn->request_info.local_uri,
	              sort_direction,
	              sort_direction,
	              sort_direction);

	/* Print first entry - link to a parent directory */
	conn->num_bytes_sent +=
	    mg_printf(conn,
	              "<tr><td><a href=\"%s%s\">%s</a></td>"
	              "<td>&nbsp;%s</td><td>&nbsp;&nbsp;%s</td></tr>\n",
	              conn->request_info.local_uri,
	              "..",
	              "Parent directory",
	              "-",
	              "-");

	/* Sort and print directory entries */
	if (data.entries != NULL) {
		qsort(data.entries,
		      (size_t)data.num_entries,
		      sizeof(data.entries[0]),
		      compare_dir_entries);
		for (i = 0; i < data.num_entries; i++) {
			print_dir_entry(&data.entries[i]);
			XX_httplib_free(data.entries[i].file_name);
		}
		XX_httplib_free(data.entries);
	}

	conn->num_bytes_sent += mg_printf(conn, "%s", "</table></body></html>");
	conn->status_code = 200;

}  /* XX_httplib_handle_directory_request */


/* Send len bytes from the opened file to the client. */
static void send_file_data(struct mg_connection *conn, struct file *filep, int64_t offset, int64_t len) {

	char buf[MG_BUF_LEN];
	int to_read;
	int num_read;
	int num_written;
	int64_t size;

	if (!filep || !conn) return;

	/* Sanity check the offset */
	size = (filep->size > INT64_MAX) ? INT64_MAX : (int64_t)(filep->size);
	offset = (offset < 0) ? 0 : ((offset > size) ? size : offset);

	if (len > 0 && filep->membuf != NULL && size > 0) {
		/* file stored in memory */
		if (len > size - offset) {
			len = size - offset;
		}
		mg_write(conn, filep->membuf + offset, (size_t)len);
	} else if (len > 0 && filep->fp != NULL) {
/* file stored on disk */
#if defined(__linux__)
		/* sendfile is only available for Linux */
		if ((conn->ssl == 0) && (conn->throttle == 0)
		    && (!mg_strcasecmp(conn->ctx->config[ALLOW_SENDFILE_CALL],
		                       "yes"))) {
			off_t sf_offs = (off_t)offset;
			ssize_t sf_sent;
			int sf_file = fileno(filep->fp);
			int loop_cnt = 0;

			do {
				/* 2147479552 (0x7FFFF000) is a limit found by experiment on
				 * 64 bit Linux (2^31 minus one memory page of 4k?). */
				size_t sf_tosend =
				    (size_t)((len < 0x7FFFF000) ? len : 0x7FFFF000);
				sf_sent =
				    sendfile(conn->client.sock, sf_file, &sf_offs, sf_tosend);
				if (sf_sent > 0) {
					conn->num_bytes_sent += sf_sent;
					len -= sf_sent;
					offset += sf_sent;
				} else if (loop_cnt == 0) {
					/* This file can not be sent using sendfile.
					 * This might be the case for pseudo-files in the
					 * /sys/ and /proc/ file system.
					 * Use the regular user mode copy code instead. */
					break;
				} else if (sf_sent == 0) {
					/* No error, but 0 bytes sent. May be EOF? */
					return;
				}
				loop_cnt++;

			} while ((len > 0) && (sf_sent >= 0));

			if (sf_sent > 0) {
				return; /* OK */
			}

			/* sf_sent<0 means error, thus fall back to the classic way */
			/* This is always the case, if sf_file is not a "normal" file,
			 * e.g., for sending data from the output of a CGI process. */
			offset = (int64_t)sf_offs;
		}
#endif
		if ((offset > 0) && (fseeko(filep->fp, offset, SEEK_SET) != 0)) {
			mg_cry(conn, "%s: fseeko() failed: %s", __func__, strerror(ERRNO));
			XX_httplib_send_http_error( conn, 500, "%s", "Error: Unable to access file at requested position.");
		} else {
			while (len > 0) {
				/* Calculate how much to read from the file in the buffer */
				to_read = sizeof(buf);
				if ((int64_t)to_read > len) {
					to_read = (int)len;
				}

				/* Read from file, exit the loop on error */
				if ((num_read = (int)fread(buf, 1, (size_t)to_read, filep->fp)) <= 0) break;

				/* Send read bytes to the client, exit the loop on error */
				if ((num_written = mg_write(conn, buf, (size_t)num_read)) != num_read) break;

				/* Both read and were successful, adjust counters */
				conn->num_bytes_sent += num_written;
				len -= num_written;
			}
		}
	}
}


static int parse_range_header(const char *header, int64_t *a, int64_t *b) {

	return sscanf(header, "bytes=%" INT64_FMT "-%" INT64_FMT, a, b);
}


static void construct_etag(char *buf, size_t buf_len, const struct file *filep) {

	if (filep != NULL && buf != NULL) {
		XX_httplib_snprintf(NULL, NULL, buf, buf_len, "\"%lx.%" INT64_FMT "\"", (unsigned long)filep->last_modified, filep->size);
	}
}


static void fclose_on_exec(struct file *filep, struct mg_connection *conn) {

	if (filep != NULL && filep->fp != NULL) {
#ifdef _WIN32
		(void)conn; /* Unused. */
#else
		if (fcntl(fileno(filep->fp), F_SETFD, FD_CLOEXEC) != 0) {
			mg_cry(conn, "%s: fcntl(F_SETFD FD_CLOEXEC) failed: %s", __func__, strerror(ERRNO));
		}
#endif
	}
}


void XX_httplib_handle_static_file_request( struct mg_connection *conn, const char *path, struct file *filep, const char *mime_type, const char *additional_headers ) {

	char date[64];
	char lm[64];
	char etag[64];
	char range[128]; /* large enough, so there will be no overflow */
	const char *msg = "OK", *hdr;
	time_t curtime = time(NULL);
	int64_t cl;
	int64_t r1;
	int64_t r2;
	struct vec mime_vec;
	int n;
	int truncated;
	char gz_path[PATH_MAX];
	const char *encoding = "";
	const char *cors1;
	const char *cors2;
	const char *cors3;

	if (conn == NULL || conn->ctx == NULL || filep == NULL) return;

	if (mime_type == NULL) {
		get_mime_type(conn->ctx, path, &mime_vec);
	} else {
		mime_vec.ptr = mime_type;
		mime_vec.len = strlen(mime_type);
	}
	if (filep->size > INT64_MAX) {
		XX_httplib_send_http_error(conn, 500, "Error: File size is too large to send\n%" INT64_FMT, filep->size);
	}
	cl = (int64_t)filep->size;
	conn->status_code = 200;
	range[0] = '\0';

	/* if this file is in fact a pre-gzipped file, rewrite its filename
	 * it's important to rewrite the filename after resolving
	 * the mime type from it, to preserve the actual file's type */
	if (filep->gzipped) {
		XX_httplib_snprintf(conn, &truncated, gz_path, sizeof(gz_path), "%s.gz", path);

		if (truncated) {
			XX_httplib_send_http_error(conn, 500, "Error: Path of zipped file too long (%s)", path);
			return;
		}

		path = gz_path;
		encoding = "Content-Encoding: gzip\r\n";
	}

	if (!XX_httplib_fopen(conn, path, "rb", filep)) {
		XX_httplib_send_http_error(conn, 500, "Error: Cannot open file\nfopen(%s): %s", path, strerror(ERRNO));
		return;
	}

	fclose_on_exec(filep, conn);

	/* If Range: header specified, act accordingly */
	r1 = r2 = 0;
	hdr = mg_get_header(conn, "Range");
	if (hdr != NULL && (n = parse_range_header(hdr, &r1, &r2)) > 0 && r1 >= 0
	    && r2 >= 0) {
		/* actually, range requests don't play well with a pre-gzipped
		 * file (since the range is specified in the uncompressed space) */
		if (filep->gzipped) {
			XX_httplib_send_http_error( conn, 501, "%s", "Error: Range requests in gzipped files are not supported"); XX_httplib_fclose(filep);
			return;
		}
		conn->status_code = 206;
		cl = (n == 2) ? (((r2 > cl) ? cl : r2) - r1 + 1) : (cl - r1);
		XX_httplib_snprintf(conn,
		            NULL, /* range buffer is big enough */
		            range,
		            sizeof(range),
		            "Content-Range: bytes "
		            "%" INT64_FMT "-%" INT64_FMT "/%" INT64_FMT "\r\n",
		            r1,
		            r1 + cl - 1,
		            filep->size);
		msg = "Partial Content";
	}

	hdr = mg_get_header(conn, "Origin");
	if (hdr) {
		/* Cross-origin resource sharing (CORS), see
		 * http://www.html5rocks.com/en/tutorials/cors/,
		 * http://www.html5rocks.com/static/images/cors_server_flowchart.png -
		 * preflight is not supported for files. */
		cors1 = "Access-Control-Allow-Origin: ";
		cors2 = conn->ctx->config[ACCESS_CONTROL_ALLOW_ORIGIN];
		cors3 = "\r\n";
	} else {
		cors1 = cors2 = cors3 = "";
	}

	/* Prepare Etag, Date, Last-Modified headers. Must be in UTC, according to
	 * http://www.w3.org/Protocols/rfc2616/rfc2616-sec3.html#sec3.3 */
	XX_httplib_gmt_time_string(date, sizeof(date), &curtime);
	XX_httplib_gmt_time_string(lm, sizeof(lm), &filep->last_modified);
	construct_etag(etag, sizeof(etag), filep);

	(void)mg_printf(conn, "HTTP/1.1 %d %s\r\n" "%s%s%s" "Date: %s\r\n", conn->status_code, msg, cors1, cors2, cors3, date);
	send_static_cache_header(conn);
	(void)mg_printf(conn,
	                "Last-Modified: %s\r\n"
	                "Etag: %s\r\n"
	                "Content-Type: %.*s\r\n"
	                "Content-Length: %" INT64_FMT "\r\n"
	                "Connection: %s\r\n"
	                "Accept-Ranges: bytes\r\n"
	                "%s%s",
	                lm,
	                etag,
	                (int)mime_vec.len,
	                mime_vec.ptr,
	                cl,
	                XX_httplib_suggest_connection_header(conn),
	                range,
	                encoding);

	/* The previous code must not add any header starting with X- to make
	 * sure no one of the additional_headers is included twice */

	if (additional_headers != NULL) {
		mg_printf(conn, "%.*s\r\n\r\n", (int)strlen(additional_headers), additional_headers);
	} else mg_printf(conn, "\r\n");

	if (strcmp(conn->request_info.request_method, "HEAD") != 0) send_file_data(conn, filep, r1, cl);
	XX_httplib_fclose(filep);

}  /* XX_handle_static_file_request */


#if !defined(NO_CACHING)
void XX_httplib_handle_not_modified_static_file_request( struct mg_connection *conn, struct file *filep ) {

	char date[64];
	char lm[64];
	char etag[64];
	time_t curtime;

	if (conn == NULL || filep == NULL) return;

	curtime = time( NULL );

	conn->status_code = 304;
	XX_httplib_gmt_time_string(date, sizeof(date), &curtime);
	XX_httplib_gmt_time_string(lm, sizeof(lm), &filep->last_modified);
	construct_etag(etag, sizeof(etag), filep);

	mg_printf(conn, "HTTP/1.1 %d %s\r\n" "Date: %s\r\n", conn->status_code, mg_get_response_code_text(conn, conn->status_code), date);
	send_static_cache_header(conn);
	mg_printf(conn, "Last-Modified: %s\r\n" "Etag: %s\r\n" "Connection: %s\r\n" "\r\n", lm, etag, XX_httplib_suggest_connection_header(conn));

}  /* XX_httplib_handle_not_modified_static_file_request */

#endif


void mg_send_file(struct mg_connection *conn, const char *path) {

	mg_send_mime_file( conn, path, NULL );
}


void mg_send_mime_file(struct mg_connection *conn, const char *path, const char *mime_type) {

	mg_send_mime_file2( conn, path, mime_type, NULL );
}


void mg_send_mime_file2( struct mg_connection *conn, const char *path, const char *mime_type, const char *additional_headers ) {

	struct file file = STRUCT_FILE_INITIALIZER;

	if (XX_httplib_stat(conn, path, &file)) {
		if (file.is_directory) {
			if (!conn) return;
			if (!mg_strcasecmp(conn->ctx->config[ENABLE_DIRECTORY_LISTING], "yes")) {
				XX_httplib_handle_directory_request(conn, path);
			} else {
				XX_httplib_send_http_error(conn, 403, "%s", "Error: Directory listing denied");
			}
		} else {
			XX_httplib_handle_static_file_request( conn, path, &file, mime_type, additional_headers);
		}
	} else XX_httplib_send_http_error(conn, 404, "%s", "Error: File not found");
}


/* For a given PUT path, create all intermediate subdirectories.
 * Return  0  if the path itself is a directory.
 * Return  1  if the path leads to a file.
 * Return -1  for if the path is too long.
 * Return -2  if path can not be created.
*/
static int put_dir(struct mg_connection *conn, const char *path) {

	char buf[PATH_MAX];
	const char *s;
	const char *p;
	struct file file = STRUCT_FILE_INITIALIZER;
	size_t len;
	int res = 1;

	for (s = p = path + 2; (p = strchr(s, '/')) != NULL; s = ++p) {
		len = (size_t)(p - path);
		if (len >= sizeof(buf)) {
			/* path too long */
			res = -1;
			break;
		}
		memcpy(buf, path, len);
		buf[len] = '\0';

		/* Try to create intermediate directory */
		if (!XX_httplib_stat(conn, buf, &file) && mg_mkdir(conn, buf, 0755) != 0) {
			/* path does not exixt and can not be created */
			res = -2;
			break;
		}

		/* Is path itself a directory? */
		if (p[1] == '\0') res = 0;
	}

	return res;
}


static void remove_bad_file(const struct mg_connection *conn, const char *path) {

	int r = mg_remove(conn, path);

	if (r != 0) mg_cry(conn, "%s: Cannot remove invalid file %s", __func__, path);
}


long long mg_store_body( struct mg_connection *conn, const char *path ) {

	char buf[MG_BUF_LEN];
	long long len = 0;
	int ret;
	int n;
	struct file fi;

	if (conn->consumed_content != 0) {
		mg_cry(conn, "%s: Contents already consumed", __func__);
		return -11;
	}

	ret = put_dir(conn, path);
	if (ret < 0) {
		/* -1 for path too long,
		 * -2 for path can not be created. */
		return ret;
	}
	if (ret != 1) {
		/* Return 0 means, path itself is a directory. */
		return 0;
	}

	if (XX_httplib_fopen(conn, path, "w", &fi) == 0) return -12;

	ret = mg_read(conn, buf, sizeof(buf));
	while (ret > 0) {
		n = (int)fwrite(buf, 1, (size_t)ret, fi.fp);
		if (n != ret) {
			XX_httplib_fclose(&fi);
			remove_bad_file(conn, path);
			return -13;
		}
		ret = mg_read(conn, buf, sizeof(buf));
	}

	/* TODO: XX_httplib_fclose should return an error,
	 * and every caller should check and handle it. */
	if (fclose(fi.fp) != 0) {
		remove_bad_file(conn, path);
		return -14;
	}

	return len;
}


/* Parse HTTP headers from the given buffer, advance buf pointer
 * to the point where parsing stopped.
 * All parameters must be valid pointers (not NULL).
 * Return <0 on error. */
static int parse_http_headers(char **buf, struct mg_request_info *ri) {

	int i;

	ri->num_headers = 0;

	for (i = 0; i < (int)ARRAY_SIZE(ri->http_headers); i++) {
		char *dp = *buf;
		while ((*dp != ':') && (*dp >= 33) && (*dp <= 126)) {
			dp++;
		}
		if (dp == *buf) {
			/* End of headers reached. */
			break;
		}
		if (*dp != ':') {
			/* This is not a valid field. */
			return -1;
		}

		/* End of header key (*dp == ':') */
		/* Truncate here and set the key name */
		*dp = 0;
		ri->http_headers[i].name = *buf;
		do {
			dp++;
		} while (*dp == ' ');

		/* The rest of the line is the value */
		ri->http_headers[i].value = dp;
		*buf = dp + strcspn(dp, "\r\n");
		if (((*buf)[0] != '\r') || ((*buf)[1] != '\n')) {
			*buf = NULL;
		}


		ri->num_headers = i + 1;
		if (*buf) {
			(*buf)[0] = 0;
			(*buf)[1] = 0;
			*buf += 2;
		} else {
			*buf = dp;
			break;
		}

		if ((*buf)[0] == '\r') {
			/* This is the end of the header */
			break;
		}
	}
	return ri->num_headers;
}


static int is_valid_http_method(const char *method) {

	return !strcmp(method, "GET")        /* HTTP (RFC 2616) */
	       || !strcmp(method, "POST")    /* HTTP (RFC 2616) */
	       || !strcmp(method, "HEAD")    /* HTTP (RFC 2616) */
	       || !strcmp(method, "PUT")     /* HTTP (RFC 2616) */
	       || !strcmp(method, "DELETE")  /* HTTP (RFC 2616) */
	       || !strcmp(method, "OPTIONS") /* HTTP (RFC 2616) */
	       /* TRACE method (RFC 2616) is not supported for security reasons */
	       || !strcmp(method, "CONNECT") /* HTTP (RFC 2616) */

	       || !strcmp(method, "PROPFIND") /* WEBDAV (RFC 2518) */
	       || !strcmp(method, "MKCOL")    /* WEBDAV (RFC 2518) */

	       /* Unsupported WEBDAV Methods: */
	       /* PROPPATCH, COPY, MOVE, LOCK, UNLOCK (RFC 2518) */
	       /* + 11 methods from RFC 3253 */
	       /* ORDERPATCH (RFC 3648) */
	       /* ACL (RFC 3744) */
	       /* SEARCH (RFC 5323) */
	       /* + MicroSoft extensions
	        * https://msdn.microsoft.com/en-us/library/aa142917.aspx */

	       /* PATCH method only allowed for CGI/Lua/LSP and callbacks. */
	       || !strcmp(method, "PATCH"); /* PATCH method (RFC 5789) */
}


/* Parse HTTP request, fill in mg_request_info structure.
 * This function modifies the buffer by NUL-terminating
 * HTTP request components, header names and header values.
 * Parameters:
 *   buf (in/out): pointer to the HTTP header to parse and split
 *   len (in): length of HTTP header buffer
 *   re (out): parsed header as mg_request_info
 * buf and ri must be valid pointers (not NULL), len>0.
 * Returns <0 on error. */
int XX_httplib_parse_http_message( char *buf, int len, struct mg_request_info *ri ) {

	int is_request;
	int request_length;
	char *start_line;

	request_length = get_request_len(buf, len);

	if (request_length > 0) {
		/* Reset attributes. DO NOT TOUCH is_ssl, remote_ip, remote_addr,
		 * remote_port */
		ri->remote_user = ri->request_method = ri->request_uri =
		    ri->http_version = NULL;
		ri->num_headers = 0;

		buf[request_length - 1] = '\0';

		/* RFC says that all initial whitespaces should be ingored */
		while (*buf != '\0' && isspace(*(unsigned char *)buf)) {
			buf++;
		}
		start_line = skip(&buf, "\r\n");
		ri->request_method = skip(&start_line, " ");
		ri->request_uri = skip(&start_line, " ");
		ri->http_version = start_line;

		/* HTTP message could be either HTTP request:
		 * "GET / HTTP/1.0 ..."
		 * or a HTTP response:
		 *  "HTTP/1.0 200 OK ..."
		 * otherwise it is invalid.
		 */
		is_request = is_valid_http_method(ri->request_method);
		if ((is_request && memcmp(ri->http_version, "HTTP/", 5) != 0)
		    || (!is_request && memcmp(ri->request_method, "HTTP/", 5) != 0)) {
			/* Not a valid request or response: invalid */
			return -1;
		}
		if (is_request) ri->http_version += 5;
		if (parse_http_headers(&buf, ri) < 0) {
			/* Error while parsing headers */
			return -1;
		}
	}
	return request_length;

}  /* XX_httplib_parse_http_message */


/* Keep reading the input (either opened file descriptor fd, or socket sock,
 * or SSL descriptor ssl) into buffer buf, until \r\n\r\n appears in the
 * buffer (which marks the end of HTTP request). Buffer buf may already
 * have some data. The length of the data is stored in nread.
 * Upon every read operation, increase nread by the number of bytes read. */
int XX_httplib_read_request( FILE *fp, struct mg_connection *conn, char *buf, int bufsiz, int *nread ) {

	int request_len;
	int n = 0;
	struct timespec last_action_time;
	double request_timeout;

	if (!conn) return 0;

	memset(&last_action_time, 0, sizeof(last_action_time));

	if (conn->ctx->config[REQUEST_TIMEOUT]) {
		/* value of request_timeout is in seconds, config in milliseconds */
		request_timeout = atof(conn->ctx->config[REQUEST_TIMEOUT]) / 1000.0;
	} else request_timeout = -1.0;

	request_len = get_request_len(buf, *nread);

	/* first time reading from this connection */
	clock_gettime(CLOCK_MONOTONIC, &last_action_time);

	while (
	    (conn->ctx->stop_flag == 0) && (*nread < bufsiz) && (request_len == 0)
	    && ((mg_difftimespec(&last_action_time, &(conn->req_time))
	         <= request_timeout) || (request_timeout < 0))
	    && ((n = pull(fp, conn, buf + *nread, bufsiz - *nread, request_timeout))
	        > 0)) {
		*nread += n;
		/* assert(*nread <= bufsiz); */
		if (*nread > bufsiz) {
			return -2;
		}
		request_len = get_request_len(buf, *nread);
		if (request_timeout > 0.0) clock_gettime(CLOCK_MONOTONIC, &last_action_time);
	}

	return ((request_len <= 0) && (n <= 0)) ? -1 : request_len;

}  /* XX_httplib_read_request */

#if !defined(NO_FILES)
/* For given directory path, substitute it to valid index file.
 * Return 1 if index file has been found, 0 if not found.
 * If the file is found, it's stats is returned in stp. */
int XX_httplib_substitute_index_file( struct mg_connection *conn, char *path, size_t path_len, struct file *filep ) {

	if ( conn == NULL  ||  conn->ctx == NULL ) return 0;

	const char *list = conn->ctx->config[INDEX_FILES];
	struct file file = STRUCT_FILE_INITIALIZER;
	struct vec filename_vec;
	size_t n = strlen(path);
	int found = 0;

	/* The 'path' given to us points to the directory. Remove all trailing
	 * directory separator characters from the end of the path, and
	 * then append single directory separator character. */
	while (n > 0 && path[n - 1] == '/') n--;
	path[n] = '/';

	/* Traverse index files list. For each entry, append it to the given
	 * path and see if the file exists. If it exists, break the loop */
	while ((list = XX_httplib_next_option(list, &filename_vec, NULL)) != NULL) {
		/* Ignore too long entries that may overflow path buffer */
		if (filename_vec.len > path_len - (n + 2)) continue;

		/* Prepare full path to the index file */
		XX_httplib_strlcpy(path + n + 1, filename_vec.ptr, filename_vec.len + 1);

		/* Does it exist? */
		if (XX_httplib_stat(conn, path, &file)) {
			/* Yes it does, break the loop */
			*filep = file;
			found = 1;
			break;
		}
	}

	/* If no index file exists, restore directory path */
	if (!found) path[n] = '\0';

	return found;

}  /* XX_httplib_substitute_index_file */
#endif


#if !defined(NO_CACHING)
/* Return True if we should reply 304 Not Modified. */
int XX_httplib_is_not_modified( const struct mg_connection *conn, const struct file *filep ) {

	char etag[64];
	const char *ims = mg_get_header(conn, "If-Modified-Since");
	const char *inm = mg_get_header(conn, "If-None-Match");

	construct_etag(etag, sizeof(etag), filep);
	if (!filep) return 0;
	return (inm != NULL && !mg_strcasecmp(etag, inm)) || (ims != NULL && (filep->last_modified <= parse_date_string(ims)));

}  /* XX_httplib_is_not_modified */

#endif /* !NO_CACHING */


#if !defined(NO_CGI) || !defined(NO_FILES)
static int forward_body_data(struct mg_connection *conn, FILE *fp, SOCKET sock, SSL *ssl) {

	const char *expect;
	const char *body;
	char buf[MG_BUF_LEN];
	int to_read;
	int nread;
	int success = 0;
	int64_t buffered_len;
	double timeout = -1.0;

	if (!conn) { return 0; }
	if (conn->ctx->config[REQUEST_TIMEOUT]) {
		timeout = atoi(conn->ctx->config[REQUEST_TIMEOUT]) / 1000.0;
	}

	expect = mg_get_header(conn, "Expect");
	/* assert(fp != NULL); */
	if (!fp) {
		XX_httplib_send_http_error(conn, 500, "%s", "Error: NULL File");
		return 0;
	}

	if (conn->content_len == -1 && !conn->is_chunked) {
		/* Content length is not specified by the client. */
		XX_httplib_send_http_error(conn, 411, "%s", "Error: Client did not specify content length");
	} else if ((expect != NULL)
	           && (mg_strcasecmp(expect, "100-continue") != 0)) {
		/* Client sent an "Expect: xyz" header and xyz is not 100-continue. */
		XX_httplib_send_http_error(conn, 417, "Error: Can not fulfill expectation %s", expect);
	} else {
		if (expect != NULL) {
			(void)mg_printf(conn, "%s", "HTTP/1.1 100 Continue\r\n\r\n");
			conn->status_code = 100;
		} else conn->status_code = 200;

		buffered_len = (int64_t)(conn->data_len) - (int64_t)conn->request_len
		               - conn->consumed_content;

		/* assert(buffered_len >= 0); */
		/* assert(conn->consumed_content == 0); */

		if ((buffered_len < 0) || (conn->consumed_content != 0)) {
			XX_httplib_send_http_error(conn, 500, "%s", "Error: Size mismatch");
			return 0;
		}

		if (buffered_len > 0) {
			if ((int64_t)buffered_len > conn->content_len) {
				buffered_len = (int)conn->content_len;
			}
			body = conn->buf + conn->request_len + conn->consumed_content;
			push_all(conn->ctx, fp, sock, ssl, body, (int64_t)buffered_len);
			conn->consumed_content += buffered_len;
		}

		nread = 0;
		while (conn->consumed_content < conn->content_len) {
			to_read = sizeof(buf);
			if ((int64_t)to_read > conn->content_len - conn->consumed_content) {
				to_read = (int)(conn->content_len - conn->consumed_content);
			}
			nread = pull(NULL, conn, buf, to_read, timeout);
			if (nread <= 0 || push_all(conn->ctx, fp, sock, ssl, buf, nread) != nread) break;
			conn->consumed_content += nread;
		}

		if (conn->consumed_content == conn->content_len) success = (nread >= 0);

		/* Each error code path in this function must send an error */
		if (!success) {
			/* NOTE: Maybe some data has already been sent. */
			/* TODO (low): If some data has been sent, a correct error
			 * reply can no longer be sent, so just close the connection */
			XX_httplib_send_http_error(conn, 500, "%s", "");
		}
	}

	return success;
}
#endif

#if !defined(NO_CGI)
/* This structure helps to create an environment for the spawned CGI program.
 * Environment is an array of "VARIABLE=VALUE\0" ASCIIZ strings,
 * last element must be NULL.
 * However, on Windows there is a requirement that all these VARIABLE=VALUE\0
 * strings must reside in a contiguous buffer. The end of the buffer is
 * marked by two '\0' characters.
 * We satisfy both worlds: we create an envp array (which is vars), all
 * entries are actually pointers inside buf. */
struct cgi_environment {
	struct mg_connection *conn;
	/* Data block */
	char *buf;      /* Environment buffer */
	size_t buflen;  /* Space available in buf */
	size_t bufused; /* Space taken in buf */
	                /* Index block */
	char **var;     /* char **envp */
	size_t varlen;  /* Number of variables available in var */
	size_t varused; /* Number of variables stored in var */
};


static void addenv(struct cgi_environment *env, PRINTF_FORMAT_STRING(const char *fmt), ...) PRINTF_ARGS(2, 3); 

/* Append VARIABLE=VALUE\0 string to the buffer, and add a respective
 * pointer into the vars array. Assumes env != NULL and fmt != NULL. */
static void addenv(struct cgi_environment *env, const char *fmt, ...) {

	size_t n;
	size_t space;
	int truncated;
	char *added;
	va_list ap;

	/* Calculate how much space is left in the buffer */
	space = (env->buflen - env->bufused);

	/* Calculate an estimate for the required space */
	n = strlen(fmt) + 2 + 128;

	do {
		if (space <= n) {
			/* Allocate new buffer */
			n = env->buflen + CGI_ENVIRONMENT_SIZE;
			added = (char *)XX_httplib_realloc(env->buf, n);
			if (!added) {
				/* Out of memory */
				mg_cry(env->conn, "%s: Cannot allocate memory for CGI variable [%s]", __func__, fmt);
				return;
			}
			env->buf = added;
			env->buflen = n;
			space = (env->buflen - env->bufused);
		}

		/* Make a pointer to the free space int the buffer */
		added = env->buf + env->bufused;

		/* Copy VARIABLE=VALUE\0 string into the free space */
		va_start(ap, fmt);
		mg_vsnprintf(env->conn, &truncated, added, (size_t)space, fmt, ap);
		va_end(ap);

		/* Do not add truncated strings to the environment */
		if (truncated) {
			/* Reallocate the buffer */
			space = 0;
			n = 1;
		}
	} while (truncated);

	/* Calculate number of bytes added to the environment */
	n = strlen(added) + 1;
	env->bufused += n;

	/* Now update the variable index */
	space = (env->varlen - env->varused);
	if (space < 2) {
		mg_cry(env->conn, "%s: Cannot register CGI variable [%s]", __func__, fmt);
		return;
	}

	/* Append a pointer to the added string into the envp array */
	env->var[env->varused] = added;
	env->varused++;
}


static void prepare_cgi_environment( struct mg_connection *conn, const char *prog, struct cgi_environment *env ) {

	const char *s;
	struct vec var_vec;
	char *p;
	char src_addr[IP_ADDR_STR_LEN];
	char http_var_name[128];
	int i;
	int truncated;

	if ( conn == NULL  ||  prog == NULL  ||  env == NULL ) return;

	env->conn    = conn;
	env->buflen  = CGI_ENVIRONMENT_SIZE;
	env->bufused = 0;
	env->buf     = (char *)XX_httplib_malloc(env->buflen);
	env->varlen  = MAX_CGI_ENVIR_VARS;
	env->varused = 0;
	env->var     = (char **)XX_httplib_malloc(env->buflen * sizeof(char *));

	addenv( env, "SERVER_NAME=%s",                   conn->ctx->config[AUTHENTICATION_DOMAIN] );
	addenv( env, "SERVER_ROOT=%s",                   conn->ctx->config[DOCUMENT_ROOT]         );
	addenv( env, "DOCUMENT_ROOT=%s",                 conn->ctx->config[DOCUMENT_ROOT]         );
	addenv( env, "SERVER_SOFTWARE=%s/%s", "LibHTTP", mg_version()                             );

	/* Prepare the environment block */
	addenv( env, "%s", "GATEWAY_INTERFACE=CGI/1.1" );
	addenv( env, "%s", "SERVER_PROTOCOL=HTTP/1.1"  );
	addenv( env, "%s", "REDIRECT_STATUS=200"       ); /* For PHP */

#if defined(USE_IPV6)
	if (conn->client.lsa.sa.sa_family == AF_INET6) {
		addenv(env, "SERVER_PORT=%d", ntohs(conn->client.lsa.sin6.sin6_port));
	} else
#endif
	{
		addenv(env, "SERVER_PORT=%d", ntohs(conn->client.lsa.sin.sin_port));
	}

	XX_httplib_sockaddr_to_string(src_addr, sizeof(src_addr), &conn->client.rsa);

	addenv( env, "REMOTE_ADDR=%s",    src_addr                          );
	addenv( env, "REQUEST_METHOD=%s", conn->request_info.request_method );
	addenv( env, "REMOTE_PORT=%d",    conn->request_info.remote_port    );
	addenv( env, "REQUEST_URI=%s",    conn->request_info.request_uri    );
	addenv( env, "LOCAL_URI=%s",      conn->request_info.local_uri      );

	/* SCRIPT_NAME */
	addenv(env,
	       "SCRIPT_NAME=%.*s",
	       (int)strlen(conn->request_info.local_uri)
	           - ((conn->path_info == NULL) ? 0 : (int)strlen(conn->path_info)),
	       conn->request_info.local_uri);

	addenv(env, "SCRIPT_FILENAME=%s", prog);

	if ( conn->path_info == NULL ) addenv( env, "PATH_TRANSLATED=%s",   conn->ctx->config[DOCUMENT_ROOT]                  );
	else                           addenv( env, "PATH_TRANSLATED=%s%s", conn->ctx->config[DOCUMENT_ROOT], conn->path_info );

	addenv(env, "HTTPS=%s", (conn->ssl == NULL) ? "off" : "on");

	if ( (s = mg_get_header( conn, "Content-Type" ) )   != NULL ) addenv( env, "CONTENT_TYPE=%s",   s                               );
	if ( conn->request_info.query_string                != NULL ) addenv( env, "QUERY_STRING=%s",   conn->request_info.query_string );
	if ( (s = mg_get_header( conn, "Content-Length" ) ) != NULL ) addenv( env, "CONTENT_LENGTH=%s", s                               );
	if ( (s = getenv( "PATH" ))                         != NULL ) addenv( env, "PATH=%s",           s                               );
	if ( conn->path_info                                != NULL ) addenv( env, "PATH_INFO=%s",      conn->path_info                 );

	if (conn->status_code > 0) {
		/* CGI error handler should show the status code */
		addenv(env, "STATUS=%d", conn->status_code);
	}

#if defined(_WIN32)
	if ( (s = getenv( "COMSPEC"           )) != NULL ) addenv( env, "COMSPEC=%s",           s );
	if ( (s = getenv( "SYSTEMROOT"        )) != NULL ) addenv( env, "SYSTEMROOT=%s",        s );
	if ( (s = getenv( "SystemDrive"       )) != NULL ) addenv( env, "SystemDrive=%s",       s );
	if ( (s = getenv( "ProgramFiles"      )) != NULL ) addenv( env, "ProgramFiles=%s",      s );
	if ( (s = getenv( "ProgramFiles(x86)" )) != NULL ) addenv( env, "ProgramFiles(x86)=%s", s );
#else
	if ( (s = getenv("LD_LIBRARY_PATH"    )) != NULL ) addenv( env, "LD_LIBRARY_PATH=%s",   s );
#endif /* _WIN32 */

	if ( (s = getenv("PERLLIB"            )) != NULL ) addenv( env, "PERLLIB=%s",           s );

	if (conn->request_info.remote_user != NULL) {
		addenv(env, "REMOTE_USER=%s", conn->request_info.remote_user);
		addenv(env, "%s", "AUTH_TYPE=Digest");
	}

	/* Add all headers as HTTP_* variables */
	for (i = 0; i < conn->request_info.num_headers; i++) {

		XX_httplib_snprintf(conn, &truncated, http_var_name, sizeof(http_var_name), "HTTP_%s", conn->request_info.http_headers[i].name);

		if (truncated) {
			mg_cry(conn, "%s: HTTP header variable too long [%s]", __func__, conn->request_info.http_headers[i].name);
			continue;
		}

		/* Convert variable name into uppercase, and change - to _ */
		for (p = http_var_name; *p != '\0'; p++) {
			if (*p == '-') *p = '_';
			*p = (char)toupper(*(unsigned char *)p);
		}

		addenv(env, "%s=%s", http_var_name, conn->request_info.http_headers[i].value);
	}

	/* Add user-specified variables */
	s = conn->ctx->config[CGI_ENVIRONMENT];
	while ((s = XX_httplib_next_option(s, &var_vec, NULL)) != NULL) {
		addenv(env, "%.*s", (int)var_vec.len, var_vec.ptr);
	}

	env->var[env->varused] = NULL;
	env->buf[env->bufused] = '\0';
}


void XX_httplib_handle_cgi_request( struct mg_connection *conn, const char *prog ) {

	char *buf;
	size_t buflen;
	int headers_len;
	int data_len;
	int i;
	int truncated;
	int fdin[2]  = {-1, -1};
	int fdout[2] = {-1, -1};
	int fderr[2] = {-1, -1};
	const char *status;
	const char *status_text;
	const char *connection_state;
	char *pbuf;
	char dir[PATH_MAX];
	char *p;
	struct mg_request_info ri;
	struct cgi_environment blk;
	FILE *in;
	FILE *out;
	FILE *err;
	struct file fout = STRUCT_FILE_INITIALIZER;
	pid_t pid = (pid_t)-1;

	if (conn == NULL) return;

	in  = NULL;
	out = NULL;
	err = NULL;

	buf    = NULL;
	buflen = 16384;
	prepare_cgi_environment(conn, prog, &blk);

	/* CGI must be executed in its own directory. 'dir' must point to the
	 * directory containing executable program, 'p' must point to the
	 * executable program name relative to 'dir'. */
	XX_httplib_snprintf(conn, &truncated, dir, sizeof(dir), "%s", prog);

	if (truncated) {
		mg_cry(conn, "Error: CGI program \"%s\": Path too long", prog);
		XX_httplib_send_http_error(conn, 500, "Error: %s", "CGI path too long");
		goto done;
	}

	if ((p = strrchr(dir, '/')) != NULL) {
		*p++ = '\0';
	} else {
		dir[0] = '.', dir[1] = '\0';
		p = (char *)prog;
	}

	if (pipe(fdin) != 0 || pipe(fdout) != 0 || pipe(fderr) != 0) {
		status = strerror(ERRNO);
		mg_cry(conn, "Error: CGI program \"%s\": Can not create CGI pipes: %s", prog, status);
		XX_httplib_send_http_error(conn, 500, "Error: Cannot create CGI pipe: %s", status);
		goto done;
	}

	pid = spawn_process(conn, p, blk.buf, blk.var, fdin, fdout, fderr, dir);

	if (pid == (pid_t)-1) {
		status = strerror(ERRNO);
		mg_cry(conn, "Error: CGI program \"%s\": Can not spawn CGI process: %s", prog, status);
		XX_httplib_send_http_error(conn, 500, "Error: Cannot spawn CGI process [%s]: %s", prog, status);
		goto done;
	}

	/* Make sure child closes all pipe descriptors. It must dup them to 0,1 */
	XX_httplib_set_close_on_exec( (SOCKET)fdin[0],  conn );  /* stdin read */
	XX_httplib_set_close_on_exec( (SOCKET)fdout[1], conn ); /* stdout write */
	XX_httplib_set_close_on_exec( (SOCKET)fderr[1], conn ); /* stderr write */
	XX_httplib_set_close_on_exec( (SOCKET)fdin[1],  conn );  /* stdin write */
	XX_httplib_set_close_on_exec( (SOCKET)fdout[0], conn ); /* stdout read */
	XX_httplib_set_close_on_exec( (SOCKET)fderr[0], conn ); /* stderr read */

	/* Parent closes only one side of the pipes.
	 * If we don't mark them as closed, close() attempt before
	 * return from this function throws an exception on Windows.
	 * Windows does not like when closed descriptor is closed again. */
	close( fdin[0]  );
	close( fdout[1] );
	close( fderr[1] );

	fdin[0]  = -1;
	fdout[1] = -1;
	fderr[1] = -1;

	if ((in = fdopen(fdin[1], "wb")) == NULL) {
		status = strerror(ERRNO);
		mg_cry(conn, "Error: CGI program \"%s\": Can not open stdin: %s", prog, status);
		XX_httplib_send_http_error(conn, 500, "Error: CGI can not open fdin\nfopen: %s", status);
		goto done;
	}

	if ((out = fdopen(fdout[0], "rb")) == NULL) {
		status = strerror(ERRNO);
		mg_cry(conn, "Error: CGI program \"%s\": Can not open stdout: %s", prog, status);
		XX_httplib_send_http_error(conn, 500, "Error: CGI can not open fdout\nfopen: %s", status);
		goto done;
	}

	if ((err = fdopen(fderr[0], "rb")) == NULL) {
		status = strerror(ERRNO);
		mg_cry(conn, "Error: CGI program \"%s\": Can not open stderr: %s", prog, status);
		XX_httplib_send_http_error(conn, 500, "Error: CGI can not open fdout\nfopen: %s", status);
		goto done;
	}

	setbuf(in, NULL);
	setbuf(out, NULL);
	setbuf(err, NULL);
	fout.fp = out;

	if ((conn->request_info.content_length > 0) || conn->is_chunked) {
		/* This is a POST/PUT request, or another request with body data. */
		if (!forward_body_data(conn, in, INVALID_SOCKET, NULL)) {
			/* Error sending the body data */
			mg_cry(conn, "Error: CGI program \"%s\": Forward body data failed", prog);
			goto done;
		}
	}

	/* Close so child gets an EOF. */
	fclose(in);
	in = NULL;
	fdin[1] = -1;

	/* Now read CGI reply into a buffer. We need to set correct
	 * status code, thus we need to see all HTTP headers first.
	 * Do not send anything back to client, until we buffer in all
	 * HTTP headers. */
	data_len = 0;
	buf = (char *)XX_httplib_malloc(buflen);
	if (buf == NULL) {
		XX_httplib_send_http_error(conn, 500, "Error: Not enough memory for CGI buffer (%u bytes)", (unsigned int)buflen);
		mg_cry(conn, "Error: CGI program \"%s\": Not enough memory for buffer (%u " "bytes)", prog, (unsigned int)buflen);
		goto done;
	}
	headers_len = XX_httplib_read_request(out, conn, buf, (int)buflen, &data_len);
	if (headers_len <= 0) {

		/* Could not parse the CGI response. Check if some error message on
		 * stderr. */
		i = pull_all(err, conn, buf, (int)buflen);
		if (i > 0) {
			mg_cry(conn, "Error: CGI program \"%s\" sent error " "message: [%.*s]", prog, i, buf);
			XX_httplib_send_http_error(conn, 500, "Error: CGI program \"%s\" sent error " "message: [%.*s]", prog, i, buf);
		} else {
			mg_cry(conn, "Error: CGI program sent malformed or too big " "(>%u bytes) HTTP headers: [%.*s]", (unsigned)buflen, data_len, buf);

			XX_httplib_send_http_error(conn,
			                500,
			                "Error: CGI program sent malformed or too big "
			                "(>%u bytes) HTTP headers: [%.*s]",
			                (unsigned)buflen,
			                data_len,
			                buf);
		}

		goto done;
	}
	pbuf = buf;
	buf[headers_len - 1] = '\0';
	parse_http_headers(&pbuf, &ri);

	/* Make up and send the status line */
	status_text = "OK";
	if ((status = XX_httplib_get_header(&ri, "Status")) != NULL) {
		conn->status_code = atoi(status);
		status_text = status;
		while (isdigit(*(const unsigned char *)status_text)
		       || *status_text == ' ') {
			status_text++;
		}
	} else if (XX_httplib_get_header(&ri, "Location") != NULL) {
		conn->status_code = 302;
	} else {
		conn->status_code = 200;
	}
	connection_state = XX_httplib_get_header(&ri, "Connection");
	if (!header_has_option(connection_state, "keep-alive")) {
		conn->must_close = 1;
	}
	mg_printf(conn, "HTTP/1.1 %d %s\r\n", conn->status_code, status_text);

	/* Send headers */
	for (i = 0; i < ri.num_headers; i++) {
		mg_printf(conn, "%s: %s\r\n", ri.http_headers[i].name, ri.http_headers[i].value);
	}
	mg_write(conn, "\r\n", 2);

	/* Send chunk of data that may have been read after the headers */
	conn->num_bytes_sent +=
	    mg_write(conn, buf + headers_len, (size_t)(data_len - headers_len));

	/* Read the rest of CGI output and send to the client */
	send_file_data(conn, &fout, 0, INT64_MAX);

done:
	XX_httplib_free(blk.var);
	XX_httplib_free(blk.buf);

	if (pid != (pid_t)-1) {
		kill(pid, SIGKILL);
#if !defined(_WIN32)
		{
			int st;
			while (waitpid(pid, &st, 0) != -1)
				; /* clean zombies */
		}
#endif
	}
	if ( fdin[0]  != -1 ) close( fdin[0]  );
	if ( fdout[1] != -1 ) close( fdout[1] );

	if ( in  != NULL ) fclose( in  ); else if ( fdin[1]  != -1 ) close( fdin[1]  );
	if ( out != NULL ) fclose( out ); else if ( fdout[0] != -1 ) close( fdout[0] );
	if ( err != NULL ) fclose( err ); else if ( fderr[0] != -1 ) close( fderr[0] );

	if ( buf != NULL ) XX_httplib_free( buf );

}  /* XX_httplib_handle_cgi_request */

#endif /* !NO_CGI */


#if !defined(NO_FILES)
void XX_httplib_mkcol( struct mg_connection *conn, const char *path ) {

	int rc;
	int body_len;
	struct de de;
	char date[64];
	time_t curtime;

	if ( conn == NULL ) return;

	curtime = time( NULL );

	/* TODO (mid): Check the XX_httplib_send_http_error situations in this function */

	memset(&de.file, 0, sizeof(de.file));
	if (!XX_httplib_stat(conn, path, &de.file)) {
		mg_cry(conn, "%s: XX_httplib_stat(%s) failed: %s", __func__, path, strerror(ERRNO));
	}

	if (de.file.last_modified) {
		/* TODO (high): This check does not seem to make any sense ! */
		XX_httplib_send_http_error( conn, 405, "Error: mkcol(%s): %s", path, strerror(ERRNO));
		return;
	}

	body_len = conn->data_len - conn->request_len;
	if (body_len > 0) {
		XX_httplib_send_http_error( conn, 415, "Error: mkcol(%s): %s", path, strerror(ERRNO));
		return;
	}

	rc = mg_mkdir( conn, path, 0755 );

	if ( rc == 0 ) {

		conn->status_code = 201;
		XX_httplib_gmt_time_string(date, sizeof(date), &curtime);
		mg_printf(conn, "HTTP/1.1 %d Created\r\n" "Date: %s\r\n", conn->status_code, date);
		send_static_cache_header(conn);
		mg_printf(conn, "Content-Length: 0\r\n" "Connection: %s\r\n\r\n", XX_httplib_suggest_connection_header(conn));
	}
	
	else if (rc == -1) {

		if      ( errno == EEXIST ) XX_httplib_send_http_error( conn, 405, "Error: mkcol(%s): %s", path, strerror( ERRNO ) );
		else if ( errno == EACCES ) XX_httplib_send_http_error( conn, 403, "Error: mkcol(%s): %s", path, strerror( ERRNO ) );
		else if ( errno == ENOENT ) XX_httplib_send_http_error( conn, 409, "Error: mkcol(%s): %s", path, strerror( ERRNO ) );
		else                        XX_httplib_send_http_error( conn, 500, "fopen(%s): %s",        path, strerror( ERRNO ) );
	}

}  /* XX_httplib_mkcol */


void XX_httplib_put_file( struct mg_connection *conn, const char *path ) {

	struct file file = STRUCT_FILE_INITIALIZER;
	const char *range;
	int64_t r1;
	int64_t r2;
	int rc;
	char date[64];
	time_t curtime;

	if (conn == NULL) return;

	curtime = time( NULL );

	if (XX_httplib_stat(conn, path, &file)) {
		/* File already exists */
		conn->status_code = 200;

		if (file.is_directory) {
			/* This is an already existing directory,
			 * so there is nothing to do for the server. */
			rc = 0;

		} else {
			/* File exists and is not a directory. */
			/* Can it be replaced? */

			if (file.membuf != NULL) {
				/* This is an "in-memory" file, that can not be replaced */
				XX_httplib_send_http_error( conn, 405, "Error: Put not possible\nReplacing %s is not supported", path);
				return;
			}

			/* Check if the server may write this file */
			if (access(path, W_OK) == 0) {
				/* Access granted */
				conn->status_code = 200;
				rc = 1;
			} else {
				XX_httplib_send_http_error( conn, 403, "Error: Put not possible\nReplacing %s is not allowed", path);
				return;
			}
		}
	} else {
		/* File should be created */
		conn->status_code = 201;
		rc = put_dir(conn, path);
	}

	if (rc == 0) {
		/* put_dir returns 0 if path is a directory */
		XX_httplib_gmt_time_string(date, sizeof(date), &curtime);
		mg_printf(conn, "HTTP/1.1 %d %s\r\n", conn->status_code, mg_get_response_code_text(NULL, conn->status_code));
		send_no_cache_header(conn);
		mg_printf(conn, "Date: %s\r\n" "Content-Length: 0\r\n" "Connection: %s\r\n\r\n", date, XX_httplib_suggest_connection_header(conn));

		/* Request to create a directory has been fulfilled successfully.
		 * No need to put a file. */
		return;
	}

	if (rc == -1) {
		/* put_dir returns -1 if the path is too long */
		XX_httplib_send_http_error(conn, 414, "Error: Path too long\nput_dir(%s): %s", path, strerror(ERRNO));
		return;
	}

	if (rc == -2) {
		/* put_dir returns -2 if the directory can not be created */
		XX_httplib_send_http_error(conn, 500, "Error: Can not create directory\nput_dir(%s): %s", path, strerror(ERRNO));
		return;
	}

	/* A file should be created or overwritten. */
	if (!XX_httplib_fopen(conn, path, "wb+", &file) || file.fp == NULL) {
		XX_httplib_fclose(&file);
		XX_httplib_send_http_error(conn, 500, "Error: Can not create file\nfopen(%s): %s", path, strerror(ERRNO));
		return;
	}

	fclose_on_exec(&file, conn);
	range = mg_get_header(conn, "Content-Range");
	r1 = r2 = 0;
	if (range != NULL && parse_range_header(range, &r1, &r2) > 0) {
		conn->status_code = 206; /* Partial content */
		fseeko(file.fp, r1, SEEK_SET);
	}

	if (!forward_body_data(conn, file.fp, INVALID_SOCKET, NULL)) {
		/* forward_body_data failed.
		 * The error code has already been sent to the client,
		 * and conn->status_code is already set. */
		XX_httplib_fclose(&file);
		return;
	}

	XX_httplib_gmt_time_string(date, sizeof(date), &curtime);
	mg_printf(conn, "HTTP/1.1 %d %s\r\n", conn->status_code, mg_get_response_code_text(NULL, conn->status_code));
	send_no_cache_header(conn);
	mg_printf(conn, "Date: %s\r\n" "Content-Length: 0\r\n" "Connection: %s\r\n\r\n", date, XX_httplib_suggest_connection_header(conn));

	XX_httplib_fclose(&file);

}  /* XX_httplib_put_file */


void XX_httplib_delete_file( struct mg_connection *conn, const char *path ) {

	struct de de;

	memset(&de.file, 0, sizeof(de.file));
	if (!XX_httplib_stat(conn, path, &de.file)) {
		/* XX_httplib_stat returns 0 if the file does not exist */
		XX_httplib_send_http_error(conn, 404, "Error: Cannot delete file\nFile %s not found", path);
		return;
	}

	if (de.file.membuf != NULL) {
		/* the file is cached in memory */
		XX_httplib_send_http_error( conn, 405, "Error: Delete not possible\nDeleting %s is not supported", path);
		return;
	}

	if (de.file.is_directory) {
		if (remove_directory(conn, path)) {
			/* Delete is successful: Return 204 without content. */
			XX_httplib_send_http_error(conn, 204, "%s", "");
		} else {
			/* Delete is not successful: Return 500 (Server error). */
			XX_httplib_send_http_error(conn, 500, "Error: Could not delete %s", path);
		}
		return;
	}

	/* This is an existing file (not a directory).
	 * Check if write permission is granted. */
	if (access(path, W_OK) != 0) {
		/* File is read only */
		XX_httplib_send_http_error( conn, 403, "Error: Delete not possible\nDeleting %s is not allowed", path);
		return;
	}

	/* Try to delete it. */
	if (mg_remove(conn, path) == 0) {
		/* Delete was successful: Return 204 without content. */
		XX_httplib_send_http_error(conn, 204, "%s", "");
	} else {
		/* Delete not successful (file locked). */
		XX_httplib_send_http_error(conn, 423, "Error: Cannot delete file\nremove(%s): %s", path, strerror(ERRNO));
	}

}  /* XX_httplib_delete_file */

#endif /* !NO_FILES */


static void
send_ssi_file(struct mg_connection *, const char *, struct file *, int);


static void do_ssi_include(struct mg_connection *conn, const char *ssi, char *tag, int include_level) {

	char file_name[MG_BUF_LEN], path[512];
	char *p;
	struct file file = STRUCT_FILE_INITIALIZER;
	size_t len;
	int truncated = 0;

	if (conn == NULL) return;

	/* sscanf() is safe here, since send_ssi_file() also uses buffer
	 * of size MG_BUF_LEN to get the tag. So strlen(tag) is
	 * always < MG_BUF_LEN. */
	if (sscanf(tag, " virtual=\"%511[^\"]\"", file_name) == 1) {
		/* File name is relative to the webserver root */
		file_name[511] = 0;
		XX_httplib_snprintf(conn, &truncated, path, sizeof(path), "%s/%s", conn->ctx->config[DOCUMENT_ROOT], file_name);

	} else if (sscanf(tag, " abspath=\"%511[^\"]\"", file_name) == 1) {
		/* File name is relative to the webserver working directory
		 * or it is absolute system path */
		file_name[511] = 0;
		XX_httplib_snprintf(conn, &truncated, path, sizeof(path), "%s", file_name);

	} else if (sscanf(tag, " file=\"%511[^\"]\"", file_name) == 1
	           || sscanf(tag, " \"%511[^\"]\"", file_name) == 1) {
		/* File name is relative to the currect document */
		file_name[511] = 0;
		XX_httplib_snprintf(conn, &truncated, path, sizeof(path), "%s", ssi);

		if (!truncated) {
			if ((p = strrchr(path, '/')) != NULL) p[1] = '\0';
			len = strlen(path);
			XX_httplib_snprintf(conn, &truncated, path + len, sizeof(path) - len, "%s", file_name);
		}

	} else {
		mg_cry(conn, "Bad SSI #include: [%s]", tag);
		return;
	}

	if (truncated) {
		mg_cry(conn, "SSI #include path length overflow: [%s]", tag);
		return;
	}

	if (!XX_httplib_fopen(conn, path, "rb", &file)) {
		mg_cry(conn, "Cannot open SSI #include: [%s]: fopen(%s): %s", tag, path, strerror(ERRNO));
	} else {
		fclose_on_exec(&file, conn);
		if (XX_httplib_match_prefix(conn->ctx->config[SSI_EXTENSIONS], strlen(conn->ctx->config[SSI_EXTENSIONS]), path) > 0) {

			send_ssi_file(conn, path, &file, include_level + 1);
		} else {
			send_file_data(conn, &file, 0, INT64_MAX);
		}
		XX_httplib_fclose(&file);
	}
}


#if !defined(NO_POPEN)
static void do_ssi_exec(struct mg_connection *conn, char *tag) {

	char cmd[1024] = "";
	struct file file = STRUCT_FILE_INITIALIZER;

	if (sscanf(tag, " \"%1023[^\"]\"", cmd) != 1) {
		mg_cry(conn, "Bad SSI #exec: [%s]", tag);
	} else {
		cmd[1023] = 0;
		if ((file.fp = popen(cmd, "r")) == NULL) {
			mg_cry(conn, "Cannot SSI #exec: [%s]: %s", cmd, strerror(ERRNO));
		} else {
			send_file_data(conn, &file, 0, INT64_MAX);
			pclose(file.fp);
		}
	}
}
#endif /* !NO_POPEN */


static int mg_fgetc(struct file *filep, int offset) {

	if (filep == NULL) return EOF;
	if (filep->membuf != NULL && offset >= 0
	    && ((unsigned int)(offset)) < filep->size) {
		return ((const unsigned char *)filep->membuf)[offset];
	} else if (filep->fp != NULL) {
		return fgetc(filep->fp);
	} else return EOF;
}


static void send_ssi_file(struct mg_connection *conn, const char *path, struct file *filep, int include_level) {

	char buf[MG_BUF_LEN];
	int ch;
	int offset;
	int len;
	int in_ssi_tag;

	if (include_level > 10) {
		mg_cry(conn, "SSI #include level is too deep (%s)", path);
		return;
	}

	in_ssi_tag = len = offset = 0;
	while ((ch = mg_fgetc(filep, offset)) != EOF) {
		if (in_ssi_tag && ch == '>') {
			in_ssi_tag = 0;
			buf[len++] = (char)ch;
			buf[len] = '\0';
			/* assert(len <= (int) sizeof(buf)); */
			if (len > (int)sizeof(buf)) {
				break;
			}
			if (len < 6 || memcmp(buf, "<!--#", 5) != 0) {
				/* Not an SSI tag, pass it */
				(void)mg_write(conn, buf, (size_t)len);
			} else {
				if (!memcmp(buf + 5, "include", 7)) {
					do_ssi_include(conn, path, buf + 12, include_level);
#if !defined(NO_POPEN)
				} else if (!memcmp(buf + 5, "exec", 4)) {
					do_ssi_exec(conn, buf + 9);
#endif /* !NO_POPEN */
				} else mg_cry(conn, "%s: unknown SSI " "command: \"%s\"", path, buf);
			}
			len = 0;
		} else if (in_ssi_tag) {
			if (len == 5 && memcmp(buf, "<!--#", 5) != 0) {
				/* Not an SSI tag */
				in_ssi_tag = 0;
			} else if (len == (int)sizeof(buf) - 2) {
				mg_cry(conn, "%s: SSI tag is too large", path);
				len = 0;
			}
			buf[len++] = (char)(ch & 0xff);
		} else if (ch == '<') {
			in_ssi_tag = 1;
			if (len > 0) {
				mg_write(conn, buf, (size_t)len);
			}
			len = 0;
			buf[len++] = (char)(ch & 0xff);
		} else {
			buf[len++] = (char)(ch & 0xff);
			if (len == (int)sizeof(buf)) {
				mg_write(conn, buf, (size_t)len);
				len = 0;
			}
		}
	}

	/* Send the rest of buffered data */
	if (len > 0) mg_write(conn, buf, (size_t)len);
}


void XX_httplib_handle_ssi_file_request( struct mg_connection *conn, const char *path, struct file *filep ) {

	char date[64];
	time_t curtime;
	const char *cors1;
	const char *cors2;
	const char *cors3;

	if ( conn == NULL  ||  path == NULL  ||  filep == NULL ) return;

	curtime = time( NULL );

	if (mg_get_header(conn, "Origin")) {
		/* Cross-origin resource sharing (CORS). */
		cors1 = "Access-Control-Allow-Origin: ";
		cors2 = conn->ctx->config[ACCESS_CONTROL_ALLOW_ORIGIN];
		cors3 = "\r\n";
	} else {
		cors1 = "";
		cors2 = "";
		cors3 = "";
	}

	if (!XX_httplib_fopen(conn, path, "rb", filep)) {
		/* File exists (precondition for calling this function),
		 * but can not be opened by the server. */
		XX_httplib_send_http_error(conn, 500, "Error: Cannot read file\nfopen(%s): %s", path, strerror(ERRNO));
	} else {
		conn->must_close = 1;
		XX_httplib_gmt_time_string(date, sizeof(date), &curtime);
		fclose_on_exec(filep, conn);
		mg_printf(conn, "HTTP/1.1 200 OK\r\n");
		send_no_cache_header(conn);
		mg_printf(conn,
		          "%s%s%s"
		          "Date: %s\r\n"
		          "Content-Type: text/html\r\n"
		          "Connection: %s\r\n\r\n",
		          cors1,
		          cors2,
		          cors3,
		          date,
		          XX_httplib_suggest_connection_header(conn));
		send_ssi_file(conn, path, filep, 0);
		XX_httplib_fclose(filep);
	}

}  /* XX_httplib_handle_ssi_file_request */


#if !defined(NO_FILES)
void XX_httplib_send_options( struct mg_connection *conn ) {

	char date[64];
	time_t curtime;

	if ( conn == NULL ) return;

	curtime           = time( NULL );
	conn->status_code = 200;
	conn->must_close  = 1;
	XX_httplib_gmt_time_string( date, sizeof(date), &curtime );

	mg_printf(conn,
	          "HTTP/1.1 200 OK\r\n"
	          "Date: %s\r\n"
	          /* TODO: "Cache-Control" (?) */
	          "Connection: %s\r\n"
	          "Allow: GET, POST, HEAD, CONNECT, PUT, DELETE, OPTIONS, "
	          "PROPFIND, MKCOL\r\n"
	          "DAV: 1\r\n\r\n",
	          date,
	          XX_httplib_suggest_connection_header(conn));

}  /* XX_httplib_send_options */


/* Writes PROPFIND properties for a collection element */
static void print_props( struct mg_connection *conn, const char *uri, struct file *filep ) {

	char mtime[64];

	if ( conn == NULL  ||  uri == NULL  ||  filep == NULL ) return;

	XX_httplib_gmt_time_string(mtime, sizeof(mtime), &filep->last_modified);
	conn->num_bytes_sent +=
	    mg_printf(conn,
	              "<d:response>"
	              "<d:href>%s</d:href>"
	              "<d:propstat>"
	              "<d:prop>"
	              "<d:resourcetype>%s</d:resourcetype>"
	              "<d:getcontentlength>%" INT64_FMT "</d:getcontentlength>"
	              "<d:getlastmodified>%s</d:getlastmodified>"
	              "</d:prop>"
	              "<d:status>HTTP/1.1 200 OK</d:status>"
	              "</d:propstat>"
	              "</d:response>\n",
	              uri,
	              filep->is_directory ? "<d:collection/>" : "",
	              filep->size,
	              mtime);
}


static void print_dav_dir_entry(struct de *de, void *data) {

	char href[PATH_MAX];
	char href_encoded[PATH_MAX * 3 /* worst case */];
	int truncated;

	struct mg_connection *conn = (struct mg_connection *)data;
	if (!de || !conn) return;

	XX_httplib_snprintf(conn, &truncated, href, sizeof(href), "%s%s", conn->request_info.local_uri, de->file_name);

	if (!truncated) {
		mg_url_encode(href, href_encoded, PATH_MAX * 3);
		print_props(conn, href_encoded, &de->file);
	}
}


void XX_httplib_handle_propfind( struct mg_connection *conn, const char *path, struct file *filep ) {

	const char *depth = mg_get_header(conn, "Depth");
	char date[64];
	time_t curtime = time(NULL);

	XX_httplib_gmt_time_string(date, sizeof(date), &curtime);

	if (!conn || !path || !filep || !conn->ctx) return;

	conn->must_close = 1;
	conn->status_code = 207;
	mg_printf(conn, "HTTP/1.1 207 Multi-Status\r\n" "Date: %s\r\n", date);
	send_static_cache_header(conn);
	mg_printf(conn, "Connection: %s\r\n" "Content-Type: text/xml; charset=utf-8\r\n\r\n", XX_httplib_suggest_connection_header(conn));

	conn->num_bytes_sent += mg_printf(conn, "<?xml version=\"1.0\" encoding=\"utf-8\"?>" "<d:multistatus xmlns:d='DAV:'>\n");

	/* Print properties for the requested resource itself */
	print_props(conn, conn->request_info.local_uri, filep);

	/* If it is a directory, print directory entries too if Depth is not 0 */
	if (filep && filep->is_directory
	    && !mg_strcasecmp(conn->ctx->config[ENABLE_DIRECTORY_LISTING], "yes")
	    && (depth == NULL || strcmp(depth, "0") != 0)) {
		scan_directory(conn, path, conn, &print_dav_dir_entry);
	}

	conn->num_bytes_sent += mg_printf(conn, "%s\n", "</d:multistatus>");

}  /* XX_httplib_handle_propfind */
#endif

void mg_lock_connection(struct mg_connection *conn) {

	if (conn) pthread_mutex_lock(&conn->mutex);
}

void mg_unlock_connection(struct mg_connection *conn) {

	if (conn) pthread_mutex_unlock(&conn->mutex);
}

void mg_lock_context(struct mg_context *ctx) {

	if (ctx) pthread_mutex_lock(&ctx->nonce_mutex);
}

void mg_unlock_context(struct mg_context *ctx) {

	if (ctx) (void)pthread_mutex_unlock(&ctx->nonce_mutex);
}

#if defined(USE_TIMERS)
#include "timer.inl"
#endif /* USE_TIMERS */

#if defined(USE_WEBSOCKET)

/* START OF SHA-1 code
 * Copyright(c) By Steve Reid <steve@edmweb.com> */
#define SHA1HANDSOFF

/* According to current tests (May 2015), the <solarisfixes.h> is not required.
 *
 * #if defined(__sun)
 * #include "solarisfixes.h"
 * #endif
 */


static int is_big_endian(void) {

	static const int n = 1;
	return ((char *)&n)[0] == 0;
}


union char64long16 {
	unsigned char c[64];
	uint32_t l[16];
};

#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))


static uint32_t blk0(union char64long16 *block, int i) {

	/* Forrest: SHA expect BIG_ENDIAN, swap if LITTLE_ENDIAN */
	if (!is_big_endian()) {
		block->l[i] = (rol(block->l[i], 24) & 0xFF00FF00)
		              | (rol(block->l[i], 8) & 0x00FF00FF);
	}
	return block->l[i];
}

#define blk(i)                                                                 \
	(block->l[i & 15] = rol(block->l[(i + 13) & 15] ^ block->l[(i + 8) & 15]   \
	                            ^ block->l[(i + 2) & 15] ^ block->l[i & 15],   \
	                        1))
#define R0(v, w, x, y, z, i)                                                   \
	z += ((w & (x ^ y)) ^ y) + blk0(block, i) + 0x5A827999 + rol(v, 5);        \
	w = rol(w, 30);
#define R1(v, w, x, y, z, i)                                                   \
	z += ((w & (x ^ y)) ^ y) + blk(i) + 0x5A827999 + rol(v, 5);                \
	w = rol(w, 30);
#define R2(v, w, x, y, z, i)                                                   \
	z += (w ^ x ^ y) + blk(i) + 0x6ED9EBA1 + rol(v, 5);                        \
	w = rol(w, 30);
#define R3(v, w, x, y, z, i)                                                   \
	z += (((w | x) & y) | (w & x)) + blk(i) + 0x8F1BBCDC + rol(v, 5);          \
	w = rol(w, 30);
#define R4(v, w, x, y, z, i)                                                   \
	z += (w ^ x ^ y) + blk(i) + 0xCA62C1D6 + rol(v, 5);                        \
	w = rol(w, 30);


typedef struct {
	uint32_t state[5];
	uint32_t count[2];
	unsigned char buffer[64];
} SHA1_CTX;


static void SHA1Transform(uint32_t state[5], const unsigned char buffer[64]) {

	uint32_t a;
	uint32_t b;
	uint32_t c;
	uint32_t d;
	uint32_t e;
	union char64long16 block[1];

	memcpy(block, buffer, 64);
	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];
	e = state[4];
	R0(a, b, c, d, e, 0);
	R0(e, a, b, c, d, 1);
	R0(d, e, a, b, c, 2);
	R0(c, d, e, a, b, 3);
	R0(b, c, d, e, a, 4);
	R0(a, b, c, d, e, 5);
	R0(e, a, b, c, d, 6);
	R0(d, e, a, b, c, 7);
	R0(c, d, e, a, b, 8);
	R0(b, c, d, e, a, 9);
	R0(a, b, c, d, e, 10);
	R0(e, a, b, c, d, 11);
	R0(d, e, a, b, c, 12);
	R0(c, d, e, a, b, 13);
	R0(b, c, d, e, a, 14);
	R0(a, b, c, d, e, 15);
	R1(e, a, b, c, d, 16);
	R1(d, e, a, b, c, 17);
	R1(c, d, e, a, b, 18);
	R1(b, c, d, e, a, 19);
	R2(a, b, c, d, e, 20);
	R2(e, a, b, c, d, 21);
	R2(d, e, a, b, c, 22);
	R2(c, d, e, a, b, 23);
	R2(b, c, d, e, a, 24);
	R2(a, b, c, d, e, 25);
	R2(e, a, b, c, d, 26);
	R2(d, e, a, b, c, 27);
	R2(c, d, e, a, b, 28);
	R2(b, c, d, e, a, 29);
	R2(a, b, c, d, e, 30);
	R2(e, a, b, c, d, 31);
	R2(d, e, a, b, c, 32);
	R2(c, d, e, a, b, 33);
	R2(b, c, d, e, a, 34);
	R2(a, b, c, d, e, 35);
	R2(e, a, b, c, d, 36);
	R2(d, e, a, b, c, 37);
	R2(c, d, e, a, b, 38);
	R2(b, c, d, e, a, 39);
	R3(a, b, c, d, e, 40);
	R3(e, a, b, c, d, 41);
	R3(d, e, a, b, c, 42);
	R3(c, d, e, a, b, 43);
	R3(b, c, d, e, a, 44);
	R3(a, b, c, d, e, 45);
	R3(e, a, b, c, d, 46);
	R3(d, e, a, b, c, 47);
	R3(c, d, e, a, b, 48);
	R3(b, c, d, e, a, 49);
	R3(a, b, c, d, e, 50);
	R3(e, a, b, c, d, 51);
	R3(d, e, a, b, c, 52);
	R3(c, d, e, a, b, 53);
	R3(b, c, d, e, a, 54);
	R3(a, b, c, d, e, 55);
	R3(e, a, b, c, d, 56);
	R3(d, e, a, b, c, 57);
	R3(c, d, e, a, b, 58);
	R3(b, c, d, e, a, 59);
	R4(a, b, c, d, e, 60);
	R4(e, a, b, c, d, 61);
	R4(d, e, a, b, c, 62);
	R4(c, d, e, a, b, 63);
	R4(b, c, d, e, a, 64);
	R4(a, b, c, d, e, 65);
	R4(e, a, b, c, d, 66);
	R4(d, e, a, b, c, 67);
	R4(c, d, e, a, b, 68);
	R4(b, c, d, e, a, 69);
	R4(a, b, c, d, e, 70);
	R4(e, a, b, c, d, 71);
	R4(d, e, a, b, c, 72);
	R4(c, d, e, a, b, 73);
	R4(b, c, d, e, a, 74);
	R4(a, b, c, d, e, 75);
	R4(e, a, b, c, d, 76);
	R4(d, e, a, b, c, 77);
	R4(c, d, e, a, b, 78);
	R4(b, c, d, e, a, 79);
	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;
	a = b = c = d = e = 0;
	memset(block, '\0', sizeof(block));
}


static void SHA1Init(SHA1_CTX *context) {

	context->state[0] = 0x67452301;
	context->state[1] = 0xEFCDAB89;
	context->state[2] = 0x98BADCFE;
	context->state[3] = 0x10325476;
	context->state[4] = 0xC3D2E1F0;
	context->count[0] = context->count[1] = 0;
}


static void SHA1Update(SHA1_CTX *context, const unsigned char *data, uint32_t len) {

	uint32_t i;
	uint32_t j;

	j = context->count[0];
	if ((context->count[0] += len << 3) < j) context->count[1]++;
	context->count[1] += (len >> 29);
	j = (j >> 3) & 63;
	if ((j + len) > 63) {
		memcpy(&context->buffer[j], data, (i = 64 - j));
		SHA1Transform(context->state, context->buffer);
		for (; i + 63 < len; i += 64) {
			SHA1Transform(context->state, &data[i]);
		}
		j = 0;
	}
	else i = 0;

	memcpy(&context->buffer[j], &data[i], len - i);
}


static void SHA1Final(unsigned char digest[20], SHA1_CTX *context) {

	unsigned i;
	unsigned char finalcount[8];
	unsigned char c;

	for (i = 0; i < 8; i++) {
		finalcount[i] = (unsigned char)((context->count[(i >= 4) ? 0 : 1] >> ((3 - (i & 3)) * 8)) & 255);
	}
	c = 0200;
	SHA1Update(context, &c, 1);
	while ((context->count[0] & 504) != 448) {
		c = 0000;
		SHA1Update(context, &c, 1);
	}
	SHA1Update(context, finalcount, 8);
	for (i = 0; i < 20; i++) {
		digest[i] = (unsigned char)((context->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
	}
	memset(context, '\0', sizeof(*context));
	memset(&finalcount, '\0', sizeof(finalcount));
}
/* END OF SHA1 CODE */


static int send_websocket_handshake(struct mg_connection *conn, const char *websock_key) {

	static const char *magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
	const char *protocol = NULL;
	char buf[100];
	char sha[20];
	char b64_sha[sizeof(sha) * 2];
	SHA1_CTX sha_ctx;
	int truncated;

	/* Calculate Sec-WebSocket-Accept reply from Sec-WebSocket-Key. */
	XX_httplib_snprintf(conn, &truncated, buf, sizeof(buf), "%s%s", websock_key, magic);
	if (truncated) {
		conn->must_close = 1;
		return 0;
	}

	SHA1Init(&sha_ctx);
	SHA1Update(&sha_ctx, (unsigned char *)buf, (uint32_t)strlen(buf));
	SHA1Final((unsigned char *)sha, &sha_ctx);
	base64_encode((unsigned char *)sha, sizeof(sha), b64_sha);
	mg_printf(conn,
	          "HTTP/1.1 101 Switching Protocols\r\n"
	          "Upgrade: websocket\r\n"
	          "Connection: Upgrade\r\n"
	          "Sec-WebSocket-Accept: %s\r\n",
	          b64_sha);
	protocol = mg_get_header(conn, "Sec-WebSocket-Protocol");
	if (protocol) {
		/* The protocol is a comma seperated list of names. */
		/* The server must only return one value from this list. */
		/* First check if it is a list or just a single value. */
		const char *sep = strchr(protocol, ',');
		if (sep == NULL) {
			/* Just a single protocol -> accept it. */
			mg_printf(conn, "Sec-WebSocket-Protocol: %s\r\n\r\n", protocol);
		} else {
			/* Multiple protocols -> accept the first one. */
			/* This is just a quick fix if the client offers multiple
			 * protocols. In order to get the behavior intended by
			 * RFC 6455 (https://tools.ietf.org/rfc/rfc6455.txt), it is
			 * required to have a list of websocket subprotocols accepted
			 * by the server. Then the server must either select a subprotocol
			 * supported by client and server, or the server has to abort the
			 * handshake by not returning a Sec-Websocket-Protocol header if
			 * no subprotocol is acceptable.
			 */
			mg_printf(conn, "Sec-WebSocket-Protocol: %.*s\r\n\r\n", (int)(sep - protocol), protocol);
		}
		/* TODO: Real subprotocol negotiation instead of just taking the first
		 * websocket subprotocol suggested by the client. */
	}
	else mg_printf(conn, "%s", "\r\n");

	return 1;
}


void XX_httplib_read_websocket( struct mg_connection *conn, mg_websocket_data_handler ws_data_handler, void *callback_data ) {

	/* Pointer to the beginning of the portion of the incoming websocket
	 * message queue.
	 * The original websocket upgrade request is never removed, so the queue
	 * begins after it. */
	unsigned char *buf = (unsigned char *)conn->buf + conn->request_len;
	int n;
	int error;
	int exit_by_callback;

	/* body_len is the length of the entire queue in bytes
	 * len is the length of the current message
	 * data_len is the length of the current message's data payload
	 * header_len is the length of the current message's header */
	size_t i;
	size_t len;
	size_t mask_len = 0;
	size_t data_len = 0;
	size_t header_len;
	size_t body_len;

	/* "The masking key is a 32-bit value chosen at random by the client."
	 * http://tools.ietf.org/html/draft-ietf-hybi-thewebsocketprotocol-17#section-5
	*/
	unsigned char mask[4];

	/* data points to the place where the message is stored when passed to
	 * the
	 * websocket_data callback.  This is either mem on the stack, or a
	 * dynamically allocated buffer if it is too large. */
	char mem[4096];
	char *data = mem;
	unsigned char mop; /* mask flag and opcode */
	double timeout;

	timeout = -1.0;

	if (                      conn->ctx->config[WEBSOCKET_TIMEOUT] ) timeout = atoi(conn->ctx->config[WEBSOCKET_TIMEOUT]) / 1000.0;
	if ( timeout <= 0.0  &&  (conn->ctx->config[REQUEST_TIMEOUT])  ) timeout = atoi(conn->ctx->config[REQUEST_TIMEOUT])   / 1000.0;

	XX_httplib_set_thread_name("wsock");

	/* Loop continuously, reading messages from the socket, invoking the
	 * callback, and waiting repeatedly until an error occurs. */
	while (!conn->ctx->stop_flag) {
		header_len = 0;
		assert(conn->data_len >= conn->request_len);
		if ((body_len = (size_t)(conn->data_len - conn->request_len)) >= 2) {
			len = buf[1] & 127;
			mask_len = (buf[1] & 128) ? 4 : 0;
			if ((len < 126) && (body_len >= mask_len)) {
				data_len = len;
				header_len = 2 + mask_len;
			} else if ((len == 126) && (body_len >= (4 + mask_len))) {
				header_len = 4 + mask_len;
				data_len = ((((size_t)buf[2]) << 8) + buf[3]);
			} else if (body_len >= (10 + mask_len)) {
				header_len = 10 + mask_len;
				data_len = (((uint64_t)ntohl(*(uint32_t *)(void *)&buf[2]))
				            << 32) + ntohl(*(uint32_t *)(void *)&buf[6]);
			}
		}

		if (header_len > 0 && body_len >= header_len) {
			/* Allocate space to hold websocket payload */
			data = mem;
			if (data_len > sizeof(mem)) {
				data = (char *)XX_httplib_malloc(data_len);
				if (data == NULL) {
					/* Allocation failed, exit the loop and then close the
					 * connection */
					mg_cry(conn, "websocket out of memory; closing connection");
					break;
				}
			}

			/* Copy the mask before we shift the queue and destroy it */
			if (mask_len > 0) memcpy( mask, buf + header_len - mask_len, sizeof(mask) );
			else              memset( mask, 0,                           sizeof(mask) );

			/* Read frame payload from the first message in the queue into
			 * data and advance the queue by moving the memory in place. */
			assert(body_len >= header_len);
			if (data_len + header_len > body_len) {
				mop = buf[0]; /* current mask and opcode */
				/* Overflow case */
				len = body_len - header_len;
				memcpy(data, buf + header_len, len);
				error = 0;
				while (len < data_len) {
					n = pull( NULL, conn, data + len, (int)(data_len - len), timeout);
					if (n <= 0) {
						error = 1;
						break;
					}
					len += (size_t)n;
				}
				if (error) {
					mg_cry(conn, "Websocket pull failed; closing connection");
					break;
				}
				conn->data_len = conn->request_len;
			} else {
				mop = buf[0]; /* current mask and opcode, overwritten by
				               * memmove() */
				/* Length of the message being read at the front of the
				 * queue */
				len = data_len + header_len;

				/* Copy the data payload into the data pointer for the
				 * callback */
				memcpy(data, buf + header_len, data_len);

				/* Move the queue forward len bytes */
				memmove(buf, buf + len, body_len - len);

				/* Mark the queue as advanced */
				conn->data_len -= (int)len;
			}

			/* Apply mask if necessary */
			if (mask_len > 0) for (i = 0; i < data_len; ++i) data[i] ^= mask[i & 3];

			/* Exit the loop if callback signals to exit (server side),
			 * or "connection close" opcode received (client side). */
			exit_by_callback = 0;
			if ((ws_data_handler != NULL) && !ws_data_handler(conn, mop, data, data_len, callback_data)) {
				exit_by_callback = 1;
			}

			if (data != mem) XX_httplib_free(data);

			if (exit_by_callback || ((mop & 0xf) == WEBSOCKET_OPCODE_CONNECTION_CLOSE)) {
				/* Opcode == 8, connection close */
				break;
			}

			/* Not breaking the loop, process next websocket frame. */
		} else {
			/* Read from the socket into the next available location in the
			 * message queue. */
			if ((n = pull(NULL, conn, conn->buf + conn->data_len, conn->buf_size - conn->data_len, timeout)) <= 0) {
				/* Error, no bytes read */
				break;
			}
			conn->data_len += n;
		}
	}

	XX_httplib_set_thread_name("worker");

}  /* XX_httplib_read_websocket */


static int mg_websocket_write_exec(struct mg_connection *conn, int opcode, const char *data, size_t dataLen, uint32_t masking_key) {

	unsigned char header[14];
	size_t headerLen = 1;

	int retval = -1;

	header[0] = 0x80 + (opcode & 0xF);

	/* Frame format: http://tools.ietf.org/html/rfc6455#section-5.2 */
	if (dataLen < 126) {
		/* inline 7-bit length field */
		header[1] = (unsigned char)dataLen;
		headerLen = 2;
	} else if (dataLen <= 0xFFFF) {
		/* 16-bit length field */
		uint16_t len = htons((uint16_t)dataLen);
		header[1] = 126;
		memcpy(header + 2, &len, 2);
		headerLen = 4;
	} else {
		/* 64-bit length field */
		uint32_t len1 = htonl((uint64_t)dataLen >> 32);
		uint32_t len2 = htonl(dataLen & 0xFFFFFFFF);
		header[1] = 127;
		memcpy(header + 2, &len1, 4);
		memcpy(header + 6, &len2, 4);
		headerLen = 10;
	}

	if (masking_key) {
		/* add mask */
		header[1] |= 0x80;
		memcpy(header + headerLen, &masking_key, 4);
		headerLen += 4;
	}


	/* Note that POSIX/Winsock's send() is threadsafe
	 * http://stackoverflow.com/questions/1981372/are-parallel-calls-to-send-recv-on-the-same-socket-valid
	 * but mongoose's mg_printf/mg_write is not (because of the loop in
	 * push(), although that is only a problem if the packet is large or
	 * outgoing buffer is full). */
	(void)mg_lock_connection(conn);
	retval = mg_write(conn, header, headerLen);
	if (dataLen > 0) retval = mg_write(conn, data, dataLen);
	mg_unlock_connection(conn);

	return retval;
}

int mg_websocket_write(struct mg_connection *conn, int opcode, const char *data, size_t dataLen) {

	return mg_websocket_write_exec(conn, opcode, data, dataLen, 0);

}  /* mg_websocket_write */


static void mask_data(const char *in, size_t in_len, uint32_t masking_key, char *out) {

	size_t i = 0;

	i = 0;
	if ((in_len > 3) && ((ptrdiff_t)in % 4) == 0) {
		/* Convert in 32 bit words, if data is 4 byte aligned */
		while (i < (in_len - 3)) {
			*(uint32_t *)(void *)(out + i) = *(uint32_t *)(void *)(in + i) ^ masking_key;
			i += 4;
		}
	}
	if (i != in_len) {
		/* convert 1-3 remaining bytes if ((dataLen % 4) != 0)*/
		while (i < in_len) {
			*(uint8_t *)(void *)(out + i) = *(uint8_t *)(void *)(in + i) ^ *(((uint8_t *)&masking_key) + (i % 4));
			i++;
		}
	}

}  /* mask_data */


int mg_websocket_client_write(struct mg_connection *conn, int opcode, const char *data, size_t dataLen) {

	int retval = -1;
	char *masked_data = (char *)XX_httplib_malloc(((dataLen + 7) / 4) * 4);
	uint32_t masking_key = (uint32_t)XX_httplib_get_random();

	if (masked_data == NULL) {
		/* Return -1 in an error case */
		mg_cry(conn, "Cannot allocate buffer for masked websocket response: Out of memory");
		return -1;
	}

	mask_data(data, dataLen, masking_key, masked_data);

	retval = mg_websocket_write_exec( conn, opcode, masked_data, dataLen, masking_key );
	XX_httplib_free(masked_data);

	return retval;

}  /* mg_websocket_client_write */


void XX_httplib_handle_websocket_request( struct mg_connection *conn, const char *path, int is_callback_resource, mg_websocket_connect_handler ws_connect_handler, mg_websocket_ready_handler ws_ready_handler, mg_websocket_data_handler ws_data_handler, mg_websocket_close_handler ws_close_handler, void *cbData ) {

	const char *websock_key = mg_get_header(conn, "Sec-WebSocket-Key");
	const char *version = mg_get_header(conn, "Sec-WebSocket-Version");
	int lua_websock = 0;

	(void)path;

	/* Step 1: Check websocket protocol version. */
	/* Step 1.1: Check Sec-WebSocket-Key. */
	if (!websock_key) {
		/* The RFC standard version (https://tools.ietf.org/html/rfc6455)
		 * requires a Sec-WebSocket-Key header.
		 */
		/* It could be the hixie draft version
		 * (http://tools.ietf.org/html/draft-hixie-thewebsocketprotocol-76).
		 */
		const char *key1 = mg_get_header(conn, "Sec-WebSocket-Key1");
		const char *key2 = mg_get_header(conn, "Sec-WebSocket-Key2");
		char key3[8];

		if ((key1 != NULL) && (key2 != NULL)) {
			/* This version uses 8 byte body data in a GET request */
			conn->content_len = 8;
			if (8 == mg_read(conn, key3, 8)) {
				/* This is the hixie version */
				XX_httplib_send_http_error(conn, 426, "%s", "Protocol upgrade to RFC 6455 required");
				return;
			}
		}
		/* This is an unknown version */
		XX_httplib_send_http_error(conn, 400, "%s", "Malformed websocket request");
		return;
	}

	/* Step 1.2: Check websocket protocol version. */
	/* The RFC version (https://tools.ietf.org/html/rfc6455) is 13. */
	if (version == NULL || strcmp(version, "13") != 0) {
		/* Reject wrong versions */
		XX_httplib_send_http_error(conn, 426, "%s", "Protocol upgrade required");
		return;
	}

	/* Step 1.3: Could check for "Host", but we do not really nead this
	 * value for anything, so just ignore it. */

	/* Step 2: If a callback is responsible, call it. */
	if (is_callback_resource) {
		if (ws_connect_handler != NULL
		    && ws_connect_handler(conn, cbData) != 0) {
			/* C callback has returned non-zero, do not proceed with
			 * handshake.
			 */
			/* Note that C callbacks are no longer called when Lua is
			 * responsible, so C can no longer filter callbacks for Lua. */
			return;
		}
	}

	/* Step 4: Check if there is a responsible websocket handler. */
	if (!is_callback_resource && !lua_websock) {
		/* There is no callback, an Lua is not responsible either. */
		/* Reply with a 404 Not Found or with nothing at all?
		 * TODO (mid): check the websocket standards, how to reply to
		 * requests to invalid websocket addresses. */
		XX_httplib_send_http_error(conn, 404, "%s", "Not found");
		return;
	}

	/* Step 5: The websocket connection has been accepted */
	if (!send_websocket_handshake(conn, websock_key)) {
		XX_httplib_send_http_error(conn, 500, "%s", "Websocket handshake failed");
		return;
	}

	/* Step 6: Call the ready handler */
	if (is_callback_resource) {
		if (ws_ready_handler != NULL) ws_ready_handler(conn, cbData);
	}

	/* Step 7: Enter the read loop */
	if (is_callback_resource) XX_httplib_read_websocket(conn, ws_data_handler, cbData);

	/* Step 8: Call the close handler */
	if (ws_close_handler) ws_close_handler(conn, cbData);

}  /* XX_httplib_handle_websocket_request */

#endif /* !USE_WEBSOCKET */


int XX_httplib_is_websocket_protocol( const struct mg_connection *conn ) {

#if defined(USE_WEBSOCKET)
	const char *upgrade;
	const char *connection;

	/* A websocket protocoll has the following HTTP headers:
	 *
	 * Connection: Upgrade
	 * Upgrade: Websocket
	 */

	upgrade = mg_get_header(conn, "Upgrade");
	if (upgrade == NULL) return 0; /* fail early, don't waste time checking other header * fields */

	if (!mg_strcasestr(upgrade, "websocket")) return 0;

	connection = mg_get_header(conn, "Connection");
	if (connection == NULL) return 0;

	if (!mg_strcasestr(connection, "upgrade")) return 0;

	/* The headers "Host", "Sec-WebSocket-Key", "Sec-WebSocket-Protocol" and
	 * "Sec-WebSocket-Version" are also required.
	 * Don't check them here, since even an unsupported websocket protocol
	 * request still IS a websocket request (in contrast to a standard HTTP
	 * request). It will fail later in handle_websocket_request.
	 */

	return 1;

#else  /* defined(USE_WEBSOCKET) */

	return 0;

#endif  /* defined(USE_WEBSOCKET) */

}  /* XX_httplib_is_websocket_protocol */


static int isbyte(int n) {

	return n >= 0 && n <= 255;

}  /* isbyte */


int XX_httplib_parse_net( const char *spec, uint32_t *net, uint32_t *mask ) {

	int n;
	int a;
	int b;
	int c;
	int d;
	int slash = 32;
	int len = 0;

	if ((sscanf(spec, "%d.%d.%d.%d/%d%n", &a, &b, &c, &d, &slash, &n) == 5
	     || sscanf(spec, "%d.%d.%d.%d%n", &a, &b, &c, &d, &n) == 4) && isbyte(a)
	    && isbyte(b) && isbyte(c) && isbyte(d) && slash >= 0
	    && slash < 33) {
		len = n;
		*net = ((uint32_t)a << 24) | ((uint32_t)b << 16) | ((uint32_t)c << 8) | (uint32_t)d;
		*mask = slash ? (0xffffffffU << (32 - slash)) : 0;
	}

	return len;

}  /* XX_httplib_parse_net */


int XX_httplib_set_throttle( const char *spec, uint32_t remote_ip, const char *uri ) {

	int throttle = 0;
	struct vec vec, val;
	uint32_t net, mask;
	char mult;
	double v;

	while ((spec = XX_httplib_next_option(spec, &vec, &val)) != NULL) {
		mult = ',';
		if ((val.ptr == NULL) || (sscanf(val.ptr, "%lf%c", &v, &mult) < 1)
		    || (v < 0) || ((lowercase(&mult) != 'k')
		                   && (lowercase(&mult) != 'm') && (mult != ','))) {
			continue;
		}
		v *= (lowercase(&mult) == 'k') ? 1024 : ((lowercase(&mult) == 'm') ? 1048576 : 1);
		if (vec.len == 1 && vec.ptr[0] == '*') {
			throttle = (int)v;
		} else if (XX_httplib_parse_net(vec.ptr, &net, &mask) > 0) {
			if ((remote_ip & mask) == net) {
				throttle = (int)v;
			}
		} else if (XX_httplib_match_prefix(vec.ptr, vec.len, uri) > 0) throttle = (int)v;
	}

	return throttle;

}  /* XX_httplib_set_throttle */


uint32_t XX_httplib_get_remote_ip( const struct mg_connection *conn ) {

	if ( conn == NULL ) return 0;

	return ntohl(*(const uint32_t *)&conn->client.rsa.sin.sin_addr);

}  /* XX_httplib_get_remote_ip */


/* The mg_upload function is superseeded by mg_handle_form_request. */
#include "handle_form.inl"
