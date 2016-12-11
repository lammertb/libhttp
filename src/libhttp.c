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
#define vsnprintf DO_NOT_USE_THIS_FUNCTION__USE_httplib_vsnprintf
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


int XX_httplib_lowercase(const char *s) {

	return tolower(*(const unsigned char *)s);

}  /* XX_httplib_lowercase */


int mg_strncasecmp(const char *s1, const char *s2, size_t len) {

	int diff = 0;

	if (len > 0) {
		do {
			diff = XX_httplib_lowercase(s1++) - XX_httplib_lowercase(s2++);
		} while (diff == 0 && s1[-1] != '\0' && --len > 0);
	}

	return diff;
}


int mg_strcasecmp(const char *s1, const char *s2) {

	int diff;

	do {
		diff = XX_httplib_lowercase(s1++) - XX_httplib_lowercase(s2++);
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


const char * XX_httplib_strcasestr( const char *big_str, const char *small_str ) {

	size_t i;
	size_t big_len = strlen(big_str);
	size_t small_len = strlen(small_str);

	if (big_len >= small_len) {
		for (i = 0; i <= (big_len - small_len); i++) {
			if (mg_strncasecmp(big_str + i, small_str, small_len) == 0) return big_str + i;
		}
	}

	return NULL;

}  /* XX_httplib_strcasestr */



/* Return null terminated string of given maximum length.
 * Report errors if length is exceeded. */
void XX_httplib_vsnprintf( const struct mg_connection *conn, int *truncated, char *buf, size_t buflen, const char *fmt, va_list ap ) {

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

}  /* XX_httplib_vsnprintf */


void XX_httplib_snprintf( const struct mg_connection *conn, int *truncated, char *buf, size_t buflen, const char *fmt, ... ) {

	va_list ap;

	va_start(ap, fmt);
	XX_httplib_vsnprintf(conn, truncated, buf, buflen, fmt, ap);
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
double XX_httplib_difftimespec(const struct timespec *ts_now, const struct timespec *ts_before) {

	return (double)(ts_now->tv_nsec - ts_before->tv_nsec) * 1.0E-9
	       + (double)(ts_now->tv_sec - ts_before->tv_sec);

}  /* XX_httplib_difftimespec */


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
char *XX_httplib_skip( char **buf, const char *delimiters ) {

	return skip_quoted( buf, delimiters, delimiters, 0 );

}  /* XX_httplib_skip */


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
int XX_httplib_header_has_option( const char *header, const char *option ) {

	struct vec opt_vec;
	struct vec eq_vec;

	assert(option != NULL);
	assert(option[0] != '\0');

	while ((header = XX_httplib_next_option(header, &opt_vec, &eq_vec)) != NULL) {
		if (mg_strncasecmp(option, opt_vec.ptr, opt_vec.len) == 0) return 1;
	}

	return 0;

}  /* XX_httplib_header_has_option */


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
		} else if (XX_httplib_lowercase(&pattern[i]) != XX_httplib_lowercase(&str[j])) {
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
		    || (header != NULL && !XX_httplib_header_has_option(header, "keep-alive"))
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


int XX_httplib_send_no_cache_header( struct mg_connection *conn ) {

	/* Send all current and obsolete cache opt-out directives. */
	return mg_printf(conn,
	                 "Cache-Control: no-cache, no-store, "
	                 "must-revalidate, private, max-age=0\r\n"
	                 "Pragma: no-cache\r\n"
	                 "Expires: 0\r\n");

}  /* XX_httplib_send_no_cache_header */


int XX_httplib_send_static_cache_header(struct mg_connection *conn) {

#if !defined(NO_CACHING)
	/* Read the server config to check how long a file may be cached.
	 * The configuration is in seconds. */
	int max_age = atoi(conn->ctx->config[STATIC_FILE_MAX_AGE]);
	if (max_age <= 0) {
		/* 0 means "do not cache". All values <0 are reserved
		 * and may be used differently in the future. */
		/* If a file should not be cached, do not only send
		 * max-age=0, but also pragmas and Expires headers. */
		return XX_httplib_send_no_cache_header(conn);
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
	return XX_httplib_send_no_cache_header(conn);
#endif /* !NO_CACHING */

}  /* XX_httplib_send_static_cache_header */


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
		XX_httplib_send_no_cache_header(conn);
		if (has_body) mg_printf(conn, "%s", "Content-Type: text/plain; charset=utf-8\r\n");
		mg_printf(conn, "Date: %s\r\n" "Connection: close\r\n\r\n", date);

		/* Errors 1xx, 204 and 304 MUST NOT send a body */
		if (has_body) {
			mg_printf(conn, "Error %d: %s\n", status, status_text);

			if (fmt != NULL) {
				va_start(ap, fmt);
				XX_httplib_vsnprintf(conn, NULL, buf, sizeof(buf), fmt, ap);
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


pid_t XX_httplib_spawn_process( struct mg_connection *conn, const char *prog, char *envblk, char *envp[], int fdin[2], int fdout[2], int fderr[2], const char *dir ) {

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

	if (pi.hThread != NULL) CloseHandle(pi.hThread);

	return (pid_t)pi.hProcess;

}  /* XX_httplib_spawn_process */

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
pid_t XX_httplib_spawn_process( struct mg_connection *conn, const char *prog, char *envblk, char *envp[], int fdin[2], int fdout[2], int fderr[2], const char *dir ) {

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

}  /* XX_httplib_spawn_process */

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

	} while ((timeout <= 0) || (XX_httplib_difftimespec(&now, &start) <= timeout));

	(void)err; /* Avoid unused warning if NO_SSL is set and DEBUG_TRACE is not
	              used */

	return -1;
}


int64_t XX_httplib_push_all(struct mg_context *ctx, FILE *fp, SOCKET sock, SSL *ssl, const char *buf, int64_t len) {

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

}  /* XX_httplib_push_all */


/* Read from IO channel - opened file descriptor, socket, or SSL descriptor.
 * Return negative value on error, or number of bytes read on success. */
int XX_httplib_pull( FILE *fp, struct mg_connection *conn, char *buf, int len, double timeout ) {

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
	} while ((timeout <= 0) || (XX_httplib_difftimespec(&now, &start) <= timeout));

	/* Timeout occured, but no data available. */
	return -1;

}  /* XX_httplib_pull */


int XX_httplib_pull_all( FILE *fp, struct mg_connection *conn, char *buf, int len ) {

	int n;
	int nread = 0;
	double timeout = -1.0;

	if (conn->ctx->config[REQUEST_TIMEOUT]) {
		timeout = atoi(conn->ctx->config[REQUEST_TIMEOUT]) / 1000.0;
	}

	while (len > 0 && conn->ctx->stop_flag == 0) {
		n = XX_httplib_pull(fp, conn, buf + nread, len, timeout);
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

}  /* XX_httplib_pull_all */


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
		if ((n = XX_httplib_pull_all(NULL, conn, (char *)buf, (int)len64)) >= 0) {
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
		if ((total = XX_httplib_push_all(conn->ctx,
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
				if ((n = XX_httplib_push_all(conn->ctx,
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
	
	else total = XX_httplib_push_all(conn->ctx, NULL, conn->client.sock, conn->ssl, (const char *)buf, (int64_t)len);

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
	for (; (s = XX_httplib_strcasestr(s, var_name)) != NULL; s += name_len) {
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
void XX_httplib_base64_encode( const unsigned char *src, int src_len, char *dst ) {

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

}  /* XX_httplib_base64_encode */
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
int XX_httplib_get_request_len( const char *buf, int buflen ) {

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

}  /* XX_httplib_get_request_len */


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
time_t XX_httplib_parse_date_string( const char *datetime ) {

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

}  /* XX_httplib_parse_date_string */

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
void XX_httplib_get_mime_type( struct mg_context *ctx, const char *path, struct vec *vec ) {

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

}  /* XX_httplib_get_mime_type */


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
	XX_httplib_send_no_cache_header(conn);
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


void XX_httplib_print_dir_entry( struct de *de ) {

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

}  /* XX_httplib_print_dir_entry */


/* This function is called from send_directory() and used for
 * sorting directory entries by size, or name, or modification time.
 * On windows, __cdecl specification is needed in case if project is built
 * with __stdcall convention. qsort always requires __cdels callback. */
int WINCDECL XX_httplib_compare_dir_entries( const void *p1, const void *p2 ) {

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

}  /* XX_httplib_compare_dir_entries */
