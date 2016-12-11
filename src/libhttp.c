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


bool XX_httplib_is_file_opened( const struct file *filep ) {

	if ( filep == NULL ) return false;

	return ( filep->membuf != NULL  ||  filep->fp != NULL );

}  /* XX_httplib_is_file_opened */


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

	return XX_httplib_is_file_opened(filep);

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
char * XX_httplib_skip_quoted( char **buf, const char *delimiters, const char *whitespace, char quotechar ) {

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
			/* This happens, e.g., in calls from XX_httplib_parse_auth_header,
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

}  /* XX_httplib_skip_quoted */


/* Simplified version of XX_httplib_skip_quoted without quote char
 * and whitespace == delimiters */
char *XX_httplib_skip( char **buf, const char *delimiters ) {

	return XX_httplib_skip_quoted( buf, delimiters, delimiters, 0 );

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
		 * functions like XX_httplib_is_file_opened() check the struct. */
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
			XX_httplib_fgets(buf, sizeof(buf), &file, &p);
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
