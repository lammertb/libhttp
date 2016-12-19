/* 
 * Copyright (C) 2016 Lammert Bies
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



extern pthread_mutex_t *	XX_httplib_ssl_mutexes;
extern pthread_key_t		XX_httplib_sTlsKey;
extern int			XX_httplib_thread_idx_max;



#if defined(_WIN32)

int		pthread_cond_broadcast( pthread_cond_t *cv );
int		pthread_cond_destroy( pthread_cond_t *cv );
int		pthread_cond_init( pthread_cond_t *cv, const void *unused );
int		pthread_cond_signal( pthread_cond_t *cv );
int		pthread_cond_timedwait( pthread_cond_t *cv, pthread_mutex_t *mutex, const struct timespec *abstime );
int		pthread_cond_wait( pthread_cond_t *cv, pthread_mutex_t *mutex );

int		pthread_key_create( pthread_key_t *key, void (*destructor)(void *) );

void *		pthread_getspecific( pthread_key_t key );

#endif  /* _WIN32 */
