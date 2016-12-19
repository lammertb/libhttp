# LibHTTP API Reference

### `httplib_pthread_mutex_destroy( mutex );`

### Parameters

| Parameter | Type | Description |
| :--- | :--- | :--- |
|**`mutex`**|`pthread_mutex_t`|The key to the mutex to destroy|

### Return Value

| Type | Description |
| :--- | :--- |
|`int`|Integer value with the result of the function|

### Description

The platform independent function `httplib_pthread_mutex_destroy()` destroys a mutex and frees the allocated resources. The function returns **0** if this is successful, or an error code if it fails. If a mutex is locked by another thread the function will return with an error code. On systems which support it, this function is implemented as a wrapper around `pthread_mutex_destroy()`. On other systems own code is used to emulate the same functionality.

### See Also

* [`httplib_pthread_mutex_init();`](httplib_pthread_mutex_init.md)
* [`httplib_pthread_mutex_lock();`](httplib_pthread_mutex_lock.md)
* [`httplib_pthread_mutex_trylock();`](httplib_pthread_mutex_trylock.md)
* [`httplib_pthread_mutex_unlock();`](httplib_pthread_mutex_unlock.md)
