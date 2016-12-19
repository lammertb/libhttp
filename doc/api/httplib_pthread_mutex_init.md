# LibHTTP API Reference

### `httplib_pthread_mutex_init( mutex, attr );`

### Parameters

| Parameter | Type | Description |
| :--- | :--- | :--- |
|**`mutex`**|`pthread_mutex_t`|The key to the mutex to initialize|
|**`attr`**|`const pthread_mutexattr_t`|Optional attributes for the initialization|

### Return Value

| Type | Description |
| :--- | :--- |
|`int`|Integer value with the result of the function|

### Description

The platform independent function `httplib_pthread_mutex_init()` is used to initialize a mutex. The function returns **0** if this is successful, or an error code if it fails. On systems which support it, this function is implemented as a direct call to `pthread_mutex_init()`. On other systems own code is used to emulate the same functionality.

Please not that on systems which do not support `pthread_mutex_init()` natively that the `attr` parameter is ignored.

### See Also

* [`httplib_pthread_mutex_destroy();`](httplib_pthread_mutex_destroy.md)
* [`httplib_pthread_mutex_lock();`](httplib_pthread_mutex_lock.md)
* [`httplib_pthread_mutex_trylock();`](httplib_pthread_mutex_trylock.md)
* [`httplib_pthread_mutex_unlock();`](httplib_pthread_mutex_unlock.md)
