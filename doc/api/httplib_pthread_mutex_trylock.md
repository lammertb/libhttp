# LibHTTP API Reference

### `httplib_pthread_mutex_trylock( mutex );`

### Parameters

| Parameter | Type | Description |
| :--- | :--- | :--- |
|**`mutex`**|`pthread_mutex_t`|The key to the mutex to try to lock|

### Return Value

| Type | Description |
| :--- | :--- |
|`int`|Integer value with the result of the function|

### Description

The platform independent function `httplib_pthread_mutex_trylock()` is used to try to lock a mutex. The function returns **0** if this is succesful, or an error code if it fails. Depending on the error code the parameter my be invalid, or the mutex is already locked. On systems which support it, this function is implemented as a direct call to `pthread_mutex_trylock()`. On other systems own code is used to emulate the same functionality.

### See Also

* [`httplib_pthread_mutex_destroy();`](httplib_pthread_mutex_destroy.md)
* [`httplib_pthread_mutex_init();`](httplib_pthread_mutex_init.md)
* [`httplib_pthread_mutex_lock();`](httplib_pthread_mutex_lock.md)
* [`httplib_pthread_mutex_unlock();`](httplib_pthread_mutex_unlock.md)
