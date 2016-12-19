# LibHTTP API Reference

### `httplib_pthread_mutex_lock( mutex );`

### Parameters

| Parameter | Type | Description |
| :--- | :--- | :--- |
|**`mutex`**|`pthread_mutex_t`|The key to the mutex to lock|

### Return Value

| Type | Description |
| :--- | :--- |
|`int`|Integer value with the result of the function call|

### Description

The platform independent function `httplib_pthread_mutex_lock()` is used to lock a mutex. The function returns **0** if this is succesful, or an error code if it fails. If a mutex is locked by another thread, the function will not return but wait until the other thread releases the mutex and the mutex be successfully locked. On systems which support it, this function is implemented as a direct call to `pthread_mutex_lock()`. On other systems own code is used to emulate the same functionality.

### See Also

* [`httplib_pthread_mutex_destroy();`](httplib_pthread_mutex_destroy.md)
* [`httplib_pthread_mutex_init();`](httplib_pthread_mutex_init.md)
* [`httplib_pthread_mutex_trylock();`](httplib_pthread_mutex_trylock.md)
* [`httplib_pthread_mutex_unlock();`](httplib_pthread_mutex_unlock.md)
