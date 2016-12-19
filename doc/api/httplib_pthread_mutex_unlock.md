# LibHTTP API Reference

### `httplib_pthread_mutex_unlock( mutex );`

### Parameters

| Parameter | Type | Description |
| :--- | :--- | :--- |
|**`mutex`**|`pthread_mutex_t`|The key to the mutex to unlock|

### Return Value

| Type | Description |
| :--- | :--- |
|`int`|Integer value with the result of the function|

### Description

The platform independent function `httplib_pthread_mutex_unlock()` is used to remove a lock on a mutex after processing a critical section is finished. The function returns **0** when successful, or a non zero value with error number if something went wrong. On systems which support it, this function is implemented as a direct call to `pthread_mutex_unlock()`. For other systems an equivalent functionality has been coded in own code.

### See Also

* [`httplib_pthread_mutex_destroy();`](httplib_pthread_mutex_destroy.md)
* [`httplib_pthread_mutex_init();`](httplib_pthread_mutex_init.md)
* [`httplib_pthread_mutex_lock();`](httplib_pthread_mutex_lock.md)
* [`httplib_pthread_mutex_trylock();`](httplib_pthread_mutex_trylock.md)
