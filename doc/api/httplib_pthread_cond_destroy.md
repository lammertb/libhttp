# LibHTTP API Reference

### `httplib_pthread_cond_destroy( cv );`

### Parameters

| Parameter | Type | Description |
| :--- | :--- | :--- |
|**`cv`**|`pthread_cond_t *`|The condition variable to destroy|

### Return Value

| Type | Description |
| :--- | :--- |
|`int`|Integer value with a success or error code of the function call|

### Description

The platform independent function `httplib_pthread_cond_destroy()` destroys a condition variable previously allocated with a call to [`httplib_pthread_cond_init()`](httplib_pthread_cond_init.md). The function returns **0** when successful and an error code otherwise. On systems which support it, the functionality is implemented as a direct call to `pthread_cond_destroy()`. On other platforms equivalent functionality is implemented with own code.

### See Also

* [`httplib_pthread_cond_broadcast();`](httplib_pthread_cond_broadcast.md)
* [`httplib_pthread_cond_init();`](httplib_pthread_cond_init.md)
* [`httplib_pthread_cond_signal();`](httplib_pthread_cond_signal.md)
* [`httplib_pthread_cond_timedwait();`](httplib_pthread_cond_timedwait.md)
* [`httplib_pthread_cond_wait();`](httplib_pthread_cond_wait.md)
