# LibHTTP API Reference

### `httplib_pthread_cond_broadcast( cv );`

### Parameters

| Parameter | Type | Description |
| :--- | :--- | :--- |
|**`cv`**|`pthread_cond_t *`|The condition which a thread is waiting on|

### Return Value

| Type | Description |
| :--- | :--- |
|`int`|Integer value with a success or error code of the function call|

### Description

The platform independent function `httplib_pthread_cond_broadcast()` unlocks all threads waiting on a specific condition. The function returns **0** when successful and an error code otherwise. On systems which support it, the functionality is implemented as a direct call to `pthread_cond_broadcast()`. Otherwise an OS dependent alternative implementation is used to emulate the same behavior.

### See Also

* [`httplib_pthread_cond_destroy();`](httplib_pthread_cond_destroy.md)
* [`httplib_pthread_cond_init();`](httplib_pthread_cond_init.md)
* [`httplib_pthread_cond_signal();`](httplib_pthread_cond_signal.md)
* [`httplib_pthread_cond_timedwait();`](httplib_pthread_cond_timedwait.md)
* [`httplib_pthread_cond_wait();`](httplib_pthread_cond_wait.md)
