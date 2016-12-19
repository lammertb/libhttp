# LibHTTP API Reference

### `httplib_pthread_cond_timedwait( cv, mutex, abstime );`

### Parameters

| Parameter | Type | Description |
| :--- | :--- | :--- |
|**`cv`**|`pthread_cond_t`|The condition to wait for|
|**`mutex`**|`pthread_mutex_t *`|The mutex to release when the condition is met|
|**`abstime`**|`const struct timespec *`|structure containing the desired timeout time|

### Return Value

| Type | Description |
| :--- | :--- |
|`int`|Integer value with a success or error code of the function call|

### Description

The platform independent function `httplib_pthread_cond_timedwait()` is used to wait for a specific condition to be met. After the condition is met, the specified mutex is unlocked. If the function succeeds, the value **0** is returned, otherwise the return value is an error code. A timeout value is specified after which the function will return, even if the condition is not met. In the later case an error code indicating the timeout is returned. On systems which support it, the functionality is implemented as a direct call to `pthread_cond_timedwait()`. Otherwise an OS dependent alternative function is called.

### See Also

* [`httplib_pthread_cond_broadcast();`](httplib_pthread_cond_broadcast.md)
* [`httplib_pthread_cond_destroy();`](httplib_pthread_cond_destroy.md)
* [`httplib_pthread_cond_init();`](httplib_pthread_cond_init.md)
* [`httplib_pthread_cond_signal();`](httplib_pthread_cond_signal.md)
* [`httplib_pthread_cond_wait();`](httplib_pthread_cond_wait.md)
