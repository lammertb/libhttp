# LibHTTP API Reference

### `httplib_pthread_cond_init( cv, attr );`

### Parameters

| Parameter | Type | Description |
| :--- | :--- | :--- |
|**`cv`**|`pthread_cond_t *`|Storage for the condition variable when the function is successful|
|**`attr`**|`const pthread_condattr_t *`|Optional attributes for creating the condition variable|


### Return Value

| Type | Description |
| :--- | :--- |
|`int`|Integer value with a success or error code of the function call|

### Description

The platform independent function `htptlib_pthread_cond_init()` allocates a condition variable which can be used for letting threads wait for a specific condition. The variable is returned in a location pointed to by a parameter. If the function is successful the value **0** is returned. Otherwise the function returns an error code. On systems which support it, the functionality is implemented as a direct call to `pthrea_cond_init()`. Otherwise own code is used which emulates the same behaviour. Please note that the `attr` parameter is ignored when the function is used on Windows.

### See Also

* [`httplib_pthread_cond_broadcast();`](httplib_pthread_cond_broadcast.md)
* [`httplib_pthread_cond_destroy();`](httplib_pthread_cond_destroy.md)
* [`httplib_pthread_cond_signal();`](httplib_pthread_cond_signal.md)
* [`httplib_pthread_cond_timedwait();`](httplib_pthread_cond_timedwait.md)
* [`httplib_pthread_cond_wait();`](httplib_pthread_cond_wait.md)
