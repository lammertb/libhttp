# LibHTTP API Reference

### `httplib_pthread_self();`

### Parameters

*none*

### Return Value

| Type | Description |
| :--- | :--- |
|`pthread_t`|An identifier specific for the current thread|

### Description

The function `httplib_pthread_self()` is a platform indepent function which returns an identifier which identifies the current thread. On systems which support it this is done with a call to the `pthread_self()` function. On other systems an OS specific function is used with equivalent functionality.

### See Also

* [`httplib_pthread_getspecific();`](httplib_pthread_getspecific.md)
* [`httplib_pthread_setspecific();`](httplib_pthread_setspecific.md)
