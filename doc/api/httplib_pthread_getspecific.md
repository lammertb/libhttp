# LibHTTP API Reference

### `httplib_pthread_getspecific( key );`

### Parameters

| Parameter | Type | Description |
| :--- | :--- | :--- |
|**`key`**|`pthread_key_t`|The key of the variable to retrieve|

### Return Value

| Type | Description |
| :--- | :--- |
|`void *`|Pointer to the memory area or NULL if no area could be found|

### Description

The platform independent function `httplib_pthread_getspecific()` is used to retrieve a memory area for a thread registered previously with a call to [`httplib_pthread_setspecific()`](httplib_pthread_setspecific.md). If no area could be found, the value `NULL` is returned instead. On systems which support it, the functionality is implemented as a direct call to `pthread_setspecific()`. On other systems own code is used to emulate the same behaviour.

### See Also

* [`httplib_pthread_key_create();`](httplib_pthread_key_create.md)
* [`httplib_pthread_key_delete();`](httplib_pthread_key_delete.md)
* [`httplib_pthread_self();`](httplib_pthread_self.md)
* [`httplib_pthread_setspecific();`](httplib_pthread_setspecific.md)
