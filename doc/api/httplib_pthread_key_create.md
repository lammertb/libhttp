# LibHTTP API Reference

### `httplib_pthread_key_create( key, destructor );`

### Parameters

| Parameter | Type | Description |
| :--- | :--- | :--- |
|**`key`**|`pthread_key_t`|The key of the variable to set|
|**`destructor`**|`void (*destructor)(void *)`|Pointer to a destructor function to be called when the key is destroyed, or NULL if no destructor functionality is needed|

### Return Value

| Type | Description |
| :--- | :--- |
|`int`|Integer value with the result of the function|

### Description

The platform independent function `httplib_pthread_key_create()` creates a key to a memory area for thread specific data storage. The function returns **0** when successful and an error code if something went wrong. On systems which support it, the functionality is implemented as a direct call to `pthread_key_create()`. Otherwise own code is used to emulate the same behaviour.

Please not that on systems which don't support the `pthread_key_create()` function natively that the `destructor` parameter is ignored. For multiplatform execution you should check that this will not cause problems regarding the functionality.

### See Also

* [`httplib_pthread_getspecific();`](httplib_pthread_getspecific.md)
* [`httplib_pthread_key_delete();`](httplib_pthread_key_delete.md)
* [`httplib_pthread_setspecific();`](httplib_pthread_setspecific.md)
* [`httplib_pthread_self();`](httplib_pthread_self.md)
