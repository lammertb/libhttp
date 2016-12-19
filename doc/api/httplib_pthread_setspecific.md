# LibHTTP API Reference

### `httplib_pthread_setspecific( key, value );`

### Parameters

| Parameter | Type | Description |
| :--- | :--- | :--- |
|**`key`**|`pthread_key_t`|The key of the variable to set|
|**`value`**|`const void *`|The value to be assigned to the key|

### Return Value

| Type | Description |
| :--- | :--- |
|`int`|Integer value with the result of the function|

### Description

The platform independent function `httplib_pthread_setspecific()` is used to set a key value for a previously obtained thread specific key. The function returns **0** when successful and an error code if something went wrong. On systems which support it, the functionality is implemented as a direct call to `pthread_setspecific()`. Otherwise an OS dependent alternative function is called.

### See Also

* [`httplib_pthread_getspecific();`](httplib_pthread_getspecific.md)
* [`httplib_pthread_key_create();`](httplib_pthread_key_create.md)
* [`httplib_pthread_key_delete();`](httplib_pthread_key_delete.md)
* [`httplib_pthread_self();`](httplib_pthread_self.md)
