# LibHTTP API Reference

### `httplib_pthread_key_delete( key );`

### Parameters

| Parameter | Type | Description |
| :--- | :--- | :--- |
|**`key`**|`pthread_key_t`|The key to delete|

### Return Value

| Type | Description |
| :--- | :--- |
|`int`|Integer value with the result of the function|

### Description

The platform independent function `httplib_pthread_key_delete()` is used to delete a previously allocated key to thread specific data memory. The function returns **0** when succesful or an error code if something went wrong. On systems which support it, the functionality is implemented as a direct call to `pthread_key_delete()`. Otherwise own code is used with equivalent functionality.

### See Also

* [`httplib_pthread_getspecific();`](httplib_pthread_getspecific.md)
* [`httplib_pthread_key_create();`](httplib_pthread_key_create.md)
* [`httplib_pthread_self();`](httplib_pthread_self.md)
* [`httplib_pthread_key_setspecific();`](httplib_pthread_setspecific.md)
