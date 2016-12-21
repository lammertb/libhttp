# LibHTTP API Reference

### `httplib_pthread_join( thread, value_ptr );`

### Parameters

| Parameter | Type | Description |
| :--- | :--- | :--- |
|**`key`**|`pthread_t`|The ID of the thread to join|
|**`value_ptr`**|`void *`|Optional pointer to location where the terminating thread stored exit information|

### Return Value

| Type | Description |
| :--- | :--- |
|`int`|Integer value with the result of the function|

### Description

The platform independent function `httplib_pthread_join()` suspends the execution of the current thread and waits until another thread specified as parameter has terminated. The function returns **0** when successful and a non zero error code if something goes wrong. On systems which support it, the functionality is implemented as a direct call to `pthread_join()`. Otherwise own code is used which emulates the same functionality.

The parameter `value_ptr` is an optional pointer to a location where an exit pointer of the terminated thread is stored. If this parameter is `NULL` no exit information will be sent back. Please note that the `value_ptr` has only be implemented on systems which use a fall-through to `pthread_join()` but is ignored in other implementations.

### See Also

* [`httplib_pthread_getspecific();`](httplib_pthread_getspecific.md)
* [`httplib_pthread_key_create();`](httplib_pthread_key_create.md)
* [`httplib_pthread_key_delete();`](httplib_pthread_key_delete.md)
* [`httplib_pthread_self();`](httplib_pthread_self.md)
* [`httplib_pthread_setspecific();`](httplib_pthread_setspecific.md)
