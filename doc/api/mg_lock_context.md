# LibHTTP API Reference

### `httplib_lock_context( ctx );`

### Parameters

| Parameter | Type | Description |
| :--- | :--- | :--- |
|**`ctx`**|`struct httplib_context *`|The context to put the lock on|

### Return Value

*none*

### Description

The function `httplib_lock_context()` can be used to acquire a lock for exclusive access to resources which are shared between connection of threads. The lock is context wide. The lock must be released with a call to [`httplib_unlock_context()`](httplib_unlock_context.md).

### See Also

* [`httplib_lock_connection();`](httplib_lock_connection.md)
* [`httplib_unlock_connection();`](httplib_unlock_connection.md)
* [`httplib_unlock_context();`](httplib_unlock_context.md)
