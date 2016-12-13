# LibHTTP API Reference

### `httplib_unlock_context( ctx );`

### Parameters

| Parameter | Type | Description |
| :--- | :--- | :--- |
|**`ctx`**|`struct httplib_context *`|The context to remove the lock from|

### Return Value

*none*

### Description

The function `httplib_unlock_contect()` removes a lock put previously on a context with a call to [`httplib_lock_context()`](httplib_lock_context.md). Locking a context may be necessary when accessing shared resources.

### See Also

* [`httplib_lock_connection();`](httplib_lock_connection.md)
* [`httplib_lock_context();`](httplib_lock_context.md)
* [`httplib_unlock_connection();`](httplib_unlock_connection.md)
