# Libhttp API Reference

### `httplib_unlock_connection( conn );`

### Parameters

| Parameter | Type | Description |
| :--- | :--- | :--- |
|**`conn`**|`struct httplib_connection *`|Connection to remove the lock from|

### Return Value

*none*

### Description

The function `httplib_unlock_connection()` removes the lock on a connection which was previously set with a call to [`httplib_lock_connection()`](httplib_lock_connection.md). Locking may be necessary when using [`httplib_write()`](httplib_write.md) or [`httplib_printf()`](httplib_printf.md) on websocket connections to prevent data corruption.

### See Also

* [`httplib_lock_connection();`](httplib_lock_connection.md)
* [`httplib_lock_context();`](httplib_lock_context.md)
* [`httplib_printf();`](httplib_printf.md)
* [`httplib_unlock_context();`](httplib_unlock_context.md)
* [`httplib_websocket_client_write();`](httplib_websocket_client_write.md)
* [`httplib_websocket_write();`](httplib_websocket_write.md)
* [`httplib_write();`](httplib_write.md)
