# LibHTTP API Reference

### `httplib_lock_connection( conn );`

### Parameters

| Parameter | Type | Description |
| :--- | :--- | :--- |
|**`conn`**|`struct httplib_connection *`|The connection to retrieve a lock|

### Return Value

*none*

### Description

The function `httplib_lock_connection()` is specifically for websocket connections to lock connection. Using this function in combination with [`httplib_unlock_connection();`](httplib_unlock_connection.md) is necessary around [`httplib_write()`](httplib_write.md) and [`httplib_printf()`](httplib_printf.md) calls if the code has server-initiated communication, as well as with communication in direct response to a message.

### See Also

* [`httplib_lock_context();`](httplib_lock_context.md)
* [`httplib_printf();`](httplib_printf.md)
* [`httplib_unlock_connection();`](httplib_unlock_connection.md)
* [`httplib_unlock_context();`](httplib_unlock_context.md)
* [`httplib_websocket_client_write();`](httplib_websocket_client_write.md)
* [`httplib_websocket_write();`](httplib_websocket_write.md)
* [`httplib_write();`](httplib_write.md)
