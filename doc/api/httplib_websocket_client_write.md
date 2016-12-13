# LibHTTP API Reference

### `httplib_websocket_client_write( conn, opcode, data, data_len );`

### Parameters

| Parameter | Type | Description |
| :--- | :--- | :--- |
|**`conn`**|`struct httplib_connection *`|Connection on which to send data|
|**`opcode`**|`int`|Opcode|
|**`data const`**|`char *`|The data to be written|
|**`data_len`**|`size_t`|Length of the data buffer|

### Return Value

| Type | Description |
| :--- | :--- |
|`int`|Number of bytes written or an error code|

### Description

The function `httplib_websocket_client_write()` sends data to a websocket server wrapped in a masked websocket frame. The function issues calls to [`httplib_lock_connection()`](httplib_lock_connection.md) and [`httplib_unlock_connection()`](httplib_unlock_connection.md) to ensure that the transmission is not interrupted. Interruption can happen the the application is proactively communicating and responding to a request simultaneously. This function is available only, if LibHTTP is compiled with the option `-DUSE_WEBSOCKET`.

The return value is the number of bytes written on success, **0** when the connection has been closed and **-1** if an error occured.

### See Also

* [`httplib_lock_connection();`](httplib_lock_connection.md)
* [`httplib_printf();`](httplib_printf.md)
* [`httplib_unlock_connection();`](httplib_unlock_connection.md)
* [`httplib_websocket_write();`](httplib_websocket_write.md)
* [`httplib_write();`](httplib_write.md)
