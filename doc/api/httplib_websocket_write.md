# LibHTTP API Reference

### `httplib_websocket_write( conn, opcode, data, data_len );`

### Parameters

| Parameter | Type | Description |
| :--- | :--- | :--- |
|**`conn`**|`struct httplib_connection *`|Connection on which the data must be written|
|**`opcode`**|`int`|Opcode|
|**`data`**|`const char *`|Data to be written to the client|
|**`data_len`**|`size_t`|Length of the data|

### Return Value

| Type | Description |
| :--- | :--- |
|`int`|Number of bytes written or an error code|

### Description

The function `httplib_websocket_write()` sends data to a websocket client wrapped in a websocket frame. The function issues calls to [`httplib_lock_connection()`](httplib_lock_connection.md) and [`httplib_unlock_connaction()`](httplib_unlock_connection.md) to ensure that the transmission is not interrupted. Data corruption can otherwise happn if the application is proactively communicating and responding to a request simultaneously.

The function is available only when LibHTTP is compiled with the `-DUSE_WEBSOCKET` option.

The function returns the number of bytes written, **0** when the connection has been closed and **-1** if an error occured.

### See Also

* [`httplib_lock_connection();`](httplib_lock_connection.md)
* [`httplib_printf();`](httplib_printf.md)
* [`httplib_unlock_connection();`](httplib_unlock_connection.md)
* [`httplib_websocket_client_write();`](httplib_websocket_client_write.md)
* [`httplib_write();`](httplib_write.md)
