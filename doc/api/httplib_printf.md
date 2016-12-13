# LibHTTP API Reference

### `httplib_printf( conn, fmt, ... );`

### Parameters

| Parameter | Type | Description |
| :--- | :--- | :--- |
|**`conn`**|`struct httplib_connection *`|The connection over which the data must be sent|
|**`fmt`**|`const char *`|Format string|
|**`...`**|*various*|Parameters as specified in the format string|

### Return Value

| Type | Description |
| :--- | :--- |
|`int`|Number of bytes written or an error code|

### Description

The function `httplib_printf()` can be used to send formatted strings over a connection. The functionality is comparable to the `printf()` family of functions in the standard C library. The function returns **0** when the connection has been closed, **-1** if an error occurred and otherwise the number of bytes written over the connection. Except for the formatting part, the `httplib_printf()` function is identical to the function [`httplib_write()`](httplib_write.md).

### See Also

* [`httplib_websocket_client_write();`](httplib_websocket_client_write.md)
* [`httplib_websocket_write();`](httplib_websocket_write.md)
* [`httplib_write();`](httplib_write.md)
