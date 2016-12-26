# LibHTTP API Reference

### `httplib_connect_client_secure( client_options, error_buffer, error_buffer_size );`

### Parameters

| Parameter | Type | Description |
| :--- | :--- | :--- |
|**`client_options`**|`const struct httplib_client_options *`|Settings about the server connection|
|**`error_buffer`**|`char *`|Buffer to store an error message|
|**`error_buffer_size`**|`size_t`|Size of the error message buffer including the NUL terminator|

### Return Value

| Type | Description |
| :--- | :--- |
|`struct httplib_connection *`|Pointer to the connection information or NULL if an error occured|

### Description

The function `httplib_connect_client_secure()` creates a secure connection with a server. The information about the connection and server is passed in a structure and an error message may be returned in a local buffer. The function returns a pointer to a `struct httplib_connection` structure when successful and NULL otherwise.

### See Also

* [`struct httplib_client_options;`](httplib_client_options.md)
* [`httplib_connect_client();`](httplib_connect_client.md)
* [`httplib_connect_websocket_client();`](httplib_connect_websocket_client.md)
