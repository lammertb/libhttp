# LibHTTP API Reference

### `httplib_connect_client( host, port, use_ssl, error_buffer, error_buffer_size );`

### Parameters

| Parameter | Type | Description |
| :--- | :--- | :--- |
|**`host`**|`const char *`|hostname or IP address of the server|
|**`port`**|`int`|The port to connect to on the server|
|**`use_ssl`**|`int`|Connects using SSL of this value is not zero|
|**`error_buffer`**|`char *`|Buffer to store an error message|
|**`error_buffer_size`**|`size_t`|Maximum size of the error buffer including the NUL terminator|

### Return Value

| Type | Description |
| :--- | :--- |
|`struct httplib_connection *`|A pointer to the connection or NULL when an error occurs|

### Description

The function `httplib_connect_client()` connects to a TCP server as a client. This server can be a HTTP server but this is not necessary. The function returns a pointer to a connection structure when the connection is established and NULL otherwise.
 
### See Also

* [`httplib_connect_client_secure();`](httplib_connect_client_secure.md)
* [`httplib_connect_websocket_client();`](httplib_connect_websocket_client.md)
