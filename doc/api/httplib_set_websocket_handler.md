# LibHTTP API Reference

### `httplib_set_websocket_handler( ctx, uri, connect_handler, ready_handler, data_handler, close_handler, cbdata );`

### Parameters

| Parameter | Type | Description |
| :--- | :--- | :--- |
|**`ctx`**|`httplib_context *`|The context in which to add the handlers|
|**`uri`**|`const char *`|The URI for which the handlers should be activated|
|**`connect_handler`**|`httplib_websocket_connect_handler`|Handler called when a connect is signalled|
|**`ready_handler`**|`httplib_websocket_ready_handler`|Handler called when the connection is ready|
|**`data_handler`**|`httplib_websocket_data_handler`|Handler called when data is received|
|**`close_handler`**|`httplib_websocket_close_handler`|Handler called when the connection closes|
|**`cbdata`**|`void *`|User defined data|

`int httplib_websocket_connect_handler( const struct httplib_connection *conn, void *cbdata );`
`int httplib_websocket_ready_handler( struct httplib_connection *conn, void *cbdata );`
`int httplib_websocket_data_handler( struct httplib_connection *conn, int opcode, char * buf, size_t buf_len, void *cbdata );`
`int httplib_websocket_close_handler( const struct httplib_connection *conn,  void *cbdata );`

### Return Value

*none*

### Description

The function `httplib_set_websocket_handler()` connects callback functions to a websocket URI. The callback functions are called when a state change is detected on the URI like an incomming connection or data received from a remote peer.

### See Also
