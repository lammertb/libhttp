# LibHTTP API Reference

### `httplib_set_request_handler( ctx, uri, handler, cbdata );`

### Parameters

| Parameter | Type | Description |
| :--- | :--- | :--- |
|**`ctx`**|`struct httplib_context *`|The context where the handler must be active|
|**`uri`**|`const char *`|The URI to hook the handler on|
|**`handler`**|`httplib_request_handler`|Callback function doing the heavy lifting|
|**`cbdata`**|`void *`|Optional user supplied data|

`int httplib_request_handler( struct httplib_connection *conn, void *cbdata );`

### Return Value

*none*

### Description

The function `httplib_set_request_handler()` hooks a callback function on a URI. That callback function is called whenever a client requests the specific URI. The callback function receives the connection information and optional user supplied data as parameters and can serve information back to the client. When the callback function does not send any information back to the client, it should return **0** to signal LibHTTP that the LibHTTP core should handle the request. A return value between 1 and 999 is used to tell LibHTTP that the request has been handled and no further processing is necessary. The returned code is stored as the status code in the access log, it is therefore recommended, although not mandatory to return a status code which matches the state of the request.

### See Also

* [`httplib_set_auth_handler();`](httplib_set_auth_handler.md)
