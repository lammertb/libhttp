# LibHTTP API Reference

### `httplib_set_auth_handler( ctx, uri, handler, cbdata );`

### Parameters

| Parameter | Type | Description |
| :--- | :--- | :--- |
|**`ctx`**|`struct httplib_context *`|The context on which the handler must be set|
|**`uri`**|`const char *`|The URI for the authorization handler|
|**`handler`**|`httplib_authorization_handler`|Callback function doing the actual authorization|
|**`cbdata`**|`void *`|Optional user data|

`int httplib_authorization_handler( struct httplib_connection *conn, void *cbdata );`

### Return Value

*none*

### Description

The function `httplib_set_auth_handler()` hooks an authorization function to an URI to check if a user is authorized to visit that URI. The check is performed by a callback function of type `httplib_authorization_handler`. The callback function is passed two parameters: the current connection and a pointer to optional user defined data which was passed to `httplib_set_auth_handler()` when the callback was hooked to the URI.

The callback function can return **0** to deny access, and **1** to allow access.

The `httplib_set_auth_handler()` function is very similar in use to [`httplib_set_request_handler()`](httplib_set_request_handler.md).

### See Also

* [`httplib_set_request_handler();`](httplib_set_request_handler.md)
