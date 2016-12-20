# LibHTTP API Reference

### `httplib_send_file( conn, path, mime_type, additional_headers );`

### Parameters

| Parameter | Type | Description |
| :--- | :--- | :--- |
|**`conn`**|`struct httplib_connection *`|The connection over which the file must be sent|
|**`path`**|`const char *`|The full path and filename of the file|
|**`mime_type`**|`const char *`|The mime type or NULL for automatic detection|
|**`additional_headers`**|`const char *`|Additional headers to be sent|

### Return Value

*none*

### Description

The function `httplib_send_file()` can be used to send a file over a connection. The MIME type of the file can be specified in the function call, or will be automatically determined based on the extension of the filename if the `mime_type` parameter has the value NULL.

Additional custom header fields can be added as a parameter. Please make sure that these header names begin with `X-` to prevent name clashes with other headers. If the `additional_headers` parameter is NULL, no custom headers will be added.

### See Also

* [`httplib_get_builtin_mime_type();`](httplib_get_builtin_mime_type.md)
* [`httplib_printf();`](httplib_printf.md)
* [`httplib_write();`](httplib_write.md)
