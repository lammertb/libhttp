# LibHTTP API Reference

### `httplib_send_file( conn, path );`

### Parameters

| Parameter | Type | Description |
| :--- | :--- | :--- |
|**`conn`**|`struct httplib_connection *`|The connection over which the file must be sent|
|**`path`**|`const char *`|The full path and filename of the file|

### Return Value

*none*

### Description

The function `httplib_send_file()` sends the contents of a file over a connection to the remote peer. The function also adds the necessary HTTP headers.

### See Also

* [`httplib_printf();`](httplib_printf.md)
* [`httplib_send_mime_file();`](httplib_send_mime_file.md)
* [`httplib_send_mime_file2();`](httplib_send_mime_file2.md)
* [`httplib_write();`](httplib_write.md)
