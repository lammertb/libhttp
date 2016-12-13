# LibHTTP API Reference

### `httplib_cry( conn, fmt, ... );`

### Parameters

| Parameter | Type | Description |
| :--- | :--- | :--- |
|**`conn`**|`const struct httplib_connection *`|The connection on which a problem occured|
|**`fmt`**|`const char *`|Format string without a line return|
|**`...`**|*various*|Parameters depending on the format string|

### Return Value

*none*

### Description

The function `httplib_cry()` is called when something happens on a connection. The function takes a format string similar to the `printf()` series of functions with parameters and creates a text string which can then be used for logging. The `httplib_cry()` function prints the output to the opened error log stream. Log messages can be processed with the `log_message()` callback function specified in the `struct httplib_callbacks` structure.

### See Also

* [`struct httplib_callbacks;`](httplib_callbacks.md)
