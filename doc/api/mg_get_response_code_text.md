# LibHTTP API Reference

### `httplib_get_response_code_text( conn, response_code );`

### Parameters

| Parameter | Type | Description |
| :--- | :--- | :--- |
|**`conn`**|`struct httplib_connection *`| A pointer referencing the connection |
|**`response_code`**|`int`| Response code for which the text is queried |

### Return Value

| Type | Description |
| :--- | :--- |
|`const char *`| A pointer to a human readable text explaining the response code. |

### Description

The function `httplib_get_response_code_text()` returns a pointer to a human readable text describing the HTTP response code which was provided as a parameter.

### See Also

* [`httplib_get_builtin_mime_type();`](httplib_get_builtin_mime_type.md)
* [`httplib_version();`](httplib_version.md)
