# LibHTTP API Reference

### `struct httplib_header;`

### Fields

| Field | Type | Description |
| :--- | :--- | :--- |
|**`name`**|`const char *`| The name of the client request header |
|**`value`**|`const char *`| The value of the client request header |

### Description

The structure `httplib_header` is used as a sub-structure in the [`struct httplib_request_info;`](httplib_request_info.md) structure to store the name and value of one HTTP request header as sent by the client.

### See Also

* [`struct httplib_request_info;`](httplib_request_info.md)
* [`httplib_get_header();`](httplib_get_header.md)
