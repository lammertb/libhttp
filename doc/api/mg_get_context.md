# LibHTTP API Reference

### `httplib_get_context( conn );`

### Parameters

| Parameter | Type | Description |
| :--- | :--- | :--- |
|**`conn`**|`const struct httplib_connection *`|The connection for which the context has to be returned|

### Return Value

| Type | Description |
| :--- | :--- |
|`struct httplib_context *`|A pointer to the context of the given connection|

### Description

The function `httplib_get_context()` returns the context associated with a connection.

### See Also

* [`httplib_start();`](httplib_start.md)
* [`httplib_stop();`](httplib_stop.md)
