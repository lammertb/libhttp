# LibHTTP API Reference

### `httplib_close_connection( conn );`

### Parameters

| Parameter | Type | Description |
| :--- | :--- | :--- |
|**`conn`**|`struct httplib_connection *`|The connection which must be closed|

### Return Value

*none*

### Description

The function `httplib_close_connection()` is used to close a connection which was opened with the [`httplib_download()`](httplib_download.md) function. Use of this function to close a connection which was opened in another way is undocumented and may give unexpected results.

### See Also

* [`httplib_download();`](httplib_download.md)
