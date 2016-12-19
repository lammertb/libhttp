# LibHTTP API Reference

### `httplib_get_user_data( ctx );`

### Parameters

| Parameter | Type | Description |
| :--- | :--- | :--- |
|**`ctx`**|`const struct httplib_context *`|The context for which the user data is requested|

### Return Value

| Type | Description |
| :--- | :--- |
|`void *`|A pointer to the user data or NULL on error, or if no user data has been registered|

### Description

The function `httplib_get_user_data()` returns the user data associated with a LibHTTP context. This is a pointer value which has previously been used in the call to [`httplib_start()`](httplib_start.md) to initialize the server context.

### See Also

* [`httplib_get_user_connection_data();`](httplib_get_user_connection_data.md)
* [`httplib_start();`](httplib_start.md)
