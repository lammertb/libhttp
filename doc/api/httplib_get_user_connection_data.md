# LibHTTP API Reference

### `httplib_get_user_connection_data( conn );`

### Parameters

| Parameter | Type | Description |
| :--- | :--- | :--- |
|**`conn`**|`const struct httplib_connection *`|The connection for which to return the user data|

### Return Value

| Type | Description | 
| :--- | :--- |
|`void *`|A pointer to the user data, or NULL if no user data was registered with the connection|

### Description

The function `httplib_get_user_connection_data()` returns the user data associated with a connection. This user data is represented with a pointer which has been prevously registered with a call to [`httplib_set_user_connection_data();`](httplib_set_user_connection_data.md). With this function it is possible to pass state information between callback functions refering to a specific connection.

### See Also

* [`httplib_get_user_data();`](httplib_get_user_data.md)
* [`httplib_set_user_connection_data();`](httplib_set_user_connection_data.md)
