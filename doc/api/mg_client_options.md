# LibHTTP API Reference

### `struct httplib_client_options;`

### Fields

| Field | Type | Description |
| :--- | :--- | :--- |
|**`host`**|`const char *`|The hostname or IP address to connect to|
|**`port`**|`int`|The port on the server|
|**`client_cert`**|`const char *`|Pointer to client certificate|
|**`server_cert`**|`const char *`|Pointer to a server certificate|

### Description

The the `mgclient_options` structure contains host and security information to connect as a client to another host. A parameter of this type is used in the call to the function [`httplib_connect_client_secure()`](httplib_connect_client_secure.md). Please note that IPv6 addresses are only permitted if IPv6 support was enabled during compilation. You can use the function [`httplib_check_feature()`](httplib_check_feature.md) with the parameter `USE_IPV6` while running your application to check if IPv6 is supported.

### See Also

* [`httplib_check_feature();`](httplib_check_feature.md)
* [`httplib_connect_client_secure();`](httplib_connect_client_secure.md)
