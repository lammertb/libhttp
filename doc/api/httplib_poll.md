# LibHTTP API Reference

### `httplib_poll( pfd, nfds, timeout );`

### Parameters

| Parameter | Type | Description |
| :--- | :--- | :--- |
|**`pfd`**|`struct pollfd *`|List of file descriptors|
|**`nfds`**|`unsigned int`|Number of file descriptors|
|**`timeout`**|`int`|Timeout of the wait in milliseconds|

### Return Value

| Type | Description |
| :--- | :--- |
|`int`|The number of descriptors ready for I/O or an error code|

### Description

The function `httplib_poll()` provides a platform independent way to perform asynchronous I/O. A list with file descriptors is provided as parameter to the function call. When one or more file desciptors are ready to provide I/O the function returns with the number of descriptors which are ready. An error is indicated with the value -1. An optional timeout value specifies in milliseconds after which time the function should return, even if no file descriptors are ready. The value **-1** as timeout is interpreted as an infinite wait.

On Posix compliant systems the call to this function is just a wrapper around the Posix `poll()` function. On other systems this function is implemented with own code to emulate the Posix functionality.

### See Also

* [`httplib_kill();`](httplib_kill.md)
