# LibHTTP API Reference

### `httplib_base64_encode( src, src_len, dst, dst_len );`

### Parameters

| Parameter | Type | Description |
| :--- | :--- | :--- |
|**`src`**|`const unsigned char *`|Pointer to binary data to be BASE64 encoded|
|**`src_len`**|`int`|The number of bytes of the binary data to encode|
|**`dst`**|`char *`|Destination buffer for the encoding string|
|**`dst_len`**|`int`|Length of the destination buffer|

### Return Value

| Type | Description |
| :--- | :--- |
|`int`|The size of the destination string or an error|

### Description

The function `httplib_base64_encode()` encodes a block of binary data to a BASE64 encoded NUL terminated string. The destination buffer should be large enough to contain the whole string and NUL terminating character. If the function succeeds the actual number of used bytes in the destination buffer is returned. An error is indicated with the return value **-1**.

### See Also

* [`httplib_url_decode();`](httplib_url_decode.md)
* [`httplib_url_encode();`](httplib_url_encode.md)
