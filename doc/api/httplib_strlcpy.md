# LibHTTP API Reference

### `httplib_strlcpy( dst, src, len );`

### Parameters

| Parameter | Type | Description |
| :--- | :--- | :--- |
|**`dst`**|`const char *`|Pointer to the destination buffer|
|**`src`**|`const char *`|Pointer to the source string which must be copied|
|**`len`**|`size_t`|The size of the receiving buffer in bytes|

### Return Value

*none*

### Description

The function `httplib_strlcpy()` provides a platform independent safe way to copy a string from one memory location to another. The size of the receiving buffer is provided as a parameter and the function ensures that no more the number of the characters fitting in the buffer will be copied. The function also ensures that if the destination buffer is not NULL and the size is at least one byte long that the resulting string is terminated with a NUL character.

If the source string is longer than will fit in the receiving buffer, the remaining characters will be ignored.

### See Also

* [`httplib_strcasecmp();`](httplib_strcasecmp.md)
* [`httplib_strcasestr();`](httplib_strcasestr.md)
* [`httplib_strncasecmp();`](httplib_strncasecmp.md)
* [`httplib_strndup();`](httplib_strndup.md)
