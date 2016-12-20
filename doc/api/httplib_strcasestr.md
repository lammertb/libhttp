# LibHTTP API Reference

### `httplib_strcasestr( big_str, small_str );`

### Parameters

| Parameter | Type | Description |
| :--- | :--- | :--- |
|**`big_str`**|`const char *`|The string to search in|
|**`small_str`**|`const char *`|The string to search for|

### Return Value

| Type | Description |
| :--- | :--- |
|`int`|First occurence of the small string, or NULL if the string could not be found|

### Description

The function `httplib_strcasestr()` is a helper function to search a NUL terminated string in another NUL terminated string. The search is case insensitive. A pointer to the first occurence of the substring in the large string is returned, or `NULL` if the string could not be found.

### See Also

* [`httplib_strcasecmp();`](httplib_strcasecmp.md)
* [`httplib_strdup();`](httplib_strdup.md)
* [`httplib_strncasecmp();`](httplib_strncasecmp.md)
* [`httplib_strndup();`](httplib_strndup.md)
