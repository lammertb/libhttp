# LibHTTP API Reference

### `httplib_strcasecmp( s1, s2 );`

### Parameters

| Parameter | Type | Description |
| :--- | :--- | :--- |
|**`s1`**|`const char *`|First string to compare|
|**`s2`**|`const char *`|Second string to compare|

### Return Value

| Type | Description |
| :--- | :--- |
|`int`|Integer value with the result of the comparison|

### Description

The function `httplib_strcasecmp()` is a helper function to compare two strings. The comparison is case insensitive. The return value is **0** if both strings are equal, less then zero if the first string is less than the second in a lexical comparison, and greater than zero if the first string is greater than the second.

### See Also

* [`httplib_strcasestr();`](httplib_strcasestr.md)
* [`httplib_strdup();`](httplib_strdup.md)
* [`httplib_strncasecmp();`](httplib_strncasecmp.md)
* [`httplib_strndup();`](httplib_strndup.md)
