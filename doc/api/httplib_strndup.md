# LibHTTP API Reference

### `httplib_strndup( str, len );`

### Parameters

| Parameter | Type | Description |
| :--- | :--- | :--- |
|**`str`**|`const char *`|Pointer to the source string which must be duplicated|
|**`len`**|`size_t`|The maximum number of string characters to duplicate|

### Return Value

| Type | Description |
| :--- | :--- |
|`char *`|Pointer to the duplicate, or NULL if an error occured|

### Description

The function `httplib_strndup()` duplicates a given number of characters of a string to a new string and terminates the result with a NUL character. If less than the specified maximum amount of characters are available, only the available characters are copied. The duplicate is stored in a newly allocated block of memory. The function is equivalent to the Posix `strndup()` function with the difference that the LibHTTP memory allocation functions are used which allow for tracking of allocation requests and memory leaks through a monitor hook. The size of the allocated memory block is the given maximum string length plus one byte for the terminating NUL character.

If the duplicate of the string is no longer used, the allocated memory should be returned to the heap with a call to [`httplib_free()`](httplib_free.md).

If the function fails the value `NULL` is returned, otherwise a pointer to the duplicate.

### See Also

* [`httplib_free();`](httplib_free.md)
* [`httplib_strcasecmp();`](httplib_strcasecmp.md)
* [`httplib_strcasestr();`](httplib_strcasestr.md)
* [`httplib_strdup();`](httplib_strdup.md)
* [`httplib_strncasecmp();`](httplib_strncasecmp.md)
