# LibHTTP API Reference

### `httplib_strdup( str );`

### Parameters

| Parameter | Type | Description |
| :--- | :--- | :--- |
|**`str`**|`const char *`|Pointer to the source string which must be duplicated|

### Return Value

| Type | Description |
| :--- | :--- |
|`char *`|Pointer to the duplicate, or NULL if an error occured|

### Description

The function `httplib_strdup()` duplicates a NUL terminated string to a new string. The duplicate is stored in a newly allocated block of memory. The function is equivalent to the Posix `strdup()` function with the difference that the LibHTTP memory allocation functions are used which allow for tracking of allocation requests and memory leaks through a monitor hook.

If the duplicate of the string is no longer used, the allocated memory should be returned to the heap with a call to [`httplib_free()`](httplib_free.md).

If the function fails the value `NULL` is returned, otherwise a pointer to the duplicate. Failure can be either through an invalid parameter in the function call, or an out of memory situation when allocating space for the duplicate.

### See Also

* [`httplib_free();`](httplib_free.md)
* [`httplib_strcasecmp();`](httplib_strcasecmp.md)
* [`httplib_strcasestr();`](httplib_strcasestr.md)
* [`httplib_strncasecmp();`](httplib_strncasecmp.md)
* [`httplib_strndup();`](httplib_strndup.md)
