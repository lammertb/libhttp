# LibHTTP API Reference

### `httplib_opendir( name );`

### Parameters

| Parameter | Type | Description |
| :--- | :--- | :--- |
|**`name`**|`const char *`| A pointer to name of the directory to open |

### Return Value

| Type | Description |
| :--- | :--- |
|`DIR *`|A pointer to a directory structure or NULL on error|

### Description

The function `httplib_opendir()` provides a platform independent way to open a directory on a system. The function uses the Posix `opendir()` function in environments where that function is supported or emulates that function with own code for other operating systems. The function is either a pointer to a DIR directory structure if the call was succesful, or a `NULL` pointer if the directory cannot be found or an other error occured.

Reading individual items in the directory is possible with the `httplib_readdir()`  function.

Please note that the `httplib_opendir()` function allocates memory and opens the directory as a file on most platforms. Closing the directory and returning the allocated resources after use of the directory is finished is therefore necessary. Closing a directory can be done with a call to the [`httplib_closedir()`](httplib_closedir.md) function.

### See Also

* [`httplib_closedir();`](httplib_closedir.md)
* [`httplib_mkdir();`](httplib_mkdir.md)
* [`httplib_readdir();`](httplib_readdir.md)
