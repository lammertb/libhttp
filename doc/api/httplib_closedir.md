# LibHTTP API Reference

### `httplib_closedir( dir );`

### Parameters

| Parameter | Type | Description |
| :--- | :--- | :--- |
|**`dir`**|`DIR *`| A pointer to a directory structure of an opened directory |

### Return Value

| Type | Description |
| :--- | :--- |
|`int`|Success or error code of the operation|

### Description

The function `httplib_closedir()` is a platform independent way to close a directory which was previously opened with a call to [`httplib_opendir()`](httplib_opendir.md). The function returns an integer which indicates the result of the operation. The return value **0** is returned if closing the directory succesful. The file associated with the directory has been closed in that situation and previously allocated memory by the `httplib_opendir()` function is returned to the heap. The directory structure to which the parameter `dir` points will in that case be invalid and should not be further used by the calling party. An error is signaled by returning the value **-1**.

On functions which support Posix the `httplib_closedir()` is a direct wrapper around `opendir()`. On other systems the functionality of the Posix function is emulated with own code.

### See Also

* [`httplib_mkdir();`](httplib_mkdir.md)
* [`httplib_opendir();`](httplib_opendir.md)
* [`httplib_readdir();`](httplib_readdir.md)
