# LibHTTP API Reference

### `httplib_readdir( dir );`

### Parameters

| Parameter | Type | Description |
| :--- | :--- | :--- |
|**`name`**|`DIR *`| A pointer to name of the directory to open |

### Return Value

| Type | Description |
| :--- | :--- |
|`struct dirent *`|A pointer to a directory entry structure or NULL on error|

### Description

The function `httplib_readdir()` reads the next entry from a directory. The directory must have been opened earlier with a call to the function [`httplib_opendir()`](httplib_opendir.md). If the next directory entry can be found, a pointer to a `dirent` structure is returned. If an error occurs or the last item in a directory has been read the value `NULL` is returned instead.

On platforms which support Posix the call to `httplib_readdir()` is a wrapper arround `readdir()`. On other systems the function is implemented with own code as a clone of the `readdir()` function.

After the last item has been read with `httplib_opendir()`, the directory must be closed with a call to [`httplib_closedir()`](httplib_closedir.md) to return occupied resources.

### See Also

* [`httplib_closedir();`](httplib_closedir.md)
* [`httplib_mkdir();`](httplib_mkdir.md)
* [`httplib_opendir();`](httplib_opendir.md)
