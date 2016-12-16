# LibHTTP API Reference

### `httplib_remove( path );`

### Parameters

| Parameter | Type | Description |
| :--- | :--- | :--- |
|**`path`**|`const char *`|The path of the file or directory to remove|

### Return Value

| Type | Description |
| :--- | :--- |
|`int`|An integer which indicates success or failure of the call|

### Description

The function `httplib_remove()` provides a platform independent way to remove an entry from a directory. The function can be used to remove both file and directory entries. Remove will only function on directories, if the contents of the directory to remove is empty. In Posix compliant environments this function is a wrapper around the Posix `remove()` function. On other systems the Posix `remove()` functionality is emulated with own code.

The function returns **0** when successful and **-1** if an error occurs.

### See Also

* [`httplib_mkdir();`](httplib_mkdir.md)
