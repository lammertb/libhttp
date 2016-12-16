# LibHTTP API Reference

### `httplib_mkdir( path, mode );`

### Parameters

| Parameter | Type | Description |
| :--- | :--- | :--- |
|**`path`**|`const char *`| A pointer to name of the directory to create |
|**`mode`**|`const char *`| The security attributes to be assigned to the directory |

### Return Value

| Type | Description |
| :--- | :--- |
|`int`|An integer which indicates success or failure of the call|

### Description

The function `httplib_mkdir()` provides an independent way to creare a directory on a system. The function uses the Posix `mkdir()` function in environments where that function is supported or emulates that function with own code for other operating systems. Please note that the `mode` parameter resembles the \*nix security attributes known for files and directories. On systems which do not support that&mdash;most notably Windows based systems&mdash;the `mode` parameter is silently ignored.

The `httplib_mkdir()` function returns **0** when it was successful and **-1** when an error occured.

### See Also

* [`httplib_closedir();`](httplib_closedir.md)
* [`httplib_opendir();`](httplib_opendir.md)
* [`httplib_readdir();`](httplib_readdir.md)
* [`httplib_remove();`](httplib_remove.md)
