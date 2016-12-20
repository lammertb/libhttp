# LibHTTP API Reference

### `httplib_get_builtin_mime_type( file_name );`

### Parameters

| Parameter | Type | Description |
| :--- | :--- | :--- |
|**`file_name`**|`const char *`|The name of the file for which the MIME type has to be determined|

### Return Value

| Type | Description |
| :--- | :--- |
|`const char *`|A text string describing the MIME type|

### Description

The function `httplib_get_builtin_mime_type()` tries to determine the MIME type of a given file. If the MIME type cannot be determined, the value `text/plain` is returned. Please note that this function does not perform an intelligent check of the file contents. The MIME type is solely determined based on the file name extension. Because no actual file check is done, the function will also return a usable value if the physical file does not exist.

This function selects the MIME type from a static list of known MIME type which was created at compile time. It is possible to add or override values used as MIME type in the library at runtime, but these manual changes do not alter the builtin list and these user changed values will therefore not be returned by the `httplib_get_builtin_mime_type()` function.

The function uses an efficient binary search algorithm, but this has implications if you want to change the list in the source code. The list has to be sorted in the source file already, otherwise it may not return valid values available in the list. After the source code has changed it is best to run the `testmime` executable in the project directory which checks the integrity of the static MIME type list. This executable is updated automatically with every compile run of the library when `make` is invoked with the default `Makefile` provided with the project.

### See Also

* [`httplib_send_file();`](httplib_send_file.md)
