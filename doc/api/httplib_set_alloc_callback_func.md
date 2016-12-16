# LibHTTP API Reference

### `httplib_set_alloc_callback_func( log_func );`

### Parameters

| Parameter | Type | Description |
| :--- | :--- | :--- |
|**`log_func`**|`httplib_alloc_callback_func`|The function called with each memory allocation transaction|

`void httplib_alloc_callback_func( const char *file, unsigned line, const char *action, int64_t current_bytes, int64_t total_blocks, int64_t total_bytes );`

### Return Value

*none*

### Description

The function `httplib_set_alloc_callback_func()` hooks an optional callback function to the LibHTTP memory allocation functions. This function can be used to track memory usage of the library and to determine memory leaks. The callback function is called each time when a memory transaction takes place which changes the amount of allocated memory from the heap.

The callback function may not call directly or indirectly any LibHTTP function as these functions may recursively call internal memory allocation functions causing an infinte loop consuming all memory resources.

If the parameter NULL is passed as callback function the existing callback is removed.

The callback function takes six parameters and does not return a value. The parameters which are passed from LibHTTP to the callback function are the following.

| Parameter | Type | Description |
| :--- | :--- | :--- |
|**`file`**|`const char *`|The name of the source file where the memory allocation function was called|
|**`line`**|`unsigned`|The line in the source file where the memory allocation function is located|
|**`action`**|`const char *`|A string indicating the source of the callback. Currently this can be either **malloc**, **free** and **realloc**. Please note that a call to `httplib_calloc()` is internally translated to a `httplib_malloc()` call and these requests are reported as **malloc** actions. Furthermore in certain situations `httplib_realloc()` may actually be converted to a plain memory allocation of free action resulting in **malloc** or **free** mentioned as `action` parameter.|
|**`current_bytes`**|`int64_t`|The amount of bytes in the current request. A positive number indicates that memory was allocated from the heap, a negative value is returned when memory was given back to the heap. Please note that a **realloc** action can therefore both have a positive and negative `current_bytes` value.|
|**`total_blocks`**|`int64_t`|The total amount of currently allocated blocks|
|**`total_bytes`**|`int64_t`|The total amount of bytes currently allocated through the LibHTTP memory allocation functions|

Please note that the processing of the callback function may take an arbitrary amount of time depending on the code which it has to execute. For that reason the setting of the callback function should not be changed during operation of a server process because this may cause unexpected results when the callback function is changed halfway an ongoing callback process. It should also be noted that the memory allocation function issuing the callback will not return until the callback has been fully processed. Long processing times in the callback function may therefore negatively impact the performance of LibHTTP.

### See Also

* [`httplib_calloc();`](httplib_calloc.md)
* [`httplib_free();`](httplib_free.md)
* [`httplib_malloc();`](httplib_malloc.md)
* [`httplib_realloc();`](httplib_realloc.md)
