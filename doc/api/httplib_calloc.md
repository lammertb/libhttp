# LibHTTP API Reference

### `httplib_calloc:( count, size );`

### Parameters

| Parameter | Type | Description |
| :--- | :--- | :--- |
|**`count`**|`size_t`|The number of elements to allocate memory for|
|**`size`**|`size_t`|The size of each individual element|

### Return Value

| Type | Description |
| :--- | :--- |
|`void *`|Pointer to the allocated memory block or `NULL` if an error occured|

### Description

The function `httplib_calloc()` tries to allocate a block of memory from the heap for an array elements with a specified size. If this succeeds, the function returns a pointer to the new block. Otherwise the value `NULL` is returned. If a callback function has been registered with the [`httplib_set_alloc_callback_func()`](httplib_set_alloc_callback_func.md) function, this function will be called to signal to the main application that a block of memory has been allocated. If a callback function has been registered and the allocation of memory fails, the value **0** is passed as the `current_bytes` parameter.

Due to the allocation of extra data space for tracking the memory allocation, the LibHTTP memory management functions including the `httplib_calloc()` function are incompatible with the memory allocation functions provided by the platform. Memory allocated with one set of functions can not be reallocated or freed by the others. Memory corruption or crashes may occur in that case.

### See Also

* [`httplib_free();`](httplib_free.md)
* [`httplib_malloc();`](httplib_malloc.md)
* [`httplib_realloc();`](httplib_realloc.md)
* [`httplib_set_alloc_callback_func();`](httplib_set_alloc_callback_func.md)
