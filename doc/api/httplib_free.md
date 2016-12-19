# LibHTTP API Reference

### `httplib_free( ptr );`

### Parameters

| Parameter | Type | Description |
| :--- | :--- | :--- |
|**`ptr`**|`void *`|Pointer to the memory block which must be freed|

### Return Value

*none*

### Description

The function `httplib_free()` frees a block of memory which has been previously allocated by [`httplib_calloc()`](httplib_calloc.md), [`httplib_malloc()`](httplib_malloc.md) or [`httplib_realloc()`](httplib_realloc.md). If a callback function has been registered with the [`httplib_set_alloc_callback_func()`](httplib_set_alloc_callback_func.md) function, this function will be called to signal to the main application that a block of memory has been freed. The amount of bytes passed to the callback function is negative, to indacte that memory has been returned to the heap.

Due to the allocation of extra data space for tracking the memory allocation, the LibHTTP memory management functions including the `httplib_free()` function are incompatible with the memory allocation functions provided by the platform. Memory allocated with one set of functions can not be reallocated or freed by the others. Memory corruption or crashes may occur in that case.

### See Also

* [`httplib_calloc();`](httplib_calloc.md)
* [`httplib_malloc();`](httplib_malloc.md)
* [`httplib_realloc();`](httplib_realloc.md)
* [`httplib_set_alloc_callback_func();`](httplib_set_alloc_callback_func.md)
* [`httplib_strdup();`](httplib_strdup.md)
* [`httplib_strndup();`](httplib_strndup.md)
