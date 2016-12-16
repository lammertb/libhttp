# LibHTTP API Reference

### `httplib_realloc( ptr, size );`

### Parameters

| Parameter | Type | Description |
| :--- | :--- | :--- |
|**`ptr`**|`void *`|A pointer to the existing memory block|
|**`size`**|`size_t`|The amount of bytes to allocate|

### Return Value

| Type | Description |
| :--- | :--- |
|`void *`|Pointer to the allocated memory block or `NULL` if an error occured|

### Description

The function `httplib_realloc()` tries to change the size of an existing allocated memory block. A pointer to the existing memory area is passed together with the requested new size. new size can both be smaller or larger than the current size of the memory block. The returned pointer can be the same pointer to the original memory block, or a new pointer to another location. In that case the contents of the memory block have been copied to the new location.

If the `ptr` parameter is NULL, the function `httplib_realloc()` is equivalent to [`httplib_malloc()`](httplib_malloc.md). If the parameter `size` is **0**, the function `httplib_realloc()` will be equal to [`httplib_free()`](httplib_free.md).

If a callback function has been registered with the [`httplib_set_alloc_callback_func()`](httplib_set_alloc_callback_func.md) function, this function will be called to signal to the main application that a block of memory has been allocated. If a callback function has been registered and the allocation of memory fails, the value **0** is passed as the `current_bytes` parameter. Please note that the `current_bytes` parameter passed to the callback function can both be a positive and negative value. A positive value indicates that the size of the memory block has increased while a negative value signals a decrease in the allocated size.

Due to the allocation of extra data space for tracking the memory allocation, the LibHTTP memory management functions including the `httplib_realloc()` function are incompatible with the memory allocation functions provided by the platform. Memory allocated with one set of functions can not be reallocated or freed by the others. Memory corruption or crashes may occur in that case.

### See Also

* [`httplib_calloc();`](httplib_calloc.md)
* [`httplib_free();`](httplib_free.md)
* [`httplib_realloc();`](httplib_malloc.md)
* [`httplib_set_alloc_callback_func();`](httplib_set_alloc_callback_func.md)
