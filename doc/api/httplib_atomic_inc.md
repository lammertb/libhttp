# LibHTTP API Reference

### `httplib_atomic_inc( addr );`

### Parameters

| Parameter | Type | Description |
| :--- | :--- | :--- |
|**`addr`**|`volatile int *`|The address of the integer to increment|

### Return Value

| Type | Description |
| :--- | :--- |
|`int`|The value of the integer after the increment|

### Description

The function `httplib_atomic_inc()` performs an atomic increment if an integer. This function can be used to increment an integer in a reliable way where multiple processes or threads have simultaneous access to the variable. The function returns the value of the integer after it has been incremented.

### See Also

* [`httplib_atomic_dec();`](httplib_atomic_dec.md)
