# LibHTTP API Reference

### `httplib_atomic_dec( addr );`

### Parameters

| Parameter | Type | Description |
| :--- | :--- | :--- |
|**`addr`**|`volatile int *`|The address of the integer to decrement|

### Return Value

| Type | Description |
| :--- | :--- |
|`int`|The value of the integer after the decrement|

### Description

The function `httplib_atomic_dec()` performs an atomic decrement if an integer. This function can be used to decrement an integer in a reliable way where multiple processes or threads have simultaneous access to the variable. The function returns the value of the integer after it has been decremented.

### See Also

* [`httplib_atomic_inc();`](httplib_atomic_inc.md)
