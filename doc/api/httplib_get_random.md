# LibHTTP API Reference

### `httplib_get_random();`

### Parameters

*none*

### Return Value

| Type | Description |
| :--- | :--- |
|`uint64_t`| A 64 bit pseudo random value|

### Description

The function `httplib_get_random()` returns a 64 bit wide pseudo random value. The calculation uses a mix of two random generator functions and the volatile part of a high speed timer value, which makes the result of the function useable in many situations. The implementation is independent of pseudo random number generators provided by the operating system or compiler run time library and will therefore give a consistent performance independent on the platform used.

### See Also
