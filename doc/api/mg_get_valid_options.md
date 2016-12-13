# LibHTTP API Reference

### `httplib_get_valid_options();`

### Parameters

*none*

### Return Value

| Type | Description | 
| :--- | :--- |
|`const struct httplib_option *`|An array with all valid configuration options|

### Description

The function `httplib_get_valid_options()` returns an array with all valid configuration options of LibHTTP. Each element in the array is a structure with three fields which represent the name of the option, the value of the option and the type of the value. The array is terminated with an element for which the name is `NULL`. See for more details about this structure the documentation of [`struct httplib_option`](httplib_option.md).

### See Also

* [`struct httplib_option;`](httplib_option.md)
* [`httplib_check_feature();`](httplib_check_feature.md)
* [`httplib_start();`](httplib_start.md)
