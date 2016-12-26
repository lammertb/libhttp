# LibHTTP API Reference

### `httplib_check_feature( feature );`

### Parameters

| Parameter | Type | Description |
| :--- | :--- | :--- |
|**`feature`**|`unsigned`| A value indicating the feature to be checked |

### Return Value

| Type | Description |
| :--- | :--- |
|`unsigned`| A value indicating if a feature is available. A positive value indicates available, while **0** is returned for an unavailable feature |

### Description

The function `httplib_check_feature()` can be called from an application program to check of specific features have been compiled in the LibHTTP version which the application has been linked to. The feature to check is provided as an unsigned integer parameter. If the function is available in the currently linked library version, a value **> 0** is returned. Otherwise the function `httplib_check_feature()` returns the value **0**.

The following parameter values can be used:

| Value | Compilation option | Description |
| :---: | :---: | :--- |
| **2** | NO_SSL | *Support for HTTPS*. If this feature is available, the webserver van use encryption in the client-server connection. SSLv2, SSLv3, TLSv1.0, TLSv1.1 and TLSv1.2 are supported depending on the SSL library LibHTTP has been compiled with, but which protocols are used effectively when the server is running is dependent on the options used when the server is started. |
| **4** | NO_CGI | *Support for CGI*. If this feature is available, external CGI scripts can be called by the webserver. |

Parameter values other than the values mentioned above will give undefined results. Therefore&mdash;although the parameter values for the `httplib_check_feature()` function are effectively bitmasks, you should't assume that combining two of those values with an OR to a new value will give any meaningful results when the function returns.

### See Also

* [`httplib_get_option();`](httplib_get_option.md)
* [`httplib_get_valid_options();`](httplib_get_valid_options.md)
