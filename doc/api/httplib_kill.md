# LibHTTP API Reference

### `httplib_kill( pid, sig );`

### Parameters

| Parameter | Type | Description |
| :--- | :--- | :--- |
|**`pid`**|`pid_t`| The process identifier of the process |
|**`sig`**|`int`| The signal to be sent to the process |

### Return Value

| Type | Description |
| :--- | :--- |
|`int`|An integer which indicates success or failure|

### Description

The function `httplib_kill()` provides a platform independent way to send a signal to a process. The function uses the Postfix `kill()` functions in environments where that function is supported or emulates that function with own code for other operating systems. The function call returns **0** if sending the signal was successful and **-1** otherwise.

Please note that for non Posix-compliant systems the functionality of the Posix `kill()` function has not been fully implemented. Currently only the `SIGKILL` has been implemented and tested fully. For other signals the functionality is unknown and may not lead to the desired results.

### See Also

* [`httplib_poll();`](httplib_poll.md)
