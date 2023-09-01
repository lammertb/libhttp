#include <stdio.h>
#include <string.h>
#include "libhttp.h"

// This function will be called by libhttp on every new request.
static int begin_request_handler(struct lh_ctx_t *ctx, struct lh_con_t *conn)
{
    const struct lh_rqi_t *request_info = httplib_get_request_info(conn);
    char content[100];

    // Prepare the message we're going to send
    int content_length = snprintf(content, sizeof(content),
                                  "Hello from civetweb! Remote port: %d",
                                  request_info->remote_port);

    // Send HTTP reply to the client
    httplib_printf(ctx,conn,
              "HTTP/1.1 200 OK\r\n"
              "Content-Type: text/plain\r\n"
              "Content-Length: %d\r\n"        // Always set Content-Length
              "\r\n"
              "%s",
              content_length, content);

    // Returning non-zero tells libhttp that our function has replied to
    // the client, and libhttp should not send client any more data.
    return 1;
}

int main(void)
{
    struct lh_ctx_t *ctx;
    struct lh_clb_t callbacks;

    // List of options. Last element must be NULL.
    struct lh_opt_t options[] = {(struct lh_opt_t){"listening_ports","8080"},{NULL}};

    // Prepare callbacks structure. We have only one callback, the rest are NULL.
    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.begin_request = begin_request_handler;

    // Start the web server.
    ctx = httplib_start(&callbacks, NULL, options);

    // Wait until user hits "enter". Server is running in separate thread.
    // Navigating to http://localhost:8080 will invoke begin_request_handler().
    getchar();

    // Stop the server.
    httplib_stop(ctx);

    return 0;
}
