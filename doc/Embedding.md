Embedding LibHTTP
=========

LibHTTP is primarily designed so applications can easily add HTTP and HTTPS server as well as WebSocket functionality.  For example, an application server could use LibHTTP to enable a web service interface for automation or remote control.

It can deliver static files and offers built-in server side Lua, JavaScript and CGI support. Some instructions how to build the stand-alone server can be found in [Building.md](Building.md).

Files
------

There is just a small set of files to compile in to the application,
but if a library is desired, see [Building.md](Building.md)

#### Regarding the INL file extension
The *INL* file extension represents code that is statically included inline in a source file.  Slightly different from C++ where it means "inline" code which is technically not the same as static code. LibHTTP overloads this extension for the sake of clarity as opposed to having .c extensions on files that should not be directly compiled.

#### HTTP Server Source Files

These files constitute the LibHTTP library.  They do not contain a `main` function,
but all functions required to run a HTTP server.

  - HTTP server API
    - include/libhttp.h
  - C implementation
    - src/libhttp.c
    - src/md5.inl (MD5 calculation)
    - src/handle_form.inl (HTML form handling functions)

Quick Start
------

By default, the server will automatically serve up files like a normal HTTP server.  An embedded server is most likely going to overload this functionality.

### C
  - Include the C interface ```libhttp.h```.
  - Use `httplib_start()` to start the server.
      - Use *options* to select the port and document root among other things.
      - Use *callbacks* to add your own hooks.
  - Use `httplib_set_request_handler()` to easily add your own request handlers.
  - Use `httplib_stop()` to stop the server.

JavaScript Support
------

LibHTTP can be built with server side JavaScript support by including the Duktape library.


LibHTTP internals
------

LibHTTP is multithreaded web server. `httplib_start()` function allocates
web server context (`struct httplib_context`), which holds all information
about web server instance:

- configuration options. Note that LibHTTP makes internal copies of
  passed options.
- SSL context, if any
- user-defined callbacks
- opened listening sockets
- a queue for accepted sockets
- mutexes and condition variables for inter-thread synchronization

When `httplib_start()` returns, all initialization is guaranteed to be complete
(e.g. listening ports are opened, SSL is initialized, etc). `httplib_start()` starts
some threads: a master thread, that accepts new connections, and several
worker threads, that process accepted connections. The number of worker threads
is configurable via `num_threads` configuration option. That number puts a
limit on number of simultaneous requests that can be handled by LibHTTP.
If you embed LibHTTP into a program that uses SSL outside LibHTTP as well,
you may need to initialize SSL before calling `httplib_start()`, and set the pre-
processor define SSL_ALREADY_INITIALIZED. This is not required if SSL is used
only within LibHTTP.

When master thread accepts new a connection, a new accepted socket (described
by `struct socket`) it placed into the accepted sockets queue,
which has size of `MGSQLEN` (default 20).
Any idle worker thread can grab accepted sockets from that queue.
If all worker threads are busy, master thread can accept and queue up to
20 more TCP connections, filling up the queue.
In the attempt to queue even more accepted connection, the master thread blocks
until there is space in the queue. When the master thread is blocked on a
full queue, the operating system can also queue incoming connection.
The number is limited by the `listen()` call parameter,
which is `SOMAXCONN` and depends on the platform.

Worker threads are running in an infinite loop, which in a simplified form
looks something like this:

    static void *worker_thread() {
      while (consume_socket()) {
        process_new_connection();
      }
    }

Function `consume_socket()` gets a new accepted socket from the LibHTTP socket
queue, atomically removing it from the queue. If the queue is empty,
`consume_socket()` blocks and waits until a new socket is placed in the queue
by the master thread.

`process_new_connection()` actually processes the
connection, i.e. reads the request, parses it, and performs appropriate action
depending on the parsed request.

Master thread uses `poll()` and `accept()` to accept new connections on
listening sockets. `poll()` is used to avoid `FD_SETSIZE` limitation of
`select()`. Since there are only a few listening sockets, there is no reason
to use hi-performance alternatives like `epoll()` or `kqueue()`. Worker
threads use blocking IO on accepted sockets for reading and writing data.
All accepted sockets have `SO_RCVTIMEO` and `SO_SNDTIMEO` socket options set
(controlled by the `request_timeout_ms` LibHTTP option, 30 seconds default)
which specifies a read/write timeout on client connections.

