# LibHTTP API Reference

LibHTTP is often used as HTTP and HTTPS library inside a larger application.  A C API is available to integrate the LibHTTP functionality in a larger codebase. A C++ wrapper is also available, although it is not guaranteed that all functionality available through the C API can also be accessed from C++. This document describes the public C API. Basic usage examples of the API can be found in [Embedding.md](Embedding.md).

## Macros

| Macro | Description |
| :--- | :--- |
| **`LIBHTTP_VERSION`** | The current version of the website as a string with the major and minor version number seperated with a dot. For version 1.9, this string will for example have the value "1.9" |

## Structures

* [`struct client_cert;`](api/client_cert.md)
* [`struct httplib_callbacks;`](api/httplib_callbacks.md)
* [`struct httplib_client_options;`](api/httplib_client_options.md)
* [`struct httplib_form_data_handler;`](api/httplib_form_data_handler.md)
* [`struct httplib_header;`](api/httplib_header.md)
* [`struct httplib_option;`](api/httplib_option.md)
* [`struct httplib_request_info;`](api/httplib_request_info.md)
* [`struct httplib_server_ports;`](api/httplib_server_ports.md)

## Functions

### System Functions

* [`httplib_check_feature( feature );`](api/httplib_check_feature.md)
* [`httplib_cry( ctx, conn, fmt, ... );`](api/httplib_cry.md)
* [`httplib_get_context( conn );`](api/httplib_get_context.md)
* [`httplib_get_builtin_mime_type( file_name );`](api/httplib_get_builtin_mime_type.md)
* [`httplib_get_option( ctx, name );`](api/httplib_get_option.md)
* [`httplib_get_random();`](api/httplib_get_random.md)
* [`httplib_get_response_code_text( conn, response_code );`](api/httplib_get_response_code_text.md)
* [`httplib_get_server_ports( ctx, size, ports );`](api/httplib_get_server_ports.md)
* [`httplib_get_user_data( ctx );`](api/httplib_get_user_data.md)
* [`httplib_get_valid_options();`](api/httplib_get_valid_options.md)
* [`httplib_start( callbacks, user_data, options );`](api/httplib_start.md)
* [`httplib_stop( ctx );`](api/httplib_stop.md)
* [`httplib_version();`](api/httplib_version.md)

### Communication Functions

* [`httplib_close_connection( conn );`](api/httplib_close_connection.md)
* [`httplib_connect_client( host, port, use_ssl, error_buffer, error_buffer_size );`](api/httplib_connect_client.md)
* [`httplib_connect_client_secure( client_options, error_buffer, error_buffer_size );`](api/httplib_connect_client_secure.md)
* [`httplib_download( host, port, use_ssl, error_buffer, error_buffer_size, fmt, ... );`](api/httplib_download.md)
* [`httplib_get_cookie( cookie, var_name, buf, buf_len );`](api/httplib_get_cookie.md)
* [`httplib_get_header( conn, name );`](api/httplib_get_header.md)
* [`httplib_get_request_info( conn );`](api/httplib_get_request_info.md)
* [`httplib_get_response( conn, ebuf, ebuf_len, timeout );`](api/httplib_get_response.md)
* [`httplib_get_user_connection_data( conn );`](api/httplib_get_user_connection_data.md)
* [`httplib_get_var( data, data_len, var_name, dst, dst_len );`](api/httplib_get_var.md)
* [`httplib_get_var2( data, data_len, var_name, dst, dst_len, occurrence );`](api/httplib_get_var2.md)
* [`httplib_handle_form_request( conn, fdh );`](api/httplib_handle_form_request.md)
* [`httplib_printf( conn, fmt, ... );`](api/httplib_printf.md)
* [`httplib_read( conn, buf, len );`](api/httplib_read.md)
* [`httplib_send_file( conn, path, mime_type, additional_headers );`](api/httplib_send_file.md)
* [`httplib_set_request_handler( ctx, uri, handler, cbdata );`](api/httplib_set_request_handler.md)
* [`httplib_set_user_connection_data( conn, data );`](api/httplib_set_user_connection_data.md)
* [`httplib_store_body( conn, path );`](api/httplib_store_body.md)
* [`httplib_write( conn, buf, len );`](api/httplib_write.md)

### Websocket Functions

* [`httplib_connect_websocket_client( host, port, use_ssl, error_buffer, error_buffer_size, path, origin, data_func, close_func, user_data);`](api/httplib_connect_websocket_client.md)
* [`httplib_set_websocket_handler( ctx, uri, connect_handler, ready_handler, data_handler, close_handler, cbdata );`](api/httplib_set_websocket_handler.md)
* [`httplib_websocket_client_write( conn, opcode, data, data_len );`](api/httplib_websocket_client_write.md)
* [`httplib_websocket_write( conn, opcode, data, data_len );`](api/httplib_websocket_write.md)

### Authentication Functions

* [`httplib_modify_passwords_file( passwords_file_name, domain, user, password );`](api/httplib_modify_passwords_file.md)
* [`httplib_set_auth_handler( ctx, uri, handler, cbdata );`](api/httplib_set_auth_handler.md)

### Data Manipulation and Comparison Functions

* [`httplib_atomic_dec( addr );`](api/httplib_atomic_dec.md)
* [`httplib_atomic_inc( addr );`](api/httplib_atomic_inc.md)
* [`httplib_base64_encode( src, src_len, dst, dst_len );`](api/httplib_base64_encode.md)
* [`httplib_md5( buf, ... );`](api/httplib_md5.md)
* [`httplib_strcasecmp( s1, s2 );`](api/httplib_strcasecmp.md)
* [`httplib_strcasestr( big_str, small_str );`](api/httplib_strcasestr.md)
* [`httplib_strdup( str );`](api/httplib_strdup.md)
* [`httplib_strlcpy( dst, src, len );`](api/httplib_strlcpy.md)
* [`httplib_strncasecmp( s1, s2, len );`](api/httplib_strncasecmp.md)
* [`httplib_strndup( str, len );`](api/httplib_strndup.md)
* [`httplib_url_decode( src, src_len, dst, dst_len, is_form_url_encoded );`](api/httplib_url_decode.md)
* [`httplib_url_encode( src, dst, dst_len );`](api/httplib_url_encode.md)

### Memory Allocation Functions

* [`httplib_calloc( ptr, size );`](api/httplib_calloc.md)
* [`httplib_free( ptr );`](api/httplib_free.md)
* [`httplib_malloc( size );`](api/httplib_malloc.md)
* [`httplib_realloc( ptr, size );`](api/httplib_realloc.md)
* [`httplib_set_alloc_callback_func( log_func );`](api/httplib_set_alloc_callback_func.md)

### Process Functions

* [`httplib_kill( pid, sig );`](api/httplib_kill.md)
* [`httplib_lock_connection( conn );`](api/httplib_lock_connection.md)
* [`httplib_lock_context( ctx );`](api/httplib_lock_context.md)
* [`httplib_poll( pfd, nfds, timeout );`](api/httplib_poll.md)
* [`httplib_pthread_cond_broadcast( cv );`](api/httplib_pthread_cond_broadcast.md)
* [`httplib_pthread_cond_destroy( cv );`](api/httplib_pthread_cond_destroy.md)
* [`httplib_pthread_cond_init( cv, attr );`](api/httplib_pthread_cond_init.md)
* [`httplib_pthread_cond_signal( cv );`](api/httplib_pthread_cond_signal.md)
* [`httplib_pthread_cond_timedwait( cv, mutex, abstime );`](api/httplib_pthread_cond_timedwait.md)
* [`httplib_pthread_cond_wait( cv, mutex );`](api/httplib_pthread_cond_wait.md)
* [`httplib_pthread_getspecific( key );`](api/httplib_pthread_getspecific.md)
* [`httplib_pthread_join( thread, value_ptr );`](api/httplib_pthread_join.md)
* [`httplib_pthread_key_create( key, destructor );`](api/httplib_pthread_key_create.md)
* [`httplib_pthread_key_delete( key );`](api/httplib_pthread_key_delete.md)
* [`httplib_pthread_mutex_destroy( mutex );`](api/httplib_pthread_mutex_destroy.md)
* [`httplib_pthread_mutex_init( mutex, attr );`](api/httplib_pthread_mutex_init.md)
* [`httplib_pthread_mutex_lock( mutex );`](api/httplib_pthread_mutex_lock.md)
* [`httplib_pthread_mutex_trylock( mutex );`](api/httplib_pthread_mutex_trylock.md)
* [`httplib_pthread_mutex_unlock( mutex );`](api/httplib_pthread_mutex_unlock.md)
* [`httplib_pthread_self();`](api/httplib_pthread_self.md)
* [`httplib_pthread_setspecific( key, value );`](api/httplib_pthread_setspecific.md)
* [`httplib_start_thread( f, p );`](api/httplib_start_thread.md)
* [`httplib_unlock_connection( conn );`](api/httplib_unlock_connection.md)
* [`httplib_unlock_context( ctx );`](api/httplib_unlock_context.md)

### File and Directory Functions

* [`httplib_closedir( dir );`](api/httplib_closedir.md)
* [`httplib_mkdir( path, mode );`](api/httplib_mkdir.md)
* [`httplib_opendir( name );`](api/httplib_opendir.md)
* [`httplib_readdir( dir );`](api/httplib_readdir.md)
* [`httplib_remove( path );`](api/httplib_remove.md)
