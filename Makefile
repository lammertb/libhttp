#
# Library: libhttp
# File:    Makefile
# Author:  Lammert Bies
#
# This file is licensed under the MIT License as stated below
#
# Copyright (c) 2016 Lammert Bies
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# Description
# -----------
# This Makefile is used to build the libhttp library. The only action you should
# normally have to do is to run the make program from the command line,
# independent on the Operating System you are working on.
#
# This Makefile is manually maintained. No autoconf or automake involved. This
# was a deliberate decision due to the absense of these tools on some systems,
# in particular in Windows environments.
#
# Dependencies
# ------------
# This Makefile is known to be functional with GNU Make. Other make utilities
# may work or may have problems. GNU Make is available both in source code
# and precompiled binaries for a large number of environments and therefore
# you are recommended to install a version of GNU Make if you encounter
# problems with the default make utility in your development chain.
#
# Aside from GNU Make and the standard C compiler headers and libraries which
# should have been installed already together with your compiler there are no
# other known dependencies.
#
# Library Type
# ------------
# The generated library is a library useable for static linking in this
# source directory structure. The decision for a static linkable library
# was deliberate because of the relatively small size of the library and the
# routines and to avoid version and dependency issues when distributing the
# end application to different environments.
#

DOCUMENT_ROOT = $(HTMLDIR)
PORTS = 8080

# only set main compile options if none were chosen

LIBS = -lpthread -lm

ifdef CONFIG_FILE
  CFLAGS += -DCONFIG_FILE=\"$(CONFIG_FILE)\"
endif

ifdef CONFIG_FILE2
  CFLAGS += -DCONFIG_FILE2=\"$(CONFIG_FILE2)\"
endif

ifdef SSL_LIB
  CFLAGS += -DSSL_LIB=\"$(SSL_LIB)\"
endif

ifdef CRYPTO_LIB
  CFLAGS += -DCRYPTO_LIB=\"$(CRYPTO_LIB)\"
endif

ifneq ($(OS),Windows_NT)
OS:=$(shell uname -s)
endif

DFLAGS = -DUSE_STACK_SIZE=102400 -DUSE_WEBSOCKET -DUSE_IPV6

INCDIR = include/
LIBDIR = lib/
OBJDIR = obj/
SRCDIR = src/
CC     = cc
RM     = /bin/rm -f
OBJEXT = .o
LIBEXT = .a
OFLAG  = -o
AR     = ar
ARQC   = qc 
ARQ    = q
RANLIB = ranlib

CFLAGS=	-Wall \
	-Wextra \
	-Wstrict-prototypes \
	-Wshadow \
	-Wpointer-arith \
	-Wformat-security \
	-Winit-self \
	-Wcast-qual \
	-Wcast-align \
	-Wwrite-strings \
	-Wnested-externs \
	-Wredundant-decls \
	-Werror \
	-O3 \
	-funsigned-char \
	-I${INCDIR}

ifeq ($(OS),Windows_NT)
INCDIR = include\\
LIBDIR = lib\\
OBJDIR = obj\\
SRCDIR = src\\
CC     = cl
RM     = del /q
OBJEXT = .obj
LIBEXT = .lib
OFLAG  = -Fo
AR     = lib
ARQC   = /NOLOGO /OUT:
ARQ    = /NOLOGO
RANLIB = dir

CFLAGS = -Ox -Ot -MT -GT -volatile:iso -I${INCDIR} -nologo -J -sdl -Wall -WX -wd4464 -wd4710 -wd4711 -wd4201 -wd4820
endif

${OBJDIR}%${OBJEXT} : ${SRCDIR}%.c
	${CC} -c ${CPPFLAGS} ${CFLAGS} ${DFLAGS} ${OFLAG}$@ $<

all: ${LIBDIR}libhttp${LIBEXT}

clean:
	${RM} ${OBJDIR}*${OBJEXT}
	${RM} ${LIBDIR}libhttp${LIBEXT}

OBJLIST =									\
	${OBJDIR}extern_md5${OBJEXT}						\
	${OBJDIR}extern_sha1${OBJEXT}						\
	${OBJDIR}extern_ssl_lut${OBJEXT}					\
	${OBJDIR}httplib_accept_new_connection${OBJEXT}				\
	${OBJDIR}httplib_addenv${OBJEXT}					\
	${OBJDIR}httplib_atomic_dec${OBJEXT}					\
	${OBJDIR}httplib_atomic_inc${OBJEXT}					\
	${OBJDIR}httplib_authorize${OBJEXT}					\
	${OBJDIR}httplib_base64_encode${OBJEXT}					\
	${OBJDIR}httplib_check_acl${OBJEXT}					\
	${OBJDIR}httplib_check_authorization${OBJEXT}				\
	${OBJDIR}httplib_check_feature${OBJEXT}					\
	${OBJDIR}httplib_check_password${OBJEXT}				\
	${OBJDIR}httplib_close_all_listening_sockets${OBJEXT}			\
	${OBJDIR}httplib_close_connection${OBJEXT}				\
	${OBJDIR}httplib_close_socket_gracefully${OBJEXT}			\
	${OBJDIR}httplib_closedir${OBJEXT}					\
	${OBJDIR}httplib_compare_dir_entries${OBJEXT}				\
	${OBJDIR}httplib_config_options${OBJEXT}				\
	${OBJDIR}httplib_connect_client${OBJEXT}				\
	${OBJDIR}httplib_connect_socket${OBJEXT}				\
	${OBJDIR}httplib_connect_websocket_client${OBJEXT}			\
	${OBJDIR}httplib_construct_etag${OBJEXT}				\
	${OBJDIR}httplib_consume_socket${OBJEXT}				\
	${OBJDIR}httplib_cry${OBJEXT}						\
	${OBJDIR}httplib_delete_file${OBJEXT}					\
	${OBJDIR}httplib_difftimespec${OBJEXT}					\
	${OBJDIR}httplib_dir_scan_callback${OBJEXT}				\
	${OBJDIR}httplib_discard_unread_request_data${OBJEXT}			\
	${OBJDIR}httplib_download${OBJEXT}					\
	${OBJDIR}httplib_event_queue${OBJEXT}					\
	${OBJDIR}httplib_fc${OBJEXT}						\
	${OBJDIR}httplib_fclose${OBJEXT}					\
	${OBJDIR}httplib_fclose_on_exec${OBJEXT}				\
	${OBJDIR}httplib_fgets${OBJEXT}						\
	${OBJDIR}httplib_fopen${OBJEXT}						\
	${OBJDIR}httplib_forward_body_data${OBJEXT}				\
	${OBJDIR}httplib_free_context${OBJEXT}					\
	${OBJDIR}httplib_get_builtin_mime_type${OBJEXT}				\
	${OBJDIR}httplib_get_context${OBJEXT}					\
	${OBJDIR}httplib_get_cookie${OBJEXT}					\
	${OBJDIR}httplib_get_first_ssl_listener_index${OBJEXT}			\
	${OBJDIR}httplib_get_header${OBJEXT}					\
	${OBJDIR}httplib_get_mime_type${OBJEXT}					\
	${OBJDIR}httplib_get_option${OBJEXT}					\
	${OBJDIR}httplib_get_option_index${OBJEXT}				\
	${OBJDIR}httplib_get_random${OBJEXT}					\
	${OBJDIR}httplib_get_rel_url_at_current_server${OBJEXT}			\
	${OBJDIR}httplib_get_remote_ip${OBJEXT}					\
	${OBJDIR}httplib_get_request_handler${OBJEXT}				\
	${OBJDIR}httplib_get_request_info${OBJEXT}				\
	${OBJDIR}httplib_get_request_len${OBJEXT}				\
	${OBJDIR}httplib_get_response${OBJEXT}					\
	${OBJDIR}httplib_get_response_code_text${OBJEXT}			\
	${OBJDIR}httplib_get_server_ports${OBJEXT}				\
	${OBJDIR}httplib_get_system_name${OBJEXT}				\
	${OBJDIR}httplib_get_uri_type${OBJEXT}					\
	${OBJDIR}httplib_get_user_connection_data${OBJEXT}			\
	${OBJDIR}httplib_get_user_data${OBJEXT}					\
	${OBJDIR}httplib_get_valid_options${OBJEXT}				\
	${OBJDIR}httplib_get_var${OBJEXT}					\
	${OBJDIR}httplib_getreq${OBJEXT}					\
	${OBJDIR}httplib_global_data${OBJEXT}					\
	${OBJDIR}httplib_gmt_time_string${OBJEXT}				\
	${OBJDIR}httplib_handle_cgi_request${OBJEXT}				\
	${OBJDIR}httplib_handle_directory_request${OBJEXT}			\
	${OBJDIR}httplib_handle_file_based_request${OBJEXT}			\
	${OBJDIR}httplib_handle_form_request${OBJEXT}				\
	${OBJDIR}httplib_handle_not_modified_static_file_request${OBJEXT}	\
	${OBJDIR}httplib_handle_propfind${OBJEXT}				\
	${OBJDIR}httplib_handle_request${OBJEXT}				\
	${OBJDIR}httplib_handle_static_file_request${OBJEXT}			\
	${OBJDIR}httplib_handle_websocket_request${OBJEXT}			\
	${OBJDIR}httplib_header_has_option${OBJEXT}				\
	${OBJDIR}httplib_inet_pton${OBJEXT}					\
	${OBJDIR}httplib_initialize_ssl${OBJEXT}				\
	${OBJDIR}httplib_interpret_uri${OBJEXT}					\
	${OBJDIR}httplib_is_authorized_for_put${OBJEXT}				\
	${OBJDIR}httplib_is_file_in_memory${OBJEXT}				\
	${OBJDIR}httplib_is_file_opened${OBJEXT}				\
	${OBJDIR}httplib_is_not_modified${OBJEXT}				\
	${OBJDIR}httplib_is_put_or_delete_method${OBJEXT}			\
	${OBJDIR}httplib_is_valid_http_method${OBJEXT}				\
	${OBJDIR}httplib_is_valid_port${OBJEXT}					\
	${OBJDIR}httplib_is_websocket_protocol${OBJEXT}				\
	${OBJDIR}httplib_join_thread${OBJEXT}					\
	${OBJDIR}httplib_load_dll${OBJEXT}					\
	${OBJDIR}httplib_lock_unlock_connection${OBJEXT}			\
	${OBJDIR}httplib_lock_unlock_context${OBJEXT}				\
	${OBJDIR}httplib_log_access${OBJEXT}					\
	${OBJDIR}httplib_lowercase${OBJEXT}					\
	${OBJDIR}httplib_malloc${OBJEXT}					\
	${OBJDIR}httplib_master_thread${OBJEXT}					\
	${OBJDIR}httplib_match_prefix${OBJEXT}					\
	${OBJDIR}httplib_md5${OBJEXT}						\
	${OBJDIR}httplib_mkcol${OBJEXT}						\
	${OBJDIR}httplib_mkdir${OBJEXT}						\
	${OBJDIR}httplib_modify_passwords_file${OBJEXT}				\
	${OBJDIR}httplib_must_hide_file${OBJEXT}				\
	${OBJDIR}httplib_next_option${OBJEXT}					\
	${OBJDIR}httplib_open_auth_file${OBJEXT}				\
	${OBJDIR}httplib_opendir${OBJEXT}					\
	${OBJDIR}httplib_parse_auth_header${OBJEXT}				\
	${OBJDIR}httplib_parse_date_string${OBJEXT}				\
	${OBJDIR}httplib_parse_http_headers${OBJEXT}				\
	${OBJDIR}httplib_parse_http_message${OBJEXT}				\
	${OBJDIR}httplib_parse_net${OBJEXT}					\
	${OBJDIR}httplib_parse_range_header${OBJEXT}				\
	${OBJDIR}httplib_path_to_unicode${OBJEXT}				\
	${OBJDIR}httplib_poll${OBJEXT}						\
	${OBJDIR}httplib_prepare_cgi_environment${OBJEXT}			\
	${OBJDIR}httplib_print_dir_entry${OBJEXT}				\
	${OBJDIR}httplib_printf${OBJEXT}					\
	${OBJDIR}httplib_process_new_connection${OBJEXT}			\
	${OBJDIR}httplib_produce_socket${OBJEXT}				\
	${OBJDIR}httplib_pull${OBJEXT}						\
	${OBJDIR}httplib_pull_all${OBJEXT}					\
	${OBJDIR}httplib_push_all${OBJEXT}					\
	${OBJDIR}httplib_put_dir${OBJEXT}					\
	${OBJDIR}httplib_put_file${OBJEXT}					\
	${OBJDIR}httplib_read${OBJEXT}						\
	${OBJDIR}httplib_read_auth_file${OBJEXT}				\
	${OBJDIR}httplib_read_request${OBJEXT}					\
	${OBJDIR}httplib_read_websocket${OBJEXT}				\
	${OBJDIR}httplib_readdir${OBJEXT}					\
	${OBJDIR}httplib_realloc2${OBJEXT}					\
	${OBJDIR}httplib_redirect_to_https_port${OBJEXT}			\
	${OBJDIR}httplib_refresh_trust${OBJEXT}					\
	${OBJDIR}httplib_remove${OBJEXT}					\
	${OBJDIR}httplib_remove_bad_file${OBJEXT}				\
	${OBJDIR}httplib_remove_directory${OBJEXT}				\
	${OBJDIR}httplib_remove_double_dots${OBJEXT}				\
	${OBJDIR}httplib_reset_per_request_attributes${OBJEXT}			\
	${OBJDIR}httplib_scan_directory${OBJEXT}				\
	${OBJDIR}httplib_send_authorization_request${OBJEXT}			\
	${OBJDIR}httplib_send_file${OBJEXT}					\
	${OBJDIR}httplib_send_file_data${OBJEXT}				\
	${OBJDIR}httplib_send_http_error${OBJEXT}				\
	${OBJDIR}httplib_send_no_cache_header${OBJEXT}				\
	${OBJDIR}httplib_send_options${OBJEXT}					\
	${OBJDIR}httplib_send_static_cache_header${OBJEXT}			\
	${OBJDIR}httplib_send_websocket_handshake${OBJEXT}			\
	${OBJDIR}httplib_set_acl_option${OBJEXT}				\
	${OBJDIR}httplib_set_auth_handler${OBJEXT}				\
	${OBJDIR}httplib_set_close_on_exec${OBJEXT}				\
	${OBJDIR}httplib_set_gpass_option${OBJEXT}				\
	${OBJDIR}httplib_set_handler_type${OBJEXT}				\
	${OBJDIR}httplib_set_non_blocking_mode${OBJEXT}				\
	${OBJDIR}httplib_set_ports_option${OBJEXT}				\
	${OBJDIR}httplib_set_request_handler${OBJEXT}				\
	${OBJDIR}httplib_set_ssl_option${OBJEXT}				\
	${OBJDIR}httplib_set_sock_timeout${OBJEXT}				\
	${OBJDIR}httplib_set_tcp_nodelay${OBJEXT}				\
	${OBJDIR}httplib_set_thread_name${OBJEXT}				\
	${OBJDIR}httplib_set_throttle${OBJEXT}					\
	${OBJDIR}httplib_set_uid_option${OBJEXT}				\
	${OBJDIR}httplib_set_user_connection_data${OBJEXT}			\
	${OBJDIR}httplib_set_websocket_handler${OBJEXT}				\
	${OBJDIR}httplib_should_decode_url${OBJEXT}				\
	${OBJDIR}httplib_should_keep_alive${OBJEXT}				\
	${OBJDIR}httplib_skip${OBJEXT}						\
	${OBJDIR}httplib_skip_quoted${OBJEXT}					\
	${OBJDIR}httplib_snprintf${OBJEXT}					\
	${OBJDIR}httplib_sockaddr_to_string${OBJEXT}				\
	${OBJDIR}httplib_spawn_process${OBJEXT}					\
	${OBJDIR}httplib_ssi${OBJEXT}						\
	${OBJDIR}httplib_ssl_error${OBJEXT}					\
	${OBJDIR}httplib_ssl_get_client_cert_info${OBJEXT}			\
	${OBJDIR}httplib_ssl_get_protocol${OBJEXT}				\
	${OBJDIR}httplib_ssl_id_callback${OBJEXT}				\
	${OBJDIR}httplib_ssl_locking_callback${OBJEXT}				\
	${OBJDIR}httplib_ssl_use_pem_file${OBJEXT}				\
	${OBJDIR}httplib_sslize${OBJEXT}					\
	${OBJDIR}httplib_start${OBJEXT}						\
	${OBJDIR}httplib_start_thread${OBJEXT}					\
	${OBJDIR}httplib_start_thread_with_id${OBJEXT}				\
	${OBJDIR}httplib_stat${OBJEXT}						\
	${OBJDIR}httplib_stop${OBJEXT}						\
	${OBJDIR}httplib_store_body${OBJEXT}					\
	${OBJDIR}httplib_strlcpy${OBJEXT}					\
	${OBJDIR}httplib_strcasecmp${OBJEXT}					\
	${OBJDIR}httplib_strcasestr${OBJEXT}					\
	${OBJDIR}httplib_strdup${OBJEXT}					\
	${OBJDIR}httplib_strncasecmp${OBJEXT}					\
	${OBJDIR}httplib_strndup${OBJEXT}					\
	${OBJDIR}httplib_substitute_index_file${OBJEXT}				\
	${OBJDIR}httplib_suggest_connection_header${OBJEXT}			\
	${OBJDIR}httplib_timer${OBJEXT}						\
	${OBJDIR}httplib_tls_dtor${OBJEXT}					\
	${OBJDIR}httplib_uninitialize_ssl${OBJEXT}				\
	${OBJDIR}httplib_url_decode${OBJEXT}					\
	${OBJDIR}httplib_url_encode${OBJEXT}					\
	${OBJDIR}httplib_version${OBJEXT}					\
	${OBJDIR}httplib_vprintf${OBJEXT}					\
	${OBJDIR}httplib_vsnprintf${OBJEXT}					\
	${OBJDIR}httplib_websocket_client_thread${OBJEXT}			\
	${OBJDIR}httplib_websocket_client_write${OBJEXT}			\
	${OBJDIR}httplib_websocket_write${OBJEXT}				\
	${OBJDIR}httplib_websocket_write_exec${OBJEXT}				\
	${OBJDIR}httplib_worker_thread${OBJEXT}					\
	${OBJDIR}httplib_write${OBJEXT}						\
	${OBJDIR}osx_clock_gettime${OBJEXT}					\
	${OBJDIR}win32_clock_gettime${OBJEXT}					\
	${OBJDIR}win32_pthread_cond_broadcast${OBJEXT}				\
	${OBJDIR}win32_pthread_cond_destroy${OBJEXT}				\
	${OBJDIR}win32_pthread_cond_init${OBJEXT}				\
	${OBJDIR}win32_pthread_cond_signal${OBJEXT}				\
	${OBJDIR}win32_pthread_cond_timedwait${OBJEXT}				\
	${OBJDIR}win32_pthread_cond_wait${OBJEXT}				\
	${OBJDIR}win32_pthread_getspecific${OBJEXT}				\
	${OBJDIR}win32_pthread_key_create${OBJEXT}				\
	${OBJDIR}win32_pthread_key_delete${OBJEXT}				\
	${OBJDIR}win32_pthread_mutex_destroy${OBJEXT}				\
	${OBJDIR}win32_pthread_mutex_init${OBJEXT}				\
	${OBJDIR}win32_pthread_mutex_lock${OBJEXT}				\
	${OBJDIR}win32_pthread_mutex_trylock${OBJEXT}				\
	${OBJDIR}win32_pthread_mutex_unlock${OBJEXT}				\
	${OBJDIR}win32_pthread_self${OBJEXT}					\
	${OBJDIR}win32_pthread_setspecific${OBJEXT}				\
	${OBJDIR}wince_gmtime${OBJEXT}						\
	${OBJDIR}wince_gmtime_s${OBJEXT}					\
	${OBJDIR}wince_localtime${OBJEXT}					\
	${OBJDIR}wince_localtime_s${OBJEXT}					\
	${OBJDIR}wince_rename${OBJEXT}						\
	${OBJDIR}wince_stat${OBJEXT}						\
	${OBJDIR}wince_strftime${OBJEXT}					\
	${OBJDIR}wince_time${OBJEXT}

#
# Creation of the library from the individually compiled object files
#

${LIBDIR}libhttp${LIBEXT} :	\
	${OBJLIST}		\
	Makefile
		${RM}        ${LIBDIR}libhttp${LIBEXT}
		${AR} ${ARQC}${LIBDIR}libhttp${LIBEXT} ${OBJLIST}
		${RANLIB}    ${LIBDIR}libhttp${LIBEXT}

#
# Individual source files with their header dependencies
#

${OBJDIR}extern_md5${OBJEXT}				: ${SRCDIR}extern_md5.c

${OBJDIR}extern_sha1${OBJEXT}				: ${SRCDIR}extern_sha1.c

${OBJDIR}extern_ssl_lut${OBJEXT}			: ${SRCDIR}extern_ssl_lut.c

${OBJDIR}httplib_accept_new_connection${OBJEXT}		: ${SRCDIR}httplib_accept_new_connection.c

${OBJDIR}httplib_addenv${OBJEXT}			: ${SRCDIR}httplib_addenv.c

${OBJDIR}httplib_atomic_dec${OBJEXT}			: ${SRCDIR}httplib_atomic_dec.c

${OBJDIR}httplib_atomic_inc${OBJEXT}			: ${SRCDIR}httplib_atomic_inc.c

${OBJDIR}httplib_authorize${OBJEXT}			: ${SRCDIR}httplib_authorize.c

${OBJDIR}httplib_base64_encode${OBJEXT}			: ${SRCDIR}httplib_base64_encode.c

${OBJDIR}httplib_check_acl${OBJEXT}			: ${SRCDIR}httplib_check_acl.c

${OBJDIR}httplib_check_authorization${OBJEXT}		: ${SRCDIR}httplib_check_authorization.c

${OBJDIR}httplib_check_feature${OBJEXT}			: ${SRCDIR}httplib_check_feature.c

${OBJDIR}httplib_check_password${OBJEXT}		: ${SRCDIR}httplib_check_password.c

${OBJDIR}httplib_close_all_listening_sockets${OBJDIR}	: ${SRCDIR}httplib_close_all_listening_sockets.c

${OBJDIR}httplib_close_connection${OBJEXT}		: ${SRCDIR}httplib_close_connection.c	\
							  ${SRCDIR}httplib_pthread.h

${OBJDIR}httplib_close_socket_gracefully${OBJEXT}	: ${SRCDIR}httplib_close_socket_gracefully.c

${OBJDIR}httplib_closedir${OBJEXT}			: ${SRCDIR}httplib_closedir.c

${OBJDIR}httplib_compare_dir_entries${OBJEXT}		: ${SRCDIR}httplib_compare_dir_entries.c

${OBJDIR}httplib_config_options${OBJEXT}		: ${SRCDIR}httplib_config_options.c

${OBJDIR}httplib_connect_client${OBJEXT}		: ${SRCDIR}httplib_connect_client.c	\
							  ${SRCDIR}httplib_pthread.h

${OBJDIR}httplib_connect_socket${OBJEXT}		: ${SRCDIR}httplib_connect_socket.c

${OBJDIR}httplib_connect_websocket_client${OBJEXT}	: ${SRCDIR}httplib_connect_websocket_client.c

${OBJDIR}httplib_construct_etag${OBJEXT}		: ${SRCDIR}httplib_construct_etag.c

${OBJDIR}httplib_consume_socket${OBJEXT}		: ${SRCDIR}httplib_consume_socket.c	\
							  ${SRCDIR}httplib_pthread.h

${OBJDIR}httplib_cry${OBJEXT}				: ${SRCDIR}httplib_cry.c

${OBJDIR}httplib_delete_file${OBJEXT}			: ${SRCDIR}httplib_delete_file.c

${OBJDIR}httplib_difftimespec${OBJEXT}			: ${SRCDIR}httplib_difftimespec.c

${OBJDIR}httplib_dir_scan_callback${OBJEXT}		: ${SRCDIR}httplib_dir_scan_callback.c

${OBJDIR}httplib_discard_unread_request_data${OBJEXT}	: ${SRCDIR}httplib_discard_unread_request_data.c

${OBJDIR}httplib_download${OBJEXT}			: ${SRCDIR}httplib_download.c

${OBJDIR}httplib_event_queue${OBJEXT}			: ${SRCDIR}httplib_event_queue.c

${OBJDIR}httplib_fc${OBJEXT}				: ${SRCDIR}httplib_fc.c

${OBJDIR}httplib_fclose${OBJEXT}			: ${SRCDIR}httplib_fclose.c

${OBJDIR}httplib_fclose_on_exec${OBJEXT}		: ${SRCDIR}httplib_fclose_on_exec.c

${OBJDIR}httplib_fgets${OBJEXT}				: ${SRCDIR}httplib_fgets.c

${OBJDIR}httplib_fopen${OBJEXT}				: ${SRCDIR}httplib_fopen.c

${OBJDIR}httplib_forward_body_data${OBJEXT}		: ${SRCDIR}httplib_forward_body_data.c

${OBJDIR}httplib_free_context${OBJEXT}			: ${SRCDIR}httplib_free_context.c	\
							  ${SRCDIR}httplib_pthread.h

${OBJDIR}httplib_get_builtin_mime_type${OBJEXT}		: ${SRCDIR}httplib_get_builtin_mime_type.c

${OBJDIR}httplib_get_context${OBJEXT}			: ${SRCDIR}httplib_get_context.c

${OBJDIR}httplib_get_cookie${OBJEXT}			: ${SRCDIR}httplib_get_cookie.c

${OBJDIR}httplib_get_first_ssl_listener_index${OBJEXT}	: ${SRCDIR}httplib_get_first_ssl_listener_index.c

${OBJDIR}httplib_get_header${OBJEXT}			: ${SRCDIR}httplib_get_header.c

${OBJDIR}httplib_get_mime_type${OBJEXT}			: ${SRCDIR}httplib_get_mime_type.c

${OBJDIR}httplib_get_option${OBJEXT}			: ${SRCDIR}httplib_get_option.c

${OBJDIR}httplib_get_option_index${OBJEXT}		: ${SRCDIR}httplib_get_option_index.c

${OBJDIR}httplib_get_random${OBJEXT}			: ${SRCDIR}httplib_get_random.c

${OBJDIR}httplib_get_rel_url_at_current_server${OBJEXT}	: ${SRCDIR}httplib_get_rel_url_at_current_server.c

${OBJDIR}httplib_get_remote_ip${OBJEXT}			: ${SRCDIR}httplib_get_remote_ip.c

${OBJDIR}httplib_get_request_handler${OBJEXT}		: ${SRCDIR}httplib_get_request_handler.c

${OBJDIR}httplib_get_request_info${OBJEXT}		: ${SRCDIR}httplib_get_request_info.c

${OBJDIR}httplib_get_request_len${OBJEXT}		: ${SRCDIR}httplib_get_request_len.c

${OBJDIR}httplib_get_response${OBJEXT}			: ${SRCDIR}httplib_get_response.c

${OBJDIR}httplib_get_response_code_text${OBJEXT}	: ${SRCDIR}httplib_get_response_code_text.c

${OBJDIR}httplib_get_server_ports${OBJEXT}		: ${SRCDIR}httplib_get_server_ports.c

${OBJDIR}httplib_get_system_name${OBJEXT}		: ${SRCDIR}httplib_get_system_name.c

${OBJDIR}httplib_get_uri_type${OBJEXT}			: ${SRCDIR}httplib_get_uri_type.c

${OBJDIR}httplib_get_user_connection_data${OBJEXT}	: ${SRCDIR}httplib_get_user_connection_data.c

${OBJDIR}httplib_get_user_data${OBJEXT}			: ${SRCDIR}httplib_get_user_data.c

${OBJDIR}httplib_get_valid_options${OBJEXT}		: ${SRCDIR}httplib_get_valid_options.c

${OBJDIR}httplib_get_var${OBJEXT}			: ${SRCDIR}httplib_get_var.c

${OBJDIR}httplib_getreq${OBJEXT}			: ${SRCDIR}httplib_getreq.c

${OBJDIR}httplib_global_data${OBJEXT}			: ${SRCDIR}httplib_global_data.c

${OBJDIR}httplib_gmt_time_string${OBJEXT}		: ${SRCDIR}httplib_gmt_time_string.c

${OBJDIR}httplib_handle_cgi_request${OBJEXT}		: ${SRCDIR}httplib_handle_cgi_request.c

${OBJDIR}httplib_handle_directory_request${OBJEXT}	: ${SRCDIR}httplib_handle_directory_request.c

${OBJDIR}httplib_handle_file_based_request${OBJEXT}	: ${SRCDIR}httplib_handle_file_based_request.c

${OBJDIR}httplib_handle_form_request${OBJEXT}		: ${SRCDIR}httplib_handle_form_request.c

${OBJDIR}httplib_handle_not_modified_static_file_request${OBJEXT}	: ${SRCDIR}httplib_handle_not_modified_static_file_request.c

${OBJDIR}httplib_handle_propfind${OBJEXT}		: ${SRCDIR}httplib_handle_propfind.c

${OBJDIR}httplib_handle_request${OBJEXT}		: ${SRCDIR}httplib_handle_request.c

${OBJDIR}httplib_handle_static_file_request${OBJEXT}	: ${SRCDIR}httplib_handle_static_file_request.c

${OBJDIR}httplib_handle_websocket_request${OBJEXT}	: ${SRCDIR}httplib_handle_websocket_request.c

${OBJDIR}httplib_header_has_option${OBJEXT}		: ${SRCDIR}httplib_header_has_option.c

${OBJDIR}httplib_inet_pton${OBJEXT}			: ${SRCDIR}httplib_inet_pton.c

${OBJDIR}httplib_initialize_ssl${OBJEXT}		: ${SRCDIR}httplib_initialize_ssl.c	\
							  ${SRCDIR}httplib_pthread.h

${OBJDIR}httplib_interpret_uri${OBJEXT}			: ${SRCDIR}httplib_interpret_uri.c

${OBJDIR}httplib_is_authorized_for_put${OBJEXT}		: ${SRCDIR}httplib_is_authorized_for_put.c

${OBJDIR}httplib_is_file_in_memory${OBJEXT}		: ${SRCDIR}httplib_is_file_in_memory.c

${OBJDIR}httplib_is_file_opened${OBJEXT}		: ${SRCDIR}httplib_is_file_opened.c

${OBJDIR}httplib_is_not_modified${OBJEXT}		: ${SRCDIR}httplib_is_not_modified.c

${OBJDIR}httplib_is_put_or_delete_method${OBJEXT}	: ${SRCDIR}httplib_is_put_or_delete_method.c

${OBJDIR}httplib_is_valid_http_method${OBJEXT}		: ${SRCDIR}httplib_is_valid_http_method.c

${OBJDIR}httplib_is_valid_port${OBJEXT}			: ${SRCDIR}httplib_is_valid_port.c

${OBJDIR}httplib_is_websocket_protocol${OBJEXT}		: ${SRCDIR}httplib_is_websocket_protocol.c

${OBJDIR}httplib_join_thread${OBJEXT}			: ${SRCDIR}httplib_join_thread.c

${OBJDIR}httplib_load_dll${OBJEXT}			: ${SRCDIR}httplib_load_dll.c

${OBJDIR}httplib_lock_unlock_connection${OBJEXT}	: ${SRCDIR}httplib_lock_unlock_connection.c	\
							  ${SRCDIR}httplib_pthread.h

${OBJDIR}httplib_lock_unlock_context${OBJEXT}		: ${SRCDIR}httplib_lock_unlock_context.c	\
							  ${SRCDIR}httplib_pthread.h

${OBJDIR}httplib_log_access${OBJEXT}			: ${SRCDIR}httplib_log_access.c

${OBJDIR}httplib_lowercase${OBJEXT}			: ${SRCDIR}httplib_lowercase.c

${OBJDIR}httplib_malloc${OBJEXT}			: ${SRCDIR}httplib_malloc.c

${OBJDIR}httplib_master_thread${OBJEXT}			: ${SRCDIR}httplib_master_thread.c		\
							  ${SRCDIR}httplib_pthread.h

${OBJDIR}httplib_match_prefix${OBJEXT}			: ${SRCDIR}httplib_match_prefix.c

${OBJDIR}httplib_md5${OBJEXT}				: ${SRCDIR}httplib_md5.c

${OBJDIR}httplib_mkcol${OBJEXT}				: ${SRCDIR}httplib_mkcol.c

${OBJDIR}httplib_mkdir${OBJEXT}				: ${SRCDIR}httplib_mkdir.c

${OBJDIR}httplib_modify_passwords_file${OBJEXT}		: ${SRCDIR}httplib_modify_passwords_file.c

${OBJDIR}httplib_must_hide_file${OBJEXT}		: ${SRCDIR}httplib_must_hide_file.c

${OBJDIR}httplib_next_option${OBJEXT}			: ${SRCDIR}httplib_next_option.c

${OBJDIR}httplib_open_auth_file${OBJEXT}		: ${SRCDIR}httplib_open_auth_file.c

${OBJDIR}httplib_opendir${OBJEXT}			: ${SRCDIR}httplib_opendir.c

${OBJDIR}httplib_parse_auth_header${OBJEXT}		: ${SRCDIR}httplib_parse_auth_header.c

${OBJDIR}httplib_parse_date_string${OBJEXT}		: ${SRCDIR}httplib_parse_date_string.c

${OBJDIR}httplib_parse_http_headers${OBJEXT}		: ${SRCDIR}httplib_parse_http_headers.c

${OBJDIR}httplib_parse_http_message${OBJEXT}		: ${SRCDIR}httplib_parse_http_message.c

${OBJDIR}httplib_parse_net${OBJEXT}			: ${SRCDIR}httplib_parse_net.c

${OBJDIR}httplib_parse_range_header${OBJEXT}		: ${SRCDIR}httplib_parse_range_header.c

${OBJDIR}httplib_path_to_unicode${OBJEXT}		: ${SRCDIR}httplib_path_to_unicode.c

${OBJDIR}httplib_poll${OBJEXT}				: ${SRCDIR}httplib_poll.c

${OBJDIR}httplib_prepare_cgi_environment${OBJEXT}	: ${SRCDIR}httplib_prepare_cgi_environment.c

${OBJDIR}httplib_print_dir_entry${OBJEXT}		: ${SRCDIR}httplib_print_dir_entry.c

${OBJDIR}httplib_printf${OBJEXT}			: ${SRCDIR}httplib_printf.c

${OBJDIR}httplib_process_new_connection${OBJEXT}	: ${SRCDIR}httplib_process_new_connection.c

${OBJDIR}httplib_produce_socket${OBJEXT}		: ${SRCDIR}httplib_produce_socket.c		\
							  ${SRCDIR}httplib_pthread.h

${OBJDIR}httplib_pull${OBJEXT}				: ${SRCDIR}httplib_pull.c

${OBJDIR}httplib_pull_all${OBJEXT}			: ${SRCDIR}httplib_pull_all.c

${OBJDIR}httplib_push_all${OBJEXT}			: ${SRCDIR}httplib_push_all.c

${OBJDIR}httplib_put_dir${OBJEXT}			: ${SRCDIR}httplib_put_dir.c

${OBJDIR}httplib_put_file${OBJEXT}			: ${SRCDIR}httplib_put_file.c

${OBJDIR}httplib_read${OBJEXT}				: ${SRCDIR}httplib_read.c

${OBJDIR}httplib_read_auth_file${OBJEXT}		: ${SRCDIR}httplib_read_auth_file.c

${OBJDIR}httplib_read_request${OBJEXT}			: ${SRCDIR}httplib_read_request.c

${OBJDIR}httplib_read_websocket${OBJEXT}		: ${SRCDIR}httplib_read_websocket.c

${OBJDIR}httplib_readdir${OBJEXT}			: ${SRCDIR}httplib_readdir.c

${OBJDIR}httplib_realloc2${OBJEXT}			: ${SRCDIR}httplib_realloc2.c

${OBJDIR}httplib_redirect_to_https_port${OBJEXT}	: ${SRCDIR}httplib_redirect_to_https_port.c

${OBJDIR}httplib_refresh_trust${OBJEXT}			: ${SRCDIR}httplib_refresh_trust.c

${OBJDIR}httplib_remove${OBJEXT}			: ${SRCDIR}httplib_remove.c

${OBJDIR}httplib_remove_bad_file${OBJEXT}		: ${SRCDIR}httplib_remove_bad_file.c

${OBJDIR}httplib_remove_directory${OBJEXT}		: ${SRCDIR}httplib_remove_directory.c

${OBJDIR}httplib_remove_double_dots${OBJEXT}		: ${SRCDIR}httplib_remove_double_dots.c

${OBJDIR}httplib_reset_per_request_attributes${OBJEXT}	: ${SRCDIR}httplib_reset_per_request_attributes.c

${OBJDIR}httplib_scan_directory${OBJEXT}		: ${SRCDIR}httplib_scan_directory.c

${OBJDIR}httplib_send_authorization_request${OBJEXT}	: ${SRCDIR}httplib_send_authorization_request.c		\
							  ${SRCDIR}httplib_pthread.h

${OBJDIR}httplib_send_file${OBJEXT}			: ${SRCDIR}httplib_send_file.c

${OBJDIR}httplib_send_file_data${OBJEXT}		: ${SRCDIR}httplib_send_file_data.c

${OBJDIR}httplib_send_http_error${OBJEXT}		: ${SRCDIR}httplib_send_http_error.c

${OBJDIR}httplib_send_no_cache_header${OBJEXT}		: ${SRCDIR}httplib_send_no_cache_header.c

${OBJDIR}httplib_send_options${OBJEXT}			: ${SRCDIR}httplib_send_options.c

${OBJDIR}httplib_send_static_cache_header${OBJEXT}	: ${SRCDIR}httplib_send_static_cache_header.c

${OBJDIR}httplib_send_websocket_handshake${OBJEXT}	: ${SRCDIR}httplib_send_websocket_handshake.c

${OBJDIR}httplib_set_acl_option${OBJEXT}		: ${SRCDIR}httplib_set_acl_option.c

${OBJDIR}httplib_set_auth_handler${OBJEXT}		: ${SRCDIR}httplib_set_auth_handler.c

${OBJDIR}httplib_set_close_on_exec${OBJEXT}		: ${SRCDIR}httplib_set_close_on_exec.c

${OBJDIR}httplib_set_gpass_option${OBJEXT}		: ${SRCDIR}httplib_set_gpass_option.c

${OBJDIR}httplib_set_handler_type${OBJEXT}		: ${SRCDIR}httplib_set_handler_type.c

${OBJDIR}httplib_set_non_blocking_mode${OBJEXT}		: ${SRCDIR}httplib_set_non_blocking_mode.c

${OBJDIR}httplib_set_ports_option${OBJEXT}		: ${SRCDIR}httplib_set_ports_option.c

${OBJDIR}httplib_set_request_handler${OBJEXT}		: ${SRCDIR}httplib_set_request_handler.c

${OBJDIR}httplib_set_ssl_option${OBJEXT}		: ${SRCDIR}httplib_set_ssl_option.c

${OBJDIR}httplib_set_sock_timeout${OBJEXT}		: ${SRCDIR}httplib_set_sock_timeout.c

${OBJDIR}httplib_set_tcp_nodelay${OBJEXT}		: ${SRCDIR}httplib_set_tcp_nodelay.c

${OBJDIR}httplib_set_thread_name${OBJEXT}		: ${SRCDIR}httplib_set_thread_name.c

${OBJDIR}httplib_set_throttle${OBJEXT}			: ${SRCDIR}httplib_set_throttle.c

${OBJDIR}httplib_set_uid_option${OBJEXT}		: ${SRCDIR}httplib_set_uid_option.c

${OBJDIR}httplib_set_user_connection_data${OBJEXT}	: ${SRCDIR}httplib_set_user_connection_data.c

${OBJDIR}httplib_set_websocket_handler${OBJEXT}		: ${SRCDIR}httplib_set_websocket_handler.c

${OBJDIR}httplib_should_decode_url${OBJEXT}		: ${SRCDIR}httplib_should_decode_url.c

${OBJDIR}httplib_should_keep_alive${OBJEXT}		: ${SRCDIR}httplib_should_keep_alive.c

${OBJDIR}httplib_skip${OBJEXT}				: ${SRCDIR}httplib_skip.c

${OBJDIR}httplib_skip_quoted${OBJEXT}			: ${SRCDIR}httplib_skip_quoted.c

${OBJDIR}httplib_snprintf${OBJEXT}			: ${SRCDIR}httplib_snprintf.c

${OBJDIR}httplib_sockaddr_to_string${OBJEXT}		: ${SRCDIR}httplib_sockaddr_to_string.c

${OBJDIR}httplib_spawn_process${OBJEXT}			: ${SRCDIR}httplib_spawn_process.c

${OBJDIR}httplib_ssi${OBJEXT}				: ${SRCDIR}httplib_ssi.c

${OBJDIR}httplib_ssl_error${OBJEXT}			: ${SRCDIR}httplib_ssl_error.c

${OBJDIR}httplib_ssl_get_client_cert_info${OBJEXT}	: ${SRCDIR}httplib_ssl_get_client_cert_info.c

${OBJDIR}httplib_ssl_get_protocol${OBJEXT}		: ${SRCDIR}httplib_ssl_get_protocol.c

${OBJDIR}httplib_ssl_id_callback${OBJEXT}		: ${SRCDIR}httplib_ssl_id_callback.c		\
							  ${SRCDIR}httplib_pthread.h

${OBJDIR}httplib_ssl_locking_callback${OBJEXT}		: ${SRCDIR}httplib_ssl_locking_callback.c	\
							  ${SRCDIR}httplib_pthread.h

${OBJDIR}httplib_ssl_use_pem_file${OBJEXT}		: ${SRCDIR}httplib_ssl_use_pem_file.c

${OBJDIR}httplib_sslize${OBJEXT}			: ${SRCDIR}httplib_sslize.c

${OBJDIR}httplib_start${OBJEXT}				: ${SRCDIR}httplib_start.c			\
							  ${SRCDIR}httplib_pthread.h

${OBJDIR}httplib_start_thread${OBJEXT}			: ${SRCDIR}httplib_start_thread.c

${OBJDIR}httplib_start_thread_with_id${OBJEXT}		: ${SRCDIR}httplib_start_thread_with_id.c

${OBJDIR}httplib_stat${OBJEXT}				: ${SRCDIR}httplib_stat.c

${OBJDIR}httplib_stop${OBJEXT}				: ${SRCDIR}httplib_stop.c

${OBJDIR}httplib_store_body${OBJEXT}			: ${SRCDIR}httplib_store_body.c

${OBJDIR}httplib_strlcpy${OBJEXT}			: ${SRCDIR}httplib_strlcpy.c

${OBJDIR}httplib_strcasecmp${OBJEXT}			: ${SRCDIR}httplib_strcasecmp.c

${OBJDIR}httplib_strcasestr${OBJEXT}			: ${SRCDIR}httplib_strcasestr.c

${OBJDIR}httplib_strdup${OBJEXT}			: ${SRCDIR}httplib_strdup.c

${OBJDIR}httplib_strncasecmp${OBJEXT}			: ${SRCDIR}httplib_strncasecmp.c

${OBJDIR}httplib_strndup${OBJEXT}			: ${SRCDIR}httplib_strndup.c

${OBJDIR}httplib_substitute_index_file${OBJEXT}		: ${SRCDIR}httplib_substitute_index_file.c

${OBJDIR}httplib_suggest_connection_header${OBJEXT}	: ${SRCDIR}httplib_suggest_connection_header.c

${OBJDIR}httplib_timer${OBJEXT}				: ${SRCDIR}httplib_timer.c

${OBJDIR}httplib_tls_dtor${OBJEXT}			: ${SRCDIR}httplib_tls_dtor.c			\
							  ${SRCDIR}httplib_pthread.h

${OBJDIR}httplib_uninitialize_ssl${OBJEXT}		: ${SRCDIR}httplib_uninitialize_ssl.c		\
							  ${SRCDIR}httplib_pthread.h

${OBJDIR}httplib_url_decode${OBJEXT}			: ${SRCDIR}httplib_url_decode.c

${OBJDIR}httplib_url_encode${OBJEXT}			: ${SRCDIR}httplib_url_encode.c

${OBJDIR}httplib_version${OBJEXT}			: ${SRCDIR}httplib_version.c

${OBJDIR}httplib_vprintf${OBJEXT}			: ${SRCDIR}httplib_vprintf.c

${OBJDIR}httplib_vsnprintf${OBJEXT}			: ${SRCDIR}httplib_vsnprintf.c

${OBJDIR}httplib_websocket_client_thread${OBJEXT}	: ${SRCDIR}httplib_websocket_client_thread.c

${OBJDIR}httplib_websocket_client_write${OBJEXT}	: ${SRCDIR}httplib_websocket_client_write.c

${OBJDIR}httplib_websocket_write${OBJEXT}		: ${SRCDIR}httplib_websocket_write.c

${OBJDIR}httplib_websocket_write_exec${OBJEXT}		: ${SRCDIR}httplib_websocket_write_exec.c

${OBJDIR}httplib_worker_thread${OBJEXT}			: ${SRCDIR}httplib_worker_thread.c		\
							  ${SRCDIR}httplib_pthread.h

${OBJDIR}httplib_write${OBJEXT}				: ${SRCDIR}httplib_write.c

${OBJDIR}osx_clock_gettime${OBJEXT}			: ${SRCDIR}osx_clock_gettime.c

${OBJDIR}win32_clock_gettime${OBJEXT}			: ${SRCDIR}win32_clock_gettime.c

${OBJDIR}win32_pthread_cond_broadcast${OBJEXT}		: ${SRCDIR}win32_pthread_cond_broadcast.c	\
							  ${SRCDIR}httplib_pthread.h

${OBJDIR}win32_pthread_cond_destroy${OBJEXT}		: ${SRCDIR}win32_pthread_cond_destroy.c		\
							  ${SRCDIR}httplib_pthread.h

${OBJDIR}win32_pthread_cond_init${OBJEXT}		: ${SRCDIR}win32_pthread_cond_init.c		\
							  ${SRCDIR}httplib_pthread.h

${OBJDIR}win32_pthread_cond_signal${OBJEXT}		: ${SRCDIR}win32_pthread_cond_signal.c		\
							  ${SRCDIR}httplib_pthread.h

${OBJDIR}win32_pthread_cond_timedwait${OBJEXT}		: ${SRCDIR}win32_pthread_cond_timedwait.c	\
							  ${SRCDIR}httplib_pthread.h

${OBJDIR}win32_pthread_cond_wait${OBJEXT}		: ${SRCDIR}win32_pthread_cond_wait.c		\
							  ${SRCDIR}httplib_pthread.h

${OBJDIR}win32_pthread_getspecific${OBJEXT}		: ${SRCDIR}win32_pthread_getspecific.c		\
							  ${SRCDIR}httplib_pthread.h

${OBJDIR}win32_pthread_key_create${OBJEXT}		: ${SRCDIR}win32_pthread_key_create.c		\
							  ${SRCDIR}httplib_pthread.h

${OBJDIR}win32_pthread_key_delete${OBJEXT}		: ${SRCDIR}win32_pthread_key_delete.c		\
							  ${SRCDIR}httplib_pthread.h

${OBJDIR}win32_pthread_mutex_destroy${OBJEXT}		: ${SRCDIR}win32_pthread_mutex_destroy.c	\
							  ${SRCDIR}httplib_pthread.h

${OBJDIR}win32_pthread_mutex_init${OBJEXT}		: ${SRCDIR}win32_pthread_mutex_init.c		\
							  ${SRCDIR}httplib_pthread.h

${OBJDIR}win32_pthread_mutex_lock${OBJEXT}		: ${SRCDIR}win32_pthread_mutex_lock.c		\
							  ${SRCDIR}httplib_pthread.h

${OBJDIR}win32_pthread_mutex_trylock${OBJEXT}		: ${SRCDIR}win32_pthread_mutex_trylock.c	\
							  ${SRCDIR}httplib_pthread.h

${OBJDIR}win32_pthread_mutex_unlock${OBJEXT}		: ${SRCDIR}win32_pthread_mutex_unlock.c		\
							  ${SRCDIR}httplib_pthread.h

${OBJDIR}win32_pthread_self${OBJEXT}			: ${SRCDIR}win32_pthread_self.c			\
							  ${SRCDIR}httplib_pthread.h

${OBJDIR}win32_pthread_setspecific${OBJEXT}		: ${SRCDIR}win32_pthread_setspecific.c		\
							  ${SRCDIR}httplib_pthread.h

${OBJDIR}wince_gmtime${OBJEXT}				: ${SRCDIR}wince_gmtime.c

${OBJDIR}wince_gmtime_s${OBJEXT}			: ${SRCDIR}wince_gmtime_s.c

${OBJDIR}wince_localtime${OBJEXT}			: ${SRCDIR}wince_localtime.c

${OBJDIR}wince_localtime_s${OBJEXT}			: ${SRCDIR}wince_localtime_s.c

${OBJDIR}wince_rename${OBJEXT}				: ${SRCDIR}wince_rename.c

${OBJDIR}wince_stat${OBJEXT}				: ${SRCDIR}wince_stat.c

${OBJDIR}wince_strftime${OBJEXT}			: ${SRCDIR}wince_strftime.c

${OBJDIR}wince_time${OBJEXT}				: ${SRCDIR}wince_time.c

