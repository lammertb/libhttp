#
# Copyright (c) 2016 Lammert Bies
# Copyright (c) 2013 No Face Press, LLC
# License http://opensource.org/licenses/mit-license.php MIT License
#

#
# For help try, "make help"
#

include resources/Makefile.in-os

CPROG = libhttp
#CXXPROG = libhttp
UNIT_TEST_PROG = libhttp_test

BUILD_DIR = out

# Installation directories by convention
# http://www.gnu.org/prep/standards/html_node/Directory-Variables.html
PREFIX = /usr/local
EXEC_PREFIX = $(PREFIX)
BINDIR = $(EXEC_PREFIX)/bin
DATAROOTDIR = $(PREFIX)/share
DOCDIR = $(DATAROOTDIR)/doc/$(CPROG)
SYSCONFDIR = $(PREFIX)/etc
HTMLDIR = $(DOCDIR)

# build tools
MKDIR = mkdir -p
RMF = rm -f
RMRF = rm -rf

# desired configuration of the document root
# never assume that the document_root actually
# exists on the build machine.  When building
# a chroot, PREFIX if just a directory which
# later becomes /.
DOCUMENT_ROOT = $(HTMLDIR)
PORTS = 8080

BUILD_DIRS = $(BUILD_DIR) $(BUILD_DIR)/src $(BUILD_DIR)/resources

LIB_SOURCES =	src/libhttp.c					\
		src/httplib_accept_new_connection.c		\
		src/httplib_check_feature.c			\
		src/httplib_connect_client.c			\
		src/httplib_connect_websocket_client.c		\
		src/httplib_consume_socket.c			\
		src/httplib_download.c				\
		src/httplib_free_context.c			\
		src/httplib_get_rel_url_at_current_server.c	\
		src/httplib_get_response.c			\
		src/httplib_get_response_code_text.c		\
		src/httplib_get_system_name.c			\
		src/httplib_get_uri_type.c			\
		src/httplib_getreq.c				\
		src/httplib_master_thread.c			\
		src/httplib_process_new_connection.c		\
		src/httplib_produce_socket.c			\
		src/httplib_start.c				\
		src/httplib_stop.c				\
		src/httplib_version.c				\
		src/httplib_websocket_client_thread.c		\
		src/httplib_worker_thread.c
LIB_INLINE  = src/mod_lua.inl src/md5.inl
APP_SOURCES = src/main.c
WINDOWS_RESOURCES = resources/res.rc
UNIT_TEST_SOURCES = test/unit_test.c
SOURCE_DIRS =

OBJECTS = $(LIB_SOURCES:.c=.o) $(APP_SOURCES:.c=.o)
BUILD_RESOURCES =

# The unit tests include the source files directly to get visibility to the
# static functions.  So we clear OBJECTS so that we don't try to build or link
# with any external object.
ifeq ($(MAKECMDGOALS), unit_test)
OBJECTS =
BUILD_DIRS += $(BUILD_DIR)/test
endif

# only set main compile options if none were chosen
CFLAGS += -Wall -Wextra -Werror -Wshadow -Wformat-security -Winit-self -Wmissing-prototypes -D$(TARGET_OS) -Iinclude $(COPT) -DUSE_STACK_SIZE=102400 -DUSE_WEBSOCKET

LIBS = -lpthread -lm

ifdef WITH_DEBUG
  CFLAGS += -g -DDEBUG
else
  CFLAGS += -O2 -DNDEBUG
endif

ifdef WITH_CPP
  OBJECTS += src/LibHTTPtServer.o
  LCC = $(CXX)
else
  LCC = $(CC)
endif

ifdef WITH_IPV6
  CFLAGS += -DUSE_IPV6
endif

ifdef WITH_WEBSOCKET
  CFLAGS += -DUSE_WEBSOCKET
endif

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

BUILD_DIRS += $(addprefix $(BUILD_DIR)/, $(SOURCE_DIRS))
BUILD_OBJECTS = $(addprefix $(BUILD_DIR)/, $(OBJECTS))
MAIN_OBJECTS = $(addprefix $(BUILD_DIR)/, $(APP_SOURCES:.c=.o))
LIB_OBJECTS = $(filter-out $(MAIN_OBJECTS), $(BUILD_OBJECTS))

ifeq ($(TARGET_OS),LINUX)
  LIBS += -lrt -ldl
  CAN_INSTALL = 1
endif

ifeq ($(TARGET_OS),WIN32)
  MKDIR = mkdir
  RMF = del /q
  RMRF = rmdir /s /q
endif

ifneq (, $(findstring mingw32, $(shell $(CC) -dumpmachine)))
  BUILD_RESOURCES = $(BUILD_DIR)/$(WINDOWS_RESOURCES:.rc=.o)
  LIBS += -lws2_32 -mwindows
  SHARED_LIB = dll
else
  SHARED_LIB = so
endif

all: build

help:
	@echo "make help                show this message"
	@echo "make build               compile"
	@echo "make install             install on the system"
	@echo "make clean               clean up the mess"
	@echo "make lib                 build a static library"
	@echo "make slib                build a shared library"
	@echo "make unit_test           build unit tests executable"
	@echo ""
	@echo " Make Options"
	@echo "   WITH_DEBUG=1          build with GDB debug support"
	@echo "   WITH_IPV6=1           with IPV6 support"
	@echo "   WITH_WEBSOCKET=1      build with web socket support"
	@echo "   WITH_CPP=1            build library with c++ classes"
	@echo "   CONFIG_FILE=file      use 'file' as the config file"
	@echo "   CONFIG_FILE2=file     use 'file' as the backup config file"
	@echo "   DOCUMENT_ROOT=/path   document root override when installing"
	@echo "   PORTS=8080            listening ports override when installing"
	@echo "   SSL_LIB=libssl.so.0   use versioned SSL library"
	@echo "   CRYPTO_LIB=libcrypto.so.0 system versioned CRYPTO library"
	@echo "   PREFIX=/usr/local     sets the install directory"
	@echo "   COPT='-DNO_SSL'       method to insert compile flags"
	@echo ""
	@echo " Compile Flags"
	@echo "   NDEBUG                strip off all debug code"
	@echo "   DEBUG                 build debug version (very noisy)"
	@echo "   NO_CGI                disable CGI support"
	@echo "   NO_SSL                disable SSL functionality"
	@echo "   NO_SSL_DL             link against system libssl library"
	@echo "   NO_FILES              do not serve files from a directory"
	@echo "   NO_CACHING            disable caching (usefull for systems without timegm())"
	@echo "   MAX_REQUEST_SIZE      maximum header size, default 16384"
	@echo ""
	@echo " Variables"
	@echo "   TARGET_OS='$(TARGET_OS)'"
	@echo "   CFLAGS='$(CFLAGS)'"
	@echo "   CXXFLAGS='$(CXXFLAGS)'"
	@echo "   LDFLAGS='$(LDFLAGS)'"
	@echo "   CC='$(CC)'"
	@echo "   CXX='$(CXX)'"

build: $(CPROG) $(CXXPROG)

unit_test: $(UNIT_TEST_PROG)

ifeq ($(CAN_INSTALL),1)
install: $(HTMLDIR)/index.html $(SYSCONFDIR)/libhttp.conf
	install -d -m 755  "$(DOCDIR)"
	install -m 644 *.md "$(DOCDIR)"
	install -d -m 755 "$(BINDIR)"
	install -m 755 $(CPROG) "$(BINDIR)/"

# Install target we do not want to overwrite
# as it may be an upgrade
$(HTMLDIR)/index.html:
	install -d -m 755  "$(HTMLDIR)"
	install -m 644 resources/itworks.html $(HTMLDIR)/index.html
	install -m 644 resources/civetweb_64x64.png $(HTMLDIR)/

# Install target we do not want to overwrite
# as it may be an upgrade
$(SYSCONFDIR)/libhttp.conf:
	install -d -m 755  "$(SYSCONFDIR)"
	install -m 644 resources/libhttp.conf  "$(SYSCONFDIR)/"
	@sed -i 's#^document_root.*$$#document_root $(DOCUMENT_ROOT)#' "$(SYSCONFDIR)/libhttp.conf"
	@sed -i 's#^listening_ports.*$$#listening_ports $(PORTS)#' "$(SYSCONFDIR)/libhttp.conf"

else
install:
	@echo "Target not flagged for installation.  Use CAN_INSTALL=1 to force"
	@echo "As a precaution only LINUX targets are set as installable."
	@echo "If the target is linux-like, use CAN_INSTALL=1 option."
endif

lib: lib$(CPROG).a

slib: lib$(CPROG).$(SHARED_LIB)

clean:
	$(RMRF) $(BUILD_DIR)
	$(eval version=$(shell grep "define LIBHTTP_VERSION" include/libhttp.h | sed 's|.*VERSION "\(.*\)"|\1|g'))
	$(eval major=$(shell echo $(version) | cut -d'.' -f1))
	$(RMRF) lib$(CPROG).a
	$(RMRF) lib$(CPROG).so
	$(RMRF) lib$(CPROG).so.$(major)
	$(RMRF) lib$(CPROG).so.$(version).0
	$(RMRF) $(CPROG)
	$(RMF) $(UNIT_TEST_PROG)

distclean: clean
	$(RMF) $(CPROG) lib$(CPROG).so lib$(CPROG).a *.dmg *.msi *.exe lib$(CPROG).dll lib$(CPROG).dll.a
	$(RMF) $(UNIT_TEST_PROG)

lib$(CPROG).a: CFLAGS += -fPIC
lib$(CPROG).a: $(LIB_OBJECTS)
	@$(RMF) $@
	ar cq $@ $(LIB_OBJECTS)

lib$(CPROG).so: CFLAGS += -fPIC
lib$(CPROG).so: $(LIB_OBJECTS)
	$(eval version=$(shell grep "define LIBHTTP_VERSION" include/libhttp.h | sed 's|.*VERSION "\(.*\)"|\1|g'))
	$(eval major=$(shell echo $(version) | cut -d'.' -f1))
	$(LCC) -shared -Wl,-soname,$@.$(major) -o $@.$(version).0 $(CFLAGS) $(LDFLAGS) $(LIB_OBJECTS)
	ln -s -f $@.$(major) $@
	ln -s -f $@.$(version).0 $@.$(major)

lib$(CPROG).dll: CFLAGS += -fPIC
lib$(CPROG).dll: $(LIB_OBJECTS)
	$(LCC) -shared -o $@ $(CFLAGS) $(LDFLAGS) $(LIB_OBJECTS) $(LIBS) -Wl,--out-implib,lib$(CPROG).dll.a

$(UNIT_TEST_PROG): CFLAGS += -Isrc -g
$(UNIT_TEST_PROG): $(LIB_SOURCES) $(LIB_INLINE) $(UNIT_TEST_SOURCES) $(BUILD_OBJECTS)
	$(LCC) -o $@ $(CFLAGS) $(LDFLAGS) $(UNIT_TEST_SOURCES) $(BUILD_OBJECTS) $(LIBS)

$(CPROG): $(BUILD_OBJECTS) $(BUILD_RESOURCES)
	$(LCC) -o $@ $(CFLAGS) $(LDFLAGS) $(BUILD_OBJECTS) $(BUILD_RESOURCES) $(LIBS)

$(CXXPROG): $(BUILD_OBJECTS)
	$(CXX) -o $@ $(CFLAGS) $(LDFLAGS) $(BUILD_OBJECTS) $(LIBS)

$(BUILD_OBJECTS): $(BUILD_DIRS)

$(BUILD_DIRS):
	-@$(MKDIR) "$@"

$(BUILD_DIR)/%.o : %.cpp
	$(CXX) -c $(CFLAGS) $(CXXFLAGS) $< -o $@

$(BUILD_DIR)/%.o : %.c
	$(CC) -c $(CFLAGS) $< -o $@

$(BUILD_RESOURCES) : $(WINDOWS_RESOURCES)
	windres $(WINDRES_FLAGS) $< $@

# This rules is used to keep the code formatted in a reasonable manor
# For this to work astyle must be installed and in the path
# http://sourceforge.net/projects/astyle
indent:
	astyle --suffix=none --style=linux --indent=spaces=4 --lineend=linux  include/*.h src/*.c src/*.cpp src/*.inl examples/*/*.c  examples/*/*.cpp

.PHONY: all help build install clean lib so
