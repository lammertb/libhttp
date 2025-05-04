Release Notes v2.0 (work in progress)
===
### Objectives: *Clean up source code, Proper documentation, Restructure embedding API, Switch to OpenSSL v1.1*

Changes
-------

- Websocket support is always compiled in and switched on/off at runtime
- Added NULL checking to all uses of context configuration settings
- IPv6 support is now always available
- Combined three send file functions into `httplib_send_file()`.
- Memory allocation debugging can be switched on and off dynamically
- Memory allocation functions are available for the main application
- Full API documentation now available at [`www.libhttp.org/api-reference/`](http://www.libhttp.org/api-reference/)
- Changed function and structure prefix from `mg_` to `httplib_`
- Search in MIME types list now costs O(log(N)) instead of O(N)
- Added several hundred MIME types
- Prototypes an definitions split over multiple header files
- All functions moved to their own source files for better maintainability
- Removed deprecated function `mg_get_ports();`
- Removed sqlite3 from the distribution
- Removed Lua support temporarily
- Removed Duktape support temporarily
- Removed Symbian support
- Changed references from CivetWeb to LibHTTP in documentation
- Removed deprecated function `mg_upload();`
- Removed deprecated function `mg_get_valid_option_names();`
- Removed all build scripts except the script for `make`
- Added website [`www.libhttp.org`](http://www.libhttp.org)
- Switched OpenSSL support to OpenSSL v1.1

Release Notes v1.9 (will never be released as LibHTTP)
===
### Objectives: *Read client certificate information, bug fixes*

Changes
-------

- Retry failing TLS/HTTPS read/write operations
- Read client certificate information
- Do not tolerate URIs with invalid characters
- Fix mg_get_cookie to ignore substrings
- Fix bug in timer logic (for Lua Websockets)
- Updated version number

Release Notes v1.8 (as Civetweb)
===
### Objectives: *CMake integration and continuous integration tests, Support client certificates, bug fixes*

Changes
-------

- Replace mg_upload by mg_handle_form_request
- CGI-scripts must receive EOF if all POST data is read
- Add API function to handle all kinds of HTML form data
- Do not allow short file names in Windows
- Callback when a new thread is initialized
- Support for short lived certificates
- Add NO_CACHING compile option
- Update Visual Studio project files to VS2015; rename directory VS2012 to VS
- Sec-Wesocket-Protocol must only return one protocol
- Mark some examples and tests as obsolete
- Remove no longer maintained test utils
- Add some default MIME types and the mg_send_mime_file API function.
- Client API using SSL certificates
- Send "Cache-Control" headers
- Add alternative to mg_upload
- Additional configuration options
- Fix memory leaks
- Add API function to check available features
- Add new interface to get listening ports
- Add websocket client interface and encode websocket data with a simple random number
- Support SSL client certificates
- Add configuration options for SSL client certificates
- Stand-alone server: Add command line option -I to display information about the system
- Redirect stderr of CGI process to error log
- Support absolute URI; split uri in mg_request_info to request_uri and local_uri
- Some source code refactoring, to improve maintainability
- Use recursive mutex for Linux
- Allow CGI environment to grow dynamically
- Support build for Lua 5.1 (including LuaJIT), Lua 5.2 and Lua 5.3
- Improve examples and documentation
- Build option CIVETWEB_SERVE_NO_FILES to disable serving static files
- Add Server side JavaScript support (Duktape library)
- Created a "civetweb" organization at GitHub.
- Repository moved from https://github.com/bel2125/civetweb to https://github.com/civetweb/civetweb
- Improved continuous integration
- CMake support, continuous integration with Travis CI and Appveyor
- Adapt/port unit tests to CMake/Travis/Appveyor
- Bug fixes, including issues from static code analysis
- Add status badges to the GitHub project main page
- Updated version number

Release Notes v1.7 (as Civetweb)
===
### Objectives: *Examples, documentation, additional API functions, some functions rewritten, bug fixes and updates*

Changes
-------

- Format source with clang_format
- Use function 'sendfile' for Linux
- Fix for CRAMFS in Linux
- Fix for file modification times in Windows
- Use SO_EXCLUSIVEADDRUSE instead of SO_REUSEADDR for Windows
- Rewrite push/pull functions
- Allow to use Lua as shared objects (WITH_LUA_SHARED)
- Fixes for many warnings
- URI specific callbacks and different timeouts for websockets
- Add chunked transfer support
- Update LuaFileSystem
- Update Lua to 5.2.4
- Fix build for MinGW-x64, TDM-GCC and clang
- Update SQLite to 3.8.10.2
- Fix CGI variables SCRIPT_NAME and PATH_TRANSLATED
- Set TCP_USER_TIMEOUT to deal faster with broken connections
- Add a Lua form handling example
- Return more differentiated HTTP error codes
- Add log_access callback
- Rewrite and comment request handling function
- Specify in detail and document return values of callback functions
- Set names for all threads (unless NO_THREAD_NAME is defined)
- New API functions for TCP/HTTP clients
- Fix upload of huge files
- Allow multiple SSL instances within one application
- Improve API and user documentation
- Allow to choose between static and dynamic Lua library
- Improve unit test
- Use temporary file name for partially uploaded files
- Additional API functions exported to C++
- Add a websocket client example
- Add a websocket client API
- Update websocket example
- Make content length available in request_info
- New API functions: access context, callback for create/delete, access user data
- Upgraded Lua from 5.2.2 to 5.2.3 and finally 5.2.4
- Integrate LuaXML (for testing purposes)
- Fix compiler warnings
- Updated version number

Release Notes v1.6 (as Civetweb)
===
### Objectives: *Enhance Lua support, configuration dialog for windows, new examples, bug fixes and updates*

Changes
-------

- Add examples of Lua pages, scripts and websockets to the test directory (bel)
- Add dialog to change htpasswd files for the Windows standalone server (bel)
- Fix compiler warnings and warnings from static code analysis (Danny Al-Gaaf, jmc-, Thomas, bel, ...)
- Add new unit tests (bel)
- Support includes in htpasswd files (bel)
- Add a basic option check for the standalone executable (bel)
- Support user defined error pages (bel)
- Method to get POST request parameters via C++ interface (bel)
- Re-Add unit tests for Linux and Windows (jmc-, bel)
- Allow to specify title and tray icon for the Windows standalone server (bel)
- Fix minor memory leaks (bel)
- Redirect all memory allocation/deallocation through mg functions which may be overwritten (bel)
- Support Cross-Origin Resource Sharing (CORS) for static files and scripts (bel)
- Win32: Replace dll.def file by export macros in civetweb.h (CSTAJ)
- Base64 encode and decode functions for Lua (bel)
- Support pre-loaded files for the Lua environment (bel)
- Server should check the nonce for http digest access authentication (bel)
- Hide read-only flag in file dialogs opened by the Edit Settings dialog for the Windows executable (bel)
- Add all functions to dll.def, that are in the header (bel)
- Added Lua extensions: send_file, get_var, get_mime_type, get_cookie, url_decode, url_encode (bel)
- mg_set_request_handler() mod to use pattern (bel, Patch from Toni Wilk)
- Solved, tested and documented SSL support for Windows (bel)
- Fixed: select for Linux needs the nfds parameter set correctly (bel)
- Add methods for returning the ports civetweb is listening on (keithel)
- Fixes for Lua Server Pages, as described within the google groups thread. (bel)
- Added support for plain Lua Scripts, and an example script. (bel)
- A completely new, and more illustrative websocket example for C. (bel)
- Websocket for Lua (bel)
- An optional websocket_root directory, including URL rewriting (bel)
- Update of SQLite3 to 3.8.1. (bel)
- Add "date" header field to replies, according to the requirements of RFC 2616 (the HTTP standard), Section 14.18 (bel)
- Fix websocket long pull (celeron55)
- Updated API documentation (Alex Kozlov)
- Fixed Posix locking functions for Windows (bel2125)
- Updated version number

Release Notes v1.5 (as Civetweb)
===
### Objectives: *Bug fixes and updates, repository restoration*

Changes
-------

- Corrected bad mask flag/opcode passing to websocket callback (William Greathouse)
- Moved CEVITWEB_VERSION define into civetweb.h
- Added new simple zip deployment build for Windows.
- Removed windows install package build.
- Fixes page violation in mod_lua.inl (apkbox)
- Use C style comments to enable compiling most of civetweb with -ansi. (F-Secure Corporation)
- Allow directories with non ASCII characters in Windows in UTF-8 encoded (bel2125)
- Added Lua File System support (bel2125)
- Added mongoose history back in repository thanks to (Paul Sokolovsky)
- Fixed keep alive (bel2125)
- Updated of MIME types (bel2125)
- Updated lsqlite (bel2125)
- Fixed master thread priority (bel2125)
- Fixed IPV6 defines under Windowe (grenclave)
- Fixed potential dead lock in connection_close() (Morgan McGuire)
- Added WebSocket example using asynchronous server messages (William Greathouse)
- Fixed the getcwd() warning (William Greathouse)
- Implemented the connection_close() callback (William Greathouse)
- Fixed support URL's in civetweb.c (Daniel Oaks)
- Allow port number to be zero to use a random free port (F-Secure Corporation)
- Wait for threads to finish when stopping for a clean shutdown (F-Secure Corporation)
- More static analysis fixes against Coverity tool (F-Secure Corporation)
- Travis automated build testing support added (Daniel Oaks)
- Updated version numbers.
- Added contributor credits file.

Release Notes v1.4 (as Civetweb)
===
### Objectives: *New URI handler interface, feature enhancements, C++ extensions*
The main idea behind this release is to bring about API consistency. All changes
are backward compatible and have been kept to a minimum.

Changes
-------

- Added mg_set_request_handler() which provides a URI mapping for callbacks.
   This is a new alternative to overriding callbacks.begin_request.
- Externalized mg_url_encode()
- Externalized mg_strncasecmp() for utiliy
- Added CivetServer::getParam methods
- Added CivetServer::urlDecode methods
- Added CivetServer::urlEncode methods
- Dealt with compiler warnings and some static analysis hits.
- Added mg_get_var2() to parse repeated query variables
- Externalized logging function cry() as mg_cry()
- Added CivetServer::getCookie method (Hariprasad Kamath)
- Added CivetServer::getHeader method (Hariprasad Kamath)
- Added new basic C embedding example
- Conformed source files to UNIX line endings for consistency.
- Unified the coding style to improve reability.

Release Notes v1.3 (as Civetweb)
===
### Objectives: *Buildroot Integration*

Changes
-------

- Made option to put initial HTMLDIR in a different place
- Validated build without SQLITE3 large file support
- Updated documentation
- Updated Buildroot config example

Release Notes v1.2 (as Civetweb)
===
### Objectives: *Installation Improvements, buildroot, cross compile support*
The objective of this release is to make installation seamless.

Changes
-------

- Create an installation guide
- Created both 32 and 64 bit windows installations
- Added install for windows distribution
- Added 64 bit build profiles for VS 2012.
- Created a buildroot patch
- Updated makefile to better support buildroot
- Made doc root and ports configurable during the make install.
- Updated Linux Install
- Updated OS X Package
- Improved install scheme with welcome web page

Known Issues
-----

- The prebuilt Window's version requires [Visual C++ Redistributable for Visual Studio 2012](http://www.microsoft.com/en-us/download/details.aspx?id=30679)

Release Notes v1.1 (as Civetweb)
===
### Objectives: *Build, Documentation, License Improvements*
The objective of this release is to establish a maintable code base, ensure MIT license rights and improve usability and documentation.

Changes
-------

- Reorangized build directories to make them more intuitive
- Added new build rules for lib and slib with option to include C++ class
- Upgraded Lua from 5.2.1 to 5.2.2
- Added fallback configuration file path for Linux systems.
    + Good for having a system wide default configuration /usr/local/etc/civetweb.conf
- Added new C++ abstraction class CivetServer
- Added thread safety for and fixed websocket defects (Morgan McGuire)
- Created PKGBUILD to use Arch distribution (Daniel Oaks)
- Created new documentation on Embeddeding, Building and yaSSL (see doc/).
- Updated License file to include all licenses.
- Replaced MD5 implementation due to questionable license.
     + This requires new source file md5.inl
- Changed UNIX/OSX build to conform to common practices.
     + Supports build, install and clean rules.
     + Supports cross compiling
     + Features can be chosen in make options
- Moved Cocoa/OSX build and packaging to a separate file.
     + This actually a second build variant for OSX.
     + Removed yaSSL from the OSX build, not needed.
- Added new Visual Studio projects for Windows builds.
     + Removed Windows support from Makefiles
     + Provided additional, examples with Lua, and another with yaSSL.
- Changed Zombie Reaping policy to not ignore SIGCHLD.
     + The previous method caused trouble in applciations that spawn children.

Known Issues
-----

- Build support for VS6 and some other has been deprecated.
    + This does not impact embedded programs, just the stand-alone build.
    + The old Makefile was renamed to Makefile.deprecated.
    + This is partcially do to lack fo testing.
    + Need to find out what is actually in demand.
- Build changes may impact current users.
    + As with any change of this type, changes may impact some users.

Release Notes v1.0 (as Civetweb)
===

### Objectives: *MIT License Preservation, Rebranding*
The objective of this release is to establish a version of the Mongoose software distribution that still retains the MIT license.

Changes
-------

- Renamed Mongoose to Civetweb in the code and documentation.
- Replaced copyrighted images with new images
- Created a new code respository at GitHub
- Created a distribution site at SourceForge
- Basic build testing
