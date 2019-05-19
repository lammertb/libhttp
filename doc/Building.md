Building LibHTTP
=========

This guide covers the build instructions for the stand-alone web server.
See [Embedding.md](Embedding.md) for information on extending an existing C or C++ application. A brief overview of the source code files can be found in [Embedding.md](Embedding.md) as well.

#### Where to get the source code?

The latest version can be found at
https://github.com/lammertb/libhttp

Released versions can be found at
https://github.com/lammertb/libhttp/releases


Building for Windows, Linux, BSD, OSX
---------
Builds for all operating systems are created with GNU Make.

## Using Make

```
make help
```
Get a list of all supported make option

```
make build
```
compile the code

```
make install
```
Install on the system, Linux only.

```
make lib WITH_CPP=1 WITH_IPV6=1
make clean slib WITH_CPP=1 WITH_LUA=1 WITH_WEBSOCKET=1
```
Build the static and shared libraries.
The *WITH_CPP* make option is to include the LibHTTPServer class.
The additional make options configure the library just as it would the application.

The *slib* option should be done on a separate clean build as position
independent code (PIC) is required for it.  Trying to run it after
building the static library or the server will result in a link error.

```
make clean
```
Clean up files generated during the build

## Setting build options

Make options can be set on the command line with the make command like so.
```
make build WITH_IPV6=1
```


| Make Options              | Description                              |
| ------------------------- | ---------------------------------------- |
| WITH_DEBUG=1              | build with GDB debug support             |
| WITH_IPV6=1               | with IPV6 support                        |
| WITH_WEBSOCKET=1          | build with web socket support            |
| WITH_CPP=1                | build libraries with c++ classes         |
| CONFIG_FILE=file          | use 'file' as the config file            |
| CONFIG_FILE2=file         | use 'file' as the backup config file     |
| HTMLDIR=/path             | place to install initial web pages       |
| DOCUMENT_ROOT=/path       | HTMLDIR override, config option, install |
|                           | nothing is installed here.               |
| PORTS=8080                | listening ports override when installing |
| SSL_LIB=libssl.so.0       | use versioned SSL library                |
| CRYPTO_LIB=libcrypto.so.0 | system versioned CRYPTO library          |
| PREFIX=/usr/local         | sets the install directory               |
| COPT='-DNO_SSL'           | method to insert compile flags           |

Note that the WITH_* options used for *make* are not identical to the
preprocessor defines in the source code - usually USE_* is used there.

## Setting compile flags

Compile flags can be set using the *COPT* make option like so.
```
make build COPT="-DNDEBUG -DNO_CGI"
```

| Compile Flags             | Description                          |
| ------------------------- | ------------------------------------ |
| NDEBUG                    | strip off all debug code             |
| DEBUG                     | build debug version (very noisy)     |
| NO_CGI                    | disable CGI support                  |
| NO_CACHING                | disable caching functionality        |
| NO_SSL                    | disable SSL functionality            |
| NO_SSL_DL                 | link against system libssl library   |
| NO_FILES                  | do not serve files from a directory  |
| SQLITE_DISABLE_LFS        | disables large files (Lua only)      |
| SSL_ALREADY_INITIALIZED   | do not initialize libcrypto          |

## Cross Compiling

Take total control with *CC*, *COPT* and *TARGET_OS* as make options.
TARGET_OS is used to determine some compile details as will as code function.
TARGET_OS values should be be one found in *resources/Makefile.in-os*.

```
make CC=arm-none-linux-gnueabi-gcc COPT="-march=armv7-a  -mfpu=vfp -mfloat-abi=softfp" TARGET_OS=FROG
```

## Cocoa DMG Packaging (OSX Only)

Use the alternate *Makefile.osx* to do the build.  The entire build has
to be done using *Makefile.osx* because additional compile and link options
are required.  This Makefile has all the same options as the other one plus
one additional *package* rule.

```
make -f Makefile.osx package
```
