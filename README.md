# LibHTTP

**The official home of LibHTTP is [www.libhttp.org](http://www.libhttp.org)**

Project Mission
-----------------

The project mission is to provide easy to use, powerful, C/C++ embeddable web
server with IPv6, CGI and SSL support. LibHTTP has a MIT license so you can innovate without restrictions.

LibHTTP can be used by developers as a library to add web server functionality to an existing application.
It can also be used by end users as a stand-alone web server. It is available as single executable, no installation is required.

LibHTTP is a fork of the Mongoose (MIT)/Civetweb family of http server libraries with the focus on event
driven efficient communication, clean code and good documentation.


Where to find the official version?
-----------------------------------

Documentation of the library can be found on [www.libhttp.org](http://www.libhttp.org)

Developers can download and contribute to Libhttp via GitHub
[https://github.com/lammertb/libhttp](https://github.com/lammertb/libhttp)

Trouble tickets should be filed on GitHub
[https://github.com/lammertb/libhttp/issues](https://github.com/lammertb/libhttp/issues)

Quick start documentation
--------------------------

- [doc/APIReference.md](doc/APIReference.md) - Reference of the C programming API
- [doc/Installing.md](doc/Installing.md) - Install Guide (for end users using pre-built binaries)
- [doc/UserManual.md](doc/UserManual.md) - End User Guide
- [doc/Building.md](doc/Building.md) - Building the Server (quick start guide)
- [doc/Embedding.md](doc/Embedding.md) - Embedding (how to add HTTP support to an existing application)
- [doc/OpenSSL.md](doc/OpenSSL.md) - Adding HTTPS (SSL/TLS) support using OpenSSL.
- [RELEASE_NOTES.md](RELEASE_NOTES.md) - Release Notes
- [LICENSE.md](LICENSE.md) - Copyright License


Overview
--------

LibHTTP keeps the balance between functionality and
simplicity by a carefully selected list of features:

- Liberal, commercial-friendly, permissive, [MIT license](http://en.wikipedia.org/wiki/MIT_License)
- Free from copy-left licenses, like GPL, because you should innovate without restrictions.
- Forked from [Mongoose](https://code.google.com/p/mongoose/) in 2013, before it changed the licence from MIT to commercial + GPL. A lot of enchancements have been added since that time, see [RELEASE_NOTES.md](RELEASE_NOTES.md).
- Works on Windows, Mac, Linux, UNIX, iPhone, Android, Buildroot, and many other platforms.
- Support for CGI, HTTPS (SSL/TLS), SSI, HTTP digest (MD5) authorization, Websocket, WEbDAV.
- Optional support for authentication using client side X.509 certificates.
- Resumed download, URL rewrite, file blacklist, IP-based ACL.
- Download speed limit based on client subnet or URI pattern. 
- Simple and clean embedding API.
- Embedding examples included.
- HTTP client capable of sending arbitrary HTTP/HTTPS requests.
- Websocket client functionality available (WS/WSS).

Support
-------

This project is very easy to install and use. Please read the [documentation](doc/) and have a look at the [examples] (examples/).


Contributions
---------------

Contributions are welcome provided all contributions carry the MIT license.

DO NOT APPLY fixes copied from Mongoose to this project to prevent GPL tainting. LibHTTP which is a Civetweb fork is based on a 2014 version of Mongoose and they are developed independently. By now the code base differs, so patches cannot be safely transfered in either direction.

Some guidelines can be found in [doc/Contribution.md](doc/Contribution.md).


### Authors

LibHTTP is based on CivetWeb which in turn is based on the Mongoose project.  The original author of Mongoose was Sergey Lyubka (Copyright (c) 2004-2013 Sergey Lyubka, MIT license).

CivetWeb has been forked from the last MIT licensed version of Mongoose. Since 2013, CivetWeb has seen many improvements from various authors (Copyright (c) 2013-2016 the CivetWeb developers, MIT license). A list of all known authors can be found in [CREDITS.md](CREDITS.md).

LibHTTP has been forked from a 2016 version of CivetWeb. It contains all updates in CivetWeb upto the moment of forking and updates of later dates in CivetWeb may be used in LibHTTP because they both use the same license. It is expected though that both projects will go in different directions though so future compatibility is not guaranteed.

Using the LibHTTP project ensures the MIT licenses terms are applied and GPL cannot be imposed on any of this code as long as it is sourced from here. This code will remain free with the MIT license protection.
