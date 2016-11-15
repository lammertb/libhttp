# Libhttp

**The official home of libhttp is [www.libhttp.org](http://www.libhttp.org)**

Project Mission
-----------------

Project mission is to provide easy to use, powerful, C/C++ embeddable web
server with optional CGI, SSL and Lua support. Libhttp has a MIT license so you can innovate without restrictions.

Libhttp can be used by developers as a library, to add web server functionality to an existing application.
It can also be used by end users as a stand-alone web server. It is available as single executable, no installation is required.

Libhttp is a fork of the Mongoose (MIT)/Civetweb family of http server libraries with the focus on event
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

- [docs/APIReference.md](docs/APIReference.md) - Reference of the C programming API
- [docs/Installing.md](docs/Installing.md) - Install Guide (for end users using pre-built binaries)
- [docs/UserManual.md](docs/UserManual.md) - End User Guide
- [docs/Building.md](docs/Building.md) - Building the Server (quick start guide)
- [docs/Embedding.md](docs/Embedding.md) - Embedding (how to add HTTP support to an existing application)
- [docs/OpenSSL.md](docs/OpenSSL.md) - Adding HTTPS (SSL/TLS) support using OpenSSL.
- [RELEASE_NOTES.md](RELEASE_NOTES.md) - Release Notes
- [LICENSE.md](LICENSE.md) - Copyright License


Overview
--------

LibHTTP keeps the balance between functionality and
simplicity by a carefully selected list of features:

- Liberal, commercial-friendly, permissive,
  [MIT license](http://en.wikipedia.org/wiki/MIT_License)
- Free from copy-left licenses, like GPL, because you should innovate without
  restrictions.
- Forked from [Mongoose](https://code.google.com/p/mongoose/) in 2013, before
  it changed the licence from MIT to commercial + GPL. A lot of enchancements
  have been added since that time, see
  [RELEASE_NOTES.md](RELEASE_NOTES.md).
- Works on Windows, Mac, Linux, UNIX, iPhone, Android, Buildroot, and many
  other platforms.
- Scripting and database support (Lua scipts, Lua Server Pages, CGI + SQLite
  database, Server side javascript).
  This provides a ready to go, powerful web development platform in a one
  single-click executable with **no dependencies**.
- Support for CGI, HTTPS (SSL/TLS), SSI, HTTP digest (MD5) authorization, Websocket,
  WEbDAV.
- Optional support for authentication using client side X.509 certificates.
- Resumed download, URL rewrite, file blacklist, IP-based ACL, Windows service.
- Download speed limit based on client subnet or URI pattern.
- Simple and clean embedding API.
- The source is in single file to make things easy.
- Embedding examples included.
- HTTP client capable of sending arbitrary HTTP/HTTPS requests.
- Websocket client functionality available (WS/WSS).


### Optionally included software

<a href="http://lua.org">
![Lua](https://raw.github.com/lammertb/libhttp/master/resources/lua-logo.jpg "Lua Logo")
</a>
<a href="http://sqlite.org">
![Sqlite3](https://raw.github.com/lammertb/libhttp/master/resources/sqlite3-logo.jpg "Sqlite3 Logo")
</a>
<a href="http://keplerproject.github.io/luafilesystem/">
![LuaFileSystem](https://raw.github.com/lammertb/libhttp/master/resources/luafilesystem-logo.jpg "LuaFileSystem Logo")
</a>
<a href="http://lua.sqlite.org/index.cgi/index">
![LuaSQLite3](https://raw.github.com/lammertb/libhttp/master/resources/luasqlite-logo.jpg "LuaSQLite3 Logo")
</a>
<a href="http://viremo.eludi.net/LuaXML/index.html">
![LuaXML](https://raw.github.com/lammertb/libhttp/master/resources/luaxml-logo.jpg "LuaXML Logo")
</a>
<a href="http://duktape.org">
![Duktape](https://raw.github.com/lammertb/libhttp/master/resources/duktape-logo.png "Duktape Logo")
</a>


Support
-------

This project is very easy to install and use. Please read the [documentation](docs/)
and have a look at the [examples] (examples/).


Contributions
---------------

Contributions are welcome provided all contributions carry the MIT license.

DO NOT APPLY fixes copied from Mongoose to this project to prevent GPL tainting.
Since 2013 CivetWeb and Mongoose are developed independently. By now the code base differs, so patches cannot be safely transfered in either direction.

Some guidelines can be found in [docs/Contribution.md](docs/Contribution.md).


### Authors

LibHTTP is based on CivetWeb which in turn is based on the Mongoose project.  The original author of Mongoose was
Sergey Lyubka (Copyright (c) 2004-2013 Sergey Lyubka, MIT license).

However, in August 16, 2013, the [license of Mongoose has been changed](https://groups.google.com/forum/#!topic/mongoose-users/aafbOnHonkI)
after writing and distributing the original code this project is based on.

CivetWeb has been forked from the last MIT version of Mongoose. 
Since 2013, CivetWeb has seen many improvements from various authors 
(Copyright (c) 2013-2016 the CivetWeb developers, MIT license).
A list of authors can be found in [CREDITS.md](CREDITS.md).

LibHTTP has been forked from a 2016 version of CivetWeb. It contains all updates in CivetWeb
upto the moment of forking and updates of later dates in CivetWeb may be used in LibHTTP
because they both use the same license. It is expected though that both projects will
go in different directions though so future compatibility is not guaranteed.

Using the LibHTTP project ensures the MIT licenses terms are applied and
GPL cannot be imposed on any of this code as long as it is sourced from
here. This code will remain free with the MIT license protection.
