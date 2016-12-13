/* 
 * Copyright (c) 2016 Lammert Bies
 * Copyright (c) 2013-2014 the Civetweb developers
 * Copyright (c) 2013 No Face Press, LLC
 *
 * License http://opensource.org/licenses/mit-license.php MIT License
 */

#ifndef _CIVETWEB_SERVER_H_
#define _CIVETWEB_SERVER_H_
#ifdef __cplusplus

#include "libhttp.h"
#include <map>
#include <string>
#include <vector>
#include <stdexcept>

// forward declaration
class LibHTTPServer;

/**
 * Exception class for thrown exceptions within the LibHTTPHandler object.
 */
class CIVETWEB_API LibHTTPException : public std::runtime_error
{
  public:
	LibHTTPException(const std::string &msg) : std::runtime_error(msg)
	{
	}
};

/**
 * Basic interface for a URI request handler.  Handlers implementations
 * must be reentrant.
 */
class CIVETWEB_API LibHTTPHandler
{
  public:
	/**
	 * Destructor
	 */
	virtual ~LibHTTPHandler()
	{
	}

	/**
	 * Callback method for GET request.
	 *
	 * @param server - the calling server
	 * @param conn - the connection information
	 * @returns true if implemented, false otherwise
	 */
	virtual bool handleGet(LibHTTPServer *server, struct httplib_connection *conn);

	/**
	 * Callback method for POST request.
	 *
	 * @param server - the calling server
	 * @param conn - the connection information
	 * @returns true if implemented, false otherwise
	 */
	virtual bool handlePost(LibHTTPServer *server, struct httplib_connection *conn);

	/**
	 * Callback method for HEAD request.
	 *
	 * @param server - the calling server
	 * @param conn - the connection information
	 * @returns true if implemented, false otherwise
	 */
	virtual bool handleHead(LibHTTPServer *server, struct httplib_connection *conn);

	/**
	 * Callback method for PUT request.
	 *
	 * @param server - the calling server
	 * @param conn - the connection information
	 * @returns true if implemented, false otherwise
	 */
	virtual bool handlePut(LibHTTPServer *server, struct httplib_connection *conn);

	/**
	 * Callback method for DELETE request.
	 *
	 * @param server - the calling server
	 * @param conn - the connection information
	 * @returns true if implemented, false otherwise
	 */
	virtual bool handleDelete(LibHTTPServer *server, struct httplib_connection *conn);

	/**
	 * Callback method for OPTIONS request.
	 *
	 * @param server - the calling server
	 * @param conn - the connection information
	 * @returns true if implemented, false otherwise
	 */
	virtual bool handleOptions(LibHTTPServer *server, struct httplib_connection *conn);

	/**
	 * Callback method for PATCH request.
	 *
	 * @param server - the calling server
	 * @param conn - the connection information
	 * @returns true if implemented, false otherwise
	 */
	virtual bool handlePatch(LibHTTPServer *server, struct httplib_connection *conn);
};

/**
 * Basic interface for a URI authorization handler.  Handler implementations
 * must be reentrant.
 */
class CIVETWEB_API LibHTTPAuthHandler
{
  public:
	/**
	 * Destructor
	 */
	virtual ~LibHTTPAuthHandler()
	{
	}

	/**
	 * Callback method for authorization requests. It is up the this handler
	 * to generate 401 responses if authorization fails.
	 *
	 * @param server - the calling server
	 * @param conn - the connection information
	 * @returns true if authorization succeeded, false otherwise
	 */
	virtual bool authorize(LibHTTPServer *server, struct httplib_connection *conn) = 0;
};

/**
 * Basic interface for a websocket handler.  Handlers implementations
 * must be reentrant.
 */
class CIVETWEB_API LibHTTPWebSocketHandler
{
  public:
	/**
	 * Destructor
	 */
	virtual ~LibHTTPWebSocketHandler()
	{
	}

	/**
	 * Callback method for when the client intends to establish a websocket
	 *connection, before websocket handshake.
	 *
	 * @param server - the calling server
	 * @param conn - the connection information
	 * @returns true to keep socket open, false to close it
	 */
	virtual bool handleConnection(LibHTTPServer *server, const struct httplib_connection *conn);

	/**
	 * Callback method for when websocket handshake is successfully completed,
	 *and connection is ready for data exchange.
	 *
	 * @param server - the calling server
	 * @param conn - the connection information
	 */
	virtual void handleReadyState(LibHTTPServer *server, struct httplib_connection *conn);

	/**
	 * Callback method for when a data frame has been received from the client.
	 *
	 * @param server - the calling server
	 * @param conn - the connection information
	 * @bits: first byte of the websocket frame, see websocket RFC at
	 *http://tools.ietf.org/html/rfc6455, section 5.2
	 * @data, data_len: payload, with mask (if any) already applied.
	 * @returns true to keep socket open, false to close it
	 */
	virtual bool handleData(LibHTTPServer *server, struct httplib_connection *conn, int bits, char *data, size_t data_len);

	/**
	 * Callback method for when the connection is closed.
	 *
	 * @param server - the calling server
	 * @param conn - the connection information
	 */
	virtual void handleClose(LibHTTPServer *server, const struct httplib_connection *conn);
};

/**
 * LibHTTPCallbacks
 *
 * wrapper for httplib_callbacks
 */
struct CIVETWEB_API LibHTTPCallbacks : public httplib_callbacks {
	LiBHTTPCallbacks();
};

/**
 * LibHTTPServer
 *
 * Basic class for embedded web server.  This has an URL mapping built-in.
 */
class CIVETWEB_API LibHTTPServer
{
  public:
	/**
	 * Constructor
	 *
	 * This automatically starts the sever.
	 * It is good practice to call getContext() after this in case there
	 * were errors starting the server.
	 *
	 * Note: LibHTTPServer should not be used as a static instance in a Windows
	 * DLL, since the constructor creates threads and the destructor joins
	 * them again (creating/joining threads should not be done in static
	 * constructors).
	 *
	 * @param options - the web server options.
	 * @param callbacks - optional web server callback methods.
	 *
	 * @throws LibHTTPException
	 */
	LibHTTPServer(const char **options,
	            const struct LibHTTPCallbacks *callbacks = 0);
	LibHTTPServer(std::vector<std::string> options,
	            const struct LibHTTPCallbacks *callbacks = 0);

	/**
	 * Destructor
	 */
	virtual ~LibHTTPServer();

	/**
	 * close()
	 *
	 * Stops server and frees resources.
	 */
	void close();

	/**
	 * getContext()
	 *
	 * @return the context or 0 if not running.
	 */
	const struct httplib_context *
	getContext() const
	{
		return context;
	}

	/**
	 * addHandler(const std::string &, LibHTTPHandler *)
	 *
	 * Adds a URI handler.  If there is existing URI handler, it will
	 * be replaced with this one.
	 *
	 * URI's are ordered and prefix (REST) URI's are supported.
	 *
	 *  @param uri - URI to match.
	 *  @param handler - handler instance to use.
	 */
	void addHandler(const std::string &uri, LibHTTPHandler *handler);

	void
	addHandler(const std::string &uri, LibHTTPHandler &handler)
	{
		addHandler(uri, &handler);
	}

	/**
	 * addWebSocketHandler
	 *
	 * Adds a WebSocket handler for a specific URI.  If there is existing URI
	 *handler, it will
	 * be replaced with this one.
	 *
	 * URI's are ordered and prefix (REST) URI's are supported.
	 *
	 *  @param uri - URI to match.
	 *  @param handler - handler instance to use.
	 */
	void addWebSocketHandler(const std::string &uri,
	                         LibHTTPWebSocketHandler *handler);

	void
	addWebSocketHandler(const std::string &uri, LibHTTPWebSocketHandler &handler)
	{
		addWebSocketHandler(uri, &handler);
	}

	/**
	 * removeHandler(const std::string &)
	 *
	 * Removes a handler.
	 *
	 * @param uri - the exact URL used in addHandler().
	 */
	void removeHandler(const std::string &uri);

	/**
	 * removeWebSocketHandler(const std::string &)
	 *
	 * Removes a web socket handler.
	 *
	 * @param uri - the exact URL used in addWebSocketHandler().
	 */
	void removeWebSocketHandler(const std::string &uri);

	/**
	 * addAuthHandler(const std::string &, LibHTTPAuthHandler *)
	 *
	 * Adds a URI authorization handler.  If there is existing URI authorization
	 * handler, it will be replaced with this one.
	 *
	 * URI's are ordered and prefix (REST) URI's are supported.
	 *
	 * @param uri - URI to match.
	 * @param handler - authorization handler instance to use.
	 */
	void addAuthHandler(const std::string &uri, LibHTTPAuthHandler *handler);

	void
	addAuthHandler(const std::string &uri, LibHTTPAuthHandler &handler)
	{
		addAuthHandler(uri, &handler);
	}

	/**
	 * removeAuthHandler(const std::string &)
	 *
	 * Removes an authorization handler.
	 *
	 * @param uri - the exact URL used in addAuthHandler().
	 */
	void removeAuthHandler(const std::string &uri);

	/**
	 * getListeningPorts()
	 *
	 * Returns a list of ports that are listening
	 *
	 * @return A vector of ports
	 */

	std::vector<int> getListeningPorts();

	/**
	 * getCookie(struct httplib_connection *conn, const std::string &cookieName,
	 *std::string &cookieValue)
	 *
	 * Puts the cookie value string that matches the cookie name in the
	 *cookieValue destinaton string.
	 *
	 * @param conn - the connection information
	 * @param cookieName - cookie name to get the value from
	 * @param cookieValue - cookie value is returned using thiis reference
	 * @returns the size of the cookie value string read.
	*/
	static int getCookie(struct httplib_connection *conn,
	                     const std::string &cookieName,
	                     std::string &cookieValue);

	/**
	 * getHeader(struct httplib_connection *conn, const std::string &headerName)
	 * @param conn - the connection information
	 * @param headerName - header name to get the value from
	 * @returns a char array whcih contains the header value as string
	*/
	static const char *getHeader(struct httplib_connection *conn, const std::string &headerName);

	/**
	 * getParam(struct httplib_connection *conn, const char *, std::string &, size_t)
	 *
	 * Returns a query paramter contained in the supplied buffer.  The
	 * occurance value is a zero-based index of a particular key name.  This
	 * should not be confused with the index over all of the keys.  Note that
	 *this
	 * function assumes that parameters are sent as text in http query string
	 * format, which is the default for web forms. This function will work for
	 * html forms with method="GET" and method="POST" attributes. In other
	 *cases,
	 * you may use a getParam version that directly takes the data instead of
	 *the
	 * connection as a first argument.
	 *
	 * @param conn - parameters are read from the data sent through this
	 *connection
	 * @param name - the key to search for
	 * @param dst - the destination string
	 * @param occurrence - the occurrence of the selected name in the query (0
	 *based).
	 * @return true if key was found
	 */
	static bool getParam(struct httplib_connection *conn, const char *name, std::string &dst, size_t occurrence = 0);

	/**
	 * getParam(const std::string &, const char *, std::string &, size_t)
	 *
	 * Returns a query paramter contained in the supplied buffer.  The
	 * occurance value is a zero-based index of a particular key name.  This
	 * should not be confused with the index over all of the keys.
	 *
	 * @param data - the query string (text)
	 * @param name - the key to search for
	 * @param dst - the destination string
	 * @param occurrence - the occurrence of the selected name in the query (0
	 *based).
	 * @return true if key was found
	 */
	static bool
	getParam(const std::string &data,
	         const char *name,
	         std::string &dst,
	         size_t occurrence = 0)
	{
		return getParam(data.c_str(), data.length(), name, dst, occurrence);
	}

	/**
	 * getParam(const char *, size_t, const char *, std::string &, size_t)
	 *
	 * Returns a query paramter contained in the supplied buffer.  The
	 * occurance value is a zero-based index of a particular key name.  This
	 * should not be confused with the index over all of the keys.
	 *
	 * @param data the - query string (text)
	 * @param data_len - length of the query string
	 * @param name - the key to search for
	 * @param dst - the destination string
	 * @param occurrence - the occurrence of the selected name in the query (0
	 *based).
	 * @return true if key was found
	 */
	static bool getParam(const char *data,
	                     size_t data_len,
	                     const char *name,
	                     std::string &dst,
	                     size_t occurrence = 0);

	/**
	 * urlDecode(const std::string &, std::string &, bool)
	 *
	 * @param src - string to be decoded
	 * @param dst - destination string
	 * @param is_form_url_encoded - true if form url encoded
	 *       form-url-encoded data differs from URI encoding in a way that it
	 *       uses '+' as character for space, see RFC 1866 section 8.2.1
	 *       http://ftp.ics.uci.edu/pub/ietf/html/rfc1866.txt
	 */
	static void
	urlDecode(const std::string &src,
	          std::string &dst,
	          bool is_form_url_encoded = true)
	{
		urlDecode(src.c_str(), src.length(), dst, is_form_url_encoded);
	}

	/**
	 * urlDecode(const char *, size_t, std::string &, bool)
	 *
	 * @param src - buffer to be decoded
	 * @param src_len - length of buffer to be decoded
	 * @param dst - destination string
	 * @param is_form_url_encoded - true if form url encoded
	 *       form-url-encoded data differs from URI encoding in a way that it
	 *       uses '+' as character for space, see RFC 1866 section 8.2.1
	 *       http://ftp.ics.uci.edu/pub/ietf/html/rfc1866.txt
	 */
	static void urlDecode(const char *src,
	                      size_t src_len,
	                      std::string &dst,
	                      bool is_form_url_encoded = true);

	/**
	 * urlDecode(const char *, std::string &, bool)
	 *
	 * @param src - buffer to be decoded (0 terminated)
	 * @param dst - destination string
	 * @param is_form_url_encoded true - if form url encoded
	 *       form-url-encoded data differs from URI encoding in a way that it
	 *       uses '+' as character for space, see RFC 1866 section 8.2.1
	 *       http://ftp.ics.uci.edu/pub/ietf/html/rfc1866.txt
	 */
	static void urlDecode(const char *src,
	                      std::string &dst,
	                      bool is_form_url_encoded = true);

	/**
	 * urlEncode(const std::string &, std::string &, bool)
	 *
	 * @param src - buffer to be encoded
	 * @param dst - destination string
	 * @param append - true if string should not be cleared before encoding.
	 */
	static void
	urlEncode(const std::string &src, std::string &dst, bool append = false)
	{
		urlEncode(src.c_str(), src.length(), dst, append);
	}

	/**
	 * urlEncode(const char *, size_t, std::string &, bool)
	 *
	 * @param src - buffer to be encoded (0 terminated)
	 * @param dst - destination string
	 * @param append - true if string should not be cleared before encoding.
	 */
	static void
	urlEncode(const char *src, std::string &dst, bool append = false);

	/**
	 * urlEncode(const char *, size_t, std::string &, bool)
	 *
	 * @param src - buffer to be encoded
	 * @param src_len - length of buffer to be decoded
	 * @param dst - destination string
	 * @param append - true if string should not be cleared before encoding.
	 */
	static void urlEncode(const char *src,
	                      size_t src_len,
	                      std::string &dst,
	                      bool append = false);

  protected:
	class LibHTTPConnection
	{
	  public:
		char *postData;
		unsigned long postDataLen;

		LibHTTPConnection();
		~LibHTTPConnection();
	};

	struct httplib_context *context;
	std::map<struct httplib_connection *, class LibHTTPConnection> connections;

  private:
	/**
	 * requestHandler(struct httplib_connection *, void *cbdata)
	 *
	 * Handles the incomming request.
	 *
	 * @param conn - the connection information
	 * @param cbdata - pointer to the LibHTTPHandler instance.
	 * @returns 0 if implemented, false otherwise
	 */
	static int requestHandler(struct httplib_connection *conn, void *cbdata);

	static int webSocketConnectionHandler(const struct httplib_connection *conn,
	                                      void *cbdata);
	static void webSocketReadyHandler(struct httplib_connection *conn, void *cbdata);
	static int webSocketDataHandler(struct httplib_connection *conn,
	                                int bits,
	                                char *data,
	                                size_t data_len,
	                                void *cbdata);
	static void webSocketCloseHandler(const struct httplib_connection *conn,
	                                  void *cbdata);
	/**
	 * authHandler(struct httplib_connection *, void *cbdata)
	 *
	 * Handles the authorization requests.
	 *
	 * @param conn - the connection information
	 * @param cbdata - pointer to the LibHTTPAuthHandler instance.
	 * @returns 1 if authorized, 0 otherwise
	 */
	static int authHandler(struct httplib_connection *conn, void *cbdata);

	/**
	 * closeHandler(struct httplib_connection *)
	 *
	 * Handles closing a request (internal handler)
	 *
	 * @param conn - the connection information
	 */
	static void closeHandler(const struct httplib_connection *conn);

	/**
	 * Stores the user provided close handler
	 */
	void (*userCloseHandler)(const struct httplib_connection *conn);
};

#endif /*  __cplusplus */
#endif /* _CIVETWEB_SERVER_H_ */
