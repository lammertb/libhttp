/* 
 * Copyright (c) 2016 Lammert Bies
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * ============
 * Release: 2.0
 */

#include "httplib_main.h"

#if defined(_WIN32)
#include <winerror.h>
#endif

/*
 * char *httplib_error_string( int error_code, char *buf, size_t buf_len );
 *
 * The function XX_httplib_error_string() returns a string associated with an
 * error code by storing it in a caller provided buffer. The function returns a
 * pointer to that buffer, or NULL if an error occured. The buffer size is
 * specified by the caller. If the resuting error message including NUL
 * terminator needs more space than the buffer provides, the error string is
 * truncated.
 *
 * The implementation of the function is thread safe.
 */

LIBHTTP_API char *httplib_error_string( int error_code, char *buf, size_t buf_len ) {

	if ( buf == NULL  ||  buf_len < 1 ) return NULL;

#if defined(_WIN32)

	const char *ptr;

	ptr = "";

	switch ( error_code ) {

		/*
		 * All possible winsock error codes according to
		 * https://msdn.microsoft.com/en-us/library/windows/desktop/ms740668(v=vs.85).aspx
		 */

		case WSA_INVALID_HANDLE         : ptr = "Specified event object handle is invalid";          break;
		case WSA_NOT_ENOUGH_MEMORY      : ptr = "Insufficient memory available";                     break;
		case WSA_INVALID_PARAMETER      : ptr = "One or more parameters are invalid";                break;
		case WSA_OPERATION_ABORTED      : ptr = "Overlapped operation aborted";                      break;
		case WSA_IO_INCOMPLETE          : ptr = "Overlapped I/O event object not in signaled state"; break;
		case WSA_IO_PENDING             : ptr = "Overlapped operations will complete later";         break;
		case WSAEINTR                   : ptr = "Interrupted function call";                         break;
		case WSAEBADF                   : ptr = "File handle is not valid";                          break;
		case WSAEACCES                  : ptr = "Permission denied";                                 break;
		case WSAEFAULT                  : ptr = "Bad address";                                       break;
		case WSAEINVAL                  : ptr = "Invalid argument";                                  break;
		case WSAEMFILE                  : ptr = "Too many open files";                               break;
		case WSAEWOULDBLOCK             : ptr = "Resource temporarily unavailable";                  break;
		case WSAEINPROGRESS             : ptr = "Operation now in progress";                         break;
		case WSAEALREADY                : ptr = "Operation already in progress";                     break;
		case WSAENOTSOCK                : ptr = "Socket operation on nonsocket";                     break;
		case WSAEDESTADDRREQ            : ptr = "Destination address required";                      break;
		case WSAEMSGSIZE                : ptr = "Message too long";                                  break;
		case WSAEPROTOTYPE              : ptr = "Protocol wrong type for socket";                    break;
		case WSAENOPROTOOPT             : ptr = "Bad protocol option";                               break;
		case WSAEPROTONOSUPPORT         : ptr = "Protocol not supported";                            break;
		case WSAESOCKTNOSUPPORT         : ptr = "Socket type not supported";                         break;
		case WSAEOPNOTSUPP              : ptr = "Operation not supported";                           break;
		case WSAEPFNOSUPPORT            : ptr = "Protocol family not supported";                     break;
		case WSAEAFNOSUPPORT            : ptr = "Address family not supported by protocol family";   break;
		case WSAEADDRINUSE              : ptr = "Address already in use";                            break;
		case WSAEADDRNOTAVAIL           : ptr = "Cannot assign requested address";                   break;
		case WSAENETDOWN                : ptr = "Network is down";                                   break;
		case WSAENETUNREACH             : ptr = "Network is unreachable";                            break;
		case WSAENETRESET               : ptr = "Network dropped connection on reset";               break;
		case WSAECONNABORTED            : ptr = "Software caused connection abort";                  break;
		case WSAECONNRESET              : ptr = "Connection reset by peer";                          break;
		case WSAENOBUFS                 : ptr = "No buffer space available";                         break;
		case WSAEISCONN                 : ptr = "Socket is already connected";                       break;
		case WSAENOTCONN                : ptr = "Socket is not connected";                           break;
		case WSAESHUTDOWN               : ptr = "Cannont send after socket shutdown";                break;
		case WSAETOOMANYREFS            : ptr = "Too many references";                               break;
		case WSAETIMEDOUT               : ptr = "Connection timed out";                              break;
		case WSAECONNREFUSED            : ptr = "Connection refused";                                break;
		case WSAELOOP                   : ptr = "Cannot translate name";                             break;
		case WSAENAMETOOLONG            : ptr = "Name too long";                                     break;
		case WSAEHOSTDOWN               : ptr = "Host is down";                                      break;
		case WSAEHOSTUNREACH            : ptr = "No route to host";                                  break;
		case WSAENOTEMPTY               : ptr = "Directory not empty";                               break;
		case WSAEPROCLIM                : ptr = "Too many processes";                                break;
		case WSAEUSERS                  : ptr = "User quota exceeded";                               break;
		case WSAEDQUOT                  : ptr = "Disk quota exceeded";                               break;
		case WSAESTALE                  : ptr = "Stale file handle reference";                       break;
		case WSAEREMOTE                 : ptr = "Item is remote";                                    break;
		case WSASYSNOTREADY             : ptr = "Network subsystem is unavailable";                  break;
		case WSAVERNOTSUPPORTED         : ptr = "Winsock.dll version out of range";                  break;
		case WSANOTINITIALISED          : ptr = "Successful WSAStartup not yet performed";           break;
		case WSAEDISCON                 : ptr = "Graceful shutdown in progress";                     break;
		case WSAENOMORE                 : ptr = "No more results";                                   break;
		case WSAECANCELLED              : ptr = "Call has been canceled";                            break;
		case WSAEINVALIDPROCTABLE       : ptr = "Procedure call table is invalid";                   break;
		case WSAEINVALIDPROVIDER        : ptr = "Service provider is invalid";                       break;
		case WSAEPROVIDERFAILEDINIT     : ptr = "Service provider failed to initialize";             break;
		case WSASYSCALLFAILURE          : ptr = "System call failure";                               break;
		case WSASERVICE_NOT_FOUND       : ptr = "Service not found";                                 break;
		case WSATYPE_NOT_FOUND          : ptr = "Class type not found";                              break;
		case WSA_E_NO_MORE              : ptr = "No more results";                                   break;
		case WSA_E_CANCELLED            : ptr = "Call was cancelled";                                break;
		case WSAEREFUSED                : ptr = "Database query was refused";                        break;
		case WSAHOST_NOT_FOUND          : ptr = "Host not found";                                    break;
		case WSATRY_AGAIN               : ptr = "Nonauthorative host not found";                     break;
		case WSANO_RECOVERY             : ptr = "This is a nonrecoverable error";                    break;
		case WSANO_DATA                 : ptr = "Valid name, no data record of requested type";      break;
		case WSA_QOS_RECEIVERS          : ptr = "At least one QoS reserve has arrived";              break;
		case WSA_QOS_SENDERS            : ptr = "At least one QoS send path has arrived";            break;
		case WSA_QOS_NO_SENDERS         : ptr = "There are no QoS senders";                          break;
		case WSA_QOS_NO_RECEIVERS       : ptr = "There are no QoS receivers";                        break;
		case WSA_QOS_REQUEST_CONFIRMED  : ptr = "QoS request confirmed";                             break;
		case WSA_QOS_ADMISSION_FAILURE  : ptr = "QoS admission error";                               break;
		case WSA_QOS_POLICY_FAILURE     : ptr = "QoS policy failure";                                break;
		case WSA_QOS_BAD_STYLE          : ptr = "QoS bad style";                                     break;
		case WSA_QOS_BAD_OBJECT         : ptr = "QoS bad object";                                    break;
		case WSA_QOS_TRAFFIC_CTRL_ERROR : ptr = "QoS traffic control error";                         break;
		case WSA_QOS_GENERIC_ERROR      : ptr = "QoS generic error";                                 break;
		case WSA_QOS_ESERVICETYPE       : ptr = "QoS service type error";                            break;
		case WSA_QOS_EFLOWSPEC          : ptr = "QoS flowspec error";                                break;
		case WSA_QOS_EPROVSPECBUF       : ptr = "Invalid QoS provider buffer";                       break;
		case WSA_QOS_EFILTERSTYLE       : ptr = "Invalid QoS filter style";                          break;
		case WSA_QOS_EFILTERTYPE        : ptr = "Invalid QoS filter type";                           break;
		case WSA_QOS_EFILTERCOUNT       : ptr = "Invalid QoS filter count";                          break;
		case WSA_QOS_EOBJLENGTH         : ptr = "Invalid QoS object length";                         break;
		case WSA_QOS_EFLOWCOUNT         : ptr = "Incorrect QoS flow count";                          break;
		case WSA_QOS_EUNKOWNPSOBJ       : ptr = "Unrecognized QoS object";                           break;
		case WSA_QOS_EPOLICYOBJ         : ptr = "Invalid QoS policy object";                         break;
		case WSA_QOS_EFLOWDESC          : ptr = "Invalid QoS flow desciptor";                        break;
		case WSA_QOS_EPSFLOWSPEC        : ptr = "Invalid QoS provider-specific flowspec";            break;
		case WSA_QOS_EPSFILTERSPEC      : ptr = "Invalid QoS provider-specific filterspec";          break;
		case WSA_QOS_ESDMODEOBJ         : ptr = "Invalid QoS shape discard mode object";             break;
		case WSA_QOS_ESHAPERATEOBJ      : ptr = "Invalid QoS shaping rate object";                   break;
		case WSA_QOS_RESERVED_PETYPE    : ptr = "Reserved policy QoS element type";                  break;
	}

	if ( ptr[0] != '\0' ) {

		httplib_strlcpy( buf, ptr, buf_len );
		return buf;
	}

	strerror_s( buf, buf_len, error_code );
	return buf;

#else  /* not _WIN32 (e.g. Linux, BSD, Solaris etc. */

	if(strerror_r( error_code, buf, buf_len )) return NULL;
	return buf;

#endif  /* _WIN32 */

}  /* httplib_error_string */
