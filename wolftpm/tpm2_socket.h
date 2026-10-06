/* tpm2_socket.h
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfTPM.
 *
 * wolfTPM is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfTPM is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#ifndef _TPM2_SOCKET_H_
#define _TPM2_SOCKET_H_

#if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(WOLFCRYPT_ONLY)
#include <wolfssl/wolfio.h>
#endif

#ifndef USE_WOLFSSL_IO

/* socket includes */
#if defined(_WIN32)

    #define SOCKET_T SOCKET

    /* SOCKET is an unsigned UINT_PTR, so the sentinel is all bits set and is
     * 64 bit wide on a 64 bit build; a literal 0xFFFFFFFF is a different
     * value there and matches no socket. */
    #undef SOCKET_INVALID
    #define SOCKET_INVALID INVALID_SOCKET
#elif defined(WOLFTPM_ZEPHYR)
    #include <zephyr/net/socket.h>

    #define SOCKET_T int
#else
    #include <sys/types.h>
    #include <sys/socket.h>

    #define SOCKET_T int
#endif

#ifndef SOCKET_INVALID
    #define SOCKET_INVALID ((SOCKET_T)-1)
#endif

#ifdef USE_WINDOWS_API
    #ifndef CloseSocket
        #define CloseSocket(s) closesocket(s)
    #endif
#else
    #ifndef CloseSocket
        #define CloseSocket(s) close(s)
    #endif
#endif

#ifndef XSOCKLENT
    #ifdef _WIN32
        #define XSOCKLENT int
    #else
        #define XSOCKLENT socklen_t
    #endif
#endif

#ifdef _WIN32
    /* no epipe yet */
    #ifndef WSAEPIPE
        #define WSAEPIPE       -12345
    #endif
    #define SOCKET_EWOULDBLOCK WSAEWOULDBLOCK
    #define SOCKET_EAGAIN      WSAETIMEDOUT
    #define SOCKET_ECONNRESET  WSAECONNRESET
    #define SOCKET_EINTR       WSAEINTR
    #define SOCKET_EPIPE       WSAEPIPE
    #define SOCKET_ECONNREFUSED WSAENOTCONN
    #define SOCKET_ECONNABORTED WSAECONNABORTED
#else
    #define SOCKET_EWOULDBLOCK EWOULDBLOCK
    #define SOCKET_EAGAIN      EAGAIN
    #define SOCKET_ECONNRESET  ECONNRESET
    #define SOCKET_EINTR       EINTR
    #define SOCKET_EPIPE       EPIPE
    #define SOCKET_ECONNREFUSED ECONNREFUSED
    #define SOCKET_ECONNABORTED ECONNABORTED
#endif /* USE_WINDOWS_API */

#endif /* !USE_WOLFSSL_IO */

#endif /* _TPM2_SOCKET_H_ */
