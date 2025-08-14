/* tls_common.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

#ifndef _TPM_TLS_COMMON_H_
#define _TPM_TLS_COMMON_H_

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_wrap.h>

#if !defined(WOLFTPM2_NO_WRAPPER) && !defined(WOLFTPM2_NO_WOLFCRYPT) && \
    !defined(WOLFCRYPT_ONLY)

#include <wolftpm/tpm2_socket.h>

#include <hal/tpm_io.h>
#include <examples/tpm_test.h>
#include <examples/tls/tls_common.h>
#include <examples/tls/tls_client.h>

#include <wolfssl/ssl.h>

#include <stdio.h>

#ifdef __cplusplus
    extern "C" {
#endif

/* TLS Configuration */
#ifndef TLS_HOST
    #define TLS_HOST "localhost"
#endif
#ifndef TLS_PORT
    #define TLS_PORT 11111
#endif

#ifndef MAX_MSG_SZ
    #define MAX_MSG_SZ   (1 * 1024)
#endif
#ifndef TOTAL_MSG_SZ
    #define TOTAL_MSG_SZ (16 * 1024)
#endif

/* force use of a TLS cipher suite */
#if 0
    #ifndef TLS_CIPHER_SUITE
        #define TLS_CIPHER_SUITE "ECDHE-RSA-AES128-SHA256"
    #endif
#endif

/* disable mutual auth for client */
#if 0
    #define NO_TLS_MUTUAL_AUTH
#endif

/* enable for testing ECC key/cert when RSA is enabled */
#if 0
    #define TLS_USE_ECC
#endif

/* enable benchmarking mode */
#if 0
    #define TLS_BENCH_MODE
#endif

#ifdef TLS_BENCH_MODE
    extern double benchStart;
#endif

/******************************************************************************/
/* --- BEGIN Socket IO Callbacks --- */
/******************************************************************************/

typedef struct SockIoCbCtx {
    SOCKET_T listenFd;
    SOCKET_T fd;
} SockIoCbCtx;

#ifndef WOLFSSL_USER_IO
/* socket includes */
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

static inline int SockIORecv(WOLFSSL* ssl, char* buff, int sz, void* ctx)
{
    SockIoCbCtx* sockCtx = (SockIoCbCtx*)ctx;
    int recvd;

    (void)ssl;

    /* Receive message from socket */
    if ((recvd = (int)recv(sockCtx->fd, buff, sz, 0)) == -1) {
        /* error encountered. Be responsible and report it in wolfSSL terms */

        printf("IO RECEIVE ERROR: ");
        switch (errno) {
        #if SOCKET_EAGAIN != SOCKET_EWOULDBLOCK
        case SOCKET_EAGAIN:
        #endif
        case SOCKET_EWOULDBLOCK:
            if (wolfSSL_get_using_nonblock(ssl)) {
                printf("would block\n");
                return WOLFSSL_CBIO_ERR_WANT_READ;
            }
            else {
                printf("socket timeout\n");
                return WOLFSSL_CBIO_ERR_TIMEOUT;
            }
        case SOCKET_ECONNRESET:
            printf("connection reset\n");
            return WOLFSSL_CBIO_ERR_CONN_RST;
        case SOCKET_EINTR:
            printf("socket interrupted\n");
            return WOLFSSL_CBIO_ERR_ISR;
        case SOCKET_ECONNREFUSED:
            printf("connection refused\n");
            return WOLFSSL_CBIO_ERR_WANT_READ;
        case SOCKET_ECONNABORTED:
            printf("connection aborted\n");
            return WOLFSSL_CBIO_ERR_CONN_CLOSE;
        default:
            printf("general error\n");
            return WOLFSSL_CBIO_ERR_GENERAL;
        }
    }
    else if (recvd == 0) {
        printf("Connection closed\n");
        return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    }

#ifdef TLS_BENCH_MODE
    {
        const double zeroVal = 0.0;
        if (XMEMCMP(&benchStart, &zeroVal, sizeof(double)) == 0) {
            benchStart = gettime_secs(1);
        }
    }
#endif

#ifdef DEBUG_WOLFTPM
    /* successful receive */
    printf("SockIORecv: received %d bytes from %d\n", sz, sockCtx->fd);
#endif

    return recvd;
}

static inline int SockIOSend(WOLFSSL* ssl, char* buff, int sz, void* ctx)
{
    SockIoCbCtx* sockCtx = (SockIoCbCtx*)ctx;
    int sent;

    (void)ssl;

    /* Receive message from socket */
    if ((sent = (int)send(sockCtx->fd, buff, sz, 0)) == -1) {
        /* error encountered. Be responsible and report it in wolfSSL terms */

        printf("IO SEND ERROR: ");
        switch (errno) {
        #if SOCKET_EAGAIN != SOCKET_EWOULDBLOCK
        case SOCKET_EAGAIN:
        #endif
        case SOCKET_EWOULDBLOCK:
            printf("would block\n");
            return WOLFSSL_CBIO_ERR_WANT_READ;
        case SOCKET_ECONNRESET:
            printf("connection reset\n");
            return WOLFSSL_CBIO_ERR_CONN_RST;
        case SOCKET_EINTR:
            printf("socket interrupted\n");
            return WOLFSSL_CBIO_ERR_ISR;
        case SOCKET_EPIPE:
            printf("socket EPIPE\n");
            return WOLFSSL_CBIO_ERR_CONN_CLOSE;
        default:
            printf("general error\n");
            return WOLFSSL_CBIO_ERR_GENERAL;
        }
    }
    else if (sent == 0) {
        printf("Connection closed\n");
        return 0;
    }

#ifdef DEBUG_WOLFTPM
    /* successful send */
    printf("SockIOSend: sent %d bytes to %d\n", sz, sockCtx->fd);
#endif

    return sent;
}

static inline int SetupSocketAndListen(SockIoCbCtx* sockIoCtx, word32 port)
{
    struct sockaddr_in servAddr;
    int optval;

#ifdef _WIN32
    WSADATA wsd;
    WSAStartup(0x0002, &wsd);
#endif

    /* Setup server address */
    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_port = htons(port);
    servAddr.sin_addr.s_addr = INADDR_ANY;

    /* Create a socket that uses an Internet IPv4 address,
     * Sets the socket to be stream based (TCP),
     * 0 means choose the default protocol. */
    if ((sockIoCtx->listenFd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        printf("ERROR: failed to create the socket\n");
        return -1;
    }

    /* allow reuse of port and address */
    optval = 1;
    if (setsockopt(sockIoCtx->listenFd, SOL_SOCKET, SO_REUSEADDR,
                   (void*)&optval, sizeof(optval)) == -1) {
        printf("setsockopt SO_REUSEADDR failed\n");
        return -1;
    }
#ifdef SO_REUSEPORT
    optval = 1;
    if (setsockopt(sockIoCtx->listenFd, SOL_SOCKET, SO_REUSEPORT,
                   (void*)&optval, sizeof(optval)) == -1) {
        printf("setsockopt SO_REUSEPORT failed\n");
        return -1;
    }
#endif

    /* Connect to the server */
    if (bind(sockIoCtx->listenFd, (struct sockaddr*)&servAddr,
                                                    sizeof(servAddr)) == -1) {
        printf("ERROR: failed to bind! errno %d\n", errno);
        return -1;
    }

    if (listen(sockIoCtx->listenFd, 5) != 0) {
        printf("ERROR: failed to listen\n");
        return -1;
    }

    return 0;
}

static inline int SocketWaitClient(SockIoCbCtx* sockIoCtx)
{
    SOCKET_T connd;
    struct sockaddr_in clientAddr;
    XSOCKLENT          size = sizeof(clientAddr);

    if ((connd = accept(sockIoCtx->listenFd, (struct sockaddr*)&clientAddr, &size)) == -1) {
        printf("ERROR: failed to accept the connection\n\n");
        return -1;
    }
    sockIoCtx->fd = connd;
    return 0;
}

static inline int SetupSocketAndConnect(SockIoCbCtx* sockIoCtx, const char* host,
    word32 port)
{
    struct sockaddr_in servAddr;
    struct hostent* entry;

#ifdef _WIN32
    WSADATA wsd;
    WSAStartup(0x0002, &wsd);
#endif

    /* Setup server address */
    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_port = htons(port);

    /* Resolve host */
    entry = gethostbyname(host);
    if (entry) {
        XMEMCPY(&servAddr.sin_addr.s_addr, entry->h_addr_list[0],
            entry->h_length);
    }
    else {
        servAddr.sin_addr.s_addr = inet_addr(host);
    }

    /* Create a socket that uses an Internet IPv4 address,
     * Sets the socket to be stream based (TCP),
     * 0 means choose the default protocol. */
    if ((sockIoCtx->fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        printf("ERROR: failed to create the socket\n");
        return -1;
    }

    /* Connect to the server */
    if (connect(sockIoCtx->fd, (struct sockaddr*)&servAddr,
                                                    sizeof(servAddr)) == -1) {
        printf("ERROR: failed to connect\n");
        return -1;
    }

    return 0;
}

static inline int SocketWaitData(SockIoCbCtx* sockIoCtx, int timeout_sec)
{
    int res;
    struct timeval timeout;
    fd_set fds, errfds;
    FD_ZERO(&fds);
    FD_ZERO(&errfds);
    FD_SET(sockIoCtx->fd, &fds);
    FD_SET(sockIoCtx->fd, &errfds);
    timeout.tv_sec = timeout_sec;
    timeout.tv_usec = 0;
    res = select(sockIoCtx->fd + 1, &fds, NULL, &errfds, &timeout);
    if (res == 0) {
        return 0; /* timeout */
    }
    else if (res > 0) {
        if (FD_ISSET(sockIoCtx->fd, &fds)) {
            return 1; /* ready to read */
        }
        else if (FD_ISSET(sockIoCtx->fd, &errfds)) {
            return -1; /* error */
        }
    }
    return 0; /* select failed */
}

static inline void CloseAndCleanupSocket(SockIoCbCtx* sockIoCtx)
{
    if (sockIoCtx->fd != -1) {
        CloseSocket(sockIoCtx->fd);
        sockIoCtx->fd = -1;
    }
    if (sockIoCtx->listenFd != -1) {
        CloseSocket(sockIoCtx->listenFd);
        sockIoCtx->listenFd = -1;
    }
}
#else
    /* Provide you own socket implementation code */
    int SockIORecv(WOLFSSL* ssl, char* buff, int sz, void* ctx);
    int SockIOSend(WOLFSSL* ssl, char* buff, int sz, void* ctx);
    int SetupSocketAndConnect(SockIoCbCtx* sockIoCtx, const char* host,
        word32 port);
    void CloseAndCleanupSocket(SockIoCbCtx* sockIoCtx);

    int SetupSocketAndListen(SockIoCbCtx* sockIoCtx, word32 port);
    int SocketWaitClient(SockIoCbCtx* sockIoCtx);
    int SocketWaitData(SockIoCbCtx* sockIoCtx, int timeout_sec);
#endif /* !WOLFSSL_USER_IO */

/******************************************************************************/
/* --- END Socket IO Callbacks --- */
/******************************************************************************/


/******************************************************************************/
/* --- BEGIN Supporting TLS functions --- */
/******************************************************************************/

static inline int myVerify(int preverify, WOLFSSL_X509_STORE_CTX* store)
{
    /* Verify Callback Arguments:
     * preverify:           1=Verify Okay, 0=Failure
     * store->current_cert: Current WOLFSSL_X509 object (only with OPENSSL_EXTRA)
     * store->error_depth:  Current Index
     * store->domain:       Subject CN as string (null term)
     * store->totalCerts:   Number of certs presented by peer
     * store->certs[i]:     A `WOLFSSL_BUFFER_INFO` with plain DER for each cert
     * store->store:        WOLFSSL_X509_STORE with CA cert chain
     * store->store->cm:    WOLFSSL_CERT_MANAGER
     * store->ex_data:      The WOLFSSL object pointer
     */

    printf("In verification callback, error = %d, %s\n",
        store->error, wolfSSL_ERR_reason_error_string(store->error));
    printf("\tPeer certs: %d\n", store->totalCerts);
    printf("\tSubject's domain name at %d is %s\n",
        store->error_depth, store->domain);

    (void)preverify;

    /* If error indicate we are overriding it for testing purposes */
    if (store->error != 0) {
        printf("\tAllowing failed certificate check, testing only "
            "(shouldn't do this in production)\n");
    }

    /* A non-zero return code indicates failure override */
    return 1;
}

#ifndef NO_DH
/* dh2048 p */
static const unsigned char test_dh_p[] =
{
    0xD3, 0xB2, 0x99, 0x84, 0x5C, 0x0A, 0x4C, 0xE7, 0x37, 0xCC, 0xFC, 0x18,
    0x37, 0x01, 0x2F, 0x5D, 0xC1, 0x4C, 0xF4, 0x5C, 0xC9, 0x82, 0x8D, 0xB7,
    0xF3, 0xD4, 0xA9, 0x8A, 0x9D, 0x34, 0xD7, 0x76, 0x57, 0xE5, 0xE5, 0xC3,
    0xE5, 0x16, 0x85, 0xCA, 0x4D, 0xD6, 0x5B, 0xC1, 0xF8, 0xCF, 0x89, 0x26,
    0xD0, 0x38, 0x8A, 0xEE, 0xF3, 0xCD, 0x33, 0xE5, 0x56, 0xBB, 0x90, 0x83,
    0x9F, 0x97, 0x8E, 0x71, 0xFB, 0x27, 0xE4, 0x35, 0x15, 0x45, 0x86, 0x09,
    0x71, 0xA8, 0x9A, 0xB9, 0x3E, 0x0F, 0x51, 0x8A, 0xC2, 0x75, 0x51, 0x23,
    0x12, 0xFB, 0x94, 0x31, 0x44, 0xBF, 0xCE, 0xF6, 0xED, 0xA6, 0x3A, 0xB7,
    0x92, 0xCE, 0x16, 0xA9, 0x14, 0xB3, 0x88, 0xB7, 0x13, 0x81, 0x71, 0x83,
    0x88, 0xCD, 0xB1, 0xA2, 0x37, 0xE1, 0x59, 0x5C, 0xD0, 0xDC, 0xCA, 0x82,
    0x87, 0xFA, 0x43, 0x44, 0xDD, 0x78, 0x3F, 0xCA, 0x27, 0x7E, 0xE1, 0x6B,
    0x93, 0x19, 0x7C, 0xD9, 0xA6, 0x96, 0x47, 0x0D, 0x12, 0xC1, 0x13, 0xD7,
    0xB9, 0x0A, 0x40, 0xD9, 0x1F, 0xFF, 0xB8, 0xB4, 0x00, 0xC8, 0xAA, 0x5E,
    0xD2, 0x66, 0x4A, 0x05, 0x8E, 0x9E, 0xF5, 0x34, 0xE7, 0xD7, 0x09, 0x7B,
    0x15, 0x49, 0x1D, 0x76, 0x31, 0xD6, 0x71, 0xEC, 0x13, 0x4E, 0x89, 0x8C,
    0x09, 0x22, 0xD8, 0xE7, 0xA3, 0xE9, 0x7D, 0x21, 0x51, 0x26, 0x6E, 0x9F,
    0x30, 0x8A, 0xBB, 0xBC, 0x74, 0xC1, 0xC3, 0x27, 0x6A, 0xCE, 0xA3, 0x12,
    0x60, 0x68, 0x01, 0xD2, 0x34, 0x07, 0x80, 0xCC, 0x2D, 0x7F, 0x5C, 0xAE,
    0xA2, 0x97, 0x40, 0xC8, 0x3C, 0xAC, 0xDB, 0x6F, 0xFE, 0x6C, 0x6D, 0xD2,
    0x06, 0x1C, 0x43, 0xA2, 0xB2, 0x2B, 0x82, 0xB7, 0xD0, 0xAB, 0x3F, 0x2C,
    0xE7, 0x9C, 0x19, 0x16, 0xD1, 0x5E, 0x26, 0x86, 0xC7, 0x92, 0xF9, 0x16,
    0x0B, 0xFA, 0x66, 0x83
};

/* dh2048 g */
static const unsigned char test_dh_g[] =
{
    0x02,
};
#endif /* !NO_DH */

/******************************************************************************/
/* --- END Supporting TLS functions --- */
/******************************************************************************/

#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* !WOLFTPM2_NO_WRAPPER && !WOLFTPM2_NO_WOLFCRYPT */

#endif /* _TPM_TLS_COMMON_H_ */
