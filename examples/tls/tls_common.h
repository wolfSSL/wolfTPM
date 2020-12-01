/* tls_common.h
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
 *
 * This file is part of wolfTPM.
 *
 * wolfTPM is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfTPM is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifndef _TPM_TLS_COMMON_H_
#define _TPM_TLS_COMMON_H_

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_wrap.h>

#if !defined(WOLFTPM2_NO_WRAPPER) && !defined(WOLFTPM2_NO_WOLFCRYPT)

#include <wolftpm/tpm2_socket.h>

#include <examples/tpm_io.h>
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
    int listenFd;
    int fd;
} SockIoCbCtx;

#ifndef WOLFSSL_USER_IO
/* socket includes */

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
    int optval  = 1;

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

    /* allow reuse */
    if (setsockopt(sockIoCtx->listenFd, SOL_SOCKET, SO_REUSEADDR,
                   (void*)&optval, sizeof(optval)) == -1) {
        printf("setsockopt SO_REUSEADDR failed\n");
        return -1;
    }

    /* Connect to the server */
    if (bind(sockIoCtx->listenFd, (struct sockaddr*)&servAddr,
                                                    sizeof(servAddr)) == -1) {
        printf("ERROR: failed to bind\n");
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
    int connd;
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

#if defined(WOLF_CRYPTO_DEV) || defined(WOLF_CRYPTO_CB)
/* Function checks key to see if its the "dummy" key */
static inline int myTpmCheckKey(wc_CryptoInfo* info, TpmCryptoDevCtx* ctx)
{
    int ret = 0;

#ifndef NO_RSA
    if (info && info->pk.type == WC_PK_TYPE_RSA) {
        byte    e[sizeof(word32)], e2[sizeof(word32)];
        byte    n[WOLFTPM2_WRAP_RSA_KEY_BITS/8], n2[WOLFTPM2_WRAP_RSA_KEY_BITS/8];
        word32  eSz = sizeof(e), e2Sz = sizeof(e);
        word32  nSz = sizeof(n), n2Sz = sizeof(n);
        RsaKey  rsakey;
        word32  idx = 0;

        /* export the raw public RSA portion */
        ret = wc_RsaFlattenPublicKey(info->pk.rsa.key, e, &eSz, n, &nSz);
        if (ret == 0) {
            /* load the modulus for the dummy key */
            ret = wc_InitRsaKey(&rsakey, NULL);
            if (ret == 0) {
                ret = wc_RsaPrivateKeyDecode(DUMMY_RSA_KEY, &idx, &rsakey,
                    (word32)sizeof(DUMMY_RSA_KEY));
                if (ret == 0) {
                    ret = wc_RsaFlattenPublicKey(&rsakey, e2, &e2Sz, n2, &n2Sz);
                }
                wc_FreeRsaKey(&rsakey);
            }
        }

        if (ret == 0 && XMEMCMP(n, n2, nSz) == 0) {
        #ifdef DEBUG_WOLFTPM
            printf("Detected dummy key, so using TPM RSA key handle\n");
        #endif
            ret = 1;
        }
    }
#endif
#if defined(HAVE_ECC)
    if (info && info->pk.type == WC_PK_TYPE_ECDSA_SIGN) {
        byte    qx[WOLFTPM2_WRAP_ECC_KEY_BITS/8], qx2[WOLFTPM2_WRAP_ECC_KEY_BITS/8];
        byte    qy[WOLFTPM2_WRAP_ECC_KEY_BITS/8], qy2[WOLFTPM2_WRAP_ECC_KEY_BITS/8];
        word32  qxSz = sizeof(qx), qx2Sz = sizeof(qx2);
        word32  qySz = sizeof(qy), qy2Sz = sizeof(qy2);
        ecc_key eccKey;
        word32  idx = 0;

        /* export the raw public ECC portion */
        ret = wc_ecc_export_public_raw(info->pk.eccsign.key, qx, &qxSz, qy, &qySz);
        if (ret == 0) {
            /* load the ECC public x/y for the dummy key */
            ret = wc_ecc_init(&eccKey);
            if (ret == 0) {
                ret = wc_EccPrivateKeyDecode(DUMMY_ECC_KEY, &idx, &eccKey,
                    (word32)sizeof(DUMMY_ECC_KEY));
                if (ret == 0) {
                    ret = wc_ecc_export_public_raw(&eccKey, qx2, &qx2Sz, qy2, &qy2Sz);
                }
                wc_ecc_free(&eccKey);
            }
        }

        if (ret == 0 && XMEMCMP(qx, qx2, qxSz) == 0 &&
                        XMEMCMP(qy, qy2, qySz) == 0) {
        #ifdef DEBUG_WOLFTPM
            printf("Detected dummy key, so using TPM ECC key handle\n");
        #endif
            ret = 1;
        }
    }
#endif
    (void)info;
    (void)ctx;

    /* non-zero return code means its a "dummy" key (not valid) and the
        provided TPM handle will be used, not the wolf public key info */
    return ret;
}
#endif /* WOLF_CRYPTO_DEV || WOLF_CRYPTO_CB */

/******************************************************************************/
/* --- END Supporting TLS functions --- */
/******************************************************************************/

#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* !WOLFTPM2_NO_WRAPPER && !WOLFTPM2_NO_WOLFCRYPT */

#endif /* _TPM_TLS_COMMON_H_ */
