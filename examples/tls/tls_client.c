/* tls_client.c
 *
 * Copyright (C) 2006-2018 wolfSSL Inc.
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


#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_wrap.h>

#if !defined(WOLFTPM2_NO_WRAPPER) && defined(WOLF_CRYPTO_DEV)

#include <examples/tpm_io.h>
#include <examples/tls/tls_client.h>

#include <wolfssl/ssl.h>

#define TLS_HOST "www.wolfssl.com"
#define TLS_PORT 443

/*
 * Generating the Client Certificate
 *
 * Run example for ./examples/csr/csr
 * Result is: ./certs/client-rsa-cert.csr and ./certs/client-ecc-cert.csr
 *
 * Run ./certs/certsign.sh
 * Result is: ./certs/client-rsa-cert.pem and ./certs/client-ecc-cert.pem
 */


/******************************************************************************/
/* --- BEGIN Socket IO Callbacks --- */
/******************************************************************************/

/* socket includes */
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

typedef struct SockIoCbCtx {
    int fd;
} SockIoCbCtx;

static int SockIORecv(WOLFSSL* ssl, char* buff, int sz, void* ctx)
{
    SockIoCbCtx* sockCtx = (SockIoCbCtx*)ctx;
    int recvd;

    (void)ssl;

    /* Receive message from socket */
    if ((recvd = recv(sockCtx->fd, buff, sz, 0)) == -1) {
        /* error encountered. Be responsible and report it in wolfSSL terms */

        fprintf(stderr, "IO RECEIVE ERROR: ");
        switch (errno) {
    #if EAGAIN != EWOULDBLOCK
        case EAGAIN: /* EAGAIN == EWOULDBLOCK on some systems, but not others */
    #endif
        case EWOULDBLOCK:
            if (wolfSSL_get_using_nonblock(ssl)) {
                fprintf(stderr, "would block\n");
                return WOLFSSL_CBIO_ERR_WANT_READ;
            }
            else {
                fprintf(stderr, "socket timeout\n");
                return WOLFSSL_CBIO_ERR_TIMEOUT;
            }
        case ECONNRESET:
            fprintf(stderr, "connection reset\n");
            return WOLFSSL_CBIO_ERR_CONN_RST;
        case EINTR:
            fprintf(stderr, "socket interrupted\n");
            return WOLFSSL_CBIO_ERR_ISR;
        case ECONNREFUSED:
            fprintf(stderr, "connection refused\n");
            return WOLFSSL_CBIO_ERR_WANT_READ;
        case ECONNABORTED:
            fprintf(stderr, "connection aborted\n");
            return WOLFSSL_CBIO_ERR_CONN_CLOSE;
        default:
            fprintf(stderr, "general error\n");
            return WOLFSSL_CBIO_ERR_GENERAL;
        }
    }
    else if (recvd == 0) {
        printf("Connection closed\n");
        return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    }

#ifdef DEBUG_WOLFTPM
    /* successful receive */
    printf("SockIORecv: received %d bytes from %d\n", sz, sockCtx->fd);
#endif

    return recvd;
}

static int SockIOSend(WOLFSSL* ssl, char* buff, int sz, void* ctx)
{
    SockIoCbCtx* sockCtx = (SockIoCbCtx*)ctx;
    int sent;

    (void)ssl;

    /* Receive message from socket */
    if ((sent = send(sockCtx->fd, buff, sz, 0)) == -1) {
        /* error encountered. Be responsible and report it in wolfSSL terms */

        fprintf(stderr, "IO SEND ERROR: ");
        switch (errno) {
    #if EAGAIN != EWOULDBLOCK
        case EAGAIN: /* EAGAIN == EWOULDBLOCK on some systems, but not others */
    #endif
        case EWOULDBLOCK:
            fprintf(stderr, "would block\n");
            return WOLFSSL_CBIO_ERR_WANT_READ;
        case ECONNRESET:
            fprintf(stderr, "connection reset\n");
            return WOLFSSL_CBIO_ERR_CONN_RST;
        case EINTR:
            fprintf(stderr, "socket interrupted\n");
            return WOLFSSL_CBIO_ERR_ISR;
        case EPIPE:
            fprintf(stderr, "socket EPIPE\n");
            return WOLFSSL_CBIO_ERR_CONN_CLOSE;
        default:
            fprintf(stderr, "general error\n");
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

static int SetupSocketAndConnect(SockIoCbCtx* sockIoCtx, const char* host,
    word32 port)
{
    struct sockaddr_in servAddr;
    struct hostent* entry;

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
        fprintf(stderr, "ERROR: failed to create the socket\n");
        return -1;
    }

    /* Connect to the server */
    if (connect(sockIoCtx->fd, (struct sockaddr*)&servAddr,
                                                    sizeof(servAddr)) == -1) {
        fprintf(stderr, "ERROR: failed to connect\n");
        return -1;
    }

    return 0;
}

static void CloseAndCleanupSocket(SockIoCbCtx* sockIoCtx)
{
    if (sockIoCtx->fd != -1) {
        close(sockIoCtx->fd);
        sockIoCtx->fd = -1;
    }
}

/******************************************************************************/
/* --- END Socket IO Callbacks --- */
/******************************************************************************/



/******************************************************************************/
/* --- BEGIN TLS Client Example -- */
/******************************************************************************/
#define MAX_REPLY_SZ 1024
int TPM2_TLS_Client(void* userCtx)
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY storageKey;
#ifndef NO_RSA
    WOLFTPM2_KEY rsaKey;
    RsaKey wolfRsaKey;
#endif
#ifdef HAVE_ECC
    WOLFTPM2_KEY eccKey;
    ecc_key wolfEccKey;
#endif
    TPMT_PUBLIC publicTemplate;
    TpmCryptoDevCtx tpmCtx;
    SockIoCbCtx sockIoCtx;
    int tpmDevId;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    char msg[] = "GET /index.html HTTP/1.0\r\n\r\n";
    char reply[MAX_REPLY_SZ];
    int msgSz, replySz;

    /* initialize variables */
    XMEMSET(&sockIoCtx, 0, sizeof(sockIoCtx));
    sockIoCtx.fd = -1;

    printf("TPM2 TLS Client Example\n");

    /* Init the TPM2 device */
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != 0) return rc;

    /* Setup the wolf crypto device callback */
#ifndef NO_RSA
    XMEMSET(&wolfRsaKey, 0, sizeof(wolfRsaKey));
    tpmCtx.rsaKey = &rsaKey;
#endif
#ifdef HAVE_ECC
    XMEMSET(&wolfEccKey, 0, sizeof(wolfEccKey));
    tpmCtx.eccKey = &eccKey;
#endif
    rc = wolfTPM2_SetCryptoDevCb(&dev, wolfTPM2_CryptoDevCb, &tpmCtx, &tpmDevId);
    if (rc != 0) goto exit;

    /* See if primary storage key already exists */
    rc = wolfTPM2_ReadPublicKey(&dev, &storageKey,
        TPM2_DEMO_STORAGE_KEY_HANDLE);
    if (rc != 0) {
        /* Create primary storage key */
        rc = wolfTPM2_GetKeyTemplate_RSA(&publicTemplate,
            TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent |
            TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
            TPMA_OBJECT_restricted | TPMA_OBJECT_decrypt | TPMA_OBJECT_noDA);
        if (rc != 0) goto exit;
        rc = wolfTPM2_CreatePrimaryKey(&dev, &storageKey, TPM_RH_OWNER,
            &publicTemplate, (byte*)gStorageKeyAuth, sizeof(gStorageKeyAuth)-1);
        if (rc != 0) goto exit;

        /* Move this key into persistent storage */
        rc = wolfTPM2_NVStoreKey(&dev, TPM_RH_OWNER, &storageKey,
            TPM2_DEMO_STORAGE_KEY_HANDLE);
        if (rc != 0) goto exit;
    }
    else {
        /* specify auth password for storage key */
        storageKey.handle.auth.size = sizeof(gStorageKeyAuth)-1;
        XMEMCPY(storageKey.handle.auth.buffer, gStorageKeyAuth,
            storageKey.handle.auth.size);
    }

#ifndef NO_RSA
    /* Create/Load RSA key for TLS authentication */
    rc = wolfTPM2_ReadPublicKey(&dev, &rsaKey, TPM2_DEMO_RSA_KEY_HANDLE);
    if (rc != 0) {
        rc = wolfTPM2_GetKeyTemplate_RSA(&publicTemplate,
            TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
            TPMA_OBJECT_decrypt | TPMA_OBJECT_sign | TPMA_OBJECT_noDA);
        if (rc != 0) goto exit;
        rc = wolfTPM2_CreateAndLoadKey(&dev, &rsaKey, &storageKey.handle,
            &publicTemplate, (byte*)gKeyAuth, sizeof(gKeyAuth)-1);
        if (rc != 0) goto exit;

        /* Move this key into persistent storage */
        rc = wolfTPM2_NVStoreKey(&dev, TPM_RH_OWNER, &rsaKey,
            TPM2_DEMO_RSA_KEY_HANDLE);
        if (rc != 0) goto exit;
    }
    else {
        /* specify auth password for rsa key */
        rsaKey.handle.auth.size = sizeof(gKeyAuth)-1;
        XMEMCPY(rsaKey.handle.auth.buffer, gKeyAuth, rsaKey.handle.auth.size);
    }

    /* setup wolf RSA key with TPM deviceID, so crypto callbacks are used */
    rc = wc_InitRsaKey_ex(&wolfRsaKey, NULL, tpmDevId);
    if (rc != 0) goto exit;
    /* load public portion of key into wolf RSA Key */
    rc = wolfTPM2_RsaKey_TpmToWolf(&dev, &rsaKey, &wolfRsaKey);
    if (rc != 0) goto exit;
#endif /* !NO_RSA */

#ifdef HAVE_ECC
    /* Create/Load ECC key for TLS authentication */
    rc = wolfTPM2_ReadPublicKey(&dev, &eccKey, TPM2_DEMO_ECC_KEY_HANDLE);
    if (rc != 0) {
        rc = wolfTPM2_GetKeyTemplate_ECC(&publicTemplate,
            TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
            TPMA_OBJECT_sign | TPMA_OBJECT_noDA,
            TPM_ECC_NIST_P256, TPM_ALG_ECDSA);
        if (rc != 0) goto exit;
        rc = wolfTPM2_CreateAndLoadKey(&dev, &eccKey, &storageKey.handle,
            &publicTemplate, (byte*)gKeyAuth, sizeof(gKeyAuth)-1);
        if (rc != 0) goto exit;

        /* Move this key into persistent storage */
        rc = wolfTPM2_NVStoreKey(&dev, TPM_RH_OWNER, &eccKey,
            TPM2_DEMO_ECC_KEY_HANDLE);
        if (rc != 0) goto exit;
    }
    else {
        /* specify auth password for ECC key */
        eccKey.handle.auth.size = sizeof(gKeyAuth)-1;
        XMEMCPY(eccKey.handle.auth.buffer, gKeyAuth, eccKey.handle.auth.size);
    }

    /* setup wolf ECC key with TPM deviceID, so crypto callbacks are used */
    rc = wc_ecc_init_ex(&wolfEccKey, NULL, tpmDevId);
    if (rc != 0) goto exit;
    /* load public portion of key into wolf ECC Key */
    rc = wolfTPM2_EccKey_TpmToWolf(&dev, &eccKey, &wolfEccKey);
    if (rc != 0) goto exit;
#endif /* HAVE_ECC */


    /* Setup the WOLFSSL context (factory) */
    if ((ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method())) == NULL) {
        rc = MEMORY_E; goto exit;
    }

    /* Setup IO Callbacks */
    wolfSSL_CTX_SetIORecv(ctx, SockIORecv);
    wolfSSL_CTX_SetIOSend(ctx, SockIOSend);

    /* Server certificate validation */
#if 0
    /* skip server cert validation for this test */
    wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);
#else
#ifdef NO_FILESYSTEM
    /* example loading from buffer */
    #if 0
        if (wolfSSL_CTX_load_verify(ctx, ca.buffer, (long)ca.size,
            WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) }
            goto exit;
        }
    #endif
#else
    /* Load CA Certificate */
    if (wolfSSL_CTX_load_verify_locations(ctx, "./certs/wolfssl-website-ca.pem",
        0) != WOLFSSL_SUCCESS) {
        goto exit;
    }
#endif /* !NO_FILESYSTEM */
#endif

#ifdef NO_FILESYSTEM
    /* example loading from buffer */
    #if 0
        if (wolfSSL_CTX_use_certificate_buffer(ctx, cert.buffer, (long)cert.size,
                                        WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
            goto exit;
        }
    #endif
#else
    /* Client certificate (mutual auth) */
#ifndef NO_RSA
    if ((rc = wolfSSL_CTX_use_certificate_file(ctx, "./certs/client-rsa-cert.pem",
        WOLFSSL_FILETYPE_PEM)) != WOLFSSL_SUCCESS) {
        goto exit;
    }
#elif defined(HAVE_ECC)
    if ((rc = wolfSSL_CTX_use_certificate_file(ctx, "./certs/client-ecc-cert.pem",
        WOLFSSL_FILETYPE_PEM)) != WOLFSSL_SUCCESS) {
        goto exit;
    }
#endif
#endif /* !NO_FILESYSTEM */

    /* No need to load private key, since its on TPM and  crypto dev callbacks are used */

#if 0
    /* Optionally choose the cipher suite */
    rc = wolfSSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES128-GCM-SHA256");
    if (rc != WOLFSSL_SUCCESS) {
        goto exit;
    }
#endif

    /* Create wolfSSL object/session */
    if ((ssl = wolfSSL_new(ctx)) == NULL) {
        rc = wolfSSL_get_error(ssl, 0);
        goto exit;
    }

    /* Setup DevID */
    wolfSSL_SetDevId(ssl, tpmDevId);

    /* Setup socket and connection */
    rc = SetupSocketAndConnect(&sockIoCtx, TLS_HOST, TLS_PORT);
    if (rc != 0) goto exit;

    /* Setup read/write callback contexts */
    wolfSSL_SetIOReadCtx(ssl, &sockIoCtx);
    wolfSSL_SetIOWriteCtx(ssl, &sockIoCtx);

    /* perform connect */
    do {
        rc = wolfSSL_connect(ssl);
        if (rc != WOLFSSL_SUCCESS) {
            rc = wolfSSL_get_error(ssl, 0);
        }
    } while (rc == WOLFSSL_ERROR_WANT_READ || rc == WOLFSSL_ERROR_WANT_WRITE);

    /* perform write */
    msgSz = sizeof(msg);
    printf("Write (%d): %s\n", msgSz, msg);
    do {
        rc = wolfSSL_write(ssl, msg, msgSz);
        if (rc != msgSz) {
            rc = wolfSSL_get_error(ssl, 0);
        }
    } while (rc == WOLFSSL_ERROR_WANT_WRITE);

    /* perform read */
    do {
        rc = wolfSSL_read(ssl, reply, sizeof(reply) - 1);
        if (rc < 0) {
            rc = wolfSSL_get_error(ssl, 0);
        }
        else {
            /* null terminate */
            reply[rc] = '\0';
            replySz = rc;
            rc = 0;
        }
    } while (rc == WOLFSSL_ERROR_WANT_READ);
    printf("Read (%d): %s\n", replySz, reply);


exit:

    if (rc != 0) {
        printf("Failure 0x%x: %s\n", rc, wolfTPM2_GetRCString(rc));
    }

    CloseAndCleanupSocket(&sockIoCtx);
    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

#ifndef NO_RSA
    wc_FreeRsaKey(&wolfRsaKey);
    wolfTPM2_UnloadHandle(&dev, &rsaKey.handle);
#endif
#ifdef HAVE_ECC
    wc_ecc_free(&wolfEccKey);
    wolfTPM2_UnloadHandle(&dev, &eccKey.handle);
#endif

    wolfTPM2_Cleanup(&dev);

    return rc;
}

/******************************************************************************/
/* --- END TLS Client Example -- */
/******************************************************************************/

#endif /* !WOLFTPM2_NO_WRAPPER && WOLF_CRYPTO_DEV */

#ifndef NO_MAIN_DRIVER
int main(void)
{
    int rc = -1;

#if !defined(WOLFTPM2_NO_WRAPPER) && defined(WOLF_CRYPTO_DEV)
    rc = TPM2_TLS_Client(TPM2_IoGetUserCtx());
#else
    printf("Wrapper/CryptoDev code not compiled in\n");
    printf("Build wolfssl with ./configure --enable-cryptodev\n");
#endif

    return rc;
}
#endif /* !NO_MAIN_DRIVER */
