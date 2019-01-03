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

#if !defined(WOLFTPM2_NO_WRAPPER) && defined(WOLF_CRYPTO_DEV) && \
    !defined(WOLFTPM2_NO_WOLFCRYPT)

#include <examples/tpm_io.h>
#include <examples/tpm_test.h>
#include <examples/tls/tls_client.h>

#include <wolfssl/ssl.h>

#ifndef TLS_HOST
#define TLS_HOST "localhost"
#endif
#ifndef TLS_PORT
#define TLS_PORT 11111
#endif

/* to manually choose a cipher suite */
#if 0
#ifndef TLS_CIPHER_SUITE
#define TLS_CIPHER_SUITE "ECDHE-RSA-AES128-SHA256"
#endif
#endif
/* enable for testing ECC key/cert when RSA is enabled */
#if 0
#define TLS_USE_ECC
#endif

/*
 * Generating the Client Certificate
 *
 * Run example for ./examples/csr/csr
 * Result is: ./certs/tpm-rsa-cert.csr and ./certs/tpm-ecc-cert.csr
 *
 * Run ./certs/certreq.sh
 * Result is: ./certs/client-rsa-cert.pem and ./certs/client-ecc-cert.pem
 *
 * This example client connects to localhost on on port 11111 by default.
 * These can be overriden using `TLS_HOST` and `TLS_PORT`.
 *
 * You can validate using the wolfSSL example server this like:
 *   ./examples/server/server -b -p 11111 -g -d
 *
 * To validate client certificate add the following wolfSSL example server args:
 * ./examples/server/server -b -p 11111 -g -A ./certs/tpm-ca-rsa-cert.pem
 * or
 * ./examples/server/server -b -p 11111 -g -A ./certs/tpm-ca-ecc-cert.pem
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


static int myVerify(int preverify, WOLFSSL_X509_STORE_CTX* store)
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

/* Function checks key to see if its the "dummy" key */
static int myTpmCheckKey(wc_CryptoInfo* info, TpmCryptoDevCtx* ctx)
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
    WOLFTPM2_KEY ecdhKey;
#endif
    TPMT_PUBLIC publicTemplate;
    TpmCryptoDevCtx tpmCtx;
    SockIoCbCtx sockIoCtx;
    int tpmDevId;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    char msg[] = "GET /index.html HTTP/1.0\r\n\r\n";
    char reply[MAX_REPLY_SZ];
    int msgSz, replySz = 0;

    /* initialize variables */
    XMEMSET(&sockIoCtx, 0, sizeof(sockIoCtx));
    sockIoCtx.fd = -1;

    printf("TPM2 TLS Client Example\n");

#ifdef DEBUG_WOLFSSL
    wolfSSL_Debugging_ON();
#endif
    wolfSSL_Init();

    /* Init the TPM2 device */
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != 0) {
        wolfSSL_Cleanup();
        return rc;
    }

    /* Setup the wolf crypto device callback */
#ifndef NO_RSA
    XMEMSET(&wolfRsaKey, 0, sizeof(wolfRsaKey));
    tpmCtx.rsaKey = &rsaKey;
#endif
#ifdef HAVE_ECC
    XMEMSET(&wolfEccKey, 0, sizeof(wolfEccKey));
    tpmCtx.eccKey = &eccKey;
#endif
    tpmCtx.checkKeyCb = myTpmCheckKey; /* detects if using "dummy" key */
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

    /* Ephemeral Key */
    XMEMSET(&ecdhKey, 0, sizeof(ecdhKey));
    tpmCtx.ecdhKey = &ecdhKey;
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
    wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, myVerify);
#else
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, myVerify);
#ifdef NO_FILESYSTEM
    /* example loading from buffer */
    #if 0
        if (wolfSSL_CTX_load_verify(ctx, ca.buffer, (long)ca.size,
            WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) }
            goto exit;
        }
    #endif
#else
    /* Load CA Certificates */
    #if !defined(NO_RSA) && !defined(TLS_USE_ECC)
    if (wolfSSL_CTX_load_verify_locations(ctx, "./certs/ca-rsa-cert.pem",
        0) != WOLFSSL_SUCCESS) {
        printf("Error loading ca-rsa-cert.pem cert\n");
        goto exit;
    }
    if (wolfSSL_CTX_load_verify_locations(ctx, "./certs/wolf-ca-rsa-cert.pem",
        0) != WOLFSSL_SUCCESS) {
        printf("Error loading wolf-ca-rsa-cert.pem cert\n");
        goto exit;
    }
    #elif defined(HAVE_ECC)
    if (wolfSSL_CTX_load_verify_locations(ctx, "./certs/ca-ecc-cert.pem",
        0) != WOLFSSL_SUCCESS) {
        printf("Error loading ca-ecc-cert.pem cert\n");
        goto exit;
    }
    if (wolfSSL_CTX_load_verify_locations(ctx, "./certs/wolf-ca-ecc-cert.pem",
        0) != WOLFSSL_SUCCESS) {
        printf("Error loading wolf-ca-ecc-cert.pem cert\n");
        goto exit;
    }
    #endif
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
#if !defined(NO_RSA) && !defined(TLS_USE_ECC)
    if ((rc = wolfSSL_CTX_use_certificate_file(ctx, "./certs/client-rsa-cert.pem",
        WOLFSSL_FILETYPE_PEM)) != WOLFSSL_SUCCESS) {
        printf("Error loading RSA client cert\n");
        goto exit;
    }

    /* Private key is on TPM and crypto dev callbacks are used */
    /* TLS client (mutual auth) requires a dummy key loaded (workaround) */
    if (wolfSSL_CTX_use_PrivateKey_buffer(ctx, DUMMY_RSA_KEY,
            sizeof(DUMMY_RSA_KEY), WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
        printf("Failed to set key!\r\n");
        goto exit;
    }
#elif defined(HAVE_ECC)
    if ((rc = wolfSSL_CTX_use_certificate_file(ctx, "./certs/client-ecc-cert.pem",
        WOLFSSL_FILETYPE_PEM)) != WOLFSSL_SUCCESS) {
        printf("Error loading ECC client cert\n");
        goto exit;
    }

    /* Private key is on TPM and crypto dev callbacks are used */
    /* TLS client (mutual auth) requires a dummy key loaded (workaround) */
    if (wolfSSL_CTX_use_PrivateKey_buffer(ctx, DUMMY_ECC_KEY,
            sizeof(DUMMY_ECC_KEY), WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
        printf("Failed to set key!\r\n");
        goto exit;
    }
#endif
#endif /* !NO_FILESYSTEM */

#ifdef TLS_CIPHER_SUITE
    /* Optionally choose the cipher suite */
    rc = wolfSSL_CTX_set_cipher_list(ctx, TLS_CIPHER_SUITE);
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
    if (rc != WOLFSSL_SUCCESS) {
        goto exit;
    }

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
    rc = 0; /* success */

exit:

    if (rc != 0) {
        printf("Failure %d (0x%x): %s\n", rc, rc, wolfTPM2_GetRCString(rc));
    }

    wolfSSL_shutdown(ssl);

    CloseAndCleanupSocket(&sockIoCtx);
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
    wolfSSL_Cleanup();

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

#if !defined(WOLFTPM2_NO_WRAPPER) && defined(WOLF_CRYPTO_DEV) && \
    !defined(WOLFTPM2_NO_WOLFCRYPT)
    rc = TPM2_TLS_Client(NULL);
#else
    printf("Wrapper/CryptoDev code not compiled in\n");
    printf("Build wolfssl with ./configure --enable-cryptodev\n");
#endif

    return rc;
}
#endif /* !NO_MAIN_DRIVER */
