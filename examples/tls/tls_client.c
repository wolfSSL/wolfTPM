/* tls_client.c
 *
 * Copyright (C) 2006-2022 wolfSSL Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */


#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_wrap.h>

#include <stdio.h>

#if !defined(WOLFTPM2_NO_WRAPPER) && defined(WOLFTPM_CRYPTOCB) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(WOLFCRYPT_ONLY)

#include <hal/tpm_io.h>
#include <examples/tpm_test.h>
#include <examples/tpm_test_keys.h>
#include <examples/tls/tls_common.h>
#include <examples/tls/tls_client.h>

#include <wolfssl/ssl.h>

#undef  USE_CERT_BUFFERS_2048
#define USE_CERT_BUFFERS_2048
#undef  USE_CERT_BUFFERS_256
#define USE_CERT_BUFFERS_256
#include <wolfssl/certs_test.h>

#ifdef TLS_BENCH_MODE
    double benchStart;
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
 * By default this example will loads RSA keys unless RSA is disabled (NO_RSA)
 * or the TLS_USE_ECC build option is used.
 *
 * You can validate using the wolfSSL example server this like:
 *   ./examples/server/server -b -p 11111 -g -d
 *
 * To validate client certificate add the following wolfSSL example server args:
 * ./examples/server/server -b -p 11111 -g -A ./certs/tpm-ca-rsa-cert.pem
 * or
 * ./examples/server/server -b -p 11111 -g -A ./certs/tpm-ca-ecc-cert.pem
 * If using an ECDSA cipher suite add:
 * "-l ECDHE-ECDSA-AES128-SHA -c ./certs/server-ecc.pem -k ./certs/ecc-key.pem"
 */


/******************************************************************************/
/* --- BEGIN TPM TLS Client Example -- */
/******************************************************************************/
static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/tls/tls_client [-ecc] [-aes/xor]\n");
    printf("* -ecc: Use RSA or ECC key\n");
    printf("* -aes/xor: Use Parameter Encryption\n");
}

int TPM2_TLS_Client(void* userCtx)
{
    return TPM2_TLS_ClientArgs(userCtx, 0, NULL);
}

int TPM2_TLS_ClientArgs(void* userCtx, int argc, char *argv[])
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
    #ifndef WOLFTPM2_USE_SW_ECDHE
    WOLFTPM2_KEY ecdhKey;
    #endif
#endif
    TpmCryptoDevCtx tpmCtx;
    SockIoCbCtx sockIoCtx;
    int tpmDevId;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
#ifndef TLS_BENCH_MODE
    const char webServerMsg[] = "GET /index.html HTTP/1.0\r\n\r\n";
#endif
    char msg[MAX_MSG_SZ];
    int msgSz = 0;
#ifdef TLS_BENCH_MODE
    int total_size;
    int i;
#endif
    int useECC = 0;
    TPM_ALG_ID paramEncAlg = TPM_ALG_NULL;
    WOLFTPM2_SESSION tpmSession;
    TPMT_PUBLIC publicTemplate;

    /* initialize variables */
    XMEMSET(&storageKey, 0, sizeof(storageKey));
    XMEMSET(&sockIoCtx, 0, sizeof(sockIoCtx));
    sockIoCtx.fd = -1;
    XMEMSET(&tpmCtx, 0, sizeof(tpmCtx));
#ifndef NO_RSA
    XMEMSET(&rsaKey, 0, sizeof(rsaKey));
    XMEMSET(&wolfRsaKey, 0, sizeof(wolfRsaKey));
#endif
#ifdef HAVE_ECC
    XMEMSET(&eccKey, 0, sizeof(eccKey));
    XMEMSET(&wolfEccKey, 0, sizeof(wolfEccKey));
#endif
    XMEMSET(&tpmSession, 0, sizeof(tpmSession));

    if (argc >= 2) {
        if (XSTRCMP(argv[1], "-?") == 0 ||
            XSTRCMP(argv[1], "-h") == 0 ||
            XSTRCMP(argv[1], "--help") == 0) {
            usage();
            return 0;
        }
    }
    while (argc > 1) {
        if (XSTRCMP(argv[argc-1], "-ecc") == 0) {
            useECC = 1;
        }
        if (XSTRCMP(argv[argc-1], "-aes") == 0) {
            paramEncAlg = TPM_ALG_CFB;
        }
        if (XSTRCMP(argv[argc-1], "-xor") == 0) {
            paramEncAlg = TPM_ALG_XOR;
        }
        argc--;
    }

    printf("TPM2 TLS Client Example\n");
    printf("\tUse %s keys\n", useECC ? "ECC" : "RSA");
    printf("\tUse Parameter Encryption: %s\n", TPM2_GetAlgName(paramEncAlg));

    /* Init the TPM2 device */
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != 0) {
        wolfSSL_Cleanup();
        return rc;
    }

    /* Setup the wolf crypto device callback */
#ifndef NO_RSA
    tpmCtx.rsaKey = &rsaKey;
#endif
#ifdef HAVE_ECC
    tpmCtx.eccKey = &eccKey;
#endif
    tpmCtx.storageKey = &storageKey;
#ifdef WOLFTPM_USE_SYMMETRIC
    tpmCtx.useSymmetricOnTPM = 1;
#endif
    rc = wolfTPM2_SetCryptoDevCb(&dev, wolfTPM2_CryptoDevCb, &tpmCtx, &tpmDevId);
    if (rc != 0) goto exit;

    rc = getPrimaryStoragekey(&dev, &storageKey, TPM_ALG_RSA);
    if (rc != 0) goto exit;

    /* Start an authenticated session (salted / unbound) with parameter encryption */
    if (paramEncAlg != TPM_ALG_NULL) {
        rc = wolfTPM2_StartSession(&dev, &tpmSession, &storageKey, NULL,
            TPM_SE_HMAC, paramEncAlg);
        if (rc != 0) goto exit;
        printf("TPM2_StartAuthSession: sessionHandle 0x%x\n",
            (word32)tpmSession.handle.hndl);

        /* set session for authorization of the storage key */
        rc = wolfTPM2_SetAuthSession(&dev, 1, &tpmSession,
            (TPMA_SESSION_decrypt | TPMA_SESSION_encrypt | TPMA_SESSION_continueSession));
        if (rc != 0) goto exit;
    }

#ifndef NO_RSA
    if (!useECC) {
        /* Create/Load RSA key for TLS authentication */
        rc = wolfTPM2_GetKeyTemplate_RSA(&publicTemplate,
                    TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
                    TPMA_OBJECT_decrypt | TPMA_OBJECT_sign | TPMA_OBJECT_noDA);
        if (rc != 0) goto exit;
        rc = getRSAkey(&dev,
                    &storageKey,
                    &rsaKey,
                    &wolfRsaKey,
                    tpmDevId,
                    (byte*)gKeyAuth, sizeof(gKeyAuth)-1,
                    &publicTemplate);
        if (rc != 0) goto exit;
    }
#endif /* !NO_RSA */

#ifdef HAVE_ECC
    if (useECC) {
        /* Create/Load ECC key for TLS authentication */
        rc = wolfTPM2_GetKeyTemplate_ECC(&publicTemplate,
                TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
                TPMA_OBJECT_sign | TPMA_OBJECT_noDA,
                TPM_ECC_NIST_P256, TPM_ALG_ECDSA);
        if (rc != 0) goto exit;
        rc = getECCkey(&dev,
                    &storageKey,
                    &eccKey,
                    &wolfEccKey,
                    tpmDevId,
                    (byte*)gKeyAuth, sizeof(gKeyAuth)-1,
                    &publicTemplate);
        if (rc != 0) goto exit;
    }

    #ifndef WOLFTPM2_USE_SW_ECDHE
    /* Ephemeral Key */
    XMEMSET(&ecdhKey, 0, sizeof(ecdhKey));
    tpmCtx.ecdhKey = &ecdhKey;
    #endif
#endif /* HAVE_ECC */

    /* Setup the WOLFSSL context (factory)
     * Use highest version, allow downgrade */
    if ((ctx = wolfSSL_CTX_new(wolfSSLv23_client_method())) == NULL) {
        rc = MEMORY_E; goto exit;
    }

    /* Setup DevID */
    wolfSSL_CTX_SetDevId(ctx, tpmDevId);

    /* Setup IO Callbacks */
    wolfSSL_CTX_SetIORecv(ctx, SockIORecv);
    wolfSSL_CTX_SetIOSend(ctx, SockIOSend);

    /* Server certificate validation */
    /* Note: Can use "WOLFSSL_VERIFY_NONE" to skip server cert validation */
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, myVerify);
#ifdef NO_FILESYSTEM
    /* Load CA Certificates from Buffer */
    if (!useECC) {
    #ifndef NO_RSA
        if (wolfSSL_CTX_load_verify_buffer(ctx,
                ca_cert_der_2048, sizeof_ca_cert_der_2048,
                WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
            printf("Error loading ca_cert_der_2048 DER cert\n");
            goto exit;
        }
    #else
        printf("Error: RSA not compiled in\n");
    #endif /* !NO_RSA */
    }
    else {
    #ifdef HAVE_ECC
        if (wolfSSL_CTX_load_verify_buffer(ctx,
                ca_ecc_cert_der_256, sizeof_ca_ecc_cert_der_256,
                WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
            printf("Error loading ca_ecc_cert_der_256 DER cert\n");
            goto exit;
        }
    #else
        printf("Error: ECC not compiled in\n");
    #endif /* HAVE_ECC */
    }
#else
    /* Load CA Certificates */
    if (!useECC) {
    #ifndef NO_RSA
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
    #else
        printf("Error: RSA not compiled in\n");
        rc = -1;
        goto exit;
    #endif /* !NO_RSA */
    }
    else {
    #ifdef HAVE_ECC
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
    #else
        printf("Error: ECC not compiled in\n");
        rc = -1;
        goto exit;
    #endif /* HAVE_ECC */
    }
#endif /* !NO_FILESYSTEM */

    /* Client Key (Mutual Authentication) */
    /* Note: Client will not send a client certificate unless a key is
     *   set. Since we do not have the private key wolfSSL allows setting a
     *   public key instead (if crypto callbacks are enabled).
     */
#ifndef NO_TLS_MUTUAL_AUTH
    if (!useECC) {
    #ifndef NO_RSA
        byte der[1024];
        word32 derSz = sizeof(der);
        rc = wc_RsaKeyToPublicDer_ex(&wolfRsaKey, der, derSz, 1);
        if (rc < 0) {
            printf("Failed to export RSA public key!\n");
            goto exit;
        }
        derSz = rc;
        rc = 0;

        /* Private key only exists on the TPM and crypto callbacks are used for
         * signing. Public key is required to enable TLS client (mutual auth).
         * This API accepts public keys when crypto callbacks are enabled */
        if (wolfSSL_CTX_use_PrivateKey_buffer(ctx, der, derSz,
                                    WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
            printf("Failed to set RSA key!\n");
            goto exit;
        }
    #else
        printf("RSA not supported in this build\n");
        rc = -1;
        goto exit;
    #endif /* !NO_RSA */
    }
    else {
    #ifdef HAVE_ECC
        byte der[256];
        word32 derSz = sizeof(der);
        rc = wc_EccPublicKeyToDer(&wolfEccKey, der, derSz, 1);
        if (rc < 0) {
            printf("Failed to export ECC public key!\n");
            goto exit;
        }
        derSz = rc;
        rc = 0;

        /* Private key only exists on the TPM and crypto callbacks are used for
         * signing. Public key is required to enable TLS client (mutual auth).
         * This API accepts public keys when crypto callbacks are enabled */
        if (wolfSSL_CTX_use_PrivateKey_buffer(ctx, der, derSz,
                                    WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
            printf("Failed to set ECC key!\n");
            goto exit;
        }
    #else
        printf("RSA not supported in this build\n");
        rc = -1;
        goto exit;
    #endif /* HAVE_ECC */
    }

    /* Client Certificate (Mutual Authentication) */
    if (!useECC) {
    #ifndef NO_RSA
        printf("Loading RSA certificate\n");
        #ifdef NO_FILESYSTEM
        /* Load "cert" buffer with ASN.1/DER certificate */
        rc = wolfSSL_CTX_use_certificate_buffer(ctx, cert.buffer, (long)cert.size,
                                                WOLFSSL_FILETYPE_ASN1);
        #else
        rc = wolfSSL_CTX_use_certificate_file(ctx, "./certs/client-rsa-cert.pem",
                                              WOLFSSL_FILETYPE_PEM);
        #endif
        if (rc != WOLFSSL_SUCCESS) {
            printf("Error loading RSA client cert\n");
            goto exit;
        }
    #else
        printf("RSA not supported in this build\n");
        rc = -1;
        goto exit;
    #endif /* !NO_RSA */
    }
    else {
    #ifdef HAVE_ECC
        printf("Loading ECC certificate\n");
        #ifdef NO_FILESYSTEM
        /* Load "cert" buffer with ASN.1/DER certificate */
        rc = wolfSSL_CTX_use_certificate_buffer(ctx, cert.buffer, (long)cert.size,
                                                WOLFSSL_FILETYPE_ASN1);
        #else
        rc = wolfSSL_CTX_use_certificate_file(ctx, "./certs/client-ecc-cert.pem",
                                              WOLFSSL_FILETYPE_PEM);
        #endif
        if (rc != WOLFSSL_SUCCESS) {
            printf("Error loading ECC client cert\n");
            goto exit;
        }
    #else
        printf("ECC not supported in this build\n");
        rc = -1;
        goto exit;
    #endif /* HAVE_ECC */
    }
#endif /* !NO_TLS_MUTUAL_AUTH */

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

    /* Setup socket and connection */
    rc = SetupSocketAndConnect(&sockIoCtx, TLS_HOST, TLS_PORT);
    if (rc != 0) goto exit;

    /* Setup read/write callback contexts */
    wolfSSL_SetIOReadCtx(ssl, &sockIoCtx);
    wolfSSL_SetIOWriteCtx(ssl, &sockIoCtx);

    /* perform connect */
#ifdef TLS_BENCH_MODE
    benchStart = gettime_secs(1);
#endif
    do {
        rc = wolfSSL_connect(ssl);
        if (rc != WOLFSSL_SUCCESS) {
            rc = wolfSSL_get_error(ssl, 0);
        }
    } while (rc == WOLFSSL_ERROR_WANT_READ || rc == WOLFSSL_ERROR_WANT_WRITE);
    if (rc != WOLFSSL_SUCCESS) {
        goto exit;
    }
#ifdef TLS_BENCH_MODE
    benchStart = gettime_secs(0) - benchStart;
    printf("Connect: %9.3f sec (%9.3f CPS)\n", benchStart, 1/benchStart);
#endif

    printf("Cipher Suite: %s\n", wolfSSL_get_cipher(ssl));

#ifdef TLS_BENCH_MODE
    rc = 0;
    total_size = 0;
    while (rc == 0 && total_size < TOTAL_MSG_SZ)
#endif
    {
        /* initialize write */
    #ifdef TLS_BENCH_MODE
        msgSz = sizeof(msg); /* sequence */
        for (i=0; i<msgSz; i++) {
            msg[i] = (i & 0xff);
        }
        total_size += msgSz;
    #else
        msgSz = sizeof(webServerMsg);
        XMEMCPY(msg, webServerMsg, msgSz);
    #endif

        /* perform write */
    #ifdef TLS_BENCH_MODE
        benchStart = gettime_secs(1);
    #endif
        do {
            rc = wolfSSL_write(ssl, msg, msgSz);
            if (rc != msgSz) {
                rc = wolfSSL_get_error(ssl, 0);
            }
        } while (rc == WOLFSSL_ERROR_WANT_WRITE);
        if (rc >= 0) {
            msgSz = rc;
        #ifdef TLS_BENCH_MODE
            benchStart = gettime_secs(0) - benchStart;
            printf("Write: %d bytes in %9.3f sec (%9.3f KB/sec)\n",
                msgSz, benchStart, msgSz / benchStart / 1024);
        #else
            printf("Write (%d): %s\n", msgSz, msg);
        #endif
            rc = 0; /* success */
        }
        if (rc != 0) goto exit;

        /* perform read */
    #ifdef TLS_BENCH_MODE
        benchStart = 0; /* use the read callback to trigger timing */
    #endif
        do {
            /* attempt to fill msg buffer */
            rc = wolfSSL_read(ssl, msg, sizeof(msg));
            if (rc < 0) {
                rc = wolfSSL_get_error(ssl, 0);
            }
        } while (rc == WOLFSSL_ERROR_WANT_READ);
        if (rc >= 0) {
            msgSz = rc;
        #ifdef TLS_BENCH_MODE
            benchStart = gettime_secs(0) - benchStart;
            printf("Read: %d bytes in %9.3f sec (%9.3f KB/sec)\n",
                msgSz, benchStart, msgSz / benchStart / 1024);
        #else
            /* null terminate */
            if (msgSz >= (int)sizeof(msg))
                msgSz = (int)sizeof(msg) - 1;
            msg[msgSz] = '\0';
            printf("Read (%d): %s\n", msgSz, msg);
        #endif
            rc = 0; /* success */
        }
    }

exit:

    if (rc != 0) {
        printf("Failure %d (0x%x): %s\n", rc, rc, wolfTPM2_GetRCString(rc));
    }

    wolfTPM2_UnloadHandle(&dev, &storageKey.handle);
#ifndef NO_RSA
    wc_FreeRsaKey(&wolfRsaKey);
    wolfTPM2_UnloadHandle(&dev, &rsaKey.handle);
#endif
#ifdef HAVE_ECC
    wc_ecc_free(&wolfEccKey);
    wolfTPM2_UnloadHandle(&dev, &eccKey.handle);
#endif
    wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);

    wolfSSL_shutdown(ssl);

    CloseAndCleanupSocket(&sockIoCtx);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    wolfTPM2_Cleanup(&dev);

    return rc;
}

/******************************************************************************/
/* --- END TPM TLS Client Example -- */
/******************************************************************************/

#endif /* !WOLFTPM2_NO_WRAPPER && WOLFTPM_CRYPTOCB && !NO_WOLFSSL_CLIENT && \
        * !WOLFCRYPT_ONLY */

#ifndef NO_MAIN_DRIVER
int main(int argc, char* argv[])
{
    int rc = -1;

#if !defined(WOLFTPM2_NO_WRAPPER) && defined(WOLFTPM_CRYPTOCB) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(WOLFCRYPT_ONLY)
    rc = TPM2_TLS_ClientArgs(NULL, argc, argv);
#else
    (void)argc;
    (void)argv;

    printf("Wrapper/Crypto callback code or TLS support not compiled in\n");
    printf("Build wolfssl with ./configure --enable-cryptocb\n");
#endif

    return rc;
}
#endif /* !NO_MAIN_DRIVER */
