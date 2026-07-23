/* tls_server_pq.c
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

/* TLS 1.3 server whose ML-DSA identity key lives in the TPM. The TPM signs the
 * CertificateVerify via the wolfTPM crypto callback. Pair with tls_client_pq. */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2_wrap.h>

#if !defined(WOLFTPM2_NO_WRAPPER) && defined(WOLFTPM_CRYPTOCB) && \
    !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_WOLFSSL_SERVER) && \
    !defined(WOLFCRYPT_ONLY) && defined(WOLFTPM_MLDSA_SIGN) && \
    defined(WOLF_PRIVATE_KEY_ID) && defined(WOLFSSL_TLS13) && \
    !defined(NO_FILESYSTEM)

#ifndef _WIN32
/* host-resolve declarations tls_common.h needs on POSIX */
#include <netdb.h>
#include <arpa/inet.h>
#endif

#include <examples/tls/tls_server_pq.h>
#include <examples/tls/tls_common.h>
#include <hal/tpm_io.h>
#include <examples/tpm_test.h>

#include <stdio.h>
#include <string.h>

#define PQ_SERVER_CERT "./certs/pq-server-cert.der"
#define PQ_CERT_BUF_SZ 10000

static const char kReplyMsg[] = "I hear you fa shizzle!\n";

static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/tls/tls_server_pq [-p=port] [-mldsa=44/65/87]\n");
    printf("* -mldsa=44/65/87: ML-DSA set (must match gen_pqc_certs, def 65)\n");
}

static int parseParamSet(const char* v, TPMI_MLDSA_PARAMETER_SET* ps)
{
    if (XSTRCMP(v, "44") == 0) { *ps = TPM_MLDSA_44; return 0; }
    if (XSTRCMP(v, "65") == 0) { *ps = TPM_MLDSA_65; return 0; }
    if (XSTRCMP(v, "87") == 0) { *ps = TPM_MLDSA_87; return 0; }
    return BAD_FUNC_ARG;
}

static int readDer(const char* file, byte* der, int* derSz)
{
    XFILE f = XFOPEN(file, "rb");
    long sz;
    if (f == XBADFILE) {
        printf("Cannot open %s (run gen_pqc_certs first)\n", file);
        return -1;
    }
    XFSEEK(f, 0, XSEEK_END); sz = XFTELL(f); XREWIND(f);
    if (sz <= 0 || sz > *derSz) { XFCLOSE(f); return -1; }
    if (XFREAD(der, 1, (size_t)sz, f) != (size_t)sz) { XFCLOSE(f); return -1; }
    XFCLOSE(f);
    *derSz = (int)sz;
    return 0;
}

int TPM2_TLS_ServerPQArgs(void* userCtx, int argc, char *argv[])
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY mldsaKey;
    TPMT_PUBLIC pub;
    TpmCryptoDevCtx tpmCtx;
    int tpmDevId = INVALID_DEVID;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    SockIoCbCtx sockIoCtx;
    word32 port = TLS_PORT;
    TPMI_MLDSA_PARAMETER_SET paramSet = TPM_MLDSA_65;
    const byte keyId[] = { 't','p','m','m','l','d','s','a' };
    byte* certDer = NULL;
    int certSz = PQ_CERT_BUF_SZ;
    char msg[MAX_MSG_SZ];
    int msgSz;

    XMEMSET(&dev, 0, sizeof(dev));
    XMEMSET(&mldsaKey, 0, sizeof(mldsaKey));
    XMEMSET(&pub, 0, sizeof(pub));
    XMEMSET(&tpmCtx, 0, sizeof(tpmCtx));
    XMEMSET(&sockIoCtx, 0, sizeof(sockIoCtx));
    sockIoCtx.fd = -1;
    sockIoCtx.listenFd = -1;

    while (argc > 1) {
        if (XSTRCMP(argv[argc-1], "-?") == 0 ||
                XSTRCMP(argv[argc-1], "-h") == 0) {
            usage();
            return 0;
        }
        else if (XSTRNCMP(argv[argc-1], "-p=", 3) == 0) {
            port = (word32)XATOI(argv[argc-1] + 3);
        }
        else if (XSTRNCMP(argv[argc-1], "-mldsa=", 7) == 0) {
            if (parseParamSet(argv[argc-1] + 7, &paramSet) != 0) {
                usage();
                return BAD_FUNC_ARG;
            }
        }
        argc--;
    }

    certDer = (byte*)XMALLOC(PQ_CERT_BUF_SZ, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (certDer == NULL) {
        return MEMORY_E;
    }

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_Init failed 0x%x: %s\n", rc, wolfTPM2_GetRCString(rc));
    }

    if (rc == 0) {
        /* recreate the same TPM ML-DSA identity key gen_pqc_certs certified */
        rc = wolfTPM2_GetKeyTemplate_MLDSA(&pub,
            TPMA_OBJECT_sign | TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent |
            TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
            TPMA_OBJECT_noDA, paramSet, 0);
        if (rc == TPM_RC_SUCCESS) {
            rc = wolfTPM2_CreatePrimaryKey(&dev, &mldsaKey, TPM_RH_OWNER, &pub,
                NULL, 0);
        }
        if (rc != TPM_RC_SUCCESS) {
            printf("Create TPM ML-DSA key failed 0x%x: %s\n",
                rc, wolfTPM2_GetRCString(rc));
        }
    }

    if (rc == 0) {
        tpmCtx.dev = &dev;
        tpmCtx.mldsaKey = &mldsaKey;
        rc = wolfTPM2_SetCryptoDevCb(&dev, wolfTPM2_CryptoDevCb, &tpmCtx,
            &tpmDevId);
        if (rc != TPM_RC_SUCCESS) {
            printf("SetCryptoDevCb failed 0x%x\n", rc);
        }
    }

    if (rc == 0) {
        ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
        if (ctx == NULL) {
            rc = MEMORY_E;
        }
    }
    if (rc == 0) {
        wolfSSL_CTX_SetDevId(ctx, tpmDevId);
        wolfSSL_CTX_SetIORecv(ctx, SockIORecv);
        wolfSSL_CTX_SetIOSend(ctx, SockIOSend);
        rc = readDer(PQ_SERVER_CERT, certDer, &certSz);
    }
    if (rc == 0) {
        if (wolfSSL_CTX_use_certificate_buffer(ctx, certDer, certSz,
                WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
            printf("use_certificate_buffer failed\n");
            rc = -1;
        }
    }
    if (rc == 0) {
        /* private key stays in the TPM: reference it by id + devId */
        if (wolfSSL_CTX_use_PrivateKey_Id(ctx, keyId, sizeof(keyId), tpmDevId)
                != WOLFSSL_SUCCESS) {
            printf("use_PrivateKey_Id failed\n");
            rc = -1;
        }
    }
    if (rc == 0) {
        ssl = wolfSSL_new(ctx);
        if (ssl == NULL) {
            rc = MEMORY_E;
        }
    }
    if (rc == 0) {
        wolfSSL_SetIOReadCtx(ssl, &sockIoCtx);
        wolfSSL_SetIOWriteCtx(ssl, &sockIoCtx);
        rc = SetupSocketAndListen(&sockIoCtx, port);
    }
    if (rc == 0) {
        printf("PQC TLS server listening on port %u\n", (unsigned)port);
        rc = SocketWaitClient(&sockIoCtx);
    }
    if (rc == 0) {
        do {
            rc = wolfSSL_accept(ssl);
        } while (rc != WOLFSSL_SUCCESS &&
                 (wolfSSL_want_read(ssl) || wolfSSL_want_write(ssl)));
        if (rc != WOLFSSL_SUCCESS) {
            printf("accept failed: %s\n",
                wolfSSL_ERR_reason_error_string(wolfSSL_get_error(ssl, rc)));
        }
        else {
            rc = 0;
        }
    }
    if (rc == 0) {
        printf("Handshake: %s, group %s (ML-DSA identity signed on TPM)\n",
            wolfSSL_get_cipher(ssl), wolfSSL_get_curve_name(ssl));
        msgSz = wolfSSL_read(ssl, msg, sizeof(msg) - 1);
        if (msgSz <= 0) {
            printf("read failed: %s\n",
                wolfSSL_ERR_reason_error_string(wolfSSL_get_error(ssl, msgSz)));
            rc = -1;
        }
        else {
            msg[msgSz] = 0;
            printf("Client: %s", msg);
        }
    }
    if (rc == 0) {
        if (wolfSSL_write(ssl, kReplyMsg, (int)XSTRLEN(kReplyMsg)) <= 0) {
            printf("write failed: %s\n",
                wolfSSL_ERR_reason_error_string(wolfSSL_get_error(ssl, 0)));
            rc = -1;
        }
    }

    if (ssl != NULL) { wolfSSL_shutdown(ssl); wolfSSL_free(ssl); }
    if (ctx != NULL) wolfSSL_CTX_free(ctx);
    CloseAndCleanupSocket(&sockIoCtx);
    if (mldsaKey.handle.hndl != 0)
        wolfTPM2_UnloadHandle(&dev, &mldsaKey.handle);
    wolfTPM2_Cleanup(&dev);
    XFREE(certDer, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return rc;
}

#endif

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = -1;
#if !defined(WOLFTPM2_NO_WRAPPER) && defined(WOLFTPM_CRYPTOCB) && \
    !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_WOLFSSL_SERVER) && \
    !defined(WOLFCRYPT_ONLY) && defined(WOLFTPM_MLDSA_SIGN) && \
    defined(WOLF_PRIVATE_KEY_ID) && defined(WOLFSSL_TLS13) && \
    !defined(NO_FILESYSTEM)
    rc = TPM2_TLS_ServerPQArgs(NULL, argc, argv);
#else
    (void)argc;
    (void)argv;
    printf("Requires wolfTPM --enable-pqc and wolfSSL crypto callbacks\n");
#endif
    return rc;
}
#endif
