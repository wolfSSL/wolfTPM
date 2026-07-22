/* tls_client_pq.c
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

/* TLS 1.3 client for the PQC example: ML-KEM key exchange, validates the
 * server's TPM ML-DSA certificate against the CA. Pair with tls_server_pq. */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2_wrap.h>

#if !defined(WOLFTPM2_NO_WRAPPER) && defined(WOLFTPM_CRYPTOCB) && \
    !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_WOLFSSL_CLIENT) && \
    !defined(WOLFCRYPT_ONLY) && defined(WOLFTPM_MLDSA_SIGN) && \
    defined(WOLFSSL_TLS13) && !defined(NO_FILESYSTEM)

#ifndef _WIN32
/* host-resolve declarations tls_common.h needs on POSIX */
#include <netdb.h>
#include <arpa/inet.h>
#endif

#include <examples/tls/tls_client_pq.h>
#include <examples/tls/tls_common.h>

#include <stdio.h>
#include <string.h>

#define PQ_CA_CERT   "./certs/pq-ca-cert.der"
#define PQ_CERT_BUF_SZ 10000

static const char kHelloMsg[] = "hello wolfssl!\n";

static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/tls/tls_client_pq [-h=host] [-p=port] [-group=name]\n");
    printf("* -group: ML_KEM_512/768/1024, or hybrid SECP256R1MLKEM768 /\n");
    printf("          X25519MLKEM768 (default ML_KEM_768)\n");
}

static int parseGroup(const char* v, int* group)
{
    if (XSTRCMP(v, "ML_KEM_512") == 0) { *group = WOLFSSL_ML_KEM_512; return 0; }
    if (XSTRCMP(v, "ML_KEM_768") == 0) { *group = WOLFSSL_ML_KEM_768; return 0; }
    if (XSTRCMP(v, "ML_KEM_1024") == 0) {
        *group = WOLFSSL_ML_KEM_1024; return 0;
    }
    if (XSTRCMP(v, "SECP256R1MLKEM768") == 0) {
        *group = WOLFSSL_SECP256R1MLKEM768; return 0;
    }
    if (XSTRCMP(v, "X25519MLKEM768") == 0) {
        *group = WOLFSSL_X25519MLKEM768; return 0;
    }
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

int TPM2_TLS_ClientPQArgs(void* userCtx, int argc, char *argv[])
{
    int rc = 0;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    SockIoCbCtx sockIoCtx;
    const char* host = TLS_HOST;
    word32 port = TLS_PORT;
    int group = WOLFSSL_ML_KEM_768;
    byte* caDer = NULL;
    int caSz = PQ_CERT_BUF_SZ;
    char reply[MAX_MSG_SZ];
    int replySz;

    (void)userCtx;
    XMEMSET(&sockIoCtx, 0, sizeof(sockIoCtx));
    sockIoCtx.fd = -1;
    sockIoCtx.listenFd = -1;

    while (argc > 1) {
        if (XSTRNCMP(argv[argc-1], "-h=", 3) == 0) {
            host = argv[argc-1] + 3;
        }
        else if (XSTRNCMP(argv[argc-1], "-p=", 3) == 0) {
            port = (word32)XATOI(argv[argc-1] + 3);
        }
        else if (XSTRNCMP(argv[argc-1], "-group=", 7) == 0) {
            if (parseGroup(argv[argc-1] + 7, &group) != 0) {
                usage();
                return BAD_FUNC_ARG;
            }
        }
        else if (XSTRCMP(argv[argc-1], "-?") == 0 ||
                XSTRCMP(argv[argc-1], "-h") == 0) {
            usage();
            return 0;
        }
        argc--;
    }

    caDer = (byte*)XMALLOC(PQ_CERT_BUF_SZ, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (caDer == NULL) {
        return MEMORY_E;
    }

    ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (ctx == NULL) {
        rc = MEMORY_E;
    }
    if (rc == 0) {
        wolfSSL_CTX_SetIORecv(ctx, SockIORecv);
        wolfSSL_CTX_SetIOSend(ctx, SockIOSend);
        /* require the server chain to validate against the software CA */
        wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
        rc = readDer(PQ_CA_CERT, caDer, &caSz);
    }
    if (rc == 0) {
        if (wolfSSL_CTX_load_verify_buffer(ctx, caDer, caSz,
                WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
            printf("load_verify_buffer failed\n");
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
        if (wolfSSL_UseKeyShare(ssl, (word16)group) != WOLFSSL_SUCCESS) {
            printf("UseKeyShare failed\n");
            rc = -1;
        }
    }
    if (rc == 0) {
        /* advertise only the chosen group; no silent downgrade */
        if (wolfSSL_set_groups(ssl, &group, 1) != WOLFSSL_SUCCESS) {
            printf("set_groups failed\n");
            rc = -1;
        }
    }
    if (rc == 0) {
        rc = SetupSocketAndConnect(&sockIoCtx, host, port);
    }
    if (rc == 0) {
        do {
            rc = wolfSSL_connect(ssl);
        } while (rc != WOLFSSL_SUCCESS &&
                 (wolfSSL_want_read(ssl) || wolfSSL_want_write(ssl)));
        if (rc != WOLFSSL_SUCCESS) {
            printf("connect failed: %s\n",
                wolfSSL_ERR_reason_error_string(wolfSSL_get_error(ssl, rc)));
        }
        else {
            rc = 0;
        }
    }
    if (rc == 0) {
        printf("Handshake: %s, group %s\n",
            wolfSSL_get_cipher(ssl), wolfSSL_get_curve_name(ssl));
        printf("Server ML-DSA identity verified against the CA\n");
        if (wolfSSL_write(ssl, kHelloMsg, (int)XSTRLEN(kHelloMsg)) <= 0) {
            printf("write failed: %s\n",
                wolfSSL_ERR_reason_error_string(wolfSSL_get_error(ssl, 0)));
            rc = -1;
        }
    }
    if (rc == 0) {
        replySz = wolfSSL_read(ssl, reply, sizeof(reply) - 1);
        if (replySz <= 0) {
            printf("read failed: %s\n",
                wolfSSL_ERR_reason_error_string(
                    wolfSSL_get_error(ssl, replySz)));
            rc = -1;
        }
        else {
            reply[replySz] = 0;
            printf("Server: %s", reply);
        }
    }

    if (ssl != NULL) { wolfSSL_shutdown(ssl); wolfSSL_free(ssl); }
    if (ctx != NULL) wolfSSL_CTX_free(ctx);
    CloseAndCleanupSocket(&sockIoCtx);
    XFREE(caDer, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return rc;
}

#endif

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = -1;
#if !defined(WOLFTPM2_NO_WRAPPER) && defined(WOLFTPM_CRYPTOCB) && \
    !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_WOLFSSL_CLIENT) && \
    !defined(WOLFCRYPT_ONLY) && defined(WOLFTPM_MLDSA_SIGN) && \
    defined(WOLFSSL_TLS13) && !defined(NO_FILESYSTEM)
    rc = TPM2_TLS_ClientPQArgs(NULL, argc, argv);
#else
    (void)argc;
    (void)argv;
    printf("Requires wolfTPM --enable-pqc and wolfSSL crypto callbacks\n");
#endif
    return rc;
}
#endif
