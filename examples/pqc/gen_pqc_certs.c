/* gen_pqc_certs.c
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

/* Generate a software ML-DSA CA and a device leaf certificate whose subject key
 * is a TPM-resident ML-DSA key, for the TLS PQC examples. */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2_wrap.h>

#if !defined(WOLFTPM2_NO_WRAPPER) && !defined(WOLFTPM2_NO_WOLFCRYPT) && \
    !defined(NO_FILESYSTEM) && \
    defined(WOLFTPM_MLDSA) && defined(WOLFSSL_CERT_GEN) && \
    !defined(WOLFSSL_MLDSA_NO_MAKE_KEY) && \
    !defined(WOLFSSL_DILITHIUM_NO_MAKE_KEY) && \
    !defined(WOLFSSL_MLDSA_NO_SIGN) && !defined(WOLFSSL_DILITHIUM_NO_SIGN) && \
    !defined(WOLFSSL_MLDSA_NO_ASN1) && !defined(WOLFSSL_DILITHIUM_NO_ASN1)

#include <hal/tpm_io.h>
#include <examples/tpm_test.h>

#include <wolfssl/wolfcrypt/wc_mldsa.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/random.h>

#include <stdio.h>
#include <string.h>

#define CA_CERT_FILE     "./certs/pq-ca-cert.der"
#define SERVER_CERT_FILE "./certs/pq-server-cert.der"

/* generous for ML-DSA-87 cert (pub ~2592 + sig ~4627 + overhead) */
#define PQC_CERT_BUF_SZ 10000

static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/pqc/gen_pqc_certs [-mldsa=44/65/87]\n");
    printf("* -mldsa=44/65/87: ML-DSA parameter set (default 65)\n");
    printf("Outputs %s and %s\n", CA_CERT_FILE, SERVER_CERT_FILE);
}

static int parseParamSet(const char* v, TPMI_MLDSA_PARAMETER_SET* ps)
{
    if (XSTRCMP(v, "44") == 0) { *ps = TPM_MLDSA_44; return 0; }
    if (XSTRCMP(v, "65") == 0) { *ps = TPM_MLDSA_65; return 0; }
    if (XSTRCMP(v, "87") == 0) { *ps = TPM_MLDSA_87; return 0; }
    return BAD_FUNC_ARG;
}

static int mldsaTypes(TPMI_MLDSA_PARAMETER_SET ps, int* keyType, int* sigType,
    int* wcLevel)
{
    switch (ps) {
        case TPM_MLDSA_44:
            *keyType = ML_DSA_44_TYPE; *sigType = CTC_ML_DSA_44;
            *wcLevel = WC_ML_DSA_44; return 0;
        case TPM_MLDSA_65:
            *keyType = ML_DSA_65_TYPE; *sigType = CTC_ML_DSA_65;
            *wcLevel = WC_ML_DSA_65; return 0;
        case TPM_MLDSA_87:
            *keyType = ML_DSA_87_TYPE; *sigType = CTC_ML_DSA_87;
            *wcLevel = WC_ML_DSA_87; return 0;
        default:
            return BAD_FUNC_ARG;
    }
}

static int writeDer(const char* file, const byte* der, int derSz)
{
    XFILE f = XFOPEN(file, "wb");
    if (f == XBADFILE) {
        printf("Failed to open %s for write\n", file);
        return -1;
    }
    if (XFWRITE(der, 1, (size_t)derSz, f) != (size_t)derSz) {
        XFCLOSE(f);
        return -1;
    }
    XFCLOSE(f);
    return 0;
}

static int TPM2_PQC_GenCerts(void* userCtx, int argc, char *argv[])
{
    int rc = 0, sz = 0;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY mldsaKey;
    TPMT_PUBLIC pub;
    TPMI_MLDSA_PARAMETER_SET paramSet = TPM_MLDSA_65;
    int keyType = ML_DSA_65_TYPE, sigType = CTC_ML_DSA_65;
    int wcLevel = WC_ML_DSA_65;
    WC_RNG rng;
    wc_MlDsaKey caKey;
    wc_MlDsaKey tpmPubKey;
    Cert caCert;
    Cert leafCert;
    byte* caDer = NULL;
    byte* leafDer = NULL;
    int caSz = 0, leafSz = 0;
    int haveRng = 0, haveCaKey = 0, havePubKey = 0;

    XMEMSET(&dev, 0, sizeof(dev));
    XMEMSET(&mldsaKey, 0, sizeof(mldsaKey));
    XMEMSET(&pub, 0, sizeof(pub));
    XMEMSET(&caKey, 0, sizeof(caKey));
    XMEMSET(&tpmPubKey, 0, sizeof(tpmPubKey));
    XMEMSET(&caCert, 0, sizeof(caCert));
    XMEMSET(&leafCert, 0, sizeof(leafCert));

    if (argc >= 2 && (XSTRCMP(argv[1], "-?") == 0 ||
            XSTRCMP(argv[1], "-h") == 0 || XSTRCMP(argv[1], "--help") == 0)) {
        usage();
        return 0;
    }
    while (argc > 1) {
        if (XSTRNCMP(argv[argc-1], "-mldsa=", 7) == 0) {
            if (parseParamSet(argv[argc-1] + 7, &paramSet) != 0) {
                usage();
                return BAD_FUNC_ARG;
            }
        }
        argc--;
    }
    (void)mldsaTypes(paramSet, &keyType, &sigType, &wcLevel);

    caDer = (byte*)XMALLOC(PQC_CERT_BUF_SZ, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    leafDer = (byte*)XMALLOC(PQC_CERT_BUF_SZ, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (caDer == NULL || leafDer == NULL) {
        rc = MEMORY_E;
    }

    if (rc == 0) {
        rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
        if (rc != TPM_RC_SUCCESS) {
            printf("wolfTPM2_Init failed 0x%x: %s\n", rc,
                wolfTPM2_GetRCString(rc));
        }
    }

    if (rc == 0) {
        /* TPM ML-DSA device key (deterministic; the server recreates it) */
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
        else {
            printf("TPM ML-DSA device key: handle 0x%08x, pub %u bytes\n",
                (unsigned)mldsaKey.handle.hndl,
                (unsigned)mldsaKey.pub.publicArea.unique.mldsa.size);
        }
    }

    if (rc == 0) {
        rc = wc_InitRng(&rng);
        if (rc == 0) haveRng = 1;
    }

    if (rc == 0) {
        /* software CA key */
        rc = wc_MlDsaKey_Init(&caKey, NULL, INVALID_DEVID);
        if (rc == 0) haveCaKey = 1;
        if (rc == 0) rc = wc_MlDsaKey_SetParams(&caKey, wcLevel);
        if (rc == 0) rc = wc_MlDsaKey_MakeKey(&caKey, &rng);
        if (rc != 0) printf("CA key gen failed %d\n", rc);
    }

    if (rc == 0) {
        /* self-signed CA cert */
        rc = wc_InitCert(&caCert);
    }
    if (rc == 0) {
        caCert.daysValid = 365;
        caCert.selfSigned = 1;
        caCert.isCA = 1;
        caCert.sigType = sigType;
        XSTRNCPY(caCert.subject.country, "US", CTC_NAME_SIZE);
        XSTRNCPY(caCert.subject.org, "wolfSSL", CTC_NAME_SIZE);
        XSTRNCPY(caCert.subject.commonName, "wolfTPM PQC Demo CA",
            CTC_NAME_SIZE);
        XMEMCPY(&caCert.issuer, &caCert.subject, sizeof(CertName));
        sz = wc_MakeCert_ex(&caCert, caDer, PQC_CERT_BUF_SZ, keyType, &caKey,
            &rng);
        if (sz < 0) rc = sz;
    }
    if (rc == 0) {
        sz = wc_SignCert_ex(caCert.bodySz, caCert.sigType, caDer,
            PQC_CERT_BUF_SZ, keyType, &caKey, &rng);
        if (sz < 0) rc = sz;
        else caSz = sz;
    }

    if (rc == 0) {
        /* TPM public key for the leaf subject */
        rc = wc_MlDsaKey_Init(&tpmPubKey, NULL, INVALID_DEVID);
        if (rc == 0) havePubKey = 1;
        if (rc == 0) rc = wc_MlDsaKey_SetParams(&tpmPubKey, wcLevel);
        if (rc == 0) rc = wc_MlDsaKey_ImportPubRaw(&tpmPubKey,
            mldsaKey.pub.publicArea.unique.mldsa.buffer,
            mldsaKey.pub.publicArea.unique.mldsa.size);
        if (rc != 0) printf("import TPM pub failed %d\n", rc);
    }

    if (rc == 0) {
        /* device leaf cert: subject = TPM key, issuer = CA, CA-signed */
        rc = wc_InitCert(&leafCert);
    }
    if (rc == 0) {
        leafCert.daysValid = 365;
        leafCert.isCA = 0;
        leafCert.sigType = sigType;
        XSTRNCPY(leafCert.subject.country, "US", CTC_NAME_SIZE);
        XSTRNCPY(leafCert.subject.org, "wolfSSL", CTC_NAME_SIZE);
        XSTRNCPY(leafCert.subject.commonName, "wolfTPM ML-DSA Device",
            CTC_NAME_SIZE);
        rc = wc_SetIssuerBuffer(&leafCert, caDer, caSz);
    }
    if (rc == 0) {
        sz = wc_MakeCert_ex(&leafCert, leafDer, PQC_CERT_BUF_SZ, keyType,
            &tpmPubKey, &rng);
        if (sz < 0) rc = sz;
    }
    if (rc == 0) {
        sz = wc_SignCert_ex(leafCert.bodySz, leafCert.sigType, leafDer,
            PQC_CERT_BUF_SZ, keyType, &caKey, &rng);
        if (sz < 0) rc = sz;
        else leafSz = sz;
    }

    if (rc == 0) {
        rc = writeDer(CA_CERT_FILE, caDer, caSz);
        if (rc == 0) rc = writeDer(SERVER_CERT_FILE, leafDer, leafSz);
        if (rc == 0) {
            printf("Wrote %s (%d bytes) and %s (%d bytes)\n",
                CA_CERT_FILE, caSz, SERVER_CERT_FILE, leafSz);
        }
    }

    if (havePubKey) wc_MlDsaKey_Free(&tpmPubKey);
    if (haveCaKey) wc_MlDsaKey_Free(&caKey);
    if (haveRng) wc_FreeRng(&rng);
    if (mldsaKey.handle.hndl != 0)
        wolfTPM2_UnloadHandle(&dev, &mldsaKey.handle);
    wolfTPM2_Cleanup(&dev);
    XFREE(caDer, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(leafDer, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return rc;
}

#endif /* !WOLFTPM2_NO_WRAPPER && !WOLFTPM2_NO_WOLFCRYPT && WOLFTPM_MLDSA */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = -1;
#if !defined(WOLFTPM2_NO_WRAPPER) && !defined(WOLFTPM2_NO_WOLFCRYPT) && \
    !defined(NO_FILESYSTEM) && \
    defined(WOLFTPM_MLDSA) && defined(WOLFSSL_CERT_GEN) && \
    !defined(WOLFSSL_MLDSA_NO_MAKE_KEY) && \
    !defined(WOLFSSL_DILITHIUM_NO_MAKE_KEY) && \
    !defined(WOLFSSL_MLDSA_NO_SIGN) && !defined(WOLFSSL_DILITHIUM_NO_SIGN) && \
    !defined(WOLFSSL_MLDSA_NO_ASN1) && !defined(WOLFSSL_DILITHIUM_NO_ASN1)
    rc = TPM2_PQC_GenCerts(NULL, argc, argv);
#else
    (void)argc;
    (void)argv;
    printf("Requires --enable-pqc (v1.85 ML-DSA) and wolfSSL cert gen\n");
#endif
    return rc;
}
#endif
