/* csr.c
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_wrap.h>

#include <stdio.h>

#if !defined(WOLFTPM2_NO_WRAPPER) && defined(WOLFTPM2_CERT_GEN) && \
    defined(WOLFTPM_CRYPTOCB)

#include <hal/tpm_io.h>
#include <examples/tpm_test.h>
#include <examples/tpm_test_keys.h>
#include <examples/csr/csr.h>
#include <wolfssl/wolfcrypt/asn_public.h>

#ifndef NO_RSA
#ifndef RSA_CERT_CSR
    #define RSA_CERT_CSR "./certs/tpm-rsa-cert.csr"
#endif
#ifndef RSA_CERT_PEM
    #define RSA_CERT_PEM "./certs/tpm-rsa-cert.pem"
#endif
static const char* gClientCsrRsaFile = RSA_CERT_CSR;
static const char* gClientCertRsaFile = RSA_CERT_PEM;
#endif

#ifdef HAVE_ECC
#ifndef ECC_CERT_CSR
    #define ECC_CERT_CSR "./certs/tpm-ecc-cert.csr"
#endif
#ifndef ECC_CERT_PEM
    #define ECC_CERT_PEM "./certs/tpm-ecc-cert.pem"
#endif
static const char* gClientCsrEccFile = ECC_CERT_CSR;
static const char* gClientCertEccFile = ECC_CERT_PEM;
#endif

#ifndef MAX_PEM_SIZE
#define MAX_PEM_SIZE MAX_CONTEXT_SIZE
#endif

/******************************************************************************/
/* --- BEGIN TPM2 CSR Example -- */
/******************************************************************************/

static int TPM2_CSR_Generate(WOLFTPM2_DEV* dev, int keyType, WOLFTPM2_KEY* key,
    const char* outputPemFile, int makeSelfSignedCert, int devId, int sigType)
{
    int rc;
    const char* subject = NULL;
    const char* keyUsage = "serverAuth,clientAuth,codeSigning,"
                           "emailProtection,timeStamping,OCSPSigning";
    byte output[MAX_PEM_SIZE];
    int outputSz;
#ifndef WOLFTPM2_NO_HEAP
    const char* custOid =    "1.2.3.4.5";
    const char* custOidVal = "This is NOT a critical extension";
    WOLFTPM2_CSR* csr = wolfTPM2_NewCSR();

    if (csr == NULL) {
        return MEMORY_E;
    }
#endif

    /* make sure each subject is unique */
    if (keyType == RSA_TYPE) {
        subject = "/C=US/ST=Oregon/L=Portland/SN=Test/O=wolfSSL"
                  "/OU=RSA/CN=127.0.0.1/emailAddress=info@wolfssl.com";
    }
    else if (keyType == ECC_TYPE) {
        subject = "/C=US/ST=Oregon/L=Portland/SN=Test/O=wolfSSL"
                  "/OU=ECC/CN=127.0.0.1/emailAddress=info@wolfssl.com";
    }

    outputSz = (int)sizeof(output);
#ifdef WOLFTPM2_NO_HEAP
    /* single shot API for CSR generation */
    rc = wolfTPM2_CSR_Generate_ex(dev, key, subject, keyUsage,
        ENCODING_TYPE_PEM, output, outputSz, sigType, makeSelfSignedCert,
        devId);
#else
    rc = wolfTPM2_CSR_SetSubject(dev, csr, subject);
    if (rc == 0) {
        rc = wolfTPM2_CSR_SetKeyUsage(dev, csr, keyUsage);
    }
    if (rc == 0) {
        /* sample custom OID for testing */
        rc = wolfTPM2_CSR_SetCustomExt(dev, csr, 0, custOid,
            (const byte*)custOidVal, (word32)XSTRLEN(custOidVal));
        if (rc == NOT_COMPILED_IN) {
            /* allow error for not compiled in */
            rc = 0;
        }
    }
    if (rc == 0) {
        rc = wolfTPM2_CSR_MakeAndSign_ex(dev, csr, key, ENCODING_TYPE_PEM,
            output, outputSz, sigType, makeSelfSignedCert, devId);
    }
#endif
    if (rc >= 0) {
        outputSz = rc;
        printf("Generated/Signed Cert (PEM %d)\n", outputSz);
    #if !defined(NO_FILESYSTEM) && !defined(NO_WRITE_TEMP_FILES)
        XFILE pemFile = XFOPEN(outputPemFile, "wb");
        if (pemFile != XBADFILE) {
            rc = (int)XFWRITE(output, 1, outputSz, pemFile);
            XFCLOSE(pemFile);
            rc = (rc == outputSz) ? 0 : -1;
            if (rc == 0) {
                printf("Saved to %s\n", outputPemFile);
            }
        }
    #endif
        printf("%s\n", (char*)output);
    }
    (void)outputPemFile;

#ifndef WOLFTPM2_NO_HEAP
    wolfTPM2_FreeCSR(csr);
#endif

    return rc;
}

static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/csr/csr [-cert]\n");
    printf("\t-cert: Make self signed certificate instead of "
                    "default CSR (Certificate Signing Request)\n");
}

int TPM2_CSR_Example(void* userCtx)
{
    return TPM2_CSR_ExampleArgs(userCtx, 0, NULL);
}
int TPM2_CSR_ExampleArgs(void* userCtx, int argc, char *argv[])
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY storageKey;
    WOLFTPM2_KEY key;
    TpmCryptoDevCtx tpmCtx;
    int tpmDevId;
    TPMT_PUBLIC publicTemplate;
    int makeSelfSignedCert = 0;

    printf("TPM2 CSR Example\n");

    if (argc >= 2) {
        if (XSTRCMP(argv[1], "-?") == 0 ||
            XSTRCMP(argv[1], "-h") == 0 ||
            XSTRCMP(argv[1], "--help") == 0) {
            usage();
            return 0;
        }
    }
    while (argc > 1) {
        if (XSTRCMP(argv[argc-1], "-cert") == 0) {
            makeSelfSignedCert = 1;
        }
        else {
            printf("Warning: Unrecognized option: %s\n", argv[argc-1]);
        }
        argc--;
    }

    /* Init the TPM2 device */
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != 0) {
        return rc;
    }

    /* initialize variables */
    XMEMSET(&storageKey, 0, sizeof(storageKey));
    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(&tpmCtx, 0, sizeof(tpmCtx));

    rc = wolfTPM2_SetCryptoDevCb(&dev, wolfTPM2_CryptoDevCb, &tpmCtx,
        &tpmDevId);

#ifndef NO_RSA
    if (rc == 0) {
        tpmCtx.rsaKey = &key; /* Setup the wolf crypto device callback */

        /* open the RSA SRK */
        rc = getPrimaryStoragekey(&dev, &storageKey, TPM_ALG_RSA);
        if (rc == 0) {
            rc = wolfTPM2_GetKeyTemplate_RSA(&publicTemplate,
                    TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
                    TPMA_OBJECT_decrypt | TPMA_OBJECT_sign | TPMA_OBJECT_noDA);
        }
        if (rc == 0) {
            rc = getRSAkey(&dev, &storageKey, &key, NULL, tpmDevId,
                (byte*)gKeyAuth, sizeof(gKeyAuth)-1, &publicTemplate);
        }
        if (rc == 0) {
            rc = TPM2_CSR_Generate(&dev, RSA_TYPE, &key,
                makeSelfSignedCert ? gClientCertRsaFile : gClientCsrRsaFile,
                makeSelfSignedCert, tpmDevId, CTC_SHA256wRSA);
        }
        wolfTPM2_UnloadHandle(&dev, &key.handle);
        wolfTPM2_UnloadHandle(&dev, &storageKey.handle);
    }
#endif /* !NO_RSA */

#ifdef HAVE_ECC
    if (rc == 0) {
        int sigType = CTC_SHA256wECDSA;
        TPM_ECC_CURVE curve = TPM_ECC_NIST_P256;
    #if defined(NO_ECC256) && defined(HAVE_ECC384) && ECC_MIN_KEY_SZ <= 384
        /* make sure we use a curve that is enabled */
        sigType = CTC_SHA384wECDSA;
        curve = TPM_ECC_NIST_P384;
    #endif
        tpmCtx.eccKey = &key;

        /* open the ECC SRK */
        rc = getPrimaryStoragekey(&dev, &storageKey, TPM_ALG_ECC);
        if (rc == 0) {
            rc = wolfTPM2_GetKeyTemplate_ECC(&publicTemplate,
                TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
                TPMA_OBJECT_sign | TPMA_OBJECT_noDA,
                curve, TPM_ALG_ECDSA);
        }
        if (rc == 0) {
            rc = getECCkey(&dev, &storageKey, &key, NULL, tpmDevId,
                  (byte*)gKeyAuth, sizeof(gKeyAuth)-1, &publicTemplate);
        }
        if (rc == 0) {
            rc = TPM2_CSR_Generate(&dev, ECC_TYPE, &key,
                makeSelfSignedCert ? gClientCertEccFile : gClientCsrEccFile,
                makeSelfSignedCert, tpmDevId, sigType);
        }
        wolfTPM2_UnloadHandle(&dev, &key.handle);
        wolfTPM2_UnloadHandle(&dev, &storageKey.handle);
    }
#endif /* HAVE_ECC */

    if (rc != 0) {
        printf("Failure 0x%x: %s\n", rc, wolfTPM2_GetRCString(rc));
    }

    wolfTPM2_Cleanup(&dev);

    return rc;
}

/******************************************************************************/
/* --- END TPM2 CSR Example -- */
/******************************************************************************/

#endif /* !WOLFTPM2_NO_WRAPPER && WOLFTPM2_CERT_GEN && WOLFTPM_CRYPTOCB */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = -1;

#if !defined(WOLFTPM2_NO_WRAPPER) && defined(WOLFTPM2_CERT_GEN) && \
    defined(WOLFTPM_CRYPTOCB)
    rc = TPM2_CSR_ExampleArgs(NULL, argc, argv);
#else
    (void)argc;
    (void)argv;

    printf("Wrapper/CertReq/CryptoCb code not compiled in\n");
    printf("Build wolfssl with ./configure --enable-certgen --enable-certreq "
                                        "--enable-certext --enable-cryptocb\n");
#endif

    return rc;
}
#endif /* !NO_MAIN_DRIVER */
