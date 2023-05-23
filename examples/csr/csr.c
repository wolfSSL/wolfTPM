/* csr.c
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

#if !defined(WOLFTPM2_NO_WRAPPER) && defined(WOLFTPM2_CERT_GEN)

#include <hal/tpm_io.h>
#include <examples/tpm_test.h>
#include <examples/tpm_test_keys.h>
#include <examples/csr/csr.h>
#include <wolfssl/wolfcrypt/asn_public.h>

#ifndef NO_RSA
static const char* gClientCsrRsaFile = "./certs/tpm-rsa-cert.csr";
static const char* gClientCertRsaFile = "./certs/tpm-rsa-cert.pem";
#endif
#ifdef HAVE_ECC
static const char* gClientCsrEccFile = "./certs/tpm-ecc-cert.csr";
static const char* gClientCertEccFile = "./certs/tpm-ecc-cert.pem";
#endif

/******************************************************************************/
/* --- BEGIN TPM2 CSR Example -- */
/******************************************************************************/

static int TPM2_CSR_Generate(WOLFTPM2_DEV* dev, int keyType, WOLFTPM2_KEY* key,
    const char* outputPemFile, int makeSelfSignedCert, int devId)
{
    int rc;
    const char* subject = NULL;
    const char* keyUsage = "serverAuth,clientAuth,codeSigning,"
                           "emailProtection,timeStamping,OCSPSigning";
    WOLFTPM2_BUFFER output;
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
                  "/OU=RSA/CN=www.wolfssl.com/emailAddress=info@wolfssl.com";
    }
    else if (keyType == ECC_TYPE) {
        subject = "/C=US/ST=Oregon/L=Portland/SN=Test/O=wolfSSL"
                  "/OU=ECC/CN=www.wolfssl.com/emailAddress=info@wolfssl.com";
    }

    output.size = (int)sizeof(output.buffer);
#ifdef WOLFTPM2_NO_HEAP
    /* single shot API for CSR generation */
    rc = wolfTPM2_CSR_Generate_ex(dev, key, subject, keyUsage,
        CTC_FILETYPE_PEM, output.buffer, output.size, 0, makeSelfSignedCert,
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
        rc = wolfTPM2_CSR_MakeAndSign_ex(dev, csr, key, CTC_FILETYPE_PEM,
            output.buffer, output.size, 0, makeSelfSignedCert, devId);
    }
#endif
    if (rc >= 0) {
        output.size = rc;
        printf("Generated/Signed Cert (PEM %d)\n", output.size);
    #if !defined(NO_FILESYSTEM) && !defined(NO_WRITE_TEMP_FILES)
        FILE* pemFile = fopen(outputPemFile, "wb");
        if (pemFile) {
            rc = (int)fwrite(output.buffer, 1, output.size, pemFile);
            fclose(pemFile);
            rc = (rc == output.size) ? 0 : -1;
            if (rc == 0) {
                printf("Saved to %s\n", outputPemFile);
            }
        }
    #endif
        printf("%s\n", (char*)output.buffer);
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
    if (rc == 0) {
        /* See if primary storage key already exists */
        rc = getPrimaryStoragekey(&dev, &storageKey, TPM_ALG_RSA);
    }

#ifndef NO_RSA
    if (rc == 0) {
        tpmCtx.rsaKey = &key; /* Setup the wolf crypto device callback */
        rc = wolfTPM2_GetKeyTemplate_RSA(&publicTemplate,
                    TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
                    TPMA_OBJECT_decrypt | TPMA_OBJECT_sign | TPMA_OBJECT_noDA);
        if (rc == 0) {
            rc = getRSAkey(&dev, &storageKey, &key, NULL, tpmDevId,
                (byte*)gKeyAuth, sizeof(gKeyAuth)-1, &publicTemplate);
        }
        if (rc == 0) {
            rc = TPM2_CSR_Generate(&dev, RSA_TYPE, &key,
                makeSelfSignedCert ? gClientCertRsaFile : gClientCsrRsaFile,
                makeSelfSignedCert, tpmDevId);
        }
        wolfTPM2_UnloadHandle(&dev, &key.handle);
    }
#endif /* !NO_RSA */

#ifdef HAVE_ECC
    if (rc == 0) {
        tpmCtx.eccKey = &key;
        rc = wolfTPM2_GetKeyTemplate_ECC(&publicTemplate,
                TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
                TPMA_OBJECT_sign | TPMA_OBJECT_noDA,
                TPM_ECC_NIST_P256, TPM_ALG_ECDSA);
        if (rc == 0) {
            rc = getECCkey(&dev, &storageKey, &key, NULL, tpmDevId,
                  (byte*)gKeyAuth, sizeof(gKeyAuth)-1, &publicTemplate);
        }
        if (rc == 0) {
            rc = TPM2_CSR_Generate(&dev, ECC_TYPE, &key,
                makeSelfSignedCert ? gClientCertEccFile : gClientCsrEccFile,
                makeSelfSignedCert, tpmDevId);
        }
        wolfTPM2_UnloadHandle(&dev, &key.handle);
    }
#endif /* HAVE_ECC */

    if (rc != 0) {
        printf("Failure 0x%x: %s\n", rc, wolfTPM2_GetRCString(rc));
    }

    wolfTPM2_UnloadHandle(&dev, &storageKey.handle);
    wolfTPM2_Cleanup(&dev);

    return rc;
}

/******************************************************************************/
/* --- END TPM2 CSR Example -- */
/******************************************************************************/

#endif /* !WOLFTPM2_NO_WRAPPER && WOLFTPM2_CERT_GEN */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = -1;

#if !defined(WOLFTPM2_NO_WRAPPER) && defined(WOLFTPM2_CERT_GEN)
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
