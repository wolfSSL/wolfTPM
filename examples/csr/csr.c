/* csr.c
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


#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_wrap.h>

#if !defined(WOLFTPM2_NO_WRAPPER) && !defined(WOLFTPM2_NO_WOLFCRYPT) && \
	defined(WOLFSSL_CERT_REQ) && \
	(defined(WOLF_CRYPTO_DEV) || defined(WOLF_CRYPTO_CB))

#include <examples/tpm_io.h>
#include <examples/tpm_test.h>
#include <examples/csr/csr.h>
#include <wolfssl/wolfcrypt/asn_public.h>

#include <stdio.h>

#ifndef NO_RSA
static const char* gClientCertRsaFile = "./certs/tpm-rsa-cert.csr";
#endif
#ifdef HAVE_ECC
static const char* gClientCertEccFile = "./certs/tpm-ecc-cert.csr";
#endif

/******************************************************************************/
/* --- BEGIN TPM2 CSR Example -- */
/******************************************************************************/

static int TPM2_CSR_Generate(WOLFTPM2_DEV* dev, int key_type, void* wolfKey,
    const char* outputPemFile)
{
    int rc;
    Cert req;
    const CertName myCertName = {
        .country = "US",        .countryEnc = CTC_PRINTABLE, /* country */
        .state = "Oregon",      .stateEnc = CTC_UTF8,        /* state */
        .locality = "Portland", .localityEnc = CTC_UTF8,     /* locality */
        .sur = "Test",          .surEnc = CTC_UTF8,          /* sur */
        .org = "wolfSSL",       .orgEnc = CTC_UTF8,          /* org */
        .unit = "Development",  .unitEnc = CTC_UTF8,         /* unit */
        .commonName = "www.wolfssl.com",                     /* commonName */
        .commonNameEnc = CTC_UTF8,
        .email = "info@wolfssl.com"                          /* email */
    };
    const char* myKeyUsage = "serverAuth,clientAuth,codeSigning,"
                             "emailProtection,timeStamping,OCSPSigning";
    WOLFTPM2_BUFFER der;
#ifdef WOLFSSL_DER_TO_PEM
    WOLFTPM2_BUFFER output;
#endif

    /* Generate CSR (using TPM key) for certification authority */
    rc = wc_InitCert(&req);
    if (rc != 0) goto exit;

    XMEMCPY(&req.subject, &myCertName, sizeof(myCertName));

    /* make sure each common name is unique */
    if (key_type == RSA_TYPE) {
        req.sigType = CTC_SHA256wRSA;
        XSTRNCPY(req.subject.unit, "RSA", sizeof(req.subject.unit));
    }
    else if (key_type == ECC_TYPE) {
        req.sigType = CTC_SHA256wECDSA;
        XSTRNCPY(req.subject.unit, "ECC", sizeof(req.subject.unit));
    }

#ifdef WOLFSSL_CERT_EXT
    /* add SKID from the Public Key */
    rc = wc_SetSubjectKeyIdFromPublicKey_ex(&req, key_type, wolfKey);
    if (rc != 0) goto exit;

    /* add Extended Key Usage */
    rc = wc_SetExtKeyUsage(&req, myKeyUsage);
    if (rc != 0) goto exit;
#endif

    rc = wc_MakeCertReq_ex(&req, der.buffer, sizeof(der.buffer), key_type,
        wolfKey);
    if (rc <= 0) goto exit;
    der.size = rc;

    rc = wc_SignCert_ex(req.bodySz, req.sigType, der.buffer, sizeof(der.buffer),
        key_type, wolfKey, wolfTPM2_GetRng(dev));
    if (rc <= 0) goto exit;
    der.size = rc;

#ifdef WOLFSSL_DER_TO_PEM
    /* Convert to PEM */
    XMEMSET(output.buffer, 0, sizeof(output.buffer));
    rc = wc_DerToPem(der.buffer, der.size, output.buffer, sizeof(output.buffer),
        CERTREQ_TYPE);
    if (rc <= 0) goto exit;
    output.size = rc;

    printf("Generated/Signed Cert (DER %d, PEM %d)\n", der.size, output.size);
    printf("%s\n", (char*)output.buffer);

#if !defined(NO_FILESYSTEM) && !defined(NO_WRITE_TEMP_FILES)
    {
        FILE* pemFile = fopen(outputPemFile, "wb");
        if (pemFile) {
            rc = (int)fwrite(output.buffer, 1, output.size, pemFile);
            fclose(pemFile);
            if (rc != output.size) {
                rc = -1; goto exit;
            }
        }
    }
#endif
#endif /* WOLFSSL_DER_TO_PEM */
    (void)outputPemFile;

    rc = 0; /* success */

exit:
    return rc;
}

int TPM2_CSR_Example(void* userCtx)
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
    int tpmDevId;

    printf("TPM2 CSR Example\n");

    /* Init the TPM2 device */
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != 0) return rc;

    /* Setup the wolf crypto device callback */
    XMEMSET(&tpmCtx, 0, sizeof(tpmCtx));
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
    /* Create/Load RSA key for CSR */
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
        /* specify auth password for RSA key */
        rsaKey.handle.auth.size = sizeof(gKeyAuth)-1;
        XMEMCPY(rsaKey.handle.auth.buffer, gKeyAuth, rsaKey.handle.auth.size);
    }

    /* setup wolf RSA key with TPM deviceID, so crypto callbacks are used */
    rc = wc_InitRsaKey_ex(&wolfRsaKey, NULL, tpmDevId);
    if (rc != 0) goto exit;
    /* load public portion of key into wolf RSA Key */
    rc = wolfTPM2_RsaKey_TpmToWolf(&dev, &rsaKey, &wolfRsaKey);
    if (rc != 0) goto exit;

    rc = TPM2_CSR_Generate(&dev, RSA_TYPE, &wolfRsaKey, gClientCertRsaFile);
    if (rc != 0) goto exit;
#endif /* !NO_RSA */


#ifdef HAVE_ECC
    /* Create/Load ECC key for CSR */
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

    rc = TPM2_CSR_Generate(&dev, ECC_TYPE, &wolfEccKey, gClientCertEccFile);
    if (rc != 0) goto exit;
#endif /* HAVE_ECC */

exit:

    if (rc != 0) {
        printf("Failure 0x%x: %s\n", rc, wolfTPM2_GetRCString(rc));
    }

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
/* --- END TPM2 CSR Example -- */
/******************************************************************************/

#endif /* !WOLFTPM2_NO_WRAPPER && WOLFSSL_CERT_REQ && WOLF_CRYPTO_DEV */

#ifndef NO_MAIN_DRIVER
int main(void)
{
    int rc = -1;

#if !defined(WOLFTPM2_NO_WRAPPER) && !defined(WOLFTPM2_NO_WOLFCRYPT) && \
    defined(WOLFSSL_CERT_REQ) && \
    (defined(WOLF_CRYPTO_DEV) || defined(WOLF_CRYPTO_CB))
    rc = TPM2_CSR_Example(NULL);
#else
    printf("Wrapper/CertReq/CryptoDev code not compiled in\n");
    printf("Build wolfssl with ./configure --enable-certgen --enable-certreq --enable-certext --enable-cryptodev\n");
#endif

    return rc;
}
#endif /* !NO_MAIN_DRIVER */
