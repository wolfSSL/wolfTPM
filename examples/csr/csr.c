/* csr.c
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

#if !defined(WOLFTPM2_NO_WRAPPER) && defined(WOLFSSL_CERT_REQ) && \
     defined(WOLF_CRYPTO_DEV)

#include <examples/tpm_io.h>
#include <examples/csr/csr.h>
#include <wolfssl/wolfcrypt/asn_public.h>

/******************************************************************************/
/* --- BEGIN TPM2 CSR Example -- */
/******************************************************************************/

int TPM2_CSR_Example(void* userCtx)
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY storageKey;
    WOLFTPM2_KEY rsaKey;
    RsaKey wolfRsaKey;
    TPMT_PUBLIC publicTemplate;
    TpmCryptoDevCtx tpmCtx;
    Cert req;
    const CertName myCertName = {
        "US",               CTC_PRINTABLE,  /* country */
        "Orgeon",           CTC_UTF8,       /* state */
        "Portland",         CTC_UTF8,       /* locality */
        "Test",             CTC_UTF8,       /* sur */
        "wolfSSL",          CTC_UTF8,       /* org */
        "Development",      CTC_UTF8,       /* unit */
        "www.wolfssl.com",  CTC_UTF8,       /* commonName */
        "info@wolfssl.com"                  /* email */
    };
    WOLFTPM2_BUFFER der;
    WOLFTPM2_BUFFER output;
    int tpmDevId;

    XMEMSET(&wolfRsaKey, 0, sizeof(wolfRsaKey));

    printf("TPM2 CSR Example\n");

    /* Init the TPM2 device */
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != 0) return rc;

    /* Setup the wolf crypto device callback */
    tpmCtx.rsaKey = &rsaKey;
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

    /* Create/Load RSA key for TLS authentication */
    rc = wolfTPM2_ReadPublicKey(&dev, &rsaKey, TPM2_DEMO_KEY_HANDLE);
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
            TPM2_DEMO_KEY_HANDLE);
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


    /* Generate CSR (using TPM key) for certification authority */
    rc = wc_InitCert(&req);
    if (rc != 0) goto exit;

    XMEMCPY(&req.subject, &myCertName, sizeof(myCertName));
    req.sigType = CTC_SHA256wRSA;

#ifdef WOLFSSL_CERT_EXT
    /* add SKID from the Public Key */
    rc = wc_SetSubjectKeyIdFromPublicKey_ex(&req, RSA_TYPE, &wolfRsaKey);
    if (rc != 0) goto exit;

    /* add Extended Key Usage */
    rc = wc_SetExtKeyUsage(&req, "serverAuth,clientAuth,codeSigning,"
                                 "emailProtection,timeStamping,OCSPSigning");
    if (rc != 0) goto exit;
#endif

    rc = wc_MakeCertReq_ex(&req, der.buffer, sizeof(der.buffer), RSA_TYPE, &wolfRsaKey);
    if (rc <= 0) goto exit;
    der.size = rc;

    rc = wc_SignCert_ex(req.bodySz, req.sigType, der.buffer, sizeof(der.buffer), RSA_TYPE,
        &wolfRsaKey, wolfTPM2_GetRng(&dev));
    if (rc <= 0) goto exit;
    der.size = rc;

    /* Convert to PEM */
    rc = wc_DerToPem(der.buffer, der.size, output.buffer, sizeof(output.buffer), CERTREQ_TYPE);
    if (rc <= 0) goto exit;
    output.size = rc;

    printf("Generated/Signed Cert (DER %d, PEM %d)\n", der.size, output.size);
    printf("%s\n", (char*)output.buffer);

    rc = 0; /* report success */

exit:

    if (rc != 0) {
        printf("Failure 0x%x: %s\n", rc, wolfTPM2_GetRCString(rc));
    }

    wc_FreeRsaKey(&wolfRsaKey);
    wolfTPM2_UnloadHandle(&dev, &rsaKey.handle);

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

#if !defined(WOLFTPM2_NO_WRAPPER) && defined(WOLFSSL_CERT_REQ) && \
     defined(WOLF_CRYPTO_DEV)
    rc = TPM2_CSR_Example(TPM2_IoGetUserCtx());
#else
    printf("Wrapper/CertReq/CryptoDev code not compiled in\n");
#endif

    return rc;
}
#endif /* !NO_MAIN_DRIVER */
