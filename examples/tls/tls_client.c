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
     defined(HAVE_PK_CALLBACKS)

#include <examples/tpm_io.h>
#include <examples/tls/tls_client.h>

/******************************************************************************/
/* --- BEGIN TLS Client Example -- */
/******************************************************************************/

int TPM2_TLS_Client(void* userCtx)
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY storageKey;
    WOLFTPM2_KEY rsaKey;
    WOLFTPM2_KEY eccKey;
    RsaKey wolfTlsRsaKey;
    WOLFTPM2_BUFFER cert;
    TPMT_PUBLIC publicTemplate;
    TPMS_NV_PUBLIC nvPublic;
    TpmCryptoDevCtx tpmCtx;
    int tpmDevId;

    XMEMSET(&wolfTlsRsaKey, 0, sizeof(wolfTlsRsaKey));

    printf("TPM2 TLS Client Example\n");

    /* Init the TPM2 device */
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != 0) return rc;

    /* Setup the wolf crypto device callback */
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
    rc = wc_InitRsaKey_ex(&wolfTlsRsaKey, NULL, tpmDevId);
    if (rc != 0) goto exit;
    /* load public portion of key into wolf RSA Key */
    rc = wolfTPM2_RsaKey_TpmToWolf(&dev, &rsaKey, &wolfTlsRsaKey);
    if (rc != 0) goto exit;


    /* Load Certificate from NV */
    rc = wolfTPM2_NVReadPublic(&dev, TPM2_DEMO_CERT_HANDLE, &nvPublic);
    if (rc != 0 && rc != TPM_RC_HANDLE) goto exit;
    if (rc == TPM_RC_HANDLE) {
        /* need to create/load certificate */
        word32 nvAttributes = 0;
        rc = wolfTPM2_GetNvAttributesTemplate(TPM_RH_OWNER, &nvAttributes);
        if (rc != 0) goto exit;
        rc = wolfTPM2_NVCreate(&dev, TPM_RH_OWNER, TPM2_DEMO_CERT_HANDLE,
            nvAttributes, 1024, NULL, 0);
        if (rc != 0 && rc != TPM_RC_NV_DEFINED) goto exit;

        cert.size = 256; /* TODO: Populate with real cert */
        XMEMSET(cert.buffer, 0x11, cert.size);
        rc = wolfTPM2_NVWrite(&dev, TPM_RH_OWNER, TPM2_DEMO_CERT_HANDLE,
            cert.buffer, cert.size, 0);
        if (rc != 0) goto exit;
    }
    else {
        cert.size = nvPublic.dataSize;
        rc = wolfTPM2_NVRead(&dev, TPM_RH_OWNER, TPM2_DEMO_CERT_HANDLE,
            cert.buffer, (word32*)&cert.size, 0);
        if (rc != 0) goto exit;
    }


    /* DO TLS */


exit:

    if (rc != 0) {
        printf("Failure 0x%x: %s\n", rc, wolfTPM2_GetRCString(rc));
    }

    wc_FreeRsaKey(&wolfTlsRsaKey);
    wolfTPM2_UnloadHandle(&dev, &rsaKey.handle);
    wolfTPM2_UnloadHandle(&dev, &eccKey.handle);

    wolfTPM2_Cleanup(&dev);

    return rc;
}

/******************************************************************************/
/* --- END TLS Client Example -- */
/******************************************************************************/

#endif /* !WOLFTPM2_NO_WRAPPER && WOLF_CRYPTO_DEV && HAVE_PK_CALLBACKS */

#ifndef NO_MAIN_DRIVER
int main(void)
{
    int rc = -1;

#if !defined(WOLFTPM2_NO_WRAPPER) && defined(WOLF_CRYPTO_DEV) && \
     defined(HAVE_PK_CALLBACKS)
    rc = TPM2_TLS_Client(TPM2_IoGetUserCtx());
#else
    printf("Wrapper/CryptoDev/PkCb code not compiled in\n");
#endif

    return rc;
}
#endif /* !NO_MAIN_DRIVER */
