/* wrap_test.c
 *
 * Copyright (C) 2006-2018 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
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

/* This example shows using the TPM2 wrapper API's in TPM2_Wrapper_Test() below. */

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_wrap.h>

#ifndef WOLFTPM2_NO_WRAPPER

#include <examples/tpm_io.h>
#include <examples/wrap/wrap_test.h>

/* Configuration */
#define TPM2_DEMO_PERSISTENT_STORAGE_KEY_HANDLE 0x81000200
//#define WOLFTPM_TEST_WITH_RESET


/******************************************************************************/
/* --- BEGIN Wrapper API Tests -- */
/******************************************************************************/

int TPM2_Wrapper_Test(void* userCtx)
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY storageKey;
    WOLFTPM2_KEY rsaKey;
    WOLFTPM2_KEY eccKey;
    WOLFTPM2_BUFFER message;
    WOLFTPM2_BUFFER cipher;
    WOLFTPM2_BUFFER plain;
    TPMT_PUBLIC publicTemplate;
    TPM2B_ECC_POINT pubPoint;
    const char storageKeyAuth[] = "ThisIsMyStorageKeyAuth";
    const char keyAuth[] = "ThisIsMyKeyAuth";

    printf("TPM2 Demo for Wrapper API's\n");


    /* Init the TPM2 device */
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != 0) return rc;

#ifdef WOLFTPM_TEST_WITH_RESET
    /* reset all content on TPM and reseed */
    rc = wolfTPM2_Clear(&dev);
    if (rc != 0) return rc;
#endif

    /* See if primary storage key already exists */
    rc = wolfTPM2_ReadPublicKey(&dev, &storageKey,
        TPM2_DEMO_PERSISTENT_STORAGE_KEY_HANDLE);
    if (rc != 0) {
        /* Create primary storage key */
        rc = wolfTPM2_GetKeyTemplate_RSA(&publicTemplate,
            TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent |
            TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
            TPMA_OBJECT_restricted | TPMA_OBJECT_decrypt | TPMA_OBJECT_noDA);
        if (rc != 0) goto exit;
        rc = wolfTPM2_CreatePrimaryKey(&dev, &storageKey, TPM_RH_OWNER,
            &publicTemplate, (byte*)storageKeyAuth, sizeof(storageKeyAuth)-1);
        if (rc != 0) goto exit;

        /* Move this key into peristent storage */
        rc = wolfTPM2_NVStoreKey(&dev, TPM_RH_OWNER, &storageKey,
            TPM2_DEMO_PERSISTENT_STORAGE_KEY_HANDLE);
        if (rc != 0) goto exit;
    }
    else {
        /* specify auth password for storage key */
        storageKey.handle.auth.size = sizeof(storageKeyAuth)-1;
        XMEMCPY(storageKey.handle.auth.buffer, storageKeyAuth,
            storageKey.handle.auth.size);
    }

    /* Create RSA key for encrypt/decrypt */
    rc = wolfTPM2_GetKeyTemplate_RSA(&publicTemplate,
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_decrypt | TPMA_OBJECT_sign | TPMA_OBJECT_noDA);
    if (rc != 0) goto exit;
    rc = wolfTPM2_CreateAndLoadKey(&dev, &rsaKey, &storageKey.handle,
        &publicTemplate, (byte*)keyAuth, sizeof(keyAuth)-1);
    if (rc != 0) goto exit;

    /* Perform RSA encrypt / decrypt */
    message.size = WC_SHA256_DIGEST_SIZE; /* test message 0x11,0x11,etc */
    XMEMSET(message.buffer, 0x11, message.size);
    cipher.size = sizeof(cipher.buffer); /* encrypted data */
    rc = wolfTPM2_RsaEncrypt(&dev, &rsaKey, TPM_ALG_OAEP,
        message.buffer, message.size, cipher.buffer, &cipher.size);
    if (rc != 0) goto exit;

    plain.size = sizeof(plain.buffer);
    rc = wolfTPM2_RsaDecrypt(&dev, &rsaKey, TPM_ALG_OAEP,
        cipher.buffer, cipher.size, plain.buffer, &plain.size);
    if (rc != 0) goto exit;

    rc = wolfTPM2_UnloadHandle(&dev, &rsaKey.handle);
    if (rc != 0) goto exit;

    /* Validate encrypt / decrypt */
    if (message.size != plain.size ||
                    XMEMCMP(message.buffer, plain.buffer, message.size) != 0) {
        rc = TPM_RC_TESTING; goto exit;
    }
    printf("RSA Encrypt Test Passed\n");


    /* Create an ECC key for ECDSA */
    rc = wolfTPM2_GetKeyTemplate_ECC(&publicTemplate,
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_sign | TPMA_OBJECT_noDA,
        TPM_ECC_NIST_P256, TPM_ALG_ECDSA);
    if (rc != 0) goto exit;
    rc = wolfTPM2_CreateAndLoadKey(&dev, &eccKey, &storageKey.handle,
        &publicTemplate, (byte*)keyAuth, sizeof(keyAuth)-1);
    if (rc != 0) goto exit;

    /* Perform sign / verify */
    message.size = WC_SHA256_DIGEST_SIZE; /* test message 0x11,0x11,etc */
    XMEMSET(message.buffer, 0x11, message.size);
    cipher.size = sizeof(cipher.buffer); /* signature */
    rc = wolfTPM2_SignHash(&dev, &eccKey, message.buffer, message.size,
        cipher.buffer, &cipher.size);
    if (rc != 0) goto exit;

    rc = wolfTPM2_VerifyHash(&dev, &eccKey, cipher.buffer, cipher.size,
        message.buffer, message.size);
    if (rc != 0) goto exit;

    rc = wolfTPM2_UnloadHandle(&dev, &eccKey.handle);
    if (rc != 0) goto exit;

    printf("ECC Sign/Verify Passed\n");


    /* Create an ECC key for DH */
    rc = wolfTPM2_GetKeyTemplate_ECC(&publicTemplate,
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_decrypt | TPMA_OBJECT_noDA,
        TPM_ECC_NIST_P256, TPM_ALG_ECDH);
    if (rc != 0) goto exit;
    rc = wolfTPM2_CreateAndLoadKey(&dev, &eccKey, &storageKey.handle,
        &publicTemplate, (byte*)keyAuth, sizeof(keyAuth)-1);
    if (rc != 0) goto exit;

    /* Create ephemeral ECC key and generate a shared secret */
    cipher.size = sizeof(cipher.buffer);
    rc = wolfTPM2_ECDHGen(&dev, &eccKey, &pubPoint,
        cipher.buffer, &cipher.size);
    if (rc != 0) goto exit;

    rc = wolfTPM2_UnloadHandle(&dev, &eccKey.handle);
    if (rc != 0) goto exit;

    printf("ECC DH Generation Passed\n");


exit:

    if (rc != 0) {
        printf("Failure 0x%x: %s\n", rc, wolfTPM2_GetRCString(rc));
    }

    wolfTPM2_UnloadHandle(&dev, &rsaKey.handle);
    wolfTPM2_UnloadHandle(&dev, &eccKey.handle);
#ifdef WOLFTPM_TEST_WITH_RESET
    wolfTPM2_NVDeleteKey(&dev, TPM_RH_OWNER, &storageKey);
#endif
    wolfTPM2_Cleanup(&dev);

    return rc;
}

/******************************************************************************/
/* --- END Wrapper API Tests -- */
/******************************************************************************/

#endif /* !WOLFTPM2_NO_WRAPPER */

#ifndef NO_MAIN_DRIVER
int main(void)
{
    int rc = -1;

#ifndef WOLFTPM2_NO_WRAPPER
    rc = TPM2_Wrapper_Test(TPM2_IoGetUserCtx());
#else
    printf("Wrapper code not compiled in\n");
#endif

    return rc;
}
#endif /* !NO_MAIN_DRIVER */
