/* wrap_test.c
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

/* This example shows using the TPM2 wrapper API's in TPM2_Wrapper_Test() below. */

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_wrap.h>

#ifndef WOLFTPM2_NO_WRAPPER

#include <examples/tpm_io.h>
#include <examples/wrap/wrap_test.h>

/* Configuration */
#define TPM2_DEMO_NV_TEST_INDEX                 0x01800200
#define TPM2_DEMO_NV_TEST_SIZE                  1024 /* max size on Infineon SLB9670 is 1664 */

#ifndef WOLFTPM2_NO_WOLFCRYPT
/* from wolfSSL ./certs/client-keyPub.der */
static const byte kRsaPubKeyRaw[] = {
    0x30, 0x82, 0x01, 0x22, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86,
    0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03,
    0x82, 0x01, 0x0F, 0x00, 0x30, 0x82, 0x01, 0x0A, 0x02, 0x82,
    0x01, 0x01, 0x00, 0xC3, 0x03, 0xD1, 0x2B, 0xFE, 0x39, 0xA4,
    0x32, 0x45, 0x3B, 0x53, 0xC8, 0x84, 0x2B, 0x2A, 0x7C, 0x74,
    0x9A, 0xBD, 0xAA, 0x2A, 0x52, 0x07, 0x47, 0xD6, 0xA6, 0x36,
    0xB2, 0x07, 0x32, 0x8E, 0xD0, 0xBA, 0x69, 0x7B, 0xC6, 0xC3,
    0x44, 0x9E, 0xD4, 0x81, 0x48, 0xFD, 0x2D, 0x68, 0xA2, 0x8B,
    0x67, 0xBB, 0xA1, 0x75, 0xC8, 0x36, 0x2C, 0x4A, 0xD2, 0x1B,
    0xF7, 0x8B, 0xBA, 0xCF, 0x0D, 0xF9, 0xEF, 0xEC, 0xF1, 0x81,
    0x1E, 0x7B, 0x9B, 0x03, 0x47, 0x9A, 0xBF, 0x65, 0xCC, 0x7F,
    0x65, 0x24, 0x69, 0xA6, 0xE8, 0x14, 0x89, 0x5B, 0xE4, 0x34,
    0xF7, 0xC5, 0xB0, 0x14, 0x93, 0xF5, 0x67, 0x7B, 0x3A, 0x7A,
    0x78, 0xE1, 0x01, 0x56, 0x56, 0x91, 0xA6, 0x13, 0x42, 0x8D,
    0xD2, 0x3C, 0x40, 0x9C, 0x4C, 0xEF, 0xD1, 0x86, 0xDF, 0x37,
    0x51, 0x1B, 0x0C, 0xA1, 0x3B, 0xF5, 0xF1, 0xA3, 0x4A, 0x35,
    0xE4, 0xE1, 0xCE, 0x96, 0xDF, 0x1B, 0x7E, 0xBF, 0x4E, 0x97,
    0xD0, 0x10, 0xE8, 0xA8, 0x08, 0x30, 0x81, 0xAF, 0x20, 0x0B,
    0x43, 0x14, 0xC5, 0x74, 0x67, 0xB4, 0x32, 0x82, 0x6F, 0x8D,
    0x86, 0xC2, 0x88, 0x40, 0x99, 0x36, 0x83, 0xBA, 0x1E, 0x40,
    0x72, 0x22, 0x17, 0xD7, 0x52, 0x65, 0x24, 0x73, 0xB0, 0xCE,
    0xEF, 0x19, 0xCD, 0xAE, 0xFF, 0x78, 0x6C, 0x7B, 0xC0, 0x12,
    0x03, 0xD4, 0x4E, 0x72, 0x0D, 0x50, 0x6D, 0x3B, 0xA3, 0x3B,
    0xA3, 0x99, 0x5E, 0x9D, 0xC8, 0xD9, 0x0C, 0x85, 0xB3, 0xD9,
    0x8A, 0xD9, 0x54, 0x26, 0xDB, 0x6D, 0xFA, 0xAC, 0xBB, 0xFF,
    0x25, 0x4C, 0xC4, 0xD1, 0x79, 0xF4, 0x71, 0xD3, 0x86, 0x40,
    0x18, 0x13, 0xB0, 0x63, 0xB5, 0x72, 0x4E, 0x30, 0xC4, 0x97,
    0x84, 0x86, 0x2D, 0x56, 0x2F, 0xD7, 0x15, 0xF7, 0x7F, 0xC0,
    0xAE, 0xF5, 0xFC, 0x5B, 0xE5, 0xFB, 0xA1, 0xBA, 0xD3, 0x02,
    0x03, 0x01, 0x00, 0x01
};

/* from wolfSSL ./certs/ecc-client-keyPub.der */
static const byte kEccPubKeyXRaw[] = {
    0x55, 0xBF, 0xF4, 0x0F, 0x44, 0x50, 0x9A, 0x3D, 0xCE, 0x9B,
    0xB7, 0xF0, 0xC5, 0x4D, 0xF5, 0x70, 0x7B, 0xD4, 0xEC, 0x24,
    0x8E, 0x19, 0x80, 0xEC, 0x5A, 0x4C, 0xA2, 0x24, 0x03, 0x62,
    0x2C, 0x9B
};
static const byte kEccPubKeyYRaw[] = {
    0xDA, 0xEF, 0xA2, 0x35, 0x12, 0x43, 0x84, 0x76, 0x16, 0xC6,
    0x56, 0x95, 0x06, 0xCC, 0x01, 0xA9, 0xBD, 0xF6, 0x75, 0x1A,
    0x42, 0xF7, 0xBD, 0xA9, 0xB2, 0x36, 0x22, 0x5F, 0xC7, 0x5D,
    0x7F, 0xB4
};
#endif /* !WOLFTPM2_NO_WOLFCRYPT */

/******************************************************************************/
/* --- BEGIN Wrapper API Tests -- */
/******************************************************************************/

static int resetTPM = 0;

void TPM2_Wrapper_SetReset(int reset)
{
    resetTPM = reset;
}

int TPM2_Wrapper_Test(void* userCtx)
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY ekKey;
    WOLFTPM2_KEY storageKey;
    WOLFTPM2_KEY rsaKey;
    WOLFTPM2_KEY eccKey;
    WOLFTPM2_BUFFER message;
    WOLFTPM2_BUFFER cipher;
    WOLFTPM2_BUFFER plain;
    TPMT_PUBLIC publicTemplate;
    TPM2B_ECC_POINT pubPoint;
    word32 nvAttributes = 0;
#ifdef WOLF_CRYPTO_DEV
    TpmCryptoDevCtx tpmCtx;
#endif

#ifndef WOLFTPM2_NO_WOLFCRYPT
    WOLFTPM2_KEY publicKey;
    int tpmDevId = INVALID_DEVID;
#ifndef NO_RSA
    word32 idx = 0;
    RsaKey wolfRsaPubKey;
    RsaKey wolfRsaPrivKey;
#endif
#ifdef HAVE_ECC
    ecc_key wolfEccPubKey;
    ecc_key wolfEccPrivKey;
#endif

#ifndef NO_RSA
    XMEMSET(&wolfRsaPubKey, 0, sizeof(wolfRsaPubKey));
    XMEMSET(&wolfRsaPrivKey, 0, sizeof(wolfRsaPrivKey));
#endif
#ifdef HAVE_ECC
    XMEMSET(&wolfEccPubKey, 0, sizeof(wolfEccPubKey));
    XMEMSET(&wolfEccPrivKey, 0, sizeof(wolfEccPrivKey));
#endif
#endif /* !WOLFTPM2_NO_WOLFCRYPT */

    printf("TPM2 Demo for Wrapper API's\n");


    /* Init the TPM2 device */
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != 0) return rc;

#ifdef WOLF_CRYPTO_DEV
    /* Setup the wolf crypto device callback */
    tpmCtx.rsaKey = &rsaKey;
    tpmCtx.eccKey = &eccKey;
    rc = wolfTPM2_SetCryptoDevCb(&dev, wolfTPM2_CryptoDevCb, &tpmCtx, &tpmDevId);
    if (rc != 0) goto exit;
#endif

    if (resetTPM) {
        /* reset all content on TPM and reseed */
        rc = wolfTPM2_Clear(&dev);
        if (rc != 0) return rc;
    }

    /* Get the RSA endorsement key (EK) */
    rc = wolfTPM2_GetKeyTemplate_RSA_EK(&publicTemplate);
    if (rc != 0) goto exit;
    rc = wolfTPM2_CreatePrimaryKey(&dev, &ekKey, TPM_RH_ENDORSEMENT,
        &publicTemplate, NULL, 0);
    if (rc != 0) goto exit;
    wolfTPM2_UnloadHandle(&dev, &ekKey.handle);

    /* Get the ECC endorsement key (EK) */
    rc = wolfTPM2_GetKeyTemplate_ECC_EK(&publicTemplate);
    if (rc != 0) goto exit;
    rc = wolfTPM2_CreatePrimaryKey(&dev, &ekKey, TPM_RH_ENDORSEMENT,
        &publicTemplate, NULL, 0);
    if (rc != 0) goto exit;
    wolfTPM2_UnloadHandle(&dev, &ekKey.handle);

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

    /* Create RSA key for encrypt/decrypt */
    rc = wolfTPM2_GetKeyTemplate_RSA(&publicTemplate,
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_decrypt | TPMA_OBJECT_sign | TPMA_OBJECT_noDA);
    if (rc != 0) goto exit;
    rc = wolfTPM2_CreateAndLoadKey(&dev, &rsaKey, &storageKey.handle,
        &publicTemplate, (byte*)gKeyAuth, sizeof(gKeyAuth)-1);
    if (rc != 0) goto exit;


    /* Perform RSA encrypt / decrypt (no pad) */
    message.size = 256; /* test message 0x11,0x11,etc */
    XMEMSET(message.buffer, 0x11, message.size);
    cipher.size = sizeof(cipher.buffer); /* encrypted data */
    rc = wolfTPM2_RsaEncrypt(&dev, &rsaKey, TPM_ALG_NULL,
        message.buffer, message.size, cipher.buffer, &cipher.size);
    if (rc != 0) goto exit;
    plain.size = sizeof(plain.buffer);
    rc = wolfTPM2_RsaDecrypt(&dev, &rsaKey, TPM_ALG_NULL,
        cipher.buffer, cipher.size, plain.buffer, &plain.size);
    if (rc != 0) goto exit;
    /* Validate encrypt / decrypt */
    if (message.size != plain.size ||
                    XMEMCMP(message.buffer, plain.buffer, message.size) != 0) {
        rc = TPM_RC_TESTING; goto exit;
    }
    printf("RSA Encrypt/Decrypt Test Passed\n");

    /* Perform RSA encrypt / decrypt (OAEP pad) */
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
    /* Validate encrypt / decrypt */
    if (message.size != plain.size ||
                    XMEMCMP(message.buffer, plain.buffer, message.size) != 0) {
        rc = TPM_RC_TESTING; goto exit;
    }
    printf("RSA Encrypt/Decrypt OAEP Test Passed\n");


#ifndef WOLFTPM2_NO_WOLFCRYPT
#ifndef NO_RSA
    /* Demonstrate loading wolf keys */
    /* setup wolf RSA key with TPM deviceID */
    /* crypto dev callbacks are used for private portion */
    rc = wc_InitRsaKey_ex(&wolfRsaPrivKey, NULL, tpmDevId);
    if (rc != 0) goto exit;

    /* load public portion of key into wolf RSA Key */
    rc = wolfTPM2_RsaKey_TpmToWolf(&dev, &rsaKey, &wolfRsaPrivKey);
    if (rc != 0) goto exit;

    /* load public key into wolf RsaKey structure */
    rc = wc_InitRsaKey(&wolfRsaPubKey, NULL);
    if (rc != 0) goto exit;
    rc = wc_RsaPublicKeyDecode(kRsaPubKeyRaw, &idx,
        &wolfRsaPubKey, (word32)sizeof(kRsaPubKeyRaw));
    if (rc != 0) goto exit;

    /* export the raw public RSA portion to TPM key */
    rc = wolfTPM2_RsaKey_WolfToTpm(&dev, &wolfRsaPubKey, &publicKey);
    if (rc != 0) goto exit;

    rc = wolfTPM2_UnloadHandle(&dev, &publicKey.handle);
    if (rc != 0) goto exit;
#endif /* NO_RSA */
#endif /* !WOLFTPM2_NO_WOLFCRYPT */
    rc = wolfTPM2_UnloadHandle(&dev, &rsaKey.handle);
    if (rc != 0) goto exit;


    /* Create an ECC key for ECDSA */
    rc = wolfTPM2_GetKeyTemplate_ECC(&publicTemplate,
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_sign | TPMA_OBJECT_noDA,
        TPM_ECC_NIST_P256, TPM_ALG_ECDSA);
    if (rc != 0) goto exit;
    rc = wolfTPM2_CreateAndLoadKey(&dev, &eccKey, &storageKey.handle,
        &publicTemplate, (byte*)gKeyAuth, sizeof(gKeyAuth)-1);
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
        &publicTemplate, (byte*)gKeyAuth, sizeof(gKeyAuth)-1);
    if (rc != 0) goto exit;

    /* Create ephemeral ECC key and generate a shared secret */
    cipher.size = sizeof(cipher.buffer);
    rc = wolfTPM2_ECDHGen(&dev, &eccKey, &pubPoint,
        cipher.buffer, &cipher.size);
    if (rc != 0) goto exit;

    printf("ECC DH Generation Passed\n");


#if !defined(WOLFTPM2_NO_WOLFCRYPT)
#ifdef HAVE_ECC
    /* Demonstrate loading wolf keys */

    /* Load an ECC public key from TPM */
    /* setup wolf ECC key with TPM deviceID, so crypto callbacks
       are used for private op */
    rc = wc_ecc_init_ex(&wolfEccPrivKey, NULL, tpmDevId);
    if (rc != 0) goto exit;
    /* load public portion of key into wolf ECC Key */
    rc = wolfTPM2_EccKey_TpmToWolf(&dev, &eccKey, &wolfEccPrivKey);
    if (rc != 0) goto exit;

    /* Load an ECC public key into TPM */
    rc = wc_ecc_init(&wolfEccPubKey);
    if (rc != 0) goto exit;
    /* load public key portion into wolf ecc_key */
    rc = wc_ecc_import_unsigned(&wolfEccPubKey, (byte*)kEccPubKeyXRaw,
        (byte*)kEccPubKeyYRaw, NULL, ECC_SECP256R1);
    if (rc != 0) goto exit;

    /* export the raw public ECC portion to TPM key */
    rc = wolfTPM2_EccKey_WolfToTpm(&dev, &wolfEccPubKey, &publicKey);
    if (rc != 0) goto exit;

    rc = wolfTPM2_UnloadHandle(&dev, &publicKey.handle);
    if (rc != 0) goto exit;
#endif /* HAVE_ECC */
#endif /* !WOLFTPM2_NO_WOLFCRYPT */

    rc = wolfTPM2_UnloadHandle(&dev, &eccKey.handle);
    if (rc != 0) goto exit;


    /* NV Tests */
    rc = wolfTPM2_GetNvAttributesTemplate(TPM_RH_OWNER, &nvAttributes);
    if (rc != 0) goto exit;
    rc = wolfTPM2_NVCreate(&dev, TPM_RH_OWNER, TPM2_DEMO_NV_TEST_INDEX,
        nvAttributes, TPM2_DEMO_NV_TEST_SIZE, NULL, 0);
    if (rc != 0 && rc != TPM_RC_NV_DEFINED) goto exit;

    message.size = TPM2_DEMO_NV_TEST_SIZE; /* test message 0x11,0x11,etc */
    XMEMSET(message.buffer, 0x11, message.size);
    rc = wolfTPM2_NVWrite(&dev, TPM_RH_OWNER, TPM2_DEMO_NV_TEST_INDEX,
        message.buffer, message.size, 0);
    if (rc != 0) goto exit;

    plain.size = TPM2_DEMO_NV_TEST_SIZE;
    rc = wolfTPM2_NVRead(&dev, TPM_RH_OWNER, TPM2_DEMO_NV_TEST_INDEX,
        plain.buffer, (word32*)&plain.size, 0);
    if (rc != 0) goto exit;

    rc = wolfTPM2_NVReadPublic(&dev, TPM2_DEMO_NV_TEST_INDEX, NULL);
    if (rc != 0) goto exit;

    rc = wolfTPM2_NVDelete(&dev, TPM_RH_OWNER, TPM2_DEMO_NV_TEST_INDEX);
    if (rc != 0) goto exit;

    if (message.size != plain.size ||
                XMEMCMP(message.buffer, plain.buffer, message.size) != 0) {
        rc = TPM_RC_TESTING; goto exit;
    }

    printf("NV Test on index 0x%x with %d bytes passed\n",
        TPM2_DEMO_NV_TEST_INDEX, TPM2_DEMO_NV_TEST_SIZE);

exit:

    if (rc != 0) {
        printf("Failure 0x%x: %s\n", rc, wolfTPM2_GetRCString(rc));
    }

#ifndef WOLFTPM2_NO_WOLFCRYPT
#ifndef NO_RSA
    wc_FreeRsaKey(&wolfRsaPubKey);
    wc_FreeRsaKey(&wolfRsaPrivKey);
#endif
#ifdef HAVE_ECC
    wc_ecc_free(&wolfEccPubKey);
    wc_ecc_free(&wolfEccPrivKey);
#endif
#endif /* !WOLFTPM2_NO_WOLFCRYPT */

    wolfTPM2_UnloadHandle(&dev, &rsaKey.handle);
    wolfTPM2_UnloadHandle(&dev, &eccKey.handle);
    wolfTPM2_UnloadHandle(&dev, &ekKey.handle);

    wolfTPM2_Cleanup(&dev);

    return rc;
}

/******************************************************************************/
/* --- END Wrapper API Tests -- */
/******************************************************************************/

#endif /* !WOLFTPM2_NO_WRAPPER */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = -1;

    if (argc > 1) {
        TPM2_Wrapper_SetReset(1);
    }
    (void)argv;

#ifndef WOLFTPM2_NO_WRAPPER
    rc = TPM2_Wrapper_Test(NULL);
#else
    printf("Wrapper code not compiled in\n");
#endif

    return rc;
}
#endif /* !NO_MAIN_DRIVER */
