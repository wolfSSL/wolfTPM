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
#include <examples/tpm_test.h>

/* Configuration */
#define TPM2_DEMO_NV_TEST_INDEX                 0x01800200
#define TPM2_DEMO_NV_TEST_SIZE                  1024 /* max size on Infineon SLB9670 is 1664 */
#if 0
    #define ENABLE_LARGE_HASH_TEST  /* optional large hash test */
#endif


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
    WOLFTPM2_KEY publicKey;
    WOLFTPM2_BUFFER message;
    WOLFTPM2_BUFFER cipher;
    WOLFTPM2_BUFFER plain;
    TPMT_PUBLIC publicTemplate;
    TPM2B_ECC_POINT pubPoint;
    word32 nvAttributes = 0;
#ifdef WOLF_CRYPTO_DEV
    TpmCryptoDevCtx tpmCtx;
#endif
    WOLFTPM2_HASH hash;
#ifdef ENABLE_LARGE_HASH_TEST
    int i;
    const char* hashTestDig =
        "\x27\x78\x3e\x87\x96\x3a\x4e\xfb\x68\x29\xb5\x31\xc9\xba\x57\xb4"
        "\x4f\x45\x79\x7f\x67\x70\xbd\x63\x7f\xbf\x0d\x80\x7c\xbd\xba\xe0";
#else
    const char* hashTestData =
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    const char* hashTestDig =
        "\x24\x8D\x6A\x61\xD2\x06\x38\xB8\xE5\xC0\x26\x93\x0C\x3E\x60\x39"
        "\xA3\x3C\xE4\x59\x64\xFF\x21\x67\xF6\xEC\xED\xD4\x19\xDB\x06\xC1";
#endif

#ifndef WOLFTPM2_NO_WOLFCRYPT
    int tpmDevId = INVALID_DEVID;
#ifndef NO_RSA
    word32 idx;
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


    /*------------------------------------------------------------------------*/
    /* RSA TESTS */
    /*------------------------------------------------------------------------*/

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
    message.size = TPM_SHA256_DIGEST_SIZE; /* test message 0x11,0x11,etc */
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


    /*------------------------------------------------------------------------*/
    /* RSA KEY LOADING TESTS */
    /*------------------------------------------------------------------------*/
#if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_RSA)
    /* Extract an RSA public key from TPM */
    /* Setup wolf RSA key with TPM deviceID */
    /* crypto dev callbacks are used for private portion */
    rc = wc_InitRsaKey_ex(&wolfRsaPrivKey, NULL, tpmDevId);
    if (rc != 0) goto exit;
    /* load public portion of key into wolf RSA Key */
    rc = wolfTPM2_RsaKey_TpmToWolf(&dev, &rsaKey, &wolfRsaPrivKey);
    if (rc != 0) goto exit;
    /* Use TPM Handle... */
    printf("RSA Key 0x%x Exported to wolf RsaKey\n",
        (word32)rsaKey.handle.hndl);
    wc_FreeRsaKey(&wolfRsaPrivKey);
    rc = wolfTPM2_UnloadHandle(&dev, &rsaKey.handle);
    if (rc != 0) goto exit;


    /* Load RSA public key into wolf RsaKey structure */
    rc = wc_InitRsaKey(&wolfRsaPubKey, NULL);
    if (rc != 0) goto exit;
    idx = 0;
    rc = wc_RsaPublicKeyDecode(kRsaKeyPubDer, &idx,
        &wolfRsaPubKey, (word32)sizeof(kRsaKeyPubDer));
    if (rc != 0) goto exit;
    rc = wolfTPM2_RsaKey_WolfToTpm(&dev, &wolfRsaPubKey, &publicKey);
    if (rc != 0) goto exit;
    /* Use TPM Handle... */
    wc_FreeRsaKey(&wolfRsaPubKey);
    rc = wolfTPM2_UnloadHandle(&dev, &publicKey.handle);
    if (rc != 0) goto exit;
#else
    rc = wolfTPM2_UnloadHandle(&dev, &rsaKey.handle);
    if (rc != 0) goto exit;
#endif /* !WOLFTPM2_NO_WOLFCRYPT && !NO_RSA */

    /* Load raw RSA public key into TPM */
    rc = wolfTPM2_LoadRsaPublicKey(&dev, &publicKey,
        kRsaKeyPubModulus, (word32)sizeof(kRsaKeyPubModulus),
        kRsaKeyPubExponent);
    if (rc != 0) goto exit;
    /* Use TPM Handle... */
    printf("wolf RsaKey loaded into TPM: Handle 0x%x\n",
        (word32)publicKey.handle.hndl);
    rc = wolfTPM2_UnloadHandle(&dev, &publicKey.handle);
    if (rc != 0) goto exit;

#if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_RSA)
    /* Load RSA private key into TPM */
    rc = wc_InitRsaKey(&wolfRsaPrivKey, NULL);
    if (rc != 0) goto exit;
    idx = 0;
    rc = wc_RsaPrivateKeyDecode(kRsaKeyPrivDer, &idx, &wolfRsaPrivKey,
        (word32)sizeof(kRsaKeyPrivDer));
    if (rc != 0) goto exit;
    rc = wolfTPM2_RsaKey_WolfToTpm_ex(&dev, &storageKey, &wolfRsaPrivKey,
        &rsaKey);
    if (rc != 0) goto exit;
    /* Use TPM Handle... */
    wc_FreeRsaKey(&wolfRsaPrivKey);
    rc = wolfTPM2_UnloadHandle(&dev, &rsaKey.handle);
    if (rc != 0) goto exit;
#endif /* !WOLFTPM2_NO_WOLFCRYPT && !NO_RSA */

    /* Load raw RSA private key into TPM */
    rc = wolfTPM2_LoadRsaPrivateKey(&dev, &storageKey, &rsaKey,
        kRsaKeyPubModulus, (word32)sizeof(kRsaKeyPubModulus),
        kRsaKeyPubExponent,
        kRsaKeyPrivQ,      (word32)sizeof(kRsaKeyPrivQ));
    if (rc != 0) goto exit;
    /* Use TPM Handle... */
    printf("RSA Private Key Loaded into TPM: Handle 0x%x\n",
        (word32)rsaKey.handle.hndl);
    rc = wolfTPM2_UnloadHandle(&dev, &rsaKey.handle);
    if (rc != 0) goto exit;


    /*------------------------------------------------------------------------*/
    /* ECC TESTS */
    /*------------------------------------------------------------------------*/

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
    message.size = TPM_SHA256_DIGEST_SIZE; /* test message 0x11,0x11,etc */
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


    /* ECC Public Key Signature Verify Test/Example */
    rc = wolfTPM2_LoadEccPublicKey(&dev, &publicKey, TPM_ECC_NIST_P256,
        kEccTestPubQX, sizeof(kEccTestPubQX),
        kEccTestPubQY, sizeof(kEccTestPubQY));
    if (rc != 0) goto exit;

    rc = wolfTPM2_VerifyHash(&dev, &publicKey,
        kEccTestSigRS, sizeof(kEccTestSigRS),
        kEccTestMsg, sizeof(kEccTestMsg));
    if (rc != 0) goto exit;

    rc = wolfTPM2_UnloadHandle(&dev, &publicKey.handle);
    if (rc != 0) goto exit;
    printf("ECC Verify Test Passed\n");


    /*------------------------------------------------------------------------*/
    /* ECC KEY LOADING TESTS */
    /*------------------------------------------------------------------------*/
#if !defined(WOLFTPM2_NO_WOLFCRYPT) && defined(HAVE_ECC)
    /* Extract an ECC public key from TPM */
    /* Setup wolf ECC key with TPM deviceID, so crypto callbacks
       can be used for private operations */
    rc = wc_ecc_init_ex(&wolfEccPrivKey, NULL, tpmDevId);
    if (rc != 0) goto exit;
    /* load public portion of key into wolf ECC Key */
    rc = wolfTPM2_EccKey_TpmToWolf(&dev, &eccKey, &wolfEccPrivKey);
    if (rc != 0) goto exit;
    /* Use TPM Handle... */
    printf("ECC Key 0x%x Exported to wolf ecc_key\n",
        (word32)eccKey.handle.hndl);
    wc_ecc_free(&wolfEccPrivKey);
    rc = wolfTPM2_UnloadHandle(&dev, &eccKey.handle);
    if (rc != 0) goto exit;


    /* Load ECC DER public key into TPM */
    rc = wc_ecc_init(&wolfEccPubKey);
    if (rc != 0) goto exit;
    idx = 0;
    rc = wc_EccPublicKeyDecode(kEccKeyPubDer, &idx, &wolfEccPubKey,
        (word32)sizeof(kEccKeyPubDer));
    if (rc != 0) goto exit;
    rc = wolfTPM2_EccKey_WolfToTpm(&dev, &wolfEccPubKey, &publicKey);
    if (rc != 0) goto exit;
    /* Use TPM Handle... */
    wc_ecc_free(&wolfEccPubKey);
    rc = wolfTPM2_UnloadHandle(&dev, &publicKey.handle);
    if (rc != 0) goto exit;
#else
    rc = wolfTPM2_UnloadHandle(&dev, &eccKey.handle);
    if (rc != 0) goto exit;
#endif /* !WOLFTPM2_NO_WOLFCRYPT && HAVE_ECC */

    /* Load raw ECC public key into TPM */
    rc = wolfTPM2_LoadEccPublicKey(&dev, &publicKey, TPM_ECC_NIST_P256,
        kEccKeyPubXRaw, (word32)sizeof(kEccKeyPubXRaw),
        kEccKeyPubYRaw, (word32)sizeof(kEccKeyPubYRaw));
    if (rc != 0) goto exit;
    /* Use TPM Handle... */
    printf("wolf ecc_key loaded into TPM: Handle 0x%x\n",
        (word32)publicKey.handle.hndl);
    rc = wolfTPM2_UnloadHandle(&dev, &publicKey.handle);
    if (rc != 0) goto exit;

#if !defined(WOLFTPM2_NO_WOLFCRYPT) && defined(HAVE_ECC)
    /* Load ECC DER Private Key into TPM */
    rc = wc_ecc_init(&wolfEccPrivKey);
    if (rc != 0) goto exit;
    idx = 0;
    rc = wc_EccPrivateKeyDecode(kEccKeyPrivDer, &idx, &wolfEccPrivKey,
        (word32)sizeof(kEccKeyPrivDer));
    if (rc != 0) goto exit;
    rc = wolfTPM2_EccKey_WolfToTpm_ex(&dev, &storageKey, &wolfEccPrivKey,
        &eccKey);
    if (rc != 0) goto exit;
    /* Use TPM Handle... */
    wc_ecc_free(&wolfEccPrivKey);
    rc = wolfTPM2_UnloadHandle(&dev, &eccKey.handle);
    if (rc != 0) goto exit;
#endif /* !WOLFTPM2_NO_WOLFCRYPT && HAVE_ECC */

    /* Load raw ECC private key into TPM */
    rc = wolfTPM2_LoadEccPrivateKey(&dev, &storageKey, &eccKey, TPM_ECC_NIST_P256,
        kEccKeyPubXRaw, (word32)sizeof(kEccKeyPubXRaw),
        kEccKeyPubYRaw, (word32)sizeof(kEccKeyPubYRaw),
        kEccKeyPrivD,   (word32)sizeof(kEccKeyPrivD));
    if (rc != 0) goto exit;
    /* Use TPM Handle... */
    printf("ECC Private Key Loaded into TPM: Handle 0x%x\n",
        (word32)eccKey.handle.hndl);
    rc = wolfTPM2_UnloadHandle(&dev, &eccKey.handle);
    if (rc != 0) goto exit;


    /*------------------------------------------------------------------------*/
    /* NV TESTS */
    /*------------------------------------------------------------------------*/

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

    /* Random Test */
    XMEMSET(message.buffer, 0, sizeof(message.buffer));
    rc = wolfTPM2_GetRandom(&dev, message.buffer, sizeof(message.buffer));
    if (rc != 0) goto exit;


    /*------------------------------------------------------------------------*/
    /* HASH TESTS */
    /*------------------------------------------------------------------------*/
    rc = wolfTPM2_HashStart(&dev, &hash, TPM_ALG_SHA256,
        (const byte*)gUsageAuth, sizeof(gUsageAuth)-1);
    if (rc != 0) goto exit;

#ifdef ENABLE_LARGE_HASH_TEST
    message.size = 1024;
    for (i = 0; i < message.size; i++) {
        message.buffer[i] = (byte)(i & 0xFF);
    }
    for (i = 0; i < 100; i++) {
        rc = wolfTPM2_HashUpdate(&dev, &hash, message.buffer, message.size);
        if (rc != 0) goto exit;
    }
#else
    rc = wolfTPM2_HashUpdate(&dev, &hash, (byte*)hashTestData,
        (word32)XSTRLEN(hashTestData));
    if (rc != 0) goto exit;
#endif

    cipher.size = TPM_SHA256_DIGEST_SIZE;
    rc = wolfTPM2_HashFinish(&dev, &hash, cipher.buffer, (word32*)&cipher.size);
    if (rc != 0) goto exit;

    if (cipher.size != TPM_SHA256_DIGEST_SIZE ||
        XMEMCMP(cipher.buffer, hashTestDig, cipher.size) != 0) {
        printf("Hash SHA256 test failed, result not as expected!\n");
        goto exit;
    }
    printf("Hash SHA256 test success\n");


exit:

    if (rc != 0) {
        printf("Failure 0x%x: %s\n", rc, wolfTPM2_GetRCString(rc));
    }

    wolfTPM2_UnloadHandle(&dev, &publicKey.handle);
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
    #ifndef WOLFTPM2_NO_WRAPPER
        TPM2_Wrapper_SetReset(1);
    #endif
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
