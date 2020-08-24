/* wrap_test.c
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

/* This example shows using the TPM2 wrapper API's in TPM2_Wrapper_Test() below. */

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_wrap.h>

#ifndef WOLFTPM2_NO_WRAPPER

#include <examples/tpm_io.h>
#include <examples/tpm_test.h>
#include <examples/wrap/wrap_test.h>

#include <stdio.h>

/* Configuration */
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
    int rc, i;
    WOLFTPM2_DEV dev;
    WOLFTPM2_CAPS caps;
    WOLFTPM2_KEY ekKey;
    WOLFTPM2_KEY storageKey;
    WOLFTPM2_KEY rsaKey;
    WOLFTPM2_KEY eccKey;
    WOLFTPM2_KEY publicKey;
    WOLFTPM2_KEY aesKey;
    byte aesIv[MAX_AES_BLOCK_SIZE_BYTES];
    WOLFTPM2_BUFFER message;
    WOLFTPM2_BUFFER cipher;
    WOLFTPM2_BUFFER plain;
    TPMT_PUBLIC publicTemplate;
    TPM2B_ECC_POINT pubPoint;
    word32 nvAttributes = 0;
#if defined(WOLF_CRYPTO_DEV) || defined(WOLF_CRYPTO_CB)
    TpmCryptoDevCtx tpmCtx;
#endif
    WOLFTPM2_HASH hash;
    byte hashBuf[TPM_MAX_DIGEST_SIZE];
    int hashSz;
#ifdef ENABLE_LARGE_HASH_TEST
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

    WOLFTPM2_HMAC hmac;
    const char* hmacTestKey =
        "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
        "\x0b\x0b\x0b\x0b";
    const char* hmacTestData = "Hi There";
    const char* hmacTestDig =
        "\xb0\x34\x4c\x61\xd8\xdb\x38\x53\x5c\xa8\xaf\xce\xaf\x0b\xf1\x2b"
        "\x88\x1d\xc2\x00\xc9\x83\x3d\xa7\x26\xe9\x37\x6c\x2e\x32\xcf\xf7";

#ifndef WOLFTPM2_NO_WOLFCRYPT
    int tpmDevId = INVALID_DEVID;
    word32 idx;
#ifndef NO_RSA
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

#if defined(WOLF_CRYPTO_DEV) || defined(WOLF_CRYPTO_CB)
    /* Setup the wolf crypto device callback */
    XMEMSET(&tpmCtx, 0, sizeof(tpmCtx));
#ifndef NO_RSA
    XMEMSET(&rsaKey, 0, sizeof(rsaKey));
    tpmCtx.rsaKey = &rsaKey;
#endif
#ifdef HAVE_ECC
    XMEMSET(&eccKey, 0, sizeof(eccKey));
    tpmCtx.eccKey = &eccKey;
#endif
    tpmCtx.storageKey = &storageKey;
    rc = wolfTPM2_SetCryptoDevCb(&dev, wolfTPM2_CryptoDevCb, &tpmCtx, &tpmDevId);
    if (rc != 0) goto exit;
#endif

    rc = wolfTPM2_GetCapabilities(&dev, &caps);
    if (rc != 0) goto exit;

    printf("Mfg %s (%d), Vendor %s, Fw %u.%u (%u), "
        "FIPS 140-2 %d, CC-EAL4 %d\n",
        caps.mfgStr, caps.mfg, caps.vendorStr, caps.fwVerMajor,
        caps.fwVerMinor, caps.fwVerVendor, caps.fips140_2, caps.cc_eal4);

    if (resetTPM) {
        /* reset all content on TPM and reseed */
        rc = wolfTPM2_Clear(&dev);
        if (rc != 0) return rc;
    }

    /* unload all transient handles */
    rc = wolfTPM2_UnloadHandles_AllTransient(&dev);
    if (rc != 0) goto exit;


    /*------------------------------------------------------------------------*/
    /* RSA TESTS */
    /*------------------------------------------------------------------------*/

    /* Get the RSA endorsement key (EK) */
    rc = wolfTPM2_GetKeyTemplate_RSA_EK(&publicTemplate);
    if (rc != 0) goto exit;
    rc = wolfTPM2_CreatePrimaryKey(&dev, &ekKey, TPM_RH_ENDORSEMENT,
        &publicTemplate, NULL, 0);
    if (rc != 0) goto exit;
    wolfTPM2_UnloadHandle(&dev, &ekKey.handle);

    /* See if RSA primary storage key already exists */
    rc = wolfTPM2_ReadPublicKey(&dev, &storageKey,
        TPM2_DEMO_STORAGE_KEY_HANDLE);

#ifdef TEST_WRAP_DELETE_KEY
    if (rc == 0) {
        storageKey.handle.hndl = TPM2_DEMO_STORAGE_KEY_HANDLE;
        rc = wolfTPM2_NVDeleteKey(&dev, TPM_RH_OWNER, &storageKey);
        if (rc != 0) goto exit;
        rc = TPM_RC_HANDLE; /* mark handle as missing */
    }
#endif
    if (rc != 0) {
        /* Create primary storage key (RSA) */
        rc = wolfTPM2_CreateSRK(&dev, &storageKey, TPM_ALG_RSA, 
            (byte*)gStorageKeyAuth, sizeof(gStorageKeyAuth)-1);
        if (rc != 0) goto exit;

        /* Move this key into persistent storage */
        rc = wolfTPM2_NVStoreKey(&dev, TPM_RH_OWNER, &storageKey,
            TPM2_DEMO_STORAGE_KEY_HANDLE);
        if (rc != 0) goto exit;

        printf("Created new RSA Primary Storage Key at 0x%x\n",
            TPM2_DEMO_STORAGE_KEY_HANDLE);
    }
    else {
        /* specify auth password for storage key */
        storageKey.handle.auth.size = sizeof(gStorageKeyAuth)-1;
        XMEMCPY(storageKey.handle.auth.buffer, gStorageKeyAuth,
            storageKey.handle.auth.size);
    }


    /* Create RSA key for sign/verify */
    rc = wolfTPM2_GetKeyTemplate_RSA(&publicTemplate,
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_sign | TPMA_OBJECT_noDA);
    if (rc != 0) goto exit;
    rc = wolfTPM2_CreateAndLoadKey(&dev, &rsaKey, &storageKey.handle,
        &publicTemplate, (byte*)gKeyAuth, sizeof(gKeyAuth)-1);
    if (rc != 0) goto exit;

    /* Perform RSA sign / verify - PKCSv1.5 (SSA) padding */
    message.size = 32; /* test message 0x11,0x11,etc */
    XMEMSET(message.buffer, 0x11, message.size);
    cipher.size = sizeof(cipher.buffer); /* signature */
    rc = wolfTPM2_SignHashScheme(&dev, &rsaKey, message.buffer, message.size,
        cipher.buffer, &cipher.size, TPM_ALG_RSASSA, TPM_ALG_SHA256);
    if (rc != 0) goto exit;
    rc = wolfTPM2_VerifyHashScheme(&dev, &rsaKey, cipher.buffer, cipher.size,
        message.buffer, message.size, TPM_ALG_RSASSA, TPM_ALG_SHA256);
    if (rc != 0) goto exit;
    printf("RSA Sign/Verify using RSA PKCSv1.5 (SSA) padding\n");

    /* Perform RSA sign / verify - PSS padding */
    message.size = 32; /* test message 0x11,0x11,etc */
    XMEMSET(message.buffer, 0x11, message.size);
    cipher.size = sizeof(cipher.buffer); /* signature */
    rc = wolfTPM2_SignHashScheme(&dev, &rsaKey, message.buffer, message.size,
        cipher.buffer, &cipher.size, TPM_ALG_RSAPSS, TPM_ALG_SHA256);
    if (rc != 0) goto exit;
    rc = wolfTPM2_VerifyHashScheme(&dev, &rsaKey, cipher.buffer, cipher.size,
        message.buffer, message.size, TPM_ALG_RSAPSS, TPM_ALG_SHA256);
    if (rc != 0) goto exit;
    printf("RSA Sign/Verify using RSA PSS padding\n");

    rc = wolfTPM2_UnloadHandle(&dev, &rsaKey.handle);
    if (rc != 0) goto exit;


    /* Create RSA key for encrypt/decrypt */
    rc = wolfTPM2_GetKeyTemplate_RSA(&publicTemplate,
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_decrypt | TPMA_OBJECT_noDA);
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

    /* Get the ECC endorsement key (EK) */
    rc = wolfTPM2_GetKeyTemplate_ECC_EK(&publicTemplate);
    if (rc != 0) goto exit;
    rc = wolfTPM2_CreatePrimaryKey(&dev, &ekKey, TPM_RH_ENDORSEMENT,
        &publicTemplate, NULL, 0);
    if (rc != 0) goto exit;
    wolfTPM2_UnloadHandle(&dev, &ekKey.handle);

    /* See if ECC primary storage key already exists */
    rc = wolfTPM2_ReadPublicKey(&dev, &storageKey,
        TPM2_DEMO_STORAGE_EC_KEY_HANDLE);

#ifdef TEST_WRAP_DELETE_KEY
    if (rc == 0) {
        storageKey.handle.hndl = TPM2_DEMO_STORAGE_EC_KEY_HANDLE;
        rc = wolfTPM2_NVDeleteKey(&dev, TPM_RH_OWNER, &storageKey);
        if (rc != 0) goto exit;
        rc = TPM_RC_HANDLE; /* mark handle as missing */
    }
#endif
    if (rc != 0) {
        /* Create primary storage key (ECC) */
        rc = wolfTPM2_CreateSRK(&dev, &storageKey, TPM_ALG_ECC, 
            (byte*)gStorageKeyAuth, sizeof(gStorageKeyAuth)-1);
        if (rc != 0) goto exit;

        /* Move this key into persistent storage */
        rc = wolfTPM2_NVStoreKey(&dev, TPM_RH_OWNER, &storageKey,
            TPM2_DEMO_STORAGE_EC_KEY_HANDLE);
        if (rc != 0) goto exit;

        printf("Created new ECC Primary Storage Key at 0x%x\n",
            TPM2_DEMO_STORAGE_EC_KEY_HANDLE);
    }
    else {
        /* specify auth password for storage key */
        storageKey.handle.auth.size = sizeof(gStorageKeyAuth)-1;
        XMEMCPY(storageKey.handle.auth.buffer, gStorageKeyAuth,
            storageKey.handle.auth.size);
    }


    /* Create an ECC key for ECDSA */
    rc = wolfTPM2_GetKeyTemplate_ECC(&publicTemplate,
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_sign | TPMA_OBJECT_noDA,
        TPM_ECC_NIST_P256, TPM_ALG_ECDSA);
    if (rc != 0) goto exit;
    publicTemplate.nameAlg = TPM_ALG_SHA256; /* make sure its SHA256 */
    rc = wolfTPM2_CreateAndLoadKey(&dev, &eccKey, &storageKey.handle,
        &publicTemplate, (byte*)gKeyAuth, sizeof(gKeyAuth)-1);
    if (rc != 0) goto exit;

    /* Test changing auth for a key */
    rc = wolfTPM2_ChangeAuthKey(&dev, &eccKey, &storageKey.handle,
        (byte*)gKeyAuthAlt, sizeof(gKeyAuthAlt)-1);
    if (rc != 0) goto exit;

    /* Perform ECC sign / verify */
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
    publicTemplate.nameAlg = TPM_ALG_SHA256; /* make sure its SHA256 */
    rc = wolfTPM2_CreateAndLoadKey(&dev, &eccKey, &storageKey.handle,
        &publicTemplate, (byte*)gKeyAuth, sizeof(gKeyAuth)-1);
    if (rc != 0) goto exit;

    /* Create ephemeral ECC key and generate a shared secret */
    message.size = sizeof(message.buffer);
    rc = wolfTPM2_ECDHGen(&dev, &eccKey, &pubPoint,
        message.buffer, &message.size);
    if (rc != 0) goto exit;

    /* Compute shared secret and compare results */
    rc = wolfTPM2_ECDHGenZ(&dev, &eccKey, &pubPoint, cipher.buffer, &cipher.size);
    if (rc != 0) goto exit;

    if (message.size != cipher.size ||
        XMEMCMP(message.buffer, cipher.buffer, message.size) != 0) {
        rc = -1; /* failed */
    }
    printf("ECC DH Test %s\n", rc == 0 ? "Passed" : "Failed");

    /* ECC Public Key Signature Verify Test/Example */
    rc = wolfTPM2_LoadEccPublicKey(&dev, &publicKey, TPM_ECC_NIST_P256,
        kEccTestPubQX, sizeof(kEccTestPubQX),
        kEccTestPubQY, sizeof(kEccTestPubQY));
    if (rc != 0) goto exit;

    rc = wolfTPM2_VerifyHashScheme(&dev, &publicKey,
        kEccTestSigRS, sizeof(kEccTestSigRS),
        kEccTestMsg, sizeof(kEccTestMsg), TPM_ALG_ECDSA, TPM_ALG_SHA1);
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
    /* NV with Auth (preferred API's) */
    {
        WOLFTPM2_HANDLE parent;
        WOLFTPM2_NV nv;

        XMEMSET(&parent, 0, sizeof(parent));
        parent.hndl = TPM_RH_OWNER;

        rc = wolfTPM2_GetNvAttributesTemplate(parent.hndl, &nvAttributes);
        if (rc != 0) goto exit;
        rc = wolfTPM2_NVCreateAuth(&dev, &parent, &nv, TPM2_DEMO_NV_TEST_AUTH_INDEX,
            nvAttributes, TPM2_DEMO_NV_TEST_SIZE, (byte*)gNvAuth, sizeof(gNvAuth)-1);
        if (rc != 0 && rc != TPM_RC_NV_DEFINED) goto exit;

        message.size = TPM2_DEMO_NV_TEST_SIZE; /* test message 0x11,0x11,etc */
        XMEMSET(message.buffer, 0x11, message.size);
        rc = wolfTPM2_NVWriteAuth(&dev, &nv, TPM2_DEMO_NV_TEST_AUTH_INDEX,
            message.buffer, message.size, 0);
        if (rc != 0) goto exit;

        plain.size = TPM2_DEMO_NV_TEST_SIZE;
        rc = wolfTPM2_NVReadAuth(&dev, &nv, TPM2_DEMO_NV_TEST_AUTH_INDEX,
            plain.buffer, (word32*)&plain.size, 0);
        if (rc != 0) goto exit;

        rc = wolfTPM2_NVReadPublic(&dev, TPM2_DEMO_NV_TEST_AUTH_INDEX, NULL);
        if (rc != 0) goto exit;

        rc = wolfTPM2_NVDeleteAuth(&dev, &parent, TPM2_DEMO_NV_TEST_AUTH_INDEX);
        if (rc != 0) goto exit;

        if (message.size != plain.size ||
                    XMEMCMP(message.buffer, plain.buffer, message.size) != 0) {
            rc = TPM_RC_TESTING; goto exit;
        }

        printf("NV Test (with auth) on index 0x%x with %d bytes passed\n",
            TPM2_DEMO_NV_TEST_AUTH_INDEX, TPM2_DEMO_NV_TEST_SIZE);
    }

    /* NV Tests (older API's without auth) */
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


    /*------------------------------------------------------------------------*/
    /* RANDOM TESTS */
    /*------------------------------------------------------------------------*/
    /* Random Test */
    XMEMSET(message.buffer, 0, sizeof(message.buffer));
    rc = wolfTPM2_GetRandom(&dev, message.buffer, sizeof(message.buffer));
    if (rc != 0) goto exit;


    /*------------------------------------------------------------------------*/
    /* HASH TESTS */
    /*------------------------------------------------------------------------*/
    XMEMSET(&hash, 0, sizeof(hash));
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


    /*------------------------------------------------------------------------*/
    /* HMAC TESTS */
    /*------------------------------------------------------------------------*/
    XMEMSET(&hmac, 0, sizeof(hmac));
    hmac.hmacKeyKeep = 1; /* don't unload key on finish */
    rc = wolfTPM2_HmacStart(&dev, &hmac, &storageKey.handle, TPM_ALG_SHA256,
        (const byte*)hmacTestKey, (word32)XSTRLEN(hmacTestKey),
        (const byte*)gUsageAuth, sizeof(gUsageAuth)-1);
    if (rc != 0) goto exit;

    rc = wolfTPM2_HmacUpdate(&dev, &hmac, (byte*)hmacTestData,
        (word32)XSTRLEN(hmacTestData));
    if (rc != 0) goto exit;

    cipher.size = TPM_SHA256_DIGEST_SIZE;
    rc = wolfTPM2_HmacFinish(&dev, &hmac, cipher.buffer, (word32*)&cipher.size);
    if (rc != 0) goto exit;

    if (cipher.size != TPM_SHA256_DIGEST_SIZE ||
        XMEMCMP(cipher.buffer, hmacTestDig, cipher.size) != 0) {
        printf("HMAC SHA256 test failed, result not as expected!\n");
        goto exit;
    }

    /* Can reuse the HMAC key here:
     *   wolfTPM2_HmacStart, wolfTPM2_HmacUpdate, wolfTPM2_HmacFinish
     */

    /* Manually unload HMAC key, since hmacKeyKeep was set above */
    /* If hmacKeyKeep == 0 then key will be unloaded in wolfTPM2_HmacFinish */
    wolfTPM2_UnloadHandle(&dev, &hmac.key.handle);

    printf("HMAC SHA256 test success\n");


    /*------------------------------------------------------------------------*/
    /* ENCRYPT/DECRYPT TESTS */
    /*------------------------------------------------------------------------*/
    XMEMSET(&aesKey, 0, sizeof(aesKey));
    rc = wolfTPM2_LoadSymmetricKey(&dev, &aesKey, TEST_AES_MODE,
        (byte*)kTestAesCbc128Key, (word32)XSTRLEN(kTestAesCbc128Key));
    if (rc != 0) goto exit;

    message.size = (word32)sizeof(kTestAesCbc128Msg);
    XMEMCPY(message.buffer, kTestAesCbc128Msg, message.size);
    XMEMSET(cipher.buffer, 0, sizeof(cipher.buffer));
    cipher.size = message.size;
    XMEMCPY(aesIv, (byte*)kTestAesCbc128Iv, (word32)XSTRLEN(kTestAesCbc128Iv));
    rc = wolfTPM2_EncryptDecrypt(&dev, &aesKey, message.buffer, cipher.buffer,
        message.size, aesIv, (word32)sizeof(aesIv), WOLFTPM2_ENCRYPT);
    if (rc != 0 && rc != TPM_RC_COMMAND_CODE) goto exit;

    XMEMSET(plain.buffer, 0, sizeof(plain.buffer));
    plain.size = message.size;
    XMEMCPY(aesIv, (byte*)kTestAesCbc128Iv, (word32)XSTRLEN(kTestAesCbc128Iv));
    rc = wolfTPM2_EncryptDecrypt(&dev, &aesKey, cipher.buffer, plain.buffer,
        cipher.size, aesIv, (word32)sizeof(aesIv), WOLFTPM2_DECRYPT);

    wolfTPM2_UnloadHandle(&dev, &aesKey.handle);

    if (rc == TPM_RC_SUCCESS &&
         message.size == plain.size &&
         XMEMCMP(message.buffer, plain.buffer, message.size) == 0 &&
         cipher.size == sizeof(kTestAesCbc128Verify) &&
         XMEMCMP(cipher.buffer, kTestAesCbc128Verify, cipher.size) == 0) {
        printf("Encrypt/Decrypt (known key) test success\n");
    }
    else if (rc == TPM_RC_COMMAND_CODE) {
        printf("Encrypt/Decrypt: Is not a supported feature due to export controls\n");
        rc = TPM_RC_SUCCESS; /* clear error code */
    }
    else {
        printf("Encrypt/Decrypt test failed, result not as expected!\n");
        goto exit;
    }
    if (rc != 0) goto exit;


    rc = wolfTPM2_GetKeyTemplate_Symmetric(&publicTemplate, 128, TEST_AES_MODE,
        NO, YES);
    if (rc != 0) goto exit;
    rc = wolfTPM2_CreateAndLoadKey(&dev, &aesKey, &storageKey.handle,
        &publicTemplate, (byte*)gUsageAuth, sizeof(gUsageAuth)-1);
    if (rc != 0) goto exit;

    /* Test data */
    message.size = sizeof(message.buffer);
    for (i=0; i<message.size; i++) {
        message.buffer[i] = (byte)(i & 0xff);
    }

    XMEMSET(cipher.buffer, 0, sizeof(cipher.buffer));
    cipher.size = message.size;
    rc = wolfTPM2_EncryptDecrypt(&dev, &aesKey, message.buffer, cipher.buffer,
        message.size, NULL, 0, WOLFTPM2_ENCRYPT);
    if (rc != 0 && rc != TPM_RC_COMMAND_CODE) goto exit;

    XMEMSET(plain.buffer, 0, sizeof(plain.buffer));
    plain.size = message.size;
    rc = wolfTPM2_EncryptDecrypt(&dev, &aesKey, cipher.buffer, plain.buffer,
        cipher.size, NULL, 0, WOLFTPM2_DECRYPT);

    wolfTPM2_UnloadHandle(&dev, &aesKey.handle);

    if (rc == TPM_RC_SUCCESS &&
         message.size == plain.size &&
         XMEMCMP(message.buffer, plain.buffer, message.size) == 0) {
        printf("Encrypt/Decrypt test success\n");
    }
    else if (rc == TPM_RC_COMMAND_CODE) {
        printf("Encrypt/Decrypt: Is not a supported feature due to export controls\n");
    }
    else {
        printf("Encrypt/Decrypt (gen key) test failed, result not as expected!\n");
        goto exit;
    }


    /*------------------------------------------------------------------------*/
    /* PCR TESTS */
    /*------------------------------------------------------------------------*/
    /* Read PCR Index 0 */
    hashSz = 0;
    rc = wolfTPM2_ReadPCR(&dev, 0, TEST_WRAP_DIGEST, hashBuf, &hashSz);
    if (rc != 0) goto exit;

    /* Extend PCR Index 0 */
    for (i=0; i<hashSz; i++) {
        hashBuf[i] = i;
    }
    rc = wolfTPM2_ExtendPCR(&dev, 0, TEST_WRAP_DIGEST, hashBuf, hashSz);
    if (rc != 0) goto exit;

    /* Read PCR Index 0 */
    rc = wolfTPM2_ReadPCR(&dev, 0, TEST_WRAP_DIGEST, hashBuf, &hashSz);
    if (rc != 0) goto exit;
    printf("PCR Test pass\n");


exit:

    if (rc != 0) {
        printf("Failure 0x%x: %s\n", rc, wolfTPM2_GetRCString(rc));
    }

    wolfTPM2_UnloadHandle(&dev, &aesKey.handle);
    wolfTPM2_UnloadHandle(&dev, &publicKey.handle);
    wolfTPM2_UnloadHandle(&dev, &rsaKey.handle);
    wolfTPM2_UnloadHandle(&dev, &eccKey.handle);
    wolfTPM2_UnloadHandle(&dev, &ekKey.handle);

    wolfTPM2_Shutdown(&dev, 0); /* 0=just shutdown, no startup */

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
