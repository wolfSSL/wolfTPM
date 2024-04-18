/* unit_tests.c
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

/* wolfTPM 2.0 unit tests */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_wrap.h>
#include <wolftpm/tpm2_param_enc.h>

#include <hal/tpm_io.h>
#include <examples/tpm_test.h>
#include <examples/tpm_test_keys.h>
#include <examples/wrap/wrap_test.h>

#include <stdio.h>

/* Test Fail Helpers */
#ifndef NO_ABORT
    #ifndef XABORT
    #include <stdlib.h>
    #define XABORT() abort()
    #endif
#else
    #undef  XABORT
    #define XABORT()
#endif

#define Fail(description, result) do {                                         \
    printf("\nERROR - %s line %d failed with:", __FILE__, __LINE__);           \
    printf("\n    expected: "); printf description;                            \
    printf("\n    result:   "); printf result; printf("\n\n");                 \
    fflush(stdout);                                                            \
    XABORT();                                                                  \
} while(0)
#define Assert(test, description, result) if (!(test)) Fail(description, result)
#define AssertTrue(x)    Assert( (x), ("%s is true",     #x), (#x " => FALSE"))
#define AssertFalse(x)   Assert(!(x), ("%s is false",    #x), (#x " => TRUE"))
#define AssertNotNull(x) Assert( (x), ("%s is not null", #x), (#x " => NULL"))
#define AssertNull(x) do {                                                     \
    void* _x = (void *) (x);                                                   \
    Assert(!_x, ("%s is null", #x), (#x " => %p", _x));                        \
} while(0)
#define AssertInt(x, y, op, er) do {                                           \
    int _x = (int)x;                                                           \
    int _y = (int)y;                                                           \
    Assert(_x op _y, ("%s " #op " %s", #x, #y), ("%d(0x%x) " #er " %d(0x%x)",  \
    _x, _x, _y, _y)); \
} while(0)
#define AssertIntEQ(x, y) AssertInt(x, y, ==, !=)
#define AssertIntNE(x, y) AssertInt(x, y, !=, ==)
#define AssertIntGT(x, y) AssertInt(x, y,  >, <=)
#define AssertIntLT(x, y) AssertInt(x, y,  <, >=)
#define AssertIntGE(x, y) AssertInt(x, y, >=,  <)
#define AssertIntLE(x, y) AssertInt(x, y, <=,  >)
#define AssertStr(x, y, op, er) do {                                           \
    const char* _x = x;                                                        \
    const char* _y = y;                                                        \
    int   _z = (_x && _y) ? strcmp(_x, _y) : -1;                               \
    Assert(_z op 0, ("%s " #op " %s", #x, #y),                                 \
                                            ("\"%s\" " #er " \"%s\"", _x, _y));\
} while(0)
#define AssertStrEQ(x, y) AssertStr(x, y, ==, !=)
#define AssertStrNE(x, y) AssertStr(x, y, !=, ==)
#define AssertStrGT(x, y) AssertStr(x, y,  >, <=)
#define AssertStrLT(x, y) AssertStr(x, y,  <, >=)
#define AssertStrGE(x, y) AssertStr(x, y, >=,  <)
#define AssertStrLE(x, y) AssertStr(x, y, <=,  >)

#ifndef WOLFTPM2_NO_WRAPPER

static void test_wolfTPM2_Init(void)
{
    int rc;
    WOLFTPM2_DEV dev;

    /* Test first argument, wolfTPM2 context */
    rc = wolfTPM2_Init(NULL, TPM2_IoCb, NULL);
    AssertIntNE(rc, 0);
    /* Test second argument, TPM2 IO Callbacks */
    rc = wolfTPM2_Init(&dev, NULL, NULL);
#if defined(WOLFTPM_LINUX_DEV) || defined(WOLFTPM_SWTPM) || defined(WOLFTPM_WINAPI)
    /* Custom IO Callbacks are not needed for Linux TIS driver */
    AssertIntEQ(rc, 0);
#else
    /* IO Callbacks are required for SPIdev/I2C and must be valid */
    AssertIntNE(rc, 0);
#endif

    /* Test success */
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, NULL);
    AssertIntEQ(rc, 0);

    wolfTPM2_Cleanup(&dev);

    printf("Test TPM Wrapper:\tInit:\t%s\n",
        rc == 0 ? "Passed" : "Failed");
}


/* test for WOLFTPM2_DEV restore */
static void test_wolfTPM2_OpenExisting(void)
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_CAPS caps;

    /* Init the TPM2 device */
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, NULL);
    AssertIntEQ(rc, 0);

    /* Test access to TPM by getting capabilities */
    rc = wolfTPM2_GetCapabilities(&dev, &caps);
    AssertIntEQ(rc, 0);

    /* Perform cleanup, but don't shutdown TPM module */
    rc = wolfTPM2_Cleanup_ex(&dev, 0);
    AssertIntEQ(rc, 0);


    /* Restore TPM access */
    rc = wolfTPM2_OpenExisting(&dev, TPM2_IoCb, NULL);
    AssertIntEQ(rc, 0);

    /* Test access to TPM by getting capabilities */
    rc = wolfTPM2_GetCapabilities(&dev, &caps);
    AssertIntEQ(rc, 0);

    wolfTPM2_Cleanup(&dev);

    printf("Test TPM Wrapper:\tOpen Existing:\t%s\n",
        rc == 0 ? "Passed" : "Failed");
}

/* test for wolfTPM2_GetCapabilities */
static void test_wolfTPM2_GetCapabilities(void)
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_CAPS caps;

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, NULL);
    AssertIntEQ(rc, 0);

    /* Test Arguments */
    rc = wolfTPM2_GetCapabilities(NULL, &caps);
    AssertIntNE(rc, 0);
    rc = wolfTPM2_GetCapabilities(&dev, NULL);
    AssertIntNE(rc, 0);

    /* Test success */
    rc = wolfTPM2_GetCapabilities(&dev, &caps);
    AssertIntEQ(rc, 0);

#ifdef DEBUG_WOLFTPM
    printf("Mfg %s (%d), Vendor %s, Fw %u.%u (%u), FIPS 140-2 %d, CC-EAL4 %d\n",
        caps.mfgStr, caps.mfg, caps.vendorStr, caps.fwVerMajor,
        caps.fwVerMinor, caps.fwVerVendor, caps.fips140_2, caps.cc_eal4);
#endif

    wolfTPM2_Cleanup(&dev);

    printf("Test TPM Wrapper:\tGet Capabilities:\t%s\n",
        rc == 0 ? "Passed" : "Failed");
}

/* test for wolfTPM2_ReadPublicKey */
static void test_wolfTPM2_ReadPublicKey(void)
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY storageKey;

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, NULL);
    AssertIntEQ(rc, 0);

    /* Test arguments */
    rc = wolfTPM2_ReadPublicKey(NULL, &storageKey, TPM2_DEMO_STORAGE_KEY_HANDLE);
    AssertIntNE(rc, 0);
    rc = wolfTPM2_ReadPublicKey(&dev, NULL, TPM2_DEMO_STORAGE_KEY_HANDLE);
    AssertIntNE(rc, 0);

    /* Test success: read storage primary key */
    rc = wolfTPM2_ReadPublicKey(&dev, &storageKey,
        TPM2_DEMO_STORAGE_KEY_HANDLE);
    if ((rc & RC_MAX_FMT1) == TPM_RC_HANDLE) {
        rc = 0; /* okay if not found */
    }
    AssertIntEQ(rc, 0);
    wolfTPM2_Cleanup(&dev);

    printf("Test TPM Wrapper:\tRead Public Key:\t%s\n",
        rc == 0 ? "Passed" : "Failed");
}

static void test_wolfTPM2_GetRandom(void)
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_BUFFER rngData;

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, NULL);
    AssertIntEQ(rc, 0);

    /* Test arguments */
    rc = wolfTPM2_GetRandom(NULL, rngData.buffer, sizeof(rngData.buffer));
    AssertIntNE(rc, 0);
    rc = wolfTPM2_GetRandom(&dev, NULL, sizeof(rngData.buffer));
    AssertIntNE(rc, 0);
    rc = wolfTPM2_GetRandom(&dev, rngData.buffer, 0);
    AssertIntEQ(rc, 0);

    /* Test success */
    rc = wolfTPM2_GetRandom(&dev, rngData.buffer, sizeof(rngData.buffer));

    AssertIntEQ(rc, 0);
    wolfTPM2_Cleanup(&dev);

    printf("Test TPM Wrapper:\tGet Random:\t%s\n",
        rc == 0 ? "Passed" : "Failed");
}

static void test_wolfTPM2_Cleanup(void)
{
    int rc;
    WOLFTPM2_DEV dev;

    /* Test arguments */
    rc = wolfTPM2_Cleanup(NULL);
    AssertIntNE(rc, 0);

    /* Test success */
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, NULL);
    AssertIntEQ(rc, 0);

    rc = wolfTPM2_Cleanup(&dev);
    AssertIntEQ(rc, 0);

    printf("Test TPM Wrapper:\tCleanup:\t%s\n",
        rc == 0 ? "Passed" : "Failed");
}

static void test_TPM2_KDFa(void)
{
    int rc;
    #define TEST_KDFA_KEYSZ 20
    TPM2B_DATA keyIn = {
        .size = TEST_KDFA_KEYSZ,
        .buffer = {0x27, 0x1F, 0xA0, 0x8B, 0xBD, 0xC5, 0x06, 0x0E, 0xC3, 0xDF,
                   0xA9, 0x28, 0xFF, 0x9B, 0x73, 0x12, 0x3A, 0x12, 0xDA, 0x0C}
    };
    const char label[] = "KDFSELFTESTLABEL";
    TPM2B_NONCE contextU = {
        .size = 8,
        .buffer = {0xCE, 0x24, 0x4F, 0x39, 0x5D, 0xCA, 0x73, 0x91}
    };
    TPM2B_NONCE contextV = {
        .size = 8,
        .buffer = {0xDA, 0x50, 0x40, 0x31, 0xDD, 0xF1, 0x2E, 0x83}
    };
    byte key[TEST_KDFA_KEYSZ];

#ifndef WOLFTPM2_NO_WOLFCRYPT
    const byte keyExp[TEST_KDFA_KEYSZ] = {
        0xbb, 0x02, 0x59, 0xe1, 0xc8, 0xba, 0x60, 0x7e, 0x6a, 0x2c,
        0xd7, 0x04, 0xb6, 0x9a, 0x90, 0x2e, 0x9a, 0xde, 0x84, 0xc4};
#endif

    rc = TPM2_KDFa(TPM_ALG_SHA256, &keyIn, label, &contextU, &contextV, key, keyIn.size);
#ifdef WOLFTPM2_NO_WOLFCRYPT
    AssertIntEQ(NOT_COMPILED_IN, rc);
#else
    AssertIntEQ(sizeof(keyExp), rc);
    AssertIntEQ(XMEMCMP(key, keyExp, sizeof(keyExp)), 0);
#endif

    printf("Test TPM Wrapper:\tKDFa:\t%s\n",
        rc >= 0 ? "Passed" : "Failed");
}

static void test_wolfTPM2_CSR(void)
{
#if defined(WOLFTPM2_CERT_GEN) && !defined(WOLFTPM2_NO_HEAP) && \
    defined(WOLFTPM_CRYPTOCB)
    int rc;
    WOLFTPM2_CSR* csr = wolfTPM2_NewCSR();
    AssertNotNull(csr);

    /* invalid cases */
    rc = wolfTPM2_CSR_SetSubject(NULL, NULL, NULL);
    AssertIntEQ(rc, BAD_FUNC_ARG);
    rc = wolfTPM2_CSR_SetSubject(NULL, csr, NULL);
    AssertIntEQ(rc, BAD_FUNC_ARG);

    /* valid, but empty DH strings */
    rc = wolfTPM2_CSR_SetSubject(NULL, csr, ""); /* test no slash */
    AssertIntEQ(rc, 0);
    rc = wolfTPM2_CSR_SetSubject(NULL, csr, "/C=/CN="); /* test blank value */
    AssertIntEQ(rc, 0);

    /* valid string */
    rc = wolfTPM2_CSR_SetSubject(NULL, csr,
        "/C=US/ST=Oregon/L=Portland/SN=Test/O=wolfSSL"
        "/OU=RSA/CN=www.wolfssl.com/emailAddress=info@wolfssl.com");
    AssertIntEQ(rc, 0);

    wolfTPM2_FreeCSR(csr);

    printf("Test TPM Wrapper:\tCSR Subject:\t%s\n",
        rc == 0 ? "Passed" : "Failed");
#endif
}

#if !defined(WOLFTPM2_NO_WOLFCRYPT) && defined(WOLFTPM2_PEM_DECODE)
static WOLFTPM2_KEY authKey; /* also used for test_wolfTPM2_PCRPolicy */

static void test_wolfTPM_ImportPublicKey(void)
{
    int rc;
    WOLFTPM2_DEV dev;
    TPM_ALG_ID alg = TPM_ALG_RSA;
    int encType = ENCODING_TYPE_PEM;
    TPMA_OBJECT attributes = (
        TPMA_OBJECT_sign |
        TPMA_OBJECT_noDA |
        TPMA_OBJECT_userWithAuth
    );
    /* public key from ibmtss/utils/policies/rsapubkey.pem */
    const char* pemPublicKey =
        "-----BEGIN PUBLIC KEY-----\n"
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAukO2Z2rjxNm7EWi82TpW\n"
        "hXmJo5fPf2enN4KzF35qVM4KjYdpVODWQ377Lq3edqriP1Ji2dUvqoUHNrkfwSOH\n"
        "EHHKWXO++if4o+kI5YdC1MzwXMVHI2Yrn7fAteGArM7Ox9GRcdzmicw38HMWWGtM\n"
        "OBUkaLZnO7rJW1VPQQw1IG9d+hFepXfrNl75zz2S2mceWecFRGBFE8DPW+zMQIMm\n"
        "qFtt9g9+LIw0b1fn13DsMW7JX3J126ZwgTH6BEmSIY04xz2Tz0Z0+GNb+mwDypP9\n"
        "1o0l0ITkETMsfabpGgEfC2x+67lQJR986MyLZ+WDK+3LeT2b4mA2bxpRa6yDrEv/\n"
        "gQIDAQAB\n"
        "-----END PUBLIC KEY-----";

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, NULL);
    AssertIntEQ(rc, 0);

    rc = wolfTPM2_ImportPublicKeyBuffer(&dev,
        alg,
        &authKey,
        encType,
        pemPublicKey, (word32)XSTRLEN(pemPublicKey),
        attributes
    );
    AssertIntEQ(rc, 0);

    wolfTPM2_Cleanup(&dev);
}

/* Test vector from ibmtss policy authorize test for SHA2-256 */
static void test_wolfTPM2_PCRPolicy(void)
{
    int rc;
    WOLFTPM2_DEV dev;
    TPM_ALG_ID pcrAlg = TPM_ALG_SHA256;
    const char* aaa = "aaa";
    byte pcrArray[1] = {TPM2_DEMO_PCR_INDEX};
    word32 pcrArraySz = 1;
    byte pcrIndex = pcrArray[0];
    byte digest[WC_SHA256_DIGEST_SIZE];
    word32 digestSz;
    byte pcrHash[WC_SHA256_DIGEST_SIZE];
    word32 pcrHashSz;
    const byte expectedPolicyAuth[] = {
        0xEB, 0xA3, 0xF9, 0x8C,  0x5E, 0xAF, 0x1E, 0xA8,
        0xF9, 0x4F, 0x51, 0x9B,  0x4D, 0x2A, 0x31, 0x83,
        0xEE, 0x79, 0x87, 0x66,  0x72, 0x39, 0x8E, 0x23,
        0x15, 0xD9, 0x33, 0xC2,  0x88, 0xA8, 0xE5, 0x03
    };
    const byte expectedPCRAuth[] = {
        0x76, 0x44, 0xF6, 0x11,  0xEA, 0x10, 0xD7, 0x60,
        0xDA, 0xB9, 0x36, 0xC3,  0x95, 0x1E, 0x1D, 0x85,
        0xEC, 0xDB, 0x84, 0xCE,  0x9A, 0x79, 0x03, 0xDD,
        0xE1, 0xC7, 0xE0, 0xA2,  0xD9, 0x09, 0xA0, 0x13
    };

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, NULL);
    AssertIntEQ(rc, 0);

    /* fixup public key to match TCG test vector */
    authKey.pub.publicArea.parameters.rsaDetail.exponent = 0;

    /* Generate authorization policy for public key */
    /* Use public key from "test_wolfTPM_ImportPublicKey" */
    XMEMSET(digest, 0, sizeof(digest)); /* empty old hash */
    digestSz = WC_SHA256_DIGEST_SIZE;
    rc = wolfTPM2_PolicyAuthorizeMake(pcrAlg, &authKey.pub,
        digest, &digestSz, NULL, 0);
    AssertIntEQ(rc, 0);

    AssertIntEQ(XMEMCMP(digest, expectedPolicyAuth, sizeof(expectedPolicyAuth)), 0);

    rc = wolfTPM2_ResetPCR(&dev, pcrIndex);
    AssertIntEQ(rc, 0);

    rc = wolfTPM2_ExtendPCR(&dev, pcrIndex, pcrAlg,
        (byte*)aaa, (int)XSTRLEN(aaa));
    AssertIntEQ(rc, 0);

    rc = wolfTPM2_PCRGetDigest(&dev, pcrAlg, pcrArray, pcrArraySz,
        pcrHash, &pcrHashSz);
    AssertIntEQ(rc, 0);

    XMEMSET(digest, 0, sizeof(digest)); /* empty old hash */
    digestSz = WC_SHA256_DIGEST_SIZE;
    rc = wolfTPM2_PolicyPCRMake(pcrAlg, pcrArray, pcrArraySz,
        pcrHash, pcrHashSz, digest, &digestSz);
    AssertIntEQ(rc, 0);

    AssertIntEQ(XMEMCMP(digest, expectedPCRAuth, sizeof(expectedPCRAuth)), 0);

    wolfTPM2_Cleanup(&dev);
}
#endif /* !WOLFTPM2_NO_WOLFCRYPT && WOLFTPM2_PEM_DECODE */

#if defined(HAVE_THREAD_LS) && defined(HAVE_PTHREAD)
#include <pthread.h>
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
int secondRunner = 0;

static void* test_wolfTPM2_thread_local_storage_work_thread(void* args)
{
    TPM2_CTX tpm2Ctx;

    TPM2_Init(&tpm2Ctx, NULL, NULL);

    /* lock so that the other thread must wait while we set the ctx */
    pthread_mutex_lock(&mutex);

    /* ctx should be what was set in init, not set by other thread */
    if (secondRunner == 1) {
        if (TPM2_GetActiveCtx() != &tpm2Ctx)
            printf("Test TPM Wrapper:\tThread Local Storage\tFailed\n");
        else
            printf("Test TPM Wrapper:\tThread Local Storage\tPassed\n");
    }

    /* set the active ctx, should not impact the other thread */
    TPM2_SetActiveCtx(&tpm2Ctx);

    secondRunner = 1;

    /* let the other thread run */
    pthread_mutex_unlock(&mutex);

    (void)args;
    return NULL;
}
#endif /* HAVE_THREAD_LS && HAVE_PTHREAD */

static void test_wolfTPM2_thread_local_storage(void)
{
#if defined(HAVE_THREAD_LS) && defined(HAVE_PTHREAD)
    pthread_t thread_1;
    pthread_t thread_2;

    pthread_create(&thread_1, NULL,
        test_wolfTPM2_thread_local_storage_work_thread, NULL);
    pthread_create(&thread_2, NULL,
        test_wolfTPM2_thread_local_storage_work_thread, NULL);

    pthread_join(thread_1, NULL);
    pthread_join(thread_2, NULL);
#endif /* HAVE_THREAD_LS && HAVE_PTHREAD */
}

/* Test creating key and exporting keyblob as buffer,
 * importing and loading key. */
static void test_wolfTPM2_KeyBlob(TPM_ALG_ID alg)
{
    int rc;
    TPM_HANDLE handle;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY srk;
    WOLFTPM2_KEYBLOB key;
    WOLFTPM2_BUFFER blob;
    TPMT_PUBLIC publicTemplate;
    word32 privBufferSz, pubBufferSz;

    XMEMSET(&srk, 0, sizeof(srk));
    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(&publicTemplate, 0, sizeof(publicTemplate));

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, NULL);
    AssertIntEQ(rc, 0);

    if (alg == TPM_ALG_ECC)
        handle = TPM2_DEMO_STORAGE_KEY_HANDLE;
    else /* RSA */
        handle = TPM2_DEMO_STORAGE_EC_KEY_HANDLE;

    /* Load or create the SRK */
    rc = wolfTPM2_ReadPublicKey(&dev, &srk, handle);
    if ((rc & RC_MAX_FMT1) == TPM_RC_HANDLE) {
        rc = wolfTPM2_CreateSRK(&dev, &srk, alg,
            (byte*)gStorageKeyAuth, sizeof(gStorageKeyAuth)-1);
        AssertIntEQ(rc, 0);
    }
    else {
        srk.handle.auth.size = sizeof(gStorageKeyAuth)-1;
        XMEMCPY(srk.handle.auth.buffer, gStorageKeyAuth, srk.handle.auth.size);
    }

    if (alg == TPM_ALG_ECC) {
        rc = wolfTPM2_GetKeyTemplate_ECC(&publicTemplate,
            TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
            TPMA_OBJECT_decrypt | TPMA_OBJECT_sign | TPMA_OBJECT_noDA,
            TPM_ECC_NIST_P256, TPM_ALG_NULL);
    }
    else { /* RSA */
        rc = wolfTPM2_GetKeyTemplate_RSA(&publicTemplate,
            TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
            TPMA_OBJECT_decrypt | TPMA_OBJECT_sign | TPMA_OBJECT_noDA);
    }
    AssertIntEQ(rc, 0);

    /* Create key under SRK and get encrypted private and public from TPM */
    rc = wolfTPM2_CreateKey(&dev, &key, &srk.handle, &publicTemplate,
        (byte*)gKeyAuth, sizeof(gKeyAuth)-1);
    AssertIntEQ(rc, 0);

    /* Test getting size only */
    rc = wolfTPM2_GetKeyBlobAsSeparateBuffers(NULL, &pubBufferSz,
        NULL, &privBufferSz, &key);
    AssertIntEQ(rc, LENGTH_ONLY_E);

    /* Test exporting private and public parts separately */
    rc = wolfTPM2_GetKeyBlobAsSeparateBuffers(blob.buffer, &pubBufferSz,
        &blob.buffer[pubBufferSz], &privBufferSz, &key);
    AssertIntEQ(rc, 0);

    /* Test getting size only */
    rc = wolfTPM2_GetKeyBlobAsBuffer(NULL, sizeof(blob.buffer), &key);
    AssertIntGT(rc, 0);

    /* Export private and public key */
    rc = wolfTPM2_GetKeyBlobAsBuffer(blob.buffer, sizeof(blob.buffer), &key);
    AssertIntGT(rc, 0);
    blob.size = rc;

    /* Reset the originally created key */
    XMEMSET(&key, 0, sizeof(key));

    /* Load key blob (private/public) from buffer */
    rc = wolfTPM2_SetKeyBlobFromBuffer(&key, blob.buffer, blob.size);
    AssertIntEQ(rc, 0);
    key.handle.auth.size = sizeof(gKeyAuth)-1;
    XMEMCPY(key.handle.auth.buffer, gKeyAuth, key.handle.auth.size);

    /* Load key to TPM and get temp handle */
    rc = wolfTPM2_LoadKey(&dev, &key, &srk.handle);
    AssertIntEQ(rc, 0);

    wolfTPM2_UnloadHandle(&dev, &key.handle);
    wolfTPM2_UnloadHandle(&dev, &srk.handle);
    wolfTPM2_Cleanup(&dev);

    printf("Test TPM Wrapper:\tKeyBlob %s:\t%s\n",
        TPM2_GetAlgName(alg), rc == 0 ? "Passed" : "Failed");
}

#endif /* !WOLFTPM2_NO_WRAPPER */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
#else
int unit_tests(int argc, char *argv[])
#endif
{
    (void)argc;
    (void)argv;

#ifndef WOLFTPM2_NO_WRAPPER
    test_wolfTPM2_Init();
    test_wolfTPM2_OpenExisting();
    test_wolfTPM2_GetCapabilities();
    test_wolfTPM2_GetRandom();
    test_TPM2_KDFa();
    test_wolfTPM2_ReadPublicKey();
    test_wolfTPM2_CSR();
    #if !defined(WOLFTPM2_NO_WOLFCRYPT) && defined(WOLFTPM2_PEM_DECODE)
    test_wolfTPM_ImportPublicKey();
    test_wolfTPM2_PCRPolicy();
    #endif
    test_wolfTPM2_KeyBlob(TPM_ALG_RSA);
    test_wolfTPM2_KeyBlob(TPM_ALG_ECC);
    test_wolfTPM2_Cleanup();
    test_wolfTPM2_thread_local_storage();
#endif /* !WOLFTPM2_NO_WRAPPER */

    return 0;
}
