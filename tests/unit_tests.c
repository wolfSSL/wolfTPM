/* unit_tests.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfTPM.
 *
 * wolfTPM is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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
#include <wolftpm/tpm2_asn.h>

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

#if !defined(WOLFTPM2_NO_WOLFCRYPT) && defined(HAVE_ECC) && \
    !defined(WOLFTPM2_NO_ASN)
/* Query TPM_CAP_ALGS to see if a given algorithm is supported.
 * Returns 1 if supported, 0 otherwise. Used to skip test iterations on TPMs
 * that don't implement a given hash (e.g. Nuvoton NPCT75x lacks SHA512).
 * Guarded by the same ifdef as its only caller (test_wolfTPM2_EccSignVerifyDig)
 * so non-ECC builds don't trip -Werror=unused-function. */
static int test_tpm_alg_supported(TPM_ALG_ID alg)
{
    GetCapability_In  in;
    GetCapability_Out out;
    word32 i;

    XMEMSET(&in, 0, sizeof(in));
    XMEMSET(&out, 0, sizeof(out));
    in.capability    = TPM_CAP_ALGS;
    in.property      = alg;
    in.propertyCount = 1;
    if (TPM2_GetCapability(&in, &out) != TPM_RC_SUCCESS) {
        return 1; /* On error, assume supported and let the real call fail */
    }
    for (i = 0; i < out.capabilityData.data.algorithms.count; i++) {
        if (out.capabilityData.data.algorithms.algProperties[i].alg == alg) {
            return 1;
        }
    }
    return 0;
}
#endif /* !WOLFTPM2_NO_WOLFCRYPT && HAVE_ECC && !WOLFTPM2_NO_ASN */

static void test_wolfTPM2_Init(void)
{
    int rc;
    WOLFTPM2_DEV dev;

    /* Test first argument, wolfTPM2 context */
    rc = wolfTPM2_Init(NULL, TPM2_IoCb, NULL);
    AssertIntNE(rc, 0);
    /* Test second argument, TPM2 IO Callbacks */
    rc = wolfTPM2_Init(&dev, NULL, NULL);
#if defined(WOLFTPM_LINUX_DEV) || defined(WOLFTPM_SWTPM) || \
    defined(WOLFTPM_WINAPI)
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

#ifdef WOLFTPM_FIRMWARE_UPGRADE
#if defined(WOLFTPM_ST33) || defined(WOLFTPM_AUTODETECT)
/* Test ST33 firmware upgrade APIs (function availability and
 * parameter validation). LMS vs non-LMS format is auto-detected
 * from manifest size (177 bytes = non-LMS, 2697 bytes = LMS). */
static void test_wolfTPM2_ST33_FirmwareUpgrade(void)
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_CAPS caps;
#if !defined(WOLFTPM2_NO_WOLFCRYPT) && defined(WOLFSSL_SHA384)
    /* Invalid manifest size (not 177 or 2697) for testing auto-detection */
    uint8_t dummy_manifest[10] = {0};
#endif

    /* Initialize TPM */
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, NULL);
    if (rc != 0) {
        printf("Test ST33 Firmware Upgrade:\tInit:\tSkipped (TPM not available)\n");
        return;
    }

    rc = wolfTPM2_GetCapabilities(&dev, &caps);
    AssertIntEQ(rc, 0);

#ifdef DEBUG_WOLFTPM
    /* Display firmware version info */
    if (caps.mfg == TPM_MFG_STM) {
        printf("ST33 TPM - Firmware: %u.%u (0x%x), Format: %s\n",
            caps.fwVerMajor, caps.fwVerMinor, caps.fwVerVendor,
            (caps.fwVerMinor >= 512) ? "LMS" : "non-LMS");
    }
#endif

    /* ===== Test NULL dev parameter handling ===== */

    /* wolfTPM2_FirmwareUpgradeCancel - NULL dev */
    rc = wolfTPM2_FirmwareUpgradeCancel(NULL);
    AssertIntNE(rc, 0);

    /* wolfTPM2_FirmwareUpgradeHash - NULL dev */
    rc = wolfTPM2_FirmwareUpgradeHash(NULL, TPM_ALG_SHA384, NULL, 0, NULL,
        0, NULL, NULL);
    AssertIntNE(rc, 0);

    /* wolfTPM2_FirmwareUpgradeRecover - NULL dev */
    rc = wolfTPM2_FirmwareUpgradeRecover(NULL, NULL, 0, NULL, NULL);
    AssertIntNE(rc, 0);

#if !defined(WOLFTPM2_NO_WOLFCRYPT) && defined(WOLFSSL_SHA384)
    /* wolfTPM2_FirmwareUpgrade - NULL dev */
    rc = wolfTPM2_FirmwareUpgrade(NULL, NULL, 0, NULL, NULL);
    AssertIntNE(rc, 0);
#endif /* !WOLFTPM2_NO_WOLFCRYPT && WOLFSSL_SHA384 */

    /* ===== Test NULL/invalid parameter combinations ===== */

    /* wolfTPM2_FirmwareUpgradeHash - valid dev, NULL manifest */
    rc = wolfTPM2_FirmwareUpgradeHash(&dev, TPM_ALG_SHA384, NULL, 0, NULL,
        0, NULL, NULL);
    AssertIntNE(rc, 0);

    /* wolfTPM2_FirmwareUpgradeRecover - valid dev, NULL manifest */
    rc = wolfTPM2_FirmwareUpgradeRecover(&dev, NULL, 0, NULL, NULL);
    AssertIntNE(rc, 0);

    /* wolfTPM2_FirmwareUpgradeCancel - valid dev (may succeed or fail
     * depending on TPM state) */
    rc = wolfTPM2_FirmwareUpgradeCancel(&dev);
    /* Note: This may return success or error depending on TPM state -
     * just verify it doesn't crash */
    (void)rc;

#if !defined(WOLFTPM2_NO_WOLFCRYPT) && defined(WOLFSSL_SHA384)
    /* wolfTPM2_FirmwareUpgrade - valid dev, NULL manifest */
    rc = wolfTPM2_FirmwareUpgrade(&dev, NULL, 0, NULL, NULL);
    AssertIntNE(rc, 0);

    /* wolfTPM2_FirmwareUpgrade - valid dev, NULL callback */
    rc = wolfTPM2_FirmwareUpgrade(&dev, dummy_manifest, sizeof(dummy_manifest),
        NULL, NULL);
    AssertIntNE(rc, 0);

    /* Test ST33-specific manifest size validation if we have an ST33 TPM.
     * Invalid manifest size (not 177 or 2697) should return BAD_FUNC_ARG. */
    if (caps.mfg == TPM_MFG_STM) {
        /* wolfTPM2_FirmwareUpgradeHash - invalid manifest size (10 bytes).
         * Should fail with BAD_FUNC_ARG because manifest_sz must be
         * exactly 177 (non-LMS) or 2697 (LMS). */
        rc = wolfTPM2_FirmwareUpgradeHash(&dev, TPM_ALG_SHA384, NULL, 0,
            dummy_manifest, sizeof(dummy_manifest), NULL, NULL);
        AssertIntEQ(rc, BAD_FUNC_ARG);
    }
#endif /* !WOLFTPM2_NO_WOLFCRYPT && WOLFSSL_SHA384 */

    wolfTPM2_Cleanup(&dev);

    printf("Test ST33 Firmware Upgrade:\tAPI Availability:\tPassed\n");
}
#endif /* WOLFTPM_ST33 || WOLFTPM_AUTODETECT */
#endif /* WOLFTPM_FIRMWARE_UPGRADE */

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

static void test_TPM2_PCRSel(void)
{
    int rc = 0;
    TPML_PCR_SELECTION pcr;
    byte   pcrArray[PCR_SELECT_MAX];
    word32 pcrArraySz;

    XMEMSET(&pcr, 0, sizeof(pcr));
    XMEMSET(pcrArray, 0, sizeof(pcrArray));

    pcrArraySz = 0;
    pcrArray[pcrArraySz++] = 1;
    pcrArray[pcrArraySz++] = 2;
    pcrArray[pcrArraySz++] = 3;
    TPM2_SetupPCRSelArray(&pcr, TPM_ALG_SHA, pcrArray, pcrArraySz);

    pcrArraySz = 0;
    pcrArray[pcrArraySz++] = 4;
    pcrArray[pcrArraySz++] = 5;
    pcrArray[pcrArraySz++] = 6;
    TPM2_SetupPCRSelArray(&pcr, TPM_ALG_SHA256, pcrArray, pcrArraySz);

    if (pcr.count != 2 ||
        pcr.pcrSelections[0].hash != TPM_ALG_SHA ||
        pcr.pcrSelections[0].pcrSelect[0] != 0x0E ||
        pcr.pcrSelections[1].hash != TPM_ALG_SHA256 ||
        pcr.pcrSelections[1].pcrSelect[0] != 0x70
    ) {
        rc = BAD_FUNC_ARG;
    }
    AssertIntEQ(rc, 0);

    /* Test bad case - invalid PCR */
    XMEMSET(&pcr, 0, sizeof(pcr));
    pcrArray[0] = PCR_LAST+1;
    TPM2_SetupPCRSelArray(&pcr, TPM_ALG_SHA256, pcrArray, 1);
    if (pcr.count != 0) {
        rc = BAD_FUNC_ARG;
    }
    AssertIntEQ(rc, 0);

    /* Test bad case - too many hash algorithms */
    XMEMSET(&pcr, 0, sizeof(pcr));
    pcrArray[0] = 1;
    TPM2_SetupPCRSelArray(&pcr, TPM_ALG_SHA, pcrArray, 1);
    pcrArray[0] = 2;
    TPM2_SetupPCRSelArray(&pcr, TPM_ALG_SHA256, pcrArray, 1);
    pcrArray[0] = 3;
    TPM2_SetupPCRSelArray(&pcr, TPM_ALG_SHA384, pcrArray, 1);
    pcrArray[0] = 4;
    TPM2_SetupPCRSelArray(&pcr, TPM_ALG_SHA512, pcrArray, 1);
    pcrArray[0] = 5;
    TPM2_SetupPCRSelArray(&pcr, TPM_ALG_SHA3_256, pcrArray, 1);
    pcrArray[0] = 6;
    TPM2_SetupPCRSelArray(&pcr, TPM_ALG_SHA3_384, pcrArray, 1);
    pcrArray[0] = 7;
    TPM2_SetupPCRSelArray(&pcr, TPM_ALG_SHA3_512, pcrArray, 1);
    if (pcr.count != HASH_COUNT) {
        rc = BAD_FUNC_ARG;
    }
    AssertIntEQ(rc, 0);

    printf("Test TPM Wrapper:\tPCR Select Array:\t%s\n",
        rc == 0 ? "Passed" : "Failed");
}

/* Test NULL input handling for policy commands (security fix) */
static void test_TPM2_Policy_NULL_Args(void)
{
    int rc;

    /* Test NULL input handling for policy commands */
    rc = TPM2_PolicyPhysicalPresence(NULL);
    AssertIntEQ(rc, BAD_FUNC_ARG);

    rc = TPM2_PolicyAuthValue(NULL);
    AssertIntEQ(rc, BAD_FUNC_ARG);

    rc = TPM2_PolicyPassword(NULL);
    AssertIntEQ(rc, BAD_FUNC_ARG);

    printf("Test TPM2:\t\tPolicy NULL Args:\tPassed\n");
}

static void test_wolfTPM2_PolicyAuthValue_AuthOffset(void)
{
#if !defined(WOLFTPM2_NO_WOLFCRYPT)
    WOLFTPM2_DEV dev;
    WOLFTPM2_SESSION session;
    const byte testAuth[] = {0x11, 0x22, 0x33, 0x44};
    int authDigestSz;
    int i;

    XMEMSET(&dev, 0, sizeof(dev));
    XMEMSET(&session, 0, sizeof(session));

    (void)wolfTPM2_Init(&dev, TPM2_IoCb, NULL);

    /* Configure session with SHA-256 auth hash */
    session.authHash = TPM_ALG_SHA256;
    authDigestSz = TPM2_GetHashDigestSize(TPM_ALG_SHA256);
    AssertIntEQ(authDigestSz, TPM_SHA256_DIGEST_SIZE);

    /* Pre-fill the HMAC key region with a sentinel */
    XMEMSET(session.handle.auth.buffer, 0xFF, authDigestSz);

    /* Call PolicyAuthValue - ignore return (TPM command may fail without
     * a real session handle, but auth buffer placement happens first) */
    (void)wolfTPM2_PolicyAuthValue(&dev, &session, testAuth,
        (int)sizeof(testAuth));

    /* Verify auth.size = authDigestSz + authSz */
    AssertIntEQ(session.handle.auth.size,
        authDigestSz + (int)sizeof(testAuth));

    /* Verify HMAC key slot [0..authDigestSz-1] is preserved (still 0xFF) */
    for (i = 0; i < authDigestSz; i++) {
        AssertIntEQ(session.handle.auth.buffer[i], 0xFF);
    }

    /* Verify auth placed at offset [authDigestSz..authDigestSz+authSz-1] */
    AssertIntEQ(XMEMCMP(&session.handle.auth.buffer[authDigestSz],
        testAuth, sizeof(testAuth)), 0);

    /* Verify policyAuth flag is set */
    AssertIntEQ(session.handle.policyAuth, 1);

    wolfTPM2_Cleanup(&dev);

    printf("Test TPM Wrapper:\tPolicyAuthValue Offset:\tPassed\n");
#endif
}

static void test_wolfTPM2_SetAuthHandle_PolicyAuthOffset(void)
{
#if !defined(WOLFTPM2_NO_WOLFCRYPT)
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_HANDLE handle;
    int authDigestSz;
    int i;

    XMEMSET(&dev, 0, sizeof(dev));
    XMEMSET(&handle, 0, sizeof(handle));

    (void)wolfTPM2_Init(&dev, TPM2_IoCb, NULL);

    /* Configure session 0 with SHA-256 auth hash and a non-PW session handle */
    dev.session[0].authHash = TPM_ALG_SHA256;
    dev.session[0].sessionHandle = 0x02000000; /* HMAC session handle */
    authDigestSz = TPM2_GetHashDigestSize(TPM_ALG_SHA256);
    AssertIntEQ(authDigestSz, TPM_SHA256_DIGEST_SIZE);

    /* Pre-fill the HMAC key region with sentinel */
    XMEMSET(dev.session[0].auth.buffer, 0xFF, authDigestSz);

    /* Set up handle with policyAuth and auth data */
    handle.policyAuth = 1;
    handle.auth.size = 4;
    handle.auth.buffer[0] = 0x11;
    handle.auth.buffer[1] = 0x22;
    handle.auth.buffer[2] = 0x33;
    handle.auth.buffer[3] = 0x44;
    handle.name.size = 2;
    handle.name.name[0] = 0xAA;
    handle.name.name[1] = 0xBB;

    /* Test wolfTPM2_SetAuthHandle policyAuth branch */
    rc = wolfTPM2_SetAuthHandle(&dev, 0, &handle);
    AssertIntEQ(rc, TPM_RC_SUCCESS);

    /* Verify auth.size = authDigestSz + authSz */
    AssertIntEQ(dev.session[0].auth.size,
        authDigestSz + (int)handle.auth.size);

    /* Verify HMAC key slot [0..authDigestSz-1] preserved */
    for (i = 0; i < authDigestSz; i++) {
        AssertIntEQ(dev.session[0].auth.buffer[i], 0xFF);
    }

    /* Verify auth at offset [authDigestSz..] */
    AssertIntEQ(XMEMCMP(&dev.session[0].auth.buffer[authDigestSz],
        handle.auth.buffer, handle.auth.size), 0);

    /* Now test wolfTPM2_SetAuthHandleName policyAuth branch */
    XMEMSET(dev.session[0].auth.buffer, 0xEE, authDigestSz);
    dev.session[0].auth.size = 0;

    rc = wolfTPM2_SetAuthHandleName(&dev, 0, &handle);
    AssertIntEQ(rc, TPM_RC_SUCCESS);

    /* Verify auth.size = authDigestSz + authSz */
    AssertIntEQ(dev.session[0].auth.size,
        authDigestSz + (int)handle.auth.size);

    /* Verify HMAC key slot [0..authDigestSz-1] preserved */
    for (i = 0; i < authDigestSz; i++) {
        AssertIntEQ(dev.session[0].auth.buffer[i], 0xEE);
    }

    /* Verify auth at offset [authDigestSz..] */
    AssertIntEQ(XMEMCMP(&dev.session[0].auth.buffer[authDigestSz],
        handle.auth.buffer, handle.auth.size), 0);

    wolfTPM2_Cleanup(&dev);

    printf("Test TPM Wrapper:\tSetAuthHandle PolicyAuth:\tPassed\n");
#endif
}

static void test_wolfTPM2_PolicyHash(void)
{
#ifndef WOLFTPM2_NO_WOLFCRYPT
    int rc;
    byte digest[TPM_SHA256_DIGEST_SIZE];
    byte digest0[TPM_SHA256_DIGEST_SIZE];
    byte digestFirst[TPM_SHA256_DIGEST_SIZE];
    word32 digestSz;
    const byte input[] = {0x01, 0x02, 0x03, 0x04};

    /* Test 1: cc=0 (no command code, used by PolicyRefMake) */
    XMEMSET(digest, 0xAA, sizeof(digest));
    digestSz = TPM_SHA256_DIGEST_SIZE;
    rc = wolfTPM2_PolicyHash(TPM_ALG_SHA256, digest, &digestSz,
        0, input, sizeof(input));
    AssertIntEQ(rc, 0);
    XMEMCPY(digest0, digest, digestSz);

    /* Test 2: cc=TPM_CC_FIRST (0x11F boundary) - must differ from cc=0 */
    XMEMSET(digest, 0xAA, sizeof(digest));
    digestSz = TPM_SHA256_DIGEST_SIZE;
    rc = wolfTPM2_PolicyHash(TPM_ALG_SHA256, digest, &digestSz,
        TPM_CC_FIRST, input, sizeof(input));
    AssertIntEQ(rc, 0);
    XMEMCPY(digestFirst, digest, digestSz);

    /* cc=0 and cc=TPM_CC_FIRST must produce different digests */
    AssertIntNE(XMEMCMP(digest0, digestFirst, digestSz), 0);

    /* Test 3: cc=TPM_CC_PolicyPCR (above boundary) - must differ from both */
    XMEMSET(digest, 0xAA, sizeof(digest));
    digestSz = TPM_SHA256_DIGEST_SIZE;
    rc = wolfTPM2_PolicyHash(TPM_ALG_SHA256, digest, &digestSz,
        TPM_CC_PolicyPCR, input, sizeof(input));
    AssertIntEQ(rc, 0);
    AssertIntNE(XMEMCMP(digest0, digest, digestSz), 0);
    AssertIntNE(XMEMCMP(digestFirst, digest, digestSz), 0);

    printf("Test TPM Wrapper:\tPolicyHash:\tPassed\n");
#else
    printf("Test TPM Wrapper:\tPolicyHash:\tSkipped\n");
#endif
}

static void test_wolfTPM2_SensitiveToPrivate(void)
{
#ifdef WOLFTPM2_PRIVATE_IMPORT
    int rc;
    TPM2B_SENSITIVE sens;
    TPM2B_PRIVATE priv;
    TPM2B_NAME name;
    TPM2B_DATA symSeed;
    TPMT_SYM_DEF_OBJECT sym;
    const byte expected[] = {
        0x00, 0x20, 0x2b, 0x59, 0xc0, 0x69, 0xf6, 0x63,
        0x7c, 0x2a, 0xe0, 0x62, 0xcf, 0x42, 0x37, 0x8b,
        0x79, 0x5d, 0xb6, 0x61, 0x4f, 0x9f, 0x93, 0x38,
        0x82, 0x06, 0x2e, 0x28, 0xbf, 0xd3, 0x5c, 0x82,
        0x1c, 0x03, 0xb5, 0x90, 0x49, 0x7a, 0x93, 0x46,
        0x31, 0x51, 0xe2, 0xdd, 0x4f, 0x0a, 0x22, 0x9b,
        0x2e, 0xd7, 0x5d, 0xc6, 0xe3, 0x97, 0xf4, 0x75,
        0xcf, 0xfd, 0xa9, 0xe9, 0xd3, 0xa4, 0x5f, 0x95,
        0xa0, 0x70, 0x2f, 0x71, 0x6c, 0xb8, 0x90, 0x39,
        0x32, 0x54, 0x91, 0x87, 0x34, 0x9b, 0xac, 0xef
    };

    /* Fixed test inputs */
    XMEMSET(&sens, 0, sizeof(sens));
    XMEMSET(&priv, 0, sizeof(priv));
    XMEMSET(&name, 0, sizeof(name));
    XMEMSET(&symSeed, 0, sizeof(symSeed));
    XMEMSET(&sym, 0, sizeof(sym));

    /* Set up a minimal sensitive area */
    sens.sensitiveArea.sensitiveType = TPM_ALG_RSA;
    sens.sensitiveArea.authValue.size = 4;
    XMEMSET(sens.sensitiveArea.authValue.buffer, 0xAA, 4);
    sens.sensitiveArea.seedValue.size = TPM_SHA256_DIGEST_SIZE;
    XMEMSET(sens.sensitiveArea.seedValue.buffer, 0xBB,
        TPM_SHA256_DIGEST_SIZE);

    /* Set up a name (hash alg + digest) */
    name.size = 2 + TPM_SHA256_DIGEST_SIZE;
    /* name[0..1] = TPM_ALG_SHA256 big-endian */
    name.name[0] = 0x00;
    name.name[1] = 0x0B; /* TPM_ALG_SHA256 */
    XMEMSET(&name.name[2], 0xCC, TPM_SHA256_DIGEST_SIZE);

    /* Set up symmetric algorithm (AES-128-CFB) */
    sym.algorithm = TPM_ALG_AES;
    sym.keyBits.sym = 128;
    sym.mode.sym = TPM_ALG_CFB;

    /* Set up a symmetric seed (triggers outer wrap / KDFa) */
    symSeed.size = TPM_SHA256_DIGEST_SIZE;
    XMEMSET(symSeed.buffer, 0xDD, TPM_SHA256_DIGEST_SIZE);

    /* Expected output - pins KDFa "STORAGE" and "INTEGRITY" labels.
     * Bytes 0-1: integrity size (0x0020 = 32),
     * Bytes 2-33: HMAC integrity (via "INTEGRITY" label KDFa),
     * Bytes 34-79: AES-CFB encrypted sensitive (via "STORAGE" label KDFa) */
    rc = wolfTPM2_SensitiveToPrivate(&sens, &priv,
        TPM_ALG_SHA256, &name, NULL, &sym, &symSeed);
    AssertIntEQ(rc, 0);
    AssertIntEQ(priv.size, (int)sizeof(expected));
    AssertIntEQ(XMEMCMP(priv.buffer, expected, sizeof(expected)), 0);

    printf("Test TPM Wrapper:\tSensitiveToPrivate:\tPassed\n");
#else
    printf("Test TPM Wrapper:\tSensitiveToPrivate:\tSkipped\n");
#endif
}

static void test_TPM2_KDFa_SessionLabels(void)
{
#ifndef WOLFTPM2_NO_WOLFCRYPT
    int rc;
    #define TEST_KDFA_LABEL_KEYSZ TPM_SHA256_DIGEST_SIZE
    TPM2B_DATA keyIn = {
        .size = 16,
        .buffer = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                   0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}
    };
    TPM2B_NONCE nonceTPM = {
        .size = 16,
        .buffer = {0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8,
                   0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0}
    };
    TPM2B_NONCE nonceCaller = {
        .size = 16,
        .buffer = {0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8,
                   0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0}
    };
    byte key[TEST_KDFA_LABEL_KEYSZ];

    /* Test "ATH" label (session key derivation, TPM 2.0 Part 1 s19.6.8) */
    {
        const byte expATH[] = {
            0x0d, 0x17, 0x5f, 0xf7, 0xac, 0xf9, 0x41, 0x9a,
            0x73, 0x75, 0x7c, 0xa6, 0x42, 0x82, 0x49, 0x61,
            0xa2, 0xc9, 0x72, 0xd9, 0x13, 0xdc, 0xbf, 0x72,
            0x06, 0xe6, 0x73, 0xe7, 0x21, 0x5f, 0x99, 0x6a
        };
        rc = TPM2_KDFa(TPM_ALG_SHA256, &keyIn, "ATH", &nonceTPM, &nonceCaller,
            key, TEST_KDFA_LABEL_KEYSZ);
        AssertIntEQ(TEST_KDFA_LABEL_KEYSZ, rc);
        AssertIntEQ(XMEMCMP(key, expATH, sizeof(expATH)), 0);
    }

    /* Test "SECRET" label (salt encryption, TPM 2.0 Part 1 s19.6.8) */
    {
        const byte expSECRET[] = {
            0x1a, 0xc4, 0xc1, 0x34, 0x78, 0x87, 0x67, 0x5e,
            0x91, 0xd1, 0xa2, 0xcd, 0xcb, 0xac, 0xdb, 0x62,
            0xed, 0x4e, 0xfe, 0x44, 0xed, 0x52, 0x34, 0x3b,
            0xf1, 0x87, 0xfb, 0x8b, 0xa9, 0xec, 0x43, 0x59
        };
        rc = TPM2_KDFa(TPM_ALG_SHA256, &keyIn, "SECRET", &nonceTPM, &nonceCaller,
            key, TEST_KDFA_LABEL_KEYSZ);
        AssertIntEQ(TEST_KDFA_LABEL_KEYSZ, rc);
        AssertIntEQ(XMEMCMP(key, expSECRET, sizeof(expSECRET)), 0);
    }

    /* Test "DUPLICATE" label (key import, TPM 2.0 Part 1 s23.3) */
    {
        const byte expDUPLICATE[] = {
            0xa3, 0xe5, 0x57, 0xc6, 0x49, 0x4c, 0xe5, 0x4f,
            0x45, 0xae, 0xf7, 0x19, 0x4d, 0x9e, 0x21, 0xa2,
            0x91, 0xeb, 0x05, 0x2d, 0x43, 0x06, 0x9f, 0xfb,
            0x69, 0x67, 0x1f, 0x99, 0x00, 0xb0, 0xcc, 0x39
        };
        rc = TPM2_KDFa(TPM_ALG_SHA256, &keyIn, "DUPLICATE", &nonceTPM, &nonceCaller,
            key, TEST_KDFA_LABEL_KEYSZ);
        AssertIntEQ(TEST_KDFA_LABEL_KEYSZ, rc);
        AssertIntEQ(XMEMCMP(key, expDUPLICATE, sizeof(expDUPLICATE)), 0);
    }

    printf("Test TPM Wrapper:\tKDFa Session Labels:\tPassed\n");
#else
    printf("Test TPM Wrapper:\tKDFa Session Labels:\tSkipped\n");
#endif
}

static void test_wolfTPM2_EncryptSecret(void)
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY tpmKey;
    TPM2B_DATA data;
    TPM2B_ENCRYPTED_SECRET secret;

    XMEMSET(&tpmKey, 0, sizeof(tpmKey));
    XMEMSET(&data, 0, sizeof(data));
    XMEMSET(&secret, 0, sizeof(secret));

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, NULL);
    AssertIntEQ(rc, 0);

    /* Test NULL tpmKey returns success (unsalted session) */
    rc = wolfTPM2_EncryptSecret(&dev, NULL, &data, &secret, "SECRET");
    AssertIntEQ(rc, TPM_RC_SUCCESS);

    /* Test NULL dev returns BAD_FUNC_ARG */
    rc = wolfTPM2_EncryptSecret(NULL, &tpmKey, &data, &secret, "SECRET");
    AssertIntEQ(rc, BAD_FUNC_ARG);

    /* Test NULL data returns BAD_FUNC_ARG */
    rc = wolfTPM2_EncryptSecret(&dev, &tpmKey, NULL, &secret, "SECRET");
    AssertIntEQ(rc, BAD_FUNC_ARG);

    /* Test NULL secret returns BAD_FUNC_ARG */
    rc = wolfTPM2_EncryptSecret(&dev, &tpmKey, &data, NULL, "SECRET");
    AssertIntEQ(rc, BAD_FUNC_ARG);

    wolfTPM2_Cleanup(&dev);

    printf("Test TPM Wrapper:\tEncryptSecret:\t%s\n",
        rc == BAD_FUNC_ARG ? "Passed" : "Failed");
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

#ifndef WOLFTPM2_NO_HEAP
    /* Test Free functions handle NULL safely (security fix) */
    rc = wolfTPM2_FreeKeyBlob(NULL);
    AssertIntEQ(rc, TPM_RC_SUCCESS);

    rc = wolfTPM2_FreeKey(NULL);
    AssertIntEQ(rc, TPM_RC_SUCCESS);

    rc = wolfTPM2_FreeSession(NULL);
    AssertIntEQ(rc, TPM_RC_SUCCESS);

    rc = wolfTPM2_FreePublicTemplate(NULL);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
#endif

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

    rc = TPM2_KDFa_ex(TPM_ALG_SHA256, keyIn.buffer, keyIn.size, label,
        contextU.buffer, contextU.size, contextV.buffer, contextV.size,
        key, keyIn.size);
#ifdef WOLFTPM2_NO_WOLFCRYPT
    AssertIntEQ(NOT_COMPILED_IN, rc);
#else
    AssertIntEQ(sizeof(keyExp), rc);
    AssertIntEQ(XMEMCMP(key, keyExp, sizeof(keyExp)), 0);
#endif

    printf("Test TPM Wrapper:\tKDFa:\t%s\n",
        rc >= 0 ? "Passed" : "Failed");
}

static void test_TPM2_KDFe(void)
{
    int rc;
    enum { TEST_KDFE_KEYSZ = 32 };
    /* Use a simple known Z, label, and party info */
    const byte Z[TEST_KDFE_KEYSZ] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20};
    const char label[] = "IDENTITY";
    const byte partyU[8] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11};
    const byte partyV[8] = {0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99};
    byte key[TEST_KDFE_KEYSZ];
#ifndef WOLFTPM2_NO_WOLFCRYPT
    byte key2[TEST_KDFE_KEYSZ];
#endif

    rc = TPM2_KDFe_ex(TPM_ALG_SHA256, Z, sizeof(Z), label,
        partyU, sizeof(partyU), partyV, sizeof(partyV),
        key, sizeof(key));
#ifdef WOLFTPM2_NO_WOLFCRYPT
    AssertIntEQ(NOT_COMPILED_IN, rc);
#else
    AssertIntEQ((int)sizeof(key), rc);
    /* Verify deterministic: same inputs produce same output */
    rc = TPM2_KDFe_ex(TPM_ALG_SHA256, Z, sizeof(Z), label,
        partyU, sizeof(partyU), partyV, sizeof(partyV),
        key2, sizeof(key2));
    AssertIntEQ((int)sizeof(key2), rc);
    AssertIntEQ(0, XMEMCMP(key, key2, sizeof(key)));
#endif

    printf("Test TPM Wrapper:\tKDFe:\t%s\n",
        rc >= 0 ? "Passed" : "Failed");
}

static void test_TPM2_HmacCompute(void)
{
#ifndef WOLFTPM2_NO_WOLFCRYPT
    int rc;
    /* RFC 4231 Test Case 2: HMAC-SHA256 with "Jefe" key and "what do ya want
     * for nothing?" data */
    const byte hmacKey[] = "Jefe";
    const byte hmacData[] = "what do ya want for nothing?";
    const byte hmacExp[] = {
        0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
        0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
        0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
        0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43};
    byte digest[TPM_MAX_DIGEST_SIZE];
    word32 digestSz = sizeof(digest);

    rc = TPM2_HmacCompute(TPM_ALG_SHA256,
        hmacKey, 4, /* "Jefe" without null terminator */
        hmacData, 28, /* "what do ya want for nothing?" without null */
        NULL, 0,
        digest, &digestSz);
    AssertIntEQ(0, rc);
    AssertIntEQ(32, (int)digestSz);
    AssertIntEQ(0, XMEMCMP(digest, hmacExp, sizeof(hmacExp)));

    /* Test HmacVerify with correct expected value */
    rc = TPM2_HmacVerify(TPM_ALG_SHA256,
        hmacKey, 4, hmacData, 28, NULL, 0,
        hmacExp, sizeof(hmacExp));
    AssertIntEQ(0, rc);

    /* Test HmacVerify with wrong expected value */
    digest[0] ^= 0xFF;
    rc = TPM2_HmacVerify(TPM_ALG_SHA256,
        hmacKey, 4, hmacData, 28, NULL, 0,
        digest, digestSz);
    AssertIntEQ(TPM_RC_INTEGRITY, rc);

    printf("Test TPM Wrapper:\tHmacCompute:\tPassed\n");
#else
    printf("Test TPM Wrapper:\tHmacCompute:\tSkipped\n");
#endif
}

static void test_TPM2_HashCompute(void)
{
#ifndef WOLFTPM2_NO_WOLFCRYPT
    int rc;
    /* SHA-256 of empty string */
    const byte hashExp[] = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};
    byte digest[TPM_MAX_DIGEST_SIZE];
    word32 digestSz = sizeof(digest);

    rc = TPM2_HashCompute(TPM_ALG_SHA256,
        (const byte*)"", 0,
        digest, &digestSz);
    AssertIntEQ(0, rc);
    AssertIntEQ(32, (int)digestSz);
    AssertIntEQ(XMEMCMP(digest, hashExp, sizeof(hashExp)), 0);

    printf("Test TPM Wrapper:\tHashCompute:\tPassed\n");
#else
    printf("Test TPM Wrapper:\tHashCompute:\tSkipped\n");
#endif
}

static void test_TPM2_ConstantCompare(void)
{
    const byte a[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    const byte b[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    const byte c[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x09};
    const byte d[] = {0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8};

    /* Identical buffers must return 0 */
    AssertIntEQ(0, TPM2_ConstantCompare(a, b, sizeof(a)));

    /* Single-byte difference must return non-zero */
    AssertIntNE(0, TPM2_ConstantCompare(a, c, sizeof(a)));

    /* Completely different buffers must return non-zero */
    AssertIntNE(0, TPM2_ConstantCompare(a, d, sizeof(a)));

    /* Zero length must return 0 (no bytes to compare) */
    AssertIntEQ(0, TPM2_ConstantCompare(a, d, 0));

    printf("Test TPM Wrapper:\tConstantCompare:\tPassed\n");
}

static void test_TPM2_AesCfbRoundtrip(void)
{
#if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_AES) && \
    defined(WOLFSSL_AES_CFB)
    int rc;
    int i;
    const int keySizes[3] = {16, 24, 32};
    byte key[32];
    byte iv[16];
    byte pt[64];
    byte ct[64];

    XMEMSET(key, 0xA5, sizeof(key));
    XMEMSET(iv,  0x5A, sizeof(iv));
    for (i = 0; i < (int)sizeof(pt); i++) {
        pt[i] = (byte)i;
    }

    /* Encrypt -> decrypt round trip for each supported key size */
    for (i = 0; i < 3; i++) {
        XMEMCPY(ct, pt, sizeof(pt));
        rc = TPM2_AesCfbEncrypt(key, keySizes[i], iv, ct, sizeof(ct));
        AssertIntEQ(0, rc);
        AssertIntNE(0, XMEMCMP(ct, pt, sizeof(pt)));
        rc = TPM2_AesCfbDecrypt(key, keySizes[i], iv, ct, sizeof(ct));
        AssertIntEQ(0, rc);
        AssertIntEQ(0, XMEMCMP(ct, pt, sizeof(pt)));
    }

    /* NULL-IV path must be accepted (zero-fill default) */
    XMEMCPY(ct, pt, sizeof(pt));
    rc = TPM2_AesCfbEncrypt(key, 16, NULL, ct, sizeof(ct));
    AssertIntEQ(0, rc);
    rc = TPM2_AesCfbDecrypt(key, 16, NULL, ct, sizeof(ct));
    AssertIntEQ(0, rc);
    AssertIntEQ(0, XMEMCMP(ct, pt, sizeof(pt)));

    /* Reject invalid key size */
    rc = TPM2_AesCfbEncrypt(key, 15, iv, ct, sizeof(ct));
    AssertIntNE(0, rc);
    rc = TPM2_AesCfbDecrypt(key, 15, iv, ct, sizeof(ct));
    AssertIntNE(0, rc);

    printf("Test TPM Wrapper:\tAesCfbRoundtrip:\tPassed\n");
#else
    printf("Test TPM Wrapper:\tAesCfbRoundtrip:\tSkipped\n");
#endif
}

/* Cover KDFa multi-iteration loop (keySz > hash digest size) and
 * SHA-384 / SHA-512 code paths, with non-empty context inputs. */
static void test_TPM2_KDFa_MultiHash(void)
{
#ifndef WOLFTPM2_NO_WOLFCRYPT
    int rc;
    size_t iAlg;
    size_t iSz;
    const UINT32 sizes[] = {1, 31, 32, 33, 64, 96};
    const byte keyIn[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};
    const char label[] = "MULTIHASHLABEL";
    const byte ctxU[8] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11};
    const byte ctxV[8] = {0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99};
    static const TPM_ALG_ID algs[] = {
        TPM_ALG_SHA256,
#ifdef WOLFSSL_SHA384
        TPM_ALG_SHA384,
#endif
#ifdef WOLFSSL_SHA512
        TPM_ALG_SHA512,
#endif
    };
    byte key1[96];
    byte key2[96];

    for (iAlg = 0; iAlg < sizeof(algs)/sizeof(algs[0]); iAlg++) {
        for (iSz = 0; iSz < sizeof(sizes)/sizeof(sizes[0]); iSz++) {
            UINT32 sz = sizes[iSz];
            rc = TPM2_KDFa_ex(algs[iAlg], keyIn, sizeof(keyIn), label,
                ctxU, sizeof(ctxU), ctxV, sizeof(ctxV), key1, sz);
            AssertIntEQ((int)sz, rc);
            rc = TPM2_KDFa_ex(algs[iAlg], keyIn, sizeof(keyIn), label,
                ctxU, sizeof(ctxU), ctxV, sizeof(ctxV), key2, sz);
            AssertIntEQ((int)sz, rc);
            AssertIntEQ(0, XMEMCMP(key1, key2, sz));
        }
    }

    printf("Test TPM Wrapper:\tKDFa multi-hash:\tPassed\n");
#else
    printf("Test TPM Wrapper:\tKDFa multi-hash:\tSkipped\n");
#endif
}

static void test_TPM2_KDFe_MultiHash(void)
{
#ifndef WOLFTPM2_NO_WOLFCRYPT
    int rc;
    size_t iAlg;
    size_t iSz;
    const UINT32 sizes[] = {1, 31, 32, 33, 64, 96};
    const byte Z[32] = {
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F};
    const char label[] = "IDENTITY";
    const byte partyU[8] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};
    const byte partyV[8] = {0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87};
    static const TPM_ALG_ID algs[] = {
        TPM_ALG_SHA256,
#ifdef WOLFSSL_SHA384
        TPM_ALG_SHA384,
#endif
#ifdef WOLFSSL_SHA512
        TPM_ALG_SHA512,
#endif
    };
    byte key1[96];
    byte key2[96];

    for (iAlg = 0; iAlg < sizeof(algs)/sizeof(algs[0]); iAlg++) {
        for (iSz = 0; iSz < sizeof(sizes)/sizeof(sizes[0]); iSz++) {
            UINT32 sz = sizes[iSz];
            rc = TPM2_KDFe_ex(algs[iAlg], Z, sizeof(Z), label,
                partyU, sizeof(partyU), partyV, sizeof(partyV), key1, sz);
            AssertIntEQ((int)sz, rc);
            rc = TPM2_KDFe_ex(algs[iAlg], Z, sizeof(Z), label,
                partyU, sizeof(partyU), partyV, sizeof(partyV), key2, sz);
            AssertIntEQ((int)sz, rc);
            AssertIntEQ(0, XMEMCMP(key1, key2, sz));
        }
    }

    printf("Test TPM Wrapper:\tKDFe multi-hash:\tPassed\n");
#else
    printf("Test TPM Wrapper:\tKDFe multi-hash:\tSkipped\n");
#endif
}

/* Exercise HmacCompute concat path (data2 != NULL) and multi-hash
 * branches. Reference result is computed by feeding the same bytes in
 * one call (data1 || data2) and comparing. */
static void test_TPM2_HmacCompute_MultiHash(void)
{
#if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_HMAC)
    int rc;
    size_t iAlg;
    static const TPM_ALG_ID algs[] = {
        TPM_ALG_SHA256,
#ifdef WOLFSSL_SHA384
        TPM_ALG_SHA384,
#endif
#ifdef WOLFSSL_SHA512
        TPM_ALG_SHA512,
#endif
    };
    const byte hmacKey[16] = {
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
        0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0x01};
    const byte data1[] = "concat-HMAC-left-half";
    const byte data2[] = "concat-HMAC-right-half";
    byte full[sizeof(data1) - 1 + sizeof(data2) - 1];
    byte d_split[TPM_MAX_DIGEST_SIZE];
    byte d_full[TPM_MAX_DIGEST_SIZE];
    word32 splitSz;
    word32 fullSz;

    XMEMCPY(full, data1, sizeof(data1) - 1);
    XMEMCPY(full + sizeof(data1) - 1, data2, sizeof(data2) - 1);

    for (iAlg = 0; iAlg < sizeof(algs)/sizeof(algs[0]); iAlg++) {
        splitSz = sizeof(d_split);
        fullSz = sizeof(d_full);
        rc = TPM2_HmacCompute(algs[iAlg], hmacKey, sizeof(hmacKey),
            data1, sizeof(data1) - 1,
            data2, sizeof(data2) - 1,
            d_split, &splitSz);
        AssertIntEQ(0, rc);
        rc = TPM2_HmacCompute(algs[iAlg], hmacKey, sizeof(hmacKey),
            full, sizeof(full),
            NULL, 0,
            d_full, &fullSz);
        AssertIntEQ(0, rc);
        AssertIntEQ((int)fullSz, (int)splitSz);
        AssertIntEQ(0, XMEMCMP(d_split, d_full, splitSz));
    }

    printf("Test TPM Wrapper:\tHmacCompute multi-hash:\tPassed\n");
#else
    printf("Test TPM Wrapper:\tHmacCompute multi-hash:\tSkipped\n");
#endif
}

static void test_TPM2_HashCompute_MultiHash(void)
{
#ifndef WOLFTPM2_NO_WOLFCRYPT
    int rc;
    size_t i;
    static const struct { TPM_ALG_ID alg; int dsz; } cases[] = {
        { TPM_ALG_SHA256, 32 },
#ifdef WOLFSSL_SHA384
        { TPM_ALG_SHA384, 48 },
#endif
#ifdef WOLFSSL_SHA512
        { TPM_ALG_SHA512, 64 },
#endif
    };
    const byte msg[] = "wolfTPM-unit-test-hash";
    byte d1[TPM_MAX_DIGEST_SIZE];
    byte d2[TPM_MAX_DIGEST_SIZE];
    word32 sz1;
    word32 sz2;

    for (i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
        sz1 = sizeof(d1);
        sz2 = sizeof(d2);
        rc = TPM2_HashCompute(cases[i].alg, msg, sizeof(msg) - 1, d1, &sz1);
        AssertIntEQ(0, rc);
        AssertIntEQ(cases[i].dsz, (int)sz1);
        rc = TPM2_HashCompute(cases[i].alg, msg, sizeof(msg) - 1, d2, &sz2);
        AssertIntEQ(0, rc);
        AssertIntEQ(0, XMEMCMP(d1, d2, sz1));
    }

    printf("Test TPM Wrapper:\tHashCompute multi-hash:\tPassed\n");
#else
    printf("Test TPM Wrapper:\tHashCompute multi-hash:\tSkipped\n");
#endif
}

/* Negative / input-validation coverage for KDFa_ex and KDFe_ex. */
static void test_TPM2_KDF_Errors(void)
{
#ifndef WOLFTPM2_NO_WOLFCRYPT
    int rc;
    byte key[32];
    const byte buf[16] = {0};
    const char label[] = "LABEL";

    /* KDFa: NULL key returns BAD_FUNC_ARG */
    rc = TPM2_KDFa_ex(TPM_ALG_SHA256, buf, sizeof(buf), label,
        NULL, 0, NULL, 0, NULL, sizeof(key));
    AssertIntEQ(BAD_FUNC_ARG, rc);

    /* KDFa: unsupported hash returns NOT_COMPILED_IN */
    rc = TPM2_KDFa_ex(TPM_ALG_NULL, buf, sizeof(buf), label,
        NULL, 0, NULL, 0, key, sizeof(key));
    AssertIntEQ(NOT_COMPILED_IN, rc);

    /* KDFe: NULL key returns BAD_FUNC_ARG */
    rc = TPM2_KDFe_ex(TPM_ALG_SHA256, buf, sizeof(buf), label,
        NULL, 0, NULL, 0, NULL, sizeof(key));
    AssertIntEQ(BAD_FUNC_ARG, rc);

    /* KDFe: NULL Z returns BAD_FUNC_ARG */
    rc = TPM2_KDFe_ex(TPM_ALG_SHA256, NULL, 0, label,
        NULL, 0, NULL, 0, key, sizeof(key));
    AssertIntEQ(BAD_FUNC_ARG, rc);

    /* KDFe: unsupported hash returns NOT_COMPILED_IN */
    rc = TPM2_KDFe_ex(TPM_ALG_NULL, buf, sizeof(buf), label,
        NULL, 0, NULL, 0, key, sizeof(key));
    AssertIntEQ(NOT_COMPILED_IN, rc);

    printf("Test TPM Wrapper:\tKDF error paths:\tPassed\n");
#else
    printf("Test TPM Wrapper:\tKDF error paths:\tSkipped\n");
#endif
}

/* Round-trip TPM2_GetHashType -> TPM2_GetTpmHashType for each TPM
 * hash algorithm compiled into wolfCrypt. Unknown inputs map to
 * TPM_ALG_ERROR. */
static void test_TPM2_GetTpmHashType(void)
{
#ifndef WOLFTPM2_NO_WOLFCRYPT
    static const TPMI_ALG_HASH algs[] = {
#ifndef NO_SHA
        TPM_ALG_SHA1,
#endif
        TPM_ALG_SHA256,
#ifdef WOLFSSL_SHA384
        TPM_ALG_SHA384,
#endif
#ifdef WOLFSSL_SHA512
        TPM_ALG_SHA512,
#endif
    };
    size_t i;
    int wcType;
    TPMI_ALG_HASH roundTrip;

    for (i = 0; i < sizeof(algs)/sizeof(algs[0]); i++) {
        wcType = TPM2_GetHashType(algs[i]);
        AssertIntNE((int)WC_HASH_TYPE_NONE, wcType);
        roundTrip = TPM2_GetTpmHashType(wcType);
        AssertIntEQ(algs[i], roundTrip);
    }

    /* Unknown wolfCrypt hash type returns TPM_ALG_ERROR */
    AssertIntEQ(TPM_ALG_ERROR, TPM2_GetTpmHashType(0xFFFF));

    printf("Test TPM Wrapper:\tGetTpmHashType:\tPassed\n");
#else
    printf("Test TPM Wrapper:\tGetTpmHashType:\tSkipped\n");
#endif
}

static void test_TPM2_ResponseHmacVerification(void)
{
#if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_HMAC)
    int rc;
    TPM2B_AUTH auth;
    TPM2B_DIGEST hash;
    TPM2B_NONCE nonceNew, nonceOld;
    TPMA_SESSION sessionAttr = TPMA_SESSION_continueSession;
    TPM2B_AUTH hmac1, hmac2;

    /* Set up known auth key */
    auth.size = 8;
    XMEMSET(auth.buffer, 0xAA, auth.size);

    /* Set up known cpHash/rpHash */
    hash.size = TPM_SHA256_DIGEST_SIZE;
    XMEMSET(hash.buffer, 0x55, hash.size);

    /* Set up nonces */
    nonceNew.size = TPM_SHA256_DIGEST_SIZE;
    XMEMSET(nonceNew.buffer, 0x11, nonceNew.size);
    nonceOld.size = TPM_SHA256_DIGEST_SIZE;
    XMEMSET(nonceOld.buffer, 0x22, nonceOld.size);

    /* Compute valid HMAC */
    rc = TPM2_CalcHmac(TPM_ALG_SHA256, &auth, &hash, &nonceNew, &nonceOld,
        sessionAttr, &hmac1);
    AssertIntEQ(0, rc);
    AssertIntGT(hmac1.size, 0);

    /* Compute same HMAC again — must be identical */
    rc = TPM2_CalcHmac(TPM_ALG_SHA256, &auth, &hash, &nonceNew, &nonceOld,
        sessionAttr, &hmac2);
    AssertIntEQ(0, rc);
    AssertIntEQ(0, TPM2_ConstantCompare(hmac1.buffer, hmac2.buffer,
        hmac1.size));

    /* Tamper one byte of the HMAC — verification must detect mismatch */
    hmac2.buffer[0] ^= 0xFF;
    AssertIntNE(0, TPM2_ConstantCompare(hmac1.buffer, hmac2.buffer,
        hmac1.size));

    printf("Test TPM Wrapper:\tResponseHmacVerification:\tPassed\n");
#endif
}

static void test_TPM2_CalcHmac(void)
{
#if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_HMAC)
    int rc;
    TPM2B_AUTH auth;
    TPM2B_DIGEST hash;
    TPM2B_NONCE nonceA, nonceB;
    TPMA_SESSION attr = TPMA_SESSION_continueSession;
    TPM2B_AUTH hmac1, hmac2;

    /* Known auth key */
    auth.size = 4;
    auth.buffer[0] = 't'; auth.buffer[1] = 'e';
    auth.buffer[2] = 's'; auth.buffer[3] = 't';

    /* Known cpHash */
    hash.size = TPM_SHA256_DIGEST_SIZE;
    XMEMSET(hash.buffer, 0xAB, hash.size);

    /* Two distinct nonces */
    nonceA.size = TPM_SHA256_DIGEST_SIZE;
    XMEMSET(nonceA.buffer, 0x11, nonceA.size);
    nonceB.size = TPM_SHA256_DIGEST_SIZE;
    XMEMSET(nonceB.buffer, 0x22, nonceB.size);

    /* Compute HMAC with (nonceA, nonceB) order */
    rc = TPM2_CalcHmac(TPM_ALG_SHA256, &auth, &hash, &nonceA, &nonceB,
        attr, &hmac1);
    AssertIntEQ(0, rc);

    /* Compute HMAC with (nonceB, nonceA) — reversed order */
    rc = TPM2_CalcHmac(TPM_ALG_SHA256, &auth, &hash, &nonceB, &nonceA,
        attr, &hmac2);
    AssertIntEQ(0, rc);

    /* Reversed nonces MUST produce different HMAC */
    AssertIntNE(0, XMEMCMP(hmac1.buffer, hmac2.buffer, hmac1.size));

    printf("Test TPM Wrapper:\tCalcHmac:\tPassed\n");
#endif
}

static void test_TPM2_ParamEnc_XOR_Vector(void)
{
#ifndef WOLFTPM2_NO_WOLFCRYPT
    int rc;
    TPMI_ALG_HASH authHash = TPM_ALG_SHA256;
    TPM2B_AUTH sessKey;
    TPM2B_NONCE nonceCaller, nonceTPM;
    const byte original[] = "XOR parameter encryption round-trip test";
    byte data[sizeof(original)];

    sessKey.size = TPM_SHA256_DIGEST_SIZE;
    XMEMSET(sessKey.buffer, 0xCC, sessKey.size);

    nonceCaller.size = TPM_SHA256_DIGEST_SIZE;
    XMEMSET(nonceCaller.buffer, 0x11, nonceCaller.size);
    nonceTPM.size = TPM_SHA256_DIGEST_SIZE;
    XMEMSET(nonceTPM.buffer, 0x22, nonceTPM.size);

    XMEMCPY(data, original, sizeof(original));

    /* Encrypt */
    rc = TPM2_ParamEnc_XOR(authHash, sessKey.buffer, sessKey.size,
        nonceCaller.buffer, nonceCaller.size,
        nonceTPM.buffer, nonceTPM.size,
        data, sizeof(data));
    AssertIntEQ(TPM_RC_SUCCESS, rc);

    /* Data must differ from original */
    AssertIntNE(0, XMEMCMP(data, original, sizeof(original)));

    /* Encrypt again with same args — XOR is self-inverse */
    rc = TPM2_ParamEnc_XOR(authHash, sessKey.buffer, sessKey.size,
        nonceCaller.buffer, nonceCaller.size,
        nonceTPM.buffer, nonceTPM.size,
        data, sizeof(data));
    AssertIntEQ(TPM_RC_SUCCESS, rc);

    /* Must match original */
    AssertIntEQ(0, XMEMCMP(data, original, sizeof(original)));

    printf("Test TPM Wrapper:\tParamEnc_XOR:\tPassed\n");
#endif
}

static void test_TPM2_ParamEnc_AESCFB_Vector(void)
{
#if !defined(WOLFTPM2_NO_WOLFCRYPT) && defined(WOLFSSL_AES_CFB)
    int rc;
    TPMI_ALG_HASH authHash = TPM_ALG_SHA256;
    UINT16 keyBits = MAX_AES_KEY_BITS;
    TPM2B_AUTH sessKey;
    TPM2B_NONCE nonceCaller, nonceTPM;
    const byte original[] = "AES-CFB parameter encryption round-trip test";
    byte data[sizeof(original)];

    sessKey.size = TPM_SHA256_DIGEST_SIZE;
    XMEMSET(sessKey.buffer, 0xDD, sessKey.size);

    nonceCaller.size = TPM_SHA256_DIGEST_SIZE;
    XMEMSET(nonceCaller.buffer, 0x33, nonceCaller.size);
    nonceTPM.size = TPM_SHA256_DIGEST_SIZE;
    XMEMSET(nonceTPM.buffer, 0x44, nonceTPM.size);

    XMEMCPY(data, original, sizeof(original));

    /* Encrypt with (nonceCaller, nonceTPM) */
    rc = TPM2_ParamEnc_AESCFB(authHash, keyBits,
        sessKey.buffer, sessKey.size,
        nonceCaller.buffer, nonceCaller.size,
        nonceTPM.buffer, nonceTPM.size,
        data, sizeof(data), 1);
    AssertIntEQ(TPM_RC_SUCCESS, rc);

    /* Data must differ from original */
    AssertIntNE(0, XMEMCMP(data, original, sizeof(original)));

    /* Decrypt: same nonce order, doEncrypt=0 */
    rc = TPM2_ParamEnc_AESCFB(authHash, keyBits,
        sessKey.buffer, sessKey.size,
        nonceCaller.buffer, nonceCaller.size,
        nonceTPM.buffer, nonceTPM.size,
        data, sizeof(data), 0);
    AssertIntEQ(TPM_RC_SUCCESS, rc);

    /* Must match original */
    AssertIntEQ(0, XMEMCMP(data, original, sizeof(original)));

    printf("Test TPM Wrapper:\tParamEnc_AESCFB:\tPassed\n");
#endif
}

static void test_TPM2_ParamDec_XOR_Roundtrip(void)
{
#ifndef WOLFTPM2_NO_WOLFCRYPT
    int rc;
    TPMI_ALG_HASH authHash = TPM_ALG_SHA256;
    TPM2B_AUTH sessKey;
    TPM2B_NONCE nonceCaller, nonceTPM;
    const byte original[] = "XOR parameter decryption round-trip test";
    byte data[sizeof(original)];

    sessKey.size = TPM_SHA256_DIGEST_SIZE;
    XMEMSET(sessKey.buffer, 0xEE, sessKey.size);

    nonceCaller.size = TPM_SHA256_DIGEST_SIZE;
    XMEMSET(nonceCaller.buffer, 0x55, nonceCaller.size);
    nonceTPM.size = TPM_SHA256_DIGEST_SIZE;
    XMEMSET(nonceTPM.buffer, 0x66, nonceTPM.size);

    XMEMCPY(data, original, sizeof(original));

    /* Decrypt direction uses (nonceTPM, nonceCaller) order. XOR is symmetric
     * so the same TPM2_ParamEnc_XOR call performs decryption. */
    rc = TPM2_ParamEnc_XOR(authHash, sessKey.buffer, sessKey.size,
        nonceTPM.buffer, nonceTPM.size,
        nonceCaller.buffer, nonceCaller.size,
        data, sizeof(data));
    AssertIntEQ(TPM_RC_SUCCESS, rc);

    /* Data must differ from original */
    AssertIntNE(0, XMEMCMP(data, original, sizeof(original)));

    /* Apply same XOR again — self-inverse recovers original */
    rc = TPM2_ParamEnc_XOR(authHash, sessKey.buffer, sessKey.size,
        nonceTPM.buffer, nonceTPM.size,
        nonceCaller.buffer, nonceCaller.size,
        data, sizeof(data));
    AssertIntEQ(TPM_RC_SUCCESS, rc);

    /* Must match original */
    AssertIntEQ(0, XMEMCMP(data, original, sizeof(original)));

    printf("Test TPM Wrapper:\tParamDec_XOR_Roundtrip:\tPassed\n");
#endif
}

static void test_TPM2_ParamDec_AESCFB_Roundtrip(void)
{
#if !defined(WOLFTPM2_NO_WOLFCRYPT) && defined(WOLFSSL_AES_CFB)
    int rc;
    TPMI_ALG_HASH authHash = TPM_ALG_SHA256;
    UINT16 keyBits = MAX_AES_KEY_BITS;
    TPM2B_AUTH sessKey;
    TPM2B_NONCE nonceCaller, nonceTPM;
    const byte original[] = "AES-CFB parameter decryption round-trip test";
    byte data[sizeof(original)];

    sessKey.size = TPM_SHA256_DIGEST_SIZE;
    XMEMSET(sessKey.buffer, 0xFF, sessKey.size);

    nonceCaller.size = TPM_SHA256_DIGEST_SIZE;
    XMEMSET(nonceCaller.buffer, 0x77, nonceCaller.size);
    nonceTPM.size = TPM_SHA256_DIGEST_SIZE;
    XMEMSET(nonceTPM.buffer, 0x88, nonceTPM.size);

    XMEMCPY(data, original, sizeof(original));

    /* Encrypt: command direction uses (nonceCaller, nonceTPM), doEncrypt=1 */
    rc = TPM2_ParamEnc_AESCFB(authHash, keyBits,
        sessKey.buffer, sessKey.size,
        nonceCaller.buffer, nonceCaller.size,
        nonceTPM.buffer, nonceTPM.size,
        data, sizeof(data), 1);
    AssertIntEQ(TPM_RC_SUCCESS, rc);

    /* Data must differ from original */
    AssertIntNE(0, XMEMCMP(data, original, sizeof(original)));

    /* Decrypt: same nonce order so KDFa produces the same key, doEncrypt=0 */
    rc = TPM2_ParamEnc_AESCFB(authHash, keyBits,
        sessKey.buffer, sessKey.size,
        nonceCaller.buffer, nonceCaller.size,
        nonceTPM.buffer, nonceTPM.size,
        data, sizeof(data), 0);
    AssertIntEQ(TPM_RC_SUCCESS, rc);

    /* Must match original */
    AssertIntEQ(0, XMEMCMP(data, original, sizeof(original)));

    printf("Test TPM Wrapper:\tParamDec_AESCFB_Roundtrip:\tPassed\n");
#endif
}

/* Test dispatch-level CmdRequest/CmdResponse nonce mapping.
 * Command direction: host encrypts with KDFa(nonceCaller, nonceTPM).
 * Response direction: TPM encrypts with KDFa(nonceTPM, nonceCaller),
 * so host decryption (CmdResponse) must derive the same key.
 * We simulate the TPM's response encryption using the standalone function
 * with the response-direction nonce order, then verify CmdResponse decrypts. */
static void test_TPM2_ParamEncDec_Dispatch_Roundtrip(void)
{
#if !defined(WOLFTPM2_NO_WOLFCRYPT) && defined(WOLFSSL_AES_CFB)
    int rc;
    TPM2_AUTH_SESSION session;
    const byte original[] = "Dispatch-level param enc/dec roundtrip test data";
    byte data[sizeof(original)];

    /* Set up session with distinct nonces to catch any swap mutation */
    XMEMSET(&session, 0, sizeof(session));
    session.authHash = TPM_ALG_SHA256;
    session.symmetric.algorithm = TPM_ALG_AES;
    session.symmetric.keyBits.aes = MAX_AES_KEY_BITS;
    session.symmetric.mode.aes = TPM_ALG_CFB;

    session.auth.size = TPM_SHA256_DIGEST_SIZE;
    XMEMSET(session.auth.buffer, 0xAA, session.auth.size);

    session.nonceCaller.size = TPM_SHA256_DIGEST_SIZE;
    XMEMSET(session.nonceCaller.buffer, 0x11, session.nonceCaller.size);
    session.nonceTPM.size = TPM_SHA256_DIGEST_SIZE;
    XMEMSET(session.nonceTPM.buffer, 0x22, session.nonceTPM.size);

    XMEMCPY(data, original, sizeof(original));

    /* Test 1: Command direction — CmdRequest enc, TPM-side dec recovers.
     * Simulate TPM decryption with raw AES-CFB using command-direction
     * nonce order: KDFa(nonceCaller, nonceTPM). doEncrypt=0 */
    rc = TPM2_ParamEnc_CmdRequest(&session, data, sizeof(data));
    AssertIntEQ(TPM_RC_SUCCESS, rc);
    AssertIntNE(0, XMEMCMP(data, original, sizeof(original)));

    rc = TPM2_ParamEnc_AESCFB(session.authHash,
        session.symmetric.keyBits.aes,
        session.auth.buffer, session.auth.size,
        session.nonceCaller.buffer, session.nonceCaller.size,
        session.nonceTPM.buffer, session.nonceTPM.size,
        data, sizeof(data), 0);
    AssertIntEQ(TPM_RC_SUCCESS, rc);
    AssertIntEQ(0, XMEMCMP(data, original, sizeof(original)));

    /* Test 2: Response direction — TPM-side enc, CmdResponse dec recovers.
     * Simulate TPM encrypting a response with response-direction nonce order:
     * KDFa(nonceTPM, nonceCaller). doEncrypt=1 */
    XMEMCPY(data, original, sizeof(original));
    rc = TPM2_ParamEnc_AESCFB(session.authHash,
        session.symmetric.keyBits.aes,
        session.auth.buffer, session.auth.size,
        session.nonceTPM.buffer, session.nonceTPM.size,
        session.nonceCaller.buffer, session.nonceCaller.size,
        data, sizeof(data), 1);
    AssertIntEQ(TPM_RC_SUCCESS, rc);
    AssertIntNE(0, XMEMCMP(data, original, sizeof(original)));

    rc = TPM2_ParamDec_CmdResponse(&session, data, sizeof(data));
    AssertIntEQ(TPM_RC_SUCCESS, rc);
    AssertIntEQ(0, XMEMCMP(data, original, sizeof(original)));

    printf("Test TPM Wrapper:\tParamEncDec_Dispatch:\tPassed\n");
#else
    printf("Test TPM Wrapper:\tParamEncDec_Dispatch:\tSkipped\n");
#endif
}

/* Known-answer test for TPM2_HashNvPublic serialization and hashing.
 * Reference: independently computed SHA-256 over the marshaled NV public
 * area fields in TPM 2.0 canonical order. */
static void test_TPM2_HashNvPublic(void)
{
#ifndef WOLFTPM2_NO_WOLFCRYPT
    int rc;
    TPMS_NV_PUBLIC nvPublic;
    byte nameBuffer[2 + WC_MAX_DIGEST_SIZE];
    UINT16 nameSize = 0;
    /* Expected Name: nameAlg(BE) || SHA256(nvIndex||nameAlg||attributes||
     *                authPolicy.size||dataSize) */
    static const byte expectedName[] = {
        0x00, 0x0b, 0x95, 0x61, 0x47, 0xe5, 0x81, 0xbd, 0xe0, 0xad, 0x4d, 0x95,
        0x83, 0x8d, 0x2c, 0x6b, 0x7b, 0xa5, 0x1c, 0xc0, 0xad, 0x56, 0xd8, 0xec,
        0xb7, 0x30, 0x24, 0xfa, 0x34, 0xb9, 0x95, 0x8f, 0xee, 0x45
    };

    XMEMSET(&nvPublic, 0, sizeof(nvPublic));
    nvPublic.nvIndex = 0x01500020;
    nvPublic.nameAlg = TPM_ALG_SHA256;
    nvPublic.attributes = TPMA_NV_AUTHWRITE | TPMA_NV_AUTHREAD | TPMA_NV_NO_DA;
    nvPublic.authPolicy.size = 0;
    nvPublic.dataSize = 32;

    XMEMSET(nameBuffer, 0, sizeof(nameBuffer));
    rc = TPM2_HashNvPublic(&nvPublic, nameBuffer, &nameSize);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    AssertIntEQ(nameSize, (int)sizeof(expectedName));
    AssertIntEQ(0, XMEMCMP(nameBuffer, expectedName, sizeof(expectedName)));

    /* Test NULL args */
    rc = TPM2_HashNvPublic(NULL, nameBuffer, &nameSize);
    AssertIntEQ(rc, BAD_FUNC_ARG);
    rc = TPM2_HashNvPublic(&nvPublic, NULL, &nameSize);
    AssertIntEQ(rc, BAD_FUNC_ARG);
    rc = TPM2_HashNvPublic(&nvPublic, nameBuffer, NULL);
    AssertIntEQ(rc, BAD_FUNC_ARG);

    printf("Test TPM Wrapper:\tHashNvPublic:\t\tPassed\n");
#else
    printf("Test TPM Wrapper:\tHashNvPublic:\t\tSkipped\n");
#endif
}

/* Known-answer test for wolfTPM2_ComputeName.
 * Reference: nameAlg(BE) || SHA256(serialized TPMT_PUBLIC) computed
 * independently for an ECC P-256 key with known field values. */
#if !defined(WOLFTPM2_NO_WOLFCRYPT) && defined(HAVE_ECC)
static void test_wolfTPM2_ComputeName(void)
{
    int rc;
    TPM2B_PUBLIC pub;
    TPM2B_NAME name;
    static const byte expectedName[] = {
        0x00, 0x0b, 0x35, 0xc3, 0x57, 0x9d, 0xf1, 0xb5,
        0x24, 0x6a, 0xb7, 0x9a, 0x0a, 0xf2, 0xd5, 0x44,
        0xcb, 0x63, 0x2a, 0x80, 0xe2, 0x24, 0x1d, 0xd3,
        0x84, 0x06, 0x34, 0xe4, 0x38, 0x00, 0x61, 0xc0,
        0x2e, 0x6f
    };

    XMEMSET(&pub, 0, sizeof(pub));
    pub.publicArea.type = TPM_ALG_ECC;
    pub.publicArea.nameAlg = TPM_ALG_SHA256;
    pub.publicArea.objectAttributes = (TPMA_OBJECT_sign | TPMA_OBJECT_decrypt |
        TPMA_OBJECT_userWithAuth | TPMA_OBJECT_noDA);
    pub.publicArea.authPolicy.size = 0;
    pub.publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
    pub.publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_NULL;
    pub.publicArea.parameters.eccDetail.curveID = TPM_ECC_NIST_P256;
    pub.publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
    pub.publicArea.unique.ecc.x.size = 32;
    XMEMSET(pub.publicArea.unique.ecc.x.buffer, 0x11, 32);
    pub.publicArea.unique.ecc.y.size = 32;
    XMEMSET(pub.publicArea.unique.ecc.y.buffer, 0x22, 32);

    XMEMSET(&name, 0, sizeof(name));
    rc = wolfTPM2_ComputeName(&pub, &name);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    AssertIntEQ(name.size, (int)sizeof(expectedName));
    AssertIntEQ(0, XMEMCMP(name.name, expectedName, sizeof(expectedName)));

    /* Test NULL args */
    rc = wolfTPM2_ComputeName(NULL, &name);
    AssertIntEQ(rc, BAD_FUNC_ARG);
    rc = wolfTPM2_ComputeName(&pub, NULL);
    AssertIntEQ(rc, BAD_FUNC_ARG);

    /* Test nameAlg = TPM_ALG_NULL returns success with empty name */
    pub.publicArea.nameAlg = TPM_ALG_NULL;
    XMEMSET(&name, 0xFF, sizeof(name));
    rc = wolfTPM2_ComputeName(&pub, &name);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    AssertIntEQ(name.size, 0);

    printf("Test TPM Wrapper:\tComputeName:\t\tPassed\n");
}
#endif

/* Test ECC ECDAA scheme serialization roundtrip — verifies count field
 * is preserved, and RSA RSAES scheme produces no spurious hashAlg */
static void test_TPM2_SchemeSerialize(void)
{
    TPM2_Packet packet;
    byte buf[256];
    TPMT_SIG_SCHEME eccSchemeIn, eccSchemeOut;
#ifndef NO_RSA
    TPMT_RSA_SCHEME rsaSchemeIn, rsaSchemeOut;
#endif

    /* Test 1: ECDAA scheme roundtrip — count field must survive */
    XMEMSET(&eccSchemeIn, 0, sizeof(eccSchemeIn));
    eccSchemeIn.scheme = TPM_ALG_ECDAA;
    eccSchemeIn.details.ecdaa.hashAlg = TPM_ALG_SHA256;
    eccSchemeIn.details.ecdaa.count = 5;

    XMEMSET(buf, 0, sizeof(buf));
    XMEMSET(&packet, 0, sizeof(packet));
    packet.buf = buf;
    packet.size = sizeof(buf);

    TPM2_Packet_AppendEccScheme(&packet, &eccSchemeIn);

    /* For ECDAA: scheme(2) + hashAlg(2) + count(2) = 6 bytes */
    AssertIntEQ(packet.pos, 6);

    /* Parse back */
    packet.pos = 0;
    XMEMSET(&eccSchemeOut, 0, sizeof(eccSchemeOut));
    TPM2_Packet_ParseEccScheme(&packet, &eccSchemeOut);

    AssertIntEQ(eccSchemeOut.scheme, TPM_ALG_ECDAA);
    AssertIntEQ(eccSchemeOut.details.ecdaa.hashAlg, TPM_ALG_SHA256);
    AssertIntEQ(eccSchemeOut.details.ecdaa.count, 5);

#ifndef NO_RSA
    /* Test 2: RSAES scheme roundtrip — no hashAlg field (TPMS_EMPTY) */
    XMEMSET(&rsaSchemeIn, 0, sizeof(rsaSchemeIn));
    rsaSchemeIn.scheme = TPM_ALG_RSAES;

    XMEMSET(buf, 0, sizeof(buf));
    XMEMSET(&packet, 0, sizeof(packet));
    packet.buf = buf;
    packet.size = sizeof(buf);

    TPM2_Packet_AppendRsaScheme(&packet, &rsaSchemeIn);

    /* For RSAES: scheme(2) only, no hashAlg */
    AssertIntEQ(packet.pos, 2);

    /* Parse back */
    packet.pos = 0;
    XMEMSET(&rsaSchemeOut, 0, sizeof(rsaSchemeOut));
    TPM2_Packet_ParseRsaScheme(&packet, &rsaSchemeOut);

    AssertIntEQ(rsaSchemeOut.scheme, TPM_ALG_RSAES);
#endif

    printf("Test TPM Wrapper:\tSchemeSerialize:\t\tPassed\n");
}

/* Exercise the parse sequence used by TPM2_ECC_Parameters response: sign
 * scheme = ECDAA (scheme + hashAlg + count) followed by a trailing U16
 * size field. Ensures the ECDAA count field is consumed so the next read
 * lands at the correct offset. The wire bytes are built by hand to avoid
 * relying on non-exported packet helpers. */
static void test_TPM2_ECC_Parameters_EcdaaResponseParse(void)
{
    TPM2_Packet packet;
    byte buf[32];
    TPMT_SIG_SCHEME signOut;
    UINT16 pSizeOut = 0;

    /* Hand-built wire: TPM2B wire is big-endian.
     *   [0-1] sign.scheme    = TPM_ALG_ECDAA (0x001A)
     *   [2-3] sign.hashAlg   = TPM_ALG_SHA256 (0x000B)
     *   [4-5] sign.count     = 0x0007
     *   [6-7] p.size sentinel= 0x0030
     */
    XMEMSET(buf, 0, sizeof(buf));
    buf[0] = 0x00; buf[1] = (byte)TPM_ALG_ECDAA;
    buf[2] = 0x00; buf[3] = (byte)TPM_ALG_SHA256;
    buf[4] = 0x00; buf[5] = 0x07;
    buf[6] = 0x00; buf[7] = 0x30;

    XMEMSET(&packet, 0, sizeof(packet));
    packet.buf = buf;
    packet.size = sizeof(buf);
    packet.pos = 0;

    XMEMSET(&signOut, 0, sizeof(signOut));
    TPM2_Packet_ParseEccScheme(&packet, &signOut);
    AssertIntEQ(signOut.scheme, TPM_ALG_ECDAA);
    AssertIntEQ(signOut.details.ecdaa.hashAlg, TPM_ALG_SHA256);
    AssertIntEQ(signOut.details.ecdaa.count, 7);

    /* After parsing the ECDAA scheme, packet.pos must be at byte 6 so the
     * next U16 read returns the sentinel 0x0030 (the simulated p.size).
     * The buggy inline parser in TPM2_ECC_Parameters consumed only
     * scheme+hashAlg (4 bytes) and left the count on the wire, which
     * would make p.size read 0x0007 instead. */
    AssertIntEQ(packet.pos, 6);
    pSizeOut = (UINT16)((buf[packet.pos] << 8) | buf[packet.pos + 1]);
    AssertIntEQ(pSizeOut, 0x0030);

    printf("Test TPM Wrapper:\tEcdaaResponseParse:\t\tPassed\n");
}

static void test_TPM2_KeyedHashScheme_XorSerialize(void)
{
    TPM2_Packet packet;
    byte buf[64];
    TPMT_KEYEDHASH_SCHEME schemeIn, schemeOut;

    /* XOR scheme roundtrip: scheme(2) + hashAlg(2) + kdf(2) = 6 bytes */
    XMEMSET(&schemeIn, 0, sizeof(schemeIn));
    schemeIn.scheme = TPM_ALG_XOR;
    schemeIn.details.xorr.hashAlg = TPM_ALG_SHA256;
    schemeIn.details.xorr.kdf = TPM_ALG_KDF1_SP800_108;

    XMEMSET(buf, 0, sizeof(buf));
    XMEMSET(&packet, 0, sizeof(packet));
    packet.buf = buf;
    packet.size = sizeof(buf);

    TPM2_Packet_AppendKeyedHashScheme(&packet, &schemeIn);
    AssertIntEQ(packet.pos, 6);

    packet.pos = 0;
    XMEMSET(&schemeOut, 0, sizeof(schemeOut));
    TPM2_Packet_ParseKeyedHashScheme(&packet, &schemeOut);

    AssertIntEQ(schemeOut.scheme, TPM_ALG_XOR);
    AssertIntEQ(schemeOut.details.xorr.hashAlg, TPM_ALG_SHA256);
    AssertIntEQ(schemeOut.details.xorr.kdf, TPM_ALG_KDF1_SP800_108);

    /* HMAC scheme still works: scheme(2) + hashAlg(2) = 4 bytes */
    XMEMSET(&schemeIn, 0, sizeof(schemeIn));
    schemeIn.scheme = TPM_ALG_HMAC;
    schemeIn.details.hmac.hashAlg = TPM_ALG_SHA384;

    XMEMSET(buf, 0, sizeof(buf));
    XMEMSET(&packet, 0, sizeof(packet));
    packet.buf = buf;
    packet.size = sizeof(buf);

    TPM2_Packet_AppendKeyedHashScheme(&packet, &schemeIn);
    AssertIntEQ(packet.pos, 4);

    packet.pos = 0;
    XMEMSET(&schemeOut, 0, sizeof(schemeOut));
    TPM2_Packet_ParseKeyedHashScheme(&packet, &schemeOut);
    AssertIntEQ(schemeOut.scheme, TPM_ALG_HMAC);
    AssertIntEQ(schemeOut.details.hmac.hashAlg, TPM_ALG_SHA384);

    /* NULL scheme: scheme(2) only */
    XMEMSET(&schemeIn, 0, sizeof(schemeIn));
    schemeIn.scheme = TPM_ALG_NULL;

    XMEMSET(buf, 0, sizeof(buf));
    XMEMSET(&packet, 0, sizeof(packet));
    packet.buf = buf;
    packet.size = sizeof(buf);

    TPM2_Packet_AppendKeyedHashScheme(&packet, &schemeIn);
    AssertIntEQ(packet.pos, 2);

    printf("Test TPM Wrapper:\tKeyedHashScheme XOR serialize:\tPassed\n");
}

static void test_TPM2_Signature_EcSchnorrSm2Serialize(void)
{
    TPM2_Packet packet;
    byte buf[256];
    TPMT_SIGNATURE sigIn, sigOut;
    const byte rBuf[8] = {0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88};
    const byte sBuf[8] = {0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00};

    /* ECSCHNORR: sigAlg(2) + hashAlg(2) + rSz(2) + r(8) + sSz(2) + s(8) = 24 */
    XMEMSET(&sigIn, 0, sizeof(sigIn));
    sigIn.sigAlg = TPM_ALG_ECSCHNORR;
    sigIn.signature.ecdsa.hash = TPM_ALG_SHA256;
    sigIn.signature.ecdsa.signatureR.size = sizeof(rBuf);
    XMEMCPY(sigIn.signature.ecdsa.signatureR.buffer, rBuf, sizeof(rBuf));
    sigIn.signature.ecdsa.signatureS.size = sizeof(sBuf);
    XMEMCPY(sigIn.signature.ecdsa.signatureS.buffer, sBuf, sizeof(sBuf));

    XMEMSET(buf, 0, sizeof(buf));
    XMEMSET(&packet, 0, sizeof(packet));
    packet.buf = buf;
    packet.size = sizeof(buf);

    TPM2_Packet_AppendSignature(&packet, &sigIn);
    AssertIntEQ(packet.pos, 24);

    packet.pos = 0;
    XMEMSET(&sigOut, 0, sizeof(sigOut));
    TPM2_Packet_ParseSignature(&packet, &sigOut);
    AssertIntEQ(sigOut.sigAlg, TPM_ALG_ECSCHNORR);
    AssertIntEQ(sigOut.signature.ecdsa.hash, TPM_ALG_SHA256);
    AssertIntEQ(sigOut.signature.ecdsa.signatureR.size, sizeof(rBuf));
    AssertIntEQ(XMEMCMP(sigOut.signature.ecdsa.signatureR.buffer,
        rBuf, sizeof(rBuf)), 0);
    AssertIntEQ(sigOut.signature.ecdsa.signatureS.size, sizeof(sBuf));
    AssertIntEQ(XMEMCMP(sigOut.signature.ecdsa.signatureS.buffer,
        sBuf, sizeof(sBuf)), 0);

    /* SM2: same wire format */
    sigIn.sigAlg = TPM_ALG_SM2;

    XMEMSET(buf, 0, sizeof(buf));
    XMEMSET(&packet, 0, sizeof(packet));
    packet.buf = buf;
    packet.size = sizeof(buf);

    TPM2_Packet_AppendSignature(&packet, &sigIn);
    AssertIntEQ(packet.pos, 24);

    packet.pos = 0;
    XMEMSET(&sigOut, 0, sizeof(sigOut));
    TPM2_Packet_ParseSignature(&packet, &sigOut);
    AssertIntEQ(sigOut.sigAlg, TPM_ALG_SM2);
    AssertIntEQ(sigOut.signature.ecdsa.signatureR.size, sizeof(rBuf));
    AssertIntEQ(sigOut.signature.ecdsa.signatureS.size, sizeof(sBuf));

    printf("Test TPM Wrapper:\tSignature ECSCHNORR/SM2 serialize:\tPassed\n");
}

static void test_TPM2_Sensitive_Roundtrip(void)
{
    TPM2_Packet packet;
    byte buf[512];
    TPM2B_SENSITIVE sensIn, sensOut;
    const byte authBuf[4] = {0x01, 0x02, 0x03, 0x04};
    const byte seedBuf[8] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11};
    const byte rsaPriv[16] = {
        0xde, 0xad, 0xbe, 0xef, 0x11, 0x22, 0x33, 0x44,
        0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc
    };

    /* RSA sensitive roundtrip */
    XMEMSET(&sensIn, 0, sizeof(sensIn));
    sensIn.sensitiveArea.sensitiveType = TPM_ALG_RSA;
    sensIn.sensitiveArea.authValue.size = sizeof(authBuf);
    XMEMCPY(sensIn.sensitiveArea.authValue.buffer, authBuf, sizeof(authBuf));
    sensIn.sensitiveArea.seedValue.size = sizeof(seedBuf);
    XMEMCPY(sensIn.sensitiveArea.seedValue.buffer, seedBuf, sizeof(seedBuf));
    sensIn.sensitiveArea.sensitive.rsa.size = sizeof(rsaPriv);
    XMEMCPY(sensIn.sensitiveArea.sensitive.rsa.buffer, rsaPriv,
        sizeof(rsaPriv));

    XMEMSET(buf, 0, sizeof(buf));
    XMEMSET(&packet, 0, sizeof(packet));
    packet.buf = buf;
    packet.size = sizeof(buf);

    TPM2_Packet_AppendSensitive(&packet, &sensIn);

    packet.pos = 0;
    XMEMSET(&sensOut, 0, sizeof(sensOut));
    TPM2_Packet_ParseSensitive(&packet, &sensOut);

    AssertIntEQ(sensOut.sensitiveArea.sensitiveType, TPM_ALG_RSA);
    AssertIntEQ(sensOut.sensitiveArea.authValue.size, sizeof(authBuf));
    AssertIntEQ(XMEMCMP(sensOut.sensitiveArea.authValue.buffer,
        authBuf, sizeof(authBuf)), 0);
    AssertIntEQ(sensOut.sensitiveArea.seedValue.size, sizeof(seedBuf));
    AssertIntEQ(XMEMCMP(sensOut.sensitiveArea.seedValue.buffer,
        seedBuf, sizeof(seedBuf)), 0);
    AssertIntEQ(sensOut.sensitiveArea.sensitive.rsa.size, sizeof(rsaPriv));
    AssertIntEQ(XMEMCMP(sensOut.sensitiveArea.sensitive.rsa.buffer,
        rsaPriv, sizeof(rsaPriv)), 0);

    /* ECC sensitive roundtrip */
    XMEMSET(&sensIn, 0, sizeof(sensIn));
    sensIn.sensitiveArea.sensitiveType = TPM_ALG_ECC;
    sensIn.sensitiveArea.sensitive.ecc.size = sizeof(rsaPriv);
    XMEMCPY(sensIn.sensitiveArea.sensitive.ecc.buffer, rsaPriv,
        sizeof(rsaPriv));

    XMEMSET(buf, 0, sizeof(buf));
    XMEMSET(&packet, 0, sizeof(packet));
    packet.buf = buf;
    packet.size = sizeof(buf);

    TPM2_Packet_AppendSensitive(&packet, &sensIn);

    packet.pos = 0;
    XMEMSET(&sensOut, 0, sizeof(sensOut));
    TPM2_Packet_ParseSensitive(&packet, &sensOut);

    AssertIntEQ(sensOut.sensitiveArea.sensitiveType, TPM_ALG_ECC);
    AssertIntEQ(sensOut.sensitiveArea.sensitive.ecc.size, sizeof(rsaPriv));
    AssertIntEQ(XMEMCMP(sensOut.sensitiveArea.sensitive.ecc.buffer,
        rsaPriv, sizeof(rsaPriv)), 0);

    /* KEYEDHASH sensitive roundtrip */
    XMEMSET(&sensIn, 0, sizeof(sensIn));
    sensIn.sensitiveArea.sensitiveType = TPM_ALG_KEYEDHASH;
    sensIn.sensitiveArea.sensitive.bits.size = sizeof(rsaPriv);
    XMEMCPY(sensIn.sensitiveArea.sensitive.bits.buffer, rsaPriv,
        sizeof(rsaPriv));

    XMEMSET(buf, 0, sizeof(buf));
    XMEMSET(&packet, 0, sizeof(packet));
    packet.buf = buf;
    packet.size = sizeof(buf);

    TPM2_Packet_AppendSensitive(&packet, &sensIn);

    packet.pos = 0;
    XMEMSET(&sensOut, 0, sizeof(sensOut));
    TPM2_Packet_ParseSensitive(&packet, &sensOut);

    AssertIntEQ(sensOut.sensitiveArea.sensitiveType, TPM_ALG_KEYEDHASH);
    AssertIntEQ(sensOut.sensitiveArea.sensitive.bits.size, sizeof(rsaPriv));
    AssertIntEQ(XMEMCMP(sensOut.sensitiveArea.sensitive.bits.buffer,
        rsaPriv, sizeof(rsaPriv)), 0);

    /* SYMCIPHER sensitive roundtrip */
    XMEMSET(&sensIn, 0, sizeof(sensIn));
    sensIn.sensitiveArea.sensitiveType = TPM_ALG_SYMCIPHER;
    sensIn.sensitiveArea.sensitive.sym.size = sizeof(rsaPriv);
    XMEMCPY(sensIn.sensitiveArea.sensitive.sym.buffer, rsaPriv,
        sizeof(rsaPriv));

    XMEMSET(buf, 0, sizeof(buf));
    XMEMSET(&packet, 0, sizeof(packet));
    packet.buf = buf;
    packet.size = sizeof(buf);

    TPM2_Packet_AppendSensitive(&packet, &sensIn);

    packet.pos = 0;
    XMEMSET(&sensOut, 0, sizeof(sensOut));
    TPM2_Packet_ParseSensitive(&packet, &sensOut);

    AssertIntEQ(sensOut.sensitiveArea.sensitiveType, TPM_ALG_SYMCIPHER);
    AssertIntEQ(sensOut.sensitiveArea.sensitive.sym.size, sizeof(rsaPriv));
    AssertIntEQ(XMEMCMP(sensOut.sensitiveArea.sensitive.sym.buffer,
        rsaPriv, sizeof(rsaPriv)), 0);

    printf("Test TPM Wrapper:\tSensitive roundtrip:\t\tPassed\n");
}

static void test_KeySealTemplate(void)
{
    int rc;
    TPMT_PUBLIC tmpl;

    rc = wolfTPM2_GetKeyTemplate_KeySeal(&tmpl, TPM_ALG_SHA256);
    AssertIntEQ(rc, TPM_RC_SUCCESS);

    /* Template must include userWithAuth so password-based unseal works */
    AssertIntNE(tmpl.objectAttributes & TPMA_OBJECT_userWithAuth, 0);

    printf("Test TPM Wrapper:\tKeySealTemplate:\t\tPassed\n");
}

/* Test boundary validation for seal size and keyed hash key size.
 * Uses zero-initialized dev intentionally — only testing argument validation,
 * not TPM operations. */
static void test_SealAndKeyedHash_Boundaries(void)
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEYBLOB keyBlob;
    WOLFTPM2_KEY key;
    WOLFTPM2_HANDLE parent;
    TPMT_PUBLIC tmpl;
    byte data[MAX_SYM_DATA + 1];

    XMEMSET(&dev, 0, sizeof(dev));
    XMEMSET(&keyBlob, 0, sizeof(keyBlob));
    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(&parent, 0, sizeof(parent));
    XMEMSET(&tmpl, 0, sizeof(tmpl));
    XMEMSET(data, 0xAA, sizeof(data));

    /* NULL arg checks */
    rc = wolfTPM2_CreateKeySeal_ex(NULL, &keyBlob, &parent, &tmpl,
        NULL, 0, TPM_ALG_NULL, NULL, 0, data, 1);
    AssertIntEQ(rc, BAD_FUNC_ARG);

    /* sealSize = MAX_SYM_DATA+1 (129) must be rejected */
    rc = wolfTPM2_CreateKeySeal_ex(&dev, &keyBlob, &parent, &tmpl,
        NULL, 0, TPM_ALG_NULL, NULL, 0, data, MAX_SYM_DATA + 1);
    AssertIntEQ(rc, BAD_FUNC_ARG);

    /* sealSize = -1 must be rejected */
    rc = wolfTPM2_CreateKeySeal_ex(&dev, &keyBlob, &parent, &tmpl,
        NULL, 0, TPM_ALG_NULL, NULL, 0, data, -1);
    AssertIntEQ(rc, BAD_FUNC_ARG);

    /* sealSize > 0 with NULL sealData must be rejected */
    rc = wolfTPM2_CreateKeySeal_ex(&dev, &keyBlob, &parent, &tmpl,
        NULL, 0, TPM_ALG_NULL, NULL, 0, NULL, 1);
    AssertIntEQ(rc, BAD_FUNC_ARG);

    /* keySz = MAX_SYM_DATA+1 (129) must be rejected */
    rc = wolfTPM2_LoadKeyedHashKey(&dev, &key, &parent,
        TPM_ALG_SHA256, data, MAX_SYM_DATA + 1, NULL, 0);
    AssertIntEQ(rc, BUFFER_E);

    /* keySz = 0 must be rejected */
    rc = wolfTPM2_LoadKeyedHashKey(&dev, &key, &parent,
        TPM_ALG_SHA256, data, 0, NULL, 0);
    AssertIntEQ(rc, BUFFER_E);

    /* NULL keyBuf must be rejected */
    rc = wolfTPM2_LoadKeyedHashKey(&dev, &key, &parent,
        TPM_ALG_SHA256, NULL, MAX_SYM_DATA, NULL, 0);
    AssertIntEQ(rc, BAD_FUNC_ARG);

    printf("Test TPM Wrapper:\tSealKeyedHash Boundary:\t\tPassed\n");
}

static void test_GetAlgId(void)
{
    TPM_ALG_ID alg = TPM2_GetAlgId("SHA256");
    AssertIntEQ(alg, TPM_ALG_SHA256);
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

#if !defined(WOLFTPM2_NO_WOLFCRYPT) && defined(HAVE_ECC) && \
    !defined(WOLFTPM2_NO_ASN)
#define FLAGS_USE_WOLFCRYPT (1 << 0)
#define FLAGS_USE_CRYPTO_CB (1 << 1)
#define FLAGS_USE_PK_CB     (1 << 2) /* requires TLS layer to test */
static void test_wolfTPM2_EccSignVerifyDig(WOLFTPM2_DEV* dev,
    WOLFTPM2_KEY* storageKey, const byte* digest, int digestSz,
    TPM_ECC_CURVE curve, TPMI_ALG_HASH hashAlg, int flags)
{
    int rc;
    int verifyRes = 0;
    WOLFTPM2_KEYBLOB eccKey;
    TPMT_PUBLIC publicTemplate;
    byte sigRs[MAX_ECC_BYTES*2];
    word32 sigRsSz = (word32)sizeof(sigRs);
    byte sig[ECC_MAX_SIG_SIZE];
    word32 sigSz;
    byte *r, *s;
    word32 rLen, sLen;
    ecc_key wolfKey;
    int curveSize = TPM2_GetCurveSize(curve);
    int tpmDevId = INVALID_DEVID;
#ifdef WOLF_CRYPTO_CB
    TpmCryptoDevCtx tpmCtx;

    XMEMSET(&tpmCtx, 0, sizeof(tpmCtx));
    tpmCtx.dev = dev;
    tpmCtx.ecdsaKey = &eccKey;
    tpmCtx.storageKey = storageKey;

    if (flags & FLAGS_USE_CRYPTO_CB) {
        rc = wolfTPM2_SetCryptoDevCb(dev, wolfTPM2_CryptoDevCb, &tpmCtx,
            &tpmDevId);
        AssertIntEQ(rc, 0);
    }
#endif

    /* Skip if this TPM doesn't implement the requested hash alg. Some TPMs
     * (e.g. Nuvoton NPCT75x) only support a subset of hashes; the TPM rejects
     * Create with TPM_RC_SIZE param 1, not TPM_RC_HASH, so the existing
     * post-hoc skip-check can't catch it. Query capabilities up front. */
    if (!test_tpm_alg_supported(hashAlg)) {
        printf("Hash alg 0x%x not supported by TPM... Skipping\n", hashAlg);
        return;
    }

    /* -- Use TPM key to sign and verify with wolfCrypt -- */
    /* Create ECC key for signing */
    rc = wolfTPM2_GetKeyTemplate_ECC_ex(&publicTemplate, hashAlg,
        (TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
         TPMA_OBJECT_sign | TPMA_OBJECT_noDA),
         curve, TPM_ALG_ECDSA, hashAlg);
    AssertIntEQ(rc, 0);

    /* Use create key and load key directly instead to make
     * sure the private portion is populated */
    rc = wolfTPM2_CreateKey(dev, &eccKey, &storageKey->handle,
        &publicTemplate, (byte*)gKeyAuth, sizeof(gKeyAuth)-1);
    if (rc == TPM_RC_SUCCESS) {
        rc = wolfTPM2_LoadKey(dev, &eccKey, &storageKey->handle);
    }
    if ((rc & TPM_RC_HASH) == TPM_RC_HASH) {
        printf("Hash type not supported... Skipping\n");
        return;
    }
    if ((rc & TPM_RC_CURVE) == TPM_RC_CURVE) {
        printf("Curve not supported... Skipping\n");
        return;
    }
    AssertIntEQ(rc, 0);

    /* Sign with TPM */
    rc = wolfTPM2_SignHashScheme(dev, (WOLFTPM2_KEY*)&eccKey, digest, digestSz,
        sigRs, (int*)&sigRsSz, TPM_ALG_ECDSA, hashAlg);
    AssertIntEQ(rc, 0);

    /* Make sure leading zero's not required are trimmed */
    rLen = sLen = sigRsSz / 2;
    r = &sigRs[0];
    s = &sigRs[rLen];

    /* Encode ECDSA Header */
    sigSz = (word32)sizeof(sig);
    rc = wc_ecc_rs_raw_to_sig(r, rLen, s, sLen, sig, &sigSz);
    AssertIntEQ(rc, 0);

    /* Initialize wolfCrypt ECC key */
    rc = wc_ecc_init_ex(&wolfKey, NULL, tpmDevId);
    AssertIntEQ(rc, 0);

    /* Convert TPM key to wolfCrypt key for verification */
    rc = wolfTPM2_EccKey_TpmToWolf(dev, (WOLFTPM2_KEY*)&eccKey, &wolfKey);
    AssertIntEQ(rc, 0);

    /* Verify TPM signature with wolfCrypt */
    rc = wc_ecc_verify_hash(sig, sigSz, digest, digestSz, &verifyRes, &wolfKey);
    AssertIntEQ(rc, 0);
    AssertIntEQ(verifyRes, 1); /* 1 indicates successful verification */

    /* Cleanup first wolfCrypt key */
    wc_ecc_free(&wolfKey);
    wolfTPM2_UnloadHandle(dev, &eccKey.handle);
#ifdef WOLF_CRYPTO_CB
    tpmCtx.ecdsaKey = NULL; /* create new one */
#endif

    /* -- Use wolfCrypt key to sign and verify with TPM -- */
    /* Initialize new wolfCrypt ECC key */
    rc = wc_ecc_init_ex(&wolfKey, NULL, tpmDevId);
    AssertIntEQ(rc, 0);

    /* Generate new ECC key with wolfCrypt */
    rc = wc_ecc_make_key(wolfTPM2_GetRng(dev), curveSize, &wolfKey);
    AssertIntEQ(rc, 0);

    /* Sign with wolfCrypt */
    sigSz = (word32)sizeof(sig);
    rc = wc_ecc_sign_hash(digest, digestSz, sig, &sigSz, wolfTPM2_GetRng(dev),
        &wolfKey);
    AssertIntEQ(rc, 0);
    wolfTPM2_UnloadHandle(dev, &eccKey.handle);

    /* Decode ECDSA Header */
    r = sigRs;
    s = &sigRs[MAX_ECC_BYTES];
    rLen = sLen = MAX_ECC_BYTES;
    rc = wc_ecc_sig_to_rs(sig, sigSz, r, &rLen, s, &sLen);
    AssertIntEQ(rc, 0);

    /* Convert wolfCrypt key to TPM key for verification */
    rc = wolfTPM2_EccKey_WolfToTpm(dev, &wolfKey, (WOLFTPM2_KEY*)&eccKey);
    AssertIntEQ(rc, 0);

    /* combine R and S at key size (zero pad leading) */
    XMEMMOVE(&sigRs[curveSize-rLen], r, rLen);
    XMEMSET(&sigRs[0], 0, curveSize-rLen);
    XMEMMOVE(&sigRs[curveSize + (curveSize-sLen)], s, sLen);
    XMEMSET(&sigRs[curveSize], 0, curveSize-sLen);

    /* Verify wolfCrypt signature with TPM */
    rc = wolfTPM2_VerifyHashScheme(dev, (WOLFTPM2_KEY*)&eccKey, sigRs,
        curveSize*2, digest, digestSz, TPM_ALG_ECDSA, hashAlg);
    AssertIntEQ(rc, 0);

    /* Cleanup */
    wc_ecc_free(&wolfKey);
    wolfTPM2_UnloadHandle(dev, &eccKey.handle);

    printf("Test TPM Wrapper:\t"
        "Sign/Verify (DigSz=%d, CurveSz=%d, Hash=%s, Flags=%s):"
        "\t%s\n",
        digestSz, TPM2_GetCurveSize(curve), TPM2_GetAlgName(hashAlg),
        (flags & FLAGS_USE_CRYPTO_CB) ? "Crypto CB" : "",
        rc == 0 ? "Passed" : "Failed");

#ifdef WOLF_CRYPTO_CB
    if (flags & FLAGS_USE_CRYPTO_CB) {
        wolfTPM2_ClearCryptoDevCb(dev, tpmDevId);
    }
#endif
}

static void test_wolfTPM2_EccSignVerify_All(WOLFTPM2_DEV* dev,
    WOLFTPM2_KEY* storageKey, int flags)
{
    int i;
    byte digest[TPM_MAX_DIGEST_SIZE];

    for (i = 0; i < (int)sizeof(digest); i++) {
        digest[i] = (byte)i;
    }

    test_wolfTPM2_EccSignVerifyDig(dev, storageKey, digest, 20,
        TPM_ECC_NIST_P256, TPM_ALG_SHA256, flags);
    test_wolfTPM2_EccSignVerifyDig(dev, storageKey, digest, 32,
        TPM_ECC_NIST_P256, TPM_ALG_SHA256, flags);
    test_wolfTPM2_EccSignVerifyDig(dev, storageKey, digest, 48,
        TPM_ECC_NIST_P256, TPM_ALG_SHA256, flags);
    test_wolfTPM2_EccSignVerifyDig(dev, storageKey, digest, 64,
        TPM_ECC_NIST_P256, TPM_ALG_SHA256, flags);

#if (defined(HAVE_ECC384) || defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 384
    test_wolfTPM2_EccSignVerifyDig(dev, storageKey, digest, 20,
        TPM_ECC_NIST_P384, TPM_ALG_SHA384, flags);
    test_wolfTPM2_EccSignVerifyDig(dev, storageKey, digest, 32,
        TPM_ECC_NIST_P384, TPM_ALG_SHA384, flags);
    test_wolfTPM2_EccSignVerifyDig(dev, storageKey, digest, 48,
        TPM_ECC_NIST_P384, TPM_ALG_SHA384, flags);
    test_wolfTPM2_EccSignVerifyDig(dev, storageKey, digest, 64,
        TPM_ECC_NIST_P384, TPM_ALG_SHA384, flags);
#endif

#if (defined(HAVE_ECC521) || defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 521
    test_wolfTPM2_EccSignVerifyDig(dev, storageKey, digest, 20,
        TPM_ECC_NIST_P521, TPM_ALG_SHA512, flags);
    test_wolfTPM2_EccSignVerifyDig(dev, storageKey, digest, 32,
        TPM_ECC_NIST_P521, TPM_ALG_SHA512, flags);
    test_wolfTPM2_EccSignVerifyDig(dev, storageKey, digest, 48,
        TPM_ECC_NIST_P521, TPM_ALG_SHA512, flags);
    test_wolfTPM2_EccSignVerifyDig(dev, storageKey, digest, 64,
        TPM_ECC_NIST_P521, TPM_ALG_SHA512, flags);
#endif
}

/* Test with smaller, same and larger digest sizes using different ECC curves.
 * Interop sign and verify with wolfCrypt and TPM */
static void test_wolfTPM2_EccSignVerify(void)
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY storageKey;

    /* Initialize TPM */
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, NULL);
    AssertIntEQ(rc, 0);

    /* Create storage key */
    rc = wolfTPM2_CreateSRK(&dev, &storageKey, TPM_ALG_ECC,
            (byte*)gStorageKeyAuth, sizeof(gStorageKeyAuth)-1);
    AssertIntEQ(rc, 0);

    test_wolfTPM2_EccSignVerify_All(&dev, &storageKey, 0);
#ifdef WOLF_CRYPTO_CB
    test_wolfTPM2_EccSignVerify_All(&dev, &storageKey, FLAGS_USE_CRYPTO_CB);
#endif

    wolfTPM2_UnloadHandle(&dev, &storageKey.handle);
    wolfTPM2_Cleanup(&dev);
}
#endif

#if !defined(WOLFTPM2_NO_WOLFCRYPT) && defined(WOLFTPM2_PEM_DECODE) && \
    !defined(NO_RSA)
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

    AssertIntEQ(XMEMCMP(digest, expectedPolicyAuth, sizeof(expectedPolicyAuth)),
        0);

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

#ifdef WOLFTPM_SPDM
/* Test SPDM wrapper API functions */
static void test_wolfTPM2_SPDM_Functions(void)
{
    int rc;
    WOLFTPM2_DEV dev;
#ifdef WOLFSPDM_NUVOTON
    WOLFSPDM_NUVOTON_STATUS nuvStatus;
#endif
#if defined(WOLFSPDM_NUVOTON) || defined(WOLFSPDM_NATIONS)
    byte pubKey[256];
    word32 pubKeySz;
#endif
#ifdef WOLFSPDM_NATIONS
    WOLFSPDM_NATIONS_STATUS nStatus;
#endif

    printf("Test TPM Wrapper:\tSPDM Functions:\t");

    /* Initialize device */
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, NULL);
    if (rc != 0) {
        printf("Failed (Init failed: 0x%x)\n", rc);
        return;
    }

    /* Test 1: Parameter validation - NULL args */
    rc = wolfTPM2_SpdmInit(NULL);
    AssertIntEQ(rc, BAD_FUNC_ARG);
    rc = wolfTPM2_SpdmConnect(NULL);
    AssertIntEQ(rc, BAD_FUNC_ARG);
    AssertIntEQ(wolfTPM2_SpdmIsConnected(NULL), 0);
    AssertIntEQ(wolfTPM2_SpdmGetSessionId(NULL), 0);
    rc = wolfTPM2_SpdmDisconnect(NULL);
    AssertIntEQ(rc, BAD_FUNC_ARG);
    rc = wolfTPM2_SpdmCleanup(NULL);
    AssertIntEQ(rc, BAD_FUNC_ARG);

    /* Test 2: Context lifecycle - init, check state, cleanup */
    rc = wolfTPM2_SpdmInit(&dev);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    /* When SPDM-only mode is active, auto-SPDM connects during Init.
     * Otherwise, just initialized but not yet connected. */
    if (!dev.ctx.spdmOnlyDetected) {
        AssertIntEQ(wolfTPM2_SpdmIsConnected(&dev), 0);
        AssertIntEQ(wolfTPM2_SpdmGetSessionId(&dev), 0);
    }
    /* Cleanup */
    rc = wolfTPM2_SpdmCleanup(&dev);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    /* Idempotent cleanup */
    rc = wolfTPM2_SpdmCleanup(&dev);
    AssertIntEQ(rc, TPM_RC_SUCCESS);

#ifdef WOLFSPDM_NUVOTON
    /* Test 3: Nuvoton-specific parameter validation */
    rc = wolfTPM2_SpdmSetNuvotonMode(NULL);
    AssertIntEQ(rc, BAD_FUNC_ARG);
    rc = wolfTPM2_SpdmEnable(NULL);
    AssertIntEQ(rc, BAD_FUNC_ARG);
    pubKeySz = sizeof(pubKey);
    rc = wolfTPM2_SpdmGetStatus(NULL, &nuvStatus);
    AssertIntEQ(rc, BAD_FUNC_ARG);
    rc = wolfTPM2_SpdmGetStatus(&dev, NULL);
    AssertIntEQ(rc, BAD_FUNC_ARG);
    rc = wolfTPM2_SpdmGetPubKey(NULL, pubKey, &pubKeySz);
    AssertIntEQ(rc, BAD_FUNC_ARG);
    rc = wolfTPM2_SpdmSetOnlyMode(NULL, 0);
    AssertIntEQ(rc, BAD_FUNC_ARG);

    /* Test 3b: SpdmEnable/Disable must preserve session[0] */
    rc = wolfTPM2_SpdmInit(&dev);
    if (rc == 0) {
        TPM2_AUTH_SESSION origSess;
        /* Set up a distinguishable session[0] state */
        dev.session[0].sessionHandle = HMAC_SESSION_FIRST;
        dev.session[0].sessionAttributes = 0x27;
        dev.session[0].auth.size = 4;
        XMEMCPY(dev.session[0].auth.buffer, "\x01\x02\x03\x04", 4);
        XMEMCPY(&origSess, &dev.session[0], sizeof(origSess));

        /* SpdmEnable may fail (no Nuvoton HW) but must restore session[0] */
        (void)wolfTPM2_SpdmEnable(&dev);
        AssertIntEQ(dev.session[0].sessionHandle, origSess.sessionHandle);
        AssertIntEQ(dev.session[0].sessionAttributes, origSess.sessionAttributes);
        AssertIntEQ(dev.session[0].auth.size, origSess.auth.size);

        /* Restore and test SpdmDisable */
        XMEMCPY(&dev.session[0], &origSess, sizeof(origSess));
        (void)wolfTPM2_SpdmDisable(&dev);
        AssertIntEQ(dev.session[0].sessionHandle, origSess.sessionHandle);
        AssertIntEQ(dev.session[0].sessionAttributes, origSess.sessionAttributes);
        AssertIntEQ(dev.session[0].auth.size, origSess.auth.size);

        wolfTPM2_SpdmCleanup(&dev);
    }
#endif /* WOLFSPDM_NUVOTON */

#ifdef WOLFSPDM_NATIONS
    /* Test 4: Nations-specific parameter validation */
    rc = wolfTPM2_SpdmSetNationsMode(NULL);
    AssertIntEQ(rc, BAD_FUNC_ARG);
    rc = wolfTPM2_SpdmNationsIdentityKeySet(NULL, 0);
    AssertIntEQ(rc, BAD_FUNC_ARG);
    pubKeySz = sizeof(pubKey);
    rc = wolfTPM2_SpdmGetPubKey(NULL, pubKey, &pubKeySz);
    AssertIntEQ(rc, BAD_FUNC_ARG);
    /* Nations PSK wrapper parameter validation */
    rc = wolfTPM2_SpdmConnectNationsPsk(NULL, NULL, 0, NULL, 0);
    AssertIntEQ(rc, BAD_FUNC_ARG);
    rc = wolfTPM2_SpdmNationsGetStatus(NULL, &nStatus);
    AssertIntEQ(rc, BAD_FUNC_ARG);
    rc = wolfTPM2_SpdmNationsSetOnlyMode(NULL, 0);
    AssertIntEQ(rc, BAD_FUNC_ARG);
    rc = wolfTPM2_SpdmNationsPskSet(NULL, NULL, 0);
    AssertIntEQ(rc, BAD_FUNC_ARG);
    rc = wolfTPM2_SpdmNationsPskClear(NULL, NULL, 0);
    AssertIntEQ(rc, BAD_FUNC_ARG);

    /* Test 4b: SpdmNationsIdentityKeySet must preserve session[0] */
    {
        TPM2_AUTH_SESSION origSess;
        dev.session[0].sessionHandle = HMAC_SESSION_FIRST;
        dev.session[0].sessionAttributes = 0x27;
        dev.session[0].auth.size = 4;
        XMEMCPY(dev.session[0].auth.buffer, "\x01\x02\x03\x04", 4);
        XMEMCPY(&origSess, &dev.session[0], sizeof(origSess));

        /* May fail (no Nations HW) but must restore session[0] */
        (void)wolfTPM2_SpdmNationsIdentityKeySet(&dev, 1);
        AssertIntEQ(dev.session[0].sessionHandle, origSess.sessionHandle);
        AssertIntEQ(dev.session[0].sessionAttributes, origSess.sessionAttributes);
        AssertIntEQ(dev.session[0].auth.size, origSess.auth.size);
    }
#endif /* WOLFSPDM_NATIONS */

    wolfTPM2_Cleanup(&dev);

    printf("Passed\n");
}
#endif /* WOLFTPM_SPDM */

/* Test creating key and exporting keyblob as buffer,
 * importing and loading key. */
static void test_wolfTPM2_KeyBlob(TPM_ALG_ID alg)
{
    int rc;
    TPM_HANDLE handle;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY srk;
    WOLFTPM2_KEYBLOB key;
    byte blob[MAX_CONTEXT_SIZE];
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

    AssertIntLT(pubBufferSz + privBufferSz, sizeof(blob));

    /* Test exporting private and public parts separately */
    rc = wolfTPM2_GetKeyBlobAsSeparateBuffers(blob, &pubBufferSz,
        blob +pubBufferSz, &privBufferSz, &key);
    AssertIntEQ(rc, 0);

    /* Test getting size only */
    rc = wolfTPM2_GetKeyBlobAsBuffer(NULL, sizeof(blob), &key);
    AssertIntGT(rc, 0);

    /* Export private and public key */
    rc = wolfTPM2_GetKeyBlobAsBuffer(blob, sizeof(blob), &key);
    AssertIntGT(rc, 0);

    /* Reset the originally created key */
    XMEMSET(&key, 0, sizeof(key));

    /* Load key blob (private/public) from buffer */
    rc = wolfTPM2_SetKeyBlobFromBuffer(&key, blob, rc);
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

/* Test DecodeRsaDer/DecodeEccDer default attributes for private key imports */
#if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_ASN)
static void test_wolfTPM2_DecodeDer_DefaultAttribs(void)
{
#ifdef HAVE_ECC
    int rc;
    TPM2B_PUBLIC pub;
    TPM2B_SENSITIVE sens;
    TPMA_OBJECT attrs;
    /* ECC P-256 private key DER (from certs/example-ecc256-key.der) */
    static const byte eccKeyDer[] = {
        0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20, 0x45, 0xb6, 0x69, 0x02,
        0x73, 0x9c, 0x6c, 0x85, 0xa1, 0x38, 0x5b, 0x72, 0xe8, 0xe8, 0xc7,
        0xac, 0xc4, 0x03, 0x8d, 0x53, 0x35, 0x04, 0xfa, 0x6c, 0x28, 0xdc,
        0x34, 0x8d, 0xe1, 0xa8, 0x09, 0x8c, 0xa0, 0x0a, 0x06, 0x08, 0x2a,
        0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0xa1, 0x44, 0x03, 0x42,
        0x00, 0x04, 0xbb, 0x33, 0xac, 0x4c, 0x27, 0x50, 0x4a, 0xc6, 0x4a,
        0xa5, 0x04, 0xc3, 0x3c, 0xde, 0x9f, 0x36, 0xdb, 0x72, 0x2d, 0xce,
        0x94, 0xea, 0x2b, 0xfa, 0xcb, 0x20, 0x09, 0x39, 0x2c, 0x16, 0xe8,
        0x61, 0x02, 0xe9, 0xaf, 0x4d, 0xd3, 0x02, 0x93, 0x9a, 0x31, 0x5b,
        0x97, 0x92, 0x21, 0x7f, 0xf0, 0xcf, 0x18, 0xda, 0x91, 0x11, 0x02,
        0x34, 0x86, 0xe8, 0x20, 0x58, 0x33, 0x0b, 0x80, 0x34, 0x89, 0xd8
    };

    XMEMSET(&pub, 0, sizeof(pub));
    XMEMSET(&sens, 0, sizeof(sens));

    /* Call with attributes=0 and sens!=NULL (private key import) */
    rc = wolfTPM2_DecodeEccDer(eccKeyDer, (word32)sizeof(eccKeyDer),
        &pub, &sens, 0);
    AssertIntEQ(rc, 0);

    attrs = pub.publicArea.objectAttributes;

    /* For imported private keys, restricted must NOT be set when both
     * sign and decrypt are set (TPM 2.0 Part 2 Table 31) */
    AssertIntEQ(attrs & TPMA_OBJECT_restricted, 0);

    /* sensitiveDataOrigin must NOT be set for imported keys */
    AssertIntEQ(attrs & TPMA_OBJECT_sensitiveDataOrigin, 0);

    /* sign and decrypt should both be set for general-purpose imported keys */
    AssertTrue(attrs & TPMA_OBJECT_sign);
    AssertTrue(attrs & TPMA_OBJECT_decrypt);

    /* userWithAuth should be set */
    AssertTrue(attrs & TPMA_OBJECT_userWithAuth);

    /* When both sign and decrypt are set, scheme must be NULL */
    AssertIntEQ(pub.publicArea.parameters.eccDetail.scheme.scheme,
        TPM_ALG_NULL);
#endif
    /* Note: DecodeRsaDer uses the same default attribute and scheme logic
     * as DecodeEccDer — validated by the ECC test above. RSA DER key is
     * too large (1217 bytes) to embed inline for a unit test. */

    printf("Test TPM Wrapper:\tDecodeDer DefaultAttribs:\tPassed\n");
}
#endif /* !WOLFTPM2_NO_WOLFCRYPT && !NO_ASN */

/* Test NULL parentKey handling in LoadRsaPrivateKey_ex and LoadEccPrivateKey */
static void test_wolfTPM2_LoadPrivateKey_NullParent(void)
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY key;
#ifndef NO_RSA
    /* Dummy RSA key material for testing NULL parentKey handling */
    byte rsaPub[1] = {0};
    byte rsaPriv[1] = {0};
#endif
#ifdef HAVE_ECC
    /* Dummy ECC key material for testing NULL parentKey handling */
    byte eccPubX[32] = {0};
    byte eccPubY[32] = {0};
    byte eccPriv[32] = {0};
#endif

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, NULL);
    AssertIntEQ(rc, 0);

    XMEMSET(&key, 0, sizeof(key));

    /* Test NULL parentKey does not crash (should not dereference NULL) */
#ifndef NO_RSA
    rc = wolfTPM2_LoadRsaPrivateKey_ex(&dev, NULL, &key, rsaPub, sizeof(rsaPub),
        RSA_DEFAULT_PUBLIC_EXPONENT, rsaPriv, sizeof(rsaPriv),
        TPM_ALG_NULL, TPM_ALG_NULL);
    /* rc may fail due to no real TPM, but must not crash */
    AssertIntNE(rc, BAD_FUNC_ARG);
#endif
#ifdef HAVE_ECC
    XMEMSET(&key, 0, sizeof(key));
    rc = wolfTPM2_LoadEccPrivateKey(&dev, NULL, &key, TPM_ECC_NIST_P256,
        eccPubX, sizeof(eccPubX), eccPubY, sizeof(eccPubY),
        eccPriv, sizeof(eccPriv));
    /* rc may fail due to no real TPM, but must not crash */
    AssertIntNE(rc, BAD_FUNC_ARG);
#endif

    wolfTPM2_Cleanup(&dev);

    printf("Test TPM Wrapper:\tLoadPrivateKey NullParent:\tPassed\n");
}

static void test_wolfTPM2_EncryptDecryptBlock(void)
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY key;
    byte in[MAX_AES_BLOCK_SIZE_BYTES];
    byte out[MAX_AES_BLOCK_SIZE_BYTES];
    byte iv[MAX_AES_BLOCK_SIZE_BYTES];
    byte bigIv[MAX_SYM_BLOCK_SIZE + 1];

    XMEMSET(in, 0, sizeof(in));
    XMEMSET(out, 0, sizeof(out));
    XMEMSET(iv, 0, sizeof(iv));
    XMEMSET(bigIv, 0, sizeof(bigIv));

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, NULL);
    AssertIntEQ(rc, 0);

    XMEMSET(&key, 0, sizeof(key));

    /* CBC mode: NULL IV should return BAD_FUNC_ARG */
    key.pub.publicArea.parameters.symDetail.sym.mode.aes = TPM_ALG_CBC;
    rc = wolfTPM2_EncryptDecryptBlock(&dev, &key, in, out,
        sizeof(in), NULL, 0, WOLFTPM2_ENCRYPT);
    AssertIntEQ(rc, BAD_FUNC_ARG);

    /* CBC mode: ivSz == 0 with non-NULL iv should return BAD_FUNC_ARG */
    rc = wolfTPM2_EncryptDecryptBlock(&dev, &key, in, out,
        sizeof(in), iv, 0, WOLFTPM2_ENCRYPT);
    AssertIntEQ(rc, BAD_FUNC_ARG);

    /* CFB mode: NULL IV should return BAD_FUNC_ARG */
    key.pub.publicArea.parameters.symDetail.sym.mode.aes = TPM_ALG_CFB;
    rc = wolfTPM2_EncryptDecryptBlock(&dev, &key, in, out,
        sizeof(in), NULL, 0, WOLFTPM2_ENCRYPT);
    AssertIntEQ(rc, BAD_FUNC_ARG);

    /* CTR mode: NULL IV should return BAD_FUNC_ARG */
    key.pub.publicArea.parameters.symDetail.sym.mode.aes = TPM_ALG_CTR;
    rc = wolfTPM2_EncryptDecryptBlock(&dev, &key, in, out,
        sizeof(in), NULL, 0, WOLFTPM2_ENCRYPT);
    AssertIntEQ(rc, BAD_FUNC_ARG);

    /* OFB mode: NULL IV should return BAD_FUNC_ARG */
    key.pub.publicArea.parameters.symDetail.sym.mode.aes = TPM_ALG_OFB;
    rc = wolfTPM2_EncryptDecryptBlock(&dev, &key, in, out,
        sizeof(in), NULL, 0, WOLFTPM2_ENCRYPT);
    AssertIntEQ(rc, BAD_FUNC_ARG);

    /* Oversized IV should return BUFFER_E */
    key.pub.publicArea.parameters.symDetail.sym.mode.aes = TPM_ALG_CBC;
    rc = wolfTPM2_EncryptDecryptBlock(&dev, &key, in, out,
        sizeof(in), bigIv, sizeof(bigIv), WOLFTPM2_ENCRYPT);
    AssertIntEQ(rc, BUFFER_E);

    /* ECB mode: NULL IV should NOT return BAD_FUNC_ARG */
    key.pub.publicArea.parameters.symDetail.sym.mode.aes = TPM_ALG_ECB;
    rc = wolfTPM2_EncryptDecryptBlock(&dev, &key, in, out,
        sizeof(in), NULL, 0, WOLFTPM2_ENCRYPT);
    AssertIntNE(rc, BAD_FUNC_ARG);

    /* NULL mode: NULL IV should NOT return BAD_FUNC_ARG */
    key.pub.publicArea.parameters.symDetail.sym.mode.aes = TPM_ALG_NULL;
    rc = wolfTPM2_EncryptDecryptBlock(&dev, &key, in, out,
        sizeof(in), NULL, 0, WOLFTPM2_ENCRYPT);
    AssertIntNE(rc, BAD_FUNC_ARG);

    wolfTPM2_Cleanup(&dev);

    printf("Test TPM Wrapper:\tEncryptDecryptBlock IV validate:\tPassed\n");
}

#ifdef HAVE_ECC
static void test_wolfTPM2_ImportEccPrivateKeySeed_ErrorPaths(void)
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY parentKey;
    WOLFTPM2_KEYBLOB keyBlob;
    byte eccPubX[32];
    byte eccPubY[32];
    byte eccPriv[32];
    /* Wrong-size seed to trigger seed size mismatch error path.
     * WOLFTPM2_WRAP_DIGEST is SHA256 (digestSz=32), so seedSz=1 mismatches. */
    byte seed[1] = {0x42};
    TPMA_OBJECT attrs = (TPMA_OBJECT_sign | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_noDA);

    XMEMSET(eccPubX, 0x01, sizeof(eccPubX));
    XMEMSET(eccPubY, 0x02, sizeof(eccPubY));
    XMEMSET(eccPriv, 0x03, sizeof(eccPriv));

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, NULL);
    AssertIntEQ(rc, 0);
    XMEMSET(&parentKey, 0, sizeof(parentKey));
    XMEMSET(&keyBlob, 0, sizeof(keyBlob));

    /* Seed size mismatch must return BAD_FUNC_ARG (and zero sens) */
    rc = wolfTPM2_ImportEccPrivateKeySeed(&dev, &parentKey, &keyBlob,
        TPM_ECC_NIST_P256, eccPubX, sizeof(eccPubX), eccPubY, sizeof(eccPubY),
        eccPriv, sizeof(eccPriv), attrs, seed, sizeof(seed));
    AssertIntEQ(rc, BAD_FUNC_ARG);

    wolfTPM2_Cleanup(&dev);

    printf("Test TPM Wrapper:\tImportEccSeed error paths:\tPassed\n");
}
#endif /* HAVE_ECC */

static void test_wolfTPM2_NVStoreKey_BoundaryChecks(void)
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY key;

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, NULL);
    AssertIntEQ(rc, 0);

    XMEMSET(&key, 0, sizeof(key));

    /* Owner hierarchy: handle below PERSISTENT_FIRST must fail */
    rc = wolfTPM2_NVStoreKey(&dev, TPM_RH_OWNER, &key,
        PERSISTENT_FIRST - 1);
    AssertIntEQ(rc, BAD_FUNC_ARG);

    /* Owner hierarchy: handle above PERSISTENT_LAST must fail */
    rc = wolfTPM2_NVStoreKey(&dev, TPM_RH_OWNER, &key,
        PERSISTENT_LAST + 1);
    AssertIntEQ(rc, BAD_FUNC_ARG);

    /* Owner hierarchy: PERSISTENT_FIRST must NOT fail with BAD_FUNC_ARG */
    key.handle.hndl = 0; /* ensure not already persistent */
    rc = wolfTPM2_NVStoreKey(&dev, TPM_RH_OWNER, &key,
        PERSISTENT_FIRST);
    AssertIntNE(rc, BAD_FUNC_ARG);

    /* Owner hierarchy: PERSISTENT_LAST must NOT fail with BAD_FUNC_ARG */
    rc = wolfTPM2_NVStoreKey(&dev, TPM_RH_OWNER, &key,
        PERSISTENT_LAST);
    AssertIntNE(rc, BAD_FUNC_ARG);

    /* Platform hierarchy: handle below PLATFORM_PERSISTENT must fail */
    rc = wolfTPM2_NVStoreKey(&dev, TPM_RH_PLATFORM, &key,
        PLATFORM_PERSISTENT - 1);
    AssertIntEQ(rc, BAD_FUNC_ARG);

    /* Platform hierarchy: PLATFORM_PERSISTENT must NOT fail with BAD_FUNC_ARG */
    rc = wolfTPM2_NVStoreKey(&dev, TPM_RH_PLATFORM, &key,
        PLATFORM_PERSISTENT);
    AssertIntNE(rc, BAD_FUNC_ARG);

    wolfTPM2_Cleanup(&dev);

    printf("Test TPM Wrapper:\tNVStoreKey boundary checks:\tPassed\n");
}

static void test_wolfTPM2_NVDeleteKey_BoundaryChecks(void)
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY key;

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, NULL);
    AssertIntEQ(rc, 0);

    XMEMSET(&key, 0, sizeof(key));

    /* Handle below PERSISTENT_FIRST: not persistent, early-return success */
    key.handle.hndl = PERSISTENT_FIRST - 1;
    rc = wolfTPM2_NVDeleteKey(&dev, TPM_RH_OWNER, &key);
    AssertIntEQ(rc, TPM_RC_SUCCESS);

    /* Handle above PERSISTENT_LAST: not persistent, early-return success */
    key.handle.hndl = PERSISTENT_LAST + 1;
    rc = wolfTPM2_NVDeleteKey(&dev, TPM_RH_OWNER, &key);
    AssertIntEQ(rc, TPM_RC_SUCCESS);

    /* Handle equal to PERSISTENT_FIRST: IS persistent, must NOT early-return */
    key.handle.hndl = PERSISTENT_FIRST;
    rc = wolfTPM2_NVDeleteKey(&dev, TPM_RH_OWNER, &key);
    AssertIntNE(rc, TPM_RC_SUCCESS); /* will fail at TPM, but not early-return */

    /* Handle equal to PERSISTENT_LAST: IS persistent, must NOT early-return */
    key.handle.hndl = PERSISTENT_LAST;
    rc = wolfTPM2_NVDeleteKey(&dev, TPM_RH_OWNER, &key);
    AssertIntNE(rc, TPM_RC_SUCCESS); /* will fail at TPM, but not early-return */

    wolfTPM2_Cleanup(&dev);

    printf("Test TPM Wrapper:\tNVDeleteKey boundary checks:\tPassed\n");
}

static void test_wolfTPM2_UnloadHandle_PersistentGuard(void)
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_HANDLE handle;

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, NULL);
    AssertIntEQ(rc, 0);

    XMEMSET(&handle, 0, sizeof(handle));

    /* Persistent handles must be skipped (return SUCCESS, no FlushContext) */
    handle.hndl = PERSISTENT_FIRST;
    rc = wolfTPM2_UnloadHandle(&dev, &handle);
    AssertIntEQ(rc, TPM_RC_SUCCESS);

    handle.hndl = PERSISTENT_LAST;
    rc = wolfTPM2_UnloadHandle(&dev, &handle);
    AssertIntEQ(rc, TPM_RC_SUCCESS);

    /* Null handle must be skipped */
    handle.hndl = TPM_RH_NULL;
    rc = wolfTPM2_UnloadHandle(&dev, &handle);
    AssertIntEQ(rc, TPM_RC_SUCCESS);

    /* Zero handle must be skipped */
    handle.hndl = 0;
    rc = wolfTPM2_UnloadHandle(&dev, &handle);
    AssertIntEQ(rc, TPM_RC_SUCCESS);

    /* Handle just outside persistent range: NOT skipped (attempts flush) */
    handle.hndl = PERSISTENT_FIRST - 1;
    rc = wolfTPM2_UnloadHandle(&dev, &handle);
    AssertIntNE(rc, TPM_RC_SUCCESS);

    handle.hndl = PERSISTENT_LAST + 1;
    rc = wolfTPM2_UnloadHandle(&dev, &handle);
    AssertIntNE(rc, TPM_RC_SUCCESS);

    wolfTPM2_Cleanup(&dev);

    printf("Test TPM Wrapper:\tUnloadHandle persistent guard:\tPassed\n");
}

static void test_TPM2_GetHashDigestSize_AllAlgs(void)
{
    /* Standard algorithms already supported */
    AssertIntEQ(TPM2_GetHashDigestSize(TPM_ALG_SHA1),   TPM_SHA_DIGEST_SIZE);
    AssertIntEQ(TPM2_GetHashDigestSize(TPM_ALG_SHA256), TPM_SHA256_DIGEST_SIZE);
    AssertIntEQ(TPM2_GetHashDigestSize(TPM_ALG_SHA384), TPM_SHA384_DIGEST_SIZE);
    AssertIntEQ(TPM2_GetHashDigestSize(TPM_ALG_SHA512), TPM_SHA512_DIGEST_SIZE);

    /* SM3 and SHA3 must return correct non-zero digest sizes */
    AssertIntEQ(TPM2_GetHashDigestSize(TPM_ALG_SM3_256),  TPM_SHA256_DIGEST_SIZE);
    AssertIntEQ(TPM2_GetHashDigestSize(TPM_ALG_SHA3_256), TPM_SHA256_DIGEST_SIZE);
    AssertIntEQ(TPM2_GetHashDigestSize(TPM_ALG_SHA3_384), TPM_SHA384_DIGEST_SIZE);
    AssertIntEQ(TPM2_GetHashDigestSize(TPM_ALG_SHA3_512), TPM_SHA512_DIGEST_SIZE);

    /* Unknown algorithm must return 0 */
    AssertIntEQ(TPM2_GetHashDigestSize(TPM_ALG_NULL), 0);

    printf("Test TPM2:\t\tGetHashDigestSize all algs:\tPassed\n");
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
    test_TPM2_PCRSel();
    test_TPM2_Policy_NULL_Args();
    test_wolfTPM2_PolicyAuthValue_AuthOffset();
    test_wolfTPM2_SetAuthHandle_PolicyAuthOffset();
    test_wolfTPM2_PolicyHash();
    test_wolfTPM2_SensitiveToPrivate();
    test_TPM2_KDFa();
    test_TPM2_KDFa_SessionLabels();
    test_TPM2_KDFe();
    test_TPM2_HmacCompute();
    test_TPM2_HashCompute();
    test_TPM2_ConstantCompare();
    test_TPM2_AesCfbRoundtrip();
    test_TPM2_KDFa_MultiHash();
    test_TPM2_KDFe_MultiHash();
    test_TPM2_HmacCompute_MultiHash();
    test_TPM2_HashCompute_MultiHash();
    test_TPM2_KDF_Errors();
    test_TPM2_GetTpmHashType();
    test_TPM2_ResponseHmacVerification();
    test_TPM2_CalcHmac();
    test_TPM2_ParamEnc_XOR_Vector();
    test_TPM2_ParamEnc_AESCFB_Vector();
    test_TPM2_ParamDec_XOR_Roundtrip();
    test_TPM2_ParamDec_AESCFB_Roundtrip();
    test_TPM2_ParamEncDec_Dispatch_Roundtrip();
    test_TPM2_HashNvPublic();
    #if !defined(WOLFTPM2_NO_WOLFCRYPT) && defined(HAVE_ECC)
    test_wolfTPM2_ComputeName();
    #endif
    test_TPM2_SchemeSerialize();
    test_TPM2_ECC_Parameters_EcdaaResponseParse();
    test_TPM2_KeyedHashScheme_XorSerialize();
    test_TPM2_Signature_EcSchnorrSm2Serialize();
    test_TPM2_Sensitive_Roundtrip();
    test_KeySealTemplate();
    test_SealAndKeyedHash_Boundaries();
    test_GetAlgId();
    test_wolfTPM2_ReadPublicKey();
    test_wolfTPM2_CSR();
    #if !defined(WOLFTPM2_NO_WOLFCRYPT) && defined(WOLFTPM2_PEM_DECODE) && \
        !defined(NO_RSA)
    test_wolfTPM_ImportPublicKey();
    test_wolfTPM2_PCRPolicy();
    #endif
    test_wolfTPM2_EncryptSecret();
    #if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_ASN)
    test_wolfTPM2_DecodeDer_DefaultAttribs();
    #endif
    test_wolfTPM2_LoadPrivateKey_NullParent();
    test_wolfTPM2_EncryptDecryptBlock();
    #ifdef HAVE_ECC
    test_wolfTPM2_ImportEccPrivateKeySeed_ErrorPaths();
    #endif
    test_wolfTPM2_NVStoreKey_BoundaryChecks();
    test_wolfTPM2_NVDeleteKey_BoundaryChecks();
    test_wolfTPM2_UnloadHandle_PersistentGuard();
    test_TPM2_GetHashDigestSize_AllAlgs();
    test_wolfTPM2_KeyBlob(TPM_ALG_RSA);
    test_wolfTPM2_KeyBlob(TPM_ALG_ECC);
    #if !defined(WOLFTPM2_NO_WOLFCRYPT) && defined(HAVE_ECC) && \
        !defined(WOLFTPM2_NO_ASN)
    test_wolfTPM2_EccSignVerify();
    #endif
    #ifdef WOLFTPM_FIRMWARE_UPGRADE
    #if defined(WOLFTPM_ST33) || defined(WOLFTPM_AUTODETECT)
    test_wolfTPM2_ST33_FirmwareUpgrade();
    #endif
    #endif
    test_wolfTPM2_Cleanup();
    test_wolfTPM2_thread_local_storage();
#ifdef WOLFTPM_SPDM
    test_wolfTPM2_SPDM_Functions();
#endif
#endif /* !WOLFTPM2_NO_WRAPPER */

    return 0;
}
