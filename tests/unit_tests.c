/* unit_tests.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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
#ifndef WOLFTPM2_NO_WOLFCRYPT
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

#ifndef WOLFTPM2_NO_WOLFCRYPT
    /* wolfTPM2_FirmwareUpgrade - NULL dev */
    rc = wolfTPM2_FirmwareUpgrade(NULL, NULL, 0, NULL, NULL);
    AssertIntNE(rc, 0);
#endif /* !WOLFTPM2_NO_WOLFCRYPT */

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

#ifndef WOLFTPM2_NO_WOLFCRYPT
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
#endif /* !WOLFTPM2_NO_WOLFCRYPT */

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

    rc = TPM2_KDFa(TPM_ALG_SHA256, &keyIn, label, &contextU, &contextV, key,
        keyIn.size);
#ifdef WOLFTPM2_NO_WOLFCRYPT
    AssertIntEQ(NOT_COMPILED_IN, rc);
#else
    AssertIntEQ(sizeof(keyExp), rc);
    AssertIntEQ(XMEMCMP(key, keyExp, sizeof(keyExp)), 0);
#endif

    printf("Test TPM Wrapper:\tKDFa:\t%s\n",
        rc >= 0 ? "Passed" : "Failed");
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
    TPM2_AUTH_SESSION session;
    TPM2B_AUTH sessKey;
    TPM2B_NONCE nonceCaller, nonceTPM;
    const byte original[] = "XOR parameter encryption round-trip test";
    byte data[sizeof(original)];

    XMEMSET(&session, 0, sizeof(session));
    session.authHash = TPM_ALG_SHA256;

    sessKey.size = TPM_SHA256_DIGEST_SIZE;
    XMEMSET(sessKey.buffer, 0xCC, sessKey.size);

    nonceCaller.size = TPM_SHA256_DIGEST_SIZE;
    XMEMSET(nonceCaller.buffer, 0x11, nonceCaller.size);
    nonceTPM.size = TPM_SHA256_DIGEST_SIZE;
    XMEMSET(nonceTPM.buffer, 0x22, nonceTPM.size);

    XMEMCPY(data, original, sizeof(original));

    /* Encrypt */
    rc = TPM2_ParamEnc_XOR(&session, &sessKey, NULL, &nonceCaller, &nonceTPM,
        data, sizeof(data));
    AssertIntEQ(TPM_RC_SUCCESS, rc);

    /* Data must differ from original */
    AssertIntNE(0, XMEMCMP(data, original, sizeof(original)));

    /* Encrypt again with same args — XOR is self-inverse */
    rc = TPM2_ParamEnc_XOR(&session, &sessKey, NULL, &nonceCaller, &nonceTPM,
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
    TPM2_AUTH_SESSION session;
    TPM2B_AUTH sessKey;
    TPM2B_NONCE nonceCaller, nonceTPM;
    const byte original[] = "AES-CFB parameter encryption round-trip test";
    byte data[sizeof(original)];

    XMEMSET(&session, 0, sizeof(session));
    session.authHash = TPM_ALG_SHA256;
    session.symmetric.keyBits.aes = MAX_AES_KEY_BITS;

    sessKey.size = TPM_SHA256_DIGEST_SIZE;
    XMEMSET(sessKey.buffer, 0xDD, sessKey.size);

    nonceCaller.size = TPM_SHA256_DIGEST_SIZE;
    XMEMSET(nonceCaller.buffer, 0x33, nonceCaller.size);
    nonceTPM.size = TPM_SHA256_DIGEST_SIZE;
    XMEMSET(nonceTPM.buffer, 0x44, nonceTPM.size);

    XMEMCPY(data, original, sizeof(original));

    /* Encrypt with (nonceCaller, nonceTPM) */
    rc = TPM2_ParamEnc_AESCFB(&session, &sessKey, NULL, &nonceCaller,
        &nonceTPM, data, sizeof(data));
    AssertIntEQ(TPM_RC_SUCCESS, rc);

    /* Data must differ from original */
    AssertIntNE(0, XMEMCMP(data, original, sizeof(original)));

    /* Decrypt: swap nonce args so KDFa produces same key */
    rc = TPM2_ParamDec_AESCFB(&session, &sessKey, NULL, &nonceTPM,
        &nonceCaller, data, sizeof(data));
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
    TPM2_AUTH_SESSION session;
    TPM2B_AUTH sessKey;
    TPM2B_NONCE nonceCaller, nonceTPM;
    const byte original[] = "XOR parameter decryption round-trip test";
    byte data[sizeof(original)];

    XMEMSET(&session, 0, sizeof(session));
    session.authHash = TPM_ALG_SHA256;

    sessKey.size = TPM_SHA256_DIGEST_SIZE;
    XMEMSET(sessKey.buffer, 0xEE, sessKey.size);

    nonceCaller.size = TPM_SHA256_DIGEST_SIZE;
    XMEMSET(nonceCaller.buffer, 0x55, nonceCaller.size);
    nonceTPM.size = TPM_SHA256_DIGEST_SIZE;
    XMEMSET(nonceTPM.buffer, 0x66, nonceTPM.size);

    XMEMCPY(data, original, sizeof(original));

    /* Decrypt direction: XOR with (nonceCaller, nonceTPM) mask */
    rc = TPM2_ParamDec_XOR(&session, &sessKey, NULL, &nonceCaller, &nonceTPM,
        data, sizeof(data));
    AssertIntEQ(TPM_RC_SUCCESS, rc);

    /* Data must differ from original */
    AssertIntNE(0, XMEMCMP(data, original, sizeof(original)));

    /* Apply same XOR again — self-inverse recovers original */
    rc = TPM2_ParamDec_XOR(&session, &sessKey, NULL, &nonceCaller, &nonceTPM,
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
    TPM2_AUTH_SESSION session;
    TPM2B_AUTH sessKey;
    TPM2B_NONCE nonceCaller, nonceTPM;
    const byte original[] = "AES-CFB parameter decryption round-trip test";
    byte data[sizeof(original)];

    XMEMSET(&session, 0, sizeof(session));
    session.authHash = TPM_ALG_SHA256;
    session.symmetric.keyBits.aes = MAX_AES_KEY_BITS;

    sessKey.size = TPM_SHA256_DIGEST_SIZE;
    XMEMSET(sessKey.buffer, 0xFF, sessKey.size);

    nonceCaller.size = TPM_SHA256_DIGEST_SIZE;
    XMEMSET(nonceCaller.buffer, 0x77, nonceCaller.size);
    nonceTPM.size = TPM_SHA256_DIGEST_SIZE;
    XMEMSET(nonceTPM.buffer, 0x88, nonceTPM.size);

    XMEMCPY(data, original, sizeof(original));

    /* Encrypt with ParamEnc_AESCFB (command direction) */
    rc = TPM2_ParamEnc_AESCFB(&session, &sessKey, NULL, &nonceCaller,
        &nonceTPM, data, sizeof(data));
    AssertIntEQ(TPM_RC_SUCCESS, rc);

    /* Data must differ from original */
    AssertIntNE(0, XMEMCMP(data, original, sizeof(original)));

    /* Decrypt with ParamDec_AESCFB: swap nonce args so internal KDFa
     * produces the same key as encryption */
    rc = TPM2_ParamDec_AESCFB(&session, &sessKey, NULL, &nonceTPM,
        &nonceCaller, data, sizeof(data));
    AssertIntEQ(TPM_RC_SUCCESS, rc);

    /* Must match original */
    AssertIntEQ(0, XMEMCMP(data, original, sizeof(original)));

    printf("Test TPM Wrapper:\tParamDec_AESCFB_Roundtrip:\tPassed\n");
#endif
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
    test_TPM2_ConstantCompare();
    test_TPM2_ResponseHmacVerification();
    test_TPM2_CalcHmac();
    test_TPM2_ParamEnc_XOR_Vector();
    test_TPM2_ParamEnc_AESCFB_Vector();
    test_TPM2_ParamDec_XOR_Roundtrip();
    test_TPM2_ParamDec_AESCFB_Roundtrip();
    test_GetAlgId();
    test_wolfTPM2_ReadPublicKey();
    test_wolfTPM2_CSR();
    #if !defined(WOLFTPM2_NO_WOLFCRYPT) && defined(WOLFTPM2_PEM_DECODE) && \
        !defined(NO_RSA)
    test_wolfTPM_ImportPublicKey();
    test_wolfTPM2_PCRPolicy();
    #endif
    test_wolfTPM2_EncryptSecret();
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
