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
#include <wolftpm/tpm2_swtpm.h>
#include <wolftpm/tpm2_tis.h>
#include <wolftpm/tpm2_spdm.h>

#include <hal/tpm_io.h>
#include <examples/tpm_test.h>
#include <examples/tpm_test_keys.h>
#include <examples/wrap/wrap_test.h>

#include <stdio.h>
#if defined(__linux__) || defined(__APPLE__) || defined(__unix__)
#include <fcntl.h>
#endif

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

    printf("Test TPM Wrapper: %-40s %s\n", "Init:",
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

    printf("Test TPM Wrapper: %-40s %s\n", "Open Existing:",
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
    printf("Mfg %s (%d), Vendor %s, Fw %u.%u (%u), FIPS %s, CC-EAL4 %d\n",
        caps.mfgStr, caps.mfg, caps.vendorStr, caps.fwVerMajor,
        caps.fwVerMinor, caps.fwVerVendor,
        TPM2_GetCapsFipsStr(caps.fips140_3, caps.fips140_2),
        caps.cc_eal4);
#endif

    wolfTPM2_Cleanup(&dev);

    printf("Test TPM Wrapper: %-40s %s\n", "Get Capabilities:",
        rc == 0 ? "Passed" : "Failed");
}

static void test_wolfTPM2_DictionaryAttack(void)
{
    /* Argument validation (non-destructive; the functional lockout/recovery
     * path is exercised by examples/management/da_check and the fwTPM unit
     * tests). */
    AssertIntEQ(wolfTPM2_DictionaryAttackLockReset(NULL), BAD_FUNC_ARG);
    AssertIntEQ(wolfTPM2_DictionaryAttackParameters(NULL, 32, 0, 0),
        BAD_FUNC_ARG);
    /* newMaxTries of 0 is rejected client-side */
    AssertIntEQ(wolfTPM2_DictionaryAttackParameters((WOLFTPM2_DEV*)1, 0, 0, 0),
        BAD_FUNC_ARG);

    printf("Test TPM Wrapper: %-40s %s\n", "Dictionary Attack args:",
        "Passed");
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

    printf("Test TPM Wrapper: %-40s %s\n", "Read Public Key:",
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
        printf("Test ST33 FW:     %-40s Skipped (TPM not available)\n", "Init:");
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

    printf("Test ST33 FW:     %-40s Passed\n", "API Availability:");
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

    printf("Test TPM Wrapper: %-40s %s\n", "Get Random:",
        rc == 0 ? "Passed" : "Failed");
}

static void test_wolfTPM2_HashFinish_BufferTooSmall(void)
{
#ifndef WOLFTPM2_NO_WOLFCRYPT
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_HASH hash;
    byte digest[TPM_SHA256_DIGEST_SIZE];
    word32 digestSz;

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, NULL);
    AssertIntEQ(rc, 0);

    XMEMSET(&hash, 0, sizeof(hash));
    rc = wolfTPM2_HashStart(&dev, &hash, TPM_ALG_SHA256, NULL, 0);
    AssertIntEQ(rc, 0);
    rc = wolfTPM2_HashUpdate(&dev, &hash, (const byte*)"abc", 3);
    AssertIntEQ(rc, 0);

    /* Undersized buffer must be rejected, not silently truncated, and the
     * required size reported back to the caller. */
    digestSz = 1;
    rc = wolfTPM2_HashFinish(&dev, &hash, digest, &digestSz);
    AssertIntEQ(BUFFER_E, rc);
    AssertIntEQ(TPM_SHA256_DIGEST_SIZE, (int)digestSz);

    wolfTPM2_Cleanup(&dev);

    printf("Test TPM Wrapper: %-40s Passed\n", "HashFinish BufferTooSmall:");
#else
    printf("Test TPM Wrapper: %-40s Skipped\n", "HashFinish BufferTooSmall:");
#endif
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

    printf("Test TPM Wrapper: %-40s %s\n", "PCR Select Array:",
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

    printf("Test TPM2:        %-40s Passed\n", "Policy NULL Args:");
}

static void test_wolfTPM2_SetLocality(void)
{
    int rc = 0;
    WOLFTPM2_DEV dev;

    XMEMSET(&dev, 0, sizeof(dev));

    /* Argument validation. The Linux-kernel driver and Windows TBS backends
     * return NOT_COMPILED_IN before validating args, so only assert
     * BAD_FUNC_ARG on the SWTPM and built-in TIS backends. */
#if !defined(WOLFTPM_LINUX_DEV) && !defined(WOLFTPM_WINAPI)
    rc = wolfTPM2_SetLocality(NULL, 0);
    AssertIntEQ(rc, BAD_FUNC_ARG);
    rc = wolfTPM2_SetLocality(&dev, -1);
    AssertIntEQ(rc, BAD_FUNC_ARG);
    rc = wolfTPM2_SetLocality(&dev, 5);
    AssertIntEQ(rc, BAD_FUNC_ARG);
#endif

#if defined(WOLFTPM_SWTPM)
    /* SWTPM/mssim record-only path: records the locality for subsequent
     * commands with no TIS handshake, so it needs no live connection. */
    rc = wolfTPM2_SetLocality(&dev, 2);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    AssertIntEQ(dev.ctx.locality, 2);
#endif
    (void)rc;

    printf("Test TPM Wrapper: %-40s Passed\n", "SetLocality args/SWTPM:");
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

    printf("Test TPM Wrapper: %-40s Passed\n", "PolicyAuthValue Offset:");
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

    printf("Test TPM Wrapper: %-40s Passed\n", "SetAuthHandle PolicyAuth:");
#endif
}

/* Verify wolfTPM2_StartSession enables encrypt/decrypt attributes for
 * salted (tpmKey-only, bind == NULL) sessions when caller selects a
 * symmetric algorithm. Per TPM 2.0 spec, salted sessions have valid
 * shared-secret state for parameter encryption. */
static void test_wolfTPM2_StartSession_SaltedEncryptAttrs(void)
{
#if !defined(WOLFTPM2_NO_WOLFCRYPT)
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY tpmKey;
    WOLFTPM2_SESSION session;
    TPMA_SESSION expected = TPMA_SESSION_decrypt | TPMA_SESSION_encrypt;

    XMEMSET(&dev, 0, sizeof(dev));
    XMEMSET(&tpmKey, 0, sizeof(tpmKey));
    XMEMSET(&session, 0, sizeof(session));

    /* Initialize so TPM2_GetNonceNoLock and dependent code paths have a
     * valid context. Skip if no TPM is reachable. */
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, NULL);
    if (rc != 0) {
        printf("Test TPM Wrapper:\tStartSession salted enc attrs:\tSkipped\n");
        return;
    }

    /* tpmKey with a non-NULL handle, no auth */
    tpmKey.handle.hndl = 0x80000000;

    /* The call will fail later (no real key with that handle) but the
     * SetAuth path that sets sessionAttributes runs first. */
    (void)wolfTPM2_StartSession(&dev, &session, &tpmKey, NULL,
        TPM_SE_HMAC, TPM_ALG_CFB);

    AssertIntEQ((int)(dev.session[0].sessionAttributes & expected),
        (int)expected);

    wolfTPM2_Cleanup(&dev);
    printf("Test TPM Wrapper:\tStartSession salted enc attrs:\tPassed\n");
#endif
}

static void test_wolfTPM2_StartSession_ex_authHash(void)
{
#if !defined(WOLFTPM2_NO_WOLFCRYPT) && defined(WOLFSSL_SHA512)
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_SESSION session;

    XMEMSET(&dev, 0, sizeof(dev));
    XMEMSET(&session, 0, sizeof(session));

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, NULL);
    if (rc != 0) {
        printf("Test TPM Wrapper:\tStartSession_ex SHA512:\tSkipped\n");
        return;
    }

    /* default (SHA-256) selected via TPM_ALG_NULL */
    rc = wolfTPM2_StartSession_ex(&dev, &session, NULL, NULL,
        TPM_SE_POLICY, TPM_ALG_NULL, TPM_ALG_NULL);
    if (rc == TPM_RC_SUCCESS) {
        AssertIntEQ(session.authHash, WOLFTPM2_WRAP_DIGEST);
        wolfTPM2_UnloadHandle(&dev, &session.handle);
    }

    /* explicit SHA-512 selection */
    rc = wolfTPM2_StartSession_ex(&dev, &session, NULL, NULL,
        TPM_SE_POLICY, TPM_ALG_NULL, TPM_ALG_SHA512);
    if (rc == TPM_RC_SUCCESS) {
        AssertIntEQ(session.authHash, TPM_ALG_SHA512);
        wolfTPM2_UnloadHandle(&dev, &session.handle);
        printf("Test TPM Wrapper:\tStartSession_ex SHA512:\tPassed\n");
    }
    else {
        printf("Test TPM Wrapper:\tStartSession_ex SHA512:\tSkipped\n");
    }

    /* a session hash weaker than the default is rejected (no TPM needed) */
#ifndef NO_SHA
    if (TPM2_GetHashDigestSize(TPM_ALG_SHA1) <
            TPM2_GetHashDigestSize(WOLFTPM2_WRAP_DIGEST)) {
        rc = wolfTPM2_StartSession_ex(&dev, &session, NULL, NULL,
            TPM_SE_POLICY, TPM_ALG_NULL, TPM_ALG_SHA1);
        AssertIntEQ(rc, BAD_FUNC_ARG);
    }
#endif

    wolfTPM2_Cleanup(&dev);
#endif
}

/* Bind an AES-CFB param-enc session to an EmptyAuth SRK and create a child
 * under it. The pre-fix code left a bound EmptyAuth sessionKey empty, breaking
 * the HMAC; this command fails pre-fix. */
static void test_wolfTPM2_BoundSession_EmptyAuth_ParamEnc(void)
{
#if !defined(WOLFTPM2_NO_WOLFCRYPT) && \
    (!defined(NO_RSA) || defined(HAVE_ECC))
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY srk;
    WOLFTPM2_KEY child;
    WOLFTPM2_SESSION session;
    TPMT_PUBLIC publicTemplate;
#if !defined(NO_RSA)
    TPM_ALG_ID srkAlg = TPM_ALG_RSA;
#else
    TPM_ALG_ID srkAlg = TPM_ALG_ECC;
#endif

    XMEMSET(&dev, 0, sizeof(dev));
    XMEMSET(&srk, 0, sizeof(srk));
    XMEMSET(&child, 0, sizeof(child));
    XMEMSET(&session, 0, sizeof(session));
    XMEMSET(&publicTemplate, 0, sizeof(publicTemplate));

    /* Skip cleanly when no TPM is reachable. */
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, NULL);
    if (rc != 0) {
        printf("Test TPM Wrapper:\tBound EmptyAuth param-enc:\tSkipped\n");
        return;
    }

    /* Storage root key with an EmptyAuth (auth NULL, authSz 0). */
    rc = wolfTPM2_CreateSRK(&dev, &srk, srkAlg, NULL, 0);
    if (rc != 0) {
        /* Environmental (TPM busy / unsupported). Treat as skip. */
        wolfTPM2_Cleanup(&dev);
        printf("Test TPM Wrapper:\tBound EmptyAuth param-enc:\tSkipped\n");
        return;
    }

    /* Bind an HMAC session to the EmptyAuth SRK with AES-CFB param enc. */
    rc = wolfTPM2_StartSession(&dev, &session, NULL, &srk.handle,
        TPM_SE_HMAC, TPM_ALG_CFB);
    AssertIntEQ(rc, TPM_RC_SUCCESS);

    /* Slot 1: the create/load wrappers own slot 0 (parent auth), so the
     * param-enc session lives in slot 1 to survive into the command. */
    rc = wolfTPM2_SetAuthSession(&dev, 1, &session,
        (TPMA_SESSION_decrypt | TPMA_SESSION_encrypt |
         TPMA_SESSION_continueSession));
    AssertIntEQ(rc, TPM_RC_SUCCESS);

    /* Create+load a child under the EmptyAuth SRK; fails pre-fix. */
#if !defined(NO_RSA)
    rc = wolfTPM2_GetKeyTemplate_RSA(&publicTemplate,
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_sign | TPMA_OBJECT_noDA);
#else
    rc = wolfTPM2_GetKeyTemplate_ECC(&publicTemplate,
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_sign | TPMA_OBJECT_noDA,
        TPM_ECC_NIST_P256, TPM_ALG_ECDSA);
#endif
    AssertIntEQ(rc, TPM_RC_SUCCESS);

    rc = wolfTPM2_CreateAndLoadKey(&dev, &child, &srk.handle,
        &publicTemplate, NULL, 0);
    AssertIntEQ(rc, TPM_RC_SUCCESS);

    /* Clear the session slot, then release handles. */
    wolfTPM2_SetAuthSession(&dev, 1, NULL, 0);
    wolfTPM2_UnloadHandle(&dev, &child.handle);
    wolfTPM2_UnloadHandle(&dev, &session.handle);
    wolfTPM2_UnloadHandle(&dev, &srk.handle);
    wolfTPM2_Cleanup(&dev);
    printf("Test TPM Wrapper:\tBound EmptyAuth param-enc:\tPassed\n");
#endif
}

/* Run TPM2_CreateLoaded under a salted AES-CFB param-enc session. Pre-fix the
 * missing response outHandleCnt mis-parsed the rpHash offset and the reply was
 * rejected with TPM_RC_HMAC. */
static void test_wolfTPM2_CreateLoaded_ParamEnc(void)
{
#if !defined(WOLFTPM2_NO_WOLFCRYPT) && \
    (!defined(NO_RSA) || defined(HAVE_ECC))
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY srk;
    WOLFTPM2_KEYBLOB child;
    WOLFTPM2_SESSION session;
    TPMT_PUBLIC publicTemplate;
#if !defined(NO_RSA)
    TPM_ALG_ID srkAlg = TPM_ALG_RSA;
#else
    TPM_ALG_ID srkAlg = TPM_ALG_ECC;
#endif

    XMEMSET(&dev, 0, sizeof(dev));
    XMEMSET(&srk, 0, sizeof(srk));
    XMEMSET(&child, 0, sizeof(child));
    XMEMSET(&session, 0, sizeof(session));
    XMEMSET(&publicTemplate, 0, sizeof(publicTemplate));

    /* Skip cleanly when no TPM is reachable. */
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, NULL);
    if (rc != 0) {
        printf("Test TPM Wrapper:\tCreateLoaded param-enc:\tSkipped\n");
        return;
    }

    rc = wolfTPM2_CreateSRK(&dev, &srk, srkAlg, NULL, 0);
    if (rc != 0) {
        /* Environmental (TPM busy / unsupported). Treat as skip. */
        wolfTPM2_Cleanup(&dev);
        printf("Test TPM Wrapper:\tCreateLoaded param-enc:\tSkipped\n");
        return;
    }

    /* Salted AES-CFB parameter-encryption session in slot 1; slot 0 is left
     * for the parent auth that wolfTPM2_CreateLoadedKey sets internally. */
    rc = wolfTPM2_StartSession(&dev, &session, &srk, NULL,
        TPM_SE_HMAC, TPM_ALG_CFB);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    rc = wolfTPM2_SetAuthSession(&dev, 1, &session,
        (TPMA_SESSION_decrypt | TPMA_SESSION_encrypt |
         TPMA_SESSION_continueSession));
    AssertIntEQ(rc, TPM_RC_SUCCESS);

#if !defined(NO_RSA)
    rc = wolfTPM2_GetKeyTemplate_RSA(&publicTemplate,
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_sign | TPMA_OBJECT_noDA);
#else
    rc = wolfTPM2_GetKeyTemplate_ECC(&publicTemplate,
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_sign | TPMA_OBJECT_noDA,
        TPM_ECC_NIST_P256, TPM_ALG_ECDSA);
#endif
    AssertIntEQ(rc, TPM_RC_SUCCESS);

    /* CreateLoaded under the param-enc session. Fails pre-fix with
     * TPM_RC_HMAC; a TPM that does not implement CreateLoaded is a skip. */
    rc = wolfTPM2_CreateLoadedKey(&dev, &child, &srk.handle,
        &publicTemplate, NULL, 0);
    if (WOLFTPM_IS_COMMAND_UNAVAILABLE(rc)) {
        printf("Test TPM Wrapper:\tCreateLoaded param-enc:\tSkipped\n");
    }
    else {
        AssertIntEQ(rc, TPM_RC_SUCCESS);
        wolfTPM2_UnloadHandle(&dev, &child.handle);
        printf("Test TPM Wrapper:\tCreateLoaded param-enc:\tPassed\n");
    }

    /* Clear the session slot, then release handles. */
    wolfTPM2_SetAuthSession(&dev, 1, NULL, 0);
    wolfTPM2_UnloadHandle(&dev, &session.handle);
    wolfTPM2_UnloadHandle(&dev, &srk.handle);
    wolfTPM2_Cleanup(&dev);
#else
    printf("Test TPM Wrapper:\tCreateLoaded param-enc:\tSkipped\n");
#endif
}

/* Exercise the bound-own-entity branch of TPM2_ParamEncBindKey: the
 * parameter-encryption key for a session that authorizes its own bind entity
 * is sessionKey || authValue. An HMAC session cannot authorize in slot 0, so
 * this uses a bound policy session (the examples/nvram/extend.c pattern): write
 * a POLICYWRITE NV index (policy PolicyPCR(16), auth "cpusecret") under a bound
 * AES-CFB policy session, then read it back. A wrong param-enc key corrupts the
 * stored data even though the write command itself succeeds. */
static void test_wolfTPM2_BoundOwnEntity_ParamEnc(void)
{
#if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(WOLFTPM_WINAPI)
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_SESSION session;
    WOLFTPM2_SESSION trial;
    WOLFTPM2_NV nv;
    WOLFTPM2_HANDLE parent;
    const word32 nvIndex = TPM2_DEMO_NV_TEST_AUTH_INDEX;
    const byte nvAuth[] = "cpusecret";
    const int nvAuthSz = (int)sizeof(nvAuth) - 1;
    word32 nvAttributes;
    byte policyDigest[TPM_SHA256_DIGEST_SIZE];
    word32 policyDigestSz = (word32)sizeof(policyDigest);
    byte pcrArray[1];
    byte buf[8];
    byte readBuf[8];
    word32 readSz;

    XMEMSET(&dev, 0, sizeof(dev));
    XMEMSET(&session, 0, sizeof(session));
    XMEMSET(&trial, 0, sizeof(trial));
    XMEMSET(&nv, 0, sizeof(nv));
    XMEMSET(&parent, 0, sizeof(parent));
    XMEMSET(policyDigest, 0, sizeof(policyDigest));
    XMEMSET(buf, 0x11, sizeof(buf));
    XMEMSET(readBuf, 0, sizeof(readBuf));
    pcrArray[0] = 16; /* resettable debug PCR */

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, NULL);
    if (rc != 0) {
        printf("Test TPM Wrapper:\tBound own-entity param-enc:\tSkipped\n");
        return;
    }

    /* Compute the index authPolicy = PolicyPCR(16) with a trial session
     * (the write helper re-runs PolicyPCR with the same selection). */
    rc = wolfTPM2_StartSession(&dev, &trial, NULL, NULL, TPM_SE_TRIAL,
        TPM_ALG_NULL);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    rc = wolfTPM2_PolicyPCR(&dev, trial.handle.hndl, TPM_ALG_SHA256,
        pcrArray, 1);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    rc = wolfTPM2_GetPolicyDigest(&dev, trial.handle.hndl, policyDigest,
        &policyDigestSz);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    wolfTPM2_UnloadHandle(&dev, &trial.handle);

    parent.hndl = TPM_RH_OWNER;
    nvAttributes = TPMA_NV_POLICYWRITE | TPMA_NV_AUTHREAD | TPMA_NV_NO_DA;
    rc = wolfTPM2_NVCreateAuthPolicy(&dev, &parent, &nv, nvIndex, nvAttributes,
        (word32)sizeof(buf), (byte*)nvAuth, nvAuthSz,
        policyDigest, (int)policyDigestSz);
    if (rc != 0 && rc != TPM_RC_NV_DEFINED) {
        /* Environmental (NV space / unsupported). Treat as skip. */
        wolfTPM2_Cleanup(&dev);
        printf("Test TPM Wrapper:\tBound own-entity param-enc:\tSkipped\n");
        return;
    }
    /* Load the NV handle's auth and Name for the bind. */
    rc = wolfTPM2_NVOpen(&dev, &nv, nvIndex, (byte*)nvAuth, nvAuthSz);
    AssertIntEQ(rc, TPM_RC_SUCCESS);

    /* Bound AES-CFB policy session (slot 0) authorizing its own bind entity. */
    rc = wolfTPM2_StartSession(&dev, &session, NULL, &nv.handle,
        TPM_SE_POLICY, TPM_ALG_CFB);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    rc = wolfTPM2_SetAuthSession(&dev, 0, &session,
        (TPMA_SESSION_decrypt | TPMA_SESSION_encrypt |
         TPMA_SESSION_continueSession));
    AssertIntEQ(rc, TPM_RC_SUCCESS);

    /* Write under the bound policy session - the data is parameter-encrypted
     * with the folded key. */
    rc = wolfTPM2_NVWriteAuthPolicy(&dev, &session, TPM_ALG_SHA256, pcrArray, 1,
        &nv, nvIndex, buf, (word32)sizeof(buf), 0);
    AssertIntEQ(rc, TPM_RC_SUCCESS);

    /* Read back with plain password auth (no param enc) and verify the data
     * round-tripped. A doubled or dropped bind authValue would have stored
     * garbage even though the write command itself succeeded. */
    wolfTPM2_SetAuthSession(&dev, 0, NULL, 0);
    wolfTPM2_UnloadHandle(&dev, &session.handle);
    wolfTPM2_SetAuthHandle(&dev, 0, &nv.handle);
    readSz = (word32)sizeof(readBuf);
    rc = wolfTPM2_NVReadAuth(&dev, &nv, nvIndex, readBuf, &readSz, 0);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    AssertIntEQ((int)readSz, (int)sizeof(buf));
    AssertIntEQ(XMEMCMP(readBuf, buf, sizeof(buf)), 0);

    wolfTPM2_NVDeleteAuth(&dev, &parent, nvIndex);
    wolfTPM2_Cleanup(&dev);
    printf("Test TPM Wrapper:\tBound own-entity param-enc:\tPassed\n");
#else
    printf("Test TPM Wrapper:\tBound own-entity param-enc:\tSkipped\n");
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

    printf("Test TPM Wrapper: %-40s Passed\n", "PolicyHash:");
#else
    printf("Test TPM Wrapper: %-40s Skipped\n", "PolicyHash:");
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

    printf("Test TPM Wrapper: %-40s Passed\n", "SensitiveToPrivate:");
#else
    printf("Test TPM Wrapper: %-40s Skipped\n", "SensitiveToPrivate:");
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
    const byte expATH[] = {
        0x0d, 0x17, 0x5f, 0xf7, 0xac, 0xf9, 0x41, 0x9a,
        0x73, 0x75, 0x7c, 0xa6, 0x42, 0x82, 0x49, 0x61,
        0xa2, 0xc9, 0x72, 0xd9, 0x13, 0xdc, 0xbf, 0x72,
        0x06, 0xe6, 0x73, 0xe7, 0x21, 0x5f, 0x99, 0x6a
    };
    const byte expSECRET[] = {
        0x1a, 0xc4, 0xc1, 0x34, 0x78, 0x87, 0x67, 0x5e,
        0x91, 0xd1, 0xa2, 0xcd, 0xcb, 0xac, 0xdb, 0x62,
        0xed, 0x4e, 0xfe, 0x44, 0xed, 0x52, 0x34, 0x3b,
        0xf1, 0x87, 0xfb, 0x8b, 0xa9, 0xec, 0x43, 0x59
    };
    const byte expDUPLICATE[] = {
        0xa3, 0xe5, 0x57, 0xc6, 0x49, 0x4c, 0xe5, 0x4f,
        0x45, 0xae, 0xf7, 0x19, 0x4d, 0x9e, 0x21, 0xa2,
        0x91, 0xeb, 0x05, 0x2d, 0x43, 0x06, 0x9f, 0xfb,
        0x69, 0x67, 0x1f, 0x99, 0x00, 0xb0, 0xcc, 0x39
    };
    byte key[TEST_KDFA_LABEL_KEYSZ];

    /* Test "ATH" label (session key derivation, TPM 2.0 Part 1 s19.6.8) */
    rc = TPM2_KDFa(TPM_ALG_SHA256, &keyIn, "ATH", &nonceTPM, &nonceCaller,
        key, TEST_KDFA_LABEL_KEYSZ);
    AssertIntEQ(TEST_KDFA_LABEL_KEYSZ, rc);
    AssertIntEQ(XMEMCMP(key, expATH, sizeof(expATH)), 0);

    /* Test "SECRET" label (salt encryption, TPM 2.0 Part 1 s19.6.8) */
    rc = TPM2_KDFa(TPM_ALG_SHA256, &keyIn, "SECRET", &nonceTPM, &nonceCaller,
        key, TEST_KDFA_LABEL_KEYSZ);
    AssertIntEQ(TEST_KDFA_LABEL_KEYSZ, rc);
    AssertIntEQ(XMEMCMP(key, expSECRET, sizeof(expSECRET)), 0);

    /* Test "DUPLICATE" label (key import, TPM 2.0 Part 1 s23.3) */
    rc = TPM2_KDFa(TPM_ALG_SHA256, &keyIn, "DUPLICATE", &nonceTPM, &nonceCaller,
        key, TEST_KDFA_LABEL_KEYSZ);
    AssertIntEQ(TEST_KDFA_LABEL_KEYSZ, rc);
    AssertIntEQ(XMEMCMP(key, expDUPLICATE, sizeof(expDUPLICATE)), 0);

    printf("Test TPM Wrapper: %-40s Passed\n", "KDFa Session Labels:");
#else
    printf("Test TPM Wrapper: %-40s Skipped\n", "KDFa Session Labels:");
#endif
}

static void test_wolfTPM2_EncryptSecret(void)
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY tpmKey;
    TPM2B_DATA data;
    TPM2B_ENCRYPTED_SECRET secret;
#if defined(WOLFTPM_MLKEM) && !defined(WOLFTPM2_NO_WOLFCRYPT) && \
    (defined(WOLFSSL_HAVE_MLKEM) || defined(WOLFSSL_KYBER512) || \
     defined(WOLFSSL_KYBER768) || defined(WOLFSSL_KYBER1024))
    WOLFTPM2_KEY mlkemKey;
    TPMT_PUBLIC mlkemPub;
#endif

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

#if defined(WOLFTPM_MLKEM) && !defined(WOLFTPM2_NO_WOLFCRYPT) && \
    (defined(WOLFSSL_HAVE_MLKEM) || defined(WOLFSSL_KYBER512) || \
     defined(WOLFSSL_KYBER768) || defined(WOLFSSL_KYBER1024))
    /* MLKEM path (v1.85 Part 1 Sec.24): caller encapsulates under the TPM's
     * ML-KEM public key; the shared secret (32 bytes) becomes the session
     * salt, the ciphertext (1088 bytes for MLKEM-768) goes on the wire. */
    XMEMSET(&mlkemKey, 0, sizeof(mlkemKey));
    XMEMSET(&mlkemPub, 0, sizeof(mlkemPub));
    XMEMSET(&data, 0, sizeof(data));
    XMEMSET(&secret, 0, sizeof(secret));

    rc = wolfTPM2_GetKeyTemplate_MLKEM(&mlkemPub,
        TPMA_OBJECT_decrypt | TPMA_OBJECT_fixedTPM |
        TPMA_OBJECT_fixedParent | TPMA_OBJECT_sensitiveDataOrigin |
        TPMA_OBJECT_userWithAuth, TPM_MLKEM_768);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    rc = wolfTPM2_CreatePrimaryKey(&dev, &mlkemKey, TPM_RH_OWNER,
        &mlkemPub, NULL, 0);
    if (rc == TPM_RC_VALUE || rc == TPM_RC_SCHEME ||
            rc == TPM_RC_COMMAND_CODE || rc == (int)(RC_VER1 + 0x043)) {
        printf("Test TPM Wrapper: %-40s Skipped (not supported)\n",
            "EncryptSecret MLKEM:");
    }
    else {
        AssertIntEQ(rc, 0);

        rc = wolfTPM2_EncryptSecret(&dev, &mlkemKey, &data, &secret,
            "SECRET");
        AssertIntEQ(rc, 0);
        AssertIntEQ(data.size, 32);      /* MLKEM shared secret */
        AssertIntEQ(secret.size, 1088);  /* MLKEM-768 ciphertext */
        printf("Test TPM Wrapper: %-40s Passed\n",
            "EncryptSecret MLKEM:");

        wolfTPM2_UnloadHandle(&dev, &mlkemKey.handle);
    }
#endif

    wolfTPM2_Cleanup(&dev);

    printf("Test TPM Wrapper: %-40s %s\n", "EncryptSecret:",
        rc == 0 || rc == BAD_FUNC_ARG ? "Passed" : "Failed");
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

    printf("Test TPM Wrapper: %-40s %s\n", "Cleanup:",
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

    printf("Test TPM Wrapper: %-40s %s\n", "KDFa:",
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
    /* KAT: SHA256(counter(1) || Z || "IDENTITY\0" || partyU || partyV) */
    const byte keyExp[TEST_KDFE_KEYSZ] = {
        0x36, 0xa3, 0xbc, 0x51, 0x5f, 0xe0, 0x12, 0xb8,
        0x1b, 0xac, 0x81, 0xd6, 0x21, 0x83, 0x74, 0x75,
        0xb9, 0x17, 0xf8, 0x9b, 0xcd, 0x94, 0xd4, 0xa3,
        0xa3, 0x7f, 0x31, 0x49, 0xaa, 0xe2, 0x9b, 0xa1};
#endif

    rc = TPM2_KDFe_ex(TPM_ALG_SHA256, Z, sizeof(Z), label,
        partyU, sizeof(partyU), partyV, sizeof(partyV),
        key, sizeof(key));
#ifdef WOLFTPM2_NO_WOLFCRYPT
    AssertIntEQ(NOT_COMPILED_IN, rc);
#else
    AssertIntEQ((int)sizeof(key), rc);
    /* Pin the exact output so counter, label and party order are verified */
    AssertIntEQ(0, XMEMCMP(key, keyExp, sizeof(keyExp)));
    /* Verify deterministic: same inputs produce same output */
    rc = TPM2_KDFe_ex(TPM_ALG_SHA256, Z, sizeof(Z), label,
        partyU, sizeof(partyU), partyV, sizeof(partyV),
        key2, sizeof(key2));
    AssertIntEQ((int)sizeof(key2), rc);
    AssertIntEQ(0, XMEMCMP(key, key2, sizeof(key)));
#endif

    printf("Test TPM Wrapper: %-40s %s\n", "KDFe:",
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

    /* A truncated (short) expected HMAC must be rejected on the length check */
    rc = TPM2_HmacVerify(TPM_ALG_SHA256,
        hmacKey, 4, hmacData, 28, NULL, 0,
        hmacExp, sizeof(hmacExp) - 1);
    AssertIntEQ(TPM_RC_INTEGRITY, rc);

    /* An output buffer smaller than the digest must be rejected */
    digestSz = 31;
    rc = TPM2_HmacCompute(TPM_ALG_SHA256,
        hmacKey, 4, hmacData, 28, NULL, 0,
        digest, &digestSz);
    AssertIntEQ(BUFFER_E, rc);

    printf("Test TPM Wrapper: %-40s Passed\n", "HmacCompute:");
#else
    printf("Test TPM Wrapper: %-40s Skipped\n", "HmacCompute:");
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

    printf("Test TPM Wrapper: %-40s Passed\n", "HashCompute:");
#else
    printf("Test TPM Wrapper: %-40s Skipped\n", "HashCompute:");
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

    printf("Test TPM Wrapper: %-40s Passed\n", "ConstantCompare:");
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

    printf("Test TPM Wrapper: %-40s Passed\n", "AesCfbRoundtrip:");
#else
    printf("Test TPM Wrapper: %-40s Skipped\n", "AesCfbRoundtrip:");
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

    printf("Test TPM Wrapper: %-40s Passed\n", "KDFa multi-hash:");
#else
    printf("Test TPM Wrapper: %-40s Skipped\n", "KDFa multi-hash:");
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

    printf("Test TPM Wrapper: %-40s Passed\n", "KDFe multi-hash:");
#else
    printf("Test TPM Wrapper: %-40s Skipped\n", "KDFe multi-hash:");
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

    printf("Test TPM Wrapper: %-40s Passed\n", "HmacCompute multi-hash:");
#else
    printf("Test TPM Wrapper: %-40s Skipped\n", "HmacCompute multi-hash:");
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

    printf("Test TPM Wrapper: %-40s Passed\n", "HashCompute multi-hash:");
#else
    printf("Test TPM Wrapper: %-40s Skipped\n", "HashCompute multi-hash:");
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

    printf("Test TPM Wrapper: %-40s Passed\n", "KDF error paths:");
#else
    printf("Test TPM Wrapper: %-40s Skipped\n", "KDF error paths:");
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

    printf("Test TPM Wrapper: %-40s Passed\n", "GetTpmHashType:");
#else
    printf("Test TPM Wrapper: %-40s Skipped\n", "GetTpmHashType:");
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

    printf("Test TPM Wrapper: %-40s Passed\n", "ResponseHmacVerification:");
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
    /* KAT: HMAC-SHA256("test", 0xAB*32 || 0x11*32 || 0x22*32 || attr(0x01)) */
    const byte hmacExp[TPM_SHA256_DIGEST_SIZE] = {
        0x42, 0x7f, 0xbf, 0xe1, 0x1b, 0xc3, 0x4d, 0xff,
        0x89, 0x73, 0x43, 0x79, 0x8f, 0xb6, 0xaa, 0x88,
        0xcd, 0xb3, 0xde, 0xae, 0x88, 0x21, 0xe9, 0xe6,
        0x40, 0x9a, 0x51, 0x3c, 0x68, 0xd5, 0x90, 0xdf};

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

    /* Pin the exact HMAC so the cpHash and sessionAttributes contributions
     * are verified, not just relative nonce ordering */
    AssertIntEQ(hmac1.size, (int)sizeof(hmacExp));
    AssertIntEQ(0, XMEMCMP(hmac1.buffer, hmacExp, sizeof(hmacExp)));

    /* Compute HMAC with (nonceB, nonceA) — reversed order */
    rc = TPM2_CalcHmac(TPM_ALG_SHA256, &auth, &hash, &nonceB, &nonceA,
        attr, &hmac2);
    AssertIntEQ(0, rc);

    /* Reversed nonces MUST produce different HMAC */
    AssertIntNE(0, XMEMCMP(hmac1.buffer, hmac2.buffer, hmac1.size));

    /* Changing only the cpHash MUST change the HMAC (binds command params) */
    XMEMSET(hash.buffer, 0xCD, hash.size);
    rc = TPM2_CalcHmac(TPM_ALG_SHA256, &auth, &hash, &nonceA, &nonceB,
        attr, &hmac2);
    AssertIntEQ(0, rc);
    AssertIntNE(0, XMEMCMP(hmac1.buffer, hmac2.buffer, hmac1.size));

    /* Changing only the sessionAttributes MUST change the HMAC */
    XMEMSET(hash.buffer, 0xAB, hash.size);
    rc = TPM2_CalcHmac(TPM_ALG_SHA256, &auth, &hash, &nonceA, &nonceB,
        (TPMA_SESSION)0, &hmac2);
    AssertIntEQ(0, rc);
    AssertIntNE(0, XMEMCMP(hmac1.buffer, hmac2.buffer, hmac1.size));

    printf("Test TPM Wrapper: %-40s Passed\n", "CalcHmac:");
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

    printf("Test TPM Wrapper: %-40s Passed\n", "ParamEnc_XOR:");
#endif
}

static void test_TPM2_ParamEnc_XOR_MaskBoundary(void)
{
#ifndef WOLFTPM2_NO_WOLFCRYPT
    int rc;
    TPMI_ALG_HASH authHash = TPM_ALG_SHA256;
    TPM2B_AUTH sessKey;
    TPM2B_NONCE nonceCaller, nonceTPM;
    byte data[TPM2_XOR_MASK_MAX + 1];

    sessKey.size = TPM_SHA256_DIGEST_SIZE;
    XMEMSET(sessKey.buffer, 0xCC, sessKey.size);
    nonceCaller.size = TPM_SHA256_DIGEST_SIZE;
    XMEMSET(nonceCaller.buffer, 0x11, nonceCaller.size);
    nonceTPM.size = TPM_SHA256_DIGEST_SIZE;
    XMEMSET(nonceTPM.buffer, 0x22, nonceTPM.size);
    XMEMSET(data, 0, sizeof(data));

    /* exactly at capacity must succeed */
    rc = TPM2_ParamEnc_XOR(authHash, sessKey.buffer, sessKey.size,
        nonceCaller.buffer, nonceCaller.size,
        nonceTPM.buffer, nonceTPM.size,
        data, TPM2_XOR_MASK_MAX);
    AssertIntEQ(TPM_RC_SUCCESS, rc);

    /* one byte past capacity must be rejected */
    rc = TPM2_ParamEnc_XOR(authHash, sessKey.buffer, sessKey.size,
        nonceCaller.buffer, nonceCaller.size,
        nonceTPM.buffer, nonceTPM.size,
        data, TPM2_XOR_MASK_MAX + 1);
    AssertIntEQ(BUFFER_E, rc);

    printf("Test TPM Wrapper: %-40s Passed\n", "ParamEnc_XOR mask boundary:");
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

    printf("Test TPM Wrapper: %-40s Passed\n", "ParamEnc_AESCFB:");
#endif
}

static void test_TPM2_ParamEnc_AESCFB_KeyBoundary(void)
{
#if !defined(WOLFTPM2_NO_WOLFCRYPT) && defined(WOLFSSL_AES_CFB)
    int rc;
    TPMI_ALG_HASH authHash = TPM_ALG_SHA256;
    TPM2B_AUTH sessKey;
    TPM2B_NONCE nonceCaller, nonceTPM;
    byte data[32];

    sessKey.size = TPM_SHA256_DIGEST_SIZE;
    XMEMSET(sessKey.buffer, 0xDD, sessKey.size);
    nonceCaller.size = TPM_SHA256_DIGEST_SIZE;
    XMEMSET(nonceCaller.buffer, 0x33, nonceCaller.size);
    nonceTPM.size = TPM_SHA256_DIGEST_SIZE;
    XMEMSET(nonceTPM.buffer, 0x44, nonceTPM.size);
    XMEMSET(data, 0, sizeof(data));

    /* keyBits above 256 (symKeySz > 32) must be rejected, not overflow symKey */
    rc = TPM2_ParamEnc_AESCFB(authHash, 512,
        sessKey.buffer, sessKey.size,
        nonceCaller.buffer, nonceCaller.size,
        nonceTPM.buffer, nonceTPM.size,
        data, sizeof(data), 1);
    AssertIntEQ(BUFFER_E, rc);

    printf("Test TPM Wrapper: %-40s Passed\n", "ParamEnc_AESCFB key boundary:");
#endif
}

/* Known-answer test cross-checking TPM2_ParamEnc_AESCFB against an
 * independent KDFa + AES-CFB reference built from wolfCrypt primitives.
 * The pure round-trip test above cannot detect mutations that affect
 * encrypt and decrypt symmetrically (IV-offset, label, KDFa output
 * split); this KAT does. */
static void test_TPM2_ParamEnc_AESCFB_KAT(void)
{
#if !defined(WOLFTPM2_NO_WOLFCRYPT) && defined(WOLFSSL_AES_CFB)
    int rc;
    TPMI_ALG_HASH authHash = TPM_ALG_SHA256;
    UINT16 keyBits = MAX_AES_KEY_BITS;
    int keyBytes = (int)keyBits / 8;
    TPM2B_AUTH sessKey;
    TPM2B_NONCE nonceCaller, nonceTPM;
    const byte original[] = "AES-CFB KAT vector";
    byte tpmCt[sizeof(original)];
    byte refCt[sizeof(original)];
    byte symKey[MAX_AES_KEY_BYTES + MAX_AES_BLOCK_SIZE_BYTES];
    Aes aes;

    sessKey.size = TPM_SHA256_DIGEST_SIZE;
    XMEMSET(sessKey.buffer, 0xCC, sessKey.size);
    nonceCaller.size = TPM_SHA256_DIGEST_SIZE;
    XMEMSET(nonceCaller.buffer, 0x11, nonceCaller.size);
    nonceTPM.size = TPM_SHA256_DIGEST_SIZE;
    XMEMSET(nonceTPM.buffer, 0x22, nonceTPM.size);

    XMEMCPY(tpmCt, original, sizeof(original));
    XMEMCPY(refCt, original, sizeof(original));

    rc = TPM2_ParamEnc_AESCFB(authHash, keyBits,
        sessKey.buffer, sessKey.size,
        nonceCaller.buffer, nonceCaller.size,
        nonceTPM.buffer, nonceTPM.size,
        tpmCt, sizeof(tpmCt), 1);
    AssertIntEQ(TPM_RC_SUCCESS, rc);

    rc = TPM2_KDFa(authHash, (TPM2B_DATA*)&sessKey,
        "CFB", &nonceCaller, &nonceTPM,
        symKey, (UINT32)(keyBytes + MAX_AES_BLOCK_SIZE_BYTES));
    AssertIntEQ(keyBytes + MAX_AES_BLOCK_SIZE_BYTES, rc);

    AssertIntEQ(0, wc_AesInit(&aes, NULL, INVALID_DEVID));
    AssertIntEQ(0, wc_AesSetKey(&aes, symKey, (word32)keyBytes,
        &symKey[keyBytes], AES_ENCRYPTION));
    AssertIntEQ(0, wc_AesCfbEncrypt(&aes, refCt, refCt, sizeof(refCt)));
    wc_AesFree(&aes);

    AssertIntEQ(0, XMEMCMP(tpmCt, refCt, sizeof(refCt)));

    printf("Test TPM Wrapper: %-40s Passed\n", "ParamEnc_AESCFB KAT:");
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

    printf("Test TPM Wrapper: %-40s Passed\n", "ParamDec_XOR_Roundtrip:");
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

    printf("Test TPM Wrapper: %-40s Passed\n", "ParamDec_AESCFB_Roundtrip:");
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

    printf("Test TPM Wrapper: %-40s Passed\n", "ParamEncDec_Dispatch:");
#else
    printf("Test TPM Wrapper: %-40s Skipped\n", "ParamEncDec_Dispatch:");
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

    printf("Test TPM Wrapper: %-40s Passed\n", "HashNvPublic:");
#else
    printf("Test TPM Wrapper: %-40s Skipped\n", "HashNvPublic:");
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

    printf("Test TPM Wrapper: %-40s Passed\n", "ComputeName:");
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

    printf("Test TPM Wrapper: %-40s Passed\n", "SchemeSerialize:");
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

    printf("Test TPM Wrapper: %-40s Passed\n", "EcdaaResponseParse:");
}

/* TPM2_Packet_AppendSignature / ParseSignature must explicitly recognize
 * TPM_ALG_NULL as a zero-payload signature so subsequent fields stay
 * aligned. The previous default-fallthrough lumped TPM_ALG_NULL together
 * with unknown algorithms, making the property "Parse(Append(NULL))
 * consumes exactly the sigAlg bytes" depend on undocumented behavior. */
static void test_TPM2_ParseSignature_NullAlg(void)
{
    TPM2_Packet packet;
    byte buf[16];
    TPMT_SIGNATURE sig;
    UINT16 sentinel;
    int pos = 0;

    XMEMSET(buf, 0, sizeof(buf));
    XMEMSET(&packet, 0, sizeof(packet));

    /* sigAlg = TPM_ALG_NULL */
    buf[pos++] = (byte)((TPM_ALG_NULL >> 8) & 0xFF);
    buf[pos++] = (byte)(TPM_ALG_NULL & 0xFF);
    /* sentinel right after the (zero-length) signature payload */
    buf[pos++] = 0xDE;
    buf[pos++] = 0xAD;

    XMEMSET(&sig, 0, sizeof(sig));
    packet.buf = buf;
    packet.size = pos;
    packet.pos = 0;

    TPM2_Packet_ParseSignature(&packet, &sig);
    AssertIntEQ(sig.sigAlg, TPM_ALG_NULL);
    AssertIntEQ(packet.pos, 2);
    sentinel = (UINT16)((buf[packet.pos] << 8) | buf[packet.pos + 1]);
    AssertIntEQ(sentinel, 0xDEAD);

    /* Round-trip: Append a TPM_ALG_NULL signature into a fresh packet and
     * verify only the 2-byte sigAlg was written. A future regression that
     * drops the explicit case (defaulting to silent fallthrough) would
     * still pass for Parse but the Append side is also locked in here. */
    XMEMSET(buf, 0, sizeof(buf));
    XMEMSET(&packet, 0, sizeof(packet));
    XMEMSET(&sig, 0, sizeof(sig));
    sig.sigAlg = TPM_ALG_NULL;
    packet.buf = buf;
    packet.size = sizeof(buf);
    packet.pos = 0;
    TPM2_Packet_AppendSignature(&packet, &sig);
    AssertIntEQ(packet.pos, 2);
    AssertIntEQ(buf[0], (byte)((TPM_ALG_NULL >> 8) & 0xFF));
    AssertIntEQ(buf[1], (byte)(TPM_ALG_NULL & 0xFF));

    /* Re-parse confirms the round-trip. */
    XMEMSET(&sig, 0, sizeof(sig));
    packet.pos = 0;
    TPM2_Packet_ParseSignature(&packet, &sig);
    AssertIntEQ(sig.sigAlg, TPM_ALG_NULL);
    AssertIntEQ(packet.pos, 2);

    printf("Test TPM Wrapper:\tParseSignature NULL alg:\tPassed\n");
}

/* TPM2_Packet_ParsePoint must resync to outerStart + point->size so a
 * malformed wire blob with inner x.size / y.size disagreement can't
 * desynchronize subsequent fields. */
static void test_TPM2_ParsePoint_OuterResync(void)
{
    TPM2_Packet packet;
    byte buf[64];
    TPM2B_ECC_POINT point;
    UINT16 sentinel;
    int outerStart, fakeOuterSz;
    int pos = 0;
    int innerStart;

    XMEMSET(buf, 0, sizeof(buf));
    XMEMSET(&packet, 0, sizeof(packet));

    /* Build TPM2B_ECC_POINT: outer.size + x(2+0) + y(2+0). Declare outer
     * size larger than actual inner consumption (4 bytes). */
    outerStart = pos;
    pos += 2; /* size placeholder */
    innerStart = pos;
    /* x.size = 0 */
    buf[pos++] = 0; buf[pos++] = 0;
    /* y.size = 0 */
    buf[pos++] = 0; buf[pos++] = 0;

    fakeOuterSz = (pos - innerStart) + 6; /* 6 padding bytes */
    buf[outerStart]     = (byte)((fakeOuterSz >> 8) & 0xFF);
    buf[outerStart + 1] = (byte)(fakeOuterSz & 0xFF);
    pos += 6;

    /* Sentinel U16 right after outer end */
    buf[pos++] = 0xBE;
    buf[pos++] = 0xEF;

    XMEMSET(&point, 0, sizeof(point));
    packet.buf = buf;
    packet.size = pos;
    packet.pos = 0;

    TPM2_Packet_ParsePoint(&packet, &point);

    /* Position must land at outerStart + 2 + outer.size (= 2 + 10 = 12).
     * Read sentinel by hand. */
    AssertIntEQ(packet.pos, 2 + fakeOuterSz);
    sentinel = (UINT16)((buf[packet.pos] << 8) | buf[packet.pos + 1]);
    AssertIntEQ(sentinel, 0xBEEF);

    printf("Test TPM Wrapper:\tParsePoint outer resync:\tPassed\n");
}

/* TPM2_Packet_ParsePublic must resync the packet position to outerStart +
 * pub->size so a malformed wire blob with inner-size disagreement can't
 * desynchronize subsequent fields. Pre-fix the parser left the position
 * wherever the inner parses ended, drifting from the declared outer size. */
static void test_TPM2_ParsePublic_OuterResync(void)
{
    TPM2_Packet packet;
    byte buf[256];
    TPM2B_PUBLIC pub;
    UINT16 sentinel = 0;
    int outerStart, fakeOuterSz;
    int pos = 0;
    int innerStart;

    /* Build a TPM2B_PUBLIC blob by hand with type=RSA, valid inner fields,
     * but outer.size declared larger than the actual inner consumption. A
     * sentinel is placed at outerStart + 2 + outer.size; only a parser
     * that resyncs to that anchor will read the sentinel correctly. */
    XMEMSET(buf, 0, sizeof(buf));
    XMEMSET(&packet, 0, sizeof(packet));

    outerStart = pos;
    pos += 2; /* size placeholder */
    innerStart = pos;
    /* type = RSA (0x0001) */
    buf[pos++] = 0x00; buf[pos++] = 0x01;
    /* nameAlg = SHA256 (0x000B) */
    buf[pos++] = 0x00; buf[pos++] = 0x0B;
    /* objectAttributes = 0 */
    buf[pos++] = 0; buf[pos++] = 0; buf[pos++] = 0; buf[pos++] = 0;
    /* authPolicy: size=0 */
    buf[pos++] = 0; buf[pos++] = 0;
    /* RSA params: sym.alg=NULL(2), scheme=NULL(2), keyBits=2048(2),
     *   exponent=0(4) */
    buf[pos++] = 0x00; buf[pos++] = 0x10; /* TPM_ALG_NULL */
    buf[pos++] = 0x00; buf[pos++] = 0x10; /* scheme NULL */
    buf[pos++] = 0x08; buf[pos++] = 0x00; /* keyBits = 2048 */
    buf[pos++] = 0; buf[pos++] = 0; buf[pos++] = 0; buf[pos++] = 0; /* exp */
    /* unique.size = 0 */
    buf[pos++] = 0; buf[pos++] = 0;

    /* Declared outer size = actual inner + 8 padding bytes. */
    fakeOuterSz = (pos - innerStart) + 8;
    buf[outerStart]     = (byte)((fakeOuterSz >> 8) & 0xFF);
    buf[outerStart + 1] = (byte)(fakeOuterSz & 0xFF);
    /* 8 zero pad bytes */
    pos += 8;

    /* Sentinel U16 at outerStart + 2 + fakeOuterSz */
    buf[pos++] = 0xCA;
    buf[pos++] = 0xFE;

    XMEMSET(&pub, 0, sizeof(pub));
    packet.buf = buf;
    packet.size = pos;
    packet.pos = 0;

    TPM2_Packet_ParsePublic(&packet, &pub);
    AssertIntEQ(pub.publicArea.type, TPM_ALG_RSA);
    AssertIntEQ(pub.publicArea.nameAlg, TPM_ALG_SHA256);

    /* Position must land at outerStart + 2 + outer.size; the sentinel U16
     * lives at that offset. Read by hand to avoid pulling in WOLFTPM_LOCAL
     * parser helpers from the test binary. */
    AssertIntEQ(packet.pos, 2 + fakeOuterSz);
    sentinel = (UINT16)((buf[packet.pos] << 8) | buf[packet.pos + 1]);
    AssertIntEQ(sentinel, 0xCAFE);

    printf("Test TPM Wrapper:\tParsePublic outer resync:\tPassed\n");
}

/* TPM2_ParseAttest must handle TPM_ST_ATTEST_NV_DIGEST (0x801C) and decode
 * TPMS_NV_DIGEST_CERTIFY_INFO. Pre-fix, the switch fell through to default
 * and left out->attested zeroed. */
static void test_TPM2_ParseAttest_NvDigest(void)
{
    TPM2B_ATTEST attestBlob;
    TPMS_ATTEST out;
    const byte name[] = {0x00, 0x0B, 0x11, 0x22, 0x33, 0x44}; /* alg + 4 bytes */
    const byte digest[] = {0xAA, 0xBB, 0xCC, 0xDD};
    byte* buf;
    int pos = 0;
    int rc;

    XMEMSET(&attestBlob, 0, sizeof(attestBlob));
    buf = attestBlob.attestationData;

    /* magic */
    buf[pos++] = (byte)((TPM_GENERATED_VALUE >> 24) & 0xFF);
    buf[pos++] = (byte)((TPM_GENERATED_VALUE >> 16) & 0xFF);
    buf[pos++] = (byte)((TPM_GENERATED_VALUE >> 8) & 0xFF);
    buf[pos++] = (byte)(TPM_GENERATED_VALUE & 0xFF);
    /* type = TPM_ST_ATTEST_NV_DIGEST (0x801C) */
    buf[pos++] = 0x80; buf[pos++] = 0x1C;
    /* qualifiedSigner: empty */
    buf[pos++] = 0; buf[pos++] = 0;
    /* extraData: empty */
    buf[pos++] = 0; buf[pos++] = 0;
    /* clockInfo: clock(8)+resetCount(4)+restartCount(4)+safe(1) */
    XMEMSET(buf + pos, 0, 17); pos += 17;
    /* firmwareVersion */
    XMEMSET(buf + pos, 0, 8); pos += 8;
    /* TPMS_NV_DIGEST_CERTIFY_INFO: indexName + nvDigest */
    buf[pos++] = 0; buf[pos++] = (byte)sizeof(name);
    XMEMCPY(buf + pos, name, sizeof(name)); pos += sizeof(name);
    buf[pos++] = 0; buf[pos++] = (byte)sizeof(digest);
    XMEMCPY(buf + pos, digest, sizeof(digest)); pos += sizeof(digest);

    attestBlob.size = (UINT16)pos;

    XMEMSET(&out, 0, sizeof(out));
    rc = TPM2_ParseAttest(&attestBlob, &out);
    AssertIntEQ(rc, TPM_RC_SUCCESS);

    AssertIntEQ(out.magic, TPM_GENERATED_VALUE);
    AssertIntEQ(out.type, 0x801C);
    AssertIntEQ(out.attested.nvDigest.indexName.size, sizeof(name));
    AssertIntEQ(XMEMCMP(out.attested.nvDigest.indexName.name, name,
        sizeof(name)), 0);
    AssertIntEQ(out.attested.nvDigest.nvDigest.size, sizeof(digest));
    AssertIntEQ(XMEMCMP(out.attested.nvDigest.nvDigest.buffer, digest,
        sizeof(digest)), 0);

    printf("Test TPM Wrapper:\tParseAttest NV_DIGEST:\t\tPassed\n");
}

#if defined(WOLFTPM_MFG_IDENTITY) && \
    !defined(WOLFTPM_ST33) && !defined(WOLFTPM_AUTODETECT)
/* On non-ST33 targets, omitting the master password must fail closed rather
 * than silently deriving auth from the public sample password. */
static void test_wolfTPM2_SetIdentityAuth_RequiresPassword(void)
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_HANDLE handle;
    byte pw[16];

    XMEMSET(&dev, 0, sizeof(dev));
    XMEMSET(&handle, 0, sizeof(handle));
    XMEMSET(pw, 0x11, sizeof(pw));

    (void)wolfTPM2_Init(&dev, TPM2_IoCb, NULL);

    /* NULL / zero-length master password is rejected */
    rc = wolfTPM2_SetIdentityAuth(&dev, &handle, NULL, 0);
    AssertIntEQ(rc, BAD_FUNC_ARG);

    /* NULL handle is rejected */
    rc = wolfTPM2_SetIdentityAuth(&dev, NULL, pw, sizeof(pw));
    AssertIntEQ(rc, BAD_FUNC_ARG);

    wolfTPM2_Cleanup(&dev);

    printf("Test TPM Wrapper:\tSetIdentityAuth requires password:\tPassed\n");
}
#endif /* WOLFTPM_MFG_IDENTITY && !WOLFTPM_ST33 && !WOLFTPM_AUTODETECT */

/* wolfTPM2_EccKey_TpmToWolf must right-align coordinates: a spec-valid TPM
 * coordinate with a stripped leading-zero byte (size < field size) would be
 * left-aligned and scaled up, corrupting the imported point. */
static void test_wolfTPM2_EccKey_TpmToWolf_ShortCoord(void)
{
#if !defined(WOLFTPM2_NO_WOLFCRYPT) && defined(HAVE_ECC) && \
    defined(HAVE_ECC_KEY_IMPORT) && defined(HAVE_ECC_KEY_EXPORT) && \
    !defined(NO_ECC256)
    int rc;
    ecc_key impKey;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY tpmKey;
    byte xImp[32], yImp[32];
    word32 xImpSz, yImpSz;
    /* Valid P-256 point whose x has a zero MSB, so the spec-valid stripped
     * TPM form (size 31) is shorter than the 32-byte field */
    const byte xRaw[32] = {
        0x00, 0x4d, 0xb3, 0x2d, 0x25, 0x8e, 0x4d, 0xfd,
        0x3f, 0x47, 0xdc, 0x30, 0x9f, 0x36, 0x7a, 0x84,
        0x17, 0x7d, 0x47, 0x71, 0x47, 0x76, 0x5d, 0x04,
        0xd7, 0x11, 0xca, 0x8f, 0xba, 0x92, 0x2f, 0x2c};
    const byte yRaw[32] = {
        0xb3, 0x3d, 0x81, 0xc0, 0x73, 0x66, 0xfd, 0x51,
        0xd5, 0x6f, 0x53, 0xed, 0xac, 0x11, 0x36, 0x40,
        0xb0, 0xb5, 0x23, 0xee, 0x7e, 0x32, 0x99, 0x35,
        0x5e, 0x0d, 0x99, 0xfa, 0xb3, 0x75, 0xc7, 0x57};

    XMEMSET(&dev, 0, sizeof(dev));
    XMEMSET(&tpmKey, 0, sizeof(tpmKey));
    tpmKey.pub.publicArea.type = TPM_ALG_ECC;
    tpmKey.pub.publicArea.parameters.eccDetail.curveID = TPM_ECC_NIST_P256;
    tpmKey.pub.publicArea.unique.ecc.x.size = 31; /* leading zero stripped */
    XMEMCPY(tpmKey.pub.publicArea.unique.ecc.x.buffer, xRaw + 1, 31);
    tpmKey.pub.publicArea.unique.ecc.y.size = 32;
    XMEMCPY(tpmKey.pub.publicArea.unique.ecc.y.buffer, yRaw, 32);

    AssertIntEQ(0, wc_ecc_init(&impKey));
    rc = wolfTPM2_EccKey_TpmToWolf(&dev, &tpmKey, &impKey);
    AssertIntEQ(0, rc);

    /* Imported point must equal the original full-width coordinates */
    xImpSz = sizeof(xImp);
    yImpSz = sizeof(yImp);
    AssertIntEQ(0, wc_ecc_export_public_raw(&impKey, xImp, &xImpSz,
        yImp, &yImpSz));
    AssertIntEQ(0, XMEMCMP(xImp, xRaw, 32));
    AssertIntEQ(0, XMEMCMP(yImp, yRaw, 32));

    wc_ecc_free(&impKey);
    printf("Test TPM Wrapper: %-40s Passed\n", "EccKey_TpmToWolf short coord:");
#endif
}

/* wolfTPM2_RsaKey_TpmToWolf must preserve the exponent for multi-byte
 * non-palindromic values. The exponent bytes are big-endian on the wolfCrypt
 * side, so a little-endian build would corrupt e.g. 0x010003. */
static void test_wolfTPM2_RsaKey_TpmToWolf_Exponent(void)
{
#if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_RSA)
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY tpmKey;
    RsaKey wolfKey;
    byte eOut[8];
    byte nOut[256];
    word32 eOutSz = (word32)sizeof(eOut);
    word32 nOutSz = (word32)sizeof(nOut);
    word32 exponent = 0x010003; /* non-palindromic multi-byte exponent */

    XMEMSET(&dev, 0, sizeof(dev));
    XMEMSET(&tpmKey, 0, sizeof(tpmKey));

    tpmKey.pub.publicArea.type = TPM_ALG_RSA;
    tpmKey.pub.publicArea.parameters.rsaDetail.exponent = exponent;
    tpmKey.pub.publicArea.unique.rsa.size = 128;
    XMEMSET(tpmKey.pub.publicArea.unique.rsa.buffer, 0xC7, 128);

    rc = wc_InitRsaKey(&wolfKey, NULL);
    AssertIntEQ(0, rc);

    rc = wolfTPM2_RsaKey_TpmToWolf(&dev, &tpmKey, &wolfKey);
    AssertIntEQ(0, rc);

    rc = wc_RsaFlattenPublicKey(&wolfKey, eOut, &eOutSz, nOut, &nOutSz);
    AssertIntEQ(0, rc);

    /* Round-trip: decoded exponent must equal the original TPM exponent */
    AssertIntEQ((int)exponent, (int)wolfTPM2_RsaKey_Exponent(eOut, eOutSz));

    wc_FreeRsaKey(&wolfKey);
    printf("Test TPM Wrapper: %-40s Passed\n", "RsaKey_TpmToWolf exponent:");
#endif
}

/* The ECDH shared-secret copy must reject a TPM response x-coordinate larger
 * than the caller's output buffer. TPM2_Packet_ParseEccPoint clamps only to
 * MAX_ECC_KEY_BYTES, so a MITM/crafted response can report a point.x.size
 * bigger than a curve-sized caller buffer; copying it would overflow. */
static void test_wolfTPM2_EccZToBuffer(void)
{
    int rc;
    int outSz;
    TPM2B_ECC_PARAMETER z;
    byte out[32];

    XMEMSET(&z, 0, sizeof(z));
    XMEMSET(out, 0, sizeof(out));

    /* Response larger than caller capacity must be rejected, not copied */
    z.size = (UINT16)(sizeof(out) + 16);
    outSz = (int)sizeof(out);
    rc = wolfTPM2_EccZToBuffer(out, &outSz, &z);
    AssertIntEQ(rc, BUFFER_E);

    /* Exact-fit response is accepted and reports its own size */
    z.size = (UINT16)sizeof(out);
    outSz = (int)sizeof(out);
    rc = wolfTPM2_EccZToBuffer(out, &outSz, &z);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    AssertIntEQ(outSz, (int)sizeof(out));

    /* Smaller response shrinks outSz to the response size */
    z.size = 20;
    outSz = (int)sizeof(out);
    rc = wolfTPM2_EccZToBuffer(out, &outSz, &z);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    AssertIntEQ(outSz, 20);

    /* NULL arguments rejected */
    outSz = (int)sizeof(out);
    AssertIntEQ(wolfTPM2_EccZToBuffer(NULL, &outSz, &z), BAD_FUNC_ARG);
    AssertIntEQ(wolfTPM2_EccZToBuffer(out, NULL, &z), BAD_FUNC_ARG);
    AssertIntEQ(wolfTPM2_EccZToBuffer(out, &outSz, NULL), BAD_FUNC_ARG);

    printf("Test TPM Wrapper:\tECDH shared secret bounds:\tPassed\n");
}

/* wolfTPM2_LoadEccPublicKey_ex must honor caller-provided scheme, hashAlg
 * and objectAttributes (in particular, allow TPMA_OBJECT_decrypt for ECDH
 * peer keys). The legacy wolfTPM2_LoadEccPublicKey must continue to default
 * to ECDSA + sign attribute. */
static void test_wolfTPM2_LoadEccPublicKey_Ex(void)
{
#if !defined(WOLFTPM2_NO_WOLFCRYPT) && defined(HAVE_ECC)
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY srk;
    WOLFTPM2_KEY peer;
    TPMT_PUBLIC pub;
    byte xBuf[MAX_ECC_KEY_BYTES];
    byte yBuf[MAX_ECC_KEY_BYTES];
    word32 xSz, ySz;
    TPM_ECC_CURVE curve;
    TPM_ALG_ID nameAlg;

    XMEMSET(&dev, 0, sizeof(dev));
    XMEMSET(&srk, 0, sizeof(srk));
    XMEMSET(&peer, 0, sizeof(peer));

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, NULL);
    if (rc != 0) {
        printf("Test TPM Wrapper:\tLoadEccPublicKey_ex:\tSkipped\n");
        return;
    }
    /* Flush any transient objects left by previous tests so CreatePrimary
     * does not get TPM_RC_OBJECT_MEMORY on a busy simulator. */
    (void)wolfTPM2_UnloadHandles_AllTransient(&dev);

    /* Create an ECC SRK to harvest valid X/Y coordinates from. The SRK follows
     * WOLFTPM2_ECC_DEFAULT_CURVE, so use its actual curve/nameAlg (not a
     * hardcoded P256) and size the buffers for any curve. */
    XMEMSET(&pub, 0, sizeof(pub));
    rc = wolfTPM2_GetKeyTemplate_ECC_SRK(&pub);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    rc = wolfTPM2_CreatePrimaryKey(&dev, &srk, TPM_RH_OWNER, &pub, NULL, 0);
    AssertIntEQ(rc, TPM_RC_SUCCESS);

    curve = srk.pub.publicArea.parameters.eccDetail.curveID;
    nameAlg = srk.pub.publicArea.nameAlg;
    xSz = srk.pub.publicArea.unique.ecc.x.size;
    ySz = srk.pub.publicArea.unique.ecc.y.size;
    AssertIntGT(xSz, 0);
    AssertIntGT(ySz, 0);
    AssertIntLE(xSz, (word32)sizeof(xBuf));
    AssertIntLE(ySz, (word32)sizeof(yBuf));
    XMEMCPY(xBuf, srk.pub.publicArea.unique.ecc.x.buffer, xSz);
    XMEMCPY(yBuf, srk.pub.publicArea.unique.ecc.y.buffer, ySz);

    /* Load same coordinates as a peer ECDH key with the decrypt attribute */
    rc = wolfTPM2_LoadEccPublicKey_ex(&dev, &peer, curve,
        xBuf, xSz, yBuf, ySz,
        TPM_ALG_ECDH, nameAlg,
        TPMA_OBJECT_decrypt | TPMA_OBJECT_userWithAuth | TPMA_OBJECT_noDA);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    AssertIntEQ(peer.pub.publicArea.parameters.eccDetail.scheme.scheme,
        TPM_ALG_ECDH);
    AssertIntEQ((int)(peer.pub.publicArea.objectAttributes &
        TPMA_OBJECT_decrypt), (int)TPMA_OBJECT_decrypt);
    AssertIntEQ((int)(peer.pub.publicArea.objectAttributes &
        TPMA_OBJECT_sign), 0);
    wolfTPM2_UnloadHandle(&dev, &peer.handle);

    /* Legacy wolfTPM2_LoadEccPublicKey: still defaults to ECDSA + sign */
    XMEMSET(&peer, 0, sizeof(peer));
    rc = wolfTPM2_LoadEccPublicKey(&dev, &peer, curve,
        xBuf, xSz, yBuf, ySz);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    AssertIntEQ(peer.pub.publicArea.parameters.eccDetail.scheme.scheme,
        TPM_ALG_ECDSA);
    AssertIntEQ((int)(peer.pub.publicArea.objectAttributes &
        TPMA_OBJECT_sign), (int)TPMA_OBJECT_sign);
    AssertIntEQ((int)(peer.pub.publicArea.objectAttributes &
        TPMA_OBJECT_decrypt), 0);
    wolfTPM2_UnloadHandle(&dev, &peer.handle);

    wolfTPM2_UnloadHandle(&dev, &srk.handle);
    wolfTPM2_Cleanup(&dev);

    printf("Test TPM Wrapper:\tLoadEccPublicKey_ex:\t\tPassed\n");
#endif
}

/* wolfTPM2_GetKeyTemplate_KeyedHash must default scheme to TPM_ALG_NULL
 * when neither isSign nor isDecrypt is set; an HMAC scheme without the
 * sign attribute produces an unusable keyed-hash object. */
static void test_wolfTPM2_GetKeyTemplate_KeyedHash_Scheme(void)
{
#if !defined(WOLFTPM2_NO_WOLFCRYPT)
    int rc;
    TPMT_PUBLIC tpl;

    /* Data/seal-style: isSign=0, isDecrypt=0 -> scheme must be NULL */
    XMEMSET(&tpl, 0, sizeof(tpl));
    rc = wolfTPM2_GetKeyTemplate_KeyedHash(&tpl, TPM_ALG_SHA256, 0, 0);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    AssertIntEQ(tpl.parameters.keyedHashDetail.scheme.scheme, TPM_ALG_NULL);
    AssertIntEQ((int)(tpl.objectAttributes & TPMA_OBJECT_sign), 0);
    AssertIntEQ((int)(tpl.objectAttributes & TPMA_OBJECT_decrypt), 0);

    /* HMAC-style: isSign=1 -> scheme HMAC + hashAlg + sign attribute */
    XMEMSET(&tpl, 0, sizeof(tpl));
    rc = wolfTPM2_GetKeyTemplate_KeyedHash(&tpl, TPM_ALG_SHA256, 1, 0);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    AssertIntEQ(tpl.parameters.keyedHashDetail.scheme.scheme, TPM_ALG_HMAC);
    AssertIntEQ(tpl.parameters.keyedHashDetail.scheme.details.hmac.hashAlg,
        TPM_ALG_SHA256);
    AssertIntEQ((int)(tpl.objectAttributes & TPMA_OBJECT_sign),
        (int)TPMA_OBJECT_sign);

    printf("Test TPM Wrapper:\tKeyedHash template scheme:\tPassed\n");
#endif
}

/* wolfTPM2_VerifyHashTicket must apply the same RSA-strict / ECDSA-permissive
 * digest size policy as wolfTPM2_SignHashScheme. The bounds check fires
 * before any TPM call so this test does not require a working TPM. */
static void test_wolfTPM2_VerifyHashTicket_DigestSize(void)
{
#if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_RSA)
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY key;
    byte digest[TPM_MAX_DIGEST_SIZE];
    byte sig[MAX_RSA_KEY_BYTES];

    XMEMSET(&dev, 0, sizeof(dev));
    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(digest, 0xCC, sizeof(digest));
    XMEMSET(sig, 0, sizeof(sig));
    key.handle.hndl = 0x80000000;
    key.pub.publicArea.type = TPM_ALG_RSA;

    /* SHA-256 digest (32) + hashAlg=SHA512 -> RSA mismatch -> BUFFER_E */
    rc = wolfTPM2_VerifyHashTicket(&dev, &key, sig, 256, digest, 32,
        TPM_ALG_RSASSA, TPM_ALG_SHA512, NULL);
    AssertIntEQ(rc, BUFFER_E);

    /* Oversized digest (64) + hashAlg=SHA256 -> BUFFER_E */
    rc = wolfTPM2_VerifyHashTicket(&dev, &key, sig, 256, digest, 64,
        TPM_ALG_RSASSA, TPM_ALG_SHA256, NULL);
    AssertIntEQ(rc, BUFFER_E);

    /* Negative digestSz -> BUFFER_E */
    rc = wolfTPM2_VerifyHashTicket(&dev, &key, sig, 256, digest, -1,
        TPM_ALG_RSASSA, TPM_ALG_SHA256, NULL);
    AssertIntEQ(rc, BUFFER_E);

    printf("Test TPM Wrapper:\tVerifyHashTicket size:\t\tPassed\n");
#endif
}

#ifndef WOLFTPM_NO_RETRY
/* Transparent TPM_RC_RETRY resubmit is configurable. Verify the default seeded
 * by init, the setter/getter round-trip, and rejection of bad arguments. */
static void test_TPM2_CommandRetries(void)
{
    int rc;
    WOLFTPM2_DEV dev;

    XMEMSET(&dev, 0, sizeof(dev));

    rc = TPM2_SetCommandRetries(NULL, 1);
    AssertIntEQ(rc, BAD_FUNC_ARG);
    rc = TPM2_GetCommandRetries(NULL);
    AssertIntEQ(rc, BAD_FUNC_ARG);
    rc = TPM2_SetCommandRetries(&dev.ctx, -1);
    AssertIntEQ(rc, BAD_FUNC_ARG);

    /* retries is seeded before any HAL IO setup, so the default holds even on
     * builds without a default IO callback where init returns an error */
    (void)TPM2_Init_minimal(&dev.ctx);
    AssertIntEQ(TPM2_GetCommandRetries(&dev.ctx), WOLFTPM_MAX_RETRIES);

    rc = TPM2_SetCommandRetries(&dev.ctx, 0);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    AssertIntEQ(TPM2_GetCommandRetries(&dev.ctx), 0);

    rc = TPM2_SetCommandRetries(&dev.ctx, 7);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    AssertIntEQ(TPM2_GetCommandRetries(&dev.ctx), 7);

    TPM2_Cleanup(&dev.ctx);

    printf("Test TPM Wrapper:\tCommandRetries config:\t\tPassed\n");
}

/* Exercise the TPM_RC_RETRY resubmit bookkeeping directly: header/size restore,
 * command-body preservation, retry-count decrement, and surfacing TPM_RC_RETRY
 * once the count is exhausted - the parts of the loop most likely to regress. */
static void test_TPM2_Packet_RetryRestore(void)
{
    TPM2_Packet packet;
    byte buf[TPM2_HEADER_SIZE + 4];
    byte hdr[TPM2_HEADER_SIZE];
    int retries;

    XMEMSET(hdr, 0xAA, sizeof(hdr));
    XMEMSET(buf, 0x00, sizeof(buf));
    buf[TPM2_HEADER_SIZE] = 0xBB; /* command body byte, must survive a resend */
    packet.buf = buf;
    packet.pos = 0;
    packet.size = TPM2_HEADER_SIZE; /* shrunk by a prior TPM2_Packet_Parse */

    /* A non-retry response must not resubmit and must leave state untouched */
    retries = 2;
    AssertIntEQ(TPM2_Packet_RetryRestore(TPM_RC_SUCCESS, &retries, &packet,
        hdr, (int)sizeof(buf)), 0);
    AssertIntEQ(retries, 2);
    AssertIntEQ(packet.size, TPM2_HEADER_SIZE);

    /* RETRY with budget: resubmit, header + size restored, body preserved */
    AssertIntEQ(TPM2_Packet_RetryRestore(TPM_RC_RETRY, &retries, &packet,
        hdr, (int)sizeof(buf)), 1);
    AssertIntEQ(retries, 1);
    AssertIntEQ(packet.size, (int)sizeof(buf));
    AssertIntEQ(buf[0], 0xAA);
    AssertIntEQ(buf[TPM2_HEADER_SIZE], 0xBB);

    /* Second RETRY exhausts the budget */
    AssertIntEQ(TPM2_Packet_RetryRestore(TPM_RC_RETRY, &retries, &packet,
        hdr, (int)sizeof(buf)), 1);
    AssertIntEQ(retries, 0);

    /* Budget exhausted: RETRY is surfaced to the caller, no resubmit */
    AssertIntEQ(TPM2_Packet_RetryRestore(TPM_RC_RETRY, &retries, &packet,
        hdr, (int)sizeof(buf)), 0);
    AssertIntEQ(retries, 0);

    /* NULL guards */
    retries = 1;
    AssertIntEQ(TPM2_Packet_RetryRestore(TPM_RC_RETRY, NULL, &packet,
        hdr, (int)sizeof(buf)), 0);
    AssertIntEQ(TPM2_Packet_RetryRestore(TPM_RC_RETRY, &retries, NULL,
        hdr, (int)sizeof(buf)), 0);

    printf("Test TPM Wrapper:\tRetryRestore logic:\t\tPassed\n");
}
#endif /* !WOLFTPM_NO_RETRY */

/* A sessioned response whose attacker-controlled parameterSize wraps UINT32
 * when added to packet->pos must be rejected up front. Without the bounds
 * check the wrapped authPos passes the "respSz > authPos" guard and the
 * oversized parameterSize flows into TPM2_CalcRpHash as an out-of-bounds
 * read length. The bounds check itself is build-independent. */
static void test_TPM2_ResponseProcess_ParamSizeOverflow(void)
{
    TPM2_CTX ctx;
    TPM2_AUTH_SESSION session[1];
    TPM2_Packet packet;
    CmdInfo_t info;
    byte buf[128];
    int rc;

    XMEMSET(&ctx, 0, sizeof(ctx));
    XMEMSET(session, 0, sizeof(session));
    XMEMSET(&info, 0, sizeof(info));
    XMEMSET(buf, 0, sizeof(buf));

    /* parameterSize field at offset TPM2_HEADER_SIZE: 0xFFFFFFF8 makes
     * authPos = pos + paramSz wrap to a small in-range value */
    buf[TPM2_HEADER_SIZE + 0] = 0xFF;
    buf[TPM2_HEADER_SIZE + 1] = 0xFF;
    buf[TPM2_HEADER_SIZE + 2] = 0xFF;
    buf[TPM2_HEADER_SIZE + 3] = 0xF8;

    session[0].sessionHandle = HMAC_SESSION_FIRST;
    session[0].authHash = TPM_ALG_SHA256;
    ctx.session = session;

    info.authCnt = 1;
    info.inHandleCnt = 0;
    info.outHandleCnt = 0;
    info.flags = 0;

    packet.buf = buf;
    packet.pos = 0;
    packet.size = (int)sizeof(buf);

    rc = TPM2_ResponseProcess(&ctx, &packet, &info, (TPM_CC)0,
        (UINT32)sizeof(buf));
    AssertIntEQ(rc, TPM_RC_SIZE);

    /* A valid in-range parameterSize must not be rejected */
    XMEMSET(buf, 0, sizeof(buf));
    buf[TPM2_HEADER_SIZE + 3] = 0x04;
    info.authCnt = 0;
    packet.pos = 0;
    packet.size = (int)sizeof(buf);

    rc = TPM2_ResponseProcess(&ctx, &packet, &info, (TPM_CC)0,
        (UINT32)sizeof(buf));
    AssertIntEQ(rc, TPM_RC_SUCCESS);

    /* A response too small to hold the parsed parameterSize must be rejected */
    packet.pos = 0;
    packet.size = (int)sizeof(buf);
    rc = TPM2_ResponseProcess(&ctx, &packet, &info, (TPM_CC)0,
        (UINT32)(TPM2_HEADER_SIZE + 2));
    AssertIntEQ(rc, TPM_RC_SIZE);

    /* An exact-fit parameterSize (paramSz == respSz - pos) must be accepted */
    XMEMSET(buf, 0, sizeof(buf));
    buf[TPM2_HEADER_SIZE + 3] = (byte)(sizeof(buf) - (TPM2_HEADER_SIZE + 4));
    packet.pos = 0;
    packet.size = (int)sizeof(buf);
    rc = TPM2_ResponseProcess(&ctx, &packet, &info, (TPM_CC)0,
        (UINT32)sizeof(buf));
    AssertIntEQ(rc, TPM_RC_SUCCESS);

    printf("Test TPM Wrapper:\tResponseProcess paramSize overflow:\tPassed\n");
}

static void test_TPM2_ResponseProcess_HmacVerify(void)
{
#if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_HMAC)
    TPM2_CTX ctx;
    TPM2_AUTH_SESSION session[1];
    TPM2_Packet packet;
    CmdInfo_t info;
    TPM2B_DIGEST rpHash;
    TPM2B_AUTH expHmac;
    TPM2B_NONCE nonceTPM;
    byte buf[128];
    int rc, i;
    TPM_CC cmdCode = 0x17F;
    UINT16 hmacSz = 32, nonceSz = 32;
    UINT32 paramSz = 4;
    UINT32 pos, hmacOff, respSz;
    byte attr = 0x01;

    XMEMSET(&ctx, 0, sizeof(ctx));
    XMEMSET(session, 0, sizeof(session));
    XMEMSET(&info, 0, sizeof(info));
    XMEMSET(buf, 0, sizeof(buf));

    /* HMAC session with a known auth value and nonces */
    session[0].sessionHandle = HMAC_SESSION_FIRST;
    session[0].authHash = TPM_ALG_SHA256;
    session[0].auth.size = 4;
    XMEMSET(session[0].auth.buffer, 0xA5, 4);
    session[0].nonceCaller.size = 32;
    XMEMSET(session[0].nonceCaller.buffer, 0x5C, 32);
    session[0].nonceTPM.size = 32;
    XMEMSET(session[0].nonceTPM.buffer, 0xC5, 32);
    ctx.session = session;
    info.authCnt = 1;

    /* header + paramSize(U32) + params + auth area (nonce, attr, hmac) */
    pos = TPM2_HEADER_SIZE;
    buf[pos++] = 0; buf[pos++] = 0; buf[pos++] = 0; buf[pos++] = (byte)paramSz;
    buf[pos++] = 0xDE; buf[pos++] = 0xAD; buf[pos++] = 0xBE; buf[pos++] = 0xEF;
    buf[pos++] = (byte)(nonceSz >> 8); buf[pos++] = (byte)(nonceSz & 0xFF);
    for (i = 0; i < nonceSz; i++)
        buf[pos++] = 0x99;                          /* response nonceTPM */
    buf[pos++] = attr;                              /* sessionAttributes */
    buf[pos++] = (byte)(hmacSz >> 8); buf[pos++] = (byte)(hmacSz & 0xFF);
    hmacOff = pos;
    pos += hmacSz;
    respSz = pos;

    /* expected HMAC uses the response nonce as nonceTPM */
    nonceTPM.size = nonceSz;
    XMEMSET(nonceTPM.buffer, 0x99, nonceSz);
    rc = TPM2_CalcRpHash(TPM_ALG_SHA256, cmdCode, &buf[TPM2_HEADER_SIZE + 4],
        paramSz, &rpHash);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    XMEMSET(&expHmac, 0, sizeof(expHmac));
    rc = TPM2_CalcHmac(TPM_ALG_SHA256, &session[0].auth, &rpHash,
        &nonceTPM, &session[0].nonceCaller, attr, &expHmac);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    XMEMCPY(&buf[hmacOff], expHmac.buffer, hmacSz);

    /* untampered response HMAC must verify and update nonceTPM */
    packet.buf = buf; packet.pos = 0; packet.size = (int)respSz;
    rc = TPM2_ResponseProcess(&ctx, &packet, &info, cmdCode, respSz);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    AssertIntEQ(session[0].nonceTPM.buffer[0], 0x99);

    /* flipping one HMAC byte must be detected */
    buf[hmacOff] ^= 0xFF;
    packet.buf = buf; packet.pos = 0; packet.size = (int)respSz;
    rc = TPM2_ResponseProcess(&ctx, &packet, &info, cmdCode, respSz);
    AssertIntEQ(rc, TPM_RC_HMAC);

    printf("Test TPM Wrapper:\tResponseProcess HMAC verify:\tPassed\n");
#endif
}

/* wolfTPM2_NVCreateAuthPolicy must derive nameAlg from authPolicySz so
 * the policy digest hash matches the index's nameAlg. Bug-mode hardcoded
 * SHA-256 nameAlg, which made SHA-384/SHA-512 policies unsatisfiable.
 * Mismatched digest sizes must be rejected up front. */
static void test_wolfTPM2_NVCreateAuthPolicy_NameAlg(void)
{
#if !defined(WOLFTPM2_NO_WOLFCRYPT)
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_HANDLE parent;
    WOLFTPM2_NV nv;
    byte policy[64];

    XMEMSET(&dev, 0, sizeof(dev));
    XMEMSET(&parent, 0, sizeof(parent));
    XMEMSET(&nv, 0, sizeof(nv));
    XMEMSET(policy, 0xAB, sizeof(policy));

    /* No real TPM call required to exercise the new size validation - the
     * mismatch check fires before TPM2_NV_DefineSpace is contacted. */
    parent.hndl = TPM_RH_OWNER;

    /* 33 bytes is not a recognized hash digest size -> BAD_FUNC_ARG. */
    rc = wolfTPM2_NVCreateAuthPolicy(&dev, &parent, &nv, 0x01400001,
        TPMA_NV_OWNERWRITE | TPMA_NV_OWNERREAD | TPMA_NV_NO_DA, 64,
        NULL, 0, policy, 33);
    AssertIntEQ(rc, BAD_FUNC_ARG);

    /* 17 bytes is not a recognized hash digest size -> BAD_FUNC_ARG. */
    rc = wolfTPM2_NVCreateAuthPolicy(&dev, &parent, &nv, 0x01400002,
        TPMA_NV_OWNERWRITE | TPMA_NV_OWNERREAD | TPMA_NV_NO_DA, 64,
        NULL, 0, policy, 17);
    AssertIntEQ(rc, BAD_FUNC_ARG);

    printf("Test TPM Wrapper:\tNVCreateAuthPolicy nameAlg:\tPassed\n");
#endif
}

/* wolfTPM2_SignHashScheme must reject digest sizes that don't match the
 * declared hashAlg for RSA keys, instead of silently zero-padding. The
 * pad-to-hash-size convention is preserved for ECDSA per spec. */
static void test_wolfTPM2_SignHashScheme_DigestSize(void)
{
#if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_RSA)
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY key;
    byte digest[TPM_MAX_DIGEST_SIZE];
    byte sig[MAX_RSA_KEY_BYTES];
    int sigSz = (int)sizeof(sig);

    XMEMSET(&dev, 0, sizeof(dev));
    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(digest, 0xCC, sizeof(digest));
    key.handle.hndl = 0x80000000;
    key.pub.publicArea.type = TPM_ALG_RSA;

    /* SHA-256 digest (32) but caller declared SHA-512 (64): for RSA this
     * was previously silently zero-padded; now must return BUFFER_E. */
    rc = wolfTPM2_SignHashScheme(&dev, &key, digest, 32, sig, &sigSz,
        TPM_ALG_RSASSA, TPM_ALG_SHA512);
    AssertIntEQ(rc, BUFFER_E);

    /* Oversized digest (larger than declared hashAlg) is also BUFFER_E. */
    sigSz = (int)sizeof(sig);
    rc = wolfTPM2_SignHashScheme(&dev, &key, digest, 64, sig, &sigSz,
        TPM_ALG_RSASSA, TPM_ALG_SHA256);
    AssertIntEQ(rc, BUFFER_E);

    printf("Test TPM Wrapper:\tSignHashScheme size:\t\tPassed\n");
#endif
}

/* wolfTPM2_RsaEncrypt and wolfTPM2_RsaDecrypt must reject oversized inputs
 * with BUFFER_E rather than silently truncating to the message buffer
 * length. The bounds check fires before the TPM is contacted, so this
 * test does not require a working TPM connection. */
static void test_wolfTPM2_RsaEncryptDecrypt_OversizedBufferE(void)
{
#if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_RSA)
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY key;
    byte oversized[MAX_RSA_KEY_BYTES + 16];
    byte out[MAX_RSA_KEY_BYTES];
    int outSz = (int)sizeof(out);

    XMEMSET(&dev, 0, sizeof(dev));
    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(oversized, 0xAB, sizeof(oversized));
    key.handle.hndl = 0x80000000;

    rc = wolfTPM2_RsaEncrypt(&dev, &key, TPM_ALG_NULL,
        oversized, (int)sizeof(oversized), out, &outSz);
    AssertIntEQ(rc, BUFFER_E);

    outSz = (int)sizeof(out);
    rc = wolfTPM2_RsaDecrypt(&dev, &key, TPM_ALG_NULL,
        oversized, (int)sizeof(oversized), out, &outSz);
    AssertIntEQ(rc, BUFFER_E);

    printf("Test TPM Wrapper:\tRsaEncDec oversized:\t\tPassed\n");
#endif
}

/* Exercise the _ex padding-scheme hash selection (e.g. SHA-512 OAEP). The
 * BAD_FUNC_ARG and BUFFER_E paths fire before the TPM is contacted, so this
 * does not require a working TPM connection. */
static void test_wolfTPM2_RsaEncryptDecrypt_ex(void)
{
#if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_RSA)
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY key;
    byte oversized[MAX_RSA_KEY_BYTES + 16];
    byte out[MAX_RSA_KEY_BYTES];
    int outSz = (int)sizeof(out);

    XMEMSET(&dev, 0, sizeof(dev));
    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(oversized, 0xAB, sizeof(oversized));
    key.handle.hndl = 0x80000000;

    rc = wolfTPM2_RsaEncrypt_ex(NULL, &key, TPM_ALG_OAEP,
        oversized, 1, out, &outSz, TPM_ALG_SHA512);
    AssertIntEQ(rc, BAD_FUNC_ARG);

    outSz = (int)sizeof(out);
    rc = wolfTPM2_RsaEncrypt_ex(&dev, &key, TPM_ALG_OAEP,
        oversized, (int)sizeof(oversized), out, &outSz, TPM_ALG_SHA512);
    AssertIntEQ(rc, BUFFER_E);

    outSz = (int)sizeof(out);
    rc = wolfTPM2_RsaDecrypt_ex(&dev, &key, TPM_ALG_OAEP,
        oversized, (int)sizeof(oversized), out, &outSz, TPM_ALG_SHA512);
    AssertIntEQ(rc, BUFFER_E);

#ifndef NO_SHA
    /* OAEP with a hash weaker than the default is rejected */
    if (TPM2_GetHashDigestSize(TPM_ALG_SHA1) <
            TPM2_GetHashDigestSize(WOLFTPM2_WRAP_DIGEST)) {
        outSz = (int)sizeof(out);
        rc = wolfTPM2_RsaEncrypt_ex(&dev, &key, TPM_ALG_OAEP,
            oversized, 1, out, &outSz, TPM_ALG_SHA1);
        AssertIntEQ(rc, BAD_FUNC_ARG);
    }
#endif

    printf("Test TPM Wrapper:\tRsaEncDec_ex SHA512:\t\tPassed\n");
#endif
}

/* Verify the PQC key-template _ex wrappers select the object name algorithm
 * and that the original wrappers keep the default. Pure struct population,
 * no TPM required. */
static void test_wolfTPM2_GetKeyTemplate_ex_nameAlg(void)
{
#if defined(WOLFTPM_PQC) && !defined(WOLFTPM2_NO_WOLFCRYPT)
    int rc;
    TPMT_PUBLIC pub;
    TPMA_OBJECT attr = TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent |
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth;

#ifdef WOLFTPM_MLDSA
    XMEMSET(&pub, 0, sizeof(pub));
    rc = wolfTPM2_GetKeyTemplate_MLDSA(&pub, attr, TPM_MLDSA_65, 0);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    AssertIntEQ(pub.nameAlg, WOLFTPM2_WRAP_DIGEST);

    rc = wolfTPM2_GetKeyTemplate_MLDSA_ex(&pub, attr, TPM_MLDSA_65, 0,
        TPM_ALG_SHA512);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    AssertIntEQ(pub.nameAlg, TPM_ALG_SHA512);

    rc = wolfTPM2_GetKeyTemplate_MLDSA_ex(&pub, attr, TPM_MLDSA_65, 0,
        TPM_ALG_NULL);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    AssertIntEQ(pub.nameAlg, WOLFTPM2_WRAP_DIGEST);
#endif

#ifdef WOLFTPM_HASH_MLDSA
    XMEMSET(&pub, 0, sizeof(pub));
    rc = wolfTPM2_GetKeyTemplate_HASH_MLDSA(&pub, attr, TPM_MLDSA_65,
        TPM_ALG_SHA256);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    AssertIntEQ(pub.nameAlg, WOLFTPM2_WRAP_DIGEST);

    rc = wolfTPM2_GetKeyTemplate_HASH_MLDSA_ex(&pub, attr, TPM_MLDSA_65,
        TPM_ALG_SHA256, TPM_ALG_SHA512);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    AssertIntEQ(pub.nameAlg, TPM_ALG_SHA512);
#endif

#ifdef WOLFTPM_MLKEM
    XMEMSET(&pub, 0, sizeof(pub));
    rc = wolfTPM2_GetKeyTemplate_MLKEM(&pub, attr, TPM_MLKEM_768);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    AssertIntEQ(pub.nameAlg, WOLFTPM2_WRAP_DIGEST);

    rc = wolfTPM2_GetKeyTemplate_MLKEM_ex(&pub, attr, TPM_MLKEM_768,
        TPM_ALG_SHA512);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    AssertIntEQ(pub.nameAlg, TPM_ALG_SHA512);

#ifndef NO_SHA
    /* a name algorithm weaker than the default is rejected */
    if (TPM2_GetHashDigestSize(TPM_ALG_SHA1) <
            TPM2_GetHashDigestSize(WOLFTPM2_WRAP_DIGEST)) {
        rc = wolfTPM2_GetKeyTemplate_MLKEM_ex(&pub, attr, TPM_MLKEM_768,
            TPM_ALG_SHA1);
        AssertIntEQ(rc, BAD_FUNC_ARG);
    }
#endif
#endif

    (void)attr;
    (void)rc;
    printf("Test TPM Wrapper:\tGetKeyTemplate _ex nameAlg:\tPassed\n");
#endif /* WOLFTPM_PQC */
}

/* TPM2_GetTpmCurve / TPM2_GetWolfCurve must map wolfCrypt's
 * ECC_BRAINPOOLP256R1 to TPM_ECC_BP_P256_R1 (0x0030), not
 * TPM_ECC_BN_P256 (0x0010, Barreto-Naehrig). Pre-fix the two were
 * conflated, producing an on-the-wire curve ID that is a different
 * mathematical curve. */
static void test_TPM2_BrainpoolCurveMapping(void)
{
#if !defined(WOLFTPM2_NO_WOLFCRYPT) && defined(HAVE_ECC)
    AssertIntEQ(TPM2_GetTpmCurve(ECC_BRAINPOOLP256R1), TPM_ECC_BP_P256_R1);
    AssertIntEQ(TPM2_GetTpmCurve(ECC_BRAINPOOLP384R1), TPM_ECC_BP_P384_R1);
    AssertIntEQ(TPM2_GetTpmCurve(ECC_BRAINPOOLP512R1), TPM_ECC_BP_P512_R1);

    AssertIntEQ(TPM2_GetWolfCurve(TPM_ECC_BP_P256_R1), ECC_BRAINPOOLP256R1);
    AssertIntEQ(TPM2_GetWolfCurve(TPM_ECC_BP_P384_R1), ECC_BRAINPOOLP384R1);
    AssertIntEQ(TPM2_GetWolfCurve(TPM_ECC_BP_P512_R1), ECC_BRAINPOOLP512R1);

    /* TPM_ECC_BN_P256 (Barreto-Naehrig pairing curve) has no wolfCrypt
     * equivalent and must report ECC_CURVE_OID_E rather than aliasing
     * to a Brainpool ID. */
    AssertIntEQ(TPM2_GetWolfCurve(TPM_ECC_BN_P256), ECC_CURVE_OID_E);

    /* Sanity: NIST mappings still round-trip. */
    AssertIntEQ(TPM2_GetTpmCurve(ECC_SECP256R1), TPM_ECC_NIST_P256);
    AssertIntEQ(TPM2_GetWolfCurve(TPM_ECC_NIST_P256), ECC_SECP256R1);

    /* TPM2_GetCurveSize must report the correct byte size for the new
     * Brainpool curve IDs (32 / 48 / 64). */
    AssertIntEQ(TPM2_GetCurveSize(TPM_ECC_BP_P256_R1), 32);
    AssertIntEQ(TPM2_GetCurveSize(TPM_ECC_BP_P384_R1), 48);
    AssertIntEQ(TPM2_GetCurveSize(TPM_ECC_BP_P512_R1), 64);

    /* TPM2_GetCurveHashAlg pairs the digest strength to the curve size,
     * per TCG recommended combinations. */
    AssertIntEQ(TPM2_GetCurveHashAlg(TPM_ECC_NIST_P256), TPM_ALG_SHA256);
    AssertIntEQ(TPM2_GetCurveHashAlg(TPM_ECC_NIST_P384), TPM_ALG_SHA384);
    AssertIntEQ(TPM2_GetCurveHashAlg(TPM_ECC_NIST_P521), TPM_ALG_SHA512);
    AssertIntEQ(TPM2_GetCurveHashAlg(TPM_ECC_BP_P256_R1), TPM_ALG_SHA256);
    AssertIntEQ(TPM2_GetCurveHashAlg(TPM_ECC_BP_P384_R1), TPM_ALG_SHA384);
    AssertIntEQ(TPM2_GetCurveHashAlg(TPM_ECC_BP_P512_R1), TPM_ALG_SHA512); /* 64 -> SHA512 */
    AssertIntEQ(TPM2_GetCurveHashAlg(TPM_ECC_BN_P638), TPM_ALG_SHA512);

    printf("Test TPM Wrapper:\tBrainpool curve mapping:\tPassed\n");
#endif
}

/* The no-explicit-curve named templates (SRK, AIK) follow the build's
 * WOLFTPM2_ECC_DEFAULT_CURVE: a no-op in the shipped P256 build, an upgrade
 * when overridden to e.g. P384. The explicit-curve APIs (general ECC/_ex) and
 * the TCG-fixed EK templates honor the exact curve requested (except under
 * NO_ECC256, where P256 is unavailable to every caller - those checks are
 * guarded for that case). */
static void test_TPM2_EccDefaultCurveTemplate(void)
{
#if !defined(WOLFTPM2_NO_WOLFCRYPT) && defined(HAVE_ECC)
    TPMT_PUBLIC t;

#ifndef NO_ECC256
    /* Explicit-curve APIs must honor exactly what is passed: an explicit P256
     * request stays P256 even in a WOLFTPM2_ECC_DEFAULT_CURVE override build.
     * This is the regression guard for protocol-bound callers (e.g. ECDH),
     * whose shared secret breaks if the curve is silently remapped. */
    AssertIntEQ(wolfTPM2_GetKeyTemplate_ECC(&t, TPMA_OBJECT_sign,
        TPM_ECC_NIST_P256, TPM_ALG_ECDSA), 0);
    AssertIntEQ(t.parameters.eccDetail.curveID, TPM_ECC_NIST_P256);
    AssertIntEQ(wolfTPM2_GetKeyTemplate_ECC_ex(&t, TPM_ALG_SHA256,
        TPMA_OBJECT_sign, TPM_ECC_NIST_P256, TPM_ALG_ECDSA, TPM_ALG_SHA256), 0);
    AssertIntEQ(t.parameters.eccDetail.curveID, TPM_ECC_NIST_P256);
#endif

    /* The storage primary (wolfTPM2_CreateSRK ECC path) follows the default. */
    AssertIntEQ(wolfTPM2_GetKeyTemplate_ECC_SRK(&t), 0);
    AssertIntEQ(t.parameters.eccDetail.curveID, WOLFTPM2_ECC_DEFAULT_CURVE);
    AssertIntEQ(t.nameAlg, TPM2_GetCurveHashAlg(WOLFTPM2_ECC_DEFAULT_CURVE));

    /* The attestation signing key (AIK) follows the default. This block
     * exercises the sigHash arg of the resolver, so lock in name and sig
     * hash too. */
    AssertIntEQ(wolfTPM2_GetKeyTemplate_ECC_AIK(&t), 0);
    AssertIntEQ(t.parameters.eccDetail.curveID, WOLFTPM2_ECC_DEFAULT_CURVE);
    AssertIntEQ(t.nameAlg, TPM2_GetCurveHashAlg(WOLFTPM2_ECC_DEFAULT_CURVE));
    AssertIntEQ(t.parameters.eccDetail.scheme.details.ecdsa.hashAlg,
        TPM2_GetCurveHashAlg(WOLFTPM2_ECC_DEFAULT_CURVE));

#ifndef NO_ECC256
    /* EK P256 NV index is TCG-fixed and must NOT follow the default curve. */
    AssertIntEQ(wolfTPM2_GetKeyTemplate_EKIndex(TPM2_NV_EK_ECC_P256, &t), 0);
    AssertIntEQ(t.parameters.eccDetail.curveID, TPM_ECC_NIST_P256);
    AssertIntEQ(t.nameAlg, TPM_ALG_SHA256);
    AssertIntEQ(t.authPolicy.size, sizeof(TPM_20_EK_AUTH_POLICY));
#else
    /* Under NO_ECC256 the EK P256 index is substituted to an enabled curve for
     * every caller. Verify the name hash matches the substituted curve and a
     * (non-empty) auth policy was selected for that same hash - i.e. nameAlg
     * and authPolicy stay consistent (regression guard for the prior mismatch
     * where nameAlg became SHA384/SHA512 but the SHA256 policy was copied). */
    AssertIntEQ(wolfTPM2_GetKeyTemplate_EKIndex(TPM2_NV_EK_ECC_P256, &t), 0);
    AssertIntEQ(t.parameters.eccDetail.curveID, WOLFTPM2_ECC_DEFAULT_CURVE);
    AssertIntEQ(t.nameAlg, TPM2_GetCurveHashAlg(WOLFTPM2_ECC_DEFAULT_CURVE));
    AssertIntGT(t.authPolicy.size, 0);
#endif

    printf("Test TPM Wrapper:\tECC default-curve template:\tPassed\n");
#endif
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

    printf("Test TPM Wrapper: %-40s Passed\n", "KeyedHashScheme XOR serialize:");
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

    printf("Test TPM Wrapper: %-40s Passed\n",
        "Signature ECSCHNORR/SM2 serialize:");
}

static void test_TPM2_Public_RsaEcc_Roundtrip(void)
{
#if !defined(WOLFTPM2_NO_WOLFCRYPT)
    int rc, sz;
    byte buf[sizeof(TPM2B_PUBLIC)];
    TPM2B_PUBLIC pubIn, pubOut;
    const byte uniqueBytes[8] = {
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22
    };

    /* RSA with AES-128-CFB symmetric wrapper (exercises the AES mode field)
     * and an RSASSA-SHA256 scheme */
    XMEMSET(&pubIn, 0, sizeof(pubIn));
    pubIn.publicArea.type = TPM_ALG_RSA;
    pubIn.publicArea.nameAlg = TPM_ALG_SHA256;
    pubIn.publicArea.objectAttributes = TPMA_OBJECT_sign;
    pubIn.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
    pubIn.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
    pubIn.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_CFB;
    pubIn.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_RSASSA;
    pubIn.publicArea.parameters.rsaDetail.scheme.details.rsassa.hashAlg =
        TPM_ALG_SHA256;
    pubIn.publicArea.parameters.rsaDetail.keyBits = 2048;
    pubIn.publicArea.parameters.rsaDetail.exponent = 0x10001;
    pubIn.publicArea.unique.rsa.size = sizeof(uniqueBytes);
    XMEMCPY(pubIn.publicArea.unique.rsa.buffer, uniqueBytes,
        sizeof(uniqueBytes));

    XMEMSET(buf, 0, sizeof(buf));
    sz = 0;
    rc = TPM2_AppendPublic(buf, (word32)sizeof(buf), &sz, &pubIn);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    AssertIntGT(sz, 0);

    XMEMSET(&pubOut, 0, sizeof(pubOut));
    rc = TPM2_ParsePublic(&pubOut, buf, (word32)sz, &sz);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    AssertIntEQ(pubOut.publicArea.type, TPM_ALG_RSA);
    AssertIntEQ(pubOut.publicArea.nameAlg, TPM_ALG_SHA256);
    AssertIntEQ(pubOut.publicArea.parameters.rsaDetail.symmetric.algorithm,
        TPM_ALG_AES);
    AssertIntEQ(pubOut.publicArea.parameters.rsaDetail.symmetric.keyBits.aes,
        128);
    AssertIntEQ(pubOut.publicArea.parameters.rsaDetail.symmetric.mode.aes,
        TPM_ALG_CFB);
    AssertIntEQ(pubOut.publicArea.parameters.rsaDetail.scheme.scheme,
        TPM_ALG_RSASSA);
    AssertIntEQ(
        pubOut.publicArea.parameters.rsaDetail.scheme.details.rsassa.hashAlg,
        TPM_ALG_SHA256);
    AssertIntEQ(pubOut.publicArea.parameters.rsaDetail.keyBits, 2048);
    AssertIntEQ((int)pubOut.publicArea.parameters.rsaDetail.exponent, 0x10001);
    AssertIntEQ(pubOut.publicArea.unique.rsa.size, sizeof(uniqueBytes));
    AssertIntEQ(XMEMCMP(pubOut.publicArea.unique.rsa.buffer, uniqueBytes,
        sizeof(uniqueBytes)), 0);

    /* ECC P-256 with ECDSA-SHA256 scheme and NULL symmetric/kdf */
    XMEMSET(&pubIn, 0, sizeof(pubIn));
    pubIn.publicArea.type = TPM_ALG_ECC;
    pubIn.publicArea.nameAlg = TPM_ALG_SHA256;
    pubIn.publicArea.objectAttributes = TPMA_OBJECT_sign;
    pubIn.publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
    pubIn.publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_ECDSA;
    pubIn.publicArea.parameters.eccDetail.scheme.details.ecdsa.hashAlg =
        TPM_ALG_SHA256;
    pubIn.publicArea.parameters.eccDetail.curveID = TPM_ECC_NIST_P256;
    pubIn.publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
    pubIn.publicArea.unique.ecc.x.size = sizeof(uniqueBytes);
    XMEMCPY(pubIn.publicArea.unique.ecc.x.buffer, uniqueBytes,
        sizeof(uniqueBytes));
    pubIn.publicArea.unique.ecc.y.size = sizeof(uniqueBytes);
    XMEMCPY(pubIn.publicArea.unique.ecc.y.buffer, uniqueBytes,
        sizeof(uniqueBytes));

    XMEMSET(buf, 0, sizeof(buf));
    sz = 0;
    rc = TPM2_AppendPublic(buf, (word32)sizeof(buf), &sz, &pubIn);
    AssertIntEQ(rc, TPM_RC_SUCCESS);

    XMEMSET(&pubOut, 0, sizeof(pubOut));
    rc = TPM2_ParsePublic(&pubOut, buf, (word32)sz, &sz);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    AssertIntEQ(pubOut.publicArea.type, TPM_ALG_ECC);
    AssertIntEQ(pubOut.publicArea.parameters.eccDetail.symmetric.algorithm,
        TPM_ALG_NULL);
    AssertIntEQ(pubOut.publicArea.parameters.eccDetail.scheme.scheme,
        TPM_ALG_ECDSA);
    AssertIntEQ(
        pubOut.publicArea.parameters.eccDetail.scheme.details.ecdsa.hashAlg,
        TPM_ALG_SHA256);
    AssertIntEQ(pubOut.publicArea.parameters.eccDetail.curveID,
        TPM_ECC_NIST_P256);
    AssertIntEQ(pubOut.publicArea.parameters.eccDetail.kdf.scheme,
        TPM_ALG_NULL);
    AssertIntEQ(pubOut.publicArea.unique.ecc.x.size, sizeof(uniqueBytes));
    AssertIntEQ(XMEMCMP(pubOut.publicArea.unique.ecc.x.buffer, uniqueBytes,
        sizeof(uniqueBytes)), 0);
    AssertIntEQ(pubOut.publicArea.unique.ecc.y.size, sizeof(uniqueBytes));
    AssertIntEQ(XMEMCMP(pubOut.publicArea.unique.ecc.y.buffer, uniqueBytes,
        sizeof(uniqueBytes)), 0);

    printf("Test TPM Wrapper: %-40s Passed\n", "Public RSA/ECC roundtrip:");
#endif
}

#ifdef WOLFTPM_PQC
/* Round-trip the v1.85 PQC arms of TPMT_SIGNATURE through the packet
 * marshaler. Pure ML-DSA (Table 217 mldsa arm) is bare TPM2B + bytes —
 * no hash field. Hash-ML-DSA prefixes a hashAlg before the TPM2B. The
 * tests pin the on-wire byte counts to catch any future drift. */
static void test_TPM2_Signature_PQC_Serialize(void)
{
    TPM2_Packet packet;
    byte buf[256];
    TPMT_SIGNATURE sigIn, sigOut;
    const byte sigBytes[16] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };

    /* Pure ML-DSA: sigAlg(2) + sigSz(2) + sig(16) = 20 bytes. */
    XMEMSET(&sigIn, 0, sizeof(sigIn));
    sigIn.sigAlg = TPM_ALG_MLDSA;
    sigIn.signature.mldsa.size = sizeof(sigBytes);
    XMEMCPY(sigIn.signature.mldsa.buffer, sigBytes, sizeof(sigBytes));

    XMEMSET(buf, 0, sizeof(buf));
    XMEMSET(&packet, 0, sizeof(packet));
    packet.buf = buf;
    packet.size = sizeof(buf);

    TPM2_Packet_AppendSignature(&packet, &sigIn);
    AssertIntEQ(packet.pos, 2 + 2 + (int)sizeof(sigBytes));

    packet.pos = 0;
    XMEMSET(&sigOut, 0, sizeof(sigOut));
    TPM2_Packet_ParseSignature(&packet, &sigOut);
    AssertIntEQ(sigOut.sigAlg, TPM_ALG_MLDSA);
    AssertIntEQ(sigOut.signature.mldsa.size, sizeof(sigBytes));
    AssertIntEQ(XMEMCMP(sigOut.signature.mldsa.buffer,
        sigBytes, sizeof(sigBytes)), 0);

    /* Hash-ML-DSA: sigAlg(2) + hash(2) + sigSz(2) + sig(16) = 22 bytes. */
    XMEMSET(&sigIn, 0, sizeof(sigIn));
    sigIn.sigAlg = TPM_ALG_HASH_MLDSA;
    sigIn.signature.hash_mldsa.hash = TPM_ALG_SHA256;
    sigIn.signature.hash_mldsa.signature.size = sizeof(sigBytes);
    XMEMCPY(sigIn.signature.hash_mldsa.signature.buffer,
        sigBytes, sizeof(sigBytes));

    XMEMSET(buf, 0, sizeof(buf));
    XMEMSET(&packet, 0, sizeof(packet));
    packet.buf = buf;
    packet.size = sizeof(buf);

    TPM2_Packet_AppendSignature(&packet, &sigIn);
    AssertIntEQ(packet.pos, 2 + 2 + 2 + (int)sizeof(sigBytes));

    packet.pos = 0;
    XMEMSET(&sigOut, 0, sizeof(sigOut));
    TPM2_Packet_ParseSignature(&packet, &sigOut);
    AssertIntEQ(sigOut.sigAlg, TPM_ALG_HASH_MLDSA);
    AssertIntEQ(sigOut.signature.hash_mldsa.hash, TPM_ALG_SHA256);
    AssertIntEQ(sigOut.signature.hash_mldsa.signature.size, sizeof(sigBytes));
    AssertIntEQ(XMEMCMP(sigOut.signature.hash_mldsa.signature.buffer,
        sigBytes, sizeof(sigBytes)), 0);

    printf("Test TPM Wrapper: %-40s Passed\n", "Signature PQC serialize:");
}

/* Round-trip the v1.85 PQC arms of TPM2B_PUBLIC through the
 * TPM2_AppendPublic / TPM2_ParsePublic public marshalers. ML-DSA +
 * Hash-ML-DSA share the unique.mldsa arm (Part 2 Table 225 note);
 * ML-KEM has its own unique.mlkem arm. Verifies every round-tripped
 * field for the three key types. */
static void test_TPM2_Public_PQC_Roundtrip(void)
{
    int rc, sz;
    /* TPM2_AppendPublic requires the scratch buffer to hold a full
     * TPM2B_PUBLIC; the v1.85 struct grows to fit the largest PQC public
     * key (MLDSA-87 = 2592 bytes). */
    byte buf[sizeof(TPM2B_PUBLIC)];
    TPM2B_PUBLIC pubIn, pubOut;
    const byte uniqueBytes[8] = {
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22
    };

    /* ML-DSA-65 */
    XMEMSET(&pubIn, 0, sizeof(pubIn));
    pubIn.publicArea.type = TPM_ALG_MLDSA;
    pubIn.publicArea.nameAlg = TPM_ALG_SHA256;
    pubIn.publicArea.objectAttributes = TPMA_OBJECT_sign;
    pubIn.publicArea.parameters.mldsaDetail.parameterSet = TPM_MLDSA_65;
    pubIn.publicArea.parameters.mldsaDetail.allowExternalMu = NO;
    pubIn.publicArea.unique.mldsa.size = sizeof(uniqueBytes);
    XMEMCPY(pubIn.publicArea.unique.mldsa.buffer,
        uniqueBytes, sizeof(uniqueBytes));

    XMEMSET(buf, 0, sizeof(buf));
    sz = 0;
    rc = TPM2_AppendPublic(buf, (word32)sizeof(buf), &sz, &pubIn);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    AssertIntGT(sz, 0);

    XMEMSET(&pubOut, 0, sizeof(pubOut));
    rc = TPM2_ParsePublic(&pubOut, buf, (word32)sz, &sz);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    AssertIntEQ(pubOut.publicArea.type, TPM_ALG_MLDSA);
    AssertIntEQ(pubOut.publicArea.nameAlg, TPM_ALG_SHA256);
    AssertIntEQ(pubOut.publicArea.parameters.mldsaDetail.parameterSet,
        TPM_MLDSA_65);
    AssertIntEQ(pubOut.publicArea.parameters.mldsaDetail.allowExternalMu, NO);
    AssertIntEQ(pubOut.publicArea.unique.mldsa.size, sizeof(uniqueBytes));
    AssertIntEQ(XMEMCMP(pubOut.publicArea.unique.mldsa.buffer,
        uniqueBytes, sizeof(uniqueBytes)), 0);

    /* Hash-ML-DSA-65 with SHA-256 — shared unique.mldsa arm. */
    XMEMSET(&pubIn, 0, sizeof(pubIn));
    pubIn.publicArea.type = TPM_ALG_HASH_MLDSA;
    pubIn.publicArea.nameAlg = TPM_ALG_SHA256;
    pubIn.publicArea.objectAttributes = TPMA_OBJECT_sign;
    pubIn.publicArea.parameters.hash_mldsaDetail.parameterSet = TPM_MLDSA_65;
    pubIn.publicArea.parameters.hash_mldsaDetail.hashAlg = TPM_ALG_SHA256;
    pubIn.publicArea.unique.mldsa.size = sizeof(uniqueBytes);
    XMEMCPY(pubIn.publicArea.unique.mldsa.buffer,
        uniqueBytes, sizeof(uniqueBytes));

    XMEMSET(buf, 0, sizeof(buf));
    sz = 0;
    rc = TPM2_AppendPublic(buf, (word32)sizeof(buf), &sz, &pubIn);
    AssertIntEQ(rc, TPM_RC_SUCCESS);

    XMEMSET(&pubOut, 0, sizeof(pubOut));
    rc = TPM2_ParsePublic(&pubOut, buf, (word32)sz, &sz);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    AssertIntEQ(pubOut.publicArea.type, TPM_ALG_HASH_MLDSA);
    AssertIntEQ(pubOut.publicArea.parameters.hash_mldsaDetail.parameterSet,
        TPM_MLDSA_65);
    AssertIntEQ(pubOut.publicArea.parameters.hash_mldsaDetail.hashAlg,
        TPM_ALG_SHA256);
    AssertIntEQ(pubOut.publicArea.unique.mldsa.size, sizeof(uniqueBytes));
    AssertIntEQ(XMEMCMP(pubOut.publicArea.unique.mldsa.buffer,
        uniqueBytes, sizeof(uniqueBytes)), 0);

    /* ML-KEM-768 — unique.mlkem arm. */
    XMEMSET(&pubIn, 0, sizeof(pubIn));
    pubIn.publicArea.type = TPM_ALG_MLKEM;
    pubIn.publicArea.nameAlg = TPM_ALG_SHA256;
    pubIn.publicArea.objectAttributes = TPMA_OBJECT_decrypt;
    pubIn.publicArea.parameters.mlkemDetail.parameterSet = TPM_MLKEM_768;
    pubIn.publicArea.parameters.mlkemDetail.symmetric.algorithm = TPM_ALG_NULL;
    pubIn.publicArea.unique.mlkem.size = sizeof(uniqueBytes);
    XMEMCPY(pubIn.publicArea.unique.mlkem.buffer,
        uniqueBytes, sizeof(uniqueBytes));

    XMEMSET(buf, 0, sizeof(buf));
    sz = 0;
    rc = TPM2_AppendPublic(buf, (word32)sizeof(buf), &sz, &pubIn);
    AssertIntEQ(rc, TPM_RC_SUCCESS);

    XMEMSET(&pubOut, 0, sizeof(pubOut));
    rc = TPM2_ParsePublic(&pubOut, buf, (word32)sz, &sz);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    AssertIntEQ(pubOut.publicArea.type, TPM_ALG_MLKEM);
    AssertIntEQ(pubOut.publicArea.parameters.mlkemDetail.parameterSet,
        TPM_MLKEM_768);
    AssertIntEQ(pubOut.publicArea.unique.mlkem.size, sizeof(uniqueBytes));
    AssertIntEQ(XMEMCMP(pubOut.publicArea.unique.mlkem.buffer,
        uniqueBytes, sizeof(uniqueBytes)), 0);

    printf("Test TPM Wrapper: %-40s Passed\n", "Public PQC roundtrip:");
}
#endif /* WOLFTPM_PQC */

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

#ifdef WOLFTPM_PQC
    /* ML-DSA sensitive roundtrip — regression for missing PQC arm in
     * TPM2_Packet_ParseSensitive (would silently drop the private bytes
     * before the parse-side fix). */
    XMEMSET(&sensIn, 0, sizeof(sensIn));
    sensIn.sensitiveArea.sensitiveType = TPM_ALG_MLDSA;
    sensIn.sensitiveArea.sensitive.mldsa.size = sizeof(rsaPriv);
    XMEMCPY(sensIn.sensitiveArea.sensitive.mldsa.buffer, rsaPriv,
        sizeof(rsaPriv));

    XMEMSET(buf, 0, sizeof(buf));
    XMEMSET(&packet, 0, sizeof(packet));
    packet.buf = buf;
    packet.size = sizeof(buf);

    TPM2_Packet_AppendSensitive(&packet, &sensIn);

    packet.pos = 0;
    XMEMSET(&sensOut, 0, sizeof(sensOut));
    TPM2_Packet_ParseSensitive(&packet, &sensOut);

    AssertIntEQ(sensOut.sensitiveArea.sensitiveType, TPM_ALG_MLDSA);
    AssertIntEQ(sensOut.sensitiveArea.sensitive.mldsa.size, sizeof(rsaPriv));
    AssertIntEQ(XMEMCMP(sensOut.sensitiveArea.sensitive.mldsa.buffer,
        rsaPriv, sizeof(rsaPriv)), 0);

    /* HASH_MLDSA shares the .mldsa arm on the wire (TPM2B_PRIVATE_VENDOR_SPECIFIC
     * bounded by MAX_MLDSA_KEY_BYTES) — sensitiveType differs, layout matches. */
    XMEMSET(&sensIn, 0, sizeof(sensIn));
    sensIn.sensitiveArea.sensitiveType = TPM_ALG_HASH_MLDSA;
    sensIn.sensitiveArea.sensitive.mldsa.size = sizeof(rsaPriv);
    XMEMCPY(sensIn.sensitiveArea.sensitive.mldsa.buffer, rsaPriv,
        sizeof(rsaPriv));

    XMEMSET(buf, 0, sizeof(buf));
    XMEMSET(&packet, 0, sizeof(packet));
    packet.buf = buf;
    packet.size = sizeof(buf);

    TPM2_Packet_AppendSensitive(&packet, &sensIn);

    packet.pos = 0;
    XMEMSET(&sensOut, 0, sizeof(sensOut));
    TPM2_Packet_ParseSensitive(&packet, &sensOut);

    AssertIntEQ(sensOut.sensitiveArea.sensitiveType, TPM_ALG_HASH_MLDSA);
    AssertIntEQ(sensOut.sensitiveArea.sensitive.mldsa.size, sizeof(rsaPriv));
    AssertIntEQ(XMEMCMP(sensOut.sensitiveArea.sensitive.mldsa.buffer,
        rsaPriv, sizeof(rsaPriv)), 0);

    /* ML-KEM sensitive roundtrip. */
    XMEMSET(&sensIn, 0, sizeof(sensIn));
    sensIn.sensitiveArea.sensitiveType = TPM_ALG_MLKEM;
    sensIn.sensitiveArea.sensitive.mlkem.size = sizeof(rsaPriv);
    XMEMCPY(sensIn.sensitiveArea.sensitive.mlkem.buffer, rsaPriv,
        sizeof(rsaPriv));

    XMEMSET(buf, 0, sizeof(buf));
    XMEMSET(&packet, 0, sizeof(packet));
    packet.buf = buf;
    packet.size = sizeof(buf);

    TPM2_Packet_AppendSensitive(&packet, &sensIn);

    packet.pos = 0;
    XMEMSET(&sensOut, 0, sizeof(sensOut));
    TPM2_Packet_ParseSensitive(&packet, &sensOut);

    AssertIntEQ(sensOut.sensitiveArea.sensitiveType, TPM_ALG_MLKEM);
    AssertIntEQ(sensOut.sensitiveArea.sensitive.mlkem.size, sizeof(rsaPriv));
    AssertIntEQ(XMEMCMP(sensOut.sensitiveArea.sensitive.mlkem.buffer,
        rsaPriv, sizeof(rsaPriv)), 0);
#endif /* WOLFTPM_PQC */

    printf("Test TPM Wrapper: %-40s Passed\n", "Sensitive roundtrip:");
}

#ifdef WOLFTPM_SPDM
/* Pin the rxBuf bound in the SPDM I/O callbacks: a response larger than the
 * caller buffer must be rejected even when it fits the local I/O buffer. */
static void test_wolfTPM2_SPDM_ValidateRspSz(void)
{
    word32 ioBufSz = MAX_RESPONSE_SIZE;
    word32 rxSz = 256;

    AssertIntEQ(wolfTPM2_SPDM_ValidateRspSz(rxSz, rxSz, ioBufSz), 0);
    AssertIntEQ(wolfTPM2_SPDM_ValidateRspSz(rxSz + 1, rxSz, ioBufSz), -1);
    AssertIntEQ(wolfTPM2_SPDM_ValidateRspSz(ioBufSz + 1, ioBufSz, ioBufSz), -1);

    printf("Test TPM2:        %-40s Passed\n", "SPDM ValidateRspSz:");
}
#endif /* WOLFTPM_SPDM */

/* Pin the TIS response-size bounds so a mutation dropping the buffer-bound or
 * the MAX_RESPONSE_SIZE term is caught. */
static void test_TPM2_TIS_ValidateRspSz(void)
{
    int packetSize = 1024;

    AssertIntEQ(TPM2_TIS_ValidateRspSz(TPM2_HEADER_SIZE, packetSize),
        TPM_RC_SUCCESS);
    AssertIntEQ(TPM2_TIS_ValidateRspSz(packetSize, packetSize),
        TPM_RC_SUCCESS);

    AssertIntEQ(TPM2_TIS_ValidateRspSz(packetSize + 1, packetSize),
        TPM_RC_FAILURE);
    AssertIntEQ(TPM2_TIS_ValidateRspSz(MAX_RESPONSE_SIZE, MAX_RESPONSE_SIZE),
        TPM_RC_FAILURE);
    AssertIntEQ(TPM2_TIS_ValidateRspSz(-1, packetSize),
        TPM_RC_FAILURE);

    printf("Test TPM2:        %-40s Passed\n", "TIS ValidateRspSz:");
}

/* A zero-size TPM2B_PUBLIC must clear publicArea so stale fields from a reused
 * struct cannot survive a parse. */
static void test_TPM2_ParsePublic_EmptyClears(void)
{
    TPM2_Packet packet;
    byte buf[8];
    TPM2B_PUBLIC pub;

    XMEMSET(&pub, 0, sizeof(pub));
    pub.publicArea.type = TPM_ALG_RSA;
    pub.publicArea.nameAlg = TPM_ALG_SHA256;
    pub.publicArea.objectAttributes = 0xFFFFFFFFUL;

    XMEMSET(buf, 0, sizeof(buf));
    XMEMSET(&packet, 0, sizeof(packet));
    packet.buf = buf;
    packet.size = sizeof(buf);

    TPM2_Packet_ParsePublic(&packet, &pub);

    AssertIntEQ(pub.size, 0);
    AssertIntEQ(pub.publicArea.type, 0);
    AssertIntEQ(pub.publicArea.nameAlg, 0);
    AssertIntEQ(pub.publicArea.objectAttributes, 0);

    printf("Test TPM2:        %-40s Passed\n", "ParsePublic empty clears:");
}

/* An oversized inner size on a classic arm must be clamped to the arm buffer
 * size, matching the PQC arms, so AppendBytes does not over-read the source.
 * Each arm has its own buffer member so all four are exercised. */
static void test_TPM2_AppendSensitive_Clamp(void)
{
    TPM2_Packet packet;
    byte buf[1024];
    TPM2B_SENSITIVE sens;
    word16 rsaCap, eccCap, bitsCap, symCap;

    rsaCap = (word16)sizeof(sens.sensitiveArea.sensitive.rsa.buffer);
    eccCap = (word16)sizeof(sens.sensitiveArea.sensitive.ecc.buffer);
    bitsCap = (word16)sizeof(sens.sensitiveArea.sensitive.bits.buffer);
    symCap = (word16)sizeof(sens.sensitiveArea.sensitive.sym.buffer);

    XMEMSET(&sens, 0, sizeof(sens));
    sens.sensitiveArea.sensitiveType = TPM_ALG_RSA;
    sens.sensitiveArea.sensitive.rsa.size = rsaCap + 100;
    XMEMSET(&packet, 0, sizeof(packet));
    packet.buf = buf;
    packet.size = sizeof(buf);
    TPM2_Packet_AppendSensitive(&packet, &sens);
    AssertIntEQ(sens.sensitiveArea.sensitive.rsa.size, rsaCap);

    XMEMSET(&sens, 0, sizeof(sens));
    sens.sensitiveArea.sensitiveType = TPM_ALG_ECC;
    sens.sensitiveArea.sensitive.ecc.size = eccCap + 100;
    XMEMSET(&packet, 0, sizeof(packet));
    packet.buf = buf;
    packet.size = sizeof(buf);
    TPM2_Packet_AppendSensitive(&packet, &sens);
    AssertIntEQ(sens.sensitiveArea.sensitive.ecc.size, eccCap);

    XMEMSET(&sens, 0, sizeof(sens));
    sens.sensitiveArea.sensitiveType = TPM_ALG_KEYEDHASH;
    sens.sensitiveArea.sensitive.bits.size = bitsCap + 100;
    XMEMSET(&packet, 0, sizeof(packet));
    packet.buf = buf;
    packet.size = sizeof(buf);
    TPM2_Packet_AppendSensitive(&packet, &sens);
    AssertIntEQ(sens.sensitiveArea.sensitive.bits.size, bitsCap);

    XMEMSET(&sens, 0, sizeof(sens));
    sens.sensitiveArea.sensitiveType = TPM_ALG_SYMCIPHER;
    sens.sensitiveArea.sensitive.sym.size = symCap + 100;
    XMEMSET(&packet, 0, sizeof(packet));
    packet.buf = buf;
    packet.size = sizeof(buf);
    TPM2_Packet_AppendSensitive(&packet, &sens);
    AssertIntEQ(sens.sensitiveArea.sensitive.sym.size, symCap);

    printf("Test TPM2:        %-40s Passed\n", "AppendSensitive clamp:");
}

static void test_TPM2_AppendPublic_Clamp(void)
{
    TPM2_Packet packet;
    byte buf[sizeof(TPM2B_PUBLIC)];
    TPM2B_PUBLIC pub;
    word16 policyCap, rsaCap, eccCap, khCap, symCap;
#ifdef WOLFTPM_MLDSA
    word16 mldsaCap;
#endif
#ifdef WOLFTPM_MLKEM
    word16 mlkemCap;
#endif

    policyCap = (word16)sizeof(pub.publicArea.authPolicy.buffer);
    rsaCap = (word16)sizeof(pub.publicArea.unique.rsa.buffer);
    eccCap = (word16)sizeof(pub.publicArea.unique.ecc.x.buffer);
    khCap = (word16)sizeof(pub.publicArea.unique.keyedHash.buffer);
    symCap = (word16)sizeof(pub.publicArea.unique.sym.buffer);

    XMEMSET(&pub, 0, sizeof(pub));
    pub.publicArea.type = TPM_ALG_RSA;
    pub.publicArea.nameAlg = TPM_ALG_SHA256;
    pub.publicArea.authPolicy.size = policyCap + 100;
    pub.publicArea.unique.rsa.size = rsaCap + 100;
    XMEMSET(&packet, 0, sizeof(packet));
    packet.buf = buf;
    packet.size = sizeof(buf);
    TPM2_Packet_AppendPublic(&packet, &pub);
    AssertIntEQ(pub.publicArea.authPolicy.size, policyCap);
    AssertIntEQ(pub.publicArea.unique.rsa.size, rsaCap);

    /* ECC point x/y sizes must clamp on append too */
    XMEMSET(&pub, 0, sizeof(pub));
    pub.publicArea.type = TPM_ALG_ECC;
    pub.publicArea.nameAlg = TPM_ALG_SHA256;
    pub.publicArea.unique.ecc.x.size = eccCap + 100;
    pub.publicArea.unique.ecc.y.size = eccCap + 100;
    XMEMSET(&packet, 0, sizeof(packet));
    packet.buf = buf;
    packet.size = sizeof(buf);
    TPM2_Packet_AppendPublic(&packet, &pub);
    AssertIntEQ(pub.publicArea.unique.ecc.x.size, eccCap);
    AssertIntEQ(pub.publicArea.unique.ecc.y.size, eccCap);

    /* keyedHash unique size must clamp */
    XMEMSET(&pub, 0, sizeof(pub));
    pub.publicArea.type = TPM_ALG_KEYEDHASH;
    pub.publicArea.nameAlg = TPM_ALG_SHA256;
    pub.publicArea.unique.keyedHash.size = khCap + 100;
    XMEMSET(&packet, 0, sizeof(packet));
    packet.buf = buf;
    packet.size = sizeof(buf);
    TPM2_Packet_AppendPublic(&packet, &pub);
    AssertIntEQ(pub.publicArea.unique.keyedHash.size, khCap);

    /* symcipher unique size must clamp */
    XMEMSET(&pub, 0, sizeof(pub));
    pub.publicArea.type = TPM_ALG_SYMCIPHER;
    pub.publicArea.nameAlg = TPM_ALG_SHA256;
    pub.publicArea.unique.sym.size = symCap + 100;
    XMEMSET(&packet, 0, sizeof(packet));
    packet.buf = buf;
    packet.size = sizeof(buf);
    TPM2_Packet_AppendPublic(&packet, &pub);
    AssertIntEQ(pub.publicArea.unique.sym.size, symCap);

#ifdef WOLFTPM_MLDSA
    mldsaCap = (word16)sizeof(pub.publicArea.unique.mldsa.buffer);
    XMEMSET(&pub, 0, sizeof(pub));
    pub.publicArea.type = TPM_ALG_MLDSA;
    pub.publicArea.nameAlg = TPM_ALG_SHA256;
    pub.publicArea.unique.mldsa.size = mldsaCap + 100;
    XMEMSET(&packet, 0, sizeof(packet));
    packet.buf = buf;
    packet.size = sizeof(buf);
    TPM2_Packet_AppendPublic(&packet, &pub);
    AssertIntEQ(pub.publicArea.unique.mldsa.size, mldsaCap);
#endif
#ifdef WOLFTPM_MLKEM
    mlkemCap = (word16)sizeof(pub.publicArea.unique.mlkem.buffer);
    XMEMSET(&pub, 0, sizeof(pub));
    pub.publicArea.type = TPM_ALG_MLKEM;
    pub.publicArea.nameAlg = TPM_ALG_SHA256;
    pub.publicArea.unique.mlkem.size = mlkemCap + 100;
    XMEMSET(&packet, 0, sizeof(packet));
    packet.buf = buf;
    packet.size = sizeof(buf);
    TPM2_Packet_AppendPublic(&packet, &pub);
    AssertIntEQ(pub.publicArea.unique.mlkem.size, mlkemCap);
#endif

    printf("Test TPM2:        %-40s Passed\n", "AppendPublic clamp:");
}

/* Roundtrip a maximum-size inner payload (size == buffer capacity) so the
 * parse-side ParseU16Buf clamp branch is exercised with valid data. */
static void test_TPM2_Sensitive_MaxRoundtrip(void)
{
    TPM2_Packet packet;
    byte buf[1024];
    TPM2B_SENSITIVE sensIn, sensOut;
    word16 cap, i;

    XMEMSET(&sensIn, 0, sizeof(sensIn));
    sensIn.sensitiveArea.sensitiveType = TPM_ALG_RSA;
    cap = (word16)sizeof(sensIn.sensitiveArea.sensitive.rsa.buffer);
    sensIn.sensitiveArea.sensitive.rsa.size = cap;
    for (i = 0; i < cap; i++) {
        sensIn.sensitiveArea.sensitive.rsa.buffer[i] = (byte)(i & 0xFF);
    }

    XMEMSET(buf, 0, sizeof(buf));
    XMEMSET(&packet, 0, sizeof(packet));
    packet.buf = buf;
    packet.size = sizeof(buf);

    TPM2_Packet_AppendSensitive(&packet, &sensIn);

    packet.pos = 0;
    XMEMSET(&sensOut, 0, sizeof(sensOut));
    TPM2_Packet_ParseSensitive(&packet, &sensOut);

    AssertIntEQ(sensOut.sensitiveArea.sensitiveType, TPM_ALG_RSA);
    AssertIntEQ(sensOut.sensitiveArea.sensitive.rsa.size, cap);
    AssertIntEQ(XMEMCMP(sensOut.sensitiveArea.sensitive.rsa.buffer,
        sensIn.sensitiveArea.sensitive.rsa.buffer, cap), 0);

    printf("Test TPM2:        %-40s Passed\n", "Sensitive max roundtrip:");
}

static void test_KeySealTemplate(void)
{
    int rc;
    TPMT_PUBLIC tmpl;

    rc = wolfTPM2_GetKeyTemplate_KeySeal(&tmpl, TPM_ALG_SHA256);
    AssertIntEQ(rc, TPM_RC_SUCCESS);

    /* Template must include userWithAuth so password-based unseal works */
    AssertIntNE(tmpl.objectAttributes & TPMA_OBJECT_userWithAuth, 0);

    printf("Test TPM Wrapper: %-40s Passed\n", "KeySealTemplate:");
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

    printf("Test TPM Wrapper: %-40s Passed\n", "SealKeyedHash Boundary:");
}

static void test_GetAlgId(void)
{
    AssertIntEQ(TPM2_GetAlgId("SHA256"), TPM_ALG_SHA256);
    AssertIntEQ(TPM2_GetAlgId("SHA3_256"), TPM_ALG_SHA3_256);
    AssertIntEQ(TPM2_GetAlgId("SHA3_384"), TPM_ALG_SHA3_384);
    AssertIntEQ(TPM2_GetAlgId("SHA3_512"), TPM_ALG_SHA3_512);
#ifdef WOLFTPM_PQC
    AssertIntEQ(TPM2_GetAlgId("ML-KEM"), TPM_ALG_MLKEM);
    AssertIntEQ(TPM2_GetAlgId("ML-DSA"), TPM_ALG_MLDSA);
    AssertIntEQ(TPM2_GetAlgId("HashML-DSA"), TPM_ALG_HASH_MLDSA);
#endif
    AssertIntEQ(TPM2_GetAlgId("not_a_real_alg"), TPM_ALG_ERROR);
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

    printf("Test TPM Wrapper: %-40s %s\n", "CSR Subject:",
        rc == 0 ? "Passed" : "Failed");
#endif
}

static void test_wolfTPM2_CryptoDevCb_EccVerifyOversizedRS(void)
{
#if !defined(WOLFTPM2_NO_WRAPPER) && defined(WOLFTPM_CRYPTOCB) && \
    !defined(WOLFTPM2_NO_WOLFCRYPT) && defined(HAVE_ECC) && \
    defined(HAVE_ECC_VERIFY) && !defined(WC_NO_RNG) && (MAX_ECC_BYTES > 32)
    int rc;
    int i;
    int c, rLen, sLen;
    int verifyRes = 0;
    WOLFTPM2_DEV dev;
    TpmCryptoDevCtx tpmCtx;
    wc_CryptoInfo info;
    ecc_key key;
    byte digest[32];
    byte sig[128];
    word32 sigSz;

    XMEMSET(digest, 0x33, sizeof(digest));
    XMEMSET(&tpmCtx, 0, sizeof(tpmCtx));

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, NULL);
    AssertIntEQ(rc, 0);
    tpmCtx.dev = &dev;

    rc = wc_ecc_init(&key);
    AssertIntEQ(rc, 0);
    rc = wc_ecc_make_key_ex(wolfTPM2_GetRng(&dev), 32, &key, ECC_SECP256R1);
    AssertIntEQ(rc, 0);

    /* c==0 drives the oversized-R guard, c==1 the oversized-S guard; both
     * exceed the P-256 key size and must fall back before the TPM key load */
    for (c = 0; c < 2; c++) {
        rLen = (c == 0) ? 40 : 32;
        sLen = (c == 0) ? 32 : 40;

        sigSz = 0;
        sig[sigSz++] = 0x30;
        sig[sigSz++] = (byte)(2 + rLen + 2 + sLen);
        sig[sigSz++] = 0x02;
        sig[sigSz++] = (byte)rLen;
        for (i = 0; i < rLen; i++)
            sig[sigSz++] = 0x11;
        sig[sigSz++] = 0x02;
        sig[sigSz++] = (byte)sLen;
        for (i = 0; i < sLen; i++)
            sig[sigSz++] = 0x22;

        XMEMSET(&info, 0, sizeof(info));
        info.algo_type = WC_ALGO_TYPE_PK;
        info.pk.type = WC_PK_TYPE_ECDSA_VERIFY;
        info.pk.eccverify.sig = sig;
        info.pk.eccverify.siglen = sigSz;
        info.pk.eccverify.hash = digest;
        info.pk.eccverify.hashlen = (word32)sizeof(digest);
        info.pk.eccverify.res = &verifyRes;
        info.pk.eccverify.key = &key;

        rc = wolfTPM2_CryptoDevCb(INVALID_DEVID, &info, &tpmCtx);
        AssertIntEQ(rc, CRYPTOCB_UNAVAILABLE);
    }

    wc_ecc_free(&key);
    wolfTPM2_Cleanup(&dev);

    printf("Test TPM Wrapper: %-40s Passed\n", "CryptoDevCb ECC oversized R/S:");
#endif
}

static void test_TPM2_ASN_DecodeX509Cert_Errors(void)
{
#if !defined(WOLFTPM2_NO_WRAPPER) && !defined(WOLFTPM2_NO_ASN)
    int rc;
    DecodedX509 x509;
    byte garbage[16];
    byte trunc[4];

    XMEMSET(&x509, 0, sizeof(x509));
    XMEMSET(garbage, 0xFF, sizeof(garbage));

    /* NULL arguments must be rejected, not dereferenced */
    rc = TPM2_ASN_DecodeX509Cert(NULL, 0, &x509);
    AssertIntNE(rc, 0);
    rc = TPM2_ASN_DecodeX509Cert(garbage, (int)sizeof(garbage), NULL);
    AssertIntNE(rc, 0);

    /* malformed input must not report success */
    rc = TPM2_ASN_DecodeX509Cert(garbage, (int)sizeof(garbage), &x509);
    AssertIntNE(rc, 0);

    /* outer SEQUENCE whose length runs past the buffer (TPM_RC_INSUFFICIENT) */
    trunc[0] = 0x30; trunc[1] = 0x20; trunc[2] = 0x00; trunc[3] = 0x00;
    rc = TPM2_ASN_DecodeX509Cert(trunc, (int)sizeof(trunc), &x509);
    AssertIntNE(rc, 0);

    printf("Test TPM Wrapper: %-40s Passed\n", "ASN DecodeX509Cert errors:");
#endif
}

#if !defined(WOLFTPM2_NO_WRAPPER) && !defined(WOLFTPM2_NO_ASN)
#include <examples/endorsement/trusted_certs_der.h>
#endif
static void test_TPM2_ASN_DecodeX509Cert_Valid(void)
{
#if !defined(WOLFTPM2_NO_WRAPPER) && !defined(WOLFTPM2_NO_ASN)
    int rc;
    DecodedX509 x509;

    /* a well-formed DER certificate must decode and populate the fields */
    XMEMSET(&x509, 0, sizeof(x509));
    rc = TPM2_ASN_DecodeX509Cert((uint8_t*)kSTSAFEIntCa20,
        (int)sizeof(kSTSAFEIntCa20), &x509);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    AssertIntGT(x509.certSz, 0);
    AssertNotNull(x509.publicKey);
    AssertIntGT(x509.pubKeySz, 0);
    AssertNotNull(x509.signature);
    AssertIntGT(x509.sigSz, 0);

    printf("Test TPM Wrapper: %-40s Passed\n", "ASN DecodeX509Cert valid:");
#endif
}

static void test_TPM2_ASN_DecodeTag_Errors(void)
{
#if !defined(WOLFTPM2_NO_WRAPPER) && !defined(WOLFTPM2_NO_ASN)
    int rc, idx, tagLen;
    byte buf[4];

    buf[0] = 0x30; buf[1] = 0x02; buf[2] = 0x00; buf[3] = 0x00;

    idx = 0;
    rc = TPM2_ASN_DecodeTag(buf, (int)sizeof(buf), &idx, &tagLen, 0x30);
    AssertIntEQ(rc, 0);

    /* wrong expected tag must be reported, not accepted as success */
    idx = 0;
    rc = TPM2_ASN_DecodeTag(buf, (int)sizeof(buf), &idx, &tagLen, 0x02);
    AssertIntNE(rc, 0);

    printf("Test TPM Wrapper: %-40s Passed\n", "ASN DecodeTag tag mismatch:");
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
    char nameBuf[48];
#ifdef WOLF_CRYPTO_CB
    TpmCryptoDevCtx tpmCtx;
    byte badDigest[TPM_MAX_DIGEST_SIZE];

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
        goto exit;
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
        goto exit;
    }
    if ((rc & TPM_RC_CURVE) == TPM_RC_CURVE) {
        printf("Curve not supported... Skipping\n");
        goto exit;
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

#ifdef WOLF_CRYPTO_CB
    /* Drive the invalid-signature branch of the crypto callback: a tampered
     * digest must return verifyRes == 0 with rc == 0 */
    if (flags & FLAGS_USE_CRYPTO_CB) {
        XMEMCPY(badDigest, digest, digestSz);
        badDigest[0] ^= 0xFF;
        verifyRes = 1;
        rc = wc_ecc_verify_hash(sig, sigSz, badDigest, digestSz, &verifyRes,
            &wolfKey);
        AssertIntEQ(rc, 0);
        AssertIntEQ(verifyRes, 0);
    }
#endif

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

    XSNPRINTF(nameBuf, sizeof(nameBuf), "Sign/Verify Dig=%d Curve=%d %s%s:",
        digestSz, TPM2_GetCurveSize(curve), TPM2_GetAlgName(hashAlg),
        (flags & FLAGS_USE_CRYPTO_CB) ? " CCB" : "");
    printf("Test TPM Wrapper: %-40s %s\n", nameBuf,
        rc == 0 ? "Passed" : "Failed");

exit:
#ifdef WOLF_CRYPTO_CB
    /* Unregister on every path (incl. skips) so a leaked registration does
     * not make the next SetCryptoDevCb return ALREADY_E on wolfSSL 5.9.2+. */
    if (flags & FLAGS_USE_CRYPTO_CB) {
        wolfTPM2_ClearCryptoDevCb(dev, tpmDevId);
    }
#endif
    (void)tpmDevId;
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

/* Returns 1 if the connected TPM has at least one PCR allocated in the @alg
 * bank. Lets bank-specific tests adapt to whatever the hardware exposes
 * instead of assuming a fixed bank (e.g. a TPM provisioned with SHA-384 PCRs
 * only). */
static int test_pcr_bank_allocated(TPM_ALG_ID alg)
{
    GetCapability_In in;
    GetCapability_Out out;
    TPML_PCR_SELECTION* sel;
    word32 i;
    int j;

    XMEMSET(&in, 0, sizeof(in));
    XMEMSET(&out, 0, sizeof(out));
    in.capability = TPM_CAP_PCRS;
    in.property = 0;
    in.propertyCount = 1;
    if (TPM2_GetCapability(&in, &out) != TPM_RC_SUCCESS)
        return 0;

    sel = &out.capabilityData.data.assignedPCR;
    for (i = 0; i < sel->count; i++) {
        if (sel->pcrSelections[i].hash == alg) {
            for (j = 0; j < sel->pcrSelections[i].sizeofSelect; j++) {
                if (sel->pcrSelections[i].pcrSelect[j] != 0)
                    return 1;
            }
        }
    }
    return 0;
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

    /* The remaining checks use fixed SHA-256 PCR vectors. A TPM without a
     * SHA-256 PCR bank allocated cannot match them, so skip that portion
     * rather than fail (the policy-authorize math above still runs). */
    if (!test_pcr_bank_allocated(pcrAlg)) {
        printf("Test TPM Wrapper: %-40s Skipped (no SHA-256 PCR bank)\n",
            "PCRPolicy bank:");
        wolfTPM2_Cleanup(&dev);
        return;
    }

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
            printf("Test TPM Wrapper: %-40s Failed\n", "Thread Local Storage:");
        else
            printf("Test TPM Wrapper: %-40s Passed\n", "Thread Local Storage:");
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
    TPM2_AUTH_SESSION nationsOrigSess;
#endif

    /* Initialize device */
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, NULL);
    if (rc != 0) {
        printf("Test TPM Wrapper: %-40s Failed (Init 0x%x)\n",
            "SPDM Functions:", rc);
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
    dev.session[0].sessionHandle = HMAC_SESSION_FIRST;
    dev.session[0].sessionAttributes = 0x27;
    dev.session[0].auth.size = 4;
    XMEMCPY(dev.session[0].auth.buffer, "\x01\x02\x03\x04", 4);
    XMEMCPY(&nationsOrigSess, &dev.session[0], sizeof(nationsOrigSess));

    /* May fail (no Nations HW) but must restore session[0] */
    (void)wolfTPM2_SpdmNationsIdentityKeySet(&dev, 1);
    AssertIntEQ(dev.session[0].sessionHandle, nationsOrigSess.sessionHandle);
    AssertIntEQ(dev.session[0].sessionAttributes,
        nationsOrigSess.sessionAttributes);
    AssertIntEQ(dev.session[0].auth.size, nationsOrigSess.auth.size);
#endif /* WOLFSPDM_NATIONS */

    wolfTPM2_Cleanup(&dev);

    printf("Test TPM Wrapper: %-40s Passed\n", "SPDM Functions:");
}
#endif /* WOLFTPM_SPDM */

#ifdef WOLFTPM_SWTPM
/* Pin the swtpm response-size bounds so a mutation dropping either the
 * lower (header) or upper (buffer) bound is caught. */
static void test_TPM2_SwtpmValidateRspSz(void)
{
    int packetSize = 4096;

    AssertIntEQ(TPM2_SwtpmValidateRspSz(packetSize, TPM2_HEADER_SIZE),
        TPM_RC_SUCCESS);
    AssertIntEQ(TPM2_SwtpmValidateRspSz(packetSize, (uint32_t)packetSize),
        TPM_RC_SUCCESS);

    AssertIntEQ(TPM2_SwtpmValidateRspSz(packetSize, TPM2_HEADER_SIZE - 1),
        TPM_RC_FAILURE);
    AssertIntEQ(TPM2_SwtpmValidateRspSz(packetSize, (uint32_t)packetSize + 1),
        TPM_RC_FAILURE);
    AssertIntEQ(TPM2_SwtpmValidateRspSz(packetSize, 0xFFFFFFFFUL),
        TPM_RC_FAILURE);

    printf("Test TPM2:        %-40s Passed\n", "Swtpm ValidateRspSz:");
}
#endif /* WOLFTPM_SWTPM */

#if !defined(NO_FILESYSTEM) && !defined(NO_WRITE_TEMP_FILES) && \
    !defined(WOLFTPM2_NO_WOLFCRYPT) && defined(HAVE_ECC)
/* Create a temp file for writing with owner-only permissions, so the test
 * does not leave a world-writable file as plain fopen("wb") would. */
static XFILE openTestFileWrite(const char* fn)
{
#if defined(__linux__) || defined(__APPLE__) || defined(__unix__)
    int fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        return XBADFILE;
    }
    return fdopen(fd, "wb");
#else
    return XFOPEN(fn, "wb");
#endif
}

/* Craft a key-blob file with a small valid public area and an oversized
 * private tail, then load it with readKeyBlob(). A canary placed directly
 * after the keyblob catches any write past it. No TPM is required. */
static void test_readKeyBlob_PrivOverflow(void)
{
    int rc;
    int pubAreaSize = 0;
    word32 i;
    size_t privTailSz, remaining, chunk;
    UINT16 privSizeMarker;
    UINT16 bigMarker;
    XFILE fp;
    byte pubAreaBuffer[sizeof(TPM2B_PUBLIC)];
    byte filler[64];
    WOLFTPM2_KEYBLOB tmpl;
    const char* filename = "keyblob_overflow_test.raw";
    struct {
        WOLFTPM2_KEYBLOB key;
        byte canary[128];
    } guarded;

    XMEMSET(&tmpl, 0, sizeof(tmpl));

    /* Build a real minimal public area so TPM2_ParsePublic() accepts it and
     * readKeyBlob proceeds to the private read. */
    rc = wolfTPM2_GetKeyTemplate_ECC(&tmpl.pub.publicArea,
        TPMA_OBJECT_sign | TPMA_OBJECT_userWithAuth | TPMA_OBJECT_noDA,
        TPM_ECC_NIST_P256, TPM_ALG_ECDSA);
    AssertIntEQ(rc, 0);
    rc = TPM2_AppendPublic(pubAreaBuffer, (word32)sizeof(pubAreaBuffer),
        &pubAreaSize, &tmpl.pub);
    AssertIntEQ(rc, 0);

    /* Private tail longer than the destination so the pre-fix path, which
     * reads the whole remaining file into &key->priv, overflows past the
     * keyblob. Keep the size marker small and valid so the post-read sanity
     * check passes. */
    privTailSz = sizeof(guarded.key.priv) + sizeof(filler);
    privSizeMarker = 32;

    fp = openTestFileWrite(filename);
    AssertNotNull(fp);
    XFWRITE(&tmpl.pub.size, 1, sizeof(tmpl.pub.size), fp);
    XFWRITE(pubAreaBuffer, 1, sizeof(UINT16) + tmpl.pub.size, fp);
    XFWRITE(&privSizeMarker, 1, sizeof(privSizeMarker), fp);
    XMEMSET(filler, 0xAB, sizeof(filler));
    remaining = privTailSz - sizeof(privSizeMarker);
    while (remaining > 0) {
        chunk = (remaining < sizeof(filler)) ? remaining : sizeof(filler);
        XFWRITE(filler, 1, chunk, fp);
        remaining -= chunk;
    }
    XFCLOSE(fp);

    XMEMSET(&guarded, 0, sizeof(guarded));
    XMEMSET(guarded.canary, 0x5A, sizeof(guarded.canary));

    rc = readKeyBlob(filename, &guarded.key);
    (void)rc;

    for (i = 0; i < sizeof(guarded.canary); i++) {
        AssertIntEQ(guarded.canary[i], 0x5A);
    }

    remove(filename);

    /* Rejection branch: priv.size marker larger than the destination buffer
     * must be refused with BUFFER_E before any bytes are read. */
    bigMarker = (UINT16)(sizeof(guarded.key.priv.buffer) + 1);
    fp = openTestFileWrite(filename);
    AssertNotNull(fp);
    XFWRITE(&tmpl.pub.size, 1, sizeof(tmpl.pub.size), fp);
    XFWRITE(pubAreaBuffer, 1, sizeof(UINT16) + tmpl.pub.size, fp);
    XFWRITE(&bigMarker, 1, sizeof(bigMarker), fp);
    XFCLOSE(fp);
    XMEMSET(&guarded, 0, sizeof(guarded));
    rc = readKeyBlob(filename, &guarded.key);
    AssertIntEQ(rc, BUFFER_E);
    remove(filename);

    /* Rejection branch: pub.size marker larger than the public area buffer. */
    bigMarker = (UINT16)sizeof(pubAreaBuffer);
    fp = openTestFileWrite(filename);
    AssertNotNull(fp);
    XFWRITE(&bigMarker, 1, sizeof(bigMarker), fp);
    XFCLOSE(fp);
    XMEMSET(&guarded, 0, sizeof(guarded));
    rc = readKeyBlob(filename, &guarded.key);
    AssertIntEQ(rc, BUFFER_E);
    remove(filename);

    printf("Test TPM Wrapper: %-40s Passed\n", "readKeyBlob priv overflow:");
}
#endif

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
    char nameBuf[32];

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

    snprintf(nameBuf, sizeof(nameBuf), "KeyBlob %s:", TPM2_GetAlgName(alg));
    printf("Test TPM Wrapper: %-40s %s\n", nameBuf,
        rc == 0 ? "Passed" : "Failed");
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

    printf("Test TPM Wrapper: %-40s Passed\n", "DecodeDer DefaultAttribs:");
}

/* Verify the AES wrap-key strength selected by wolfTPM2_DecodeRsaDer /
 * wolfTPM2_DecodeEccDer scales with the imported parent's strength: 2048-bit
 * RSA / P-256 -> AES-128, 3072-bit RSA / P-384 -> AES-256. */
static void test_wolfTPM2_DecodeDer_WrapKeyScaling(void)
{
#if defined(HAVE_ECC) && defined(WOLFSSL_KEY_GEN) && \
    !defined(WC_NO_RNG)
    int rc;
    WC_RNG rng;
    ecc_key eccKey;
    byte derBuf[1024];
    int derSz;
    TPM2B_PUBLIC pub;
    const TPMA_OBJECT restrictedDecrypt =
        TPMA_OBJECT_restricted | TPMA_OBJECT_decrypt;
#if !defined(NO_RSA)
    RsaKey rsaKey;
    byte rsaDer[2048];
    int rsaDerSz;
#endif

    AssertIntEQ(wc_InitRng(&rng), 0);

    /* P-256 -> AES-128 */
    AssertIntEQ(wc_ecc_init(&eccKey), 0);
    AssertIntEQ(wc_ecc_make_key_ex(&rng, 32, &eccKey, ECC_SECP256R1), 0);
    derSz = wc_EccKeyToDer(&eccKey, derBuf, (word32)sizeof(derBuf));
    AssertIntGT(derSz, 0);
    XMEMSET(&pub, 0, sizeof(pub));
    rc = wolfTPM2_DecodeEccDer(derBuf, (word32)derSz, &pub, NULL,
        restrictedDecrypt);
    AssertIntEQ(rc, 0);
    AssertIntEQ(pub.publicArea.parameters.eccDetail.symmetric.algorithm,
        TPM_ALG_AES);
    AssertIntEQ(pub.publicArea.parameters.eccDetail.symmetric.keyBits.aes,
        128);
    wc_ecc_free(&eccKey);

    /* P-384 -> AES-256 */
    AssertIntEQ(wc_ecc_init(&eccKey), 0);
    AssertIntEQ(wc_ecc_make_key_ex(&rng, 48, &eccKey, ECC_SECP384R1), 0);
    derSz = wc_EccKeyToDer(&eccKey, derBuf, (word32)sizeof(derBuf));
    AssertIntGT(derSz, 0);
    XMEMSET(&pub, 0, sizeof(pub));
    rc = wolfTPM2_DecodeEccDer(derBuf, (word32)derSz, &pub, NULL,
        restrictedDecrypt);
    AssertIntEQ(rc, 0);
    AssertIntEQ(pub.publicArea.parameters.eccDetail.symmetric.algorithm,
        TPM_ALG_AES);
    AssertIntEQ(pub.publicArea.parameters.eccDetail.symmetric.keyBits.aes,
        256);
    wc_ecc_free(&eccKey);

#if !defined(NO_RSA)
    /* 2048-bit RSA -> AES-128 */
    AssertIntEQ(wc_InitRsaKey(&rsaKey, NULL), 0);
    AssertIntEQ(wc_MakeRsaKey(&rsaKey, 2048, WC_RSA_EXPONENT, &rng), 0);
    rsaDerSz = wc_RsaKeyToDer(&rsaKey, rsaDer, (word32)sizeof(rsaDer));
    AssertIntGT(rsaDerSz, 0);
    XMEMSET(&pub, 0, sizeof(pub));
    rc = wolfTPM2_DecodeRsaDer(rsaDer, (word32)rsaDerSz, &pub, NULL,
        restrictedDecrypt);
    AssertIntEQ(rc, 0);
    AssertIntEQ(pub.publicArea.parameters.rsaDetail.symmetric.algorithm,
        TPM_ALG_AES);
    AssertIntEQ(pub.publicArea.parameters.rsaDetail.symmetric.keyBits.aes,
        128);
    wc_FreeRsaKey(&rsaKey);

    /* 3072-bit RSA -> AES-256 */
    AssertIntEQ(wc_InitRsaKey(&rsaKey, NULL), 0);
    AssertIntEQ(wc_MakeRsaKey(&rsaKey, 3072, WC_RSA_EXPONENT, &rng), 0);
    rsaDerSz = wc_RsaKeyToDer(&rsaKey, rsaDer, (word32)sizeof(rsaDer));
    AssertIntGT(rsaDerSz, 0);
    XMEMSET(&pub, 0, sizeof(pub));
    rc = wolfTPM2_DecodeRsaDer(rsaDer, (word32)rsaDerSz, &pub, NULL,
        restrictedDecrypt);
    AssertIntEQ(rc, 0);
    AssertIntEQ(pub.publicArea.parameters.rsaDetail.symmetric.algorithm,
        TPM_ALG_AES);
    AssertIntEQ(pub.publicArea.parameters.rsaDetail.symmetric.keyBits.aes,
        256);
    wc_FreeRsaKey(&rsaKey);
#endif /* !NO_RSA */

    wc_FreeRng(&rng);
    printf("Test TPM Wrapper: %-40s Passed\n", "DecodeDer WrapKeyScaling:");
#endif /* HAVE_ECC && WOLFSSL_KEY_GEN && !WC_NO_RNG */
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

    printf("Test TPM Wrapper: %-40s Passed\n", "LoadPrivateKey NullParent:");
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

    /* CBC mode: non-block-aligned inOutSz must return BAD_FUNC_ARG. */
    key.pub.publicArea.parameters.symDetail.sym.mode.aes = TPM_ALG_CBC;
    rc = wolfTPM2_EncryptDecryptBlock(&dev, &key, in, out,
        MAX_AES_BLOCK_SIZE_BYTES - 1, iv, sizeof(iv), WOLFTPM2_ENCRYPT);
    AssertIntEQ(rc, BAD_FUNC_ARG);

    /* ECB mode: non-block-aligned inOutSz must return BAD_FUNC_ARG. */
    key.pub.publicArea.parameters.symDetail.sym.mode.aes = TPM_ALG_ECB;
    rc = wolfTPM2_EncryptDecryptBlock(&dev, &key, in, out,
        MAX_AES_BLOCK_SIZE_BYTES + 1, NULL, 0, WOLFTPM2_ENCRYPT);
    AssertIntEQ(rc, BAD_FUNC_ARG);

    /* CFB mode: non-block-aligned inOutSz is a stream length and must
     * bypass the block-alignment gate (so the return must not be the
     * BAD_FUNC_ARG produced by the alignment check). */
    key.pub.publicArea.parameters.symDetail.sym.mode.aes = TPM_ALG_CFB;
    rc = wolfTPM2_EncryptDecryptBlock(&dev, &key, in, out,
        MAX_AES_BLOCK_SIZE_BYTES - 1, iv, sizeof(iv), WOLFTPM2_ENCRYPT);
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

/* These PQC unit tests call both ML-DSA and ML-KEM wrappers, so they compile
 * only when both families are present (a WOLFTPM_NO_MLDSA or WOLFTPM_NO_MLKEM
 * build excludes the matching wrapper definitions). CI always builds full
 * PQC, so coverage is unchanged there. */
#if defined(WOLFTPM_MLDSA) && defined(WOLFTPM_MLKEM)
/* Post-Quantum Cryptography (PQC) Unit Tests - TPM 2.0 v185 */

/* TODO: Remove TPM_RC_COMMAND_CODE skip logic once we have a TPM simulator
 * or hardware that supports TPM 2.0 v1.85 PQC commands. Currently the IBM SW
 * TPM does not support ML-DSA/ML-KEM, so tests skip with TPM_RC_COMMAND_CODE.
 * When real support is available, update tests to require success. */

/* Test ML-DSA Sign Sequence (Start, Update, Complete) */
/* Test ML-DSA Sign Sequence; writes sig to caller buffer on success. */
static void test_wolfTPM2_MLDSA_SignSequence(WOLFTPM2_DEV* dev,
    WOLFTPM2_KEY* mldsaKey, const byte* message, int messageSz,
    byte* sig, int* sigSz)
{
    int rc;
    TPM_HANDLE sequenceHandle;
    byte context[16];
    int contextSz = 0;

    XMEMSET(context, 0, sizeof(context));

    rc = wolfTPM2_SignSequenceStart(dev, mldsaKey, context, contextSz,
        &sequenceHandle);
    if (rc == TPM_RC_VALUE || rc == TPM_RC_SCHEME ||
        rc == TPM_RC_COMMAND_CODE || rc == (int)(RC_VER1 + 0x043)) {
        printf("Test TPM Wrapper: %-40s Skipped (not supported)\n",
            "ML-DSA Sign Sequence:");
        *sigSz = 0;
        return;
    }
    AssertIntEQ(rc, 0);

    /* Pure-MLDSA rejects SequenceUpdate (Sec.17.5 TPM_RC_ONE_SHOT_SIGNATURE)
     * — the message must be supplied in one shot at Complete. */
    rc = wolfTPM2_SignSequenceComplete(dev, sequenceHandle, mldsaKey,
        message, messageSz, sig, sigSz);
    AssertIntEQ(rc, 0);
    AssertIntGT(*sigSz, 0);

    printf("Test TPM Wrapper: %-40s Passed\n", "ML-DSA Sign Sequence:");
}

/* Test ML-DSA Verify Sequence (Start, Update, Complete) */
static void test_wolfTPM2_MLDSA_VerifySequence(WOLFTPM2_DEV* dev,
    WOLFTPM2_KEY* mldsaKey, const byte* message, int messageSz,
    const byte* sig, int sigSz)
{
    int rc;
    TPM_HANDLE sequenceHandle;

    TPMT_TK_VERIFIED validation;

    XMEMSET(&validation, 0, sizeof(validation));

    if (sigSz <= 0) {
        printf("Test TPM Wrapper: %-40s Skipped (no signature)\n",
            "ML-DSA Verify Sequence:");
        return;
    }
    rc = wolfTPM2_VerifySequenceStart(dev, mldsaKey, NULL, 0, &sequenceHandle);
    if (rc == TPM_RC_VALUE || rc == TPM_RC_SCHEME ||
        rc == TPM_RC_COMMAND_CODE || rc == (int)(RC_VER1 + 0x043)) {
        printf("Test TPM Wrapper: %-40s Skipped (not supported)\n",
            "ML-DSA Verify Sequence:");
        return;
    }
    AssertIntEQ(rc, 0);

    /* Verify sequences accept SequenceUpdate per Part 3 Sec.20.3 */
    rc = wolfTPM2_VerifySequenceUpdate(dev, sequenceHandle, message, messageSz);
    AssertIntEQ(rc, 0);

    rc = wolfTPM2_VerifySequenceComplete(dev, sequenceHandle, mldsaKey,
        NULL, 0, sig, sigSz, &validation);
    AssertIntEQ(rc, 0);

    printf("Test TPM Wrapper: %-40s Passed\n", "ML-DSA Verify Sequence:");
}

/* Regression for the SignSequenceComplete slot-1 auth fix.
 * Creates a separate ML-DSA-65 primary with a NON-EMPTY user auth and runs
 * a sign sequence end-to-end. The wrapper now sets both auth slots
 * (slot 0 = sequence handle, slot 1 = key handle); if a future change drops
 * the slot-1 SetAuthHandle call, the TPM rejects Complete with TPM_RC_BAD_AUTH. */
static void test_wolfTPM2_MLDSA_SignSequence_NonEmptyAuth(WOLFTPM2_DEV* dev,
    const TPMT_PUBLIC* mldsaPub)
{
    int rc;
    WOLFTPM2_KEY key;
    TPMT_PUBLIC pub;
    static const byte gAuth[] = { 'p','q','c','_','a','u','t','h' };
    byte sig[5000];
    int sigSz = (int)sizeof(sig);
    static const byte gMsg[] = "Auth-bearing ML-DSA test message";
    int msgSz = (int)sizeof(gMsg) - 1;

    XMEMSET(&key, 0, sizeof(key));
    XMEMCPY(&pub, mldsaPub, sizeof(pub));

    rc = wolfTPM2_CreatePrimaryKey(dev, &key, TPM_RH_OWNER, &pub,
        gAuth, (int)sizeof(gAuth));
    if (rc == TPM_RC_VALUE || rc == TPM_RC_SCHEME ||
            rc == TPM_RC_COMMAND_CODE || rc == (int)(RC_VER1 + 0x043)) {
        printf("Test TPM Wrapper: %-40s Skipped (not supported)\n",
            "ML-DSA Sign Seq w/ key auth:");
        return;
    }
    AssertIntEQ(rc, 0);

    test_wolfTPM2_MLDSA_SignSequence(dev, &key, gMsg, msgSz, sig, &sigSz);

    wolfTPM2_UnloadHandle(dev, &key.handle);
    printf("Test TPM Wrapper: %-40s Passed\n",
        "ML-DSA Sign Seq w/ key auth:");
}

/* Regression for the VerifySequenceComplete data-chain fix.
 *
 * The wrapper used to silently drop the data/dataSz arguments; the fix
 * folds them in via an internal SequenceUpdate before Complete. Uses a
 * Hash-ML-DSA-65 key (NOT the existing Pure ML-DSA + allowExternalMu key)
 * because Hash-ML-DSA derives the verified message from the SHA-256
 * digest of every byte streamed through SequenceUpdate — so dropping the
 * Complete data argument actually changes the digest the signature is
 * verified against. (Pure ML-DSA + allowExternalMu accepts a 64-byte μ
 * digest directly and would not detect the drop.)
 *
 * If the silent-drop regresses, the verify sees only the first half of
 * the message, computes a different digest from what the signature is
 * over, and TPM_RC_SIGNATURE comes back. */
static void test_wolfTPM2_MLDSA_VerifySequence_DataChain(WOLFTPM2_DEV* dev)
{
    int rc;
    WOLFTPM2_KEY hashKey;
    TPMT_PUBLIC pub;
    TPM_HANDLE seqHandle;
    TPMT_TK_VERIFIED validation;
    byte sig[5000];
    int sigSz = (int)sizeof(sig);
    static const byte msg[] =
        "Hash-ML-DSA data-chain regression message: covers HIGH-3";
    int msgSz = (int)sizeof(msg) - 1;
    int firstHalf;

    XMEMSET(&hashKey, 0, sizeof(hashKey));
    XMEMSET(&pub, 0, sizeof(pub));
    XMEMSET(&validation, 0, sizeof(validation));

    rc = wolfTPM2_GetKeyTemplate_HASH_MLDSA(&pub,
        TPMA_OBJECT_sign | TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent |
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth,
        TPM_MLDSA_65, TPM_ALG_SHA256);
    AssertIntEQ(rc, TPM_RC_SUCCESS);

    rc = wolfTPM2_CreatePrimaryKey(dev, &hashKey, TPM_RH_OWNER, &pub, NULL, 0);
    if (rc == TPM_RC_VALUE || rc == TPM_RC_SCHEME ||
            rc == TPM_RC_COMMAND_CODE || rc == (int)(RC_VER1 + 0x043)) {
        printf("Test TPM Wrapper: %-40s Skipped (not supported)\n",
            "ML-DSA Verify Seq data-chain:");
        return;
    }
    AssertIntEQ(rc, 0);

    /* Sign the full message in one shot via SignSequence (Hash-ML-DSA
     * accepts SequenceUpdate; doing it all via Complete's data arg here
     * is fine and simpler). */
    test_wolfTPM2_MLDSA_SignSequence(dev, &hashKey, msg, msgSz, sig, &sigSz);
    if (sigSz <= 0) {
        wolfTPM2_UnloadHandle(dev, &hashKey.handle);
        return;
    }

    /* Verify with the message split: first half via SequenceUpdate, second
     * half via Complete's data arg. The fix's internal SequenceUpdate folds
     * the second half before Complete; if the bug regresses, only the first
     * half is in the sequence and the digest diverges from the signature's. */
    firstHalf = msgSz / 2;
    rc = wolfTPM2_VerifySequenceStart(dev, &hashKey, NULL, 0, &seqHandle);
    AssertIntEQ(rc, 0);

    rc = wolfTPM2_VerifySequenceUpdate(dev, seqHandle, msg, firstHalf);
    AssertIntEQ(rc, 0);

    rc = wolfTPM2_VerifySequenceComplete(dev, seqHandle, &hashKey,
        msg + firstHalf, msgSz - firstHalf, sig, sigSz, &validation);
    AssertIntEQ(rc, 0);

    wolfTPM2_UnloadHandle(dev, &hashKey.handle);
    printf("Test TPM Wrapper: %-40s Passed\n",
        "ML-DSA Verify Seq data-chain:");
}

/* Hash-ML-DSA streaming sign coverage: split the message across multiple
 * wolfTPM2_SignSequenceUpdate calls then sign with an empty trailing
 * buffer at Complete. Verifies the sig end-to-end. Also exercises the
 * argument-validation paths (NULL dev / NULL data / dataSz<=0 /
 * dataSz > buffer) — the wrapper is the documented streaming-update
 * mechanism for Hash-ML-DSA so it needs direct test coverage. */
static void test_wolfTPM2_HashMLDSA_SignSequence_Streaming(WOLFTPM2_DEV* dev)
{
    int rc;
    WOLFTPM2_KEY hashKey;
    TPMT_PUBLIC pub;
    TPM_HANDLE seqHandle;
    TPMT_TK_VERIFIED validation;
    byte sig[5000];
    int sigSz = (int)sizeof(sig);
    static const byte msg[] =
        "Hash-ML-DSA streaming sign test — split across SequenceUpdate calls";
    int msgSz = (int)sizeof(msg) - 1;
    int firstHalf;

    XMEMSET(&hashKey, 0, sizeof(hashKey));
    XMEMSET(&pub, 0, sizeof(pub));
    XMEMSET(&validation, 0, sizeof(validation));

    rc = wolfTPM2_GetKeyTemplate_HASH_MLDSA(&pub,
        TPMA_OBJECT_sign | TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent |
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth,
        TPM_MLDSA_65, TPM_ALG_SHA256);
    AssertIntEQ(rc, TPM_RC_SUCCESS);

    rc = wolfTPM2_CreatePrimaryKey(dev, &hashKey, TPM_RH_OWNER, &pub, NULL, 0);
    if (rc == TPM_RC_VALUE || rc == TPM_RC_SCHEME ||
            rc == TPM_RC_COMMAND_CODE || rc == (int)(RC_VER1 + 0x043)) {
        printf("Test TPM Wrapper: %-40s Skipped (not supported)\n",
            "Hash-ML-DSA SignSeqUpdate streaming:");
        return;
    }
    AssertIntEQ(rc, 0);

    /* Argument validation — none of these should reach the TPM. */
    AssertIntEQ(wolfTPM2_SignSequenceUpdate(NULL, 0x80000000,
                    (const byte*)"x", 1), BAD_FUNC_ARG);
    AssertIntEQ(wolfTPM2_SignSequenceUpdate(dev, 0x80000000, NULL, 1),
                    BAD_FUNC_ARG);
    AssertIntEQ(wolfTPM2_SignSequenceUpdate(dev, 0x80000000,
                    (const byte*)"x", 0), BAD_FUNC_ARG);
    /* dataSz larger than the SequenceUpdate buffer must reject locally. */
    AssertIntEQ(wolfTPM2_SignSequenceUpdate(dev, 0x80000000,
                    (const byte*)"x", MAX_DIGEST_BUFFER + 1), BUFFER_E);

    /* Streaming sign: SignSequenceStart → Update(part1) → Update(part2) →
     * Complete(empty trailing buffer). */
    rc = wolfTPM2_SignSequenceStart(dev, &hashKey, NULL, 0, &seqHandle);
    AssertIntEQ(rc, 0);

    firstHalf = msgSz / 2;
    rc = wolfTPM2_SignSequenceUpdate(dev, seqHandle, msg, firstHalf);
    AssertIntEQ(rc, 0);
    rc = wolfTPM2_SignSequenceUpdate(dev, seqHandle,
            msg + firstHalf, msgSz - firstHalf);
    AssertIntEQ(rc, 0);

    sigSz = (int)sizeof(sig);
    rc = wolfTPM2_SignSequenceComplete(dev, seqHandle, &hashKey,
            NULL, 0, sig, &sigSz);
    AssertIntEQ(rc, 0);
    AssertIntGT(sigSz, 0);

    /* Round-trip: verify the streamed signature matches the original
     * message via VerifySequence (also streaming). */
    rc = wolfTPM2_VerifySequenceStart(dev, &hashKey, NULL, 0, &seqHandle);
    AssertIntEQ(rc, 0);
    rc = wolfTPM2_VerifySequenceComplete(dev, seqHandle, &hashKey,
            msg, msgSz, sig, sigSz, &validation);
    AssertIntEQ(rc, 0);

    wolfTPM2_UnloadHandle(dev, &hashKey.handle);
    printf("Test TPM Wrapper: %-40s Passed\n",
        "Hash-ML-DSA SignSeqUpdate streaming:");
}

/* Direct coverage for wolfTPM2_SignDigest + wolfTPM2_VerifyDigestSignature
 * wrappers. These are the documented one-shot digest APIs and were only
 * exercised via the pqc_mssim_e2e example — wrapper-level marshaling bugs
 * (TPMT_TK_HASHCHECK synthesis, sigAlg dispatch, ticket parse) were not
 * caught by unit tests. Sign + Verify round-trip then assert the
 * validation ticket reports DIGEST_VERIFIED. */
static void test_wolfTPM2_HashMLDSA_SignDigest_RoundTrip(WOLFTPM2_DEV* dev)
{
    int rc;
    WOLFTPM2_KEY hashKey;
    TPMT_PUBLIC pub;
    TPMT_TK_VERIFIED validation;
    byte sig[5000];
    int sigSz = (int)sizeof(sig);
    /* SHA-256 digest of an arbitrary 32-byte test vector. */
    const byte digest[32] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F
    };

    XMEMSET(&hashKey, 0, sizeof(hashKey));
    XMEMSET(&pub, 0, sizeof(pub));
    XMEMSET(&validation, 0, sizeof(validation));

    rc = wolfTPM2_GetKeyTemplate_HASH_MLDSA(&pub,
        TPMA_OBJECT_sign | TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent |
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth,
        TPM_MLDSA_65, TPM_ALG_SHA256);
    AssertIntEQ(rc, TPM_RC_SUCCESS);

    rc = wolfTPM2_CreatePrimaryKey(dev, &hashKey, TPM_RH_OWNER, &pub, NULL, 0);
    if (rc == TPM_RC_VALUE || rc == TPM_RC_SCHEME ||
            rc == TPM_RC_COMMAND_CODE || rc == (int)(RC_VER1 + 0x043)) {
        printf("Test TPM Wrapper: %-40s Skipped (not supported)\n",
            "Hash-ML-DSA SignDigest roundtrip:");
        return;
    }
    AssertIntEQ(rc, 0);

    rc = wolfTPM2_SignDigest(dev, &hashKey, digest, (int)sizeof(digest),
            NULL, 0, sig, &sigSz);
    AssertIntEQ(rc, 0);
    AssertIntGT(sigSz, 0);

    rc = wolfTPM2_VerifyDigestSignature(dev, &hashKey,
            digest, (int)sizeof(digest), sig, sigSz, NULL, 0, &validation);
    AssertIntEQ(rc, 0);
    /* Ticket from VerifyDigestSignature must be DIGEST_VERIFIED — a
     * downstream PolicyTicket consumer relies on this tag. */
    AssertIntEQ(validation.tag, TPM_ST_DIGEST_VERIFIED);

    wolfTPM2_UnloadHandle(dev, &hashKey.handle);
    printf("Test TPM Wrapper: %-40s Passed\n",
        "Hash-ML-DSA SignDigest roundtrip:");
}

/* Regression for the TPM2_SignSequenceStart no-session path.
 * Per Part 3 Sec.17.6.3 the command has Auth Index: None; the native API
 * used to require ctx->session != NULL and hardcode TPM_ST_SESSIONS.
 * This test forces the no-session branch and asserts success — if a
 * future change re-adds the spurious session check or hardcodes the
 * tag, the call returns BAD_FUNC_ARG. */
static void test_TPM2_SignSequenceStart_NoSession(WOLFTPM2_DEV* dev,
    WOLFTPM2_KEY* mldsaKey)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();
    TPM2_AUTH_SESSION* savedSession;
    SignSequenceStart_In in;
    SignSequenceStart_Out out;

    if (ctx == NULL) {
        printf("Test TPM Wrapper: %-40s Skipped (no ctx)\n",
            "ML-DSA SignSeqStart no-session:");
        return;
    }

    savedSession = ctx->session;
    ctx->session = NULL;

    XMEMSET(&in, 0, sizeof(in));
    XMEMSET(&out, 0, sizeof(out));
    in.keyHandle = mldsaKey->handle.hndl;

    rc = TPM2_SignSequenceStart(&in, &out);

    ctx->session = savedSession;

    if (rc == TPM_RC_VALUE || rc == TPM_RC_SCHEME ||
            rc == TPM_RC_COMMAND_CODE || rc == (TPM_RC)(RC_VER1 + 0x043)) {
        printf("Test TPM Wrapper: %-40s Skipped (not supported)\n",
            "ML-DSA SignSeqStart no-session:");
        return;
    }
    AssertIntEQ(rc, TPM_RC_SUCCESS);

    /* Flush the sequence we just started */
    if (out.sequenceHandle != 0) {
        WOLFTPM2_HANDLE seqHandle;
        XMEMSET(&seqHandle, 0, sizeof(seqHandle));
        seqHandle.hndl = out.sequenceHandle;
        wolfTPM2_UnloadHandle(dev, &seqHandle);
    }

    printf("Test TPM Wrapper: %-40s Passed\n",
        "ML-DSA SignSeqStart no-session:");
}

#if !defined(WOLFTPM2_NO_WOLFCRYPT) && \
    (defined(WOLFSSL_HAVE_MLKEM) || defined(WOLFSSL_KYBER512) || \
     defined(WOLFSSL_KYBER768) || defined(WOLFSSL_KYBER1024))
/* Test ML-KEM Encapsulate; writes ct to caller buffer on success */
static void test_wolfTPM2_MLKEM_Encapsulate(WOLFTPM2_DEV* dev,
    WOLFTPM2_KEY* mlkemKey, byte* ciphertext, int* ciphertextSz)
{
    int rc;
    byte sharedSecret[64];
    int sharedSecretSz = (int)sizeof(sharedSecret);

    XMEMSET(sharedSecret, 0, sizeof(sharedSecret));

    rc = wolfTPM2_Encapsulate(dev, mlkemKey, ciphertext, ciphertextSz,
        sharedSecret, &sharedSecretSz);
    if (rc == TPM_RC_VALUE || rc == TPM_RC_SCHEME ||
        rc == TPM_RC_COMMAND_CODE || rc == (int)(RC_VER1 + 0x043)) {
        printf("Test TPM Wrapper: %-40s Skipped (not supported)\n", "ML-KEM Encapsulate:");
        *ciphertextSz = 0;
        return;
    }
    AssertIntEQ(rc, 0);
    AssertIntGT(*ciphertextSz, 0);
    AssertIntGT(sharedSecretSz, 0);

    printf("Test TPM Wrapper: %-40s %s\n", "ML-KEM Encapsulate:",
        rc == 0 ? "Passed" : "Failed");
}

/* Test ML-KEM Decapsulate */
static void test_wolfTPM2_MLKEM_Decapsulate(WOLFTPM2_DEV* dev,
    WOLFTPM2_KEY* mlkemKey, const byte* ciphertext, int ciphertextSz)
{
    int rc;
    byte sharedSecret[64]; /* Shared secret */
    int sharedSecretSz = (int)sizeof(sharedSecret);

    XMEMSET(sharedSecret, 0, sizeof(sharedSecret));

    /* Test Decapsulate */
    rc = wolfTPM2_Decapsulate(dev, mlkemKey, ciphertext, ciphertextSz,
        sharedSecret, &sharedSecretSz);
    if (rc == TPM_RC_VALUE || rc == TPM_RC_SCHEME ||
        rc == TPM_RC_COMMAND_CODE || rc == (int)(RC_VER1 + 0x043)) {
        printf("Test TPM Wrapper: %-40s Skipped (not supported)\n", "ML-KEM Decapsulate:");
        return;
    }
    AssertIntEQ(rc, 0);
    AssertIntGT(sharedSecretSz, 0);

    printf("Test TPM Wrapper: %-40s %s\n", "ML-KEM Decapsulate:",
        rc == 0 ? "Passed" : "Failed");
}

/* Test ML-KEM Encapsulate/Decapsulate round-trip */
static void test_wolfTPM2_MLKEM_RoundTrip(WOLFTPM2_DEV* dev,
    WOLFTPM2_KEY* mlkemKey)
{
    int rc;
    byte ciphertext[2048];
    int ciphertextSz = (int)sizeof(ciphertext);
    byte sharedSecret1[64], sharedSecret2[64];
    int sharedSecret1Sz = (int)sizeof(sharedSecret1);
    int sharedSecret2Sz = (int)sizeof(sharedSecret2);

    XMEMSET(ciphertext, 0, sizeof(ciphertext));
    XMEMSET(sharedSecret1, 0, sizeof(sharedSecret1));
    XMEMSET(sharedSecret2, 0, sizeof(sharedSecret2));

    /* Encapsulate */
    rc = wolfTPM2_Encapsulate(dev, mlkemKey, ciphertext, &ciphertextSz,
        sharedSecret1, &sharedSecret1Sz);
    if (rc == TPM_RC_VALUE || rc == TPM_RC_SCHEME ||
        rc == TPM_RC_COMMAND_CODE || rc == (int)(RC_VER1 + 0x043)) {
        printf("Test TPM Wrapper: %-40s Skipped (not supported)\n", "ML-KEM Round Trip:");
        return;
    }
    AssertIntEQ(rc, 0);
    AssertIntGT(ciphertextSz, 0);
    AssertIntGT(sharedSecret1Sz, 0);

    /* Decapsulate */
    rc = wolfTPM2_Decapsulate(dev, mlkemKey, ciphertext, ciphertextSz,
        sharedSecret2, &sharedSecret2Sz);
    AssertIntEQ(rc, 0);
    AssertIntGT(sharedSecret2Sz, 0);

    /* Verify shared secrets match */
    AssertIntEQ(sharedSecret1Sz, sharedSecret2Sz);
    AssertIntEQ(XMEMCMP(sharedSecret1, sharedSecret2, sharedSecret1Sz), 0);

    printf("Test TPM Wrapper: %-40s %s\n", "ML-KEM Round Trip:",
        rc == 0 ? "Passed" : "Failed");
}
#endif /* ML-KEM support */

/* Main PQC test function */
/* Returns 1 if the connected TPM advertises @alg in its TPM_CAP_ALGS list.
 * Used to skip sub-tests for optional algorithms (e.g. Hash-ML-DSA) that a
 * given TPM may not implement, without hard-coding any model check. */
static int test_alg_supported(TPM_ALG_ID alg)
{
    GetCapability_In in;
    GetCapability_Out out;
    TPML_ALG_PROPERTY* algs;
    word32 i;

    XMEMSET(&in, 0, sizeof(in));
    XMEMSET(&out, 0, sizeof(out));
    in.capability = TPM_CAP_ALGS;
    in.property = TPM_ALG_FIRST;
    in.propertyCount = MAX_CAP_ALGS;
    if (TPM2_GetCapability(&in, &out) != TPM_RC_SUCCESS)
        return 0;

    algs = &out.capabilityData.data.algorithms;
    for (i = 0; i < algs->count; i++) {
        if (algs->algProperties[i].alg == alg)
            return 1;
    }
    return 0;
}

/* Regression for the VerifySequenceComplete flush-on-error fix: looping
 * failed verifies must not exhaust transient memory (TPM_RC_OBJECT_MEMORY).
 * Uses an ECC key to cover the classical (non-PQC) wrapper path. */
static void test_wolfTPM2_VerifySequence_NoLeak(void)
{
    int rc, i;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY eccKey;
    TPMT_PUBLIC pub;
    TPM_HANDLE seqHandle;
    TPMT_TK_VERIFIED validation;
    byte msg[32];
    byte badSig[64]; /* ECC P-256 r||s, deliberately invalid */

    XMEMSET(&eccKey, 0, sizeof(eccKey));
    XMEMSET(&pub, 0, sizeof(pub));
    XMEMSET(msg, 0xAB, sizeof(msg));
    XMEMSET(badSig, 0xAA, sizeof(badSig));

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, NULL);
    AssertIntEQ(rc, 0);

    rc = wolfTPM2_GetKeyTemplate_ECC(&pub,
        TPMA_OBJECT_sign | TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent |
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_noDA, TPM_ECC_NIST_P256, TPM_ALG_ECDSA);
    AssertIntEQ(rc, TPM_RC_SUCCESS);

    rc = wolfTPM2_CreatePrimaryKey(&dev, &eccKey, TPM_RH_OWNER, &pub, NULL, 0);
    if (rc != TPM_RC_SUCCESS) {
        printf("Test TPM Wrapper: %-40s Skipped (not supported)\n",
            "VerifySequence no-leak:");
        wolfTPM2_Cleanup(&dev);
        return;
    }

    /* More iterations than the TPM has transient slots. Without the fix the
     * leaked sequence objects exhaust memory and a later call returns
     * TPM_RC_OBJECT_MEMORY; with it each failed verify is flushed. */
    for (i = 0; i < 8; i++) {
        rc = wolfTPM2_VerifySequenceStart(&dev, &eccKey, NULL, 0, &seqHandle);
        if (rc == TPM_RC_SUCCESS) {
            rc = wolfTPM2_VerifySequenceComplete(&dev, seqHandle, &eccKey,
                msg, (int)sizeof(msg), badSig, (int)sizeof(badSig),
                &validation);
        }
        AssertIntNE(rc, TPM_RC_OBJECT_MEMORY);
        AssertIntNE(rc, TPM_RC_SUCCESS); /* bad signature must be rejected */
    }

    wolfTPM2_UnloadHandle(&dev, &eccKey.handle);
    wolfTPM2_Cleanup(&dev);
    printf("Test TPM Wrapper: %-40s Passed\n", "VerifySequence no-leak:");
}

static void test_wolfTPM2_PQC(void)
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY storageKey;
    WOLFTPM2_KEY mldsaKey;
    TPMT_PUBLIC mldsaPub;
    byte sig[5000];
    int sigSz = (int)sizeof(sig);
    byte testMessage[] = "Test message for ML-DSA signing";
    int testMessageSz = (int)sizeof(testMessage) - 1;
#if !defined(WOLFTPM2_NO_WOLFCRYPT) && \
    (defined(WOLFSSL_HAVE_MLKEM) || defined(WOLFSSL_KYBER512) || \
     defined(WOLFSSL_KYBER768) || defined(WOLFSSL_KYBER1024))
    WOLFTPM2_KEY mlkemKey;
    TPMT_PUBLIC mlkemPub;
    byte testCiphertext[2048];
    int testCiphertextSz;
#endif

    /* Initialize TPM */
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, NULL);
    AssertIntEQ(rc, 0);

    /* Create storage key (exercises CreateSRK), then flush it immediately.
     * It is not used as a parent below, and holding it would consume one of
     * the few transient object slots on constrained hardware, leaving no
     * room for a sub-test's own primary plus a sign-sequence object
     * (TPM_RC_OBJECT_MEMORY). */
    rc = wolfTPM2_CreateSRK(&dev, &storageKey, TPM_ALG_ECC,
        (byte*)gStorageKeyAuth, sizeof(gStorageKeyAuth)-1);
    AssertIntEQ(rc, 0);
    wolfTPM2_UnloadHandle(&dev, &storageKey.handle);

    /* Create a real ML-DSA-65 primary key so Sign/Verify sequence tests
     * operate on an actual handle. Pure-MLDSA SignDigest is deferred
     * until wolfCrypt exposes a mu-direct sign API (DEC-0006). */
    printf("Testing ML-DSA functions...\n");
    XMEMSET(&mldsaKey, 0, sizeof(mldsaKey));
    XMEMSET(&mldsaPub, 0, sizeof(mldsaPub));
    /* allowExternalMu=0: fwTPM does not yet implement μ-direct sign, so per
     * Part 2 Sec.12.2.3.6 keys created with allowExternalMu=YES are rejected at
     * object creation with TPM_RC_EXT_MU. Use NO for the suite key. */
    rc = wolfTPM2_GetKeyTemplate_MLDSA(&mldsaPub,
        TPMA_OBJECT_sign | TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent |
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth,
        TPM_MLDSA_65, 0 /* allowExternalMu */);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    rc = wolfTPM2_CreatePrimaryKey(&dev, &mldsaKey, TPM_RH_OWNER,
        &mldsaPub, NULL, 0);
    if (rc == TPM_RC_VALUE || rc == TPM_RC_SCHEME ||
            rc == TPM_RC_COMMAND_CODE || rc == (int)(RC_VER1 + 0x043)) {
        printf("Test TPM Wrapper: %-40s Skipped (not supported)\n",
            "ML-DSA PQC suite:");
        goto mldsa_done;
    }
    AssertIntEQ(rc, 0);

    sigSz = (int)sizeof(sig);
    test_wolfTPM2_MLDSA_SignSequence(&dev, &mldsaKey,
        testMessage, testMessageSz, sig, &sigSz);

    test_wolfTPM2_MLDSA_VerifySequence(&dev, &mldsaKey,
        testMessage, testMessageSz, sig, sigSz);

    /* Bug-fix regressions: each test exercises a wrapper / native-API path
     * that no existing test covers, so a re-introduction of the underlying
     * fix would silently pass CI without these. */
    /* These sub-tests each create a HASH_MLDSA key (DataChain included), so
     * only run them when the TPM advertises TPM_ALG_HASH_MLDSA. */
    if (test_alg_supported(TPM_ALG_HASH_MLDSA)) {
        test_wolfTPM2_MLDSA_VerifySequence_DataChain(&dev);
        test_wolfTPM2_HashMLDSA_SignSequence_Streaming(&dev);
        test_wolfTPM2_HashMLDSA_SignDigest_RoundTrip(&dev);
    }
    else {
        printf("Test TPM Wrapper: %-40s Skipped (no Hash-ML-DSA)\n",
            "Hash-ML-DSA:");
    }
    test_TPM2_SignSequenceStart_NoSession(&dev, &mldsaKey);
    test_wolfTPM2_MLDSA_SignSequence_NonEmptyAuth(&dev, &mldsaPub);

    wolfTPM2_UnloadHandle(&dev, &mldsaKey.handle);
mldsa_done:

#if !defined(WOLFTPM2_NO_WOLFCRYPT) && \
    (defined(WOLFSSL_HAVE_MLKEM) || defined(WOLFSSL_KYBER512) || \
     defined(WOLFSSL_KYBER768) || defined(WOLFSSL_KYBER1024))
    printf("Testing ML-KEM functions...\n");
    XMEMSET(&mlkemKey, 0, sizeof(mlkemKey));
    XMEMSET(&mlkemPub, 0, sizeof(mlkemPub));
    rc = wolfTPM2_GetKeyTemplate_MLKEM(&mlkemPub,
        TPMA_OBJECT_decrypt | TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent |
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth,
        TPM_MLKEM_768);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    rc = wolfTPM2_CreatePrimaryKey(&dev, &mlkemKey, TPM_RH_OWNER,
        &mlkemPub, NULL, 0);
    if (rc == TPM_RC_VALUE || rc == TPM_RC_SCHEME ||
            rc == TPM_RC_COMMAND_CODE || rc == (int)(RC_VER1 + 0x043)) {
        printf("Test TPM Wrapper: %-40s Skipped (not supported)\n",
            "ML-KEM PQC suite:");
        goto mlkem_done;
    }
    AssertIntEQ(rc, 0);

    XMEMSET(testCiphertext, 0, sizeof(testCiphertext));
    testCiphertextSz = (int)sizeof(testCiphertext);
    test_wolfTPM2_MLKEM_Encapsulate(&dev, &mlkemKey,
        testCiphertext, &testCiphertextSz);
    if (testCiphertextSz > 0) {
        test_wolfTPM2_MLKEM_Decapsulate(&dev, &mlkemKey,
            testCiphertext, testCiphertextSz);
    }

    test_wolfTPM2_MLKEM_RoundTrip(&dev, &mlkemKey);
    wolfTPM2_UnloadHandle(&dev, &mlkemKey.handle);
mlkem_done:
#endif

    wolfTPM2_UnloadHandle(&dev, &storageKey.handle);
    wolfTPM2_Cleanup(&dev);
}

/* Test PQC key template creation */
static void test_wolfTPM2_PQC_KeyTemplates(void)
{
    int rc;
    TPMT_PUBLIC mldsaTemplate, hashMldsaTemplate, mlkemTemplate;

    printf("Testing PQC Key Templates...\n");

    /* Test MLDSA template */
    rc = wolfTPM2_GetKeyTemplate_MLDSA(&mldsaTemplate,
        TPMA_OBJECT_sign | TPMA_OBJECT_userWithAuth,
        TPM_MLDSA_65, 1);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    AssertIntEQ(mldsaTemplate.type, TPM_ALG_MLDSA);
    AssertIntEQ(mldsaTemplate.parameters.mldsaDetail.parameterSet, TPM_MLDSA_65);
    AssertIntEQ(mldsaTemplate.parameters.mldsaDetail.allowExternalMu, YES);
    /* Verify sign is set, decrypt is NOT set */
    AssertTrue(mldsaTemplate.objectAttributes & TPMA_OBJECT_sign);
    AssertFalse(mldsaTemplate.objectAttributes & TPMA_OBJECT_decrypt);

    /* Test HASH_MLDSA template */
    rc = wolfTPM2_GetKeyTemplate_HASH_MLDSA(&hashMldsaTemplate,
        TPMA_OBJECT_sign | TPMA_OBJECT_userWithAuth,
        TPM_MLDSA_87, TPM_ALG_SHA256);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    AssertIntEQ(hashMldsaTemplate.type, TPM_ALG_HASH_MLDSA);
    AssertIntEQ(hashMldsaTemplate.parameters.hash_mldsaDetail.parameterSet, TPM_MLDSA_87);
    AssertIntEQ(hashMldsaTemplate.parameters.hash_mldsaDetail.hashAlg, TPM_ALG_SHA256);

    /* Test MLKEM template */
    rc = wolfTPM2_GetKeyTemplate_MLKEM(&mlkemTemplate,
        TPMA_OBJECT_decrypt | TPMA_OBJECT_userWithAuth,
        TPM_MLKEM_768);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    AssertIntEQ(mlkemTemplate.type, TPM_ALG_MLKEM);
    AssertIntEQ(mlkemTemplate.parameters.mlkemDetail.parameterSet, TPM_MLKEM_768);
    /* Verify decrypt is set, sign is NOT set */
    AssertTrue(mlkemTemplate.objectAttributes & TPMA_OBJECT_decrypt);
    AssertFalse(mlkemTemplate.objectAttributes & TPMA_OBJECT_sign);

    /* Test NULL argument handling */
    rc = wolfTPM2_GetKeyTemplate_MLDSA(NULL, 0, TPM_MLDSA_44, 0);
    AssertIntEQ(rc, BAD_FUNC_ARG);

    rc = wolfTPM2_GetKeyTemplate_HASH_MLDSA(NULL, 0, TPM_MLDSA_44, TPM_ALG_SHA256);
    AssertIntEQ(rc, BAD_FUNC_ARG);

    rc = wolfTPM2_GetKeyTemplate_MLKEM(NULL, 0, TPM_MLKEM_512);
    AssertIntEQ(rc, BAD_FUNC_ARG);

    printf("Test TPM Wrapper: %-40s Passed\n", "PQC Key Templates:");
}

/* Test PQC sizes sanity check */
static void test_wolfTPM2_PQC_Sizes(void)
{
    printf("Testing PQC Sizes...\n");

    /* Verify TPMT_PUBLIC size is reasonable for embedded targets */
    printf("  TPMT_PUBLIC size with PQC: %zu bytes\n", sizeof(TPMT_PUBLIC));
    /* Warn if > 5KB, which could be large for embedded stacks */
    if (sizeof(TPMT_PUBLIC) >= 5120) {
        printf("  WARNING: TPMT_PUBLIC size (%zu bytes) may be large for "
               "embedded stacks\n", sizeof(TPMT_PUBLIC));
    }

    /* Verify key buffer sizes are correct */
    AssertIntEQ(MAX_MLDSA_PUB_SIZE, 2592);  /* ML-DSA-87 */
    AssertIntEQ(MAX_MLDSA_SIG_SIZE, 4627);  /* ML-DSA-87 */
    AssertIntEQ(MAX_MLDSA_PRIV_SEED_SIZE, 32);
    AssertIntEQ(MAX_MLKEM_PUB_SIZE, 1568);  /* ML-KEM-1024 */
    AssertIntEQ(MAX_MLKEM_PRIV_SEED_SIZE, 64);

    printf("Test TPM Wrapper: %-40s Passed\n", "PQC Sizes:");
}
#endif /* WOLFTPM_MLDSA && WOLFTPM_MLKEM */

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
    test_wolfTPM2_DictionaryAttack();
    test_wolfTPM2_HashFinish_BufferTooSmall();
    test_TPM2_PCRSel();
    test_TPM2_Policy_NULL_Args();
    test_wolfTPM2_SetLocality();
    test_wolfTPM2_PolicyAuthValue_AuthOffset();
    test_wolfTPM2_SetAuthHandle_PolicyAuthOffset();
    test_wolfTPM2_StartSession_SaltedEncryptAttrs();
    test_wolfTPM2_StartSession_ex_authHash();
    test_wolfTPM2_BoundSession_EmptyAuth_ParamEnc();
    test_wolfTPM2_CreateLoaded_ParamEnc();
    test_wolfTPM2_BoundOwnEntity_ParamEnc();
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
    test_TPM2_ParamEnc_XOR_MaskBoundary();
    test_TPM2_ParamEnc_AESCFB_Vector();
    test_TPM2_ParamEnc_AESCFB_KeyBoundary();
    test_TPM2_ParamEnc_AESCFB_KAT();
    test_TPM2_ParamDec_XOR_Roundtrip();
    test_TPM2_ParamDec_AESCFB_Roundtrip();
    test_TPM2_ParamEncDec_Dispatch_Roundtrip();
    test_TPM2_HashNvPublic();
    #if !defined(WOLFTPM2_NO_WOLFCRYPT) && defined(HAVE_ECC)
    test_wolfTPM2_ComputeName();
    #endif
    test_TPM2_SchemeSerialize();
    test_TPM2_ECC_Parameters_EcdaaResponseParse();
    test_TPM2_ParseAttest_NvDigest();
    test_TPM2_ParsePublic_OuterResync();
    test_TPM2_ParsePoint_OuterResync();
    test_TPM2_ParseSignature_NullAlg();
    test_TPM2_BrainpoolCurveMapping();
    test_TPM2_EccDefaultCurveTemplate();
    test_wolfTPM2_RsaEncryptDecrypt_OversizedBufferE();
    test_wolfTPM2_RsaEncryptDecrypt_ex();
    test_wolfTPM2_GetKeyTemplate_ex_nameAlg();
    test_wolfTPM2_SignHashScheme_DigestSize();
    test_wolfTPM2_VerifyHashTicket_DigestSize();
#ifndef WOLFTPM_NO_RETRY
    test_TPM2_CommandRetries();
    test_TPM2_Packet_RetryRestore();
#endif
    test_TPM2_ResponseProcess_ParamSizeOverflow();
    test_TPM2_ResponseProcess_HmacVerify();
    test_wolfTPM2_NVCreateAuthPolicy_NameAlg();
    test_wolfTPM2_GetKeyTemplate_KeyedHash_Scheme();
#if defined(WOLFTPM_MFG_IDENTITY) && \
    !defined(WOLFTPM_ST33) && !defined(WOLFTPM_AUTODETECT)
    test_wolfTPM2_SetIdentityAuth_RequiresPassword();
#endif
    test_wolfTPM2_EccKey_TpmToWolf_ShortCoord();
    test_wolfTPM2_RsaKey_TpmToWolf_Exponent();
    test_wolfTPM2_EccZToBuffer();
    test_wolfTPM2_LoadEccPublicKey_Ex();
    test_TPM2_KeyedHashScheme_XorSerialize();
    test_TPM2_Signature_EcSchnorrSm2Serialize();
    test_TPM2_Public_RsaEcc_Roundtrip();
#ifdef WOLFTPM_PQC
    test_TPM2_Signature_PQC_Serialize();
    test_TPM2_Public_PQC_Roundtrip();
#endif
    test_TPM2_Sensitive_Roundtrip();
    test_TPM2_TIS_ValidateRspSz();
    test_TPM2_ParsePublic_EmptyClears();
    test_TPM2_AppendSensitive_Clamp();
    test_TPM2_AppendPublic_Clamp();
    test_TPM2_Sensitive_MaxRoundtrip();
    test_KeySealTemplate();
    test_SealAndKeyedHash_Boundaries();
    test_GetAlgId();
    test_wolfTPM2_ReadPublicKey();
    test_wolfTPM2_CSR();
    test_wolfTPM2_CryptoDevCb_EccVerifyOversizedRS();
    test_TPM2_ASN_DecodeX509Cert_Errors();
    test_TPM2_ASN_DecodeX509Cert_Valid();
    test_TPM2_ASN_DecodeTag_Errors();
    #if !defined(WOLFTPM2_NO_WOLFCRYPT) && defined(WOLFTPM2_PEM_DECODE) && \
        !defined(NO_RSA)
    test_wolfTPM_ImportPublicKey();
    test_wolfTPM2_PCRPolicy();
    #endif
    test_wolfTPM2_EncryptSecret();
    #if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_ASN)
    test_wolfTPM2_DecodeDer_DefaultAttribs();
    test_wolfTPM2_DecodeDer_WrapKeyScaling();
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
    #ifdef WOLFTPM_SWTPM
    test_TPM2_SwtpmValidateRspSz();
    #endif
    #if !defined(NO_FILESYSTEM) && !defined(NO_WRITE_TEMP_FILES) && \
        !defined(WOLFTPM2_NO_WOLFCRYPT) && defined(HAVE_ECC)
    test_readKeyBlob_PrivOverflow();
    #endif
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
    #if defined(WOLFTPM_MLDSA) && defined(WOLFTPM_MLKEM)
    /* Run non-TPM-dependent tests first */
    test_wolfTPM2_PQC_KeyTemplates();
    test_wolfTPM2_PQC_Sizes();
    /* Then run TPM-dependent PQC tests */
    test_wolfTPM2_PQC();
    test_wolfTPM2_VerifySequence_NoLeak();
    #endif
    test_wolfTPM2_Cleanup();
    test_wolfTPM2_thread_local_storage();
#ifdef WOLFTPM_SPDM
    test_wolfTPM2_SPDM_ValidateRspSz();
    test_wolfTPM2_SPDM_Functions();
#endif
#endif /* !WOLFTPM2_NO_WRAPPER */

    return 0;
}
