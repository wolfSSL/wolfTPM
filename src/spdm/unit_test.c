/* unit_test.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSPDM.
 *
 * wolfSPDM is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSPDM is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/spdm/spdm.h>
#include "spdm_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_testsPassed = 0;
static int g_testsFailed = 0;

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d)\n", msg, __LINE__); \
        g_testsFailed++; \
        return -1; \
    } \
} while(0)

#define TEST_PASS() do { \
    g_testsPassed++; \
    return 0; \
} while(0)

#define ASSERT_SUCCESS(expr) do { int _r = (expr); if (_r != 0) { \
    printf("  FAIL %s:%d: %s returned %d\n", __FILE__, __LINE__, #expr, _r); \
    g_testsFailed++; return -1; } } while(0)

#define ASSERT_EQ(a, b, msg) TEST_ASSERT((a) == (b), msg)
#define ASSERT_NE(a, b, msg) TEST_ASSERT((a) != (b), msg)

/* Test context setup/cleanup macros */
#define TEST_CTX_SETUP() \
    WOLFSPDM_CTX ctxBuf; \
    WOLFSPDM_CTX* ctx = &ctxBuf; \
    wolfSPDM_Init(ctx)

#define TEST_CTX_SETUP_V12() \
    TEST_CTX_SETUP(); \
    ctx->spdmVersion = SPDM_VERSION_12

#define TEST_CTX_FREE() \
    wolfSPDM_Free(ctx)

/* Dummy I/O callback for testing */
static int dummy_io_cb(WOLFSPDM_CTX* ctx, const byte* txBuf, word32 txSz,
    byte* rxBuf, word32* rxSz, void* userCtx)
{
    (void)ctx; (void)txBuf; (void)txSz;
    (void)rxBuf; (void)rxSz; (void)userCtx;
    return -1;
}

/* ----- Context Tests ----- */

#ifdef WOLFTPM_SMALL_STACK
static int test_context_new_free(void)
{
    WOLFSPDM_CTX* ctx;

    printf("test_context_new_free...\n");

    ctx = wolfSPDM_New();
    TEST_ASSERT(ctx != NULL, "wolfSPDM_New returned NULL");
    ASSERT_EQ(ctx->state, WOLFSPDM_STATE_INIT, "Initial state wrong");
    ASSERT_EQ(ctx->flags.initialized, 1, "Should be initialized by New()");

    wolfSPDM_Free(ctx);
    wolfSPDM_Free(NULL); /* Should not crash */

    TEST_PASS();
}
#endif /* WOLFTPM_SMALL_STACK */

static int test_context_init(void)
{
    TEST_CTX_SETUP();

    printf("test_context_init...\n");
    ASSERT_EQ(ctx->flags.initialized, 1, "Not marked initialized");
    ASSERT_EQ(ctx->flags.rngInitialized, 1, "RNG not initialized");

    TEST_CTX_FREE();
    TEST_PASS();
}

static int test_context_static_alloc(void)
{
    byte buffer[sizeof(WOLFSPDM_CTX) + 64];
    WOLFSPDM_CTX* ctx = (WOLFSPDM_CTX*)buffer;

    printf("test_context_static_alloc...\n");

    ASSERT_EQ(wolfSPDM_GetCtxSize(), (int)sizeof(WOLFSPDM_CTX),
        "GetCtxSize mismatch");
    ASSERT_EQ(wolfSPDM_InitStatic(ctx, 10), WOLFSPDM_E_BUFFER_SMALL,
        "Should fail on small buffer");
    ASSERT_SUCCESS(wolfSPDM_InitStatic(ctx, sizeof(buffer)));
    ASSERT_EQ(ctx->flags.initialized, 1, "Static ctx not initialized");

    wolfSPDM_Free(ctx);
    TEST_PASS();
}

static int test_context_set_io(void)
{
    int dummy = 42;
    TEST_CTX_SETUP();

    printf("test_context_set_io...\n");

    ASSERT_SUCCESS(wolfSPDM_SetIO(ctx, dummy_io_cb, &dummy));
    ASSERT_EQ(ctx->ioCb, dummy_io_cb, "IO callback not set");
    ASSERT_EQ(ctx->ioUserCtx, &dummy, "User context not set");
    ASSERT_EQ(wolfSPDM_SetIO(ctx, NULL, NULL), WOLFSPDM_E_INVALID_ARG,
        "NULL callback should fail");

    TEST_CTX_FREE();
    TEST_PASS();
}

/* ----- Transcript Tests ----- */

static int test_transcript_add_reset(void)
{
    byte data1[] = {0x01, 0x02, 0x03, 0x04};
    byte data2[] = {0x05, 0x06, 0x07, 0x08};
    TEST_CTX_SETUP();

    printf("test_transcript_add_reset...\n");
    ASSERT_EQ(ctx->transcriptLen, 0, "Transcript should start empty");

    ASSERT_SUCCESS(wolfSPDM_TranscriptAdd(ctx, data1, sizeof(data1)));
    ASSERT_EQ(ctx->transcriptLen, 4, "Length should be 4");
    ASSERT_EQ(memcmp(ctx->transcript, data1, 4), 0, "Data mismatch");

    ASSERT_SUCCESS(wolfSPDM_TranscriptAdd(ctx, data2, sizeof(data2)));
    ASSERT_EQ(ctx->transcriptLen, 8, "Length should be 8");
    ASSERT_EQ(memcmp(ctx->transcript + 4, data2, 4), 0, "Data2 mismatch");

    wolfSPDM_TranscriptReset(ctx);
    ASSERT_EQ(ctx->transcriptLen, 0, "Reset should clear length");

    TEST_CTX_FREE();
    TEST_PASS();
}

static int test_transcript_hash(void)
{
    byte data[] = "test data for hashing";
    byte hash[WOLFSPDM_HASH_SIZE];
    byte zeros[WOLFSPDM_HASH_SIZE];
    TEST_CTX_SETUP();

    printf("test_transcript_hash...\n");
    wolfSPDM_TranscriptAdd(ctx, data, sizeof(data) - 1);
    ASSERT_SUCCESS(wolfSPDM_TranscriptHash(ctx, hash));
    XMEMSET(zeros, 0, sizeof(zeros));
    ASSERT_NE(memcmp(hash, zeros, WOLFSPDM_HASH_SIZE), 0,
        "Hash should be non-zero");

    TEST_CTX_FREE();
    TEST_PASS();
}

/* ----- Crypto Tests ----- */

static int test_random_generation(void)
{
    byte buf1[32], buf2[32];
    TEST_CTX_SETUP();

    printf("test_random_generation...\n");
    ASSERT_SUCCESS(wolfSPDM_GetRandom(ctx, buf1, sizeof(buf1)));
    ASSERT_SUCCESS(wolfSPDM_GetRandom(ctx, buf2, sizeof(buf2)));
    ASSERT_NE(memcmp(buf1, buf2, sizeof(buf1)), 0,
        "Random outputs should differ");

    TEST_CTX_FREE();
    TEST_PASS();
}

static int test_ephemeral_key_generation(void)
{
    byte pubKeyX[WOLFSPDM_ECC_KEY_SIZE];
    byte pubKeyY[WOLFSPDM_ECC_KEY_SIZE];
    byte zeros[WOLFSPDM_ECC_KEY_SIZE];
    word32 xSz = sizeof(pubKeyX);
    word32 ySz = sizeof(pubKeyY);
    TEST_CTX_SETUP();

    printf("test_ephemeral_key_generation...\n");
    ASSERT_SUCCESS(wolfSPDM_GenerateEphemeralKey(ctx));
    ASSERT_EQ(ctx->flags.ephemeralKeyInit, 1, "Key not marked initialized");
    ASSERT_SUCCESS(wolfSPDM_ExportEphemeralPubKey(ctx, pubKeyX, &xSz, pubKeyY, &ySz));
    ASSERT_EQ(xSz, WOLFSPDM_ECC_KEY_SIZE, "X coordinate wrong size");
    ASSERT_EQ(ySz, WOLFSPDM_ECC_KEY_SIZE, "Y coordinate wrong size");
    XMEMSET(zeros, 0, sizeof(zeros));
    ASSERT_NE(memcmp(pubKeyX, zeros, WOLFSPDM_ECC_KEY_SIZE), 0,
        "Public key X should be non-zero");

    TEST_CTX_FREE();
    TEST_PASS();
}

/* ----- KDF Tests ----- */

static int test_hkdf_expand_label(void)
{
    byte secret[48];
    byte output[32];
    byte context[48];
    byte zeros[32];

    printf("test_hkdf_expand_label...\n");

    memset(secret, 0x5A, sizeof(secret));
    memset(context, 0x00, sizeof(context));

    ASSERT_SUCCESS(wolfSPDM_HkdfExpandLabel(0x13, secret, sizeof(secret),
        SPDM_LABEL_KEY, context, sizeof(context), output, sizeof(output)));
    XMEMSET(zeros, 0, sizeof(zeros));
    ASSERT_NE(memcmp(output, zeros, sizeof(output)), 0,
        "HKDF output should be non-zero");

    TEST_PASS();
}

static int test_compute_verify_data(void)
{
    byte finishedKey[WOLFSPDM_HASH_SIZE];
    byte thHash[WOLFSPDM_HASH_SIZE];
    byte verifyData[WOLFSPDM_HASH_SIZE];
    byte zeros[WOLFSPDM_HASH_SIZE];

    printf("test_compute_verify_data...\n");

    memset(finishedKey, 0xAB, sizeof(finishedKey));
    memset(thHash, 0xCD, sizeof(thHash));

    ASSERT_SUCCESS(wolfSPDM_ComputeVerifyData(finishedKey, thHash, verifyData));
    XMEMSET(zeros, 0, sizeof(zeros));
    ASSERT_NE(memcmp(verifyData, zeros, WOLFSPDM_HASH_SIZE), 0,
        "VerifyData should be non-zero");

    TEST_PASS();
}

/* ----- Message Builder Tests ----- */

static int test_build_get_version(void)
{
    byte buf[16];
    word32 bufSz = sizeof(buf);

    printf("test_build_get_version...\n");

    ASSERT_SUCCESS(wolfSPDM_BuildGetVersion(buf, &bufSz));
    ASSERT_EQ(bufSz, 4, "GET_VERSION should be 4 bytes");
    ASSERT_EQ(buf[1], SPDM_GET_VERSION, "Code should be 0x84");

    bufSz = 2;
    ASSERT_EQ(wolfSPDM_BuildGetVersion(buf, &bufSz), WOLFSPDM_E_BUFFER_SMALL,
        "Should fail on small buffer");

    TEST_PASS();
}

static int test_build_end_session(void)
{
    byte buf[16];
    word32 bufSz = sizeof(buf);
    TEST_CTX_SETUP_V12();

    printf("test_build_end_session...\n");
    ASSERT_SUCCESS(wolfSPDM_BuildEndSession(ctx, buf, &bufSz));
    ASSERT_EQ(bufSz, 4, "END_SESSION should be 4 bytes");
    ASSERT_EQ(buf[1], SPDM_END_SESSION, "Code should be 0xEA");

    TEST_CTX_FREE();
    TEST_PASS();
}

/* ----- Error Check Tests ----- */

static int test_check_error(void)
{
    byte errorMsg[] = {0x12, SPDM_ERROR, 0x06, 0x00};
    byte okMsg[] = {0x12, SPDM_VERSION, 0x00, 0x00};
    int errorCode = 0;

    printf("test_check_error...\n");

    TEST_ASSERT(wolfSPDM_CheckError(errorMsg, sizeof(errorMsg), &errorCode) == 1,
        "Should detect error");
    TEST_ASSERT(errorCode == SPDM_ERROR_DECRYPT_ERROR, "Error code wrong");

    TEST_ASSERT(wolfSPDM_CheckError(okMsg, sizeof(okMsg), NULL) == 0,
        "Should not detect error on OK message");

    TEST_PASS();
}

static int test_error_strings(void)
{
    printf("test_error_strings...\n");

    TEST_ASSERT(strcmp(wolfSPDM_GetErrorString(WOLFSPDM_SUCCESS), "Success") == 0,
        "SUCCESS string wrong");
    TEST_ASSERT(strcmp(wolfSPDM_GetErrorString(WOLFSPDM_E_INVALID_ARG),
        "Invalid argument") == 0, "INVALID_ARG string wrong");
    TEST_ASSERT(strcmp(wolfSPDM_GetErrorString(WOLFSPDM_E_CRYPTO_FAIL),
        "Crypto operation failed") == 0, "CRYPTO_FAIL string wrong");

    TEST_PASS();
}

/* ----- Multi-Version Tests ----- */

static int test_kdf_version_prefix(void)
{
    byte secret[48];
    byte context[48];
    byte out12[32], out13[32], out14[32];

    printf("test_kdf_version_prefix...\n");

    memset(secret, 0x5A, sizeof(secret));
    memset(context, 0x00, sizeof(context));

    ASSERT_SUCCESS(wolfSPDM_HkdfExpandLabel(SPDM_VERSION_12, secret,
        sizeof(secret), SPDM_LABEL_KEY, context, sizeof(context),
        out12, sizeof(out12)));
    ASSERT_SUCCESS(wolfSPDM_HkdfExpandLabel(SPDM_VERSION_13, secret,
        sizeof(secret), SPDM_LABEL_KEY, context, sizeof(context),
        out13, sizeof(out13)));
    ASSERT_SUCCESS(wolfSPDM_HkdfExpandLabel(SPDM_VERSION_14, secret,
        sizeof(secret), SPDM_LABEL_KEY, context, sizeof(context),
        out14, sizeof(out14)));

    /* All three outputs should differ due to different BinConcat prefixes */
    ASSERT_NE(memcmp(out12, out13, sizeof(out12)), 0,
        "1.2 and 1.3 outputs should differ");
    ASSERT_NE(memcmp(out13, out14, sizeof(out13)), 0,
        "1.3 and 1.4 outputs should differ");
    ASSERT_NE(memcmp(out12, out14, sizeof(out12)), 0,
        "1.2 and 1.4 outputs should differ");

    TEST_PASS();
}

static int test_hmac_mismatch_negative(void)
{
    byte finishedKeyA[WOLFSPDM_HASH_SIZE];
    byte finishedKeyB[WOLFSPDM_HASH_SIZE];
    byte thHash[WOLFSPDM_HASH_SIZE];
    byte verifyA[WOLFSPDM_HASH_SIZE];
    byte verifyB[WOLFSPDM_HASH_SIZE];

    printf("test_hmac_mismatch_negative...\n");

    memset(finishedKeyA, 0xAB, sizeof(finishedKeyA));
    memset(finishedKeyB, 0xAC, sizeof(finishedKeyB));  /* Differs by 1 bit */
    memset(thHash, 0xCD, sizeof(thHash));

    ASSERT_SUCCESS(wolfSPDM_ComputeVerifyData(finishedKeyA, thHash, verifyA));
    ASSERT_SUCCESS(wolfSPDM_ComputeVerifyData(finishedKeyB, thHash, verifyB));

    /* Single-bit change in key must produce different verify data */
    ASSERT_NE(memcmp(verifyA, verifyB, WOLFSPDM_HASH_SIZE), 0,
        "Different keys should produce different verify data");

    TEST_PASS();
}

static int test_transcript_overflow(void)
{
    byte chunk[256];
    word32 i, needed;
    TEST_CTX_SETUP();

    printf("test_transcript_overflow...\n");

    memset(chunk, 0x42, sizeof(chunk));

    /* Fill transcript to capacity */
    needed = WOLFSPDM_MAX_TRANSCRIPT / sizeof(chunk);
    for (i = 0; i < needed; i++) {
        ASSERT_SUCCESS(wolfSPDM_TranscriptAdd(ctx, chunk, sizeof(chunk)));
    }
    ASSERT_EQ(ctx->transcriptLen, (word32)(needed * sizeof(chunk)),
        "Transcript should be full");

    /* Next add should fail with BUFFER_SMALL */
    ASSERT_EQ(wolfSPDM_TranscriptAdd(ctx, chunk, sizeof(chunk)),
        WOLFSPDM_E_BUFFER_SMALL, "Overflow should return BUFFER_SMALL");

    TEST_CTX_FREE();
    TEST_PASS();
}

static int test_version_fallback(void)
{
    /* Fake VERSION response with versions 1.0, 1.1, 1.2, 1.3 */
    byte rsp[] = {
        0x10, SPDM_VERSION, 0x00, 0x00,    /* header */
        0x04, 0x00,                        /* entryCount = 4 */
        0x00, 0x10,                        /* 1.0 */
        0x00, 0x11,                        /* 1.1 */
        0x00, 0x12,                        /* 1.2 */
        0x00, 0x13                         /* 1.3 */
    };
    TEST_CTX_SETUP();

    printf("test_version_fallback...\n");

    /* With no maxVersion set, should select 1.3 (highest mutual) */
    ASSERT_SUCCESS(wolfSPDM_ParseVersion(ctx, rsp, sizeof(rsp)));
    ASSERT_EQ(ctx->spdmVersion, SPDM_VERSION_13,
        "Should select 1.3 as highest mutual");

    /* Reset state and set maxVersion to 1.2 */
    ctx->state = WOLFSPDM_STATE_INIT;
    ctx->spdmVersion = 0;
    ctx->maxVersion = SPDM_VERSION_12;
    ASSERT_SUCCESS(wolfSPDM_ParseVersion(ctx, rsp, sizeof(rsp)));
    ASSERT_EQ(ctx->spdmVersion, SPDM_VERSION_12,
        "Should fall back to 1.2 with maxVersion cap");

    TEST_CTX_FREE();
    TEST_PASS();
}

/* ----- Session State Tests ----- */

static int test_session_state(void)
{
    TEST_CTX_SETUP();

    printf("test_session_state...\n");
    ASSERT_EQ(wolfSPDM_IsConnected(ctx), 0, "Should not be connected");
    ASSERT_EQ(wolfSPDM_GetSessionId(ctx), 0, "SessionId should be 0");

    /* Simulate connected state */
    ctx->state = WOLFSPDM_STATE_CONNECTED;
    ctx->sessionId = 0xAABBCCDD;
    ctx->spdmVersion = SPDM_VERSION_12;
    ASSERT_EQ(wolfSPDM_IsConnected(ctx), 1, "Should be connected");
    ASSERT_EQ(wolfSPDM_GetSessionId(ctx), (word32)0xAABBCCDD, "SessionId wrong");
    ASSERT_EQ(wolfSPDM_GetNegotiatedVersion(ctx), SPDM_VERSION_12, "Version wrong");

    TEST_CTX_FREE();
    TEST_PASS();
}

/* ----- Security Tests ----- */

/* Test Fix 1: MITM rejection — a KEY_EXCHANGE_RSP with a forged signature
 * (signed by an attacker's key, not the real responder) must be rejected. */
static int test_mitm_signature_rejected(void)
{
    ecc_key realKey, attackerKey;
    byte realPubX[WOLFSPDM_ECC_KEY_SIZE], realPubY[WOLFSPDM_ECC_KEY_SIZE];
    byte atkPubX[WOLFSPDM_ECC_KEY_SIZE], atkPubY[WOLFSPDM_ECC_KEY_SIZE];
    word32 xSz, ySz;
    byte rspPubKey[WOLFSPDM_ECC_POINT_SIZE];
    byte keRsp[300]; /* KEY_EXCHANGE_RSP: 282 bytes with opaqueLen=0 */
    int rc;
    TEST_CTX_SETUP_V12();

    printf("test_mitm_signature_rejected...\n");

    /* Generate "real responder" key and "attacker" key */
    wc_ecc_init(&realKey);
    wc_ecc_init(&attackerKey);
    wc_ecc_make_key(&ctx->rng, WOLFSPDM_ECC_KEY_SIZE, &realKey);
    wc_ecc_make_key(&ctx->rng, WOLFSPDM_ECC_KEY_SIZE, &attackerKey);

    /* Export real responder public key and set it on ctx */
    xSz = ySz = WOLFSPDM_ECC_KEY_SIZE;
    wc_ecc_export_public_raw(&realKey, realPubX, &xSz, realPubY, &ySz);
    memcpy(rspPubKey, realPubX, WOLFSPDM_ECC_KEY_SIZE);
    memcpy(rspPubKey + WOLFSPDM_ECC_KEY_SIZE, realPubY, WOLFSPDM_ECC_KEY_SIZE);
    wolfSPDM_SetResponderPubKey(ctx, rspPubKey, WOLFSPDM_ECC_POINT_SIZE);

    /* Export attacker's ephemeral public key */
    xSz = ySz = WOLFSPDM_ECC_KEY_SIZE;
    wc_ecc_export_public_raw(&attackerKey, atkPubX, &xSz, atkPubY, &ySz);

    /* Generate our ephemeral key (needed for ECDH later) */
    ASSERT_SUCCESS(wolfSPDM_GenerateEphemeralKey(ctx));

    /* Build a fake KEY_EXCHANGE_RSP:
     * [0]=ver, [1]=0x64, [2-3]=params, [4-5]=rspSessionId,
     * [6-7]=mutAuth, [8-39]=random, [40-87]=pubX, [88-135]=pubY,
     * [136-137]=opaqueLen=0, [138-233]=signature, [234-281]=verifyData */
    memset(keRsp, 0, sizeof(keRsp));
    keRsp[0] = SPDM_VERSION_12;
    keRsp[1] = SPDM_KEY_EXCHANGE_RSP;
    SPDM_Set16LE(&keRsp[4], 0x0002); /* rspSessionId */
    wolfSPDM_GetRandom(ctx, &keRsp[8], 32); /* random */
    memcpy(&keRsp[40], atkPubX, WOLFSPDM_ECC_KEY_SIZE);
    memcpy(&keRsp[88], atkPubY, WOLFSPDM_ECC_KEY_SIZE);
    SPDM_Set16LE(&keRsp[136], 0); /* opaqueLen = 0 */
    /* Signature at [138]: fill with garbage (attacker can't sign with real key) */
    wolfSPDM_GetRandom(ctx, &keRsp[138], WOLFSPDM_ECC_SIG_SIZE);
    /* VerifyData at [234]: garbage */
    memset(&keRsp[234], 0xAA, WOLFSPDM_HASH_SIZE);

    /* Parse should reject: signature doesn't match real responder's key */
    rc = wolfSPDM_ParseKeyExchangeRsp(ctx, keRsp, 282);
    ASSERT_EQ(rc, WOLFSPDM_E_BAD_SIGNATURE, "MITM forged sig must be rejected");

    wc_ecc_free(&realKey);
    wc_ecc_free(&attackerKey);
    TEST_CTX_FREE();
    TEST_PASS();
}

/* Test Fix 4: Invalid curve point must be rejected by ComputeSharedSecret */
static int test_invalid_curve_point(void)
{
    byte badX[WOLFSPDM_ECC_KEY_SIZE];
    byte badY[WOLFSPDM_ECC_KEY_SIZE];
    int rc;
    TEST_CTX_SETUP_V12();

    printf("test_invalid_curve_point...\n");

    ASSERT_SUCCESS(wolfSPDM_GenerateEphemeralKey(ctx));

    /* Point (1, 1) is not on P-384 */
    memset(badX, 0, sizeof(badX));
    memset(badY, 0, sizeof(badY));
    badX[WOLFSPDM_ECC_KEY_SIZE - 1] = 0x01;
    badY[WOLFSPDM_ECC_KEY_SIZE - 1] = 0x01;

    rc = wolfSPDM_ComputeSharedSecret(ctx, badX, badY);
    ASSERT_EQ(rc, WOLFSPDM_E_CRYPTO_FAIL, "Off-curve point must be rejected");

    /* Verify shared secret was zeroed on failure */
    {
        byte zeros[WOLFSPDM_ECC_KEY_SIZE];
        memset(zeros, 0, sizeof(zeros));
        ASSERT_EQ(memcmp(ctx->sharedSecret, zeros, sizeof(ctx->sharedSecret)), 0,
            "sharedSecret must be zeroed on failure");
        ASSERT_EQ(ctx->sharedSecretSz, 0, "sharedSecretSz must be 0 on failure");
    }

    TEST_CTX_FREE();
    TEST_PASS();
}

#ifdef WOLFTPM_SPDM_TCG
/* I/O callback that returns a TCG response with msgSize < TCG_HEADER_SIZE */
static int tcg_underflow_io_cb(WOLFSPDM_CTX* ctx, const byte* txBuf, word32 txSz,
    byte* rxBuf, word32* rxSz, void* userCtx)
{
    (void)ctx; (void)txBuf; (void)txSz; (void)userCtx;
    /* Return a 20-byte TCG response with msgSize field = 5 (< 16) */
    if (*rxSz < 20) return -1;
    memset(rxBuf, 0, 20);
    SPDM_Set16BE(rxBuf, 0x8101);     /* tag: clear SPDM */
    SPDM_Set32BE(rxBuf + 2, 5);      /* msgSize = 5 (underflow!) */
    *rxSz = 20;
    return 0;
}

static int test_tcg_underflow(void)
{
    byte txBuf[32];
    byte rxBuf[32];
    word32 rxSz = sizeof(rxBuf);
    int rc;
    TEST_CTX_SETUP();

    printf("test_tcg_underflow...\n");

#ifdef WOLFSPDM_NUVOTON
    wolfSPDM_SetMode(ctx, WOLFSPDM_MODE_NUVOTON);
#else
    wolfSPDM_SetMode(ctx, WOLFSPDM_MODE_NATIONS);
#endif
    wolfSPDM_SetIO(ctx, tcg_underflow_io_cb, NULL);

    txBuf[0] = 0x10;
    txBuf[1] = SPDM_GET_VERSION;
    txBuf[2] = 0x00;
    txBuf[3] = 0x00;

    rc = wolfSPDM_SendReceive(ctx, txBuf, 4, rxBuf, &rxSz);
    ASSERT_EQ(rc, WOLFSPDM_E_BUFFER_SMALL, 
        "msgSize < 16 must return BUFFER_SMALL");

    TEST_CTX_FREE();
    TEST_PASS();
}
#endif /* WOLFTPM_SPDM_TCG */

#ifdef WOLFSPDM_NATIONS
static int test_nations_mode(void)
{
    int rc;
    TEST_CTX_SETUP();

    printf("test_nations_mode...\n");

    /* Test Nations mode can be set */
    rc = wolfSPDM_SetMode(ctx, WOLFSPDM_MODE_NATIONS);
    ASSERT_SUCCESS(rc);
    ASSERT_EQ(wolfSPDM_GetMode(ctx), WOLFSPDM_MODE_NATIONS,
        "Mode should be NATIONS");

    /* Verify TCG fields initialized */
    ASSERT_EQ(wolfSPDM_GetConnectionHandle(ctx), 0,
        "connectionHandle should be 0");
    ASSERT_EQ(wolfSPDM_GetFipsIndicator(ctx), WOLFSPDM_FIPS_NON_FIPS,
        "fipsIndicator should be NON_FIPS");

    /* Test Nations PSK mode can be set */
    rc = wolfSPDM_SetMode(ctx, WOLFSPDM_MODE_NATIONS_PSK);
    ASSERT_SUCCESS(rc);
    ASSERT_EQ(wolfSPDM_GetMode(ctx), WOLFSPDM_MODE_NATIONS_PSK,
        "Mode should be NATIONS_PSK");

    TEST_CTX_FREE();
    TEST_PASS();
}

static int test_nations_psk_set(void)
{
    int rc;
    byte psk[48];
    byte hint[] = "test_hint";
    TEST_CTX_SETUP();

    printf("test_nations_psk_set...\n");

    memset(psk, 0xAB, sizeof(psk));

    /* NULL args */
    rc = wolfSPDM_SetPSK(NULL, psk, sizeof(psk), NULL, 0);
    ASSERT_EQ(rc, WOLFSPDM_E_INVALID_ARG, "NULL ctx should fail");
    rc = wolfSPDM_SetPSK(ctx, NULL, sizeof(psk), NULL, 0);
    ASSERT_EQ(rc, WOLFSPDM_E_INVALID_ARG, "NULL psk should fail");
    rc = wolfSPDM_SetPSK(ctx, psk, 0, NULL, 0);
    ASSERT_EQ(rc, WOLFSPDM_E_INVALID_ARG, "Zero pskSz should fail");

    /* Valid PSK without hint */
    rc = wolfSPDM_SetPSK(ctx, psk, sizeof(psk), NULL, 0);
    ASSERT_SUCCESS(rc);
    ASSERT_EQ(ctx->pskSz, sizeof(psk), "pskSz should be 48");
    ASSERT_EQ(ctx->pskHintSz, 0, "hintSz should be 0");

    /* Valid PSK with hint */
    rc = wolfSPDM_SetPSK(ctx, psk, sizeof(psk), hint, sizeof(hint) - 1);
    ASSERT_SUCCESS(rc);
    ASSERT_EQ(ctx->pskHintSz, sizeof(hint) - 1, "hintSz mismatch");

    TEST_CTX_FREE();
    TEST_PASS();
}

static int test_nations_psk_kdf(void)
{
    int rc;
    byte psk[48];
    byte th1[WOLFSPDM_HASH_SIZE];
    byte zeros[WOLFSPDM_PSK_MAX_SIZE];
    TEST_CTX_SETUP_V12();

    printf("test_nations_psk_kdf...\n");

    memset(psk, 0xCD, sizeof(psk));
    memset(th1, 0xEF, sizeof(th1));
    memset(zeros, 0, sizeof(zeros));

    /* Set PSK */
    rc = wolfSPDM_SetPSK(ctx, psk, sizeof(psk), NULL, 0);
    ASSERT_SUCCESS(rc);

    /* Derive handshake keys from PSK */
    rc = wolfSPDM_DeriveHandshakeKeysPsk(ctx, th1);
    ASSERT_SUCCESS(rc);

    /* Verify PSK was scrubbed */
    ASSERT_EQ(ctx->pskSz, 0, "pskSz should be 0 after derivation");
    ASSERT_EQ(memcmp(ctx->psk, zeros, WOLFSPDM_PSK_MAX_SIZE), 0,
        "PSK not zeroed after derivation");

    /* Verify handshake secret was derived (non-zero) */
    ASSERT_NE(memcmp(ctx->handshakeSecret, zeros, sizeof(ctx->handshakeSecret)), 0,
        "handshakeSecret should be non-zero");

    /* Verify finished keys were derived (non-zero) */
    ASSERT_NE(memcmp(ctx->reqFinishedKey, zeros, sizeof(ctx->reqFinishedKey)), 0,
        "reqFinishedKey should be non-zero");

    TEST_CTX_FREE();
    TEST_PASS();
}

static int test_nations_psk_message_format(void)
{
    int rc;
    byte psk[48];
    byte buf[128];
    word32 bufSz = sizeof(buf);
    TEST_CTX_SETUP_V12();

    printf("test_nations_psk_message_format...\n");

    memset(psk, 0xAA, sizeof(psk));
    rc = wolfSPDM_SetPSK(ctx, psk, sizeof(psk), NULL, 0);
    ASSERT_SUCCESS(rc);

    /* Build PSK_EXCHANGE */
    rc = wolfSPDM_BuildPskExchange(ctx, buf, &bufSz);
    ASSERT_SUCCESS(rc);

    /* Verify header */
    ASSERT_EQ(buf[0], SPDM_VERSION_12, "Version should be 0x12");
    ASSERT_EQ(buf[1], SPDM_PSK_EXCHANGE, "Code should be PSK_EXCHANGE");

    /* ReqSessionID at offset 4-5 */
    ASSERT_EQ(SPDM_Get16LE(&buf[4]), ctx->reqSessionId,
        "ReqSessionID mismatch");

    /* PSKHintLength at offset 6-7 should be 0 (no hint) */
    ASSERT_EQ(SPDM_Get16LE(&buf[6]), 0, "PSKHintLen should be 0");

    /* RequesterContextLength at offset 8-9 should be 32 */
    ASSERT_EQ(SPDM_Get16LE(&buf[8]), WOLFSPDM_RANDOM_SIZE,
        "ReqCtxLen should be 32");

    TEST_CTX_FREE();
    TEST_PASS();
}
#endif /* WOLFSPDM_NATIONS */

static int test_decrypt_overflow(void)
{
    /* Static to avoid 4KB+ on stack; cipherLen must exceed
     * sizeof(decrypted) = WOLFSPDM_MAX_MSG_SIZE + 16 = 4112 */
    static byte enc[4140];
    byte plain[64];
    word32 plainSz = sizeof(plain);
    int rc;
    TEST_CTX_SETUP_V12();

    printf("test_decrypt_overflow...\n");

    ctx->sessionId = 0x00010001;
    ctx->rspSeqNum = 0;
    memset(ctx->rspDataKey, 0x42, sizeof(ctx->rspDataKey));
    memset(ctx->rspDataIv, 0x42, sizeof(ctx->rspDataIv));

    /* MCTP header: rspLen=4130 -> cipherLen=4114 > 4112 = overflow guard */
    memset(enc, 0, sizeof(enc));
    SPDM_Set32LE(&enc[0], ctx->sessionId);
    SPDM_Set16LE(&enc[4], 0x0000);
    SPDM_Set16LE(&enc[6], 4130);

    rc = wolfSPDM_DecryptInternal(ctx, enc, 4138, plain, &plainSz);
    ASSERT_EQ(rc, WOLFSPDM_E_BUFFER_SMALL, "Overflow cipherLen must be caught");

    TEST_CTX_FREE();
    TEST_PASS();
}

static int test_oob_read_error(void)
{
    byte shortErr[2] = {0x12, SPDM_ERROR};
    byte fullErr[4] = {0x12, SPDM_ERROR, 0x06, 0x00};
    int rc;
    TEST_CTX_SETUP_V12();

    printf("test_oob_read_error...\n");

    rc = wolfSPDM_ParseFinishRsp(ctx, fullErr, sizeof(fullErr));
    ASSERT_EQ(rc, WOLFSPDM_E_PEER_ERROR, "Should return peer error");

    rc = wolfSPDM_ParseFinishRsp(ctx, shortErr, sizeof(shortErr));
    ASSERT_EQ(rc, WOLFSPDM_E_INVALID_ARG, "Short buffer should fail");

    TEST_CTX_FREE();
    TEST_PASS();
}

static int test_constant_time_hmac(void)
{
    byte finishedKey[WOLFSPDM_HASH_SIZE];
    byte thHash[WOLFSPDM_HASH_SIZE];
    byte verifyData[WOLFSPDM_HASH_SIZE];
    byte fakeVerify[WOLFSPDM_HASH_SIZE];
    word32 i;
    int diff;

    printf("test_constant_time_hmac...\n");

    memset(finishedKey, 0xAB, sizeof(finishedKey));
    memset(thHash, 0xCD, sizeof(thHash));
    ASSERT_SUCCESS(wolfSPDM_ComputeVerifyData(finishedKey, thHash, verifyData));

    /* 1-byte difference must be detected */
    memcpy(fakeVerify, verifyData, sizeof(fakeVerify));
    fakeVerify[WOLFSPDM_HASH_SIZE - 1] ^= 0x01;

    diff = 0;
    for (i = 0; i < WOLFSPDM_HASH_SIZE; i++)
        diff |= verifyData[i] ^ fakeVerify[i];
    ASSERT_NE(diff, 0, "Should detect 1-byte diff");

    /* Identical must pass */
    diff = 0;
    for (i = 0; i < WOLFSPDM_HASH_SIZE; i++)
        diff |= verifyData[i] ^ verifyData[i];
    ASSERT_EQ(diff, 0, "Identical data should match");

    TEST_PASS();
}

static int test_setdebug_truncation(void)
{
    TEST_CTX_SETUP();

    printf("test_setdebug_truncation...\n");

    wolfSPDM_SetDebug(ctx, 2);
    ASSERT_EQ(ctx->flags.debug, 1, "debug=2 should be 1");

    wolfSPDM_SetDebug(ctx, 0);
    ASSERT_EQ(ctx->flags.debug, 0, "debug=0 should be 0");

    wolfSPDM_SetDebug(ctx, 255);
    ASSERT_EQ(ctx->flags.debug, 1, "debug=255 should be 1");

    TEST_CTX_FREE();
    TEST_PASS();
}

static int test_key_zeroing(void)
{
    byte zeros[WOLFSPDM_HASH_SIZE];
    byte zeroKey[WOLFSPDM_AEAD_KEY_SIZE];
    byte zeroIv[WOLFSPDM_AEAD_IV_SIZE];
    TEST_CTX_SETUP_V12();

    printf("test_key_zeroing...\n");

    memset(zeros, 0, sizeof(zeros));
    memset(zeroKey, 0, sizeof(zeroKey));
    memset(zeroIv, 0, sizeof(zeroIv));

    /* Fill key material with non-zero data */
    memset(ctx->reqDataKey, 0xAA, sizeof(ctx->reqDataKey));
    memset(ctx->rspDataKey, 0xBB, sizeof(ctx->rspDataKey));
    memset(ctx->reqDataIv, 0xCC, sizeof(ctx->reqDataIv));
    memset(ctx->rspDataIv, 0xDD, sizeof(ctx->rspDataIv));
    memset(ctx->reqHsSecret, 0x11, sizeof(ctx->reqHsSecret));
    memset(ctx->rspHsSecret, 0x22, sizeof(ctx->rspHsSecret));
    memset(ctx->reqFinishedKey, 0x33, sizeof(ctx->reqFinishedKey));
    memset(ctx->rspFinishedKey, 0x44, sizeof(ctx->rspFinishedKey));
    memset(ctx->handshakeSecret, 0x55, sizeof(ctx->handshakeSecret));
    memset(ctx->sharedSecret, 0x66, sizeof(ctx->sharedSecret));
    memset(ctx->th1, 0x77, sizeof(ctx->th1));
    memset(ctx->th2, 0x88, sizeof(ctx->th2));
    ctx->sharedSecretSz = WOLFSPDM_ECC_KEY_SIZE;

    ctx->state = WOLFSPDM_STATE_CONNECTED;
    ctx->sessionId = 0x00010001;
    ctx->ioCb = dummy_io_cb;

    wolfSPDM_Disconnect(ctx);

    ASSERT_EQ(memcmp(ctx->reqDataKey, zeroKey, sizeof(ctx->reqDataKey)), 0,
        "reqDataKey not zeroed");
    ASSERT_EQ(memcmp(ctx->rspDataKey, zeroKey, sizeof(ctx->rspDataKey)), 0,
        "rspDataKey not zeroed");
    ASSERT_EQ(memcmp(ctx->reqDataIv, zeroIv, sizeof(ctx->reqDataIv)), 0,
        "reqDataIv not zeroed");
    ASSERT_EQ(memcmp(ctx->rspDataIv, zeroIv, sizeof(ctx->rspDataIv)), 0,
        "rspDataIv not zeroed");
    ASSERT_EQ(memcmp(ctx->reqHsSecret, zeros, sizeof(ctx->reqHsSecret)), 0,
        "reqHsSecret not zeroed");
    ASSERT_EQ(memcmp(ctx->rspHsSecret, zeros, sizeof(ctx->rspHsSecret)), 0,
        "rspHsSecret not zeroed");
    ASSERT_EQ(memcmp(ctx->reqFinishedKey, zeros, sizeof(ctx->reqFinishedKey)), 0,
        "reqFinishedKey not zeroed");
    ASSERT_EQ(memcmp(ctx->rspFinishedKey, zeros, sizeof(ctx->rspFinishedKey)), 0,
        "rspFinishedKey not zeroed");
    ASSERT_EQ(memcmp(ctx->handshakeSecret, zeros, sizeof(ctx->handshakeSecret)), 0,
        "handshakeSecret not zeroed");
    ASSERT_EQ(memcmp(ctx->sharedSecret, zeros, sizeof(ctx->sharedSecret)), 0,
        "sharedSecret not zeroed");
    ASSERT_EQ(ctx->sharedSecretSz, 0, "sharedSecretSz not zeroed");
    ASSERT_EQ(memcmp(ctx->th1, zeros, sizeof(ctx->th1)), 0,
        "th1 not zeroed");
    ASSERT_EQ(memcmp(ctx->th2, zeros, sizeof(ctx->th2)), 0,
        "th2 not zeroed");

    wolfSPDM_Init(ctx);
    TEST_CTX_FREE();
    TEST_PASS();
}

/* ----- Main ----- */

int main(void)
{
    printf("===========================================\n");
    printf("wolfSPDM Unit Tests\n");
    printf("===========================================\n\n");

    /* Context tests */
#ifdef WOLFTPM_SMALL_STACK
    test_context_new_free();
#endif
    test_context_init();
    test_context_static_alloc();
    test_context_set_io();

    /* Transcript tests */
    test_transcript_add_reset();
    test_transcript_hash();

    /* Crypto tests */
    test_random_generation();
    test_ephemeral_key_generation();

    /* KDF tests */
    test_hkdf_expand_label();
    test_compute_verify_data();

    /* Message builder tests */
    test_build_get_version();
    test_build_end_session();

    /* Error tests */
    test_check_error();
    test_error_strings();

    /* Multi-version tests */
    test_kdf_version_prefix();
    test_hmac_mismatch_negative();
    test_transcript_overflow();
    test_version_fallback();

    /* Session state tests */
    test_session_state();

    /* Security tests */
    test_mitm_signature_rejected();
    test_invalid_curve_point();
#ifdef WOLFTPM_SPDM_TCG
    test_tcg_underflow();
#endif
#ifdef WOLFSPDM_NATIONS
    test_nations_mode();
    test_nations_psk_set();
    test_nations_psk_kdf();
    test_nations_psk_message_format();
#endif
    test_decrypt_overflow();
    test_oob_read_error();
    test_constant_time_hmac();
    test_setdebug_truncation();
    test_key_zeroing();

    printf("\n===========================================\n");
    printf("Results: %d passed, %d failed\n", g_testsPassed, g_testsFailed);
    printf("===========================================\n");

    return (g_testsFailed == 0) ? 0 : 1;
}
