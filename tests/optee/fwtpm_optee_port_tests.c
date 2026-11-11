/* fwtpm_optee_port_tests.c
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

/* Tests for the OP-TEE trusted application port in src/fwtpm/ports/optee,
 * run on the host against the mock TEE in mock_tee.c. The fwTPM core is
 * replaced by the stubs below, so what is tested is the port itself: which
 * NV integrity key it settles on and when it refuses to start, how it
 * presents secure storage to the journal, and how the entry points map TEE
 * sessions and buffers onto the core. optee_core_tests.c runs the same
 * port against the real core. */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2_types.h>

#if defined(WOLFTPM_FWTPM) && defined(WOLFSSL_OPTEE)

#include <wolftpm/fwtpm/fwtpm_optee.h>
#include <wolftpm/fwtpm/fwtpm_command.h>

#include "mock_tee.h"

#include <stdio.h>

/* --- fwTPM core stubs --- */

#define MAX_FLUSHED 16

static FWTPM_NV_HAL stubHal;
static int stubInitRc;
static int stubProcessCalls;
static int stubProcessRc;
static int stubRspLen = 64;
static UINT32 stubProcessClient;
static int stubBuffersClean;
static UINT32 stubFlushed[MAX_FLUSHED];
static int stubFlushCount;

int FWTPM_NV_SetHAL(FWTPM_CTX* ctx, FWTPM_NV_HAL* hal)
{
    (void)ctx;
    stubHal = *hal;
    return TPM_RC_SUCCESS;
}

int FWTPM_Clock_SetHAL(FWTPM_CTX* ctx, UINT64 (*clockMs)(void* ctx),
    void* clockCtx)
{
    (void)ctx;
    (void)clockMs;
    (void)clockCtx;
    return TPM_RC_SUCCESS;
}

int FWTPM_Init(FWTPM_CTX* ctx)
{
    (void)ctx;
    return stubInitRc;
}

int FWTPM_Cleanup(FWTPM_CTX* ctx)
{
    (void)ctx;
    return TPM_RC_SUCCESS;
}

void FWTPM_SetCommandClient(FWTPM_CTX* ctx, UINT32 clientId)
{
    ctx->clientId = clientId;
}

void FWTPM_FlushCommandClient(FWTPM_CTX* ctx, UINT32 clientId)
{
    (void)ctx;
    if (stubFlushCount < MAX_FLUSHED) {
        stubFlushed[stubFlushCount++] = clientId;
    }
}

int FWTPM_ProcessCommand(FWTPM_CTX* ctx, const byte* cmdBuf, int cmdSize,
    byte* rspBuf, int* rspSize, int locality)
{
    int i;

    (void)cmdBuf;
    (void)cmdSize;
    (void)locality;
    stubProcessCalls++;
    stubProcessClient = ctx->clientId;
    /* The previous command's response must not still be in the staging
     * buffer when the next command runs. */
    stubBuffersClean = 1;
    for (i = 0; i < *rspSize; i++) {
        if (rspBuf[i] != 0) {
            stubBuffersClean = 0;
            break;
        }
    }
    if (stubProcessRc != TPM_RC_SUCCESS) {
        return stubProcessRc;
    }
    XMEMSET(rspBuf, 0x5A, (size_t)stubRspLen);
    *rspSize = stubRspLen;
    return TPM_RC_SUCCESS;
}

void TPM2_ForceZero(void* mem, word32 len)
{
    volatile byte* p = (volatile byte*)mem;

    while (len-- > 0) {
        *p++ = 0;
    }
}

/* --- harness --- */

static int failures;

#define CHECK(cond, msg) do {                                   \
    int ok_ = (cond) ? 1 : 0;                                   \
    printf("  %-58s %s\n", (msg), ok_ ? "passed" : "FAILED");   \
    if (!ok_) failures++;                                       \
} while (0)

static FWTPM_CTX nvCtx;
static FWTPM_OPTEE_NV nv;
static const byte journalBytes[] = "journal";

static int NvStart(void)
{
    XMEMSET(&nvCtx, 0, sizeof(nvCtx));
    XMEMSET(&nv, 0, sizeof(nv));
    XMEMSET(&stubHal, 0, sizeof(stubHal));
    return FWTPM_OPTEE_NV_SetHAL(&nvCtx, &nv);
}

static int NvKey(byte* key)
{
    word32 sz = 0;
    int rc = stubHal.get_integrity_key(stubHal.ctx, key, &sz);

    return (rc == TPM_RC_SUCCESS && sz == WC_SHA256_DIGEST_SIZE) ? 0 : -1;
}

static int KeyObjectExists(void)
{
    return MockTee_ObjectData(FWTPM_OPTEE_KEY_OBJECT_ID, NULL) != NULL;
}

static void test_nv_key_selection(void)
{
    byte k1[WC_SHA256_DIGEST_SIZE];
    byte k2[WC_SHA256_DIGEST_SIZE];
    byte derived[WC_SHA256_DIGEST_SIZE];
    byte zero[WC_SHA256_DIGEST_SIZE];
    int rc;

    printf("NV integrity key selection\n");
    XMEMSET(derived, 0x11, sizeof(derived));
    XMEMSET(zero, 0, sizeof(zero));

    MockTee_Reset();
    MockTee_SetDerivedKey(derived, sizeof(derived));
    CHECK(NvStart() == TPM_RC_SUCCESS && NvKey(k1) == 0 &&
        XMEMCMP(k1, derived, sizeof(k1)) == 0,
        "first start uses the derived key");
    CHECK(!KeyObjectExists(), "no fallback key object with the PTA present");
    CHECK(stubHal.write(stubHal.ctx, 0, journalBytes,
        sizeof(journalBytes)) == TPM_RC_SUCCESS, "journal written");
    FWTPM_OPTEE_NV_Close(&nv);
    CHECK(XMEMCMP(nv.integrityKey, zero, sizeof(zero)) == 0,
        "close zeroizes the cached key");

    mockTeeFaults.deriveFail = 1;
    rc = NvStart();
    CHECK(rc != TPM_RC_SUCCESS,
        "derive failure with a journal refuses to start");
    CHECK(!KeyObjectExists(), "no fallback key created over a journal");
    mockTeeFaults.deriveFail = 0;
    CHECK(NvStart() == TPM_RC_SUCCESS && NvKey(k2) == 0 &&
        XMEMCMP(k1, k2, sizeof(k1)) == 0,
        "next start recovers the same key");

    mockTeeFaults.deriveFail = 1;
    CHECK(NvKey(k2) == 0 && XMEMCMP(k1, k2, sizeof(k1)) == 0,
        "key stays available when the PTA goes away after start");
    FWTPM_OPTEE_NV_Close(&nv);

    MockTee_Reset();
    mockTeeFaults.deriveFail = 1;
    CHECK(NvStart() == TPM_RC_SUCCESS && NvKey(k1) == 0 &&
        KeyObjectExists(), "no PTA, empty journal: fallback key recorded");
    stubHal.write(stubHal.ctx, 0, journalBytes, sizeof(journalBytes));
    FWTPM_OPTEE_NV_Close(&nv);
    CHECK(NvStart() == TPM_RC_SUCCESS && NvKey(k2) == 0 &&
        XMEMCMP(k1, k2, sizeof(k1)) == 0, "fallback key is stable");
    FWTPM_OPTEE_NV_Close(&nv);
    mockTeeFaults.deriveFail = 0;
    CHECK(NvStart() == TPM_RC_SUCCESS && NvKey(k2) == 0 &&
        XMEMCMP(k1, k2, sizeof(k1)) == 0,
        "PTA appearing later does not change the key");
    FWTPM_OPTEE_NV_Close(&nv);

    mockTeeFaults.openFailId = FWTPM_OPTEE_KEY_OBJECT_ID;
    mockTeeFaults.openFailResult = TEE_ERROR_BUSY;
    CHECK(NvStart() != TPM_RC_SUCCESS,
        "unreadable fallback key refuses to start");
    mockTeeFaults.openFailId = NULL;

    MockTee_Reset();
    mockTeeFaults.createFail = 1;
    CHECK(NvStart() != TPM_RC_SUCCESS,
        "no secure storage refuses to start");
}

static void test_nv_storage(void)
{
    byte buf[16];
    byte expect[16];
    byte* data;
    size_t size = 0;
    word32 maxSize;

    printf("NV secure storage access\n");
    MockTee_Reset();
    CHECK(NvStart() == TPM_RC_SUCCESS, "started");
    maxSize = nv.maxSize;

    XMEMSET(expect, 0xFF, sizeof(expect));
    CHECK(stubHal.read(stubHal.ctx, 0, buf, sizeof(buf)) == TPM_RC_SUCCESS &&
        XMEMCMP(buf, expect, sizeof(buf)) == 0,
        "never-written NV reads as erased");

    CHECK(stubHal.write(stubHal.ctx, 8, journalBytes, 4) == TPM_RC_SUCCESS,
        "write past the end of the stream");
    data = MockTee_ObjectData(FWTPM_OPTEE_NV_OBJECT_ID, &size);
    CHECK(data != NULL && size == 12 &&
        XMEMCMP(data, expect, 8) == 0 && XMEMCMP(data + 8, journalBytes, 4) == 0,
        "gap before it is filled as erased, not zero");

    CHECK(stubHal.read(stubHal.ctx, 8, buf, sizeof(buf)) == TPM_RC_SUCCESS &&
        XMEMCMP(buf, journalBytes, 4) == 0 &&
        XMEMCMP(buf + 4, expect, sizeof(buf) - 4) == 0,
        "short read is padded as erased");

    stubHal.write(stubHal.ctx, 0, journalBytes, 8);
    CHECK(stubHal.erase(stubHal.ctx, 2, 2) == TPM_RC_SUCCESS &&
        MockTee_ObjectData(FWTPM_OPTEE_NV_OBJECT_ID, &size) != NULL &&
        size == 12 && data[1] == journalBytes[1] && data[2] == 0xFF &&
        data[3] == 0xFF && data[4] == journalBytes[4],
        "erase inside the stream fills");
    CHECK(stubHal.erase(stubHal.ctx, 4, 64) == TPM_RC_SUCCESS &&
        MockTee_ObjectData(FWTPM_OPTEE_NV_OBJECT_ID, &size) != NULL &&
        size == 4, "erase to the end truncates");

    CHECK(stubHal.read(stubHal.ctx, maxSize - 4, buf, 8) != TPM_RC_SUCCESS,
        "read beyond the NV size refused");
    CHECK(stubHal.write(stubHal.ctx, maxSize, journalBytes, 1) !=
        TPM_RC_SUCCESS, "write beyond the NV size refused");
    CHECK(stubHal.erase(stubHal.ctx, 0xFFFFFFF0u, 0x20) != TPM_RC_SUCCESS,
        "wrapping erase refused");
    FWTPM_OPTEE_NV_Close(&nv);
}

static byte cmd[16];
static byte rsp[FWTPM_MAX_COMMAND_SIZE + 64];

static TEE_Result Submit(void* sess, void* buf, size_t cap, uint32_t rspType,
    size_t* outSz)
{
    TEE_Param p[TEE_NUM_PARAMS];
    TEE_Result res;

    XMEMSET(p, 0, sizeof(p));
    XMEMSET(cmd, 0x80, sizeof(cmd));
    p[0].memref.buffer = cmd;
    p[0].memref.size = sizeof(cmd);
    p[1].memref.buffer = buf;
    p[1].memref.size = cap;
    res = TA_InvokeCommandEntryPoint(sess, FWTPM_OPTEE_CMD_SUBMIT,
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, rspType,
            TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE), p);
    if (outSz != NULL) {
        *outSz = p[1].memref.size;
    }
    return res;
}

static int WasFlushed(UINT32 id)
{
    int i;

    for (i = 0; i < stubFlushCount; i++) {
        if (stubFlushed[i] == id) {
            return 1;
        }
    }
    return 0;
}

static void test_ta_sessions(void)
{
    TEE_Param p[TEE_NUM_PARAMS];
    void* a = NULL;
    void* b = NULL;
    size_t out;

    printf("TA sessions\n");
    MockTee_Reset();
    XMEMSET(p, 0, sizeof(p));
    CHECK(TA_CreateEntryPoint() == TEE_SUCCESS, "TA created");
    CHECK(TA_OpenSessionEntryPoint(0, p, &a) == TEE_SUCCESS &&
        TA_OpenSessionEntryPoint(0, p, &b) == TEE_SUCCESS && a != b,
        "each session gets its own client id");

    Submit(a, rsp, sizeof(rsp), TEE_PARAM_TYPE_MEMREF_OUTPUT, &out);
    CHECK(stubProcessClient == (UINT32)(size_t)a, "A's command runs as A");
    Submit(b, rsp, sizeof(rsp), TEE_PARAM_TYPE_MEMREF_OUTPUT, &out);
    CHECK(stubProcessClient == (UINT32)(size_t)b, "B's command runs as B");

    stubFlushCount = 0;
    CHECK(TA_InvokeCommandEntryPoint(b, FWTPM_OPTEE_CMD_RESET, 0, p) ==
        TEE_SUCCESS && stubFlushCount == 1 && WasFlushed((UINT32)(size_t)b),
        "CMD_RESET flushes only the caller");

    stubFlushCount = 0;
    TA_CloseSessionEntryPoint(a);
    CHECK(stubFlushCount == 1 && WasFlushed((UINT32)(size_t)a),
        "closing A flushes only A");
    TA_OpenSessionEntryPoint(0, p, &a);
    CHECK(a != b && (UINT32)(size_t)a != 0, "a reopened session is new");

    p[0].value.a = p[0].value.b = 0;
    CHECK(TA_InvokeCommandEntryPoint(b, FWTPM_OPTEE_CMD_GET_INFO,
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_NONE,
            TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE), p) == TEE_SUCCESS &&
        p[0].value.a == FWTPM_OPTEE_ABI_VERSION &&
        p[0].value.b == FWTPM_MAX_COMMAND_SIZE, "GET_INFO reports the ABI");
    CHECK(TA_InvokeCommandEntryPoint(b, 99, 0, p) == TEE_ERROR_NOT_SUPPORTED,
        "unknown command refused");

    TA_CloseSessionEntryPoint(a);
    TA_CloseSessionEntryPoint(b);
    TA_DestroyEntryPoint();

    stubInitRc = TPM_RC_FAILURE;
    CHECK(TA_CreateEntryPoint() != TEE_SUCCESS, "core init failure fails");
    stubInitRc = TPM_RC_SUCCESS;
    mockTeeFaults.createFail = 1;
    MockTee_DeleteObject(FWTPM_OPTEE_NV_OBJECT_ID);
    CHECK(TA_CreateEntryPoint() == TEE_ERROR_STORAGE_NOT_AVAILABLE,
        "no secure storage fails with STORAGE_NOT_AVAILABLE");
    mockTeeFaults.createFail = 0;
}

static void test_ta_buffers(void)
{
    TEE_Param p[TEE_NUM_PARAMS];
    void* s = NULL;
    size_t out = 0;
    size_t full = FWTPM_MAX_COMMAND_SIZE;
    int before;
    TEE_Result res;

    printf("TA command and response buffers\n");
    MockTee_Reset();
    XMEMSET(p, 0, sizeof(p));
    TA_CreateEntryPoint();
    TA_OpenSessionEntryPoint(0, p, &s);
    stubRspLen = 64;

    before = stubProcessCalls;
    res = Submit(s, rsp, 1024, TEE_PARAM_TYPE_MEMREF_OUTPUT, &out);
    CHECK(res == TEE_ERROR_SHORT_BUFFER && stubProcessCalls == before &&
        out == full, "small buffer refused before the command runs");
    before = stubProcessCalls;
    res = Submit(s, NULL, 0, TEE_PARAM_TYPE_MEMREF_OUTPUT, &out);
    CHECK(res == TEE_ERROR_SHORT_BUFFER && stubProcessCalls == before &&
        out == full, "size query reports the full size");
    before = stubProcessCalls;
    res = Submit(s, NULL, full, TEE_PARAM_TYPE_MEMREF_OUTPUT, &out);
    CHECK(res == TEE_ERROR_BAD_PARAMETERS && stubProcessCalls == before,
        "NULL response buffer refused");
    before = stubProcessCalls;
    res = Submit(s, rsp, full, TEE_PARAM_TYPE_MEMREF_INPUT, &out);
    CHECK(res == TEE_ERROR_BAD_PARAMETERS && stubProcessCalls == before,
        "wrong parameter types refused");

    before = stubProcessCalls;
    res = Submit(s, rsp, FWTPM_OPTEE_MIN_RSP_SIZE,
        TEE_PARAM_TYPE_MEMREF_INOUT, &out);
    CHECK(res == TEE_SUCCESS && stubProcessCalls == before + 1 && out == 64 &&
        rsp[0] == 0x5A, "kernel driver shape (4096, INOUT) works");
    res = Submit(s, rsp, full, TEE_PARAM_TYPE_MEMREF_OUTPUT, &out);
    CHECK(res == TEE_SUCCESS && stubBuffersClean,
        "previous response not left in the staging buffer");

    if (full > FWTPM_OPTEE_MIN_RSP_SIZE) {
        stubRspLen = FWTPM_OPTEE_MIN_RSP_SIZE + 100;
        res = Submit(s, rsp, FWTPM_OPTEE_MIN_RSP_SIZE,
            TEE_PARAM_TYPE_MEMREF_INOUT, &out);
        CHECK(res == TEE_ERROR_SHORT_BUFFER && out == (size_t)stubRspLen,
            "oversized response reports the size it needs");
        res = Submit(s, rsp, full, TEE_PARAM_TYPE_MEMREF_OUTPUT, &out);
        CHECK(res == TEE_SUCCESS && out == (size_t)stubRspLen,
            "full-size buffer receives it");
        stubRspLen = 64;
    }

    stubProcessRc = TPM_RC_FAILURE;
    res = Submit(s, rsp, full, TEE_PARAM_TYPE_MEMREF_OUTPUT, &out);
    CHECK(res == TEE_ERROR_BAD_FORMAT, "core parse failure is BAD_FORMAT");
    stubProcessRc = TPM_RC_SUCCESS;

    XMEMSET(p, 0, sizeof(p));
    p[0].memref.buffer = cmd;
    p[0].memref.size = FWTPM_MAX_COMMAND_SIZE + 1;
    p[1].memref.buffer = rsp;
    p[1].memref.size = full;
    before = stubProcessCalls;
    res = TA_InvokeCommandEntryPoint(s, FWTPM_OPTEE_CMD_SUBMIT,
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
            TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE,
            TEE_PARAM_TYPE_NONE), p);
    CHECK(res == TEE_ERROR_BAD_PARAMETERS && stubProcessCalls == before,
        "oversized command refused");

    TA_CloseSessionEntryPoint(s);
    TA_DestroyEntryPoint();
}

int main(void)
{
    test_nv_key_selection();
    test_nv_storage();
    test_ta_sessions();
    test_ta_buffers();
    printf("fwTPM OP-TEE port tests: %s (%d failure%s)\n",
        failures == 0 ? "PASSED" : "FAILED", failures,
        failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}

#else

#include <stdio.h>

int main(void)
{
    printf("fwTPM OP-TEE port tests: skipped (needs WOLFTPM_FWTPM)\n");
    return 77;
}

#endif /* WOLFTPM_FWTPM && WOLFSSL_OPTEE */
