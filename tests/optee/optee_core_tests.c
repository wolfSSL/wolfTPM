/* optee_core_tests.c
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

/* End-to-end tests for the fwTPM OP-TEE trusted application: the port in
 * src/fwtpm/ports/optee and the real fwTPM core, with wolfCrypt built as
 * WOLFSSL_OPTEE, driven through the TA entry points on the host against the
 * mock TEE. Covers what the stubbed tests in fwtpm_optee_port_tests.c cannot:
 * per-session ownership of transient state inside the core, and the NV
 * journal kept in secure storage across TA instances. Built by
 * optee_core.mk. */

#include <wolftpm/tpm2_types.h>
#include <wolftpm/tpm2.h>
#include <wolftpm/fwtpm/fwtpm_optee.h>

#include "mock_tee.h"

#include <stdio.h>
#include <stdlib.h>

#define PERSISTENT_HANDLE 0x81000100u

static int failures;

#define CHECK(cond, msg) do {                                   \
    int ok_ = (cond) ? 1 : 0;                                   \
    printf("  %-58s %s\n", (msg), ok_ ? "passed" : "FAILED");   \
    if (!ok_) failures++;                                       \
} while (0)

typedef struct {
    byte buf[256];
    word32 len;
} Cmd;

static byte rsp[FWTPM_MAX_COMMAND_SIZE];
static word32 rspLen;

static void Put16(Cmd* c, word16 v)
{
    c->buf[c->len++] = (byte)(v >> 8);
    c->buf[c->len++] = (byte)v;
}

static void Put32(Cmd* c, word32 v)
{
    Put16(c, (word16)(v >> 16));
    Put16(c, (word16)v);
}

static word32 Get32(const byte* p)
{
    return ((word32)p[0] << 24) | ((word32)p[1] << 16) |
        ((word32)p[2] << 8) | (word32)p[3];
}

static void CmdStart(Cmd* c, word16 tag, word32 cc)
{
    c->len = 0;
    Put16(c, tag);
    Put32(c, 0); /* size, set by CmdEnd */
    Put32(c, cc);
}

/* Empty password authorization. */
static void CmdPwAuth(Cmd* c)
{
    Put32(c, 9);
    Put32(c, TPM_RS_PW);
    Put16(c, 0);
    c->buf[c->len++] = 0;
    Put16(c, 0);
}

static TEE_Result Send(void* sess, Cmd* c, size_t rspCap, uint32_t rspType)
{
    TEE_Param p[TEE_NUM_PARAMS];
    TEE_Result res;

    c->buf[2] = (byte)(c->len >> 24);
    c->buf[3] = (byte)(c->len >> 16);
    c->buf[4] = (byte)(c->len >> 8);
    c->buf[5] = (byte)c->len;

    XMEMSET(p, 0, sizeof(p));
    p[0].memref.buffer = c->buf;
    p[0].memref.size = c->len;
    p[1].memref.buffer = rsp;
    p[1].memref.size = rspCap;
    res = TA_InvokeCommandEntryPoint(sess, FWTPM_OPTEE_CMD_SUBMIT,
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, rspType,
            TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE), p);
    rspLen = (word32)p[1].memref.size;
    return res;
}

/* TPM response code, or a TEE failure as-is. */
static word32 Run(void* sess, Cmd* c)
{
    TEE_Result res = Send(sess, c, sizeof(rsp), TEE_PARAM_TYPE_MEMREF_OUTPUT);

    if (res != TEE_SUCCESS) {
        return res;
    }
    if (rspLen < TPM2_HEADER_SIZE) {
        return TEE_ERROR_GENERIC;
    }
    return Get32(rsp + 6);
}

static word32 Startup(void* sess, word16 type)
{
    Cmd c;

    CmdStart(&c, TPM_ST_NO_SESSIONS, TPM_CC_Startup);
    Put16(&c, type);
    return Run(sess, &c);
}

static word32 Shutdown(void* sess)
{
    Cmd c;

    CmdStart(&c, TPM_ST_NO_SESSIONS, TPM_CC_Shutdown);
    Put16(&c, TPM_SU_CLEAR);
    return Run(sess, &c);
}

/* ECC P-256 signing primary in the owner hierarchy. */
static word32 CreatePrimary(void* sess, word32* handle)
{
    Cmd c;
    word32 rc;

    CmdStart(&c, TPM_ST_SESSIONS, TPM_CC_CreatePrimary);
    Put32(&c, TPM_RH_OWNER);
    CmdPwAuth(&c);
    Put16(&c, 4);                       /* inSensitive */
    Put16(&c, 0);
    Put16(&c, 0);
    Put16(&c, 24);                      /* inPublic */
    Put16(&c, TPM_ALG_ECC);
    Put16(&c, TPM_ALG_SHA256);
    Put32(&c, TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent |
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_sign);
    Put16(&c, 0);                       /* authPolicy */
    Put16(&c, TPM_ALG_NULL);            /* symmetric */
    Put16(&c, TPM_ALG_ECDSA);
    Put16(&c, TPM_ALG_SHA256);
    Put16(&c, TPM_ECC_NIST_P256);
    Put16(&c, TPM_ALG_NULL);            /* kdf */
    Put16(&c, 0);                       /* unique.x */
    Put16(&c, 0);                       /* unique.y */
    Put16(&c, 0);                       /* outsideInfo */
    Put32(&c, 0);                       /* creationPCR */
    rc = Run(sess, &c);
    *handle = (rc == TPM_RC_SUCCESS) ? Get32(rsp + TPM2_HEADER_SIZE) : 0;
    return rc;
}

static word32 EvictControl(void* sess, word32 object, word32 persistent)
{
    Cmd c;

    CmdStart(&c, TPM_ST_SESSIONS, TPM_CC_EvictControl);
    Put32(&c, TPM_RH_OWNER);
    Put32(&c, object);
    CmdPwAuth(&c);
    Put32(&c, persistent);
    return Run(sess, &c);
}

/* Number of handles in the range starting at first, or -1. */
static int CountHandles(void* sess, word32 first)
{
    Cmd c;

    CmdStart(&c, TPM_ST_NO_SESSIONS, TPM_CC_GetCapability);
    Put32(&c, TPM_CAP_HANDLES);
    Put32(&c, first);
    Put32(&c, 32);
    if (Run(sess, &c) != TPM_RC_SUCCESS || rspLen < TPM2_HEADER_SIZE + 9) {
        return -1;
    }
    /* header, moreData, capability, count */
    return (int)Get32(rsp + TPM2_HEADER_SIZE + 5);
}

static void* Open(void)
{
    TEE_Param p[TEE_NUM_PARAMS];
    void* s = NULL;

    XMEMSET(p, 0, sizeof(p));
    if (TA_OpenSessionEntryPoint(0, p, &s) != TEE_SUCCESS) {
        return NULL;
    }
    return s;
}

static void test_session_ownership(void)
{
    void* a;
    void* b;
    void* c;
    word32 ha = 0;
    word32 hb = 0;
    TEE_Param p[TEE_NUM_PARAMS];

    printf("Per-session ownership in the core\n");
    MockTee_Reset();
    CHECK(TA_CreateEntryPoint() == TEE_SUCCESS, "TA created on empty storage");
    a = Open();
    b = Open();
    CHECK(Startup(a, TPM_SU_CLEAR) == TPM_RC_SUCCESS, "Startup(CLEAR)");
    CHECK(Startup(b, TPM_SU_CLEAR) == TPM_RC_INITIALIZE,
        "second client's Startup gets TPM_RC_INITIALIZE");

    CHECK(CreatePrimary(a, &ha) == TPM_RC_SUCCESS, "A creates a primary");
    CHECK(CreatePrimary(b, &hb) == TPM_RC_SUCCESS, "B creates a primary");
    CHECK(CountHandles(b, TRANSIENT_FIRST) == 2, "two transient objects");

    TA_CloseSessionEntryPoint(a);
    CHECK(CountHandles(b, TRANSIENT_FIRST) == 1,
        "closing A releases A's object only");

    c = Open();
    CHECK(CreatePrimary(c, &ha) == TPM_RC_SUCCESS, "C creates a primary");
    XMEMSET(p, 0, sizeof(p));
    CHECK(TA_InvokeCommandEntryPoint(c, FWTPM_OPTEE_CMD_RESET, 0, p) ==
        TEE_SUCCESS && CountHandles(b, TRANSIENT_FIRST) == 1,
        "CMD_RESET from C releases C's object only");

    TA_CloseSessionEntryPoint(c);
    TA_CloseSessionEntryPoint(b);
    TA_DestroyEntryPoint();
}

static void test_nv_persistence(void)
{
    void* s;
    byte* journal;
    byte* saved;
    size_t size = 0;
    byte otherKey[32];
    word32 handle = 0;

    printf("NV journal in secure storage across TA instances\n");
    MockTee_Reset();
    CHECK(TA_CreateEntryPoint() == TEE_SUCCESS, "TA created on empty storage");
    s = Open();
    CHECK(Startup(s, TPM_SU_CLEAR) == TPM_RC_SUCCESS &&
        CreatePrimary(s, &handle) == TPM_RC_SUCCESS &&
        EvictControl(s, handle, PERSISTENT_HANDLE) == TPM_RC_SUCCESS &&
        Shutdown(s) == TPM_RC_SUCCESS, "primary persisted, Shutdown(CLEAR)");
    TA_CloseSessionEntryPoint(s);
    TA_DestroyEntryPoint();

    CHECK(TA_CreateEntryPoint() == TEE_SUCCESS, "TA recreated");
    s = Open();
    CHECK(Startup(s, TPM_SU_CLEAR) == TPM_RC_SUCCESS, "Startup(CLEAR)");
    CHECK(CountHandles(s, PERSISTENT_FIRST) == 1,
        "persistent object survived the TA instance");
    CHECK(CountHandles(s, TRANSIENT_FIRST) == 0, "no transient objects");
    CHECK(Shutdown(s) == TPM_RC_SUCCESS, "Shutdown(CLEAR)");
    TA_CloseSessionEntryPoint(s);
    TA_DestroyEntryPoint();

    journal = MockTee_ObjectData(FWTPM_OPTEE_NV_OBJECT_ID, &size);
    saved = (byte*)malloc(size);
    if (journal == NULL || saved == NULL) {
        CHECK(0, "journal present");
        free(saved);
        return;
    }
    XMEMCPY(saved, journal, size);

    mockTeeFaults.deriveFail = 1;
    CHECK(TA_CreateEntryPoint() != TEE_SUCCESS,
        "PTA unavailable: TA refuses to start");
    journal = MockTee_ObjectData(FWTPM_OPTEE_NV_OBJECT_ID, NULL);
    CHECK(journal != NULL && XMEMCMP(journal, saved, size) == 0,
        "journal left untouched");
    mockTeeFaults.deriveFail = 0;

    CHECK(TA_CreateEntryPoint() == TEE_SUCCESS, "TA starts once it returns");
    s = Open();
    Startup(s, TPM_SU_CLEAR);
    CHECK(CountHandles(s, PERSISTENT_FIRST) == 1,
        "persistent object still there");
    TA_CloseSessionEntryPoint(s);
    TA_DestroyEntryPoint();

    XMEMSET(otherKey, 0x22, sizeof(otherKey));
    MockTee_SetDerivedKey(otherKey, sizeof(otherKey));
    CHECK(TA_CreateEntryPoint() == TEE_SUCCESS, "TA starts under another key");
    s = Open();
    Startup(s, TPM_SU_CLEAR);
    CHECK(CountHandles(s, PERSISTENT_FIRST) == 0,
        "journal that fails its MAC is not trusted");
    TA_CloseSessionEntryPoint(s);
    TA_DestroyEntryPoint();
    free(saved);
}

static void test_kernel_driver_shape(void)
{
    void* s;
    Cmd c;
    TEE_Result res;

    printf("Response buffer as the Linux driver passes it\n");
    MockTee_Reset();
    TA_CreateEntryPoint();
    s = Open();
    Startup(s, TPM_SU_CLEAR);
    CmdStart(&c, TPM_ST_NO_SESSIONS, TPM_CC_GetRandom);
    Put16(&c, 32);
    res = Send(s, &c, FWTPM_OPTEE_MIN_RSP_SIZE, TEE_PARAM_TYPE_MEMREF_INOUT);
    CHECK(res == TEE_SUCCESS && rspLen == TPM2_HEADER_SIZE + 2 + 32 &&
        Get32(rsp + 6) == TPM_RC_SUCCESS, "GetRandom through a 4096 INOUT");
    TA_CloseSessionEntryPoint(s);
    TA_DestroyEntryPoint();
}

int main(void)
{
    test_session_ownership();
    test_nv_persistence();
    test_kernel_driver_shape();
    printf("fwTPM OP-TEE core tests: %s (%d failure%s)\n",
        failures == 0 ? "PASSED" : "FAILED", failures,
        failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
