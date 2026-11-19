/* transient_unload_tests.c
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2_wrap.h>
#include <wolftpm/tpm2_packet.h>

#include <stdio.h>
#include <stdlib.h>

#define Fail(description, result) do {                                      \
    printf("\nERROR - %s line %d failed with:", __FILE__, __LINE__);        \
    printf("\n    expected: "); printf description;                         \
    printf("\n    result:   "); printf result; printf("\n\n");              \
    fflush(stdout);                                                         \
    abort();                                                                \
} while (0)
#define Assert(test, description, result) if (!(test)) Fail(description, result)
#define AssertInt(x, y, op, er) do {                                        \
    int _x = (int)(x);                                                       \
    int _y = (int)(y);                                                       \
    Assert(_x op _y, ("%s " #op " %s", #x, #y),                           \
        ("%d(0x%x) " #er " %d(0x%x)", _x, _x, _y, _y));                   \
} while (0)
#define AssertIntEQ(x, y) AssertInt(x, y, ==, !=)

#define TEST_MAX_PAGES   3
#define TEST_PAGE_HANDLES 4
#define TEST_MAX_FLUSHES (2 * MAX_HANDLE_NUM)
#define TEST_POLICY_SESSION (POLICY_SESSION_FIRST + 2)
#define TEST_CANNED_MAX   128

/* Scripted TPM_CAP_HANDLES pages and a record of what the wrapper sent */
static struct {
    TPM_HANDLE page[TEST_MAX_PAGES][TEST_PAGE_HANDLES];
    int pageCount[TEST_MAX_PAGES];
    byte pageMore[TEST_MAX_PAGES];
    TPM_RC pageRc[TEST_MAX_PAGES];
    int pages;
    TPM_HANDLE queried[TEST_MAX_PAGES];
    TPM_HANDLE flushed[TEST_MAX_FLUSHES];
    int flushes;
    TPM_HANDLE flushFail;
    /* a response returned as is, whatever the command */
    byte canned[TEST_CANNED_MAX];
    int cannedSz;
} script;

/* Exercise the real wrapper, command builders and response parser without a
 * TPM or socket. */
#if defined(WOLFTPM_LINUX_DEV)
    #define TPM2_LINUX_SendCommand test_unload_send
#elif defined(WOLFTPM_LINUX_DEV_AUTODETECT)
    #define TPM2_LINUX_AUTODETECT_SendCommand test_unload_send
#elif defined(WOLFTPM_SWTPM)
    #define TPM2_SWTPM_SendCommand test_unload_send
#elif defined(WOLFTPM_WINAPI)
    #define TPM2_WinApi_SendCommand test_unload_send
#else
    #define TPM2_TIS_SendCommand test_unload_send
#endif
#include "../src/tpm2.c"

static UINT32 test_get_u32(const byte* buf)
{
    return ((UINT32)buf[0] << 24) | ((UINT32)buf[1] << 16) |
        ((UINT32)buf[2] << 8) | buf[3];
}

int test_unload_send(TPM2_CTX* ctx, TPM2_Packet* packet)
{
    TPM2_Packet rsp;
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 code = test_get_u32(packet->buf + 6);
    /* the response is built over the command, so read its arguments first */
    UINT32 arg0 = test_get_u32(packet->buf + TPM2_HEADER_SIZE);
    UINT32 arg1 = test_get_u32(packet->buf + TPM2_HEADER_SIZE + 4);
    int page = script.pages;
    int i;

    if (script.cannedSz > 0) {
        XMEMCPY(packet->buf, script.canned, script.cannedSz);
        packet->size = script.cannedSz;
        return TPM_RC_SUCCESS;
    }

    TPM2_Packet_Init(ctx, &rsp);
    if (code == TPM_CC_FlushContext) {
        AssertIntEQ(script.flushes < TEST_MAX_FLUSHES, 1);
        script.flushed[script.flushes++] = arg0;
        if (arg0 == script.flushFail) {
            rc = TPM_RC_FAILURE;
        }
    }
    else if (code == TPM_CC_StartAuthSession) {
        TPM2_Packet_AppendU32(&rsp, TEST_POLICY_SESSION);
        TPM2_Packet_AppendU16(&rsp, TPM_SHA256_DIGEST_SIZE);
        for (i = 0; i < TPM_SHA256_DIGEST_SIZE; i++) {
            TPM2_Packet_AppendU8(&rsp, 0x5A);
        }
    }
    else if (code == TPM_CC_PolicySecret) {
        rc = TPM_RC_FAILURE;
    }
    else {
        AssertIntEQ(code, TPM_CC_GetCapability);
        AssertIntEQ(arg0, TPM_CAP_HANDLES);
        AssertIntEQ(page < TEST_MAX_PAGES, 1);
        script.queried[page] = arg1;
        script.pages++;
        rc = script.pageRc[page];
        if (rc == TPM_RC_SUCCESS) {
            TPM2_Packet_AppendU8(&rsp, script.pageMore[page]);
            TPM2_Packet_AppendU32(&rsp, TPM_CAP_HANDLES);
            TPM2_Packet_AppendU32(&rsp, (UINT32)script.pageCount[page]);
            for (i = 0; i < script.pageCount[page]; i++) {
                TPM2_Packet_AppendU32(&rsp, script.page[page][i]);
            }
        }
    }
    TPM2_Packet_Finalize(&rsp, TPM_ST_NO_SESSIONS, rc);
    packet->size = rsp.pos;
    return TPM_RC_SUCCESS;
}

#if !defined(WOLFTPM_LINUX_DEV) && !defined(WOLFTPM_SWTPM) && \
    !defined(WOLFTPM_WINAPI)
#ifdef WOLFTPM_ADV_IO
static int test_unload_io(TPM2_CTX* ctx, INT32 read, UINT32 addr,
    BYTE* buf, UINT16 sz, void* user)
{
    (void)read;
    (void)addr;
    (void)buf;
#else
static int test_unload_io(TPM2_CTX* ctx, const BYTE* tx, BYTE* rx,
    UINT16 sz, void* user)
{
    (void)tx;
    (void)rx;
#endif
    (void)ctx;
    (void)sz;
    (void)user;
    return TPM_RC_FAILURE;
}
#endif /* callback transports */

static void test_setup(WOLFTPM2_DEV* dev)
{
    int rc;

    XMEMSET(dev, 0, sizeof(*dev));
    XMEMSET(&script, 0, sizeof(script));
#if defined(WOLFTPM_LINUX_DEV) || defined(WOLFTPM_SWTPM) || \
    defined(WOLFTPM_WINAPI)
    rc = TPM2_Init_minimal(&dev->ctx);
#else
    rc = TPM2_Init_ex(&dev->ctx, test_unload_io, NULL, 0);
#endif
    AssertIntEQ(rc, TPM_RC_SUCCESS);
}

/* A partial page with moreData continues from the handle after its last one,
 * so handles on the next page are flushed as well */
static void test_two_pages(void)
{
    WOLFTPM2_DEV dev;

    test_setup(&dev);
    script.pageCount[0] = 2;
    script.page[0][0] = TRANSIENT_FIRST;
    script.page[0][1] = TRANSIENT_FIRST + 1;
    script.pageMore[0] = 1;
    script.pageCount[1] = 1;
    script.page[1][0] = TRANSIENT_FIRST + 4;

    AssertIntEQ(wolfTPM2_UnloadHandles_AllTransient(&dev), TPM_RC_SUCCESS);
    AssertIntEQ(script.pages, 2);
    AssertIntEQ(script.queried[0], TRANSIENT_FIRST);
    AssertIntEQ(script.queried[1], TRANSIENT_FIRST + 2);
    AssertIntEQ(script.flushes, 3);
    AssertIntEQ(script.flushed[0], TRANSIENT_FIRST);
    AssertIntEQ(script.flushed[1], TRANSIENT_FIRST + 1);
    AssertIntEQ(script.flushed[2], TRANSIENT_FIRST + 4);
    TPM2_Cleanup(&dev.ctx);
}

/* Nothing loaded: no flush is attempted */
static void test_none_loaded(void)
{
    WOLFTPM2_DEV dev;

    test_setup(&dev);
    AssertIntEQ(wolfTPM2_UnloadHandles_AllTransient(&dev), TPM_RC_SUCCESS);
    AssertIntEQ(script.pages, 1);
    AssertIntEQ(script.flushes, 0);
    TPM2_Cleanup(&dev.ctx);
}

/* When discovery fails the fixed range is still tried, but nothing confirms it
 * worked, so the failure reaches the caller */
static void test_query_failure(void)
{
    WOLFTPM2_DEV dev;

    test_setup(&dev);
    script.pageRc[0] = TPM_RC_FAILURE;
    AssertIntEQ(wolfTPM2_UnloadHandles_AllTransient(&dev), TPM_RC_FAILURE);
    AssertIntEQ(script.flushes, MAX_HANDLE_NUM);
    AssertIntEQ(script.flushed[0], TRANSIENT_FIRST);
    TPM2_Cleanup(&dev.ctx);
}

/* A later page failing is reported without restarting the fixed range */
static void test_second_page_failure(void)
{
    WOLFTPM2_DEV dev;

    test_setup(&dev);
    script.pageCount[0] = 1;
    script.page[0][0] = TRANSIENT_FIRST;
    script.pageMore[0] = 1;
    script.pageRc[1] = TPM_RC_FAILURE;
    AssertIntEQ(wolfTPM2_UnloadHandles_AllTransient(&dev), TPM_RC_FAILURE);
    AssertIntEQ(script.flushes, 1);
    TPM2_Cleanup(&dev.ctx);
}

/* A failed flush is reported, and the remaining handles are still flushed */
static void test_flush_failure(void)
{
    WOLFTPM2_DEV dev;

    test_setup(&dev);
    script.pageCount[0] = 2;
    script.page[0][0] = TRANSIENT_FIRST;
    script.page[0][1] = TRANSIENT_FIRST + 1;
    script.flushFail = TRANSIENT_FIRST;
    AssertIntEQ(wolfTPM2_UnloadHandles_AllTransient(&dev), TPM_RC_FAILURE);
    AssertIntEQ(script.flushes, 2);
    TPM2_Cleanup(&dev.ctx);
}

/* A handle outside the transient range or out of order ends the walk unflushed
 * and does not follow moreData */
static void test_bad_handles(void)
{
    WOLFTPM2_DEV dev;

    test_setup(&dev);
    script.pageCount[0] = 2;
    script.page[0][0] = TRANSIENT_FIRST;
    script.page[0][1] = HMAC_SESSION_FIRST;
    script.pageMore[0] = 1;
    AssertIntEQ(wolfTPM2_UnloadHandles_AllTransient(&dev), TPM_RC_SUCCESS);
    AssertIntEQ(script.pages, 1);
    AssertIntEQ(script.flushes, 1);
    TPM2_Cleanup(&dev.ctx);

    test_setup(&dev);
    script.pageCount[0] = 2;
    script.page[0][0] = TRANSIENT_FIRST + 1;
    script.page[0][1] = TRANSIENT_FIRST;
    script.pageMore[0] = 1;
    AssertIntEQ(wolfTPM2_UnloadHandles_AllTransient(&dev), TPM_RC_SUCCESS);
    AssertIntEQ(script.pages, 1);
    AssertIntEQ(script.flushes, 1);
    TPM2_Cleanup(&dev.ctx);
}

#if MAX_SESSION_NUM > 1
/* Unloading a session wipes its key from the handle and from every device
 * slot it was installed in, whether or not the TPM accepts the flush */
static void test_session_unload(void)
{
    WOLFTPM2_DEV dev;
    WOLFTPM2_HANDLE handle;
    int pass, i;

    for (pass = 0; pass < 2; pass++) {
        test_setup(&dev);
        XMEMSET(&handle, 0, sizeof(handle));
        handle.hndl = HMAC_SESSION_FIRST + 1;
        handle.auth.size = 8;
        XMEMSET(handle.auth.buffer, 0xA5, handle.auth.size);
        dev.session[0].sessionHandle = TPM_RS_PW;
        dev.session[0].auth.size = 4;
        dev.session[1].sessionHandle = handle.hndl;
        dev.session[1].sessionAttributes = TPMA_SESSION_decrypt;
        dev.session[1].auth.size = 8;
        XMEMSET(dev.session[1].auth.buffer, 0xA5, 8);
        if (pass == 1) {
            script.flushFail = handle.hndl;
        }

        AssertIntEQ(wolfTPM2_UnloadHandle(&dev, &handle),
            (pass == 0) ? TPM_RC_SUCCESS : TPM_RC_FAILURE);
        AssertIntEQ(script.flushes, 1);
        AssertIntEQ(script.flushed[0], HMAC_SESSION_FIRST + 1);
        AssertIntEQ(handle.auth.size, 0);
        for (i = 0; i < (int)sizeof(handle.auth.buffer); i++) {
            AssertIntEQ(handle.auth.buffer[i], 0);
        }
        AssertIntEQ(dev.session[1].sessionHandle, TPM_RS_PW);
        AssertIntEQ(dev.session[1].sessionAttributes, 0);
        AssertIntEQ(dev.session[1].auth.size, 0);
        for (i = 0; i < (int)sizeof(dev.session[1].auth.buffer); i++) {
            AssertIntEQ(dev.session[1].auth.buffer[i], 0);
        }
        /* an unrelated slot is left alone */
        AssertIntEQ(dev.session[0].auth.size, 4);
        AssertIntEQ(handle.hndl,
            (pass == 0) ? (TPM_HANDLE)TPM_RH_NULL : HMAC_SESSION_FIRST + 1);
        TPM2_Cleanup(&dev.ctx);
    }
}
#endif

/* Build a canned response from a tag, response code and body */
static void test_canned(TPM_ST tag, TPM_RC rc, const byte* body, int bodySz)
{
    int sz = TPM2_HEADER_SIZE + bodySz;

    AssertIntEQ(sz <= TEST_CANNED_MAX, 1);
    script.canned[0] = (byte)(tag >> 8);
    script.canned[1] = (byte)tag;
    script.canned[2] = 0;
    script.canned[3] = 0;
    script.canned[4] = 0;
    script.canned[5] = (byte)sz;
    script.canned[6] = (byte)(rc >> 24);
    script.canned[7] = (byte)(rc >> 16);
    script.canned[8] = (byte)(rc >> 8);
    script.canned[9] = (byte)rc;
    if (bodySz > 0) {
        XMEMCPY(&script.canned[TPM2_HEADER_SIZE], body, bodySz);
    }
    script.cannedSz = sz;
}

/* A command sent with sessions must be answered with sessions. A success
 * response tagged TPM_ST_NO_SESSIONS would skip the response HMAC, so it is
 * refused and nothing of it is left in the command buffer. */
static void test_response_tag_downgrade(void)
{
    static const byte emptyAuth[] = {
        0, 0, 0, 0,     /* parameterSize */
        0, 0,           /* nonceTPM */
        0,              /* sessionAttributes */
        0, 0            /* hmac */
    };
    static const byte payload[] = { 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE };
    WOLFTPM2_DEV dev;
    Clear_In in;
    int i;

    test_setup(&dev);
    dev.session[0].sessionHandle = TPM_RS_PW;
    AssertIntEQ(TPM2_SetSessionAuth(dev.session), TPM_RC_SUCCESS);
    XMEMSET(&in, 0, sizeof(in));
    in.authHandle = TPM_RH_LOCKOUT;

    test_canned(TPM_ST_SESSIONS, TPM_RC_SUCCESS, emptyAuth,
        (int)sizeof(emptyAuth));
    AssertIntEQ(TPM2_Clear(&in), TPM_RC_SUCCESS);

    test_canned(TPM_ST_NO_SESSIONS, TPM_RC_SUCCESS, payload,
        (int)sizeof(payload));
    AssertIntEQ(TPM2_Clear(&in), TPM_RC_HMAC);
    for (i = 0; i < (int)sizeof(dev.ctx.cmdBuf); i++) {
        AssertIntEQ(dev.ctx.cmdBuf[i], 0);
    }
    TPM2_Cleanup(&dev.ctx);
}

/* A PCR read that returns no digest, or one larger than the caller's buffer,
 * is refused without writing to the buffer */
static void test_read_pcr_guards(void)
{
    static const byte noDigest[] = {
        0, 0, 0, 1,                         /* pcrUpdateCounter */
        0, 0, 0, 1, 0x00, 0x0B, 3, 1, 0, 0, /* one SHA-256 selection */
        0, 0, 0, 0                          /* no digests */
    };
    byte oneDigest[sizeof(noDigest) + 2 + TPM_SHA256_DIGEST_SIZE];
    WOLFTPM2_DEV dev;
    byte digest[TPM_SHA256_DIGEST_SIZE + 1];
    int digestLen;
    int i;

    test_setup(&dev);

    AssertIntEQ(wolfTPM2_ReadPCR(&dev, -1, TPM_ALG_SHA256, digest,
        &digestLen), BAD_FUNC_ARG);
    AssertIntEQ(wolfTPM2_ReadPCR(&dev, PCR_LAST + 1, TPM_ALG_SHA256, digest,
        &digestLen), BAD_FUNC_ARG);

    test_canned(TPM_ST_NO_SESSIONS, TPM_RC_SUCCESS, noDigest,
        (int)sizeof(noDigest));
    digestLen = (int)sizeof(digest);
    AssertIntEQ(wolfTPM2_ReadPCR(&dev, 0, TPM_ALG_SHA256, digest,
        &digestLen), TPM_RC_FAILURE);

    XMEMCPY(oneDigest, noDigest, sizeof(noDigest));
    oneDigest[sizeof(noDigest) - 1] = 1;
    oneDigest[sizeof(noDigest)] = 0;
    oneDigest[sizeof(noDigest) + 1] = TPM_SHA256_DIGEST_SIZE;
    XMEMSET(&oneDigest[sizeof(noDigest) + 2], 0x77, TPM_SHA256_DIGEST_SIZE);
    test_canned(TPM_ST_NO_SESSIONS, TPM_RC_SUCCESS, oneDigest,
        (int)sizeof(oneDigest));

    XMEMSET(digest, 0xC3, sizeof(digest));
    digestLen = TPM_SHA256_DIGEST_SIZE - 1;
    AssertIntEQ(wolfTPM2_ReadPCR(&dev, 0, TPM_ALG_SHA256, digest,
        &digestLen), BUFFER_E);
    for (i = 0; i < (int)sizeof(digest); i++) {
        AssertIntEQ(digest[i], 0xC3);
    }
    AssertIntEQ(wolfTPM2_ReadPCR(&dev, 0, TPM_ALG_SHA256, digest, NULL),
        BAD_FUNC_ARG);

    digestLen = TPM_SHA256_DIGEST_SIZE;
    AssertIntEQ(wolfTPM2_ReadPCR(&dev, 0, TPM_ALG_SHA256, digest,
        &digestLen), TPM_RC_SUCCESS);
    AssertIntEQ(digestLen, TPM_SHA256_DIGEST_SIZE);
    AssertIntEQ(digest[0], 0x77);
    AssertIntEQ(digest[TPM_SHA256_DIGEST_SIZE - 1], 0x77);
    AssertIntEQ(digest[TPM_SHA256_DIGEST_SIZE], 0xC3);
    TPM2_Cleanup(&dev.ctx);
}

#ifdef WOLFTPM2_USE_WOLF_RNG
/* A policy session whose PolicySecret is refused is not left loaded */
static void test_ek_policy_secret_failure(void)
{
    WOLFTPM2_DEV dev;
    WOLFTPM2_SESSION session;

    test_setup(&dev);
    XMEMSET(&session, 0, sizeof(session));
    AssertIntEQ(wolfTPM2_CreateAuthSession_EkPolicy(&dev, &session),
        TPM_RC_FAILURE);
    AssertIntEQ(script.flushes, 1);
    AssertIntEQ(script.flushed[0], TEST_POLICY_SESSION);
    AssertIntEQ(session.handle.hndl, TPM_RH_NULL);
    TPM2_Cleanup(&dev.ctx);
}
#endif

int main(void)
{
    test_two_pages();
    test_none_loaded();
    test_query_failure();
    test_second_page_failure();
    test_flush_failure();
    test_bad_handles();
#if MAX_SESSION_NUM > 1
    test_session_unload();
#endif
    test_response_tag_downgrade();
    test_read_pcr_guards();
#ifdef WOLFTPM2_USE_WOLF_RNG
    test_ek_policy_secret_failure();
#endif
    printf("Transient unload tests: passed\n");
    return 0;
}
