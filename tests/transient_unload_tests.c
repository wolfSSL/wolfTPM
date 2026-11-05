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

    TPM2_Packet_Init(ctx, &rsp);
    if (code == TPM_CC_FlushContext) {
        AssertIntEQ(script.flushes < TEST_MAX_FLUSHES, 1);
        script.flushed[script.flushes++] = arg0;
        if (arg0 == script.flushFail) {
            rc = TPM_RC_FAILURE;
        }
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

int main(void)
{
    test_two_pages();
    test_none_loaded();
    test_query_failure();
    test_second_page_failure();
    test_flush_failure();
    test_bad_handles();
    printf("Transient unload tests: passed\n");
    return 0;
}
