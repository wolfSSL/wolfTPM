/* user_transport_unit_tests.c
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

/* Runs the user command transport through the public TPM2_Init_ex,
 * TPM2_Startup and TPM2_Cleanup API so the transport dispatch is covered. */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_packet.h>
#ifndef WOLFTPM2_NO_WRAPPER
#include <wolftpm/tpm2_wrap.h>
#endif

#include <stdio.h>
#include <string.h>

#define TEST_ERR 7

enum {
    RSP_OK,
    RSP_SHORT,
    RSP_OVERSIZE,
    RSP_LEN_MISMATCH,
    RSP_SEND_ERROR,
    RSP_RETRY_ONCE
};

static const byte startupCmd[] = {
    0x80, 0x01, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00
};
static const byte rspOk[] = {
    0x80, 0x01, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x00
};
static const byte rspRetry[] = {
    0x80, 0x01, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x09, 0x22
};

static struct {
    int mode;
    int sends;
    void* sendCtx;
    TPM2_CTX* sendTpmCtx;
    byte lastCmd[64];
    byte firstCmd[64];
    UINT32 lastCmdSz;
} stub;

static int gUser;
static int gFailures;

#define CHECK(cond) do {                                                     \
    if (!(cond)) {                                                           \
        printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);               \
        gFailures++;                                                         \
    }                                                                        \
} while (0)

/* Declare the reported size in the header so only a bound check rejects it */
static void stubSetRspSize(BYTE* rsp, UINT32 sz)
{
    rsp[2] = (BYTE)(sz >> 24);
    rsp[3] = (BYTE)(sz >> 16);
    rsp[4] = (BYTE)(sz >> 8);
    rsp[5] = (BYTE)sz;
}

static int stubSend(TPM2_CTX* ctx, const BYTE* cmd, UINT32 cmdSz, BYTE* rsp,
    UINT32 rspMax, UINT32* rspSz, void* userCtx)
{
    stub.sendTpmCtx = ctx;
    stub.sends++;
    stub.sendCtx = userCtx;
    stub.lastCmdSz = cmdSz;
    if (cmdSz <= sizeof(stub.lastCmd)) {
        XMEMCPY(stub.lastCmd, cmd, cmdSz);
    }

    if (stub.mode == RSP_SEND_ERROR) {
        return TEST_ERR;
    }
    if (rspMax < sizeof(rspOk)) {
        return TEST_ERR;
    }
    if (stub.mode == RSP_RETRY_ONCE && stub.sends == 1) {
        XMEMCPY(stub.firstCmd, cmd, cmdSz);
        XMEMCPY(rsp, rspRetry, sizeof(rspRetry));
        *rspSz = (UINT32)sizeof(rspRetry);
        return 0;
    }
    XMEMCPY(rsp, rspOk, sizeof(rspOk));
    *rspSz = (UINT32)sizeof(rspOk);
    if (stub.mode == RSP_SHORT) {
        *rspSz = TPM2_HEADER_SIZE - 1;
        stubSetRspSize(rsp, *rspSz);
    }
    else if (stub.mode == RSP_OVERSIZE) {
        *rspSz = rspMax + 1;
        stubSetRspSize(rsp, *rspSz);
    }
    else if (stub.mode == RSP_LEN_MISMATCH) {
        rsp[5] = 0x0B;
    }
    return 0;
}

static TPM_RC sendStartup(void)
{
    Startup_In in;

    XMEMSET(&in, 0, sizeof(in));
    in.startupType = TPM_SU_CLEAR;
    return TPM2_Startup(&in);
}

/* The transport is the IO callback, and there is no TIS startup wait */
static void test_init_args(void)
{
    TPM2_CTX ctx;

    XMEMSET(&stub, 0, sizeof(stub));
    CHECK(TPM2_Init_ex(&ctx, NULL, &gUser, 0) == BAD_FUNC_ARG);
    CHECK(TPM2_Init_ex(&ctx, stubSend, &gUser, 1) == BAD_FUNC_ARG);
    CHECK(TPM2_Init_minimal(&ctx) == BAD_FUNC_ARG);
    CHECK(TPM2_Init(&ctx, stubSend, &gUser) == TPM_RC_SUCCESS);
    CHECK(TPM2_ChipStartup(&ctx, 1) == NOT_COMPILED_IN);
    CHECK(TPM2_SetHalIoCb(&ctx, NULL, &gUser) == BAD_FUNC_ARG);
    CHECK(stub.sends == 0);
    (void)TPM2_Cleanup(&ctx);
    printf("Test user transport: init arguments done\n");
}

/* A command reaches the callback unchanged with the caller's context */
static void test_send(void)
{
    TPM2_CTX ctx;

    XMEMSET(&stub, 0, sizeof(stub));
    CHECK(TPM2_Init_ex(&ctx, stubSend, &gUser, 0) == TPM_RC_SUCCESS);
    CHECK(sendStartup() == TPM_RC_SUCCESS);
    CHECK(stub.sends == 1);
    CHECK(stub.sendCtx == &gUser);
    CHECK(stub.sendTpmCtx == &ctx);
    CHECK(stub.lastCmdSz == sizeof(startupCmd));
    CHECK(XMEMCMP(stub.lastCmd, startupCmd, sizeof(startupCmd)) == 0);
    CHECK(TPM2_Cleanup(&ctx) == TPM_RC_SUCCESS);
    printf("Test user transport: send done\n");
}

/* A response outside the header and buffer bounds, or whose header length
 * disagrees with the received size, is rejected */
static void test_bad_responses(void)
{
    TPM2_CTX ctx;
    int mode;

    for (mode = RSP_SHORT; mode <= RSP_SEND_ERROR; mode++) {
        XMEMSET(&stub, 0, sizeof(stub));
        stub.mode = mode;
        CHECK(TPM2_Init_ex(&ctx, stubSend, &gUser, 0) == TPM_RC_SUCCESS);
        CHECK(sendStartup() == TPM_RC_FAILURE);
        CHECK(stub.sends == 1);
        (void)TPM2_Cleanup(&ctx);
    }
    printf("Test user transport: bad responses done\n");
}

#ifndef WOLFTPM_NO_RETRY
/* A TPM_RC_RETRY response resends the identical command */
static void test_retry(void)
{
    TPM2_CTX ctx;

    XMEMSET(&stub, 0, sizeof(stub));
    stub.mode = RSP_RETRY_ONCE;
    CHECK(TPM2_Init_ex(&ctx, stubSend, &gUser, 0) == TPM_RC_SUCCESS);
    CHECK(TPM2_SetCommandRetries(&ctx, 1) == TPM_RC_SUCCESS);
    CHECK(sendStartup() == TPM_RC_SUCCESS);
    CHECK(stub.sends == 2);
    CHECK(XMEMCMP(stub.firstCmd, startupCmd, sizeof(startupCmd)) == 0);
    CHECK(stub.lastCmdSz == sizeof(startupCmd));
    CHECK(XMEMCMP(stub.lastCmd, startupCmd, sizeof(startupCmd)) == 0);
    (void)TPM2_Cleanup(&ctx);
    printf("Test user transport: retry done\n");
}
#endif

/* Each context sends through its own callback context, and
 * TPM2_SetHalIoCb replaces it */
static void test_per_context(void)
{
    TPM2_CTX ctxA;
    TPM2_CTX ctxB;
    int other;

    XMEMSET(&stub, 0, sizeof(stub));
    CHECK(TPM2_Init_ex(&ctxA, stubSend, &gUser, 0) == TPM_RC_SUCCESS);
    CHECK(TPM2_Init_ex(&ctxB, stubSend, &other, 0) == TPM_RC_SUCCESS);
    CHECK(sendStartup() == TPM_RC_SUCCESS);
    CHECK(stub.sendCtx == &other);
    CHECK(stub.sendTpmCtx == &ctxB);

    TPM2_SetActiveCtx(&ctxA);
    CHECK(sendStartup() == TPM_RC_SUCCESS);
    CHECK(stub.sendCtx == &gUser);
    CHECK(stub.sendTpmCtx == &ctxA);

    CHECK(TPM2_SetHalIoCb(&ctxA, stubSend, &other) == TPM_RC_SUCCESS);
    CHECK(sendStartup() == TPM_RC_SUCCESS);
    CHECK(stub.sendCtx == &other);
    CHECK(stub.sends == 3);

    CHECK(TPM2_Cleanup(&ctxA) == TPM_RC_SUCCESS);
    CHECK(TPM2_Cleanup(&ctxB) == TPM_RC_SUCCESS);
    printf("Test user transport: per context done\n");
}

#ifndef WOLFTPM2_NO_WRAPPER
/* The wrapper passes its IO callback through and starts the TPM with it */
static void test_wrapper_init(void)
{
    WOLFTPM2_DEV dev;

    XMEMSET(&stub, 0, sizeof(stub));
    CHECK(wolfTPM2_Init(&dev, NULL, NULL) == BAD_FUNC_ARG);
    CHECK(stub.sends == 0);

    CHECK(wolfTPM2_Init(&dev, stubSend, &gUser) == TPM_RC_SUCCESS);
    CHECK(stub.sends >= 1);
    CHECK(stub.sendCtx == &gUser);
    CHECK(stub.sendTpmCtx == &dev.ctx);
    CHECK(wolfTPM2_Test(stubSend, &gUser, NULL) == TPM_RC_SUCCESS);
    CHECK(TPM2_GetActiveCtx() == &dev.ctx);
    CHECK(wolfTPM2_Cleanup(&dev) == TPM_RC_SUCCESS);

    XMEMSET(&stub, 0, sizeof(stub));
    stub.mode = RSP_SEND_ERROR;
    CHECK(wolfTPM2_Init(&dev, stubSend, &gUser) != TPM_RC_SUCCESS);
    CHECK(stub.sends >= 1);
#ifndef WOLFTPM2_NO_HEAP
    /* wolfTPM2_New has no way to take the transport callback */
    CHECK(wolfTPM2_New() == NULL);
#endif
    printf("Test user transport: wrapper init done\n");
}
#endif

int main(void)
{
    test_init_args();
    test_send();
    test_bad_responses();
#ifndef WOLFTPM_NO_RETRY
    test_retry();
#endif
    test_per_context();
#ifndef WOLFTPM2_NO_WRAPPER
    test_wrapper_init();
#endif

    printf("User transport tests: %s\n", gFailures == 0 ? "passed" : "failed");
    return gFailures == 0 ? 0 : 1;
}
