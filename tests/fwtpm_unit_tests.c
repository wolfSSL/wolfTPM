/* fwtpm_unit_tests.c
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

/* wolfTPM fwTPM Unit Tests
 *
 * Standalone unit tests for the fwTPM command processor. Tests call
 * FWTPM_ProcessCommand() directly with crafted TPM command packets,
 * verifying response codes and output data. This file compiles as its
 * own binary with -DWOLFTPM_FWTPM, following the wolfSPDM separation
 * pattern for potential future modularization.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2_types.h>

#ifdef WOLFTPM_FWTPM

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_packet.h>
#include <wolftpm/fwtpm/fwtpm.h>
#include <wolftpm/fwtpm/fwtpm_command.h>

#include <wolftpm/fwtpm/fwtpm_nv.h>

#include <stdio.h>
#include <string.h>

/* Test Fail Helpers (same as unit_tests.c) */
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
#define AssertIntEQ(x, y) do {                                                \
    int _x = (int)(x); int _y = (int)(y);                                    \
    Assert(_x == _y, ("%s == %s", #x, #y),                                   \
        ("%d(0x%x) != %d(0x%x)", _x, _x, _y, _y));                          \
} while(0)
#define AssertIntNE(x, y) do {                                                \
    int _x = (int)(x); int _y = (int)(y);                                    \
    Assert(_x != _y, ("%s != %s", #x, #y),                                   \
        ("%d(0x%x) == %d(0x%x)", _x, _x, _y, _y));                          \
} while(0)
#define AssertIntGT(x, y) do {                                                \
    int _x = (int)(x); int _y = (int)(y);                                    \
    Assert(_x > _y, ("%s > %s", #x, #y),                                     \
        ("%d <= %d", _x, _y));                                                \
} while(0)

/* ================================================================== */
/* Packet building helpers                                             */
/* ================================================================== */

/* Store 16-bit big-endian value at buf */
static void PutU16BE(byte* buf, UINT16 val)
{
    buf[0] = (byte)(val >> 8);
    buf[1] = (byte)(val);
}

/* Store 32-bit big-endian value at buf */
static void PutU32BE(byte* buf, UINT32 val)
{
    buf[0] = (byte)(val >> 24);
    buf[1] = (byte)(val >> 16);
    buf[2] = (byte)(val >> 8);
    buf[3] = (byte)(val);
}

/* Read 16-bit big-endian value from buf */
static UINT16 GetU16BE(const byte* buf)
{
    return (UINT16)((UINT16)buf[0] << 8 | buf[1]);
}

/* Read 32-bit big-endian value from buf */
static UINT32 GetU32BE(const byte* buf)
{
    return ((UINT32)buf[0] << 24) | ((UINT32)buf[1] << 16) |
           ((UINT32)buf[2] << 8) | buf[3];
}

/* Build a TPM command header. Returns TPM2_HEADER_SIZE (10). */
static int BuildCmdHeader(byte* buf, UINT16 tag, UINT32 totalSize, UINT32 cc)
{
    PutU16BE(buf, tag);
    PutU32BE(buf + 2, totalSize);
    PutU32BE(buf + 6, cc);
    return TPM2_HEADER_SIZE;
}

/* Parse TPM response header fields */
static void ParseRspHeader(const byte* buf, UINT16* tag, UINT32* size,
    TPM_RC* rc)
{
    if (tag)  *tag  = GetU16BE(buf);
    if (size) *size = GetU32BE(buf + 2);
    if (rc)   *rc   = (TPM_RC)GetU32BE(buf + 6);
}

/* Get response RC from a response buffer */
static TPM_RC GetRspRC(const byte* rsp)
{
    return (TPM_RC)GetU32BE(rsp + 6);
}

/* ================================================================== */
/* Test context management                                             */
/* ================================================================== */

static byte gCmd[FWTPM_MAX_COMMAND_SIZE];
static byte gRsp[FWTPM_MAX_COMMAND_SIZE];

/* Initialize fwTPM context and send Startup + SelfTest */
static int fwtpm_test_startup(FWTPM_CTX* ctx)
{
    int rc;
    int rspSize;
    int cmdSz;

    rc = FWTPM_Init(ctx);
    if (rc != 0) return rc;

    /* TPM2_Startup(SU_CLEAR) */
    cmdSz = BuildCmdHeader(gCmd, TPM_ST_NO_SESSIONS, 12, TPM_CC_Startup);
    PutU16BE(gCmd + cmdSz, TPM_SU_CLEAR);
    cmdSz += 2;
    PutU32BE(gCmd + 2, (UINT32)cmdSz); /* fix size */
    rspSize = 0;
    rc = FWTPM_ProcessCommand(ctx, gCmd, cmdSz, gRsp, &rspSize, 0);
    if (rc != 0) return rc;
    rc = (int)GetRspRC(gRsp);
    if (rc != TPM_RC_SUCCESS) return rc;

    /* TPM2_SelfTest(fullTest=1) */
    cmdSz = BuildCmdHeader(gCmd, TPM_ST_NO_SESSIONS, 11, TPM_CC_SelfTest);
    gCmd[cmdSz++] = 1; /* fullTest = YES */
    PutU32BE(gCmd + 2, (UINT32)cmdSz);
    rspSize = 0;
    rc = FWTPM_ProcessCommand(ctx, gCmd, cmdSz, gRsp, &rspSize, 0);
    if (rc != 0) return rc;

    return (int)GetRspRC(gRsp);
}

/* ================================================================== */
/* 1. Core Lifecycle Tests                                             */
/* ================================================================== */

static void test_fwtpm_init_cleanup(void)
{
    FWTPM_CTX ctx;
    int rc;

    memset(&ctx, 0, sizeof(ctx));
    rc = FWTPM_Init(&ctx);
    AssertIntEQ(rc, 0);
    FWTPM_Cleanup(&ctx);

    printf("Test fwTPM:\tInit/Cleanup:\t\t\tPassed\n");
}

static void test_fwtpm_startup_clear(void)
{
    FWTPM_CTX ctx;
    int rc, rspSize, cmdSz;

    memset(&ctx, 0, sizeof(ctx));
    rc = FWTPM_Init(&ctx);
    AssertIntEQ(rc, 0);

    /* Startup(SU_CLEAR) */
    cmdSz = BuildCmdHeader(gCmd, TPM_ST_NO_SESSIONS, 12, TPM_CC_Startup);
    PutU16BE(gCmd + cmdSz, TPM_SU_CLEAR);
    cmdSz += 2;
    PutU32BE(gCmd + 2, (UINT32)cmdSz);

    rspSize = 0;
    rc = FWTPM_ProcessCommand(&ctx, gCmd, cmdSz, gRsp, &rspSize, 0);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    AssertIntEQ(GetRspRC(gRsp), TPM_RC_SUCCESS);
    AssertIntGT(rspSize, 0);

    FWTPM_Cleanup(&ctx);
    printf("Test fwTPM:\tStartup(CLEAR):\t\t\tPassed\n");
}

static void test_fwtpm_double_startup(void)
{
    FWTPM_CTX ctx;
    int rc, rspSize, cmdSz;

    memset(&ctx, 0, sizeof(ctx));
    rc = fwtpm_test_startup(&ctx);
    AssertIntEQ(rc, 0);

    /* Second Startup(SU_CLEAR) after already started should fail */
    cmdSz = BuildCmdHeader(gCmd, TPM_ST_NO_SESSIONS, 12, TPM_CC_Startup);
    PutU16BE(gCmd + cmdSz, TPM_SU_CLEAR);
    cmdSz += 2;
    PutU32BE(gCmd + 2, (UINT32)cmdSz);

    rspSize = 0;
    rc = FWTPM_ProcessCommand(&ctx, gCmd, cmdSz, gRsp, &rspSize, 0);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    /* Should get TPM_RC_INITIALIZE (already started) */
    AssertIntNE(GetRspRC(gRsp), TPM_RC_SUCCESS);

    FWTPM_Cleanup(&ctx);
    printf("Test fwTPM:\tDouble Startup:\t\t\tPassed\n");
}

static void test_fwtpm_selftest(void)
{
    FWTPM_CTX ctx;
    int rc;

    memset(&ctx, 0, sizeof(ctx));
    rc = fwtpm_test_startup(&ctx);
    AssertIntEQ(rc, 0);

    FWTPM_Cleanup(&ctx);
    printf("Test fwTPM:\tSelfTest:\t\t\tPassed\n");
}

static void test_fwtpm_shutdown(void)
{
    FWTPM_CTX ctx;
    int rc, rspSize, cmdSz;

    memset(&ctx, 0, sizeof(ctx));
    rc = fwtpm_test_startup(&ctx);
    AssertIntEQ(rc, 0);

    /* Shutdown(SU_CLEAR) */
    cmdSz = BuildCmdHeader(gCmd, TPM_ST_NO_SESSIONS, 12, TPM_CC_Shutdown);
    PutU16BE(gCmd + cmdSz, TPM_SU_CLEAR);
    cmdSz += 2;
    PutU32BE(gCmd + 2, (UINT32)cmdSz);

    rspSize = 0;
    rc = FWTPM_ProcessCommand(&ctx, gCmd, cmdSz, gRsp, &rspSize, 0);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    AssertIntEQ(GetRspRC(gRsp), TPM_RC_SUCCESS);

    FWTPM_Cleanup(&ctx);
    printf("Test fwTPM:\tShutdown:\t\t\tPassed\n");
}

/* ================================================================== */
/* 2. Command Dispatch & Error Handling                                */
/* ================================================================== */

static void test_fwtpm_undersized_command(void)
{
    FWTPM_CTX ctx;
    int rc, rspSize;

    memset(&ctx, 0, sizeof(ctx));
    rc = fwtpm_test_startup(&ctx);
    AssertIntEQ(rc, 0);

    /* Send only 4 bytes (< TPM2_HEADER_SIZE=10) */
    memset(gCmd, 0, 4);
    rspSize = 0;
    rc = FWTPM_ProcessCommand(&ctx, gCmd, 4, gRsp, &rspSize, 0);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    AssertIntEQ(GetRspRC(gRsp), TPM_RC_COMMAND_SIZE);

    FWTPM_Cleanup(&ctx);
    printf("Test fwTPM:\tUndersized command:\t\tPassed\n");
}

static void test_fwtpm_bad_tag(void)
{
    FWTPM_CTX ctx;
    int rc, rspSize;

    memset(&ctx, 0, sizeof(ctx));
    rc = fwtpm_test_startup(&ctx);
    AssertIntEQ(rc, 0);

    /* Send with bad tag 0x1234 */
    BuildCmdHeader(gCmd, 0x1234, 10, TPM_CC_GetRandom);
    rspSize = 0;
    rc = FWTPM_ProcessCommand(&ctx, gCmd, 10, gRsp, &rspSize, 0);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    AssertIntEQ(GetRspRC(gRsp), TPM_RC_BAD_TAG);

    FWTPM_Cleanup(&ctx);
    printf("Test fwTPM:\tBad tag:\t\t\tPassed\n");
}

static void test_fwtpm_size_mismatch(void)
{
    FWTPM_CTX ctx;
    int rc, rspSize;

    memset(&ctx, 0, sizeof(ctx));
    rc = fwtpm_test_startup(&ctx);
    AssertIntEQ(rc, 0);

    /* Header says size=100 but we only send 12 bytes */
    BuildCmdHeader(gCmd, TPM_ST_NO_SESSIONS, 100, TPM_CC_GetRandom);
    PutU16BE(gCmd + 10, 16);
    rspSize = 0;
    rc = FWTPM_ProcessCommand(&ctx, gCmd, 12, gRsp, &rspSize, 0);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    AssertIntEQ(GetRspRC(gRsp), TPM_RC_COMMAND_SIZE);

    FWTPM_Cleanup(&ctx);
    printf("Test fwTPM:\tSize mismatch:\t\t\tPassed\n");
}

static void test_fwtpm_unknown_command(void)
{
    FWTPM_CTX ctx;
    int rc, rspSize;

    memset(&ctx, 0, sizeof(ctx));
    rc = fwtpm_test_startup(&ctx);
    AssertIntEQ(rc, 0);

    /* Send command code 0xDEADBEEF */
    BuildCmdHeader(gCmd, TPM_ST_NO_SESSIONS, 10, 0xDEADBEEF);
    rspSize = 0;
    rc = FWTPM_ProcessCommand(&ctx, gCmd, 10, gRsp, &rspSize, 0);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    AssertIntEQ(GetRspRC(gRsp), TPM_RC_COMMAND_CODE);

    FWTPM_Cleanup(&ctx);
    printf("Test fwTPM:\tUnknown command code:\t\tPassed\n");
}

static void test_fwtpm_no_startup(void)
{
    FWTPM_CTX ctx;
    int rc, rspSize, cmdSz;

    memset(&ctx, 0, sizeof(ctx));
    rc = FWTPM_Init(&ctx);
    AssertIntEQ(rc, 0);

    /* Send Startup first to set powerOn */
    cmdSz = BuildCmdHeader(gCmd, TPM_ST_NO_SESSIONS, 12, TPM_CC_Startup);
    PutU16BE(gCmd + cmdSz, TPM_SU_CLEAR);
    cmdSz += 2;
    PutU32BE(gCmd + 2, (UINT32)cmdSz);
    rspSize = 0;
    FWTPM_ProcessCommand(&ctx, gCmd, cmdSz, gRsp, &rspSize, 0);

    /* Now cleanup and reinit WITHOUT startup */
    FWTPM_Cleanup(&ctx);
    memset(&ctx, 0, sizeof(ctx));
    rc = FWTPM_Init(&ctx);
    AssertIntEQ(rc, 0);

    /* GetRandom without Startup should get TPM_RC_INITIALIZE */
    cmdSz = BuildCmdHeader(gCmd, TPM_ST_NO_SESSIONS, 12, TPM_CC_GetRandom);
    PutU16BE(gCmd + cmdSz, 16);
    cmdSz += 2;
    PutU32BE(gCmd + 2, (UINT32)cmdSz);
    rspSize = 0;
    rc = FWTPM_ProcessCommand(&ctx, gCmd, cmdSz, gRsp, &rspSize, 0);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    AssertIntEQ(GetRspRC(gRsp), TPM_RC_INITIALIZE);

    FWTPM_Cleanup(&ctx);
    printf("Test fwTPM:\tNo startup (INITIALIZE):\t\tPassed\n");
}

/* ================================================================== */
/* 3. Security Fix Regression Tests                                    */
/* ================================================================== */

/* Test MEDIUM-1: oversized auth area should return TPM_RC_AUTHSIZE */
static void test_fwtpm_auth_area_oversize(void)
{
    FWTPM_CTX ctx;
    int rc, rspSize, cmdSz;

    memset(&ctx, 0, sizeof(ctx));
    rc = fwtpm_test_startup(&ctx);
    AssertIntEQ(rc, 0);

    /* Build a GetCapability command with TPM_ST_SESSIONS tag but a
     * bogus oversized auth area. GetCapability doesn't normally use
     * sessions, but the auth area parser runs before dispatch for any
     * TPM_ST_SESSIONS command. */
    cmdSz = 0;
    PutU16BE(gCmd + cmdSz, TPM_ST_SESSIONS); cmdSz += 2;
    PutU32BE(gCmd + cmdSz, 0); cmdSz += 4; /* size placeholder */
    PutU32BE(gCmd + cmdSz, TPM_CC_GetCapability); cmdSz += 4;
    /* Auth area size = 0xFFFFFFFF (way too large) */
    PutU32BE(gCmd + cmdSz, 0xFFFFFFFF); cmdSz += 4;
    PutU32BE(gCmd + 2, (UINT32)cmdSz); /* fix total size */

    rspSize = 0;
    rc = FWTPM_ProcessCommand(&ctx, gCmd, cmdSz, gRsp, &rspSize, 0);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    /* Should get TPM_RC_AUTHSIZE (not silently clamped) */
    AssertIntEQ(GetRspRC(gRsp), TPM_RC_AUTHSIZE);

    FWTPM_Cleanup(&ctx);
    printf("Test fwTPM:\tAuth area oversize (MEDIUM-1):\tPassed\n");
}

/* Test MEDIUM-4: zero-size command should be caught */
static void test_fwtpm_zero_size_command(void)
{
    FWTPM_CTX ctx;
    int rc, rspSize;

    memset(&ctx, 0, sizeof(ctx));
    rc = fwtpm_test_startup(&ctx);
    AssertIntEQ(rc, 0);

    /* Send 0 bytes */
    rspSize = 0;
    rc = FWTPM_ProcessCommand(&ctx, gCmd, 0, gRsp, &rspSize, 0);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    AssertIntEQ(GetRspRC(gRsp), TPM_RC_COMMAND_SIZE);

    FWTPM_Cleanup(&ctx);
    printf("Test fwTPM:\tZero-size command (MEDIUM-4):\tPassed\n");
}

/* ================================================================== */
/* 4. GetRandom / StirRandom                                           */
/* ================================================================== */

static void test_fwtpm_getrandom(void)
{
    FWTPM_CTX ctx;
    int rc, rspSize, cmdSz;
    UINT16 rspTag;
    UINT32 rspSizeHdr;
    UINT16 randomSz;

    memset(&ctx, 0, sizeof(ctx));
    rc = fwtpm_test_startup(&ctx);
    AssertIntEQ(rc, 0);

    /* GetRandom(bytesRequested=32) */
    cmdSz = BuildCmdHeader(gCmd, TPM_ST_NO_SESSIONS, 12, TPM_CC_GetRandom);
    PutU16BE(gCmd + cmdSz, 32);
    cmdSz += 2;
    PutU32BE(gCmd + 2, (UINT32)cmdSz);

    rspSize = 0;
    rc = FWTPM_ProcessCommand(&ctx, gCmd, cmdSz, gRsp, &rspSize, 0);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    AssertIntEQ(GetRspRC(gRsp), TPM_RC_SUCCESS);

    /* Parse response: header(10) + TPM2B_DIGEST(2+N) */
    ParseRspHeader(gRsp, &rspTag, &rspSizeHdr, NULL);
    AssertIntEQ(rspTag, TPM_ST_NO_SESSIONS);
    randomSz = GetU16BE(gRsp + TPM2_HEADER_SIZE);
    AssertIntEQ(randomSz, 32);
    AssertIntEQ((int)rspSizeHdr, TPM2_HEADER_SIZE + 2 + 32);

    FWTPM_Cleanup(&ctx);
    printf("Test fwTPM:\tGetRandom(32):\t\t\tPassed\n");
}

static void test_fwtpm_getrandom_zero(void)
{
    FWTPM_CTX ctx;
    int rc, rspSize, cmdSz;

    memset(&ctx, 0, sizeof(ctx));
    rc = fwtpm_test_startup(&ctx);
    AssertIntEQ(rc, 0);

    /* GetRandom(bytesRequested=0) */
    cmdSz = BuildCmdHeader(gCmd, TPM_ST_NO_SESSIONS, 12, TPM_CC_GetRandom);
    PutU16BE(gCmd + cmdSz, 0);
    cmdSz += 2;
    PutU32BE(gCmd + 2, (UINT32)cmdSz);

    rspSize = 0;
    rc = FWTPM_ProcessCommand(&ctx, gCmd, cmdSz, gRsp, &rspSize, 0);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    AssertIntEQ(GetRspRC(gRsp), TPM_RC_SUCCESS);

    FWTPM_Cleanup(&ctx);
    printf("Test fwTPM:\tGetRandom(0):\t\t\tPassed\n");
}

static void test_fwtpm_stirrandom(void)
{
    FWTPM_CTX ctx;
    int rc, rspSize, cmdSz;

    memset(&ctx, 0, sizeof(ctx));
    rc = fwtpm_test_startup(&ctx);
    AssertIntEQ(rc, 0);

    /* StirRandom: tag(2) + size(4) + CC(4) + inData(2+N) */
    cmdSz = BuildCmdHeader(gCmd, TPM_ST_NO_SESSIONS, 0, TPM_CC_StirRandom);
    PutU16BE(gCmd + cmdSz, 8); /* 8 bytes of entropy */
    cmdSz += 2;
    memset(gCmd + cmdSz, 0xAB, 8);
    cmdSz += 8;
    PutU32BE(gCmd + 2, (UINT32)cmdSz);

    rspSize = 0;
    rc = FWTPM_ProcessCommand(&ctx, gCmd, cmdSz, gRsp, &rspSize, 0);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    AssertIntEQ(GetRspRC(gRsp), TPM_RC_SUCCESS);

    FWTPM_Cleanup(&ctx);
    printf("Test fwTPM:\tStirRandom:\t\t\tPassed\n");
}

/* ================================================================== */
/* 5. GetCapability                                                    */
/* ================================================================== */

static void test_fwtpm_getcap_algorithms(void)
{
    FWTPM_CTX ctx;
    int rc, rspSize, cmdSz;

    memset(&ctx, 0, sizeof(ctx));
    rc = fwtpm_test_startup(&ctx);
    AssertIntEQ(rc, 0);

    /* GetCapability(TPM_CAP_ALGS, first=0, count=64) */
    cmdSz = BuildCmdHeader(gCmd, TPM_ST_NO_SESSIONS, 0, TPM_CC_GetCapability);
    PutU32BE(gCmd + cmdSz, TPM_CAP_ALGS); cmdSz += 4;
    PutU32BE(gCmd + cmdSz, 0); cmdSz += 4;  /* property = 0 */
    PutU32BE(gCmd + cmdSz, 64); cmdSz += 4; /* propertyCount */
    PutU32BE(gCmd + 2, (UINT32)cmdSz);

    rspSize = 0;
    rc = FWTPM_ProcessCommand(&ctx, gCmd, cmdSz, gRsp, &rspSize, 0);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    AssertIntEQ(GetRspRC(gRsp), TPM_RC_SUCCESS);
    AssertIntGT(rspSize, TPM2_HEADER_SIZE);

    FWTPM_Cleanup(&ctx);
    printf("Test fwTPM:\tGetCapability(ALGS):\t\tPassed\n");
}

static void test_fwtpm_getcap_commands(void)
{
    FWTPM_CTX ctx;
    int rc, rspSize, cmdSz;

    memset(&ctx, 0, sizeof(ctx));
    rc = fwtpm_test_startup(&ctx);
    AssertIntEQ(rc, 0);

    /* GetCapability(TPM_CAP_COMMANDS, first=TPM_CC_FIRST, count=256) */
    cmdSz = BuildCmdHeader(gCmd, TPM_ST_NO_SESSIONS, 0, TPM_CC_GetCapability);
    PutU32BE(gCmd + cmdSz, TPM_CAP_COMMANDS); cmdSz += 4;
    PutU32BE(gCmd + cmdSz, TPM_CC_FIRST); cmdSz += 4;
    PutU32BE(gCmd + cmdSz, 256); cmdSz += 4;
    PutU32BE(gCmd + 2, (UINT32)cmdSz);

    rspSize = 0;
    rc = FWTPM_ProcessCommand(&ctx, gCmd, cmdSz, gRsp, &rspSize, 0);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    AssertIntEQ(GetRspRC(gRsp), TPM_RC_SUCCESS);
    AssertIntGT(rspSize, TPM2_HEADER_SIZE);

    FWTPM_Cleanup(&ctx);
    printf("Test fwTPM:\tGetCapability(COMMANDS):\t\tPassed\n");
}

static void test_fwtpm_getcap_properties(void)
{
    FWTPM_CTX ctx;
    int rc, rspSize, cmdSz;

    memset(&ctx, 0, sizeof(ctx));
    rc = fwtpm_test_startup(&ctx);
    AssertIntEQ(rc, 0);

    /* GetCapability(TPM_CAP_TPM_PROPERTIES, first=TPM_PT_MANUFACTURER, count=8) */
    cmdSz = BuildCmdHeader(gCmd, TPM_ST_NO_SESSIONS, 0, TPM_CC_GetCapability);
    PutU32BE(gCmd + cmdSz, TPM_CAP_TPM_PROPERTIES); cmdSz += 4;
    PutU32BE(gCmd + cmdSz, TPM_PT_MANUFACTURER); cmdSz += 4;
    PutU32BE(gCmd + cmdSz, 8); cmdSz += 4;
    PutU32BE(gCmd + 2, (UINT32)cmdSz);

    rspSize = 0;
    rc = FWTPM_ProcessCommand(&ctx, gCmd, cmdSz, gRsp, &rspSize, 0);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    AssertIntEQ(GetRspRC(gRsp), TPM_RC_SUCCESS);

    FWTPM_Cleanup(&ctx);
    printf("Test fwTPM:\tGetCapability(PROPERTIES):\tPassed\n");
}

static void test_fwtpm_getcap_pcrs(void)
{
    FWTPM_CTX ctx;
    int rc, rspSize, cmdSz;

    memset(&ctx, 0, sizeof(ctx));
    rc = fwtpm_test_startup(&ctx);
    AssertIntEQ(rc, 0);

    /* GetCapability(TPM_CAP_PCRS, first=0, count=1) */
    cmdSz = BuildCmdHeader(gCmd, TPM_ST_NO_SESSIONS, 0, TPM_CC_GetCapability);
    PutU32BE(gCmd + cmdSz, TPM_CAP_PCRS); cmdSz += 4;
    PutU32BE(gCmd + cmdSz, 0); cmdSz += 4;
    PutU32BE(gCmd + cmdSz, 1); cmdSz += 4;
    PutU32BE(gCmd + 2, (UINT32)cmdSz);

    rspSize = 0;
    rc = FWTPM_ProcessCommand(&ctx, gCmd, cmdSz, gRsp, &rspSize, 0);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    AssertIntEQ(GetRspRC(gRsp), TPM_RC_SUCCESS);

    FWTPM_Cleanup(&ctx);
    printf("Test fwTPM:\tGetCapability(PCRS):\t\tPassed\n");
}

/* ================================================================== */
/* 6. PCR Operations                                                   */
/* ================================================================== */

/* Build PCR_Read command for SHA-256 bank */
static int BuildPcrReadCmd(byte* buf, UINT32 pcrIndex)
{
    int pos;
    pos = BuildCmdHeader(buf, TPM_ST_NO_SESSIONS, 0, TPM_CC_PCR_Read);
    /* TPML_PCR_SELECTION: count=1 */
    PutU32BE(buf + pos, 1); pos += 4;
    /* TPMS_PCR_SELECTION: hash=SHA256, sizeofSelect=3, pcrSelect[3] */
    PutU16BE(buf + pos, TPM_ALG_SHA256); pos += 2;
    buf[pos++] = 3; /* sizeofSelect */
    /* Set bit for pcrIndex in the bitmap */
    buf[pos] = 0; buf[pos+1] = 0; buf[pos+2] = 0;
    if (pcrIndex < 24) {
        buf[pos + (pcrIndex / 8)] = (byte)(1 << (pcrIndex % 8));
    }
    pos += 3;
    PutU32BE(buf + 2, (UINT32)pos);
    return pos;
}

static void test_fwtpm_pcr_read(void)
{
    FWTPM_CTX ctx;
    int rc, rspSize, cmdSz;

    memset(&ctx, 0, sizeof(ctx));
    rc = fwtpm_test_startup(&ctx);
    AssertIntEQ(rc, 0);

    cmdSz = BuildPcrReadCmd(gCmd, 0);
    rspSize = 0;
    rc = FWTPM_ProcessCommand(&ctx, gCmd, cmdSz, gRsp, &rspSize, 0);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    AssertIntEQ(GetRspRC(gRsp), TPM_RC_SUCCESS);
    AssertIntGT(rspSize, TPM2_HEADER_SIZE);

    FWTPM_Cleanup(&ctx);
    printf("Test fwTPM:\tPCR_Read(0):\t\t\tPassed\n");
}

static void test_fwtpm_pcr_extend_and_read(void)
{
    FWTPM_CTX ctx;
    int rc, rspSize, cmdSz;
    byte digestBefore[32], digestAfter[32];
    int i;
    int allZero;

    memset(&ctx, 0, sizeof(ctx));
    rc = fwtpm_test_startup(&ctx);
    AssertIntEQ(rc, 0);

    /* Read PCR 16 (resettable) before extend */
    cmdSz = BuildPcrReadCmd(gCmd, 16);
    rspSize = 0;
    rc = FWTPM_ProcessCommand(&ctx, gCmd, cmdSz, gRsp, &rspSize, 0);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    AssertIntEQ(GetRspRC(gRsp), TPM_RC_SUCCESS);

    /* Extract digest from response. Response format:
     * header(10) + updateCounter(4) + pcrSelectionOut(varies) + pcrDigest
     * Skip to find the digest - locate the TPML_DIGEST section.
     * For simplicity, look for the 32-byte digest near end of response. */
    if (rspSize >= TPM2_HEADER_SIZE + 4 + 10 + 2 + 2 + 32) {
        /* Last 32 bytes before end should be the digest value */
        memcpy(digestBefore, gRsp + rspSize - 32, 32);
    }
    else {
        memset(digestBefore, 0, 32);
    }

    /* PCR_Extend on PCR 16 with SHA-256 */
    cmdSz = 0;
    PutU16BE(gCmd + cmdSz, TPM_ST_SESSIONS); cmdSz += 2;
    PutU32BE(gCmd + cmdSz, 0); cmdSz += 4; /* size placeholder */
    PutU32BE(gCmd + cmdSz, TPM_CC_PCR_Extend); cmdSz += 4;
    /* pcrHandle = PCR 16 */
    PutU32BE(gCmd + cmdSz, 16); cmdSz += 4;
    /* Auth area: size(4) + sessionHandle(4) + nonce(2) + attrs(1) + hmac(2) */
    PutU32BE(gCmd + cmdSz, 9); cmdSz += 4; /* authAreaSize */
    PutU32BE(gCmd + cmdSz, TPM_RS_PW); cmdSz += 4; /* password session */
    PutU16BE(gCmd + cmdSz, 0); cmdSz += 2; /* nonce size = 0 */
    gCmd[cmdSz++] = 0; /* attributes */
    PutU16BE(gCmd + cmdSz, 0); cmdSz += 2; /* hmac size = 0 (empty password) */
    /* TPML_DIGEST_VALUES: count=1 */
    PutU32BE(gCmd + cmdSz, 1); cmdSz += 4;
    /* TPMT_HA: hashAlg + digest */
    PutU16BE(gCmd + cmdSz, TPM_ALG_SHA256); cmdSz += 2;
    /* 32 bytes of digest data */
    memset(gCmd + cmdSz, 0x42, 32); cmdSz += 32;
    PutU32BE(gCmd + 2, (UINT32)cmdSz);

    rspSize = 0;
    rc = FWTPM_ProcessCommand(&ctx, gCmd, cmdSz, gRsp, &rspSize, 0);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    AssertIntEQ(GetRspRC(gRsp), TPM_RC_SUCCESS);

    /* Read PCR 16 again - should be different from before */
    cmdSz = BuildPcrReadCmd(gCmd, 16);
    rspSize = 0;
    rc = FWTPM_ProcessCommand(&ctx, gCmd, cmdSz, gRsp, &rspSize, 0);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    AssertIntEQ(GetRspRC(gRsp), TPM_RC_SUCCESS);

    if (rspSize >= TPM2_HEADER_SIZE + 4 + 10 + 2 + 2 + 32) {
        memcpy(digestAfter, gRsp + rspSize - 32, 32);
    }
    else {
        memset(digestAfter, 0xFF, 32);
    }

    /* Digest should have changed */
    allZero = 1;
    for (i = 0; i < 32; i++) {
        if (digestAfter[i] != 0) allZero = 0;
    }
    AssertFalse(allZero); /* After extend, PCR should not be all zeros */

    FWTPM_Cleanup(&ctx);
    printf("Test fwTPM:\tPCR_Extend + Read(16):\t\tPassed\n");
}

/* ================================================================== */
/* 7. ReadClock                                                        */
/* ================================================================== */

static void test_fwtpm_readclock(void)
{
    FWTPM_CTX ctx;
    int rc, rspSize, cmdSz;

    memset(&ctx, 0, sizeof(ctx));
    rc = fwtpm_test_startup(&ctx);
    AssertIntEQ(rc, 0);

    /* ReadClock: no parameters */
    cmdSz = BuildCmdHeader(gCmd, TPM_ST_NO_SESSIONS, 10, TPM_CC_ReadClock);
    rspSize = 0;
    rc = FWTPM_ProcessCommand(&ctx, gCmd, cmdSz, gRsp, &rspSize, 0);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    AssertIntEQ(GetRspRC(gRsp), TPM_RC_SUCCESS);
    /* Response should contain TPMS_TIME_INFO: clock(8) + resetCount(4) +
     * restartCount(4) + safe(1) + TPMS_CLOCK_INFO */
    AssertIntGT(rspSize, TPM2_HEADER_SIZE + 8);

    FWTPM_Cleanup(&ctx);
    printf("Test fwTPM:\tReadClock:\t\t\tPassed\n");
}

/* ================================================================== */
/* 8. CreatePrimary (RSA and ECC)                                      */
/* ================================================================== */

/* Build a minimal CreatePrimary command for RSA-2048 or ECC-256.
 * Uses password auth with empty password on owner hierarchy. */
static int BuildCreatePrimaryCmd(byte* buf, TPM_ALG_ID algType)
{
    int pos = 0;
    int pubAreaStart, pubAreaLen;
    int sensStart, sensLen;

    PutU16BE(buf + pos, TPM_ST_SESSIONS); pos += 2;
    PutU32BE(buf + pos, 0); pos += 4; /* size placeholder */
    PutU32BE(buf + pos, TPM_CC_CreatePrimary); pos += 4;
    /* primaryHandle = TPM_RH_OWNER */
    PutU32BE(buf + pos, TPM_RH_OWNER); pos += 4;
    /* Auth area: password session with empty password */
    PutU32BE(buf + pos, 9); pos += 4; /* authAreaSize */
    PutU32BE(buf + pos, TPM_RS_PW); pos += 4;
    PutU16BE(buf + pos, 0); pos += 2; /* nonce = 0 */
    buf[pos++] = 0; /* attributes */
    PutU16BE(buf + pos, 0); pos += 2; /* hmac = 0 */

    /* inSensitive (TPM2B_SENSITIVE_CREATE) */
    sensStart = pos;
    PutU16BE(buf + pos, 0); pos += 2; /* size placeholder */
    /* TPMS_SENSITIVE_CREATE: userAuth(2+0) + data(2+0) */
    PutU16BE(buf + pos, 0); pos += 2; /* userAuth size = 0 */
    PutU16BE(buf + pos, 0); pos += 2; /* data size = 0 */
    sensLen = pos - sensStart - 2;
    PutU16BE(buf + sensStart, (UINT16)sensLen);

    /* inPublic (TPM2B_PUBLIC) */
    pubAreaStart = pos;
    PutU16BE(buf + pos, 0); pos += 2; /* size placeholder */

    /* TPMT_PUBLIC */
    if (algType == TPM_ALG_RSA) {
        PutU16BE(buf + pos, TPM_ALG_RSA); pos += 2;     /* type */
        PutU16BE(buf + pos, TPM_ALG_SHA256); pos += 2;   /* nameAlg */
        /* objectAttributes: fixedTPM|fixedParent|sensitiveDataOrigin|
         * userWithAuth|restricted|decrypt */
        PutU32BE(buf + pos, 0x00030472); pos += 4;
        PutU16BE(buf + pos, 0); pos += 2; /* authPolicy size = 0 */
        /* TPMS_RSA_PARMS: symmetric(AES-128-CFB) + scheme(NULL) +
         * keyBits + exponent */
        PutU16BE(buf + pos, TPM_ALG_AES); pos += 2;  /* sym.algorithm */
        PutU16BE(buf + pos, 128); pos += 2;           /* sym.keyBits */
        PutU16BE(buf + pos, TPM_ALG_CFB); pos += 2;  /* sym.mode */
        PutU16BE(buf + pos, TPM_ALG_NULL); pos += 2;  /* scheme */
        PutU16BE(buf + pos, 2048); pos += 2;           /* keyBits */
        PutU32BE(buf + pos, 0); pos += 4;              /* exponent (0=default) */
        /* unique (TPM2B): size=0 (TPM generates) */
        PutU16BE(buf + pos, 0); pos += 2;
    }
    else { /* ECC */
        PutU16BE(buf + pos, TPM_ALG_ECC); pos += 2;     /* type */
        PutU16BE(buf + pos, TPM_ALG_SHA256); pos += 2;   /* nameAlg */
        PutU32BE(buf + pos, 0x00030472); pos += 4;       /* objectAttributes */
        PutU16BE(buf + pos, 0); pos += 2;                /* authPolicy = 0 */
        /* TPMS_ECC_PARMS: symmetric(AES-128-CFB) + scheme(NULL) +
         * curveID + kdf(NULL) */
        PutU16BE(buf + pos, TPM_ALG_AES); pos += 2;
        PutU16BE(buf + pos, 128); pos += 2;
        PutU16BE(buf + pos, TPM_ALG_CFB); pos += 2;
        PutU16BE(buf + pos, TPM_ALG_NULL); pos += 2; /* scheme */
        PutU16BE(buf + pos, TPM_ECC_NIST_P256); pos += 2; /* curveID */
        PutU16BE(buf + pos, TPM_ALG_NULL); pos += 2; /* kdf */
        /* unique: x(2+0) + y(2+0) */
        PutU16BE(buf + pos, 0); pos += 2;
        PutU16BE(buf + pos, 0); pos += 2;
    }

    pubAreaLen = pos - pubAreaStart - 2;
    PutU16BE(buf + pubAreaStart, (UINT16)pubAreaLen);

    /* outsideInfo (TPM2B) = empty */
    PutU16BE(buf + pos, 0); pos += 2;
    /* creationPCR (TPML_PCR_SELECTION) = empty */
    PutU32BE(buf + pos, 0); pos += 4;

    PutU32BE(buf + 2, (UINT32)pos);
    return pos;
}

#if !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN)
static void test_fwtpm_create_primary_rsa(void)
{
    FWTPM_CTX ctx;
    int rc, rspSize, cmdSz;
    UINT32 handle;

    memset(&ctx, 0, sizeof(ctx));
    rc = fwtpm_test_startup(&ctx);
    AssertIntEQ(rc, 0);

    cmdSz = BuildCreatePrimaryCmd(gCmd, TPM_ALG_RSA);
    rspSize = 0;
    rc = FWTPM_ProcessCommand(&ctx, gCmd, cmdSz, gRsp, &rspSize, 0);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    AssertIntEQ(GetRspRC(gRsp), TPM_RC_SUCCESS);
    AssertIntGT(rspSize, TPM2_HEADER_SIZE + 4);

    /* First 4 bytes after header is the object handle */
    handle = GetU32BE(gRsp + TPM2_HEADER_SIZE);
    AssertIntNE(handle, 0);

    /* Flush the key */
    cmdSz = BuildCmdHeader(gCmd, TPM_ST_NO_SESSIONS, 14, TPM_CC_FlushContext);
    PutU32BE(gCmd + cmdSz, handle);
    cmdSz += 4;
    rspSize = 0;
    rc = FWTPM_ProcessCommand(&ctx, gCmd, cmdSz, gRsp, &rspSize, 0);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    AssertIntEQ(GetRspRC(gRsp), TPM_RC_SUCCESS);

    FWTPM_Cleanup(&ctx);
    printf("Test fwTPM:\tCreatePrimary(RSA-2048):\t\tPassed\n");
}
#endif /* !NO_RSA && WOLFSSL_KEY_GEN */

#ifdef HAVE_ECC
static void test_fwtpm_create_primary_ecc(void)
{
    FWTPM_CTX ctx;
    int rc, rspSize, cmdSz;
    UINT32 handle;

    memset(&ctx, 0, sizeof(ctx));
    rc = fwtpm_test_startup(&ctx);
    AssertIntEQ(rc, 0);

    cmdSz = BuildCreatePrimaryCmd(gCmd, TPM_ALG_ECC);
    rspSize = 0;
    rc = FWTPM_ProcessCommand(&ctx, gCmd, cmdSz, gRsp, &rspSize, 0);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    AssertIntEQ(GetRspRC(gRsp), TPM_RC_SUCCESS);
    AssertIntGT(rspSize, TPM2_HEADER_SIZE + 4);

    handle = GetU32BE(gRsp + TPM2_HEADER_SIZE);
    AssertIntNE(handle, 0);

    /* Flush */
    cmdSz = BuildCmdHeader(gCmd, TPM_ST_NO_SESSIONS, 14, TPM_CC_FlushContext);
    PutU32BE(gCmd + cmdSz, handle);
    cmdSz += 4;
    rspSize = 0;
    rc = FWTPM_ProcessCommand(&ctx, gCmd, cmdSz, gRsp, &rspSize, 0);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    AssertIntEQ(GetRspRC(gRsp), TPM_RC_SUCCESS);

    FWTPM_Cleanup(&ctx);
    printf("Test fwTPM:\tCreatePrimary(ECC-P256):\t\tPassed\n");
}
#endif /* HAVE_ECC */

/* ================================================================== */
/* 9. Hash Sequence                                                    */
/* ================================================================== */

static void test_fwtpm_hash(void)
{
    FWTPM_CTX ctx;
    int rc, rspSize, cmdSz;

    memset(&ctx, 0, sizeof(ctx));
    rc = fwtpm_test_startup(&ctx);
    AssertIntEQ(rc, 0);

    /* TPM2_Hash: tag + size + CC + data(2+3) + hashAlg(2) + hierarchy(4) */
    cmdSz = BuildCmdHeader(gCmd, TPM_ST_NO_SESSIONS, 0, TPM_CC_Hash);
    PutU16BE(gCmd + cmdSz, 3); cmdSz += 2; /* data size = 3 */
    gCmd[cmdSz++] = 'a';
    gCmd[cmdSz++] = 'b';
    gCmd[cmdSz++] = 'c';
    PutU16BE(gCmd + cmdSz, TPM_ALG_SHA256); cmdSz += 2;
    PutU32BE(gCmd + cmdSz, TPM_RH_OWNER); cmdSz += 4;
    PutU32BE(gCmd + 2, (UINT32)cmdSz);

    rspSize = 0;
    rc = FWTPM_ProcessCommand(&ctx, gCmd, cmdSz, gRsp, &rspSize, 0);
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    AssertIntEQ(GetRspRC(gRsp), TPM_RC_SUCCESS);

    /* Response should have: header(10) + outDigest(2+32) + ticket */
    AssertIntGT(rspSize, TPM2_HEADER_SIZE + 2 + 32);

    /* Verify SHA-256("abc") = known value */
    {
        static const byte expected[] = {
            0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA,
            0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE, 0x22, 0x23,
            0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C,
            0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00, 0x15, 0xAD
        };
        UINT16 digestSz = GetU16BE(gRsp + TPM2_HEADER_SIZE);
        AssertIntEQ(digestSz, 32);
        Assert(memcmp(gRsp + TPM2_HEADER_SIZE + 2, expected, 32) == 0,
            ("SHA-256(abc) matches expected"), ("digest mismatch"));
    }

    FWTPM_Cleanup(&ctx);
    printf("Test fwTPM:\tHash(SHA256, \"abc\"):\t\tPassed\n");
}

/* ================================================================== */
/* 10. NULL pointer checks                                             */
/* ================================================================== */

static void test_fwtpm_null_args(void)
{
    int rc, rspSize = 0;
    FWTPM_CTX ctx;

    memset(&ctx, 0, sizeof(ctx));

    /* NULL ctx */
    rc = FWTPM_ProcessCommand(NULL, gCmd, 10, gRsp, &rspSize, 0);
    AssertIntEQ(rc, BAD_FUNC_ARG);

    /* NULL cmdBuf */
    rc = FWTPM_ProcessCommand(&ctx, NULL, 10, gRsp, &rspSize, 0);
    AssertIntEQ(rc, BAD_FUNC_ARG);

    /* NULL rspBuf */
    rc = FWTPM_ProcessCommand(&ctx, gCmd, 10, NULL, &rspSize, 0);
    AssertIntEQ(rc, BAD_FUNC_ARG);

    /* NULL rspSize */
    rc = FWTPM_ProcessCommand(&ctx, gCmd, 10, gRsp, NULL, 0);
    AssertIntEQ(rc, BAD_FUNC_ARG);

    /* NULL to Init */
    rc = FWTPM_Init(NULL);
    AssertIntEQ(rc, BAD_FUNC_ARG);

    printf("Test fwTPM:\tNULL arg checks:\t\tPassed\n");
}

/* ================================================================== */
/* Additional helpers for advanced tests                               */
/* ================================================================== */

/* Append a password auth area to buf at offset pos.
 * Returns new pos after auth area. */
static int AppendPwAuth(byte* buf, int pos, const byte* pw, int pwSz)
{
    int authStart = pos;
    PutU32BE(buf + pos, 0); pos += 4; /* authAreaSize placeholder */
    PutU32BE(buf + pos, TPM_RS_PW); pos += 4;
    PutU16BE(buf + pos, 0); pos += 2; /* nonce = 0 */
    buf[pos++] = 0; /* attributes */
    PutU16BE(buf + pos, (UINT16)pwSz); pos += 2;
    if (pwSz > 0 && pw != NULL) {
        memcpy(buf + pos, pw, pwSz);
        pos += pwSz;
    }
    PutU32BE(buf + authStart, (UINT32)(pos - authStart - 4));
    return pos;
}

/* Send a simple no-param session command (e.g. Clear, ChangeEPS, etc.) */
static TPM_RC SendSimpleSessionCmd(FWTPM_CTX* ctx, UINT32 cc,
    UINT32 handle)
{
    int pos = 0, rspSize = 0;
    PutU16BE(gCmd + pos, TPM_ST_SESSIONS); pos += 2;
    PutU32BE(gCmd + pos, 0); pos += 4;
    PutU32BE(gCmd + pos, cc); pos += 4;
    PutU32BE(gCmd + pos, handle); pos += 4;
    pos = AppendPwAuth(gCmd, pos, NULL, 0);
    PutU32BE(gCmd + 2, (UINT32)pos);
    FWTPM_ProcessCommand(ctx, gCmd, pos, gRsp, &rspSize, 0);
    return GetRspRC(gRsp);
}

/* Helper: create a primary and return its handle */
static UINT32 CreatePrimaryHelper(FWTPM_CTX* ctx, TPM_ALG_ID alg)
{
    int cmdSz, rspSize = 0;
    cmdSz = BuildCreatePrimaryCmd(gCmd, alg);
    FWTPM_ProcessCommand(ctx, gCmd, cmdSz, gRsp, &rspSize, 0);
    if (GetRspRC(gRsp) != TPM_RC_SUCCESS) return 0;
    return GetU32BE(gRsp + TPM2_HEADER_SIZE);
}

/* Helper: flush a handle */
static void FlushHandle(FWTPM_CTX* ctx, UINT32 handle)
{
    int rspSize = 0;
    BuildCmdHeader(gCmd, TPM_ST_NO_SESSIONS, 14, TPM_CC_FlushContext);
    PutU32BE(gCmd + 10, handle);
    FWTPM_ProcessCommand(ctx, gCmd, 14, gRsp, &rspSize, 0);
}

/* Helper: build StartAuthSession command. Returns cmd size. */
static int BuildStartAuthSessionCmd(byte* buf, UINT8 sessionType,
    UINT16 hashAlg)
{
    int pos;
    pos = BuildCmdHeader(buf, TPM_ST_NO_SESSIONS, 0, TPM_CC_StartAuthSession);
    PutU32BE(buf + pos, TPM_RH_NULL); pos += 4; /* tpmKey */
    PutU32BE(buf + pos, TPM_RH_NULL); pos += 4; /* bind */
    PutU16BE(buf + pos, 16); pos += 2; /* nonceCaller size */
    memset(buf + pos, 0xAA, 16); pos += 16; /* nonceCaller */
    PutU16BE(buf + pos, 0); pos += 2; /* encryptedSalt = 0 */
    buf[pos++] = sessionType;
    PutU16BE(buf + pos, TPM_ALG_NULL); pos += 2; /* symmetric */
    PutU16BE(buf + pos, hashAlg); pos += 2; /* authHash */
    PutU32BE(buf + 2, (UINT32)pos);
    return pos;
}

/* Helper: start a session and return its handle */
static UINT32 StartSessionHelper(FWTPM_CTX* ctx, UINT8 sessType)
{
    int cmdSz, rspSize = 0;
    cmdSz = BuildStartAuthSessionCmd(gCmd, sessType, TPM_ALG_SHA256);
    FWTPM_ProcessCommand(ctx, gCmd, cmdSz, gRsp, &rspSize, 0);
    if (GetRspRC(gRsp) != TPM_RC_SUCCESS) return 0;
    return GetU32BE(gRsp + TPM2_HEADER_SIZE);
}

#ifndef FWTPM_NO_POLICY
/* Helper: send a policy command that takes only sessionHandle */
static TPM_RC SendPolicyCmd(FWTPM_CTX* ctx, UINT32 cc, UINT32 sessHandle)
{
    int pos = 0, rspSize = 0;
    PutU16BE(gCmd + pos, TPM_ST_SESSIONS); pos += 2;
    PutU32BE(gCmd + pos, 0); pos += 4;
    PutU32BE(gCmd + pos, cc); pos += 4;
    PutU32BE(gCmd + pos, sessHandle); pos += 4;
    pos = AppendPwAuth(gCmd, pos, NULL, 0);
    PutU32BE(gCmd + 2, (UINT32)pos);
    FWTPM_ProcessCommand(ctx, gCmd, pos, gRsp, &rspSize, 0);
    return GetRspRC(gRsp);
}
#endif /* !FWTPM_NO_POLICY */

#ifndef FWTPM_NO_NV
/* Helper: build NV_DefineSpace command */
static int BuildNvDefineCmd(byte* buf, UINT32 nvIndex, UINT16 dataSize,
    UINT32 attributes)
{
    int pos = 0;
    int nvPubStart;
    PutU16BE(buf + pos, TPM_ST_SESSIONS); pos += 2;
    PutU32BE(buf + pos, 0); pos += 4;
    PutU32BE(buf + pos, TPM_CC_NV_DefineSpace); pos += 4;
    PutU32BE(buf + pos, TPM_RH_OWNER); pos += 4; /* authHandle */
    pos = AppendPwAuth(buf, pos, NULL, 0);
    PutU16BE(buf + pos, 0); pos += 2; /* auth size = 0 */
    /* TPM2B_NV_PUBLIC */
    nvPubStart = pos;
    PutU16BE(buf + pos, 0); pos += 2; /* size placeholder */
    PutU32BE(buf + pos, nvIndex); pos += 4;
    PutU16BE(buf + pos, TPM_ALG_SHA256); pos += 2; /* nameAlg */
    PutU32BE(buf + pos, attributes); pos += 4;
    PutU16BE(buf + pos, 0); pos += 2; /* authPolicy = 0 */
    PutU16BE(buf + pos, dataSize); pos += 2;
    PutU16BE(buf + nvPubStart, (UINT16)(pos - nvPubStart - 2));
    PutU32BE(buf + 2, (UINT32)pos);
    return pos;
}
#endif /* !FWTPM_NO_NV */

/* ================================================================== */
/* Group E: Sessions                                                   */
/* ================================================================== */

static void test_fwtpm_start_hmac_session(void)
{
    FWTPM_CTX ctx;
    UINT32 sessH;
    memset(&ctx, 0, sizeof(ctx));
    AssertIntEQ(fwtpm_test_startup(&ctx), 0);
    sessH = StartSessionHelper(&ctx, TPM_SE_HMAC);
    AssertIntNE(sessH, 0);
    FlushHandle(&ctx, sessH);
    FWTPM_Cleanup(&ctx);
    printf("Test fwTPM:\tStartAuthSession(HMAC):\t\tPassed\n");
}

static void test_fwtpm_start_policy_session(void)
{
    FWTPM_CTX ctx;
    UINT32 sessH;
    memset(&ctx, 0, sizeof(ctx));
    AssertIntEQ(fwtpm_test_startup(&ctx), 0);
    sessH = StartSessionHelper(&ctx, TPM_SE_POLICY);
    AssertIntNE(sessH, 0);
    FlushHandle(&ctx, sessH);
    FWTPM_Cleanup(&ctx);
    printf("Test fwTPM:\tStartAuthSession(POLICY):\tPassed\n");
}

static void test_fwtpm_start_trial_session(void)
{
    FWTPM_CTX ctx;
    UINT32 sessH;
    memset(&ctx, 0, sizeof(ctx));
    AssertIntEQ(fwtpm_test_startup(&ctx), 0);
    sessH = StartSessionHelper(&ctx, TPM_SE_TRIAL);
    AssertIntNE(sessH, 0);
    FlushHandle(&ctx, sessH);
    FWTPM_Cleanup(&ctx);
    printf("Test fwTPM:\tStartAuthSession(TRIAL):\t\tPassed\n");
}

/* ================================================================== */
/* Group F: Policy                                                     */
/* ================================================================== */

#ifndef FWTPM_NO_POLICY
static void test_fwtpm_policy_password(void)
{
    FWTPM_CTX ctx;
    UINT32 sessH;
    memset(&ctx, 0, sizeof(ctx));
    AssertIntEQ(fwtpm_test_startup(&ctx), 0);
    sessH = StartSessionHelper(&ctx, TPM_SE_POLICY);
    AssertIntNE(sessH, 0);
    AssertIntEQ(SendPolicyCmd(&ctx, TPM_CC_PolicyPassword, sessH), TPM_RC_SUCCESS);
    FlushHandle(&ctx, sessH);
    FWTPM_Cleanup(&ctx);
    printf("Test fwTPM:\tPolicyPassword:\t\t\tPassed\n");
}

static void test_fwtpm_policy_auth_value(void)
{
    FWTPM_CTX ctx;
    UINT32 sessH;
    memset(&ctx, 0, sizeof(ctx));
    AssertIntEQ(fwtpm_test_startup(&ctx), 0);
    sessH = StartSessionHelper(&ctx, TPM_SE_POLICY);
    AssertIntNE(sessH, 0);
    AssertIntEQ(SendPolicyCmd(&ctx, TPM_CC_PolicyAuthValue, sessH), TPM_RC_SUCCESS);
    FlushHandle(&ctx, sessH);
    FWTPM_Cleanup(&ctx);
    printf("Test fwTPM:\tPolicyAuthValue:\t\tPassed\n");
}

static void test_fwtpm_policy_get_digest(void)
{
    FWTPM_CTX ctx;
    UINT32 sessH;
    memset(&ctx, 0, sizeof(ctx));
    AssertIntEQ(fwtpm_test_startup(&ctx), 0);
    sessH = StartSessionHelper(&ctx, TPM_SE_POLICY);
    AssertIntNE(sessH, 0);
    AssertIntEQ(SendPolicyCmd(&ctx, TPM_CC_PolicyGetDigest, sessH), TPM_RC_SUCCESS);
    FlushHandle(&ctx, sessH);
    FWTPM_Cleanup(&ctx);
    printf("Test fwTPM:\tPolicyGetDigest:\t\tPassed\n");
}

static void test_fwtpm_policy_restart(void)
{
    FWTPM_CTX ctx;
    UINT32 sessH;
    memset(&ctx, 0, sizeof(ctx));
    AssertIntEQ(fwtpm_test_startup(&ctx), 0);
    sessH = StartSessionHelper(&ctx, TPM_SE_POLICY);
    AssertIntNE(sessH, 0);
    AssertIntEQ(SendPolicyCmd(&ctx, TPM_CC_PolicyPassword, sessH), TPM_RC_SUCCESS);
    AssertIntEQ(SendPolicyCmd(&ctx, TPM_CC_PolicyRestart, sessH), TPM_RC_SUCCESS);
    FlushHandle(&ctx, sessH);
    FWTPM_Cleanup(&ctx);
    printf("Test fwTPM:\tPolicyRestart:\t\t\tPassed\n");
}

static void test_fwtpm_policy_command_code(void)
{
    FWTPM_CTX ctx;
    UINT32 sessH;
    int pos, rspSize;
    memset(&ctx, 0, sizeof(ctx));
    AssertIntEQ(fwtpm_test_startup(&ctx), 0);
    sessH = StartSessionHelper(&ctx, TPM_SE_POLICY);
    AssertIntNE(sessH, 0);
    /* PolicyCommandCode(sessHandle, CC_GetRandom) */
    pos = 0;
    PutU16BE(gCmd + pos, TPM_ST_SESSIONS); pos += 2;
    PutU32BE(gCmd + pos, 0); pos += 4;
    PutU32BE(gCmd + pos, TPM_CC_PolicyCommandCode); pos += 4;
    PutU32BE(gCmd + pos, sessH); pos += 4;
    pos = AppendPwAuth(gCmd, pos, NULL, 0);
    PutU32BE(gCmd + pos, TPM_CC_GetRandom); pos += 4;
    PutU32BE(gCmd + 2, (UINT32)pos);
    rspSize = 0;
    FWTPM_ProcessCommand(&ctx, gCmd, pos, gRsp, &rspSize, 0);
    AssertIntEQ(GetRspRC(gRsp), TPM_RC_SUCCESS);
    FlushHandle(&ctx, sessH);
    FWTPM_Cleanup(&ctx);
    printf("Test fwTPM:\tPolicyCommandCode:\t\tPassed\n");
}

static void test_fwtpm_policy_locality(void)
{
    FWTPM_CTX ctx;
    UINT32 sessH;
    int pos, rspSize;
    memset(&ctx, 0, sizeof(ctx));
    AssertIntEQ(fwtpm_test_startup(&ctx), 0);
    sessH = StartSessionHelper(&ctx, TPM_SE_POLICY);
    AssertIntNE(sessH, 0);
    /* PolicyLocality(sessHandle, locality=1) */
    pos = 0;
    PutU16BE(gCmd + pos, TPM_ST_SESSIONS); pos += 2;
    PutU32BE(gCmd + pos, 0); pos += 4;
    PutU32BE(gCmd + pos, TPM_CC_PolicyLocality); pos += 4;
    PutU32BE(gCmd + pos, sessH); pos += 4;
    pos = AppendPwAuth(gCmd, pos, NULL, 0);
    gCmd[pos++] = 1; /* locality = 1 */
    PutU32BE(gCmd + 2, (UINT32)pos);
    rspSize = 0;
    FWTPM_ProcessCommand(&ctx, gCmd, pos, gRsp, &rspSize, 0);
    AssertIntEQ(GetRspRC(gRsp), TPM_RC_SUCCESS);
    FlushHandle(&ctx, sessH);
    FWTPM_Cleanup(&ctx);
    printf("Test fwTPM:\tPolicyLocality:\t\t\tPassed\n");
}

static void test_fwtpm_policy_pcr(void)
{
    FWTPM_CTX ctx;
    UINT32 sessH;
    int pos, rspSize;
    memset(&ctx, 0, sizeof(ctx));
    AssertIntEQ(fwtpm_test_startup(&ctx), 0);
    sessH = StartSessionHelper(&ctx, TPM_SE_POLICY);
    AssertIntNE(sessH, 0);
    /* PolicyPCR(sessHandle, pcrDigest=empty, pcrSelect=count 0) */
    pos = 0;
    PutU16BE(gCmd + pos, TPM_ST_SESSIONS); pos += 2;
    PutU32BE(gCmd + pos, 0); pos += 4;
    PutU32BE(gCmd + pos, TPM_CC_PolicyPCR); pos += 4;
    PutU32BE(gCmd + pos, sessH); pos += 4;
    pos = AppendPwAuth(gCmd, pos, NULL, 0);
    PutU16BE(gCmd + pos, 0); pos += 2; /* pcrDigest size = 0 */
    PutU32BE(gCmd + pos, 0); pos += 4; /* pcrSelect count = 0 */
    PutU32BE(gCmd + 2, (UINT32)pos);
    rspSize = 0;
    FWTPM_ProcessCommand(&ctx, gCmd, pos, gRsp, &rspSize, 0);
    AssertIntEQ(GetRspRC(gRsp), TPM_RC_SUCCESS);
    FlushHandle(&ctx, sessH);
    FWTPM_Cleanup(&ctx);
    printf("Test fwTPM:\tPolicyPCR:\t\t\tPassed\n");
}
#endif /* !FWTPM_NO_POLICY */

/* ================================================================== */
/* Group B: NV Operations                                              */
/* ================================================================== */

#ifndef FWTPM_NO_NV
static void test_fwtpm_nv_define_write_read(void)
{
    FWTPM_CTX ctx;
    int pos, rspSize, cmdSz;
    UINT32 nvIdx = 0x01500001;
    byte testData[] = {0xDE, 0xAD, 0xBE, 0xEF};
    UINT32 attrs = TPMA_NV_OWNERWRITE | TPMA_NV_OWNERREAD | TPMA_NV_NO_DA;

    memset(&ctx, 0, sizeof(ctx));
    AssertIntEQ(fwtpm_test_startup(&ctx), 0);

    /* NV_DefineSpace */
    cmdSz = BuildNvDefineCmd(gCmd, nvIdx, 32, attrs);
    rspSize = 0;
    FWTPM_ProcessCommand(&ctx, gCmd, cmdSz, gRsp, &rspSize, 0);
    AssertIntEQ(GetRspRC(gRsp), TPM_RC_SUCCESS);

    /* NV_Write */
    pos = 0;
    PutU16BE(gCmd + pos, TPM_ST_SESSIONS); pos += 2;
    PutU32BE(gCmd + pos, 0); pos += 4;
    PutU32BE(gCmd + pos, TPM_CC_NV_Write); pos += 4;
    PutU32BE(gCmd + pos, TPM_RH_OWNER); pos += 4; /* authHandle */
    PutU32BE(gCmd + pos, nvIdx); pos += 4;
    pos = AppendPwAuth(gCmd, pos, NULL, 0);
    PutU16BE(gCmd + pos, (UINT16)sizeof(testData)); pos += 2;
    memcpy(gCmd + pos, testData, sizeof(testData)); pos += sizeof(testData);
    PutU16BE(gCmd + pos, 0); pos += 2; /* offset = 0 */
    PutU32BE(gCmd + 2, (UINT32)pos);
    rspSize = 0;
    FWTPM_ProcessCommand(&ctx, gCmd, pos, gRsp, &rspSize, 0);
    AssertIntEQ(GetRspRC(gRsp), TPM_RC_SUCCESS);

    /* NV_Read */
    pos = 0;
    PutU16BE(gCmd + pos, TPM_ST_SESSIONS); pos += 2;
    PutU32BE(gCmd + pos, 0); pos += 4;
    PutU32BE(gCmd + pos, TPM_CC_NV_Read); pos += 4;
    PutU32BE(gCmd + pos, TPM_RH_OWNER); pos += 4;
    PutU32BE(gCmd + pos, nvIdx); pos += 4;
    pos = AppendPwAuth(gCmd, pos, NULL, 0);
    PutU16BE(gCmd + pos, (UINT16)sizeof(testData)); pos += 2; /* readSize */
    PutU16BE(gCmd + pos, 0); pos += 2; /* offset = 0 */
    PutU32BE(gCmd + 2, (UINT32)pos);
    rspSize = 0;
    FWTPM_ProcessCommand(&ctx, gCmd, pos, gRsp, &rspSize, 0);
    AssertIntEQ(GetRspRC(gRsp), TPM_RC_SUCCESS);

    /* NV_UndefineSpace */
    pos = 0;
    PutU16BE(gCmd + pos, TPM_ST_SESSIONS); pos += 2;
    PutU32BE(gCmd + pos, 0); pos += 4;
    PutU32BE(gCmd + pos, TPM_CC_NV_UndefineSpace); pos += 4;
    PutU32BE(gCmd + pos, TPM_RH_OWNER); pos += 4;
    PutU32BE(gCmd + pos, nvIdx); pos += 4;
    pos = AppendPwAuth(gCmd, pos, NULL, 0);
    PutU32BE(gCmd + 2, (UINT32)pos);
    rspSize = 0;
    FWTPM_ProcessCommand(&ctx, gCmd, pos, gRsp, &rspSize, 0);
    AssertIntEQ(GetRspRC(gRsp), TPM_RC_SUCCESS);

    FWTPM_Cleanup(&ctx);
    printf("Test fwTPM:\tNV Define/Write/Read/Undef:\tPassed\n");
}

static void test_fwtpm_nv_read_public(void)
{
    FWTPM_CTX ctx;
    int pos, rspSize, cmdSz;
    UINT32 nvIdx = 0x01500002;
    UINT32 attrs = TPMA_NV_OWNERWRITE | TPMA_NV_OWNERREAD | TPMA_NV_NO_DA;

    memset(&ctx, 0, sizeof(ctx));
    AssertIntEQ(fwtpm_test_startup(&ctx), 0);

    cmdSz = BuildNvDefineCmd(gCmd, nvIdx, 16, attrs);
    rspSize = 0;
    FWTPM_ProcessCommand(&ctx, gCmd, cmdSz, gRsp, &rspSize, 0);
    AssertIntEQ(GetRspRC(gRsp), TPM_RC_SUCCESS);

    /* NV_ReadPublic */
    pos = BuildCmdHeader(gCmd, TPM_ST_NO_SESSIONS, 0, TPM_CC_NV_ReadPublic);
    PutU32BE(gCmd + pos, nvIdx); pos += 4;
    PutU32BE(gCmd + 2, (UINT32)pos);
    rspSize = 0;
    FWTPM_ProcessCommand(&ctx, gCmd, pos, gRsp, &rspSize, 0);
    AssertIntEQ(GetRspRC(gRsp), TPM_RC_SUCCESS);
    AssertIntGT(rspSize, TPM2_HEADER_SIZE);

    /* Cleanup: undefine */
    pos = 0;
    PutU16BE(gCmd + pos, TPM_ST_SESSIONS); pos += 2;
    PutU32BE(gCmd + pos, 0); pos += 4;
    PutU32BE(gCmd + pos, TPM_CC_NV_UndefineSpace); pos += 4;
    PutU32BE(gCmd + pos, TPM_RH_OWNER); pos += 4;
    PutU32BE(gCmd + pos, nvIdx); pos += 4;
    pos = AppendPwAuth(gCmd, pos, NULL, 0);
    PutU32BE(gCmd + 2, (UINT32)pos);
    rspSize = 0;
    FWTPM_ProcessCommand(&ctx, gCmd, pos, gRsp, &rspSize, 0);

    FWTPM_Cleanup(&ctx);
    printf("Test fwTPM:\tNV_ReadPublic:\t\t\tPassed\n");
}

static void test_fwtpm_nv_counter(void)
{
    FWTPM_CTX ctx;
    int pos, rspSize, cmdSz;
    UINT32 nvIdx = 0x01500003;
    UINT32 attrs = TPMA_NV_OWNERWRITE | TPMA_NV_OWNERREAD | TPMA_NV_NO_DA |
                   ((UINT32)TPM_NT_COUNTER << 4);

    memset(&ctx, 0, sizeof(ctx));
    AssertIntEQ(fwtpm_test_startup(&ctx), 0);

    cmdSz = BuildNvDefineCmd(gCmd, nvIdx, 8, attrs);
    rspSize = 0;
    FWTPM_ProcessCommand(&ctx, gCmd, cmdSz, gRsp, &rspSize, 0);
    AssertIntEQ(GetRspRC(gRsp), TPM_RC_SUCCESS);

    /* NV_Increment */
    pos = 0;
    PutU16BE(gCmd + pos, TPM_ST_SESSIONS); pos += 2;
    PutU32BE(gCmd + pos, 0); pos += 4;
    PutU32BE(gCmd + pos, TPM_CC_NV_Increment); pos += 4;
    PutU32BE(gCmd + pos, TPM_RH_OWNER); pos += 4;
    PutU32BE(gCmd + pos, nvIdx); pos += 4;
    pos = AppendPwAuth(gCmd, pos, NULL, 0);
    PutU32BE(gCmd + 2, (UINT32)pos);
    rspSize = 0;
    FWTPM_ProcessCommand(&ctx, gCmd, pos, gRsp, &rspSize, 0);
    AssertIntEQ(GetRspRC(gRsp), TPM_RC_SUCCESS);

    /* Cleanup */
    pos = 0;
    PutU16BE(gCmd + pos, TPM_ST_SESSIONS); pos += 2;
    PutU32BE(gCmd + pos, 0); pos += 4;
    PutU32BE(gCmd + pos, TPM_CC_NV_UndefineSpace); pos += 4;
    PutU32BE(gCmd + pos, TPM_RH_OWNER); pos += 4;
    PutU32BE(gCmd + pos, nvIdx); pos += 4;
    pos = AppendPwAuth(gCmd, pos, NULL, 0);
    PutU32BE(gCmd + 2, (UINT32)pos);
    rspSize = 0;
    FWTPM_ProcessCommand(&ctx, gCmd, pos, gRsp, &rspSize, 0);

    FWTPM_Cleanup(&ctx);
    printf("Test fwTPM:\tNV_Increment (counter):\t\tPassed\n");
}
#endif /* !FWTPM_NO_NV */

/* ================================================================== */
/* Group H: Hierarchy & Misc                                           */
/* ================================================================== */

static void test_fwtpm_test_parms(void)
{
    FWTPM_CTX ctx;
    int pos, rspSize;
    memset(&ctx, 0, sizeof(ctx));
    AssertIntEQ(fwtpm_test_startup(&ctx), 0);

    /* TestParms: RSA-2048 */
    pos = BuildCmdHeader(gCmd, TPM_ST_NO_SESSIONS, 0, TPM_CC_TestParms);
    PutU16BE(gCmd + pos, TPM_ALG_RSA); pos += 2;
    PutU16BE(gCmd + pos, 2048); pos += 2; /* keyBits */
    PutU32BE(gCmd + pos, 0); pos += 4; /* exponent */
    PutU16BE(gCmd + pos, TPM_ALG_NULL); pos += 2; /* scheme */
    PutU32BE(gCmd + 2, (UINT32)pos);
    rspSize = 0;
    FWTPM_ProcessCommand(&ctx, gCmd, pos, gRsp, &rspSize, 0);
    AssertIntEQ(GetRspRC(gRsp), TPM_RC_SUCCESS);

    FWTPM_Cleanup(&ctx);
    printf("Test fwTPM:\tTestParms(RSA-2048):\t\tPassed\n");
}

static void test_fwtpm_incremental_selftest(void)
{
    FWTPM_CTX ctx;
    int pos, rspSize;
    memset(&ctx, 0, sizeof(ctx));
    AssertIntEQ(fwtpm_test_startup(&ctx), 0);

    /* IncrementalSelfTest: algCount=1, alg=SHA256 */
    pos = BuildCmdHeader(gCmd, TPM_ST_NO_SESSIONS, 0,
        TPM_CC_IncrementalSelfTest);
    PutU32BE(gCmd + pos, 1); pos += 4; /* algCount */
    PutU16BE(gCmd + pos, TPM_ALG_SHA256); pos += 2;
    PutU32BE(gCmd + 2, (UINT32)pos);
    rspSize = 0;
    FWTPM_ProcessCommand(&ctx, gCmd, pos, gRsp, &rspSize, 0);
    AssertIntEQ(GetRspRC(gRsp), TPM_RC_SUCCESS);

    /* GetTestResult */
    pos = BuildCmdHeader(gCmd, TPM_ST_NO_SESSIONS, 10, TPM_CC_GetTestResult);
    rspSize = 0;
    FWTPM_ProcessCommand(&ctx, gCmd, pos, gRsp, &rspSize, 0);
    AssertIntEQ(GetRspRC(gRsp), TPM_RC_SUCCESS);

    FWTPM_Cleanup(&ctx);
    printf("Test fwTPM:\tIncrementalSelfTest/GetResult:\tPassed\n");
}

static void test_fwtpm_pcr_reset(void)
{
    FWTPM_CTX ctx;
    memset(&ctx, 0, sizeof(ctx));
    AssertIntEQ(fwtpm_test_startup(&ctx), 0);

    /* PCR_Reset(16) - resettable PCR */
    AssertIntEQ(SendSimpleSessionCmd(&ctx, TPM_CC_PCR_Reset, 16),
        TPM_RC_SUCCESS);

    FWTPM_Cleanup(&ctx);
    printf("Test fwTPM:\tPCR_Reset(16):\t\t\tPassed\n");
}

static void test_fwtpm_pcr_event(void)
{
    FWTPM_CTX ctx;
    int pos, rspSize;
    memset(&ctx, 0, sizeof(ctx));
    AssertIntEQ(fwtpm_test_startup(&ctx), 0);

    /* PCR_Event(16, eventData="test") */
    pos = 0;
    PutU16BE(gCmd + pos, TPM_ST_SESSIONS); pos += 2;
    PutU32BE(gCmd + pos, 0); pos += 4;
    PutU32BE(gCmd + pos, TPM_CC_PCR_Event); pos += 4;
    PutU32BE(gCmd + pos, 16); pos += 4; /* pcrHandle */
    pos = AppendPwAuth(gCmd, pos, NULL, 0);
    PutU16BE(gCmd + pos, 4); pos += 2; /* eventData size */
    memcpy(gCmd + pos, "test", 4); pos += 4;
    PutU32BE(gCmd + 2, (UINT32)pos);
    rspSize = 0;
    FWTPM_ProcessCommand(&ctx, gCmd, pos, gRsp, &rspSize, 0);
    AssertIntEQ(GetRspRC(gRsp), TPM_RC_SUCCESS);

    FWTPM_Cleanup(&ctx);
    printf("Test fwTPM:\tPCR_Event(16):\t\t\tPassed\n");
}

static void test_fwtpm_hierarchy_change_auth(void)
{
    FWTPM_CTX ctx;
    int pos, rspSize;
    byte newAuth[] = {0x01, 0x02, 0x03, 0x04};
    memset(&ctx, 0, sizeof(ctx));
    AssertIntEQ(fwtpm_test_startup(&ctx), 0);

    /* HierarchyChangeAuth(OWNER, newAuth) */
    pos = 0;
    PutU16BE(gCmd + pos, TPM_ST_SESSIONS); pos += 2;
    PutU32BE(gCmd + pos, 0); pos += 4;
    PutU32BE(gCmd + pos, TPM_CC_HierarchyChangeAuth); pos += 4;
    PutU32BE(gCmd + pos, TPM_RH_OWNER); pos += 4;
    pos = AppendPwAuth(gCmd, pos, NULL, 0);
    PutU16BE(gCmd + pos, (UINT16)sizeof(newAuth)); pos += 2;
    memcpy(gCmd + pos, newAuth, sizeof(newAuth)); pos += sizeof(newAuth);
    PutU32BE(gCmd + 2, (UINT32)pos);
    rspSize = 0;
    FWTPM_ProcessCommand(&ctx, gCmd, pos, gRsp, &rspSize, 0);
    AssertIntEQ(GetRspRC(gRsp), TPM_RC_SUCCESS);

    /* Reset auth back to empty (using new auth) */
    pos = 0;
    PutU16BE(gCmd + pos, TPM_ST_SESSIONS); pos += 2;
    PutU32BE(gCmd + pos, 0); pos += 4;
    PutU32BE(gCmd + pos, TPM_CC_HierarchyChangeAuth); pos += 4;
    PutU32BE(gCmd + pos, TPM_RH_OWNER); pos += 4;
    pos = AppendPwAuth(gCmd, pos, newAuth, sizeof(newAuth));
    PutU16BE(gCmd + pos, 0); pos += 2; /* empty new auth */
    PutU32BE(gCmd + 2, (UINT32)pos);
    rspSize = 0;
    FWTPM_ProcessCommand(&ctx, gCmd, pos, gRsp, &rspSize, 0);
    AssertIntEQ(GetRspRC(gRsp), TPM_RC_SUCCESS);

    FWTPM_Cleanup(&ctx);
    printf("Test fwTPM:\tHierarchyChangeAuth:\t\tPassed\n");
}

static void test_fwtpm_clear(void)
{
    FWTPM_CTX ctx;
    memset(&ctx, 0, sizeof(ctx));
    AssertIntEQ(fwtpm_test_startup(&ctx), 0);

    AssertIntEQ(SendSimpleSessionCmd(&ctx, TPM_CC_Clear, TPM_RH_LOCKOUT),
        TPM_RC_SUCCESS);

    FWTPM_Cleanup(&ctx);
    printf("Test fwTPM:\tClear(LOCKOUT):\t\t\tPassed\n");
}

static void test_fwtpm_change_eps(void)
{
    FWTPM_CTX ctx;
    memset(&ctx, 0, sizeof(ctx));
    AssertIntEQ(fwtpm_test_startup(&ctx), 0);

    AssertIntEQ(SendSimpleSessionCmd(&ctx, TPM_CC_ChangeEPS, TPM_RH_PLATFORM),
        TPM_RC_SUCCESS);

    FWTPM_Cleanup(&ctx);
    printf("Test fwTPM:\tChangeEPS:\t\t\tPassed\n");
}

static void test_fwtpm_change_pps(void)
{
    FWTPM_CTX ctx;
    memset(&ctx, 0, sizeof(ctx));
    AssertIntEQ(fwtpm_test_startup(&ctx), 0);

    AssertIntEQ(SendSimpleSessionCmd(&ctx, TPM_CC_ChangePPS, TPM_RH_PLATFORM),
        TPM_RC_SUCCESS);

    FWTPM_Cleanup(&ctx);
    printf("Test fwTPM:\tChangePPS:\t\t\tPassed\n");
}

#ifndef FWTPM_NO_DA
static void test_fwtpm_da_parameters_and_reset(void)
{
    FWTPM_CTX ctx;
    int pos, rspSize;
    memset(&ctx, 0, sizeof(ctx));
    AssertIntEQ(fwtpm_test_startup(&ctx), 0);

    /* DictionaryAttackParameters(lockout, maxTries=10, recovery=60, lockout=300) */
    pos = 0;
    PutU16BE(gCmd + pos, TPM_ST_SESSIONS); pos += 2;
    PutU32BE(gCmd + pos, 0); pos += 4;
    PutU32BE(gCmd + pos, TPM_CC_DictionaryAttackParameters); pos += 4;
    PutU32BE(gCmd + pos, TPM_RH_LOCKOUT); pos += 4;
    pos = AppendPwAuth(gCmd, pos, NULL, 0);
    PutU32BE(gCmd + pos, 10); pos += 4;  /* newMaxTries */
    PutU32BE(gCmd + pos, 60); pos += 4;  /* newRecoveryTime */
    PutU32BE(gCmd + pos, 300); pos += 4; /* lockoutRecovery */
    PutU32BE(gCmd + 2, (UINT32)pos);
    rspSize = 0;
    FWTPM_ProcessCommand(&ctx, gCmd, pos, gRsp, &rspSize, 0);
    AssertIntEQ(GetRspRC(gRsp), TPM_RC_SUCCESS);

    /* DictionaryAttackLockReset */
    AssertIntEQ(SendSimpleSessionCmd(&ctx, TPM_CC_DictionaryAttackLockReset,
        TPM_RH_LOCKOUT), TPM_RC_SUCCESS);

    FWTPM_Cleanup(&ctx);
    printf("Test fwTPM:\tDA Parameters/LockReset:\t\tPassed\n");
}
#endif /* !FWTPM_NO_DA */

static void test_fwtpm_read_public(void)
{
    FWTPM_CTX ctx;
    int pos, rspSize;
    UINT32 keyH;
    memset(&ctx, 0, sizeof(ctx));
    AssertIntEQ(fwtpm_test_startup(&ctx), 0);

#ifdef HAVE_ECC
    keyH = CreatePrimaryHelper(&ctx, TPM_ALG_ECC);
#else
    keyH = CreatePrimaryHelper(&ctx, TPM_ALG_RSA);
#endif
    AssertIntNE(keyH, 0);

    /* ReadPublic */
    pos = BuildCmdHeader(gCmd, TPM_ST_NO_SESSIONS, 0, TPM_CC_ReadPublic);
    PutU32BE(gCmd + pos, keyH); pos += 4;
    PutU32BE(gCmd + 2, (UINT32)pos);
    rspSize = 0;
    FWTPM_ProcessCommand(&ctx, gCmd, pos, gRsp, &rspSize, 0);
    AssertIntEQ(GetRspRC(gRsp), TPM_RC_SUCCESS);
    AssertIntGT(rspSize, TPM2_HEADER_SIZE + 4);

    FlushHandle(&ctx, keyH);
    FWTPM_Cleanup(&ctx);
    printf("Test fwTPM:\tReadPublic:\t\t\tPassed\n");
}

/* ================================================================== */
/* Group D: Hash/HMAC Sequences                                        */
/* ================================================================== */

static void test_fwtpm_hash_sequence(void)
{
    FWTPM_CTX ctx;
    int pos, rspSize;
    UINT32 seqH;
    memset(&ctx, 0, sizeof(ctx));
    AssertIntEQ(fwtpm_test_startup(&ctx), 0);

    /* HashSequenceStart(auth=empty, hashAlg=SHA256) */
    pos = BuildCmdHeader(gCmd, TPM_ST_NO_SESSIONS, 0, TPM_CC_HashSequenceStart);
    PutU16BE(gCmd + pos, 0); pos += 2; /* auth size = 0 */
    PutU16BE(gCmd + pos, TPM_ALG_SHA256); pos += 2;
    PutU32BE(gCmd + 2, (UINT32)pos);
    rspSize = 0;
    FWTPM_ProcessCommand(&ctx, gCmd, pos, gRsp, &rspSize, 0);
    AssertIntEQ(GetRspRC(gRsp), TPM_RC_SUCCESS);
    seqH = GetU32BE(gRsp + TPM2_HEADER_SIZE);
    AssertIntNE(seqH, 0);

    /* SequenceUpdate(seqHandle, data="abc") */
    pos = 0;
    PutU16BE(gCmd + pos, TPM_ST_SESSIONS); pos += 2;
    PutU32BE(gCmd + pos, 0); pos += 4;
    PutU32BE(gCmd + pos, TPM_CC_SequenceUpdate); pos += 4;
    PutU32BE(gCmd + pos, seqH); pos += 4;
    pos = AppendPwAuth(gCmd, pos, NULL, 0);
    PutU16BE(gCmd + pos, 3); pos += 2;
    memcpy(gCmd + pos, "abc", 3); pos += 3;
    PutU32BE(gCmd + 2, (UINT32)pos);
    rspSize = 0;
    FWTPM_ProcessCommand(&ctx, gCmd, pos, gRsp, &rspSize, 0);
    AssertIntEQ(GetRspRC(gRsp), TPM_RC_SUCCESS);

    /* SequenceComplete(seqHandle, buffer=empty, hierarchy=OWNER) */
    pos = 0;
    PutU16BE(gCmd + pos, TPM_ST_SESSIONS); pos += 2;
    PutU32BE(gCmd + pos, 0); pos += 4;
    PutU32BE(gCmd + pos, TPM_CC_SequenceComplete); pos += 4;
    PutU32BE(gCmd + pos, seqH); pos += 4;
    pos = AppendPwAuth(gCmd, pos, NULL, 0);
    PutU16BE(gCmd + pos, 0); pos += 2; /* buffer size = 0 */
    PutU32BE(gCmd + pos, TPM_RH_OWNER); pos += 4;
    PutU32BE(gCmd + 2, (UINT32)pos);
    rspSize = 0;
    FWTPM_ProcessCommand(&ctx, gCmd, pos, gRsp, &rspSize, 0);
    AssertIntEQ(GetRspRC(gRsp), TPM_RC_SUCCESS);

    FWTPM_Cleanup(&ctx);
    printf("Test fwTPM:\tHashSequence (Start/Upd/Comp):\tPassed\n");
}

#ifdef HAVE_ECC
static void test_fwtpm_ecc_parameters(void)
{
    FWTPM_CTX ctx;
    int pos, rspSize;
    memset(&ctx, 0, sizeof(ctx));
    AssertIntEQ(fwtpm_test_startup(&ctx), 0);

    /* ECC_Parameters(curveID=NIST_P256) */
    pos = BuildCmdHeader(gCmd, TPM_ST_NO_SESSIONS, 0, TPM_CC_ECC_Parameters);
    PutU16BE(gCmd + pos, TPM_ECC_NIST_P256); pos += 2;
    PutU32BE(gCmd + 2, (UINT32)pos);
    rspSize = 0;
    FWTPM_ProcessCommand(&ctx, gCmd, pos, gRsp, &rspSize, 0);
    AssertIntEQ(GetRspRC(gRsp), TPM_RC_SUCCESS);
    AssertIntGT(rspSize, TPM2_HEADER_SIZE);

    FWTPM_Cleanup(&ctx);
    printf("Test fwTPM:\tECC_Parameters(P256):\t\tPassed\n");
}
#endif

static void test_fwtpm_context_save(void)
{
    FWTPM_CTX ctx;
    int rspSize;
    UINT32 keyH;
    memset(&ctx, 0, sizeof(ctx));
    AssertIntEQ(fwtpm_test_startup(&ctx), 0);

#ifdef HAVE_ECC
    keyH = CreatePrimaryHelper(&ctx, TPM_ALG_ECC);
#else
    keyH = CreatePrimaryHelper(&ctx, TPM_ALG_RSA);
#endif
    AssertIntNE(keyH, 0);

    /* ContextSave */
    BuildCmdHeader(gCmd, TPM_ST_NO_SESSIONS, 14, TPM_CC_ContextSave);
    PutU32BE(gCmd + 10, keyH);
    rspSize = 0;
    FWTPM_ProcessCommand(&ctx, gCmd, 14, gRsp, &rspSize, 0);
    AssertIntEQ(GetRspRC(gRsp), TPM_RC_SUCCESS);
    AssertIntGT(rspSize, TPM2_HEADER_SIZE + 16);

    FlushHandle(&ctx, keyH);
    FWTPM_Cleanup(&ctx);
    printf("Test fwTPM:\tContextSave:\t\t\tPassed\n");
}

static void test_fwtpm_evict_control(void)
{
    FWTPM_CTX ctx;
    int pos, rspSize;
    UINT32 keyH;
    UINT32 persH = 0x81000001;
    memset(&ctx, 0, sizeof(ctx));
    AssertIntEQ(fwtpm_test_startup(&ctx), 0);

#ifdef HAVE_ECC
    keyH = CreatePrimaryHelper(&ctx, TPM_ALG_ECC);
#else
    keyH = CreatePrimaryHelper(&ctx, TPM_ALG_RSA);
#endif
    AssertIntNE(keyH, 0);

    /* EvictControl: make persistent */
    pos = 0;
    PutU16BE(gCmd + pos, TPM_ST_SESSIONS); pos += 2;
    PutU32BE(gCmd + pos, 0); pos += 4;
    PutU32BE(gCmd + pos, TPM_CC_EvictControl); pos += 4;
    PutU32BE(gCmd + pos, TPM_RH_OWNER); pos += 4;
    PutU32BE(gCmd + pos, keyH); pos += 4;
    pos = AppendPwAuth(gCmd, pos, NULL, 0);
    PutU32BE(gCmd + pos, persH); pos += 4;
    PutU32BE(gCmd + 2, (UINT32)pos);
    rspSize = 0;
    FWTPM_ProcessCommand(&ctx, gCmd, pos, gRsp, &rspSize, 0);
    AssertIntEQ(GetRspRC(gRsp), TPM_RC_SUCCESS);

    /* Flush transient */
    FlushHandle(&ctx, keyH);

    /* EvictControl: remove persistent */
    pos = 0;
    PutU16BE(gCmd + pos, TPM_ST_SESSIONS); pos += 2;
    PutU32BE(gCmd + pos, 0); pos += 4;
    PutU32BE(gCmd + pos, TPM_CC_EvictControl); pos += 4;
    PutU32BE(gCmd + pos, TPM_RH_OWNER); pos += 4;
    PutU32BE(gCmd + pos, persH); pos += 4;
    pos = AppendPwAuth(gCmd, pos, NULL, 0);
    PutU32BE(gCmd + pos, persH); pos += 4;
    PutU32BE(gCmd + 2, (UINT32)pos);
    rspSize = 0;
    FWTPM_ProcessCommand(&ctx, gCmd, pos, gRsp, &rspSize, 0);
    AssertIntEQ(GetRspRC(gRsp), TPM_RC_SUCCESS);

    FWTPM_Cleanup(&ctx);
    printf("Test fwTPM:\tEvictControl (persist/remove):\tPassed\n");
}

static void test_fwtpm_clock_set(void)
{
    FWTPM_CTX ctx;
    int pos, rspSize;
    memset(&ctx, 0, sizeof(ctx));
    AssertIntEQ(fwtpm_test_startup(&ctx), 0);

    /* ClockSet(auth=OWNER, newTime=1000000) */
    pos = 0;
    PutU16BE(gCmd + pos, TPM_ST_SESSIONS); pos += 2;
    PutU32BE(gCmd + pos, 0); pos += 4;
    PutU32BE(gCmd + pos, TPM_CC_ClockSet); pos += 4;
    PutU32BE(gCmd + pos, TPM_RH_OWNER); pos += 4;
    pos = AppendPwAuth(gCmd, pos, NULL, 0);
    /* newTime (UINT64, big-endian) */
    PutU32BE(gCmd + pos, 0); pos += 4;
    PutU32BE(gCmd + pos, 1000000); pos += 4;
    PutU32BE(gCmd + 2, (UINT32)pos);
    rspSize = 0;
    FWTPM_ProcessCommand(&ctx, gCmd, pos, gRsp, &rspSize, 0);
    AssertIntEQ(GetRspRC(gRsp), TPM_RC_SUCCESS);

    /* ClockRateAdjust(auth=OWNER, rateAdjust=0) */
    pos = 0;
    PutU16BE(gCmd + pos, TPM_ST_SESSIONS); pos += 2;
    PutU32BE(gCmd + pos, 0); pos += 4;
    PutU32BE(gCmd + pos, TPM_CC_ClockRateAdjust); pos += 4;
    PutU32BE(gCmd + pos, TPM_RH_OWNER); pos += 4;
    pos = AppendPwAuth(gCmd, pos, NULL, 0);
    gCmd[pos++] = 0; /* rateAdjust = no change */
    PutU32BE(gCmd + 2, (UINT32)pos);
    rspSize = 0;
    FWTPM_ProcessCommand(&ctx, gCmd, pos, gRsp, &rspSize, 0);
    AssertIntEQ(GetRspRC(gRsp), TPM_RC_SUCCESS);

    FWTPM_Cleanup(&ctx);
    printf("Test fwTPM:\tClockSet/ClockRateAdjust:\tPassed\n");
}

/* ================================================================== */
/* HAL registration tests                                              */
/* ================================================================== */

/* Mock clock HAL state */
static UINT64 gMockClockMs;
static int    gMockClockCalls;
static void*  gMockClockCtxSeen;

static UINT64 mock_clock_get_ms(void* ctx)
{
    gMockClockCalls++;
    gMockClockCtxSeen = ctx;
    return gMockClockMs;
}

static void test_fwtpm_clock_sethal(void)
{
    FWTPM_CTX ctx;
    int rc;
    UINT64 v;
    void* halCtx = (void*)0xC0FFEE;

    memset(&ctx, 0, sizeof(ctx));
    rc = FWTPM_Init(&ctx);
    AssertIntEQ(rc, 0);

    /* Register mock clock HAL */
    gMockClockMs = 0x12345678ULL;
    gMockClockCalls = 0;
    gMockClockCtxSeen = NULL;
    rc = FWTPM_Clock_SetHAL(&ctx, mock_clock_get_ms, halCtx);
    AssertIntEQ(rc, 0);

    /* Verify callback fires. FWTPM_Clock_GetMs returns
     * clockHal.get_ms() + ctx->clockOffset — so verify the relative
     * contribution of the mock, not the absolute value. */
    v = FWTPM_Clock_GetMs(&ctx);
    AssertIntGT(gMockClockCalls, 0);
    AssertTrue(gMockClockCtxSeen == halCtx);
    AssertIntEQ((int)((v - ctx.clockOffset) & 0xFFFFFFFFU), 0x12345678);

    /* Confirm the HAL is re-read on every call: change mock value,
     * verify next call reflects it. */
    gMockClockMs = 0xABCDEF00ULL;
    v = FWTPM_Clock_GetMs(&ctx);
    AssertIntEQ((int)((v - ctx.clockOffset) & 0xFFFFFFFFU), (int)0xABCDEF00);

    /* Error path: NULL ctx must be rejected */
    rc = FWTPM_Clock_SetHAL(NULL, mock_clock_get_ms, NULL);
    AssertIntNE(rc, 0);

    FWTPM_Cleanup(&ctx);
    printf("Test fwTPM:\tClock HAL:\t\t\tPassed\n");
}

#ifndef FWTPM_NO_NV
/* Mock NV HAL backend: 64 KB byte buffer with per-call counters. */
#define MOCK_NV_SIZE (64 * 1024)
static byte gMockNvStore[MOCK_NV_SIZE];
static int  gMockNvReads;
static int  gMockNvWrites;
static int  gMockNvErases;

static int mock_nv_read(void* c, word32 off, byte* buf, word32 sz)
{
    (void)c;
    if ((size_t)off + sz > MOCK_NV_SIZE) {
        return -1;
    }
    memcpy(buf, gMockNvStore + off, sz);
    gMockNvReads++;
    return TPM_RC_SUCCESS;
}
static int mock_nv_write(void* c, word32 off, const byte* buf, word32 sz)
{
    (void)c;
    if ((size_t)off + sz > MOCK_NV_SIZE) {
        return -1;
    }
    memcpy(gMockNvStore + off, buf, sz);
    gMockNvWrites++;
    return TPM_RC_SUCCESS;
}
static int mock_nv_erase(void* c, word32 off, word32 sz)
{
    (void)c;
    if ((size_t)off + sz > MOCK_NV_SIZE) {
        return -1;
    }
    memset(gMockNvStore + off, 0xFF, sz);
    gMockNvErases++;
    return TPM_RC_SUCCESS;
}
#endif /* !FWTPM_NO_NV */

/* Register a mock NV HAL before FWTPM_Init and verify that NV writes
 * go to the mock backend rather than the default file. */
static void test_fwtpm_nv_sethal_mock(void)
{
#ifndef FWTPM_NO_NV
    FWTPM_CTX ctx;
    FWTPM_NV_HAL hal;
    int rc;

    /* Fresh mock store: erased-flash pattern */
    memset(gMockNvStore, 0xFF, sizeof(gMockNvStore));
    gMockNvReads = gMockNvWrites = gMockNvErases = 0;

    memset(&ctx, 0, sizeof(ctx));
    memset(&hal, 0, sizeof(hal));
    hal.read   = mock_nv_read;
    hal.write  = mock_nv_write;
    hal.erase  = mock_nv_erase;
    hal.ctx    = NULL;
    hal.maxSize = MOCK_NV_SIZE;

    /* SetHAL before Init: FWTPM_Init preserves pre-set HAL */
    rc = FWTPM_NV_SetHAL(&ctx, &hal);
    AssertIntEQ(rc, 0);

    rc = FWTPM_Init(&ctx);
    AssertIntEQ(rc, 0);

    /* Fresh init must have written the journal header + seed state via
     * the mock HAL. If this fails, the mock was not wired up. */
    AssertIntGT(gMockNvWrites, 0);
    AssertIntGT(gMockNvReads, 0);

    /* Error paths */
    rc = FWTPM_NV_SetHAL(NULL, &hal);
    AssertIntNE(rc, 0);
    rc = FWTPM_NV_SetHAL(&ctx, NULL);
    AssertIntNE(rc, 0);

    FWTPM_Cleanup(&ctx);
    printf("Test fwTPM:\tNV HAL (mock backend):\t\tPassed\n");
#else
    printf("Test fwTPM:\tNV HAL (mock backend):\t\tSkipped\n");
#endif
}

/* ================================================================== */
/* main                                                                */
/* ================================================================== */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
#else
int fwtpm_unit_tests(int argc, char *argv[])
#endif
{
    (void)argc;
    (void)argv;

    printf("fwTPM Unit Tests\n");

    /* Remove stale NV state to ensure clean test runs */
    (void)remove(FWTPM_NV_FILE);

    /* Lifecycle */
    test_fwtpm_init_cleanup();
    test_fwtpm_startup_clear();
    test_fwtpm_double_startup();
    test_fwtpm_selftest();
    test_fwtpm_shutdown();

    /* Command dispatch & error handling */
    test_fwtpm_undersized_command();
    test_fwtpm_bad_tag();
    test_fwtpm_size_mismatch();
    test_fwtpm_unknown_command();
    test_fwtpm_no_startup();
    test_fwtpm_null_args();

    /* Security fix regressions */
    test_fwtpm_auth_area_oversize();
    test_fwtpm_zero_size_command();

    /* GetRandom / StirRandom */
    test_fwtpm_getrandom();
    test_fwtpm_getrandom_zero();
    test_fwtpm_stirrandom();

    /* GetCapability */
    test_fwtpm_getcap_algorithms();
    test_fwtpm_getcap_commands();
    test_fwtpm_getcap_properties();
    test_fwtpm_getcap_pcrs();

    /* PCR operations */
    test_fwtpm_pcr_read();
    test_fwtpm_pcr_extend_and_read();
    test_fwtpm_pcr_reset();
    test_fwtpm_pcr_event();

    /* Clock */
    test_fwtpm_readclock();
    test_fwtpm_clock_set();

    /* HAL registration (clock + NV). The NV HAL test uses a mock
     * backend and must not leave the default file in a half-written
     * state, so remove FWTPM_NV_FILE afterwards. */
    test_fwtpm_clock_sethal();
    test_fwtpm_nv_sethal_mock();
    (void)remove(FWTPM_NV_FILE);

    /* Key operations */
#if !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN)
    test_fwtpm_create_primary_rsa();
#endif
#ifdef HAVE_ECC
    test_fwtpm_create_primary_ecc();
#endif
    test_fwtpm_read_public();
    test_fwtpm_evict_control();
    test_fwtpm_context_save();

    /* Crypto */
    test_fwtpm_hash();
    test_fwtpm_hash_sequence();
#ifdef HAVE_ECC
    test_fwtpm_ecc_parameters();
#endif

    /* Sessions */
    test_fwtpm_start_hmac_session();
    test_fwtpm_start_policy_session();
    test_fwtpm_start_trial_session();

    /* Auth */
    test_fwtpm_hierarchy_change_auth();
#ifndef FWTPM_NO_DA
    test_fwtpm_da_parameters_and_reset();
#endif

    /* Policy */
#ifndef FWTPM_NO_POLICY
    test_fwtpm_policy_password();
    test_fwtpm_policy_auth_value();
    test_fwtpm_policy_get_digest();
    test_fwtpm_policy_restart();
    test_fwtpm_policy_command_code();
    test_fwtpm_policy_locality();
    test_fwtpm_policy_pcr();
#endif

    /* NV operations */
#ifndef FWTPM_NO_NV
    test_fwtpm_nv_define_write_read();
    test_fwtpm_nv_read_public();
    test_fwtpm_nv_counter();
#endif

    /* Hierarchy & misc */
    test_fwtpm_test_parms();
    test_fwtpm_incremental_selftest();

    /* Destructive tests last (Clear changes state) */
    test_fwtpm_change_eps();
    test_fwtpm_change_pps();
    test_fwtpm_clear();

    printf("\nAll fwTPM unit tests passed!\n");
    return 0;
}

#else /* !WOLFTPM_FWTPM */

#include <stdio.h>

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
#else
int fwtpm_unit_tests(int argc, char *argv[])
#endif
{
    (void)argc;
    (void)argv;
    printf("fwTPM not enabled (--enable-fwtpm), skipping tests\n");
    return 0;
}

#endif /* WOLFTPM_FWTPM */
