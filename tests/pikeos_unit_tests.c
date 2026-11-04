/* pikeos_unit_tests.c
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

/* Runs the PikeOS transport on a host against stubbed vm_* calls, through the
 * public TPM2_Init_ex/TPM2_Startup/TPM2_Cleanup API so the build's transport
 * dispatch is covered as well. */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_packet.h>
#include <vm.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_ERR 7

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
    int openRc, writeRc, readRc, closeRc;
    int opens, writes, reads, closes, sleeps;
    int retriesLeft;
    int shortWrite;
    P4_size_t readSzOverride;
    int oversizeRead;
    byte lastCmd[64];
    P4_size_t lastCmdSz;
    unsigned int openFlags;
    char openName[32];
} stub;

P4_e_t p4_sleep(P4_time_t timeout)
{
    (void)timeout;
    stub.sleeps++;
    return P4_E_OK;
}

P4_time_t p4_get_time(void)
{
    return 0;
}

P4_e_t vm_open(const char *name, unsigned int oflags, vm_file_desc_t *fd)
{
    stub.opens++;
    stub.openFlags = oflags;
    strncpy(stub.openName, name, sizeof(stub.openName) - 1);
    fd->gdh = 1;
    return stub.openRc;
}

P4_e_t vm_write(vm_file_desc_t *fd, const void *buff, P4_size_t buff_size,
    P4_size_t *written_size)
{
    (void)fd;
    stub.writes++;
    stub.lastCmdSz = buff_size;
    if (buff_size <= sizeof(stub.lastCmd)) {
        memcpy(stub.lastCmd, buff, buff_size);
    }
    *written_size = stub.shortWrite ? buff_size - 1 : buff_size;
    return stub.writeRc;
}

P4_e_t vm_read(vm_file_desc_t *fd, void *buff, P4_size_t buff_size,
    P4_size_t *read_size)
{
    const byte* rsp = rspOk;
    P4_size_t sz = sizeof(rspOk);

    (void)fd;
    stub.reads++;
    if (stub.retriesLeft > 0) {
        stub.retriesLeft--;
        rsp = rspRetry;
        sz = sizeof(rspRetry);
    }
    if (stub.readSzOverride != 0 && stub.readSzOverride < sz) {
        sz = stub.readSzOverride;
    }
    memcpy(buff, rsp, sz);
    *read_size = stub.oversizeRead ? buff_size + 1 : sz;
    return stub.readRc;
}

P4_e_t vm_close(vm_file_desc_t *fd)
{
    (void)fd;
    stub.closes++;
    return stub.closeRc;
}

static int gFailures;

#define CHECK(cond) do {                                                     \
    if (!(cond)) {                                                           \
        printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);               \
        gFailures++;                                                         \
    }                                                                        \
} while (0)

static TPM_RC sendStartup(void)
{
    Startup_In in;

    XMEMSET(&in, 0, sizeof(in));
    in.startupType = TPM_SU_CLEAR;
    return TPM2_Startup(&in);
}

static void testInit(TPM2_CTX* ctx)
{
    XMEMSET(&stub, 0, sizeof(stub));
    CHECK(TPM2_Init_ex(ctx, NULL, NULL, 0) == TPM_RC_SUCCESS);
}

/* A command reaches the PikeOS file provider and is framed unchanged. The
 * descriptor stays open across commands and is closed exactly once. */
static void test_send_and_cleanup(void)
{
    TPM2_CTX ctx;

    testInit(&ctx);
    CHECK(sendStartup() == TPM_RC_SUCCESS);
    CHECK(stub.opens == 1);
    CHECK(stub.openFlags == VM_O_RD_WR);
    CHECK(strcmp(stub.openName, "tpm0:dev0") == 0);
    CHECK(stub.writes == 1);
    CHECK(stub.reads == 1);
    CHECK(stub.lastCmdSz == sizeof(startupCmd));
    CHECK(memcmp(stub.lastCmd, startupCmd, sizeof(startupCmd)) == 0);

    CHECK(sendStartup() == TPM_RC_SUCCESS);
    CHECK(stub.opens == 1);
    CHECK(stub.writes == 2);

    CHECK(TPM2_Cleanup(&ctx) == TPM_RC_SUCCESS);
    CHECK(stub.closes == 1);
    CHECK(TPM2_Cleanup(&ctx) == TPM_RC_SUCCESS);
    CHECK(stub.closes == 1);
    printf("Test PikeOS: send and cleanup done\n");
}

/* A failed close still marks the descriptor closed */
static void test_close_failure(void)
{
    TPM2_CTX ctx;

    testInit(&ctx);
    CHECK(sendStartup() == TPM_RC_SUCCESS);
    stub.closeRc = TEST_ERR;
    CHECK(TPM2_Cleanup(&ctx) == TPM_RC_FAILURE);
    CHECK(stub.closes == 1);
    CHECK(TPM2_Cleanup(&ctx) == TPM_RC_SUCCESS);
    CHECK(stub.closes == 1);
    printf("Test PikeOS: close failure done\n");
}

/* There is no TIS layer, so no HAL callback and no chip startup wait */
static void test_init_args(void)
{
    TPM2_CTX ctx;
    int user = 0;

    XMEMSET(&stub, 0, sizeof(stub));
    CHECK(TPM2_Init_ex(&ctx, NULL, NULL, 1) == BAD_FUNC_ARG);
    CHECK(TPM2_Init_ex(&ctx, NULL, &user, 0) == BAD_FUNC_ARG);
    CHECK(stub.opens == 0);
    CHECK(TPM2_Init_minimal(&ctx) == TPM_RC_SUCCESS);
    CHECK(stub.opens == 0);
    (void)TPM2_Cleanup(&ctx);
    printf("Test PikeOS: init arguments done\n");
}

/* An open failure sends nothing, and the next command tries the open again */
static void test_open_failure(void)
{
    TPM2_CTX ctx;

    testInit(&ctx);
    stub.openRc = TEST_ERR;
    CHECK(sendStartup() == TPM_RC_FAILURE);
    CHECK(stub.writes == 0);

    stub.openRc = P4_E_OK;
    CHECK(sendStartup() == TPM_RC_SUCCESS);
    CHECK(stub.opens == 2);
    CHECK(stub.writes == 1);
    (void)TPM2_Cleanup(&ctx);
    CHECK(stub.closes == 1);
    printf("Test PikeOS: open failure done\n");
}

static void test_write_failures(void)
{
    TPM2_CTX ctx;

    testInit(&ctx);
    stub.writeRc = TEST_ERR;
    CHECK(sendStartup() == TPM_RC_FAILURE);
    CHECK(stub.reads == 0);
    stub.writeRc = P4_E_OK;

    stub.shortWrite = 1;
    CHECK(sendStartup() == TPM_RC_FAILURE);
    CHECK(stub.reads == 0);
    (void)TPM2_Cleanup(&ctx);
    printf("Test PikeOS: write failures done\n");
}

/* A read error and a response length outside the header size or the command
 * buffer all fail before the response is parsed */
static void test_read_failures(void)
{
    TPM2_CTX ctx;

    testInit(&ctx);
    stub.readRc = TEST_ERR;
    CHECK(sendStartup() == TPM_RC_FAILURE);
    stub.readRc = P4_E_OK;

    stub.readSzOverride = TPM2_HEADER_SIZE - 1;
    CHECK(sendStartup() == TPM_RC_FAILURE);
    stub.readSzOverride = 0;

    stub.oversizeRead = 1;
    CHECK(sendStartup() == TPM_RC_FAILURE);
    stub.oversizeRead = 0;

    CHECK(sendStartup() == TPM_RC_SUCCESS);
    (void)TPM2_Cleanup(&ctx);
    printf("Test PikeOS: read failures done\n");
}

#ifndef WOLFTPM_NO_RETRY
/* With retries enabled, TPM_RC_RETRY resubmits the same command through the
 * transport. It is returned to the caller otherwise, the default. */
static void test_retry(void)
{
    TPM2_CTX ctx;

    testInit(&ctx);
    stub.retriesLeft = 1;
    CHECK(sendStartup() == TPM_RC_RETRY);
    CHECK(stub.writes == 1);

    testInit(&ctx);
    CHECK(TPM2_SetCommandRetries(&ctx, 2) == TPM_RC_SUCCESS);
    stub.retriesLeft = 2;
    CHECK(sendStartup() == TPM_RC_SUCCESS);
    CHECK(stub.writes == 3);
    CHECK(stub.reads == 3);
    CHECK(stub.opens == 1);
    CHECK(stub.lastCmdSz == sizeof(startupCmd));
    CHECK(memcmp(stub.lastCmd, startupCmd, sizeof(startupCmd)) == 0);
    (void)TPM2_Cleanup(&ctx);
    printf("Test PikeOS: retry done\n");
}
#endif /* !WOLFTPM_NO_RETRY */

int main(void)
{
    test_send_and_cleanup();
    test_close_failure();
    test_init_args();
    test_open_failure();
    test_write_failures();
    test_read_failures();
#ifndef WOLFTPM_NO_RETRY
    test_retry();
#endif

    printf("PikeOS transport tests: %s\n", gFailures == 0 ? "passed" : "failed");
    return gFailures == 0 ? 0 : 1;
}
