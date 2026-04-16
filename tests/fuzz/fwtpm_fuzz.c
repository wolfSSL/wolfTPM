/* fwtpm_fuzz.c
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

/* libFuzzer harness for FWTPM_ProcessCommand.
 *
 * Feeds raw TPM command packets into the fwTPM command processor
 * to find parsing bugs, buffer overflows, and undefined behavior.
 *
 * Build: ./configure --enable-fwtpm --enable-fuzz
 *        make CC=clang \
 *          CFLAGS="-fsanitize=fuzzer-no-link,address -g" \
 *          LDFLAGS="-fsanitize=fuzzer,address"
 *
 * Run:   ./tests/fuzz/fwtpm_fuzz corpus/ -max_len=4096 -timeout=30
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2_types.h>

#ifdef WOLFTPM_FWTPM

#include <wolftpm/fwtpm/fwtpm.h>
#include <wolftpm/fwtpm/fwtpm_command.h>

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* libFuzzer entry point prototypes */
int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static FWTPM_CTX g_ctx;
static int g_initialized = 0;
static int g_iterations = 0;
static byte g_rspBuf[FWTPM_MAX_COMMAND_SIZE];

/* Reset interval: re-initialize FWTPM_CTX to prevent state accumulation
 * from causing non-reproducible crashes */
#define FUZZ_RESET_INTERVAL 1000

/* Issue TPM2_Startup(SU_CLEAR) so that subsequent commands are accepted */
static void fuzz_startup(void)
{
    /* TPM2_Startup command: tag(2) + size(4) + CC(4) + startupType(2) = 12 */
    byte startupCmd[12];
    int rspSize = 0;

    /* tag = TPM_ST_NO_SESSIONS (0x8001) */
    startupCmd[0] = 0x80; startupCmd[1] = 0x01;
    /* size = 12 */
    startupCmd[2] = 0x00; startupCmd[3] = 0x00;
    startupCmd[4] = 0x00; startupCmd[5] = 0x0C;
    /* CC = TPM_CC_Startup (0x00000144) */
    startupCmd[6] = 0x00; startupCmd[7] = 0x00;
    startupCmd[8] = 0x01; startupCmd[9] = 0x44;
    /* startupType = TPM_SU_CLEAR (0x0000) */
    startupCmd[10] = 0x00; startupCmd[11] = 0x00;

    FWTPM_ProcessCommand(&g_ctx, startupCmd, (int)sizeof(startupCmd),
        g_rspBuf, &rspSize, 0);
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;

    if (FWTPM_Init(&g_ctx) == 0) {
        fuzz_startup();
        g_initialized = 1;
    }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    int rspSize = 0;

    if (!g_initialized) {
        return 0;
    }

    /* Periodically reset state to keep crashes reproducible */
    if (++g_iterations >= FUZZ_RESET_INTERVAL) {
        g_iterations = 0;
        FWTPM_Cleanup(&g_ctx);
        memset(&g_ctx, 0, sizeof(g_ctx));
        if (FWTPM_Init(&g_ctx) == 0) {
            fuzz_startup();
        }
        else {
            g_initialized = 0;
        }
    }

    /* TPM commands have a 10-byte minimum header (tag + size + CC) */
    if (size < 10 || size > FWTPM_MAX_COMMAND_SIZE) {
        return 0;
    }

    FWTPM_ProcessCommand(&g_ctx, data, (int)size,
        g_rspBuf, &rspSize, 0);

    return 0;
}

#else /* !WOLFTPM_FWTPM */

#include <stdint.h>
#include <stddef.h>

/* Stub when fwTPM is not enabled */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    (void)data;
    (void)size;
    return 0;
}

#endif /* WOLFTPM_FWTPM */
