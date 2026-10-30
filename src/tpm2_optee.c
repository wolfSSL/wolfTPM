/* tpm2_optee.c
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

/* Normal-world transport to the fwTPM running as an OP-TEE trusted
 * application. See src/fwtpm/ports/optee for the secure-world side. */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2_types.h>

#ifdef WOLFTPM_OPTEE

#include <wolftpm/tpm2_optee.h>
#include <wolftpm/tpm2_packet.h>

#include <tee_client_api.h>

#include <wolftpm/fwtpm/fwtpm_optee.h>

/* The trusted application is single instance, so one session per process is
 * the right granularity, and these live here rather than in TPM2_CTX to keep
 * tee_client_api.h out of tpm2.h, which every caller includes.
 *
 * The consequence is that a second TPM2_CTX in the same process shares one
 * session, so TPM2_Cleanup on either closes it. The connect below is lazy, so
 * the other context reconnects on its next command rather than failing, but
 * the trusted application flushes transient objects when a session closes, so
 * it loses any transient handles it was holding. That is the same hazard the
 * Linux resource manager has when a file descriptor closes (see
 * docs/DEVTPM.md): create and use in one context, or make the handle
 * persistent with TPM2_EvictControl. */
static TEEC_Context gTeeCtx;
static TEEC_Session gTeeSess;
static TEEC_SharedMemory gCmdShm;
static TEEC_SharedMemory gRspShm;
static int gTeeOpen = 0;

static void OpteeDisconnect(void)
{
    if (gTeeOpen) {
        TEEC_ReleaseSharedMemory(&gRspShm);
        TEEC_ReleaseSharedMemory(&gCmdShm);
        TEEC_CloseSession(&gTeeSess);
        TEEC_FinalizeContext(&gTeeCtx);
        gTeeOpen = 0;
    }
}

static int OpteeConnect(void)
{
    static const TEEC_UUID uuid = WOLFTPM_OPTEE_TA_UUID;
    TEEC_Operation op;
    TEEC_Result res;
    uint32_t origin = 0;
    uint32_t taCmdSize;

    if (gTeeOpen) {
        return TPM_RC_SUCCESS;
    }

    XMEMSET(&gTeeCtx, 0, sizeof(gTeeCtx));
    XMEMSET(&gTeeSess, 0, sizeof(gTeeSess));
    XMEMSET(&gCmdShm, 0, sizeof(gCmdShm));
    XMEMSET(&gRspShm, 0, sizeof(gRspShm));

    res = TEEC_InitializeContext(NULL, &gTeeCtx);
    if (res != TEEC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TEEC_InitializeContext failed 0x%08x\n", (unsigned int)res);
    #endif
        return TPM_RC_FAILURE;
    }

    res = TEEC_OpenSession(&gTeeCtx, &gTeeSess, &uuid, TEEC_LOGIN_PUBLIC,
        NULL, NULL, &origin);
    if (res != TEEC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TEEC_OpenSession failed 0x%08x origin %u\n",
            (unsigned int)res, (unsigned int)origin);
    #endif
        TEEC_FinalizeContext(&gTeeCtx);
        return TPM_RC_FAILURE;
    }

    /* Ask the trusted application for its ABI version and command size
     * rather than assuming they match this build: MAX_RESPONSE_SIZE here and
     * FWTPM_MAX_COMMAND_SIZE there are set by independent feature flags, and
     * a response buffer smaller than the TA stages only fails at run time on
     * whichever command first exceeds it. */
    XMEMSET(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT, TEEC_NONE,
                                     TEEC_NONE, TEEC_NONE);
    res = TEEC_InvokeCommand(&gTeeSess, FWTPM_OPTEE_CMD_GET_INFO, &op,
        &origin);
    if (res != TEEC_SUCCESS) {
        TEEC_CloseSession(&gTeeSess);
        TEEC_FinalizeContext(&gTeeCtx);
        return TPM_RC_FAILURE;
    }
    if (op.params[0].value.a != FWTPM_OPTEE_ABI_VERSION) {
    #ifdef DEBUG_WOLFTPM
        printf("fwTPM TA ABI %u, client built for %u\n",
            (unsigned int)op.params[0].value.a,
            (unsigned int)FWTPM_OPTEE_ABI_VERSION);
    #endif
        TEEC_CloseSession(&gTeeSess);
        TEEC_FinalizeContext(&gTeeCtx);
        return TPM_RC_FAILURE;
    }
    taCmdSize = op.params[0].value.b;

    /* Registered once rather than per command: a temporary memref is
     * registered and unregistered on every invoke, which for a TPM command
     * rate is measurable. */
    gCmdShm.size = MAX_COMMAND_SIZE;
    if (gCmdShm.size < taCmdSize) {
        gCmdShm.size = taCmdSize;
    }
    gCmdShm.flags = TEEC_MEM_INPUT;
    res = TEEC_AllocateSharedMemory(&gTeeCtx, &gCmdShm);
    if (res != TEEC_SUCCESS) {
        TEEC_CloseSession(&gTeeSess);
        TEEC_FinalizeContext(&gTeeCtx);
        return TPM_RC_FAILURE;
    }
    gRspShm.size = MAX_RESPONSE_SIZE;
    if (gRspShm.size < taCmdSize) {
        gRspShm.size = taCmdSize;
    }
    gRspShm.flags = TEEC_MEM_OUTPUT;
    res = TEEC_AllocateSharedMemory(&gTeeCtx, &gRspShm);
    if (res != TEEC_SUCCESS) {
        TEEC_ReleaseSharedMemory(&gCmdShm);
        TEEC_CloseSession(&gTeeSess);
        TEEC_FinalizeContext(&gTeeCtx);
        return TPM_RC_FAILURE;
    }

    gTeeOpen = 1;
    return TPM_RC_SUCCESS;
}

int TPM2_OPTEE_SendCommand(TPM2_CTX* ctx, TPM2_Packet* packet)
{
    int rc;
    TEEC_Operation op;
    TEEC_Result res;
    uint32_t origin = 0;
    uint32_t rspSz;

    if (ctx == NULL || packet == NULL || packet->buf == NULL) {
        return BAD_FUNC_ARG;
    }
    if (packet->pos < TPM2_HEADER_SIZE) {
        return BAD_FUNC_ARG;
    }

    /* Connect first: the shared memory is allocated there, so its size is
     * not a bound to check against until it exists. */
    rc = OpteeConnect();
    if (rc != TPM_RC_SUCCESS) {
        return rc;
    }
    if ((uint32_t)packet->pos > gCmdShm.size) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLFTPM_DEBUG_VERBOSE
    printf("Command size: %d\n", packet->pos);
    TPM2_PrintBin(packet->buf, packet->pos);
#endif

    XMEMCPY(gCmdShm.buffer, packet->buf, (size_t)packet->pos);

    XMEMSET(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT,
                                     TEEC_MEMREF_PARTIAL_OUTPUT,
                                     TEEC_NONE, TEEC_NONE);
    op.params[0].memref.parent = &gCmdShm;
    op.params[0].memref.offset = 0;
    op.params[0].memref.size = (size_t)packet->pos;
    op.params[1].memref.parent = &gRspShm;
    op.params[1].memref.offset = 0;
    op.params[1].memref.size = gRspShm.size;

    res = TEEC_InvokeCommand(&gTeeSess, FWTPM_OPTEE_CMD_SUBMIT, &op, &origin);
    if (res != TEEC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TEEC_InvokeCommand failed 0x%08x origin %u\n",
            (unsigned int)res, (unsigned int)origin);
    #endif
        return TPM_RC_FAILURE;
    }

    /* Trust the buffer size, not the length the response claims for itself. */
    rspSz = (uint32_t)op.params[1].memref.size;
    if (rspSz < TPM2_HEADER_SIZE || rspSz > (uint32_t)packet->size ||
            rspSz > gRspShm.size) {
        return TPM_RC_FAILURE;
    }
    XMEMCPY(packet->buf, gRspShm.buffer, (size_t)rspSz);

    packet->pos = 0;
    packet->size = (int)rspSz;

#ifdef WOLFTPM_DEBUG_VERBOSE
    printf("Response size: %d\n", packet->size);
    TPM2_PrintBin(packet->buf, (word32)packet->size);
#endif

    return TPM_RC_SUCCESS;
}

void TPM2_OpteeClose(TPM2_CTX* ctx)
{
    (void)ctx;
    OpteeDisconnect();
}

#endif /* WOLFTPM_OPTEE */
