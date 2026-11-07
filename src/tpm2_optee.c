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

/* One TEE session per TPM2_CTX, as the swtpm transport keeps one socket per
 * context. The trusted application records which session created each
 * transient object, so cleaning up one context, such as the temporary one in
 * wolfTPM2_Test, flushes only that context's handles. Held through an opaque
 * pointer to keep tee_client_api.h out of tpm2.h, which every caller
 * includes. */
typedef struct OPTEE_CLIENT {
    TEEC_Context teeCtx;
    TEEC_Session sess;
    TEEC_SharedMemory cmdShm;
    TEEC_SharedMemory rspShm;
} OPTEE_CLIENT;

static void OpteeDisconnect(TPM2_CTX* ctx)
{
    OPTEE_CLIENT* c = (OPTEE_CLIENT*)ctx->opteeCtx;

    if (c != NULL) {
        TEEC_ReleaseSharedMemory(&c->rspShm);
        TEEC_ReleaseSharedMemory(&c->cmdShm);
        TEEC_CloseSession(&c->sess);
        TEEC_FinalizeContext(&c->teeCtx);
        TPM2_ForceZero(c, sizeof(*c));
        XFREE(c, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        ctx->opteeCtx = NULL;
    }
}

static int OpteeOpen(OPTEE_CLIENT* c)
{
    static const TEEC_UUID uuid = WOLFTPM_OPTEE_TA_UUID;
    TEEC_Operation op;
    TEEC_Result res;
    uint32_t origin = 0;
    uint32_t taCmdSize;

    res = TEEC_InitializeContext(NULL, &c->teeCtx);
    if (res != TEEC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TEEC_InitializeContext failed 0x%08x\n", (unsigned int)res);
    #endif
        return TPM_RC_FAILURE;
    }

    res = TEEC_OpenSession(&c->teeCtx, &c->sess, &uuid, TEEC_LOGIN_PUBLIC,
        NULL, NULL, &origin);
    if (res != TEEC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TEEC_OpenSession failed 0x%08x origin %u\n",
            (unsigned int)res, (unsigned int)origin);
    #endif
        TEEC_FinalizeContext(&c->teeCtx);
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
    res = TEEC_InvokeCommand(&c->sess, FWTPM_OPTEE_CMD_GET_INFO, &op,
        &origin);
    if (res != TEEC_SUCCESS) {
        TEEC_CloseSession(&c->sess);
        TEEC_FinalizeContext(&c->teeCtx);
        return TPM_RC_FAILURE;
    }
    if (op.params[0].value.a != FWTPM_OPTEE_ABI_VERSION) {
    #ifdef DEBUG_WOLFTPM
        printf("fwTPM TA ABI %u, client built for %u\n",
            (unsigned int)op.params[0].value.a,
            (unsigned int)FWTPM_OPTEE_ABI_VERSION);
    #endif
        TEEC_CloseSession(&c->sess);
        TEEC_FinalizeContext(&c->teeCtx);
        return TPM_RC_FAILURE;
    }
    taCmdSize = op.params[0].value.b;

    /* Registered once rather than per command: a temporary memref is
     * registered and unregistered on every invoke, which for a TPM command
     * rate is measurable. */
    c->cmdShm.size = MAX_COMMAND_SIZE;
    if (c->cmdShm.size < taCmdSize) {
        c->cmdShm.size = taCmdSize;
    }
    c->cmdShm.flags = TEEC_MEM_INPUT;
    res = TEEC_AllocateSharedMemory(&c->teeCtx, &c->cmdShm);
    if (res != TEEC_SUCCESS) {
        TEEC_CloseSession(&c->sess);
        TEEC_FinalizeContext(&c->teeCtx);
        return TPM_RC_FAILURE;
    }
    c->rspShm.size = MAX_RESPONSE_SIZE;
    if (c->rspShm.size < taCmdSize) {
        c->rspShm.size = taCmdSize;
    }
    c->rspShm.flags = TEEC_MEM_OUTPUT;
    res = TEEC_AllocateSharedMemory(&c->teeCtx, &c->rspShm);
    if (res != TEEC_SUCCESS) {
        TEEC_ReleaseSharedMemory(&c->cmdShm);
        TEEC_CloseSession(&c->sess);
        TEEC_FinalizeContext(&c->teeCtx);
        return TPM_RC_FAILURE;
    }

    return TPM_RC_SUCCESS;
}

static int OpteeConnect(TPM2_CTX* ctx)
{
    OPTEE_CLIENT* c;
    int rc;

    if (ctx->opteeCtx != NULL) {
        return TPM_RC_SUCCESS;
    }
    c = (OPTEE_CLIENT*)XMALLOC(sizeof(OPTEE_CLIENT), NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (c == NULL) {
        return MEMORY_E;
    }
    XMEMSET(c, 0, sizeof(*c));
    rc = OpteeOpen(c);
    if (rc != TPM_RC_SUCCESS) {
        XFREE(c, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return rc;
    }
    ctx->opteeCtx = c;
    return TPM_RC_SUCCESS;
}

int TPM2_OPTEE_SendCommand(TPM2_CTX* ctx, TPM2_Packet* packet)
{
    int rc;
    TEEC_Operation op;
    TEEC_Result res;
    uint32_t origin = 0;
    uint32_t rspSz;
    OPTEE_CLIENT* c;

    if (ctx == NULL || packet == NULL || packet->buf == NULL) {
        return BAD_FUNC_ARG;
    }
    if (packet->pos < TPM2_HEADER_SIZE) {
        return BAD_FUNC_ARG;
    }

    /* Connect first: the shared memory is allocated there, so its size is
     * not a bound to check against until it exists. */
    rc = OpteeConnect(ctx);
    if (rc != TPM_RC_SUCCESS) {
        return rc;
    }
    c = (OPTEE_CLIENT*)ctx->opteeCtx;
    if ((uint32_t)packet->pos > c->cmdShm.size) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLFTPM_DEBUG_VERBOSE
    printf("Command size: %d\n", packet->pos);
    TPM2_PrintBin(packet->buf, packet->pos);
#endif

    XMEMCPY(c->cmdShm.buffer, packet->buf, (size_t)packet->pos);

    XMEMSET(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT,
                                     TEEC_MEMREF_PARTIAL_OUTPUT,
                                     TEEC_NONE, TEEC_NONE);
    op.params[0].memref.parent = &c->cmdShm;
    op.params[0].memref.offset = 0;
    op.params[0].memref.size = (size_t)packet->pos;
    op.params[1].memref.parent = &c->rspShm;
    op.params[1].memref.offset = 0;
    op.params[1].memref.size = c->rspShm.size;

    res = TEEC_InvokeCommand(&c->sess, FWTPM_OPTEE_CMD_SUBMIT, &op, &origin);

    /* Trust the buffer size, not the length the response claims for itself. */
    rspSz = (uint32_t)op.params[1].memref.size;
    if (res == TEEC_SUCCESS && rspSz >= TPM2_HEADER_SIZE &&
            rspSz <= (uint32_t)packet->size && rspSz <= c->rspShm.size) {
        XMEMCPY(packet->buf, c->rspShm.buffer, (size_t)rspSz);
        rc = TPM_RC_SUCCESS;
    }
    else {
        rc = TPM_RC_FAILURE;
    }

    /* Both carry authorization values and secret output such as unsealed
     * data, and outlive this call, so clear them now. */
    TPM2_ForceZero(c->cmdShm.buffer, (word32)c->cmdShm.size);
    TPM2_ForceZero(c->rspShm.buffer, (word32)c->rspShm.size);

    if (res != TEEC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TEEC_InvokeCommand failed 0x%08x origin %u\n",
            (unsigned int)res, (unsigned int)origin);
    #endif
        /* The session is unusable, so reconnect on the next command. */
        if (res == TEEC_ERROR_TARGET_DEAD) {
            OpteeDisconnect(ctx);
        }
    }
    if (rc != TPM_RC_SUCCESS) {
        return rc;
    }

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
    if (ctx != NULL) {
        OpteeDisconnect(ctx);
    }
}

#endif /* WOLFTPM_OPTEE */
