/* fwtpm_optee_ta.c
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

/* OP-TEE trusted application entry points for the fwTPM.
 *
 * One TA invocation carries one whole TPM command, so FWTPM_ProcessCommand
 * is the entire transport. Neither server loop is used: FWTPM_IO_ServerLoop
 * and FWTPM_TIS_ServerLoop both block, which a trusted application cannot
 * do, so fwtpm_io.c, fwtpm_tis.c, fwtpm_tis_shm.c and fwtpm_main.c are not
 * part of this build.
 *
 * A board port supplies user_ta_header_defines.h (UUID, flags, stack and
 * heap sizes) and the wolfCrypt platform shims; nothing here is specific to
 * any SoC.
 */

#include <wolftpm/tpm2_types.h>

#include <wolftpm/fwtpm/fwtpm_optee.h>

/* Only an OP-TEE trusted application build has libutee. WOLFSSL_OPTEE is what
 * says so and is what wolfCrypt keys its own TEE support off; WOLFTPM_FWTPM
 * alone is not enough, since a plain Linux fwTPM build defines that too and
 * would then compile this against headers it does not have. */
#if defined(WOLFTPM_FWTPM) && defined(WOLFSSL_OPTEE)

#include <wolftpm/fwtpm/fwtpm_command.h>

#include <tee_internal_api_extensions.h>

/* The TA is single instance, so one TPM. A second instance would be a second
 * TPM sharing one NV journal. */
static FWTPM_CTX fwCtx;
static FWTPM_OPTEE_NV fwNv;

/* FWTPM_ProcessCommand requires a response buffer of at least
 * FWTPM_MAX_COMMAND_SIZE whatever the caller's capacity, so both directions
 * are staged through buffers of that size. Staging the command also removes
 * the normal world's ability to change it after it has been parsed. */
static byte fwCmdBuf[FWTPM_MAX_COMMAND_SIZE];
static byte fwRspBuf[FWTPM_MAX_COMMAND_SIZE];

TEE_Result TA_CreateEntryPoint(void)
{
    int rc;

    XMEMSET(&fwCtx, 0, sizeof(fwCtx));
    XMEMSET(&fwNv, 0, sizeof(fwNv));

    /* Before FWTPM_Init, which is what calls FWTPM_NV_Init. */
    rc = FWTPM_OPTEE_NV_SetHAL(&fwCtx, &fwNv);
    if (rc != TPM_RC_SUCCESS) {
        EMSG("fwTPM: secure storage NV unavailable (%d)", rc);
        return TEE_ERROR_STORAGE_NOT_AVAILABLE;
    }

    rc = FWTPM_Clock_SetHAL(&fwCtx, FWTPM_OPTEE_Clock_GetMs, NULL);
    if (rc != TPM_RC_SUCCESS) {
        FWTPM_OPTEE_NV_Close(&fwNv);
        return TEE_ERROR_GENERIC;
    }

    rc = FWTPM_Init(&fwCtx);
    if (rc != TPM_RC_SUCCESS) {
        EMSG("fwTPM: FWTPM_Init failed (%d)", rc);
        FWTPM_OPTEE_NV_Close(&fwNv);
        return TEE_ERROR_GENERIC;
    }

    IMSG("fwTPM ready");
    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
    FWTPM_Cleanup(&fwCtx);
    FWTPM_OPTEE_NV_Close(&fwNv);
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t paramTypes,
    TEE_Param params[TEE_NUM_PARAMS], void** sessCtx)
{
    (void)paramTypes;
    (void)params;

    *sessCtx = NULL;
    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void* sessCtx)
{
    (void)sessCtx;

    /* So the next client cannot inherit transient objects, sessions or
     * sequences from this one. */
    FWTPM_ResetCommandClient(&fwCtx);
}

static TEE_Result FwOpteeSubmit(uint32_t paramTypes,
    TEE_Param params[TEE_NUM_PARAMS])
{
    int rc;
    int rspSize;
    uint32_t expected;
    uint32_t expectedInOut;
    uint32_t cmdSize;

    expected = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                               TEE_PARAM_TYPE_MEMREF_OUTPUT,
                               TEE_PARAM_TYPE_NONE,
                               TEE_PARAM_TYPE_NONE);
    /* Linux's tpm_ftpm_tee passes the response buffer as INOUT, since it
     * carries both memrefs in one registered shared memory. Accept that too,
     * so an in-kernel TPM driver can drive this and present a /dev/tpm
     * device. Nothing is read out of the response buffer either way. */
    expectedInOut = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                    TEE_PARAM_TYPE_MEMREF_INOUT,
                                    TEE_PARAM_TYPE_NONE,
                                    TEE_PARAM_TYPE_NONE);
    if (paramTypes != expected && paramTypes != expectedInOut) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    cmdSize = params[0].memref.size;
    if (params[0].memref.buffer == NULL || cmdSize == 0 ||
            cmdSize > sizeof(fwCmdBuf)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    XMEMCPY(fwCmdBuf, params[0].memref.buffer, cmdSize);

    rspSize = (int)sizeof(fwRspBuf);
    rc = FWTPM_ProcessCommand(&fwCtx, fwCmdBuf, (int)cmdSize,
        fwRspBuf, &rspSize, FWTPM_OPTEE_LOCALITY);
    if (rc != TPM_RC_SUCCESS) {
        /* A TPM level failure is encoded in the response and does not come
         * back here, so this is a parse or transport error. */
        return TEE_ERROR_BAD_FORMAT;
    }
    if (rspSize <= 0) {
        return TEE_ERROR_GENERIC;
    }

    /* Short output buffer: report the size the client needs and let it
     * retry, the usual GP convention. */
    if (params[1].memref.size < (uint32_t)rspSize) {
        params[1].memref.size = (uint32_t)rspSize;
        return TEE_ERROR_SHORT_BUFFER;
    }
    if (params[1].memref.buffer == NULL) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    XMEMCPY(params[1].memref.buffer, fwRspBuf, (size_t)rspSize);
    params[1].memref.size = (uint32_t)rspSize;
    return TEE_SUCCESS;
}

static TEE_Result FwOpteeGetInfo(uint32_t paramTypes,
    TEE_Param params[TEE_NUM_PARAMS])
{
    uint32_t expected;

    expected = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
                               TEE_PARAM_TYPE_NONE,
                               TEE_PARAM_TYPE_NONE,
                               TEE_PARAM_TYPE_NONE);
    if (paramTypes != expected) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    params[0].value.a = FWTPM_OPTEE_ABI_VERSION;
    params[0].value.b = FWTPM_MAX_COMMAND_SIZE;
    return TEE_SUCCESS;
}

TEE_Result TA_InvokeCommandEntryPoint(void* sessCtx, uint32_t cmdId,
    uint32_t paramTypes, TEE_Param params[TEE_NUM_PARAMS])
{
    TEE_Result res;

    (void)sessCtx;

    switch (cmdId) {
        case FWTPM_OPTEE_CMD_SUBMIT:
            res = FwOpteeSubmit(paramTypes, params);
            break;
        case FWTPM_OPTEE_CMD_RESET:
            FWTPM_ResetCommandClient(&fwCtx);
            res = TEE_SUCCESS;
            break;
        case FWTPM_OPTEE_CMD_GET_INFO:
            res = FwOpteeGetInfo(paramTypes, params);
            break;
        default:
            res = TEE_ERROR_NOT_SUPPORTED;
            break;
    }
    return res;
}

#endif /* WOLFTPM_FWTPM && WOLFSSL_OPTEE */
