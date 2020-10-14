/* tpm2_winapi.c
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
 *
 * This file is part of wolfTPM.
 *
 * wolfTPM is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
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


#ifdef WOLFTPM_WINAPI
#include <wolftpm/tpm2_winapi.h>

#include <windows.h>
#include <tbs.h>

/*
 * minGW doesn't define the structs necessary for TPM2, so the TBS
 * structures are defined here to match the windows API.
 */
#ifndef TBS_CONTEXT_VERSION_TWO
#define TBS_CONTEXT_VERSION_TWO 2

/**
 * This supports native windows API for TPM support. This uses the
 *  Windows TBSI (TPM Base Service Interface)
 */
typedef struct tdTBS_CONTEXT_PARAMS2
{
    UINT32  version;

    union
    {
        struct
        {
            UINT32 requestRaw : 1;     // if set to 1, request raw context
            UINT32 includeTpm12 : 1;   // if 1.2 device present, can use this
            UINT32 includeTpm20 : 1;   // if 2.0 device present, can use this
        };
        UINT32  asUINT32;
    };
} TBS_CONTEXT_PARAMS2, *PTBS_CONTEXT_PARAMS2;
typedef const TBS_CONTEXT_PARAMS2 *PCTBS_CONTEXT_PARAMS2;

#endif /* ! TBS_CONTEXT_VERSION_TWO */


/* Talk to a TPM device using Windows TBS */
int TPM2_WinApi_SendCommand(TPM2_CTX* ctx, TPM2_Packet* packet)
{
    int rc = 0;
    TBS_CONTEXT_PARAMS2 tbs_params;
    tbs_params.version = TBS_CONTEXT_VERSION_TWO;
    tbs_params.includeTpm12 = 0;
    tbs_params.includeTpm20 = 1;


    /* open, if not already open */
    if (ctx->winCtx.tbs_context == NULL) {
        rc = Tbsi_Context_Create((TBS_CONTEXT_PARAMS*)&tbs_params,
                                 &ctx->winCtx.tbs_context);
    }

    /* send the command to the device.  Error if the device send fails. */
    if (rc == 0) {
        uint32_t tmp = packet->size;
        rc = Tbsip_Submit_Command(ctx->winCtx.tbs_context,
                                  TBS_COMMAND_LOCALITY_ZERO,
                                  TBS_COMMAND_PRIORITY_NORMAL,
                                  packet->buf,
                                  packet->pos,
                                  packet->buf,
                                  (UINT32*)&tmp);
        packet->pos = tmp;
    }

    return rc;
}

int TPM2_WinApi_Cleanup(TPM2_CTX* ctx)
{
    int rc = TPM_RC_SUCCESS;
    if (ctx->winCtx.tbs_context != NULL) {
        rc = Tbsip_Context_Close(ctx->winCtx.tbs_context);
        ctx->winCtx.tbs_context = NULL;
    }

    return rc;
}

#endif
