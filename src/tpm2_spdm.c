/* tpm2_spdm.c
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

/* SPDM Thin Wrapper Layer for wolfTPM
 *
 * This file provides thin wrapper functions around the wolfSPDM library.
 * All SPDM protocol logic, cryptography, and message handling is implemented
 * in wolfSPDM. This file only provides:
 *
 *   1. Context management (init/free)
 *   2. Pass-through wrappers to wolfSPDM functions
 *   3. TPM-specific NTC2_PreConfig for SPDM enable (Nuvoton only)
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_spdm.h>

#ifdef WOLFTPM_SPDM

#include <wolftpm/tpm2_wrap.h>

/* wolfSPDM provides all SPDM protocol implementation */
#include <wolfspdm/spdm.h>

/* -------------------------------------------------------------------------- */
/* Context Management */
/* -------------------------------------------------------------------------- */

int wolfTPM2_SPDM_InitCtx(
    WOLFTPM2_SPDM_CTX* ctx,
    WOLFSPDM_IO_CB ioCb,
    void* userCtx)
{
    int rc;

    if (ctx == NULL) {
        return BAD_FUNC_ARG;
    }

    /* Zero initialize context */
    XMEMSET(ctx, 0, sizeof(WOLFTPM2_SPDM_CTX));

#ifdef WOLFSPDM_DYNAMIC_MEMORY
    /* Dynamic path: allocate and initialize via wolfSPDM_New() */
    ctx->spdmCtx = wolfSPDM_New();
    if (ctx->spdmCtx == NULL) {
        return MEMORY_E;
    }
#else
    /* Static path: use inline buffer, no malloc */
    ctx->spdmCtx = (WOLFSPDM_CTX*)ctx->spdmBuf;
    rc = wolfSPDM_InitStatic(ctx->spdmCtx, (int)sizeof(ctx->spdmBuf));
    if (rc != WOLFSPDM_SUCCESS) {
        ctx->spdmCtx = NULL;
        return rc;
    }
#endif

    /* Set I/O callback if provided */
    if (ioCb != NULL) {
        rc = wolfSPDM_SetIO(ctx->spdmCtx, ioCb, userCtx);
        if (rc != WOLFSPDM_SUCCESS) {
            wolfSPDM_Free(ctx->spdmCtx);
            ctx->spdmCtx = NULL;
            return rc;
        }
    }

    return TPM_RC_SUCCESS;
}

int wolfTPM2_SPDM_SetTPMCtx(
    WOLFTPM2_SPDM_CTX* ctx,
    TPM2_CTX* tpmCtx)
{
    if (ctx == NULL) {
        return BAD_FUNC_ARG;
    }
    ctx->tpmCtx = tpmCtx;
    return TPM_RC_SUCCESS;
}

void wolfTPM2_SPDM_FreeCtx(WOLFTPM2_SPDM_CTX* ctx)
{
    if (ctx == NULL) {
        return;
    }

    if (ctx->spdmCtx != NULL) {
        wolfSPDM_Free(ctx->spdmCtx);
        ctx->spdmCtx = NULL;
    }

    ctx->tpmCtx = NULL;
    ctx->spdmOnlyLocked = 0;
}

/* -------------------------------------------------------------------------- */
/* Configuration */
/* -------------------------------------------------------------------------- */

int wolfTPM2_SPDM_SetIoCb(
    WOLFTPM2_SPDM_CTX* ctx,
    WOLFSPDM_IO_CB ioCb,
    void* userCtx)
{
    if (ctx == NULL || ctx->spdmCtx == NULL) {
        return BAD_FUNC_ARG;
    }
    return wolfSPDM_SetIO(ctx->spdmCtx, ioCb, userCtx);
}

int wolfTPM2_SPDM_SetRequesterKeyPair(
    WOLFTPM2_SPDM_CTX* ctx,
    const byte* privKey, word32 privKeySz,
    const byte* pubKey, word32 pubKeySz)
{
    if (ctx == NULL || ctx->spdmCtx == NULL) {
        return BAD_FUNC_ARG;
    }
    return wolfSPDM_SetRequesterKeyPair(ctx->spdmCtx,
        privKey, privKeySz, pubKey, pubKeySz);
}

void wolfTPM2_SPDM_SetDebug(WOLFTPM2_SPDM_CTX* ctx, int enable)
{
    if (ctx != NULL && ctx->spdmCtx != NULL) {
        wolfSPDM_SetDebug(ctx->spdmCtx, enable);
    }
}

/* -------------------------------------------------------------------------- */
/* Session Establishment */
/* -------------------------------------------------------------------------- */

int wolfTPM2_SPDM_Connect(WOLFTPM2_SPDM_CTX* ctx)
{
    if (ctx == NULL || ctx->spdmCtx == NULL) {
        return BAD_FUNC_ARG;
    }
    return wolfSPDM_Connect(ctx->spdmCtx);
}

int wolfTPM2_SPDM_IsConnected(WOLFTPM2_SPDM_CTX* ctx)
{
    if (ctx == NULL || ctx->spdmCtx == NULL) {
        return 0;
    }
    return wolfSPDM_IsConnected(ctx->spdmCtx);
}

word32 wolfTPM2_SPDM_GetSessionId(WOLFTPM2_SPDM_CTX* ctx)
{
    if (ctx == NULL || ctx->spdmCtx == NULL) {
        return 0;
    }
    return wolfSPDM_GetSessionId(ctx->spdmCtx);
}

int wolfTPM2_SPDM_Disconnect(WOLFTPM2_SPDM_CTX* ctx)
{
    if (ctx == NULL || ctx->spdmCtx == NULL) {
        return BAD_FUNC_ARG;
    }
    return wolfSPDM_Disconnect(ctx->spdmCtx);
}

/* -------------------------------------------------------------------------- */
/* Secured Messaging */
/* -------------------------------------------------------------------------- */

int wolfTPM2_SPDM_SecuredExchange(
    WOLFTPM2_SPDM_CTX* ctx,
    const byte* cmdPlain, word32 cmdSz,
    byte* rspPlain, word32* rspSz)
{
    if (ctx == NULL || ctx->spdmCtx == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLFSPDM_NUVOTON
    /* In SPDM-only mode, TPM commands must be wrapped in SPDM VENDOR_DEFINED
     * messages with the TPM2_CMD vendor code. The TPM's SPDM layer only
     * accepts SPDM messages (starting with version byte 0x13), not raw TPM
     * commands (starting with tag 0x80 0x01). */
    if (wolfSPDM_GetMode(ctx->spdmCtx) == WOLFSPDM_MODE_NUVOTON) {
        byte vdMsg[WOLFSPDM_MAX_MSG_SIZE];
        byte vdRsp[WOLFSPDM_MAX_MSG_SIZE];
        word32 vdRspSz = sizeof(vdRsp);
        char rspVdCode[WOLFSPDM_VDCODE_LEN + 1];
        int vdMsgSz;
        int rc;

        /* Wrap TPM command in SPDM VENDOR_DEFINED_REQUEST("TPM2_CMD") */
        vdMsgSz = wolfSPDM_BuildVendorDefined(WOLFSPDM_VDCODE_TPM2_CMD,
            cmdPlain, cmdSz, vdMsg, sizeof(vdMsg));
        if (vdMsgSz < 0) {
            return vdMsgSz;
        }

        /* Send encrypted VENDOR_DEFINED, receive encrypted response */
        rc = wolfSPDM_SecuredExchange(ctx->spdmCtx,
            vdMsg, (word32)vdMsgSz, vdRsp, &vdRspSz);
        if (rc != 0) {
            return rc;
        }

        /* Parse VENDOR_DEFINED_RESPONSE to extract TPM response */
        rc = wolfSPDM_ParseVendorDefined(vdRsp, vdRspSz,
            rspVdCode, rspPlain, rspSz);
        if (rc < 0) {
            return rc;
        }

        return TPM_RC_SUCCESS;
    }
#endif /* WOLFSPDM_NUVOTON */

    /* Standard SPDM mode: send TPM command as raw app data */
    return wolfSPDM_SecuredExchange(ctx->spdmCtx,
        cmdPlain, cmdSz, rspPlain, rspSz);
}

/* -------------------------------------------------------------------------- */
/* Nuvoton-Specific Functions */
/* -------------------------------------------------------------------------- */

#ifdef WOLFSPDM_NUVOTON

int wolfTPM2_SPDM_SetNuvotonMode(WOLFTPM2_SPDM_CTX* ctx)
{
    if (ctx == NULL || ctx->spdmCtx == NULL) {
        return BAD_FUNC_ARG;
    }
    return wolfSPDM_SetMode(ctx->spdmCtx, WOLFSPDM_MODE_NUVOTON);
}

int wolfTPM2_SPDM_GetStatus(
    WOLFTPM2_SPDM_CTX* ctx,
    WOLFSPDM_NUVOTON_STATUS* status)
{
    if (ctx == NULL || ctx->spdmCtx == NULL || status == NULL) {
        return BAD_FUNC_ARG;
    }
    return wolfSPDM_Nuvoton_GetStatus(ctx->spdmCtx, status);
}

int wolfTPM2_SPDM_GetPubKey(
    WOLFTPM2_SPDM_CTX* ctx,
    byte* pubKey, word32* pubKeySz)
{
    if (ctx == NULL || ctx->spdmCtx == NULL) {
        return BAD_FUNC_ARG;
    }
    return wolfSPDM_Nuvoton_GetPubKey(ctx->spdmCtx, pubKey, pubKeySz);
}

int wolfTPM2_SPDM_SetOnlyMode(WOLFTPM2_SPDM_CTX* ctx, int lock)
{
    int rc;

    if (ctx == NULL || ctx->spdmCtx == NULL) {
        return BAD_FUNC_ARG;
    }

    rc = wolfSPDM_Nuvoton_SetOnlyMode(ctx->spdmCtx, lock);
    if (rc == WOLFSPDM_SUCCESS) {
        ctx->spdmOnlyLocked = lock;
    }
    return rc;
}

int wolfTPM2_SPDM_SetRequesterKeyTPMT(
    WOLFTPM2_SPDM_CTX* ctx,
    const byte* tpmtPub, word32 tpmtPubSz)
{
    if (ctx == NULL || ctx->spdmCtx == NULL) {
        return BAD_FUNC_ARG;
    }
    return wolfSPDM_SetRequesterKeyTPMT(ctx->spdmCtx, tpmtPub, tpmtPubSz);
}

/* Enable SPDM on Nuvoton TPM via NTC2_PreConfig vendor command.
 * This requires platform hierarchy authorization and a TPM reset. */
int wolfTPM2_SPDM_Enable(WOLFTPM2_SPDM_CTX* ctx)
{
    int rc;
    WOLFTPM2_DEV dev;
    NTC2_PreConfig_In preConfigIn;
    NTC2_GetConfig_Out getConfigOut;

    if (ctx == NULL) {
        return BAD_FUNC_ARG;
    }

    if (ctx->tpmCtx == NULL) {
        /* Need TPM context for NTC2 commands */
        return BAD_FUNC_ARG;
    }

    /* Initialize wrapper device from TPM context */
    XMEMSET(&dev, 0, sizeof(dev));
    dev.ctx = *ctx->tpmCtx;

    /* Get current NTC2 configuration */
    XMEMSET(&getConfigOut, 0, sizeof(getConfigOut));
    rc = TPM2_NTC2_GetConfig(&getConfigOut);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("NTC2_GetConfig failed: 0x%x\n", rc);
    #endif
        return rc;
    }

    /* Check if SPDM is already enabled (bit 1 of Cfg_H, 0 = enabled) */
    if ((getConfigOut.preConfig.Cfg_H & NTC2_CFG_H_SPDM_DISABLE) == 0) {
    #ifdef DEBUG_WOLFTPM
        printf("SPDM already enabled on TPM\n");
    #endif
        return TPM_RC_SUCCESS;
    }

    /* Set SPDM capability bit (clear bit 1 to enable) */
    XMEMSET(&preConfigIn, 0, sizeof(preConfigIn));
    preConfigIn.preConfig = getConfigOut.preConfig;
    preConfigIn.preConfig.Cfg_H &= ~NTC2_CFG_H_SPDM_DISABLE;

    /* Apply new configuration (requires platform auth) */
    rc = TPM2_NTC2_PreConfig(&preConfigIn);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("NTC2_PreConfig failed: 0x%x\n", rc);
    #endif
        return rc;
    }

#ifdef DEBUG_WOLFTPM
    printf("SPDM enabled. TPM reset required for changes to take effect.\n");
#endif

    return TPM_RC_SUCCESS;
}

#endif /* WOLFSPDM_NUVOTON */

#endif /* WOLFTPM_SPDM */
