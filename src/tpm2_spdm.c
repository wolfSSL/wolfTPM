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

/* SPDM Integration Layer for wolfTPM
 *
 * All SPDM protocol logic, cryptography, and message handling is implemented
 * in wolfSPDM (spdm/ subdirectory). This file provides:
 *
 *   1. Context management (init/free)
 *   2. Secured exchange with VENDOR_DEFINED wrapping (Nuvoton)
 *   3. TPM-specific NTC2_PreConfig for SPDM enable/disable (Nuvoton only)
 *   4. TIS I/O callback for routing wolfSPDM through TPM SPI transport
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_spdm.h>

#ifdef WOLFTPM_SPDM

#include <wolftpm/tpm2_wrap.h>

/* TIS functions for SPI/I2C TPM transport */
#if defined(WOLFTPM_SPDM_TCG) && \
    !defined(WOLFTPM_LINUX_DEV) && !defined(WOLFTPM_SWTPM) && \
    !defined(WOLFTPM_WINAPI)
    #include <wolftpm/tpm2_tis.h>
    #include <wolftpm/tpm2_packet.h>
    #define WOLFTPM_SPDM_TIS_IO
#endif

/* wolfSPDM provides all SPDM protocol implementation */
#include <wolftpm/spdm/spdm.h>

/* -------------------------------------------------------------------------- */
/* TIS I/O Callback (SPI/I2C TPM transport for SPDM) */
/* -------------------------------------------------------------------------- */

#ifdef WOLFTPM_SPDM_TIS_IO
/* TIS I/O callback for routing wolfSPDM through TPM SPI/I2C FIFO.
 * This matches the WOLFSPDM_IO_CB signature. TCG framing (headers) is
 * handled by wolfSPDM_SendReceive() in Nuvoton mode, so this callback
 * just sends/receives raw bytes through the TIS FIFO. */
static int wolfTPM2_SPDM_TisIoCb(
    WOLFSPDM_CTX* spdmCtx,
    const byte* txBuf, word32 txSz,
    byte* rxBuf, word32* rxSz,
    void* userCtx)
{
    TPM2_CTX* tpmCtx = (TPM2_CTX*)userCtx;
    byte ioBuf[MAX_RESPONSE_SIZE];
    TPM2_Packet packet;
    int rc;
    UINT32 rspSz;

    (void)spdmCtx;

    if (tpmCtx == NULL || txBuf == NULL || rxBuf == NULL || rxSz == NULL) {
        return -1;
    }

    if (txSz > sizeof(ioBuf)) {
        return -1;
    }

    /* Set up packet with TX data */
    XMEMCPY(ioBuf, txBuf, txSz);
    packet.buf = ioBuf;
    packet.pos = (int)txSz;
    packet.size = (int)sizeof(ioBuf);

    /* Ensure we have TPM locality */
    rc = TPM2_TIS_RequestLocality(tpmCtx, TPM_TIMEOUT_TRIES);
    if (rc != TPM_RC_SUCCESS) {
        return rc;
    }

    /* Send through TIS FIFO and receive response */
    rc = TPM2_TIS_SendCommand(tpmCtx, &packet);
    if (rc != TPM_RC_SUCCESS) {
        return rc;
    }

    /* Extract response size from header bytes [2..5] (big-endian).
     * Both TPM headers and TCG SPDM binding headers store the total
     * message size at this offset in the same format. */
    XMEMCPY(&rspSz, &ioBuf[2], sizeof(UINT32));
    rspSz = TPM2_Packet_SwapU32(rspSz);

    if (rspSz > *rxSz || rspSz > sizeof(ioBuf)) {
        return -1;
    }

    XMEMCPY(rxBuf, ioBuf, rspSz);
    *rxSz = rspSz;

    return 0;
}
#endif /* WOLFTPM_SPDM_TIS_IO */

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

#ifdef WOLFTPM_SMALL_STACK
    /* Heap path: allocate and initialize via wolfSPDM_New() */
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

#ifdef WOLFTPM_SPDM_TCG
    /* In SPDM-only mode, TPM commands must be wrapped in SPDM VENDOR_DEFINED
     * messages with the TPM2_CMD vendor code. The TPM's SPDM layer only
     * accepts SPDM messages (starting with version byte 0x13), not raw TPM
     * commands (starting with tag 0x80 0x01). */
    if (wolfSPDM_GetMode(ctx->spdmCtx) == WOLFSPDM_MODE_NUVOTON ||
        wolfSPDM_GetMode(ctx->spdmCtx) == WOLFSPDM_MODE_NATIONS ||
        wolfSPDM_GetMode(ctx->spdmCtx) == WOLFSPDM_MODE_NATIONS_PSK) {
    #ifdef WOLFTPM_SMALL_STACK
        byte* vdMsg = (byte*)XMALLOC(WOLFSPDM_MAX_MSG_SIZE, NULL,
            DYNAMIC_TYPE_TMP_BUFFER);
        byte* vdRsp = (byte*)XMALLOC(WOLFSPDM_MAX_MSG_SIZE, NULL,
            DYNAMIC_TYPE_TMP_BUFFER);
    #else
        byte vdMsg[WOLFSPDM_MAX_MSG_SIZE];
        byte vdRsp[WOLFSPDM_MAX_MSG_SIZE];
    #endif
        word32 vdRspSz = WOLFSPDM_MAX_MSG_SIZE;
        char rspVdCode[WOLFSPDM_VDCODE_LEN + 1];
        int vdMsgSz;
        int rc = 0;
        byte ver;

    #ifdef WOLFTPM_SMALL_STACK
        if (vdMsg == NULL || vdRsp == NULL) {
            XFREE(vdMsg, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(vdRsp, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return MEMORY_E;
        }
    #endif

        /* Wrap TPM command in SPDM VENDOR_DEFINED_REQUEST("TPM2_CMD") */
        ver = wolfSPDM_GetNegotiatedVersion(ctx->spdmCtx);
        if (ver == 0) ver = SPDM_VERSION_13;
        vdMsgSz = wolfSPDM_BuildVendorDefined(ver,
            WOLFSPDM_VDCODE_TPM2_CMD,
            cmdPlain, cmdSz, vdMsg, WOLFSPDM_MAX_MSG_SIZE);
        if (vdMsgSz < 0) {
            rc = vdMsgSz;
        }

        /* Send encrypted VENDOR_DEFINED, receive encrypted response */
        if (rc == 0) {
            rc = wolfSPDM_SecuredExchange(ctx->spdmCtx,
                vdMsg, (word32)vdMsgSz, vdRsp, &vdRspSz);
        }

        /* Parse VENDOR_DEFINED_RESPONSE to extract TPM response.
         * ParseVendorDefined returns payload dataLen (>= 0) on success,
         * negative WOLFSPDM_E_* on failure. */
        if (rc == 0) {
            rc = wolfSPDM_ParseVendorDefined(vdRsp, vdRspSz,
                rspVdCode, rspPlain, rspSz);
            if (rc >= 0) {
                rc = 0; /* success - convert dataLen to success indicator */
            }
        }

        /* Verify response is for our TPM2_CMD request */
        if (rc == 0 && XMEMCMP(rspVdCode, WOLFSPDM_VDCODE_TPM2_CMD,
                     WOLFSPDM_VDCODE_LEN) != 0) {
            rc = WOLFSPDM_E_PEER_ERROR;
        }

    #ifdef WOLFTPM_SMALL_STACK
        XFREE(vdMsg, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(vdRsp, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    #endif
        return rc;
    }
#endif /* WOLFTPM_SPDM_TCG */

    /* Standard SPDM mode: send TPM command as raw app data */
    return wolfSPDM_SecuredExchange(ctx->spdmCtx,
        cmdPlain, cmdSz, rspPlain, rspSz);
}

/* -------------------------------------------------------------------------- */
/* Nuvoton-Specific Functions */
/* -------------------------------------------------------------------------- */

#ifdef WOLFTPM_SPDM_TCG

/* Set built-in TIS I/O callback for routing SPDM through TPM SPI/I2C.
 * Must be called after wolfTPM2_SPDM_InitCtx() and SetTPMCtx(). */
int wolfTPM2_SPDM_SetTisIO(WOLFTPM2_SPDM_CTX* ctx)
{
    if (ctx == NULL || ctx->spdmCtx == NULL || ctx->tpmCtx == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLFTPM_SPDM_TIS_IO
    return wolfSPDM_SetIO(ctx->spdmCtx, wolfTPM2_SPDM_TisIoCb, ctx->tpmCtx);
#else
    (void)ctx;
    return NOT_COMPILED_IN;
#endif
}

#ifdef WOLFSPDM_NUVOTON
/* Enable SPDM on Nuvoton TPM via NTC2_PreConfig vendor command.
 * This requires platform hierarchy authorization and a TPM reset. */
int wolfTPM2_SPDM_Enable(WOLFTPM2_SPDM_CTX* ctx)
{
    int rc;
    NTC2_PreConfig_In preConfigIn;
    NTC2_GetConfig_Out getConfigOut;

    if (ctx == NULL || ctx->tpmCtx == NULL) {
        return BAD_FUNC_ARG;
    }

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
    preConfigIn.authHandle = TPM_RH_PLATFORM;
    preConfigIn.preConfig = getConfigOut.preConfig;
    preConfigIn.preConfig.Cfg_H &= ~NTC2_CFG_H_SPDM_DISABLE;

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

int wolfTPM2_SPDM_Disable(WOLFTPM2_SPDM_CTX* ctx)
{
    int rc;
    NTC2_PreConfig_In preConfigIn;
    NTC2_GetConfig_Out getConfigOut;

    if (ctx == NULL || ctx->tpmCtx == NULL) {
        return BAD_FUNC_ARG;
    }

    /* Get current NTC2 configuration */
    XMEMSET(&getConfigOut, 0, sizeof(getConfigOut));
    rc = TPM2_NTC2_GetConfig(&getConfigOut);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("NTC2_GetConfig failed: 0x%x\n", rc);
    #endif
        return rc;
    }

    /* Check if SPDM is already disabled (bit 1 of Cfg_H, 1 = disabled) */
    if ((getConfigOut.preConfig.Cfg_H & NTC2_CFG_H_SPDM_DISABLE) != 0) {
    #ifdef DEBUG_WOLFTPM
        printf("SPDM already disabled on TPM\n");
    #endif
        return TPM_RC_SUCCESS;
    }


    /* Set SPDM disable bit (set bit 1 to disable) */
    XMEMSET(&preConfigIn, 0, sizeof(preConfigIn));
    preConfigIn.authHandle = TPM_RH_PLATFORM;
    preConfigIn.preConfig = getConfigOut.preConfig;
    preConfigIn.preConfig.Cfg_H |= NTC2_CFG_H_SPDM_DISABLE;

    rc = TPM2_NTC2_PreConfig(&preConfigIn);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("NTC2_PreConfig failed: 0x%x\n", rc);
    #endif
        return rc;
    }

#ifdef DEBUG_WOLFTPM
    printf("SPDM disabled. TPM reset required for changes to take effect.\n");
#endif

    return TPM_RC_SUCCESS;
}

#endif /* WOLFSPDM_NUVOTON */

#endif /* WOLFTPM_SPDM_TCG */

#endif /* WOLFTPM_SPDM */
