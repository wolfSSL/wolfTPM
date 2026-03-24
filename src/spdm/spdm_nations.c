/* spdm_nations.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSPDM.
 *
 * wolfSPDM is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSPDM is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#ifdef WOLFTPM_SPDM

/* Nations Technology NS350 SPDM Functions
 *
 * PSK-mode vendor commands and PSK connection flow.
 * Identity key mode uses shared TCG code in spdm_tcg.c.
 */

#include "spdm_internal.h"

#ifdef WOLFSPDM_NATIONS

#include <wolftpm/spdm/spdm_nations.h>

/* ----- Nations PSK-Mode Vendor Commands ----- */

int wolfSPDM_Nations_GetStatus(WOLFSPDM_CTX* ctx,
    WOLFSPDM_NATIONS_STATUS* status)
{
    WOLFSPDM_VENDOR_RSP rsp;
    int rc;

    if (ctx == NULL || status == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    XMEMSET(status, 0, sizeof(*status));

    wolfSPDM_DebugPrint(ctx, "Nations: GET_STS_\n");

    /* NS350 accepts GET_STATUS with no payload (Type field omitted) */
    rc = wolfSPDM_TCG_VendorCmdClear(ctx, WOLFSPDM_VDCODE_GET_STS,
        NULL, 0, &rsp);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    wolfSPDM_DebugHex(ctx, "GET_STS_ payload", rsp.payload, rsp.payloadSz);

    /* Per TCG spec Table 15 — GET_STATUS_RSP payload:
     * [0] SpecMajorVersion, [1] SpecMinorVersion,
     * [2] PSKSet (00=NO, 01=YES),
     * [3] SPDMOnly (00=DISABLED, 01=ENABLED, 81=PENDING_DISABLE) */
    if (rsp.payloadSz >= 4) {
        status->spdmEnabled = 1;
        status->pskProvisioned = (rsp.payload[2] != 0);
        status->spdmOnlyLocked = (rsp.payload[3] != 0);
        wolfSPDM_DebugPrint(ctx, "GET_STS_: v%u.%u PSK=%s SPDMOnly=0x%02x\n",
            rsp.payload[0], rsp.payload[1],
            status->pskProvisioned ? "YES" : "NO",
            rsp.payload[3]);
    }

    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_Nations_SetOnlyMode(WOLFSPDM_CTX* ctx, int lock)
{
    byte param[1];
    int rc;

    if (ctx == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (ctx->state != WOLFSPDM_STATE_CONNECTED) {
        return WOLFSPDM_E_NOT_CONNECTED;
    }

    param[0] = lock ? WOLFSPDM_SPDMONLY_LOCK : WOLFSPDM_SPDMONLY_UNLOCK;

    wolfSPDM_DebugPrint(ctx, "Nations: SPDMONLY %s\n",
        lock ? "LOCK" : "UNLOCK");

    rc = wolfSPDM_TCG_VendorCmdSecured(ctx, WOLFSPDM_VDCODE_SPDMONLY,
        param, sizeof(param));
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    wolfSPDM_DebugPrint(ctx, "SPDMONLY: Success (Lock=%u)\n", param[0]);
    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_Nations_PskSet(WOLFSPDM_CTX* ctx,
    const byte* psk, word32 pskSz)
{
    int rc;

    if (ctx == NULL || psk == NULL || pskSz == 0) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    wolfSPDM_DebugPrint(ctx, "Nations: PSK_SET_ (%u bytes)\n", pskSz);

    rc = wolfSPDM_TCG_VendorCmdClear(ctx, WOLFSPDM_NATIONS_VDCODE_PSK_SET,
        psk, pskSz, NULL);
    if (rc != WOLFSPDM_SUCCESS) {
        wolfSPDM_DebugPrint(ctx, "PSK_SET_ failed: %d\n", rc);
        return rc;
    }

    wolfSPDM_DebugPrint(ctx, "PSK_SET_: Success\n");
    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_Nations_PskClear(WOLFSPDM_CTX* ctx,
    const byte* clearAuth, word32 clearAuthSz)
{
    int rc;

    if (ctx == NULL || clearAuth == NULL || clearAuthSz == 0) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    wolfSPDM_DebugPrint(ctx, "Nations: PSK_CLR_ (auth=%u bytes)\n",
        clearAuthSz);

    rc = wolfSPDM_TCG_VendorCmdClear(ctx, WOLFSPDM_NATIONS_VDCODE_PSK_CLEAR,
        clearAuth, clearAuthSz, NULL);
    if (rc != WOLFSPDM_SUCCESS) {
        wolfSPDM_DebugPrint(ctx, "PSK_CLR_ failed: %d\n", rc);
        return rc;
    }

    wolfSPDM_DebugPrint(ctx, "PSK_CLR_: Success\n");
    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_Nations_PskClearWithVCA(WOLFSPDM_CTX* ctx,
    const byte* clearAuth, word32 clearAuthSz)
{
    int rc;

    if (ctx == NULL || clearAuth == NULL || clearAuthSz == 0) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    /* Full VCA: GET_VERSION + GET_CAPABILITIES + NEGOTIATE_ALGORITHMS */
    rc = wolfSPDM_GetVersion(ctx);
    if (rc != WOLFSPDM_SUCCESS) return rc;

    rc = wolfSPDM_TCG_GetCapabilities(ctx, WOLFSPDM_TCG_CAPS_FLAGS_PSK);
    if (rc != WOLFSPDM_SUCCESS) return rc;

    rc = wolfSPDM_TCG_NegotiateAlgorithms(ctx);
    if (rc != WOLFSPDM_SUCCESS) return rc;

    return wolfSPDM_Nations_PskClear(ctx, clearAuth, clearAuthSz);
}

/* PSK connection flow moved to spdm_psk.c (wolfSPDM_ConnectPsk).
 * wolfSPDM_ConnectNationsPsk is a backward-compat alias in spdm_psk.h. */

#endif /* WOLFSPDM_NATIONS */

#endif /* WOLFTPM_SPDM */
