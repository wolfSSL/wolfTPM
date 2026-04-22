/* spdm_nuvoton.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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

/* Nuvoton-specific SPDM functions (GetStatus, SetOnlyMode). */

#include "spdm_internal.h"

#ifdef WOLFSPDM_NUVOTON

#include <wolftpm/spdm/spdm_nuvoton.h>

int wolfSPDM_Nuvoton_GetStatus(
    WOLFSPDM_CTX* ctx,
    WOLFSPDM_NUVOTON_STATUS* status)
{
    WOLFSPDM_VENDOR_RSP rsp;
    byte statusType[4] = {0x00, 0x00, 0x00, 0x00};
    int rc;

    if (ctx == NULL || status == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    XMEMSET(status, 0, sizeof(*status));

    wolfSPDM_DebugPrint(ctx, "Nuvoton: GET_STS_\n");

    rc = wolfSPDM_TCG_VendorCmdClear(ctx, WOLFSPDM_VDCODE_GET_STS,
        statusType, sizeof(statusType), &rsp);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    wolfSPDM_DebugPrint(ctx, "GET_STS_: VdCode='%.8s', %u bytes\n",
        rsp.vdCode, rsp.payloadSz);

    /* Parse status fields per Nuvoton spec page 9:
     * Byte 0: SpecVersionMajor (0 for SPDM 1.x)
     * Byte 1: SpecVersionMinor (1 = SPDM 1.1, 3 = SPDM 1.3)
     * Byte 2: Reserved
     * Byte 3: SPDMOnly lock state (0 = unlocked, 1 = locked) */
    if (rsp.payloadSz >= 4) {
        byte specMajor = rsp.payload[0];
        byte specMinor = rsp.payload[1];
        byte spdmOnly = rsp.payload[3];

        status->specVersionMajor = specMajor;
        status->specVersionMinor = specMinor;
        status->spdmOnlyLocked = (spdmOnly != 0);
        status->spdmEnabled = 1;
        status->sessionActive = 0;

        wolfSPDM_DebugPrint(ctx, "GET_STS_: SpecVersion=%u.%u, SPDMOnly=%s\n",
            specMajor, specMinor, spdmOnly ? "LOCKED" : "unlocked");
    } else if (rsp.payloadSz >= 1) {
        status->spdmOnlyLocked = (rsp.payload[0] != 0);
        status->spdmEnabled = 1;
        wolfSPDM_DebugPrint(ctx, "GET_STS_: SPDMOnly=%s (minimal response)\n",
            status->spdmOnlyLocked ? "LOCKED" : "unlocked");
    }
    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_Nuvoton_SetOnlyMode(
    WOLFSPDM_CTX* ctx,
    int lock)
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

    wolfSPDM_DebugPrint(ctx, "Nuvoton: SPDMONLY %s\n",
        lock ? "LOCK" : "UNLOCK");

    rc = wolfSPDM_TCG_VendorCmdSecured(ctx, WOLFSPDM_VDCODE_SPDMONLY,
        param, sizeof(param));
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    wolfSPDM_DebugPrint(ctx, "SPDMONLY: Success\n");
    return WOLFSPDM_SUCCESS;
}

#endif /* WOLFSPDM_NUVOTON */

#endif /* WOLFTPM_SPDM */
