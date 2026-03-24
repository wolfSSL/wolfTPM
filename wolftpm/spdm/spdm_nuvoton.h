/* spdm_nuvoton.h
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

/* Nuvoton TPM SPDM Support
 *
 * Nuvoton-specific SPDM functions (GetStatus, SetOnlyMode).
 * Shared TCG code is in spdm_tcg.h / spdm_tcg.c.
 *
 * The Nuvoton NPCT75x TPM uses a simplified SPDM flow:
 *   GET_VERSION -> GET_PUB_KEY -> KEY_EXCHANGE -> GIVE_PUB_KEY -> FINISH
 *
 * Notable differences from standard SPDM:
 * - No GET_CAPABILITIES or NEGOTIATE_ALGORITHMS (Algorithm Set B is fixed)
 * - Uses vendor-defined commands for identity key exchange
 * - TCG binding headers wrap all SPDM messages
 *
 * Reference: Nuvoton SPDM Guidance Rev 1.11
 */

#ifndef WOLFSPDM_NUVOTON_H
#define WOLFSPDM_NUVOTON_H

/* Include shared TCG declarations */
#include <wolftpm/spdm/spdm_tcg.h>

#ifdef WOLFSPDM_NUVOTON

#ifdef __cplusplus
extern "C" {
#endif

/* ----- Nuvoton SPDM Status ----- */

typedef struct WOLFSPDM_NUVOTON_STATUS {
    int     spdmEnabled;
    int     sessionActive;
    int     spdmOnlyLocked;
    byte    specVersionMajor;
    byte    specVersionMinor;
} WOLFSPDM_NUVOTON_STATUS;

/* ----- Nuvoton-Only Functions ----- */

WOLFTPM_API int wolfSPDM_Nuvoton_GetStatus(
    WOLFSPDM_CTX* ctx,
    WOLFSPDM_NUVOTON_STATUS* status);

WOLFTPM_API int wolfSPDM_Nuvoton_SetOnlyMode(
    WOLFSPDM_CTX* ctx,
    int lock);

#ifdef __cplusplus
}
#endif

#endif /* WOLFSPDM_NUVOTON */

#endif /* WOLFSPDM_NUVOTON_H */
