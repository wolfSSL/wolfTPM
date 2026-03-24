/* spdm_nations.h
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

/* Nations Technology NS350 TPM SPDM Support
 *
 * Two SPDM modes (mutually exclusive):
 *
 * 1. Identity key mode — TCG "TPM Communication over SPDM"
 *    - Uses shared TCG binding code (spdm_tcg.c)
 *    - GET_PUB_KEY, GIVE_PUB_KEY, TPM_CMD vendor commands
 *    - Algorithm Set B (P-384/SHA-384/AES-256-GCM)
 *
 * 2. PSK mode — PSK_EXCHANGE/PSK_FINISH
 *    - GET_STATUS, SPDM_ONLY, PSK_SET, PSK_CLEAR vendor commands
 *    - Same Algorithm Set B
 *
 * Reference: NS350 Datasheet Rev 2.06 Section 4.5.8
 */

#ifndef WOLFSPDM_NATIONS_H
#define WOLFSPDM_NATIONS_H

#ifdef WOLFSPDM_NATIONS

/* Include shared TCG declarations */
#include <wolftpm/spdm/spdm_tcg.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ----- Nations Vendor TPM Command ----- */

#define TPM_CC_Nations_SpdmIdentityKeySet  (0x20000708)

/* Nations vendor capability properties */
#define TPM_PT_VENDOR_NATIONS_FIPS_SL2     (TPM_PT_VENDOR + 11)
#define TPM_PT_VENDOR_NATIONS_IDENTITY_KEY (TPM_PT_VENDOR + 12)

/* ----- Nations-Only Vendor-Defined Commands ----- */

#define WOLFSPDM_NATIONS_VDCODE_PSK_SET     "PSK_SET_"
#define WOLFSPDM_NATIONS_VDCODE_PSK_CLEAR   "PSK_CLR_"

/* ----- Nations SPDM Status ----- */

/* GET_STATUS_RSP fields per TCG spec Table 15 */
typedef struct WOLFSPDM_NATIONS_STATUS {
    unsigned int spdmEnabled            : 1;
    unsigned int sessionActive          : 1;
    unsigned int spdmOnlyLocked         : 1;
    unsigned int spdmOnlyPending        : 1;
    unsigned int pskProvisioned         : 1;
    unsigned int identityKeyProvisioned : 1;
} WOLFSPDM_NATIONS_STATUS;

/* ----- Nations PSK-Mode SPDM Functions ----- */

WOLFTPM_API int wolfSPDM_Nations_GetStatus(WOLFSPDM_CTX* ctx,
    WOLFSPDM_NATIONS_STATUS* status);

WOLFTPM_API int wolfSPDM_Nations_SetOnlyMode(WOLFSPDM_CTX* ctx, int lock);

WOLFTPM_API int wolfSPDM_Nations_PskSet(WOLFSPDM_CTX* ctx,
    const byte* psk, word32 pskSz);

WOLFTPM_API int wolfSPDM_Nations_PskClear(WOLFSPDM_CTX* ctx,
    const byte* clearAuth, word32 clearAuthSz);

WOLFTPM_API int wolfSPDM_Nations_PskClearWithVCA(WOLFSPDM_CTX* ctx,
    const byte* clearAuth, word32 clearAuthSz);

/* wolfSPDM_ConnectNationsPsk is an alias for wolfSPDM_ConnectPsk (spdm_psk.h) */

#ifdef __cplusplus
}
#endif

#endif /* WOLFSPDM_NATIONS */

#endif /* WOLFSPDM_NATIONS_H */
