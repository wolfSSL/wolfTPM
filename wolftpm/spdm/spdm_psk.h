/* spdm_psk.h
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

/* Shared SPDM PSK Support (DSP0274 1.2+)
 *
 * Standard SPDM PSK protocol:
 * - PSK_EXCHANGE / PSK_EXCHANGE_RSP
 * - PSK_FINISH / PSK_FINISH_RSP
 * - PSK key derivation (HKDF-Extract with PSK)
 * - Shared PSK connection flow
 *
 * Vendor-specific PSK provisioning commands (PSK_SET, PSK_CLEAR, etc.)
 * remain in the vendor files (spdm_nations.c, etc.).
 */

#ifndef WOLFSPDM_PSK_H
#define WOLFSPDM_PSK_H

#include <wolftpm/spdm/spdm_types.h>

#ifdef WOLFTPM_SPDM_PSK

#ifdef __cplusplus
extern "C" {
#endif

/* ----- PSK Context Setup ----- */

WOLFTPM_API int wolfSPDM_SetPSK(WOLFSPDM_CTX* ctx,
    const byte* psk, word32 pskSz,
    const byte* hint, word32 hintSz);

/* ----- PSK Message Builders/Parsers ----- */

WOLFTPM_API int wolfSPDM_BuildPskExchange(WOLFSPDM_CTX* ctx,
    byte* buf, word32* bufSz);

WOLFTPM_API int wolfSPDM_ParsePskExchangeRsp(WOLFSPDM_CTX* ctx,
    const byte* buf, word32 bufSz);

WOLFTPM_API int wolfSPDM_BuildPskFinish(WOLFSPDM_CTX* ctx,
    byte* buf, word32* bufSz);

WOLFTPM_API int wolfSPDM_ParsePskFinishRsp(WOLFSPDM_CTX* ctx,
    const byte* buf, word32 bufSz);

/* ----- PSK Key Derivation ----- */

WOLFTPM_API int wolfSPDM_DeriveHandshakeKeysPsk(WOLFSPDM_CTX* ctx,
    const byte* th1Hash);

/* ----- Shared PSK Connection Flow ----- */

/**
 * Perform PSK SPDM connection.
 * GET_VERSION -> GET_CAPABILITIES -> NEGOTIATE_ALGORITHMS ->
 * PSK_EXCHANGE -> PSK_FINISH -> app key derivation.
 *
 * @param ctx       wolfSPDM context (must have PSK set via wolfSPDM_SetPSK)
 * @return WOLFSPDM_SUCCESS or negative error code
 */
WOLFTPM_API int wolfSPDM_ConnectPsk(WOLFSPDM_CTX* ctx);

/* Backward compatibility */
#define wolfSPDM_ConnectNationsPsk wolfSPDM_ConnectPsk

#ifdef __cplusplus
}
#endif

#endif /* WOLFTPM_SPDM_PSK */

#endif /* WOLFSPDM_PSK_H */
