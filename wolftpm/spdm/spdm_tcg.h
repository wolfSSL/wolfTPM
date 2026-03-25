/* spdm_tcg.h
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

/* Shared TCG SPDM Binding Support
 *
 * This header provides shared TCG SPDM functionality used by both
 * Nuvoton and Nations Technology TPMs:
 * - TCG SPDM Binding message framing (per TCG SPDM Binding Spec v1.0)
 * - Vendor-defined command helpers
 * - Identity key exchange (GET_PUBK, GIVE_PUB)
 * - GET_CAPABILITIES + NEGOTIATE_ALGORITHMS
 * - TCG SPDM connection flow
 */

#ifndef WOLFSPDM_TCG_H
#define WOLFSPDM_TCG_H

#include <wolftpm/spdm/spdm_types.h>

#ifdef WOLFTPM_SPDM_TCG

#ifdef __cplusplus
extern "C" {
#endif

/* ----- TCG SPDM Binding Constants (per TCG SPDM Binding Spec v1.0) ----- */

/* Message Tags */
#define WOLFSPDM_TCG_TAG_CLEAR          0x8101  /* Clear (unencrypted) message */
#define WOLFSPDM_TCG_TAG_SECURED        0x8201  /* Secured (encrypted) message */

/* Header Sizes */
#define WOLFSPDM_TCG_HEADER_SIZE        16      /* TCG binding header size */

/* FIPS Service Indicator */
#define WOLFSPDM_FIPS_NON_FIPS          0x00
#define WOLFSPDM_FIPS_APPROVED          0x01

/* ----- TCG Vendor-Defined Command Codes (shared) ----- */

/* 8-byte ASCII vendor codes for SPDM VENDOR_DEFINED messages */
#define WOLFSPDM_VDCODE_LEN             8

#define WOLFSPDM_VDCODE_TPM2_CMD        "TPM2_CMD"  /* TPM command over SPDM */
#define WOLFSPDM_VDCODE_GET_PUBK        "GET_PUBK"  /* Get TPM's identity key */
#define WOLFSPDM_VDCODE_GIVE_PUB        "GIVE_PUB"  /* Give host's identity key */
#define WOLFSPDM_VDCODE_GET_STS         "GET_STS_"  /* Get SPDM status */
#define WOLFSPDM_VDCODE_SPDMONLY        "SPDMONLY"  /* Lock/unlock SPDM-only */

/* SPDMONLY command parameters */
#define WOLFSPDM_SPDMONLY_LOCK          0x01
#define WOLFSPDM_SPDMONLY_UNLOCK        0x00

/* ----- TCG Binding Header Structures ----- */

/* Clear message header (tag 0x8101)
 * Layout: tag(2/BE) + size(4/BE) + connectionHandle(4/BE) +
 *         fipsIndicator(2/BE) + reserved(4) = 16 bytes */
typedef struct WOLFSPDM_TCG_CLEAR_HDR {
    word16  tag;
    word32  size;
    word32  connectionHandle;
    word16  fipsIndicator;
    word32  reserved;
} WOLFSPDM_TCG_CLEAR_HDR;

/* ----- Vendor Command Response Container ----- */

typedef struct {
    char   vdCode[WOLFSPDM_VDCODE_LEN + 1];
    byte   payload[WOLFSPDM_VENDOR_BUF_SZ];
    word32 payloadSz;
} WOLFSPDM_VENDOR_RSP;

/* ----- Vendor Command Helpers ----- */

WOLFTPM_API int wolfSPDM_TCG_VendorCmdClear(WOLFSPDM_CTX* ctx,
    const char* vdCode, const byte* payload, word32 payloadSz,
    WOLFSPDM_VENDOR_RSP* rsp);

WOLFTPM_API int wolfSPDM_TCG_VendorCmdSecured(WOLFSPDM_CTX* ctx,
    const char* vdCode, const byte* payload, word32 payloadSz);

/* ----- TCG Binding Message Framing ----- */

WOLFTPM_API int wolfSPDM_BuildTcgClearMessage(
    WOLFSPDM_CTX* ctx,
    const byte* spdmPayload, word32 spdmPayloadSz,
    byte* outBuf, word32 outBufSz);

WOLFTPM_API int wolfSPDM_ParseTcgClearMessage(
    const byte* inBuf, word32 inBufSz,
    byte* spdmPayload, word32* spdmPayloadSz,
    WOLFSPDM_TCG_CLEAR_HDR* hdr);

/* ----- Vendor-Defined Message Helpers ----- */

WOLFTPM_API int wolfSPDM_BuildVendorDefined(
    byte spdmVersion, const char* vdCode,
    const byte* payload, word32 payloadSz,
    byte* outBuf, word32 outBufSz);

WOLFTPM_API int wolfSPDM_ParseVendorDefined(
    const byte* inBuf, word32 inBufSz, char* vdCode,
    byte* payload, word32* payloadSz);

/* ----- Shared TCG SPDM Functions ----- */

WOLFTPM_API int wolfSPDM_TCG_GetPubKey(WOLFSPDM_CTX* ctx,
    byte* pubKey, word32* pubKeySz);

WOLFTPM_API int wolfSPDM_TCG_GivePubKey(WOLFSPDM_CTX* ctx,
    const byte* pubKey, word32 pubKeySz);

WOLFTPM_API int wolfSPDM_TCG_GetCapabilities(WOLFSPDM_CTX* ctx,
    word32 capsFlags);

WOLFTPM_API int wolfSPDM_TCG_NegotiateAlgorithms(WOLFSPDM_CTX* ctx);

WOLFTPM_API int wolfSPDM_SetRequesterKeyTPMT(WOLFSPDM_CTX* ctx,
    const byte* tpmtPub, word32 tpmtPubSz);

WOLFTPM_API int wolfSPDM_ConnectTCG(WOLFSPDM_CTX* ctx);

/* Backward compatibility aliases */
#define wolfSPDM_ConnectNuvoton     wolfSPDM_ConnectTCG
#define wolfSPDM_Nuvoton_GetPubKey  wolfSPDM_TCG_GetPubKey
#define wolfSPDM_Nuvoton_GivePubKey wolfSPDM_TCG_GivePubKey

/* ----- TCG Context Defaults ----- */

#define WOLFSPDM_NUVOTON_CONN_HANDLE_DEFAULT    0
#define WOLFSPDM_NUVOTON_FIPS_DEFAULT           WOLFSPDM_FIPS_NON_FIPS

/* Default capabilities flags (identity key mode, no PSK_CAP) */
#define WOLFSPDM_TCG_CAPS_FLAGS_DEFAULT         0x000193C0UL
/* Capabilities flags with PSK_CAP (bit 10) set */
#define WOLFSPDM_TCG_CAPS_FLAGS_PSK             0x000197C0UL

#ifdef __cplusplus
}
#endif

#endif /* WOLFTPM_SPDM_TCG */

#endif /* WOLFSPDM_TCG_H */
