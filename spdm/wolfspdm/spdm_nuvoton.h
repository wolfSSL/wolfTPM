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
 * This header provides Nuvoton-specific SPDM functionality:
 * - TCG SPDM Binding message framing (per TCG SPDM Binding Spec v1.0)
 * - Nuvoton vendor-defined commands (GET_PUBK, GIVE_PUB, GET_STS_, SPDMONLY)
 * - Nuvoton SPDM handshake flow (differs from standard SPDM)
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

/* Note: This header is included from spdm.h after WOLFSPDM_CTX forward declaration.
 * DO NOT include spdm.h here to avoid circular dependency.
 * Include spdm_types.h for basic types only. */
#include <wolfspdm/spdm_types.h>

#ifdef WOLFSPDM_NUVOTON

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

/* ----- Nuvoton Vendor-Defined Command Codes ----- */

/* 8-byte ASCII vendor codes for SPDM VENDOR_DEFINED messages */
#define WOLFSPDM_VDCODE_LEN             8

#define WOLFSPDM_VDCODE_TPM2_CMD        "TPM2_CMD"  /* TPM command over SPDM */
#define WOLFSPDM_VDCODE_GET_PUBK        "GET_PUBK"  /* Get TPM's SPDM-Identity key */
#define WOLFSPDM_VDCODE_GIVE_PUB        "GIVE_PUB"  /* Give host's SPDM-Identity key */
#define WOLFSPDM_VDCODE_GET_STS         "GET_STS_"  /* Get SPDM status */
#define WOLFSPDM_VDCODE_SPDMONLY        "SPDMONLY"  /* Lock/unlock SPDM-only mode */

/* SPDMONLY command parameters */
#define WOLFSPDM_SPDMONLY_LOCK          0x01
#define WOLFSPDM_SPDMONLY_UNLOCK        0x00

/* ----- TCG Binding Header Structures ----- */

/* Clear message header (tag 0x8101)
 * Layout: tag(2/BE) + size(4/BE) + connectionHandle(4/BE) +
 *         fipsIndicator(2/BE) + reserved(4) = 16 bytes */
typedef struct WOLFSPDM_TCG_CLEAR_HDR {
    word16  tag;              /* WOLFSPDM_TCG_TAG_CLEAR (0x8101) */
    word32  size;             /* Total message size including header */
    word32  connectionHandle; /* Connection handle (0 for single connection) */
    word16  fipsIndicator;    /* FIPS service indicator */
    word32  reserved;         /* Must be 0 */
} WOLFSPDM_TCG_CLEAR_HDR;

/* ----- Nuvoton SPDM Status ----- */

typedef struct WOLFSPDM_NUVOTON_STATUS {
    int     spdmEnabled;      /* SPDM is enabled on the TPM */
    int     sessionActive;    /* An SPDM session is currently active */
    int     spdmOnlyLocked;   /* SPDM-only mode is locked */
    byte    specVersionMajor; /* SPDM spec version major (0 for 1.x) */
    byte    specVersionMinor; /* SPDM spec version minor (1=1.1, 3=1.3) */
} WOLFSPDM_NUVOTON_STATUS;

/* ----- TCG Binding Message Framing Functions ----- */

/**
 * Build a TCG SPDM clear message (tag 0x8101).
 * Wraps an SPDM payload in the TCG binding header format.
 *
 * @param ctx           wolfSPDM context
 * @param spdmPayload   SPDM message payload
 * @param spdmPayloadSz Size of SPDM payload
 * @param outBuf        Output buffer for framed message
 * @param outBufSz      Size of output buffer
 * @return Total message size on success, negative on error
 */
WOLFSPDM_API int wolfSPDM_BuildTcgClearMessage(
    WOLFSPDM_CTX* ctx,
    const byte* spdmPayload, word32 spdmPayloadSz,
    byte* outBuf, word32 outBufSz);

/**
 * Parse a TCG SPDM clear message (tag 0x8101).
 * Extracts the SPDM payload from the TCG binding header.
 *
 * @param inBuf         Input buffer containing framed message
 * @param inBufSz       Size of input buffer
 * @param spdmPayload   Output buffer for SPDM payload
 * @param spdmPayloadSz [in] Size of output buffer, [out] Actual payload size
 * @param hdr           Optional: receives parsed header fields
 * @return Payload size on success, negative on error
 */
WOLFSPDM_API int wolfSPDM_ParseTcgClearMessage(
    const byte* inBuf, word32 inBufSz,
    byte* spdmPayload, word32* spdmPayloadSz,
    WOLFSPDM_TCG_CLEAR_HDR* hdr);

/* ----- Vendor-Defined Message Helpers ----- */

/**
 * Build an SPDM VENDOR_DEFINED_REQUEST message.
 *
 * @param spdmVersion   Negotiated SPDM version byte (e.g., 0x13)
 * @param vdCode        8-byte ASCII vendor code (e.g., "GET_PUBK")
 * @param payload       Vendor-specific payload (may be NULL)
 * @param payloadSz     Size of payload
 * @param outBuf        Output buffer for message
 * @param outBufSz      Size of output buffer
 * @return Message size on success, negative on error
 */
WOLFSPDM_API int wolfSPDM_BuildVendorDefined(
    byte spdmVersion,
    const char* vdCode,
    const byte* payload, word32 payloadSz,
    byte* outBuf, word32 outBufSz);

/**
 * Parse an SPDM VENDOR_DEFINED_RESPONSE message.
 *
 * @param inBuf         Input buffer containing message
 * @param inBufSz       Size of input buffer
 * @param vdCode        Receives 8-byte vendor code (buffer must be 9+ bytes)
 * @param payload       Output buffer for payload
 * @param payloadSz     [in] Size of output buffer, [out] Actual payload size
 * @return Payload size on success, negative on error
 */
WOLFSPDM_API int wolfSPDM_ParseVendorDefined(
    const byte* inBuf, word32 inBufSz,
    char* vdCode,
    byte* payload, word32* payloadSz);

/* ----- Nuvoton-Specific SPDM Functions ----- */

/**
 * Get the TPM's SPDM-Identity public key (GET_PUBK vendor command).
 * This is sent as a clear (unencrypted) SPDM message before key exchange.
 *
 * @param ctx       wolfSPDM context
 * @param pubKey    Output buffer for public key (raw X||Y, 96 bytes for P-384)
 * @param pubKeySz  [in] Size of buffer, [out] Actual key size
 * @return WOLFSPDM_SUCCESS or negative error code
 */
WOLFSPDM_API int wolfSPDM_Nuvoton_GetPubKey(
    WOLFSPDM_CTX* ctx,
    byte* pubKey, word32* pubKeySz);

/**
 * Give the host's SPDM-Identity public key to the TPM (GIVE_PUB vendor command).
 * This is sent as a secured (encrypted) message after key exchange.
 *
 * @param ctx       wolfSPDM context
 * @param pubKey    Host's public key (TPMT_PUBLIC format, ~120 bytes)
 * @param pubKeySz  Size of public key
 * @return WOLFSPDM_SUCCESS or negative error code
 */
WOLFSPDM_API int wolfSPDM_Nuvoton_GivePubKey(
    WOLFSPDM_CTX* ctx,
    const byte* pubKey, word32 pubKeySz);

/**
 * Get SPDM status from the TPM (GET_STS_ vendor command).
 * Can be called before or after session establishment.
 *
 * @param ctx       wolfSPDM context
 * @param status    Receives SPDM status information
 * @return WOLFSPDM_SUCCESS or negative error code
 */
WOLFSPDM_API int wolfSPDM_Nuvoton_GetStatus(
    WOLFSPDM_CTX* ctx,
    WOLFSPDM_NUVOTON_STATUS* status);

/**
 * Lock or unlock SPDM-only mode (SPDMONLY vendor command).
 * When locked, the TPM only accepts commands over SPDM.
 *
 * @param ctx       wolfSPDM context
 * @param lock      WOLFSPDM_SPDMONLY_LOCK (1) or WOLFSPDM_SPDMONLY_UNLOCK (0)
 * @return WOLFSPDM_SUCCESS or negative error code
 */
WOLFSPDM_API int wolfSPDM_Nuvoton_SetOnlyMode(
    WOLFSPDM_CTX* ctx,
    int lock);

/**
 * Set the requester's SPDM-Identity public key in TPMT_PUBLIC format.
 * Required for GIVE_PUB step in Nuvoton handshake.
 *
 * @param ctx       wolfSPDM context
 * @param tpmtPub   Public key in TPMT_PUBLIC format (~120 bytes for P-384)
 * @param tpmtPubSz Size of TPMT_PUBLIC
 * @return WOLFSPDM_SUCCESS or negative error code
 */
WOLFSPDM_API int wolfSPDM_SetRequesterKeyTPMT(WOLFSPDM_CTX* ctx,
    const byte* tpmtPub, word32 tpmtPubSz);

/**
 * Perform Nuvoton-specific SPDM connection.
 * Uses the Nuvoton handshake flow:
 *   GET_VERSION -> GET_PUB_KEY -> KEY_EXCHANGE -> GIVE_PUB_KEY -> FINISH
 *
 * This is called internally by wolfSPDM_Connect() when mode is NUVOTON.
 *
 * @param ctx       wolfSPDM context
 * @return WOLFSPDM_SUCCESS or negative error code
 */
WOLFSPDM_API int wolfSPDM_ConnectNuvoton(WOLFSPDM_CTX* ctx);

/* ----- Nuvoton Context Fields ----- */

/* These fields are added to WOLFSPDM_CTX when WOLFSPDM_NUVOTON is defined */

/* Connection handle for TCG binding (usually 0) */
#define WOLFSPDM_NUVOTON_CONN_HANDLE_DEFAULT    0

/* FIPS indicator for TCG binding */
#define WOLFSPDM_NUVOTON_FIPS_DEFAULT           WOLFSPDM_FIPS_NON_FIPS

#ifdef __cplusplus
}
#endif

#endif /* WOLFSPDM_NUVOTON */

#endif /* WOLFSPDM_NUVOTON_H */
