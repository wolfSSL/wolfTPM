/* tpm2_spdm.h
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

/* SPDM Secure Session Support for wolfTPM
 *
 * Implements SPDM (Security Protocol and Data Model) secure communication
 * between host and TPM per:
 * - DMTF DSP0274 (SPDM v1.3)
 * - TCG SPDM Binding for Secure Communication v1.0
 * - TCG TPM 2.0 Library Specification v1.84
 *
 * Architecture:
 *   Application -> wolfTPM2 Wrapper -> TPM2 Native -> TPM2 Packet
 *       -> SPDM Transport Layer (this module) -> SPI HAL
 *
 * The SPDM layer intercepts TPM commands when a session is active and wraps
 * them as VENDOR_DEFINED(TPM2_CMD) secured messages with AES-256-GCM AEAD.
 *
 * Backend abstraction allows swapping libspdm for wolfSPDM without changing
 * the transport or wrapper API.
 */

#ifndef __TPM2_SPDM_H__
#define __TPM2_SPDM_H__

#include <wolftpm/tpm2.h>

#ifdef WOLFTPM_SPDM

#ifdef __cplusplus
    extern "C" {
#endif

/* Forward declarations */
struct WOLFTPM2_SPDM_CTX;
struct WOLFTPM2_SPDM_BACKEND;

/* -------------------------------------------------------------------------- */
/* SPDM Session State */
/* -------------------------------------------------------------------------- */

typedef enum {
    SPDM_STATE_DISCONNECTED = 0,  /* No session */
    SPDM_STATE_INITIALIZED,       /* Context allocated, backend initialized */
    SPDM_STATE_VERSION_DONE,      /* GET_VERSION/VERSION complete */
    SPDM_STATE_CAPS_DONE,         /* Reserved (Nuvoton does not use CAPS) */
    SPDM_STATE_ALGORITHMS_DONE,   /* Reserved (Nuvoton does not use ALGO) */
    SPDM_STATE_PUBKEY_DONE,       /* GET_PUB_KEY vendor command complete */
    SPDM_STATE_KEY_EXCHANGE_DONE, /* KEY_EXCHANGE/KEY_EXCHANGE_RSP complete */
    SPDM_STATE_GIVE_PUBKEY_DONE,  /* GIVE_PUB_KEY vendor command complete */
    SPDM_STATE_CONNECTED,         /* FINISH/FINISH_RSP complete, session active */
    SPDM_STATE_ERROR              /* Error state */
} WOLFTPM2_SPDM_STATE;

/* -------------------------------------------------------------------------- */
/* SPDM Status (from GET_STS_ vendor command) */
/* -------------------------------------------------------------------------- */

typedef struct WOLFTPM2_SPDM_STATUS {
    int     spdmEnabled;      /* SPDM is enabled on the TPM */
    int     sessionActive;    /* An SPDM session is currently active */
    int     spdmOnlyLocked;   /* SPDM-only mode is locked */
    word32  fwVersion;        /* TPM firmware version */
} WOLFTPM2_SPDM_STATUS;

/* -------------------------------------------------------------------------- */
/* SPDM Backend Abstraction */
/* -------------------------------------------------------------------------- */

/* I/O callback type for SPDM backend to send/receive raw bytes over SPI.
 * This is separate from the TPM HAL callback - it sends raw SPDM-framed
 * messages (with TCG binding headers) directly over the wire. */
typedef int (*WOLFTPM2_SPDM_IoCallback)(
    struct WOLFTPM2_SPDM_CTX* ctx,
    const byte* txBuf, word32 txSz,
    byte* rxBuf, word32* rxSz,
    void* userCtx
);

/* Backend interface - implemented by libspdm or wolfSPDM.
 * Each function returns 0 on success, negative on error. */
typedef struct WOLFTPM2_SPDM_BACKEND {
    /* Initialize backend context.
     * Called once during wolfTPM2_SPDM_Init(). */
    int (*Init)(struct WOLFTPM2_SPDM_CTX* ctx,
                WOLFTPM2_SPDM_IoCallback ioCb, void* userCtx);

    /* GET_VERSION / VERSION exchange.
     * Negotiates SPDM protocol version (should select v1.3). */
    int (*GetVersion)(struct WOLFTPM2_SPDM_CTX* ctx);

    /* KEY_EXCHANGE / KEY_EXCHANGE_RSP.
     * Performs ECDHE P-384 key exchange. Responder signs transcript.
     * rspPubKey is the TPM's SPDM-Identity public key (from GET_PUB_KEY). */
    int (*KeyExchange)(struct WOLFTPM2_SPDM_CTX* ctx,
                       const byte* rspPubKey, word32 rspPubKeyLen);

    /* FINISH / FINISH_RSP.
     * Requester signs transcript + HMAC. Session is established after this.
     * reqPrivKey is the host's SPDM-Identity private key for mutual auth. */
    int (*Finish)(struct WOLFTPM2_SPDM_CTX* ctx,
                  const byte* reqPrivKey, word32 reqPrivKeyLen);

    /* Encrypt a plaintext TPM command into an SPDM secured message.
     * Applies AEAD (AES-256-GCM) encryption with session keys. */
    int (*EncryptMessage)(struct WOLFTPM2_SPDM_CTX* ctx,
                          const byte* plain, word32 plainSz,
                          byte* enc, word32* encSz);

    /* Decrypt an SPDM secured message to extract the TPM response.
     * Verifies and strips AEAD (AES-256-GCM) encryption. */
    int (*DecryptMessage)(struct WOLFTPM2_SPDM_CTX* ctx,
                          const byte* enc, word32 encSz,
                          byte* plain, word32* plainSz);

    /* End the SPDM session (END_SESSION / END_SESSION_ACK). */
    int (*EndSession)(struct WOLFTPM2_SPDM_CTX* ctx);

    /* Free backend resources. */
    void (*Cleanup)(struct WOLFTPM2_SPDM_CTX* ctx);
} WOLFTPM2_SPDM_BACKEND;

/* -------------------------------------------------------------------------- */
/* SPDM Context */
/* -------------------------------------------------------------------------- */

typedef struct WOLFTPM2_SPDM_CTX {
    /* Session state */
    WOLFTPM2_SPDM_STATE state;

    /* Session IDs */
    word16  reqSessionId;   /* Requester-chosen session ID */
    word16  rspSessionId;   /* Responder session ID (0xAEAD for Nuvoton) */
    word32  sessionId;      /* Combined: (reqSessionId << 16) | rspSessionId */

    /* Sequence numbers (monotonic, per direction) */
    word64  reqSeqNum;      /* Outgoing (host -> TPM) sequence number */
    word64  rspSeqNum;      /* Incoming (TPM -> host) sequence number */

    /* TPM's SPDM-Identity public key (ECDSA P-384, from GET_PUB_KEY) */
    byte    rspPubKey[160]; /* Full VENDOR_DEFINED_RESPONSE (137 bytes) */
    word32  rspPubKeyLen;

    /* Host's SPDM-Identity public key (ECDSA P-384) */
    byte    reqPubKey[128]; /* TPMT_PUBLIC serialized */
    word32  reqPubKeyLen;

    /* Connection handle (TCG binding, usually 0) - 4 bytes per Nuvoton spec */
    word32  connectionHandle;

    /* FIPS Service Indicator - 2 bytes per Nuvoton spec */
    word16  fipsIndicator;

    /* SPDM-only mode */
    int     spdmOnlyLocked;

    /* I/O callback for raw SPI communication */
    WOLFTPM2_SPDM_IoCallback ioCb;
    void*   ioUserCtx;

    /* Backend (libspdm or wolfSPDM) */
    WOLFTPM2_SPDM_BACKEND* backend;
    void*   backendCtx;  /* Opaque backend-specific context */

#ifndef WOLFTPM2_NO_WOLFCRYPT
    /* Native wolfCrypt crypto state for SPDM handshake.
     * Used when no external backend (libspdm/wolfSPDM) is configured. */

    /* RNG for ephemeral key generation and random data */
    WC_RNG  rng;
    int     rngInit;

    /* Ephemeral ECDHE P-384 key pair (host side) */
    ecc_key ephemeralKey;
    int     ephemeralKeyInit;

    /* ECDHE shared secret (raw X-coordinate, 48 bytes for P-384) */
    byte    sharedSecret[SPDM_ECDSA_KEY_SIZE];
    word32  sharedSecretLen;

    /* Transcript buffer - accumulates all SPDM messages for hashing.
     * The transcript hash (TH) is computed at specific points in the
     * handshake for signature verification and key derivation. */
    byte    transcript[SPDM_MAX_MSG_SIZE * 4];
    word32  transcriptLen;

    /* Random data from KEY_EXCHANGE (saved for transcript) */
    byte    reqRandom[32];    /* Requester random data */
    byte    rspRandom[32];    /* Responder random data */

    /* Session keys - handshake phase (derived after KEY_EXCHANGE_RSP) */
    byte    handshakeSecret[SPDM_HASH_SIZE];
    byte    reqHandshakeKey[SPDM_AEAD_KEY_SIZE];
    byte    rspHandshakeKey[SPDM_AEAD_KEY_SIZE];
    byte    reqHandshakeIv[SPDM_AEAD_IV_SIZE];
    byte    rspHandshakeIv[SPDM_AEAD_IV_SIZE];
    byte    reqFinishedKey[SPDM_HASH_SIZE];
    byte    rspFinishedKey[SPDM_HASH_SIZE];
    byte    th1HashNoSig[SPDM_HASH_SIZE];  /* TH1 hash from 356-byte transcript (no sig) for HMAC testing */

    /* Session keys - application phase (derived after FINISH_RSP) */
    byte    masterSecret[SPDM_HASH_SIZE];
    byte    reqDataKey[SPDM_AEAD_KEY_SIZE];
    byte    rspDataKey[SPDM_AEAD_KEY_SIZE];
    byte    reqDataIv[SPDM_AEAD_IV_SIZE];
    byte    rspDataIv[SPDM_AEAD_IV_SIZE];
#endif /* !WOLFTPM2_NO_WOLFCRYPT */

    /* Scratch buffer for message framing */
    byte    msgBuf[SPDM_MAX_MSG_SIZE];
} WOLFTPM2_SPDM_CTX;

/* -------------------------------------------------------------------------- */
/* TCG SPDM Binding Message Structures */
/* -------------------------------------------------------------------------- */

/* Clear message header (tag 0x8101) - per Nuvoton SPDM Guidance Rev 1.11
 * Layout: tag(2/BE) + size(4/BE) + connectionHandle(4/BE) +
 *         fipsIndicator(2/BE) + reserved(4) = 16 bytes total */
typedef struct SPDM_TCG_CLEAR_HDR {
    word16  tag;              /* SPDM_TAG_CLEAR (0x8101) */
    word32  size;             /* Total message size including header */
    word32  connectionHandle; /* Connection handle (0 for single connection) */
    word16  fipsIndicator;    /* SPDM_FIPS_NON_FIPS or SPDM_FIPS_APPROVED */
    word32  reserved;         /* Must be 0 */
} SPDM_TCG_CLEAR_HDR;

/* Secured message header (tag 0x8201) - per Nuvoton SPDM Guidance Rev 1.11
 * Layout: tag(2/BE) + size(4/BE) + connectionHandle(4/BE) +
 *         fipsIndicator(2/BE) + reserved(4) = 16 bytes total
 * Followed by SPDM secured record (per DSP0277, all LE):
 *   sessionId(4/LE) + seqNum(8/LE) + length(2/LE) + encData + MAC(16) */
typedef struct SPDM_TCG_SECURED_HDR {
    word16  tag;              /* SPDM_TAG_SECURED (0x8201) */
    word32  size;             /* Total message size including header */
    word32  connectionHandle; /* Connection handle */
    word16  fipsIndicator;    /* FIPS indicator */
    word32  reserved;         /* Must be 0 */
} SPDM_TCG_SECURED_HDR;

/* SPDM VENDOR_DEFINED_REQUEST header */
typedef struct SPDM_VENDOR_DEFINED_HDR {
    byte    requestResponseCode; /* SPDM_VENDOR_DEFINED_REQUEST (0xFE) */
    byte    param1;
    byte    param2;
    word16  standardId;       /* DMTF standard ID (usually 0x0001) */
    byte    vendorIdLen;      /* Length of vendor ID (0 for TCG) */
    word16  reqLength;        /* Length of vendor-defined payload */
    byte    vdCode[SPDM_VDCODE_LEN]; /* 8-byte ASCII vendor code */
} SPDM_VENDOR_DEFINED_HDR;

/* -------------------------------------------------------------------------- */
/* SPDM Core API Functions */
/* -------------------------------------------------------------------------- */

/* Initialize SPDM context and backend.
 * Must be called before any other SPDM function.
 * Returns 0 on success. */
WOLFTPM_API int wolfTPM2_SPDM_InitCtx(
    WOLFTPM2_SPDM_CTX* ctx,
    WOLFTPM2_SPDM_BACKEND* backend,
    WOLFTPM2_SPDM_IoCallback ioCb,
    void* userCtx
);

/* Enable SPDM on the TPM via NTC2_PreConfig.
 * Requires platform hierarchy authorization.
 * TPM must be reset after this for SPDM to take effect.
 * Returns 0 on success. */
WOLFTPM_API int wolfTPM2_SPDM_Enable(
    WOLFTPM2_SPDM_CTX* ctx,
    TPM2_CTX* tpmCtx
);

/* Get SPDM status from the TPM (GET_STS_ vendor command).
 * Can be called before or after session establishment.
 * Returns 0 on success. */
WOLFTPM_API int wolfTPM2_SPDM_GetStatus(
    WOLFTPM2_SPDM_CTX* ctx,
    WOLFTPM2_SPDM_STATUS* status
);

/* Get the TPM's SPDM-Identity public key (GET_PUBK vendor command).
 * This is sent as a clear (unencrypted) SPDM message before key exchange.
 * pubKey receives the serialized TPMT_PUBLIC.
 * Returns 0 on success. */
WOLFTPM_API int wolfTPM2_SPDM_GetPubKey(
    WOLFTPM2_SPDM_CTX* ctx,
    byte* pubKey, word32* pubKeySz
);

/* Establish an SPDM secure session (full handshake).
 * Performs: GET_VERSION -> GET_PUB_KEY -> KEY_EXCHANGE -> GIVE_PUB_KEY -> FINISH
 *
 * reqPubKey/reqPubKeySz: Host's ECDSA P-384 public key (TPMT_PUBLIC)
 * reqPrivKey/reqPrivKeySz: Host's ECDSA P-384 private key (for mutual auth signing)
 *
 * After success, all TPM commands sent through this context will be automatically
 * wrapped in SPDM VENDOR_DEFINED(TPM2_CMD) secured messages.
 * Returns 0 on success. */
WOLFTPM_API int wolfTPM2_SPDM_Connect(
    WOLFTPM2_SPDM_CTX* ctx,
    const byte* reqPubKey, word32 reqPubKeySz,
    const byte* reqPrivKey, word32 reqPrivKeySz
);

/* Check if an SPDM session is currently active.
 * Returns 1 if connected, 0 if not. */
WOLFTPM_API int wolfTPM2_SPDM_IsConnected(
    WOLFTPM2_SPDM_CTX* ctx
);

/* Establish an SPDM secure session using standard message flow.
 * Uses: GET_VERSION -> GET_CAPABILITIES -> NEGOTIATE_ALGORITHMS ->
 *       GET_CERTIFICATE (optional) -> KEY_EXCHANGE -> FINISH
 *
 * For use with libspdm emulator or standard SPDM responders.
 * For Nuvoton TPMs, use wolfTPM2_SPDM_Connect() instead.
 *
 * reqPrivKey/reqPrivKeySz: Host's ECDSA P-384 private key (for signing)
 * getCert: If non-zero, request responder's certificate chain
 *
 * Returns 0 on success. */
WOLFTPM_API int wolfTPM2_SPDM_ConnectStandard(
    WOLFTPM2_SPDM_CTX* ctx,
    const byte* reqPrivKey, word32 reqPrivKeySz,
    int getCert
);

/* Wrap a raw TPM command in an SPDM VENDOR_DEFINED(TPM2_CMD) secured message.
 * Used by the transport layer to intercept outgoing commands.
 * tpmCmd/tpmCmdSz: Raw TPM command bytes
 * spdmMsg/spdmMsgSz: Output buffer for the SPDM secured message
 * Returns 0 on success. */
WOLFTPM_API int wolfTPM2_SPDM_WrapCommand(
    WOLFTPM2_SPDM_CTX* ctx,
    const byte* tpmCmd, word32 tpmCmdSz,
    byte* spdmMsg, word32* spdmMsgSz
);

/* Unwrap an SPDM secured response to extract the TPM response.
 * Used by the transport layer to process incoming responses.
 * spdmMsg/spdmMsgSz: SPDM secured message bytes
 * tpmResp/tpmRespSz: Output buffer for the raw TPM response
 * Returns 0 on success. */
WOLFTPM_API int wolfTPM2_SPDM_UnwrapResponse(
    WOLFTPM2_SPDM_CTX* ctx,
    const byte* spdmMsg, word32 spdmMsgSz,
    byte* tpmResp, word32* tpmRespSz
);

/* Lock or unlock SPDM-only mode (SPDMONLY vendor command).
 * When locked, the TPM will only accept commands over SPDM.
 * lock: SPDM_ONLY_LOCK (1) to lock, SPDM_ONLY_UNLOCK (0) to unlock
 * Returns 0 on success. */
WOLFTPM_API int wolfTPM2_SPDM_SetOnlyMode(
    WOLFTPM2_SPDM_CTX* ctx,
    int lock
);

/* Disconnect the SPDM session (END_SESSION).
 * After this call, TPM commands will be sent in the clear.
 * Returns 0 on success. */
WOLFTPM_API int wolfTPM2_SPDM_Disconnect(
    WOLFTPM2_SPDM_CTX* ctx
);

/* Free all SPDM context resources.
 * Safe to call on an already-cleaned-up or zero-initialized context. */
WOLFTPM_API void wolfTPM2_SPDM_FreeCtx(
    WOLFTPM2_SPDM_CTX* ctx
);

/* -------------------------------------------------------------------------- */
/* TCG SPDM Message Framing Helpers (internal use) */
/* -------------------------------------------------------------------------- */

/* Build a TCG SPDM clear message (tag 0x8101).
 * Wraps spdmPayload in the TCG binding header format.
 * Returns total message size, or negative on error. */
WOLFTPM_API int SPDM_BuildClearMessage(
    WOLFTPM2_SPDM_CTX* ctx,
    const byte* spdmPayload, word32 spdmPayloadSz,
    byte* outBuf, word32 outBufSz
);

/* Parse a TCG SPDM clear message (tag 0x8101).
 * Extracts the SPDM payload from the TCG binding header.
 * Returns payload size, or negative on error. */
WOLFTPM_API int SPDM_ParseClearMessage(
    const byte* inBuf, word32 inBufSz,
    byte* spdmPayload, word32* spdmPayloadSz,
    SPDM_TCG_CLEAR_HDR* hdr
);

/* Build a TCG SPDM secured message (tag 0x8201).
 * Wraps encrypted payload with session ID, sequence number, and MAC.
 * Returns total message size, or negative on error. */
WOLFTPM_API int SPDM_BuildSecuredMessage(
    WOLFTPM2_SPDM_CTX* ctx,
    const byte* encPayload, word32 encPayloadSz,
    const byte* mac, word32 macSz,
    byte* outBuf, word32 outBufSz
);

/* Parse a TCG SPDM secured message (tag 0x8201).
 * Extracts session ID, sequence number, encrypted payload, and MAC.
 * Returns payload size, or negative on error. */
WOLFTPM_API int SPDM_ParseSecuredMessage(
    const byte* inBuf, word32 inBufSz,
    word32* sessionId, word64* seqNum,
    byte* encPayload, word32* encPayloadSz,
    byte* mac, word32* macSz,
    SPDM_TCG_SECURED_HDR* hdr
);

/* Build an SPDM VENDOR_DEFINED_REQUEST message with the given VdCode and payload.
 * Returns message size, or negative on error. */
WOLFTPM_API int SPDM_BuildVendorDefined(
    const char* vdCode,
    const byte* payload, word32 payloadSz,
    byte* outBuf, word32 outBufSz
);

/* Parse an SPDM VENDOR_DEFINED_RESPONSE message.
 * Extracts VdCode and payload.
 * Returns payload size, or negative on error. */
WOLFTPM_API int SPDM_ParseVendorDefined(
    const byte* inBuf, word32 inBufSz,
    char* vdCode,
    byte* payload, word32* payloadSz
);

/* -------------------------------------------------------------------------- */
/* Backend Registration */
/* -------------------------------------------------------------------------- */

/* Get the libspdm backend implementation.
 * Returns NULL if not compiled with WOLFTPM_WITH_LIBSPDM. */
WOLFTPM_API WOLFTPM2_SPDM_BACKEND* wolfTPM2_SPDM_GetLibspdmBackend(void);

/* Get the wolfSPDM backend implementation (future).
 * Returns NULL if not compiled with WOLFTPM_WITH_WOLFSPDM. */
WOLFTPM_API WOLFTPM2_SPDM_BACKEND* wolfTPM2_SPDM_GetWolfSPDMBackend(void);

/* Get the default SPDM backend (prefers wolfSPDM if available, else libspdm). */
WOLFTPM_API WOLFTPM2_SPDM_BACKEND* wolfTPM2_SPDM_GetDefaultBackend(void);

/* Get the native SPDM backend implementation (wolfCrypt-based).
 * This backend uses wolfCrypt for all cryptographic operations including
 * ECDHE key exchange, ECDSA signature verification, HKDF key derivation,
 * and AES-256-GCM encryption/decryption. Returns NULL if compiled with
 * WOLFTPM2_NO_WOLFCRYPT. */
WOLFTPM_API WOLFTPM2_SPDM_BACKEND* wolfTPM2_SPDM_GetNativeBackend(void);

/* Set the I/O callback and user context on an existing SPDM context.
 * Use this to wire the SPDM layer to the TPM transport after initialization. */
WOLFTPM_API int wolfTPM2_SPDM_SetIoCb(
    WOLFTPM2_SPDM_CTX* ctx,
    WOLFTPM2_SPDM_IoCallback ioCb,
    void* userCtx
);

/* Get the default SPDM I/O callback that sends TCG-framed messages through
 * TPM2_SendRawBytes (the same TIS FIFO used for regular TPM commands).
 * The userCtx for this callback must be a TPM2_CTX pointer. */
WOLFTPM_API WOLFTPM2_SPDM_IoCallback wolfTPM2_SPDM_GetDefaultIoCb(void);

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFTPM_SPDM */

#endif /* __TPM2_SPDM_H__ */
