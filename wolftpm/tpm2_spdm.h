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
 * between host and TPM using the wolfSPDM library for all protocol operations.
 *
 * References:
 * - DMTF DSP0274 (SPDM v1.2/1.3)
 * - TCG SPDM Binding for Secure Communication v1.0
 * - TCG TPM 2.0 Library Specification v1.84
 *
 * Architecture:
 *   Application -> wolfTPM2 Wrapper -> SPDM Transport (this module) -> SPI HAL
 *                                            |
 *                                      wolfSPDM library
 *                                      (all SPDM protocol logic)
 *
 * wolfTPM provides:
 * - Thin wrapper APIs that call wolfSPDM functions
 * - TPM-specific SPDM enable via NTC2 vendor commands
 * - I/O callback adapter to route wolfSPDM through TPM transport
 *
 * wolfSPDM provides:
 * - Full SPDM protocol implementation (handshake, key derivation, encryption)
 * - Standard and Nuvoton mode support
 * - TCG binding message framing (for Nuvoton TPMs)
 * - All cryptographic operations
 */

#ifndef __TPM2_SPDM_H__
#define __TPM2_SPDM_H__

#include <wolftpm/tpm2.h>

#ifdef WOLFTPM_SPDM

/* wolfSPDM library provides all SPDM protocol implementation */
#include <wolfspdm/spdm.h>

#ifdef __cplusplus
    extern "C" {
#endif

/* Forward declarations */
struct WOLFTPM2_SPDM_CTX;

/* -------------------------------------------------------------------------- */
/* SPDM Context
 *
 * This is a thin wrapper around WOLFSPDM_CTX. wolfSPDM handles all the
 * SPDM protocol state, key derivation, and encryption. This context adds
 * only TPM-specific fields needed for integration with wolfTPM2.
 * -------------------------------------------------------------------------- */

typedef struct WOLFTPM2_SPDM_CTX {
    /* wolfSPDM context - handles all SPDM protocol operations */
    WOLFSPDM_CTX* spdmCtx;

    /* Reference to TPM context for NTC2 vendor commands */
    TPM2_CTX* tpmCtx;

    /* SPDM-only mode tracking (for Nuvoton TPMs) */
    int spdmOnlyLocked;

#ifndef WOLFSPDM_DYNAMIC_MEMORY
    /* Inline buffer for static wolfSPDM context (zero-malloc mode) */
    byte spdmBuf[WOLFSPDM_CTX_STATIC_SIZE];
#endif
} WOLFTPM2_SPDM_CTX;

/* -------------------------------------------------------------------------- */
/* SPDM Core API Functions
 *
 * These are thin wrappers around wolfSPDM functions. All protocol logic
 * is implemented in wolfSPDM.
 * -------------------------------------------------------------------------- */

/**
 * Initialize SPDM context with wolfSPDM.
 * Must be called before any other SPDM function.
 *
 * @param ctx       wolfTPM2 SPDM context
 * @param ioCb      I/O callback for sending/receiving SPDM messages
 * @param userCtx   User context passed to the I/O callback
 * @return 0 on success, negative on error
 */
WOLFTPM_API int wolfTPM2_SPDM_InitCtx(
    WOLFTPM2_SPDM_CTX* ctx,
    WOLFSPDM_IO_CB ioCb,
    void* userCtx
);

/**
 * Set the TPM context for NTC2 vendor commands.
 * Only needed for Nuvoton TPMs when using wolfTPM2_SPDM_Enable().
 *
 * @param ctx       wolfTPM2 SPDM context
 * @param tpmCtx    TPM2 context
 * @return 0 on success, negative on error
 */
WOLFTPM_API int wolfTPM2_SPDM_SetTPMCtx(
    WOLFTPM2_SPDM_CTX* ctx,
    TPM2_CTX* tpmCtx
);

/**
 * Enable SPDM on the TPM via NTC2_PreConfig.
 * Requires platform hierarchy authorization.
 * TPM must be reset after this for SPDM to take effect.
 * NOTE: This is a Nuvoton-specific feature.
 *
 * @param ctx       wolfTPM2 SPDM context
 * @return 0 on success, negative on error
 */
WOLFTPM_API int wolfTPM2_SPDM_Enable(
    WOLFTPM2_SPDM_CTX* ctx
);

/**
 * Establish an SPDM secure session using standard message flow.
 * Uses: GET_VERSION -> GET_CAPABILITIES -> NEGOTIATE_ALGORITHMS ->
 *       GET_DIGESTS -> GET_CERTIFICATE (optional) -> KEY_EXCHANGE -> FINISH
 *
 * For use with libspdm emulator or standard SPDM responders.
 *
 * @param ctx       wolfTPM2 SPDM context
 * @return 0 on success, negative on error
 */
WOLFTPM_API int wolfTPM2_SPDM_Connect(
    WOLFTPM2_SPDM_CTX* ctx
);

/**
 * Check if an SPDM session is currently active.
 *
 * @param ctx       wolfTPM2 SPDM context
 * @return 1 if connected, 0 if not
 */
WOLFTPM_API int wolfTPM2_SPDM_IsConnected(
    WOLFTPM2_SPDM_CTX* ctx
);

/**
 * Get the current session ID.
 *
 * @param ctx       wolfTPM2 SPDM context
 * @return Session ID, or 0 if not connected
 */
WOLFTPM_API word32 wolfTPM2_SPDM_GetSessionId(
    WOLFTPM2_SPDM_CTX* ctx
);

/**
 * Perform a secured message exchange (encrypt, send, receive, decrypt).
 * Wraps wolfSPDM_SecuredExchange() for TPM command/response.
 *
 * @param ctx       wolfTPM2 SPDM context
 * @param cmdPlain  Plaintext command to send
 * @param cmdSz     Size of command
 * @param rspPlain  Buffer for plaintext response
 * @param rspSz     [in] Size of response buffer, [out] Actual response size
 * @return 0 on success, negative on error
 */
WOLFTPM_API int wolfTPM2_SPDM_SecuredExchange(
    WOLFTPM2_SPDM_CTX* ctx,
    const byte* cmdPlain, word32 cmdSz,
    byte* rspPlain, word32* rspSz
);

/**
 * Disconnect the SPDM session (END_SESSION).
 * After this call, TPM commands will be sent in the clear.
 *
 * @param ctx       wolfTPM2 SPDM context
 * @return 0 on success, negative on error
 */
WOLFTPM_API int wolfTPM2_SPDM_Disconnect(
    WOLFTPM2_SPDM_CTX* ctx
);

/**
 * Free all SPDM context resources.
 * Safe to call on an already-cleaned-up or zero-initialized context.
 *
 * @param ctx       wolfTPM2 SPDM context
 */
WOLFTPM_API void wolfTPM2_SPDM_FreeCtx(
    WOLFTPM2_SPDM_CTX* ctx
);

/* -------------------------------------------------------------------------- */
/* Nuvoton-Specific Functions (requires wolfSPDM with --enable-nuvoton)
 * -------------------------------------------------------------------------- */

#ifdef WOLFSPDM_NUVOTON

/**
 * Set Nuvoton mode and configure for Nuvoton TPM handshake.
 * Must be called before wolfTPM2_SPDM_Connect() for Nuvoton TPMs.
 *
 * @param ctx       wolfTPM2 SPDM context
 * @return 0 on success, negative on error
 */
WOLFTPM_API int wolfTPM2_SPDM_SetNuvotonMode(
    WOLFTPM2_SPDM_CTX* ctx
);

/**
 * Get SPDM status from the TPM (GET_STS_ vendor command).
 * Wraps wolfSPDM_Nuvoton_GetStatus().
 *
 * @param ctx       wolfTPM2 SPDM context
 * @param status    Receives SPDM status information
 * @return 0 on success, negative on error
 */
WOLFTPM_API int wolfTPM2_SPDM_GetStatus(
    WOLFTPM2_SPDM_CTX* ctx,
    WOLFSPDM_NUVOTON_STATUS* status
);

/**
 * Get the TPM's SPDM-Identity public key (GET_PUBK vendor command).
 * Wraps wolfSPDM_Nuvoton_GetPubKey().
 *
 * @param ctx       wolfTPM2 SPDM context
 * @param pubKey    Output buffer for public key (raw X||Y, 96 bytes for P-384)
 * @param pubKeySz  [in] Size of buffer, [out] Actual key size
 * @return 0 on success, negative on error
 */
WOLFTPM_API int wolfTPM2_SPDM_GetPubKey(
    WOLFTPM2_SPDM_CTX* ctx,
    byte* pubKey, word32* pubKeySz
);

/**
 * Lock or unlock SPDM-only mode (SPDMONLY vendor command).
 * When locked, the TPM only accepts commands over SPDM.
 * Wraps wolfSPDM_Nuvoton_SetOnlyMode().
 *
 * @param ctx       wolfTPM2 SPDM context
 * @param lock      WOLFSPDM_SPDMONLY_LOCK (1) or WOLFSPDM_SPDMONLY_UNLOCK (0)
 * @return 0 on success, negative on error
 */
WOLFTPM_API int wolfTPM2_SPDM_SetOnlyMode(
    WOLFTPM2_SPDM_CTX* ctx,
    int lock
);

/**
 * Set the requester's SPDM-Identity public key in TPMT_PUBLIC format.
 * Required for GIVE_PUB step in Nuvoton handshake.
 * Wraps wolfSPDM_SetRequesterKeyTPMT().
 *
 * @param ctx       wolfTPM2 SPDM context
 * @param tpmtPub   Public key in TPMT_PUBLIC format (~120 bytes for P-384)
 * @param tpmtPubSz Size of TPMT_PUBLIC
 * @return 0 on success, negative on error
 */
WOLFTPM_API int wolfTPM2_SPDM_SetRequesterKeyTPMT(
    WOLFTPM2_SPDM_CTX* ctx,
    const byte* tpmtPub, word32 tpmtPubSz
);

#endif /* WOLFSPDM_NUVOTON */

/* -------------------------------------------------------------------------- */
/* Configuration Helpers
 * -------------------------------------------------------------------------- */

/**
 * Set the I/O callback and user context on an existing SPDM context.
 * Wraps wolfSPDM_SetIO().
 *
 * @param ctx       wolfTPM2 SPDM context
 * @param ioCb      I/O callback function
 * @param userCtx   User context passed to callback
 * @return 0 on success, negative on error
 */
WOLFTPM_API int wolfTPM2_SPDM_SetIoCb(
    WOLFTPM2_SPDM_CTX* ctx,
    WOLFSPDM_IO_CB ioCb,
    void* userCtx
);

/**
 * Set the requester's key pair for mutual authentication.
 * Wraps wolfSPDM_SetRequesterKeyPair().
 *
 * @param ctx        wolfTPM2 SPDM context
 * @param privKey    Raw private key bytes (48 bytes for P-384)
 * @param privKeySz  Size of private key
 * @param pubKey     Raw public key bytes (96 bytes for P-384: X||Y)
 * @param pubKeySz   Size of public key
 * @return 0 on success, negative on error
 */
WOLFTPM_API int wolfTPM2_SPDM_SetRequesterKeyPair(
    WOLFTPM2_SPDM_CTX* ctx,
    const byte* privKey, word32 privKeySz,
    const byte* pubKey, word32 pubKeySz
);

/**
 * Enable or disable debug output.
 * Wraps wolfSPDM_SetDebug().
 *
 * @param ctx       wolfTPM2 SPDM context
 * @param enable    Non-zero to enable, 0 to disable
 */
WOLFTPM_API void wolfTPM2_SPDM_SetDebug(
    WOLFTPM2_SPDM_CTX* ctx,
    int enable
);

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFTPM_SPDM */

#endif /* __TPM2_SPDM_H__ */
