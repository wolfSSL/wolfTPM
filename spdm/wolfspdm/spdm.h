/* spdm.h
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

#ifndef WOLFSPDM_SPDM_H
#define WOLFSPDM_SPDM_H

/* Include build options (WOLFSPDM_DYNAMIC_MEMORY, WOLFSPDM_NUVOTON, etc.)
 * Generated from config.h during build; installed alongside this header. */
#ifndef HAVE_CONFIG_H
    #include <wolfspdm/options.h>
#endif

#include <wolfspdm/spdm_types.h>
#include <wolfspdm/spdm_error.h>

/* Feature detection macros — external projects (e.g. wolfTPM) can check these
 * to conditionally compile against optional wolfSPDM APIs. */
#ifndef NO_WOLFSPDM_MEAS
#define WOLFSPDM_HAS_MEASUREMENTS
#endif
#ifndef NO_WOLFSPDM_CHALLENGE
#define WOLFSPDM_HAS_CHALLENGE
#endif
#define WOLFSPDM_HAS_HEARTBEAT
#define WOLFSPDM_HAS_KEY_UPDATE

#ifdef __cplusplus
extern "C" {
#endif

/* --- Protocol Mode Selection ---
 *
 * wolfSPDM supports two protocol modes:
 *
 * WOLFSPDM_MODE_STANDARD (default):
 *   Standard SPDM 1.2 protocol per DMTF DSP0274/DSP0277.
 *   Flow: GET_VERSION -> GET_CAPABILITIES -> NEGOTIATE_ALGORITHMS ->
 *         GET_DIGESTS -> GET_CERTIFICATE -> KEY_EXCHANGE -> FINISH
 *   Use with: libspdm emulator, standard SPDM responders
 *
 * WOLFSPDM_MODE_NUVOTON (requires --enable-nuvoton):
 *   Nuvoton TPM-specific protocol with TCG binding headers.
 *   Flow: GET_VERSION -> GET_PUB_KEY -> KEY_EXCHANGE -> GIVE_PUB_KEY -> FINISH
 *   Use with: Nuvoton NPCT75x TPMs (FW 7.2+) */

typedef enum {
    WOLFSPDM_MODE_STANDARD = 0,    /* Standard SPDM 1.2 (default) */
    WOLFSPDM_MODE_NUVOTON  = 1,    /* Nuvoton TCG binding + vendor commands */
} WOLFSPDM_MODE;

/* --- wolfSPDM Overview ---
 *
 * wolfSPDM is a lightweight SPDM (Security Protocol and Data Model)
 * implementation using wolfCrypt for all cryptographic operations.
 *
 * Key Features:
 *   - Requester-only (initiator) implementation
 *   - Algorithm Set B fixed: P-384/SHA-384/AES-256-GCM
 *   - Full transcript tracking for proper TH1/TH2 computation
 *   - Compatible with libspdm emulator for testing
 *   - No external dependencies beyond wolfCrypt
 *
 * Typical Usage:
 *
 *   Static (default, zero-malloc):
 *     WOLFSPDM_CTX ctx;
 *     wolfSPDM_Init(&ctx);
 *     wolfSPDM_SetIO(&ctx, callback, userPtr);
 *     wolfSPDM_Connect(&ctx);
 *     wolfSPDM_SecuredExchange(&ctx, ...);
 *     wolfSPDM_Disconnect(&ctx);
 *     wolfSPDM_Free(&ctx);
 *
 *   Dynamic (opt-in, requires --enable-dynamic-mem):
 *     ctx = wolfSPDM_New();       // Allocates and fully initializes
 *     wolfSPDM_SetIO(ctx, callback, userPtr);
 *     wolfSPDM_Connect(ctx);
 *     wolfSPDM_SecuredExchange(ctx, ...);
 *     wolfSPDM_Disconnect(ctx);
 *     wolfSPDM_Free(ctx);         // Frees the allocation
 *
 *   Note: WOLFSPDM_CTX is approximately 22KB. On embedded systems with
 *   small stacks, declare it as a static global rather than a local variable. */

/* Compile-time size for static allocation of WOLFSPDM_CTX.
 * Use this when you need a buffer large enough to hold WOLFSPDM_CTX
 * without access to the struct definition (e.g., in wolfTPM).
 * Actual struct size: ~31.3 KB (with measurements) / ~29.9 KB (NO_WOLFSPDM_MEAS).
 * Rounded up to 32 KB for platform alignment.
 * wolfSPDM_InitStatic() verifies at runtime that the provided buffer
 * is large enough; returns WOLFSPDM_E_BUFFER_SMALL if not. */
#define WOLFSPDM_CTX_STATIC_SIZE  32768  /* 32KB - fits CTX with cert validation + challenge + key update fields */

/* Forward declaration */
struct WOLFSPDM_CTX;
typedef struct WOLFSPDM_CTX WOLFSPDM_CTX;

/* Include Nuvoton support if enabled (must be after WOLFSPDM_CTX forward declaration) */
#ifdef WOLFSPDM_NUVOTON
    #include <wolfspdm/spdm_nuvoton.h>
#endif

/* --- I/O Callback ---
 *
 * The I/O callback is called by wolfSPDM to send and receive raw SPDM
 * messages. The transport layer (SPI, I2C, TCP, etc.) is handled externally.
 *
 * Parameters:
 *   ctx      - wolfSPDM context
 *   txBuf    - Data to transmit (raw SPDM message, no transport headers)
 *   txSz     - Size of transmit data
 *   rxBuf    - Buffer to receive response
 *   rxSz     - [in] Size of receive buffer, [out] Actual received size
 *   userCtx  - User context pointer from wolfSPDM_SetIO()
 *
 * Returns:
 *   0 on success, negative on error
 *
 * Notes:
 *   - For MCTP transport, the callback should handle MCTP encapsulation
 *   - For secured messages (after KEY_EXCHANGE), the callback receives
 *     already-encrypted data including the session header */
typedef int (*WOLFSPDM_IO_CB)(
    WOLFSPDM_CTX* ctx,
    const byte* txBuf, word32 txSz,
    byte* rxBuf, word32* rxSz,
    void* userCtx
);

/* --- Context Management --- */

/**
 * Initialize a wolfSPDM context for use.
 * Zeroes the context and initializes all internal state.
 * Works on stack, static, or dynamically-allocated contexts.
 * Must be called before wolfSPDM_Connect().
 *
 * Call wolfSPDM_Free() before re-initializing to avoid leaking the RNG.
 *
 * @param ctx  The wolfSPDM context.
 * @return WOLFSPDM_SUCCESS or negative error code.
 */
WOLFSPDM_API int wolfSPDM_Init(WOLFSPDM_CTX* ctx);

#ifdef WOLFSPDM_DYNAMIC_MEMORY
/**
 * Allocate and fully initialize a new wolfSPDM context.
 * No separate wolfSPDM_Init() call needed.
 * Requires --enable-dynamic-mem at configure time.
 *
 * @return Pointer to new context, or NULL on failure.
 */
WOLFSPDM_API WOLFSPDM_CTX* wolfSPDM_New(void);
#endif

/**
 * Free a wolfSPDM context and all associated resources.
 * Safe for both stack-allocated and dynamically-allocated contexts.
 * Zeroes all sensitive key material before returning.
 *
 * @param ctx  The wolfSPDM context to free.
 */
WOLFSPDM_API void wolfSPDM_Free(WOLFSPDM_CTX* ctx);

/**
 * Get the size of the WOLFSPDM_CTX structure.
 * Useful for static allocation.
 *
 * @return Size in bytes.
 */
WOLFSPDM_API int wolfSPDM_GetCtxSize(void);

/**
 * Initialize a statically-allocated context with size check.
 * Verifies the buffer is large enough, then calls wolfSPDM_Init().
 *
 * @param ctx   Pointer to pre-allocated memory of at least wolfSPDM_GetCtxSize().
 * @param size  Size of the provided buffer.
 * @return WOLFSPDM_SUCCESS or negative error code.
 */
WOLFSPDM_API int wolfSPDM_InitStatic(WOLFSPDM_CTX* ctx, int size);

/* --- Configuration --- */

/**
 * Set the I/O callback for sending/receiving SPDM messages.
 *
 * @param ctx      The wolfSPDM context.
 * @param ioCb     The I/O callback function.
 * @param userCtx  User context pointer passed to callback.
 * @return WOLFSPDM_SUCCESS or negative error code.
 */
WOLFSPDM_API int wolfSPDM_SetIO(WOLFSPDM_CTX* ctx, WOLFSPDM_IO_CB ioCb, void* userCtx);

/**
 * Set the protocol mode (standard SPDM or Nuvoton-specific).
 * Must be called before wolfSPDM_Connect().
 *
 * @param ctx   The wolfSPDM context.
 * @param mode  WOLFSPDM_MODE_STANDARD or WOLFSPDM_MODE_NUVOTON.
 * @return WOLFSPDM_SUCCESS or negative error code.
 *         Returns WOLFSPDM_E_INVALID_ARG if NUVOTON mode requested
 *         but wolfSPDM was not built with --enable-nuvoton.
 */
WOLFSPDM_API int wolfSPDM_SetMode(WOLFSPDM_CTX* ctx, WOLFSPDM_MODE mode);

/**
 * Get the current protocol mode.
 *
 * @param ctx  The wolfSPDM context.
 * @return Current mode (WOLFSPDM_MODE_STANDARD or WOLFSPDM_MODE_NUVOTON).
 */
WOLFSPDM_API WOLFSPDM_MODE wolfSPDM_GetMode(WOLFSPDM_CTX* ctx);

/**
 * Set the responder's public key for certificate-less operation.
 * Used when the responder doesn't send a certificate chain (e.g., Nuvoton TPM).
 *
 * @param ctx       The wolfSPDM context.
 * @param pubKey    Raw public key bytes (96 bytes for P-384: X||Y).
 * @param pubKeySz  Size of public key (must be 96 for P-384).
 * @return WOLFSPDM_SUCCESS or negative error code.
 */
WOLFSPDM_API int wolfSPDM_SetResponderPubKey(WOLFSPDM_CTX* ctx,
    const byte* pubKey, word32 pubKeySz);

/**
 * Set the requester's key pair for mutual authentication.
 * Optional - only needed if responder requires mutual auth.
 *
 * @param ctx        The wolfSPDM context.
 * @param privKey    Raw private key bytes (48 bytes for P-384).
 * @param privKeySz  Size of private key.
 * @param pubKey     Raw public key bytes (96 bytes for P-384: X||Y).
 * @param pubKeySz   Size of public key.
 * @return WOLFSPDM_SUCCESS or negative error code.
 */
WOLFSPDM_API int wolfSPDM_SetRequesterKeyPair(WOLFSPDM_CTX* ctx,
    const byte* privKey, word32 privKeySz,
    const byte* pubKey, word32 pubKeySz);

/* --- Session Establishment --- */

/**
 * Establish an SPDM session (full handshake).
 * Performs: GET_VERSION -> GET_CAPABILITIES -> NEGOTIATE_ALGORITHMS ->
 *           GET_DIGESTS -> GET_CERTIFICATE -> KEY_EXCHANGE -> FINISH
 *
 * After successful completion, use wolfSPDM_SecuredExchange() for
 * encrypted communication.
 *
 * @param ctx  The wolfSPDM context.
 * @return WOLFSPDM_SUCCESS or negative error code.
 */
WOLFSPDM_API int wolfSPDM_Connect(WOLFSPDM_CTX* ctx);

/**
 * Check if an SPDM session is established.
 *
 * @param ctx  The wolfSPDM context.
 * @return 1 if connected, 0 if not.
 */
WOLFSPDM_API int wolfSPDM_IsConnected(WOLFSPDM_CTX* ctx);

/**
 * End the SPDM session gracefully.
 *
 * @param ctx  The wolfSPDM context.
 * @return WOLFSPDM_SUCCESS or negative error code.
 */
WOLFSPDM_API int wolfSPDM_Disconnect(WOLFSPDM_CTX* ctx);

/* --- Individual Handshake Steps (for fine-grained control) --- */

/**
 * Send GET_VERSION and receive VERSION response.
 * First step in SPDM handshake (VCA part 1).
 *
 * @param ctx  The wolfSPDM context.
 * @return WOLFSPDM_SUCCESS or negative error code.
 */
WOLFSPDM_API int wolfSPDM_GetVersion(WOLFSPDM_CTX* ctx);

/**
 * Send GET_CAPABILITIES and receive CAPABILITIES response.
 * Second step in SPDM handshake (VCA part 2).
 *
 * @param ctx  The wolfSPDM context.
 * @return WOLFSPDM_SUCCESS or negative error code.
 */
WOLFSPDM_API int wolfSPDM_GetCapabilities(WOLFSPDM_CTX* ctx);

/**
 * Send NEGOTIATE_ALGORITHMS and receive ALGORITHMS response.
 * Third step in SPDM handshake (VCA part 3).
 *
 * @param ctx  The wolfSPDM context.
 * @return WOLFSPDM_SUCCESS or negative error code.
 */
WOLFSPDM_API int wolfSPDM_NegotiateAlgorithms(WOLFSPDM_CTX* ctx);

/**
 * Send GET_DIGESTS and receive DIGESTS response.
 *
 * @param ctx  The wolfSPDM context.
 * @return WOLFSPDM_SUCCESS or negative error code.
 */
WOLFSPDM_API int wolfSPDM_GetDigests(WOLFSPDM_CTX* ctx);

/**
 * Send GET_CERTIFICATE and receive full certificate chain.
 * May require multiple requests for large chains.
 *
 * @param ctx     The wolfSPDM context.
 * @param slotId  Certificate slot (0-7, typically 0).
 * @return WOLFSPDM_SUCCESS or negative error code.
 */
WOLFSPDM_API int wolfSPDM_GetCertificate(WOLFSPDM_CTX* ctx, int slotId);

/**
 * Send KEY_EXCHANGE and receive KEY_EXCHANGE_RSP.
 * Performs ECDHE key exchange and derives handshake keys.
 *
 * @param ctx  The wolfSPDM context.
 * @return WOLFSPDM_SUCCESS or negative error code.
 */
WOLFSPDM_API int wolfSPDM_KeyExchange(WOLFSPDM_CTX* ctx);

/**
 * Send FINISH and receive FINISH_RSP (encrypted).
 * Completes the handshake and establishes the secure session.
 *
 * @param ctx  The wolfSPDM context.
 * @return WOLFSPDM_SUCCESS or negative error code.
 */
WOLFSPDM_API int wolfSPDM_Finish(WOLFSPDM_CTX* ctx);

/* --- Secured Messaging --- */

#ifndef WOLFSPDM_LEAN
/**
 * Encrypt a message for sending over the established session.
 *
 * @param ctx       The wolfSPDM context.
 * @param plain     Plaintext message to encrypt.
 * @param plainSz   Size of plaintext.
 * @param enc       Buffer for encrypted output (includes header and tag).
 * @param encSz     [in] Size of enc buffer, [out] Actual encrypted size.
 * @return WOLFSPDM_SUCCESS or negative error code.
 */
WOLFSPDM_API int wolfSPDM_EncryptMessage(WOLFSPDM_CTX* ctx,
    const byte* plain, word32 plainSz,
    byte* enc, word32* encSz);

/**
 * Decrypt a message received over the established session.
 *
 * @param ctx       The wolfSPDM context.
 * @param enc       Encrypted message (includes header and tag).
 * @param encSz     Size of encrypted message.
 * @param plain     Buffer for decrypted output.
 * @param plainSz   [in] Size of plain buffer, [out] Actual decrypted size.
 * @return WOLFSPDM_SUCCESS or negative error code.
 */
WOLFSPDM_API int wolfSPDM_DecryptMessage(WOLFSPDM_CTX* ctx,
    const byte* enc, word32 encSz,
    byte* plain, word32* plainSz);
#endif /* !WOLFSPDM_LEAN */

/**
 * Perform a secured message exchange (encrypt, send, receive, decrypt).
 * Convenience function combining encrypt, I/O, and decrypt.
 *
 * @param ctx         The wolfSPDM context.
 * @param cmdPlain    Plaintext command to send.
 * @param cmdSz       Size of command.
 * @param rspPlain    Buffer for plaintext response.
 * @param rspSz       [in] Size of response buffer, [out] Actual response size.
 * @return WOLFSPDM_SUCCESS or negative error code.
 */
WOLFSPDM_API int wolfSPDM_SecuredExchange(WOLFSPDM_CTX* ctx,
    const byte* cmdPlain, word32 cmdSz,
    byte* rspPlain, word32* rspSz);

#ifndef NO_WOLFSPDM_MEAS
/* --- Measurements (Device Attestation) ---
 *
 * When requestSignature=1 (and NO_WOLFSPDM_MEAS_VERIFY is NOT defined):
 *   Retrieves measurements with a cryptographic signature from the responder,
 *   then verifies the signature using the responder's certificate (retrieved
 *   during wolfSPDM_Connect). Returns WOLFSPDM_SUCCESS if verification passes.
 *   Returns WOLFSPDM_E_MEAS_SIG_FAIL if the signature is invalid.
 *
 * When requestSignature=0:
 *   Retrieves measurements WITHOUT a signature.
 *   Returns WOLFSPDM_E_MEAS_NOT_VERIFIED. Measurements are informational
 *   only and should not be used for security-critical decisions.
 *
 * If compiled with NO_WOLFSPDM_MEAS_VERIFY, signature verification is
 * disabled and returns WOLFSPDM_E_MEAS_NOT_VERIFIED regardless of
 * requestSignature (signature bytes are still captured in the context).
 *
 * Contexts are NOT thread-safe; do not call from multiple threads. */

/**
 * Retrieve measurements from the SPDM responder.
 *
 * @param ctx               The wolfSPDM context.
 * @param measOperation     SPDM_MEAS_OPERATION_ALL (0xFF) or specific index.
 * @param requestSignature  1 to request signed measurements, 0 for unsigned.
 * @return WOLFSPDM_SUCCESS (verified), WOLFSPDM_E_MEAS_NOT_VERIFIED (unsigned),
 *         WOLFSPDM_E_MEAS_SIG_FAIL (sig invalid), or negative error code.
 */
WOLFSPDM_API int wolfSPDM_GetMeasurements(WOLFSPDM_CTX* ctx, byte measOperation,
    int requestSignature);

/**
 * Get the number of measurement blocks retrieved.
 *
 * @param ctx  The wolfSPDM context.
 * @return Number of measurement blocks, or 0 if none.
 */
WOLFSPDM_API int wolfSPDM_GetMeasurementCount(WOLFSPDM_CTX* ctx);

/**
 * Get a specific measurement block by index.
 *
 * @param ctx        The wolfSPDM context.
 * @param blockIdx   Index into retrieved blocks (0-based).
 * @param measIndex  [out] SPDM measurement index (1-based).
 * @param measType   [out] DMTFSpecMeasurementValueType.
 * @param value      [out] Buffer for measurement value.
 * @param valueSz    [in] Size of value buffer, [out] Actual value size.
 * @return WOLFSPDM_SUCCESS or negative error code.
 */
WOLFSPDM_API int wolfSPDM_GetMeasurementBlock(WOLFSPDM_CTX* ctx, int blockIdx,
    byte* measIndex, byte* measType, byte* value, word32* valueSz);
#endif /* !NO_WOLFSPDM_MEAS */

#ifndef WOLFSPDM_LEAN
/* --- Application Data Transfer ---
 *
 * Send/receive application data over an established SPDM session.
 * Max payload per call: WOLFSPDM_MAX_MSG_SIZE minus AEAD overhead (~4000 bytes).
 * These are message-oriented (no partial reads/writes).
 * Contexts are NOT thread-safe; do not call from multiple threads. */

/**
 * Send application data over an established SPDM session.
 *
 * @param ctx     The wolfSPDM context (must be connected).
 * @param data    Data to send.
 * @param dataSz  Size of data.
 * @return WOLFSPDM_SUCCESS or negative error code.
 */
WOLFSPDM_API int wolfSPDM_SendData(WOLFSPDM_CTX* ctx, const byte* data, word32 dataSz);

/**
 * Receive application data over an established SPDM session.
 *
 * @param ctx     The wolfSPDM context (must be connected).
 * @param data    Buffer for received data.
 * @param dataSz  [in] Size of buffer, [out] Actual data size.
 * @return WOLFSPDM_SUCCESS or negative error code.
 */
WOLFSPDM_API int wolfSPDM_ReceiveData(WOLFSPDM_CTX* ctx, byte* data, word32* dataSz);
#endif /* !WOLFSPDM_LEAN */

/* --- Session Information --- */

/**
 * Get the current session ID.
 *
 * @param ctx  The wolfSPDM context.
 * @return Session ID (combined reqSessionId | rspSessionId << 16), or 0 if not connected.
 */
WOLFSPDM_API word32 wolfSPDM_GetSessionId(WOLFSPDM_CTX* ctx);

/**
 * Get negotiated SPDM version.
 *
 * @param ctx  The wolfSPDM context.
 * @return Version (e.g., 0x12 for SPDM 1.2), or 0 if not negotiated.
 */
WOLFSPDM_API byte wolfSPDM_GetNegotiatedVersion(WOLFSPDM_CTX* ctx);

#ifdef WOLFSPDM_NUVOTON
/**
 * Get the connection handle (Nuvoton TCG binding).
 *
 * @param ctx  The wolfSPDM context.
 * @return Connection handle value.
 */
WOLFSPDM_API word32 wolfSPDM_GetConnectionHandle(WOLFSPDM_CTX* ctx);

/**
 * Get the FIPS indicator (Nuvoton TCG binding).
 *
 * @param ctx  The wolfSPDM context.
 * @return FIPS indicator value.
 */
WOLFSPDM_API word16 wolfSPDM_GetFipsIndicator(WOLFSPDM_CTX* ctx);
#endif

/* --- Certificate Chain Validation --- */

/**
 * Load trusted root CA certificates for certificate chain validation.
 * When set, wolfSPDM_Connect() will validate the responder's certificate
 * chain against these CAs. Without this, only the public key is extracted.
 *
 * @param ctx         The wolfSPDM context.
 * @param derCerts    DER-encoded CA certificate(s) (concatenated if multiple).
 * @param derCertsSz  Size of DER certificate data.
 * @return WOLFSPDM_SUCCESS or negative error code.
 */
WOLFSPDM_API int wolfSPDM_SetTrustedCAs(WOLFSPDM_CTX* ctx, const byte* derCerts,
    word32 derCertsSz);

#ifndef NO_WOLFSPDM_CHALLENGE
/* --- Challenge Authentication (Sessionless Attestation) --- */

/**
 * Perform CHALLENGE/CHALLENGE_AUTH exchange for sessionless attestation.
 * Requires state >= WOLFSPDM_STATE_CERT (cert chain must be retrieved).
 * Typical flow: GET_VERSION -> GET_CAPS -> NEGOTIATE_ALGO -> GET_DIGESTS
 *   -> GET_CERTIFICATE -> CHALLENGE
 *
 * @param ctx            The wolfSPDM context.
 * @param slotId         Certificate slot (0-7, typically 0).
 * @param measHashType   Measurement summary hash type:
 *                       SPDM_MEAS_SUMMARY_HASH_NONE (0x00),
 *                       SPDM_MEAS_SUMMARY_HASH_TCB (0x01), or
 *                       SPDM_MEAS_SUMMARY_HASH_ALL (0xFF).
 * @return WOLFSPDM_SUCCESS or negative error code.
 */
WOLFSPDM_API int wolfSPDM_Challenge(WOLFSPDM_CTX* ctx, int slotId, byte measHashType);
#endif /* !NO_WOLFSPDM_CHALLENGE */

/* --- Session Keep-Alive --- */

/**
 * Send HEARTBEAT and receive HEARTBEAT_ACK.
 * Must be in an established session (CONNECTED or MEASURED state).
 * Sent over the encrypted channel.
 *
 * @param ctx  The wolfSPDM context.
 * @return WOLFSPDM_SUCCESS or negative error code.
 */
WOLFSPDM_API int wolfSPDM_Heartbeat(WOLFSPDM_CTX* ctx);

/* --- Key Update (Session Key Rotation) --- */

/**
 * Perform KEY_UPDATE to rotate session encryption keys.
 * Must be in an established session (CONNECTED or MEASURED state).
 * Follows up with VERIFY_NEW_KEY to confirm the new keys work.
 *
 * @param ctx        The wolfSPDM context.
 * @param updateAll  0 = rotate requester key only,
 *                   1 = rotate both requester and responder keys.
 * @return WOLFSPDM_SUCCESS or negative error code.
 */
WOLFSPDM_API int wolfSPDM_KeyUpdate(WOLFSPDM_CTX* ctx, int updateAll);

/* --- Debug/Utility --- */

/**
 * Enable or disable debug output.
 *
 * @param ctx    The wolfSPDM context.
 * @param enable Non-zero to enable, 0 to disable.
 */
WOLFSPDM_API void wolfSPDM_SetDebug(WOLFSPDM_CTX* ctx, int enable);

#ifdef __cplusplus
}
#endif

#endif /* WOLFSPDM_SPDM_H */
