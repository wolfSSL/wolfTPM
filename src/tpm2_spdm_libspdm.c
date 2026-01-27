/* tpm2_spdm_libspdm.c
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

/* libspdm Backend for wolfTPM SPDM Support
 *
 * This file implements the WOLFTPM2_SPDM_BACKEND interface using the
 * DMTF libspdm library (requester side). libspdm v4.0.0.
 *
 * REPLACEABLE: To swap libspdm for wolfSPDM, create tpm2_spdm_wolfspdm.c
 * implementing the same WOLFTPM2_SPDM_BACKEND function pointer interface
 * and link it instead of this file. No other files need to change.
 *
 * The public interface is defined in wolftpm/tpm2_spdm.h:
 *   - WOLFTPM2_SPDM_BACKEND struct with Init/GetVersion/KeyExchange/Finish/
 *     EncryptMessage/DecryptMessage/EndSession/Cleanup function pointers
 *   - All types used are wolfTPM types (byte, word32, etc.) - no libspdm
 *     types leak into the public API
 *
 * Configuration for Nuvoton NPCT75x:
 *   - Algorithm Set B: ECDSA P-384, SHA-384, ECDHE P-384, AES-256-GCM
 *   - Mutual authentication (MUT_AUTH_CAP)
 *   - Single connection (0), single session (0xAEAD RspSessionID)
 *   - No GET_CAPABILITIES or NEGOTIATE_ALGORITHMS (Nuvoton skips these)
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_spdm.h>

#if defined(WOLFTPM_SPDM) && defined(WOLFTPM_WITH_LIBSPDM)

/* libspdm headers - ALL libspdm-specific includes are confined to this file */
#include <industry_standard/spdm.h>
#include <library/spdm_common_lib.h>
#include <library/spdm_requester_lib.h>
#include <library/spdm_secured_message_lib.h>
#include <library/spdm_return_status.h>

/* -------------------------------------------------------------------------- */
/* Constants */
/* -------------------------------------------------------------------------- */

/* TCG SPDM transport header/tail sizes for buffer allocation.
 * TCG binding header: tag(2) + size(4) + connHandle(2) + fips(1) + rsvd(1) = 10
 * No tail beyond what the SPDM secured message itself includes. */
#define TCG_SPDM_TRANSPORT_HEADER_SIZE  10
#define TCG_SPDM_TRANSPORT_TAIL_SIZE    0

/* Max SPDM message size we support (same as SPDM_MAX_MSG_SIZE from tpm2.h) */
#ifndef LIBSPDM_MAX_SPDM_MSG_SIZE_LOCAL
#define LIBSPDM_MAX_SPDM_MSG_SIZE_LOCAL SPDM_MAX_MSG_SIZE
#endif

/* Buffer sizes for sender/receiver */
#define SPDM_SENDER_BUFFER_SIZE   SPDM_MAX_MSG_SIZE
#define SPDM_RECEIVER_BUFFER_SIZE SPDM_MAX_MSG_SIZE

/* -------------------------------------------------------------------------- */
/* libspdm Backend Context (opaque, stored in WOLFTPM2_SPDM_CTX.backendCtx) */
/* -------------------------------------------------------------------------- */

typedef struct {
    void*   spdmContext;        /* libspdm context pointer */
    size_t  spdmContextSize;    /* allocated size */
    void*   scratchBuffer;      /* libspdm scratch buffer */
    size_t  scratchBufferSize;

    /* Sender/receiver buffers (libspdm v4 requires these) */
    byte    senderBuffer[SPDM_SENDER_BUFFER_SIZE];
    byte    receiverBuffer[SPDM_RECEIVER_BUFFER_SIZE];

    /* I/O callback for SPI transport */
    WOLFTPM2_SPDM_IoCallback ioCb;
    void*   ioUserCtx;

    /* Parent SPDM context reference */
    WOLFTPM2_SPDM_CTX* parentCtx;

    /* Session ID returned by libspdm_start_session */
    uint32_t sessionId;
} LIBSPDM_BACKEND_CTX;

/* -------------------------------------------------------------------------- */
/* libspdm Buffer Management Callbacks */
/* -------------------------------------------------------------------------- */

static libspdm_return_t spdm_acquire_sender_buffer(
    void* spdm_context, void** msg_buf_ptr)
{
    LIBSPDM_BACKEND_CTX* bctx;
    libspdm_data_parameter_t param;
    void* appCtx = NULL;
    size_t dataSize = sizeof(void*);

    XMEMSET(&param, 0, sizeof(param));
    param.location = LIBSPDM_DATA_LOCATION_LOCAL;
    libspdm_get_data(spdm_context, LIBSPDM_DATA_APP_CONTEXT_DATA,
        &param, &appCtx, &dataSize);
    bctx = (LIBSPDM_BACKEND_CTX*)appCtx;
    if (bctx == NULL) {
        return LIBSPDM_STATUS_SEND_FAIL;
    }
    *msg_buf_ptr = bctx->senderBuffer;
    return LIBSPDM_STATUS_SUCCESS;
}

static void spdm_release_sender_buffer(
    void* spdm_context, const void* msg_buf_ptr)
{
    (void)spdm_context;
    (void)msg_buf_ptr;
    /* Static buffer, nothing to release */
}

static libspdm_return_t spdm_acquire_receiver_buffer(
    void* spdm_context, void** msg_buf_ptr)
{
    LIBSPDM_BACKEND_CTX* bctx;
    libspdm_data_parameter_t param;
    void* appCtx = NULL;
    size_t dataSize = sizeof(void*);

    XMEMSET(&param, 0, sizeof(param));
    param.location = LIBSPDM_DATA_LOCATION_LOCAL;
    libspdm_get_data(spdm_context, LIBSPDM_DATA_APP_CONTEXT_DATA,
        &param, &appCtx, &dataSize);
    bctx = (LIBSPDM_BACKEND_CTX*)appCtx;
    if (bctx == NULL) {
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }
    *msg_buf_ptr = bctx->receiverBuffer;
    return LIBSPDM_STATUS_SUCCESS;
}

static void spdm_release_receiver_buffer(
    void* spdm_context, const void* msg_buf_ptr)
{
    (void)spdm_context;
    (void)msg_buf_ptr;
    /* Static buffer, nothing to release */
}

/* -------------------------------------------------------------------------- */
/* libspdm Device I/O Callbacks */
/* -------------------------------------------------------------------------- */

/* Send SPDM message over SPI via wolfTPM's I/O callback.
 * libspdm calls this to send raw SPDM messages. We wrap them in the
 * TCG SPDM binding format before sending over SPI. */
static libspdm_return_t spdm_device_send_message(
    void* spdm_context,
    size_t request_size,
    const void* request,
    uint64_t timeout)
{
    LIBSPDM_BACKEND_CTX* bctx;
    WOLFTPM2_SPDM_CTX* ctx;
    libspdm_data_parameter_t param;
    void* appCtx = NULL;
    size_t dataSize = sizeof(void*);
    byte tcgMsg[SPDM_MAX_MSG_SIZE];
    int tcgMsgSz;
    byte rxBuf[SPDM_MAX_MSG_SIZE];
    word32 rxSz;
    int rc;

    (void)timeout;

    /* Get our backend context via libspdm's app context data */
    XMEMSET(&param, 0, sizeof(param));
    param.location = LIBSPDM_DATA_LOCATION_LOCAL;
    libspdm_get_data(spdm_context, LIBSPDM_DATA_APP_CONTEXT_DATA,
        &param, &appCtx, &dataSize);
    bctx = (LIBSPDM_BACKEND_CTX*)appCtx;
    if (bctx == NULL || bctx->parentCtx == NULL) {
        return LIBSPDM_STATUS_SEND_FAIL;
    }

    ctx = bctx->parentCtx;

    /* Wrap SPDM message in TCG binding clear message format */
    tcgMsgSz = SPDM_BuildClearMessage(ctx,
        (const byte*)request, (word32)request_size,
        tcgMsg, sizeof(tcgMsg));
    if (tcgMsgSz < 0) {
        return LIBSPDM_STATUS_SEND_FAIL;
    }

    /* Send via I/O callback */
    if (bctx->ioCb == NULL) {
        return LIBSPDM_STATUS_SEND_FAIL;
    }

    rxSz = sizeof(rxBuf);
    rc = bctx->ioCb(ctx, tcgMsg, (word32)tcgMsgSz, rxBuf, &rxSz,
        bctx->ioUserCtx);
    if (rc != 0) {
        return LIBSPDM_STATUS_SEND_FAIL;
    }

    /* Response is stored in receiver buffer for the receive callback.
     * For SPI transport, send and receive happen in one transaction. */
    if (rxSz > 0 && rxSz <= SPDM_RECEIVER_BUFFER_SIZE) {
        XMEMCPY(bctx->receiverBuffer, rxBuf, rxSz);
    }

    return LIBSPDM_STATUS_SUCCESS;
}

/* Receive SPDM message over SPI.
 * For SPI-based TPMs, the response was already received synchronously
 * in the send callback and stored in the receiver buffer. */
static libspdm_return_t spdm_device_receive_message(
    void* spdm_context,
    size_t* response_size,
    void** response,
    uint64_t timeout)
{
    LIBSPDM_BACKEND_CTX* bctx;
    libspdm_data_parameter_t param;
    void* appCtx = NULL;
    size_t dataSize = sizeof(void*);

    (void)timeout;

    XMEMSET(&param, 0, sizeof(param));
    param.location = LIBSPDM_DATA_LOCATION_LOCAL;
    libspdm_get_data(spdm_context, LIBSPDM_DATA_APP_CONTEXT_DATA,
        &param, &appCtx, &dataSize);
    bctx = (LIBSPDM_BACKEND_CTX*)appCtx;
    if (bctx == NULL) {
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }

    /* Response was stored in receiver buffer by the send callback */
    *response = bctx->receiverBuffer;
    *response_size = SPDM_RECEIVER_BUFFER_SIZE; /* libspdm will parse actual size */

    return LIBSPDM_STATUS_SUCCESS;
}

/* -------------------------------------------------------------------------- */
/* TCG SPDM Custom Transport Encode/Decode */
/* -------------------------------------------------------------------------- */

/* We implement our own transport encode/decode since the TCG SPDM binding
 * format is different from MCTP/PCI-DOE/TCP. These callbacks are registered
 * with libspdm via libspdm_register_transport_layer_func(). */

/* Encode: libspdm gives us an SPDM message, we pass it through.
 * The actual TCG framing is done in the device_send_message callback. */
static libspdm_return_t spdm_transport_tcg_encode_message(
    void* spdm_context,
    const uint32_t* session_id,
    bool is_app_message,
    bool is_request_message,
    size_t message_size,
    void* message,
    size_t* transport_message_size,
    void** transport_message)
{
    (void)spdm_context;
    (void)session_id;
    (void)is_app_message;
    (void)is_request_message;

    /* Pass-through: TCG framing is handled at the device I/O layer.
     * libspdm's message is already the SPDM payload we need. */
    *transport_message = message;
    *transport_message_size = message_size;
    return LIBSPDM_STATUS_SUCCESS;
}

/* Decode: we receive a transport message and extract the SPDM payload.
 * The actual TCG unframing is done in the device_receive_message callback. */
static libspdm_return_t spdm_transport_tcg_decode_message(
    void* spdm_context,
    uint32_t** session_id,
    bool* is_app_message,
    bool is_request_message,
    size_t transport_message_size,
    void* transport_message,
    size_t* message_size,
    void** message)
{
    (void)spdm_context;
    (void)is_request_message;

    /* Pass-through: TCG unframing is handled at the device I/O layer. */
    *session_id = NULL;     /* Non-secured for clear messages */
    *is_app_message = false;
    *message = transport_message;
    *message_size = transport_message_size;
    return LIBSPDM_STATUS_SUCCESS;
}

/* -------------------------------------------------------------------------- */
/* Secured Message Callbacks for TCG Transport */
/* -------------------------------------------------------------------------- */

/* TCG SPDM binding uses 8-byte sequence numbers */
static uint8_t spdm_tcg_get_sequence_number(
    uint64_t sequence_number, uint8_t* sequence_number_buffer)
{
    /* TCG binding: 8-byte sequence number in big-endian */
    sequence_number_buffer[0] = (uint8_t)(sequence_number >> 56);
    sequence_number_buffer[1] = (uint8_t)(sequence_number >> 48);
    sequence_number_buffer[2] = (uint8_t)(sequence_number >> 40);
    sequence_number_buffer[3] = (uint8_t)(sequence_number >> 32);
    sequence_number_buffer[4] = (uint8_t)(sequence_number >> 24);
    sequence_number_buffer[5] = (uint8_t)(sequence_number >> 16);
    sequence_number_buffer[6] = (uint8_t)(sequence_number >> 8);
    sequence_number_buffer[7] = (uint8_t)(sequence_number);
    return 8; /* 8 bytes */
}

static uint32_t spdm_tcg_get_max_random_number_count(void)
{
    return 0; /* TCG binding does not use random padding */
}

static spdm_version_number_t spdm_tcg_get_secured_spdm_version(
    spdm_version_number_t secured_message_version)
{
    /* Return the negotiated version as-is for TCG binding */
    return secured_message_version;
}

/* -------------------------------------------------------------------------- */
/* Backend Function: Init */
/* -------------------------------------------------------------------------- */

static int libspdm_backend_init(
    WOLFTPM2_SPDM_CTX* ctx,
    WOLFTPM2_SPDM_IoCallback ioCb,
    void* userCtx)
{
    LIBSPDM_BACKEND_CTX* bctx;
    void* spdmContext;
    size_t spdmContextSize;
    size_t scratchSize;
    libspdm_data_parameter_t parameter;
    uint8_t data8;
    uint16_t data16;
    uint32_t data32;
    void* appCtxPtr;

    if (ctx == NULL) {
        return BAD_FUNC_ARG;
    }

    /* Allocate backend context */
    bctx = (LIBSPDM_BACKEND_CTX*)XMALLOC(sizeof(LIBSPDM_BACKEND_CTX),
        NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (bctx == NULL) {
        return MEMORY_E;
    }
    XMEMSET(bctx, 0, sizeof(*bctx));

    bctx->ioCb = ioCb;
    bctx->ioUserCtx = userCtx;
    bctx->parentCtx = ctx;

    /* Get libspdm context size and allocate */
    spdmContextSize = libspdm_get_context_size();
    spdmContext = XMALLOC(spdmContextSize, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (spdmContext == NULL) {
        XFREE(bctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return MEMORY_E;
    }

    /* Initialize libspdm context */
    libspdm_init_context(spdmContext);

    /* Register device I/O callbacks */
    libspdm_register_device_io_func(spdmContext,
        spdm_device_send_message,
        spdm_device_receive_message);

    /* Register buffer management callbacks (required in libspdm v4) */
    libspdm_register_device_buffer_func(spdmContext,
        SPDM_SENDER_BUFFER_SIZE,
        SPDM_RECEIVER_BUFFER_SIZE,
        spdm_acquire_sender_buffer,
        spdm_release_sender_buffer,
        spdm_acquire_receiver_buffer,
        spdm_release_receiver_buffer);

    /* Register custom TCG transport layer (pass-through - we handle
     * TCG framing in the device I/O callbacks instead) */
    libspdm_register_transport_layer_func(spdmContext,
        LIBSPDM_MAX_SPDM_MSG_SIZE_LOCAL,
        TCG_SPDM_TRANSPORT_HEADER_SIZE,
        TCG_SPDM_TRANSPORT_TAIL_SIZE,
        spdm_transport_tcg_encode_message,
        spdm_transport_tcg_decode_message);

    /* Set app context so callbacks can find our backend context */
    XMEMSET(&parameter, 0, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
    appCtxPtr = (void*)bctx;
    libspdm_set_data(spdmContext, LIBSPDM_DATA_APP_CONTEXT_DATA,
        &parameter, &appCtxPtr, sizeof(void*));

    /* Allocate scratch buffer (required by libspdm) */
    scratchSize = libspdm_get_sizeof_required_scratch_buffer(spdmContext);
    bctx->scratchBuffer = XMALLOC(scratchSize, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (bctx->scratchBuffer == NULL) {
        XFREE(spdmContext, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(bctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return MEMORY_E;
    }
    bctx->scratchBufferSize = scratchSize;
    libspdm_set_scratch_buffer(spdmContext, bctx->scratchBuffer, scratchSize);

    /* ------------------------------------------------------------------ */
    /* Configure libspdm for Algorithm Set B (Nuvoton NPCT75x) */
    /* ------------------------------------------------------------------ */

    /* SPDM Version: 1.3 */
    XMEMSET(&parameter, 0, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
    data8 = SPDM_MESSAGE_VERSION_13;
    libspdm_set_data(spdmContext, LIBSPDM_DATA_SPDM_VERSION,
        &parameter, &data8, sizeof(data8));

    /* Base Asymmetric Algorithm: ECDSA P-384 */
    data32 = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384;
    libspdm_set_data(spdmContext, LIBSPDM_DATA_BASE_ASYM_ALGO,
        &parameter, &data32, sizeof(data32));

    /* Base Hash Algorithm: SHA-384 */
    data32 = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384;
    libspdm_set_data(spdmContext, LIBSPDM_DATA_BASE_HASH_ALGO,
        &parameter, &data32, sizeof(data32));

    /* DHE Named Group: ECDHE P-384 */
    data16 = SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1;
    libspdm_set_data(spdmContext, LIBSPDM_DATA_DHE_NAME_GROUP,
        &parameter, &data16, sizeof(data16));

    /* AEAD Cipher Suite: AES-256-GCM */
    data16 = SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM;
    libspdm_set_data(spdmContext, LIBSPDM_DATA_AEAD_CIPHER_SUITE,
        &parameter, &data16, sizeof(data16));

    /* Requester Base Asymmetric Algorithm (for mutual auth): ECDSA P-384 */
    data16 = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384;
    libspdm_set_data(spdmContext, LIBSPDM_DATA_REQ_BASE_ASYM_ALG,
        &parameter, &data16, sizeof(data16));

    /* Capability Flags: key exchange + mutual auth + encrypt + MAC */
    data32 = SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP |
             SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
             SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
             SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
             SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    libspdm_set_data(spdmContext, LIBSPDM_DATA_CAPABILITY_FLAGS,
        &parameter, &data32, sizeof(data32));

    bctx->spdmContext = spdmContext;
    bctx->spdmContextSize = spdmContextSize;

    ctx->backendCtx = bctx;

    return 0;
}

/* -------------------------------------------------------------------------- */
/* Backend Function: GetVersion */
/* -------------------------------------------------------------------------- */

static int libspdm_backend_get_version(WOLFTPM2_SPDM_CTX* ctx)
{
    LIBSPDM_BACKEND_CTX* bctx;
    libspdm_return_t status;

    if (ctx == NULL || ctx->backendCtx == NULL) {
        return BAD_FUNC_ARG;
    }

    bctx = (LIBSPDM_BACKEND_CTX*)ctx->backendCtx;

    /* For Nuvoton, we only need GET_VERSION (not full init_connection
     * which would also do GET_CAPABILITIES and NEGOTIATE_ALGORITHMS).
     * Passing true = get_version_only skips those steps. */
    status = libspdm_init_connection(bctx->spdmContext, true);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return TPM_RC_FAILURE;
    }

    return 0;
}

/* -------------------------------------------------------------------------- */
/* Backend Function: KeyExchange (KEY_EXCHANGE + FINISH in one step) */
/* -------------------------------------------------------------------------- */

static int libspdm_backend_key_exchange(
    WOLFTPM2_SPDM_CTX* ctx,
    const byte* rspPubKey, word32 rspPubKeyLen)
{
    LIBSPDM_BACKEND_CTX* bctx;
    libspdm_return_t status;
    uint8_t heartbeatPeriod = 0;
    uint8_t measurementHash[SPDM_HASH_SIZE];

    if (ctx == NULL || ctx->backendCtx == NULL) {
        return BAD_FUNC_ARG;
    }

    (void)rspPubKey;
    (void)rspPubKeyLen;

    bctx = (LIBSPDM_BACKEND_CTX*)ctx->backendCtx;

    /* libspdm_start_session performs KEY_EXCHANGE + FINISH in one call.
     * use_psk=false: use certificate-based (asymmetric) key exchange */
    status = libspdm_start_session(
        bctx->spdmContext,
        false,      /* use_psk = false (asymmetric key exchange) */
        NULL,       /* psk_hint (not used for cert-based) */
        0,          /* psk_hint_size */
        SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
        0,          /* slot_id */
        SPDM_KEY_EXCHANGE_REQUEST_SESSION_POLICY_TERMINATION_POLICY_RUNTIME_UPDATE,
        &bctx->sessionId,
        &heartbeatPeriod,
        measurementHash);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return TPM_RC_FAILURE;
    }

    /* Update parent context with session IDs */
    ctx->rspSessionId = (word16)(bctx->sessionId & 0xFFFF);
    ctx->reqSessionId = (word16)(bctx->sessionId >> 16);
    ctx->sessionId = bctx->sessionId;

    return 0;
}

/* -------------------------------------------------------------------------- */
/* Backend Function: Finish */
/* -------------------------------------------------------------------------- */

static int libspdm_backend_finish(
    WOLFTPM2_SPDM_CTX* ctx,
    const byte* reqPrivKey, word32 reqPrivKeySz)
{
    /* In libspdm v4, libspdm_start_session() already performs both
     * KEY_EXCHANGE and FINISH. This function is called for backends
     * that separate those steps. For libspdm, it's a no-op. */
    (void)ctx;
    (void)reqPrivKey;
    (void)reqPrivKeySz;

    return 0;
}

/* -------------------------------------------------------------------------- */
/* Backend Function: EncryptMessage */
/* -------------------------------------------------------------------------- */

static int libspdm_backend_encrypt(
    WOLFTPM2_SPDM_CTX* ctx,
    const byte* plain, word32 plainSz,
    byte* enc, word32* encSz)
{
    LIBSPDM_BACKEND_CTX* bctx;
    libspdm_return_t status;
    size_t securedMsgSize;
    void* securedMsg;
    libspdm_secured_message_callbacks_t secCallbacks;

    if (ctx == NULL || ctx->backendCtx == NULL ||
        plain == NULL || enc == NULL || encSz == NULL) {
        return BAD_FUNC_ARG;
    }

    bctx = (LIBSPDM_BACKEND_CTX*)ctx->backendCtx;

    /* Set up TCG transport callbacks for secured message */
    XMEMSET(&secCallbacks, 0, sizeof(secCallbacks));
    secCallbacks.version = LIBSPDM_SECURED_MESSAGE_CALLBACKS_VERSION;
    secCallbacks.get_sequence_number = spdm_tcg_get_sequence_number;
    secCallbacks.get_max_random_number_count =
        spdm_tcg_get_max_random_number_count;
    secCallbacks.get_secured_spdm_version =
        spdm_tcg_get_secured_spdm_version;

    /* Copy plaintext to scratch area (libspdm operates in-place) */
    XMEMCPY(bctx->senderBuffer, plain, plainSz);

    securedMsgSize = *encSz;
    securedMsg = enc;

    status = libspdm_encode_secured_message(
        bctx->spdmContext,
        bctx->sessionId,
        true,  /* is_request_message = true (host sending to TPM) */
        plainSz,
        bctx->senderBuffer,
        &securedMsgSize,
        securedMsg,
        &secCallbacks);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return TPM_RC_FAILURE;
    }

    *encSz = (word32)securedMsgSize;
    return 0;
}

/* -------------------------------------------------------------------------- */
/* Backend Function: DecryptMessage */
/* -------------------------------------------------------------------------- */

static int libspdm_backend_decrypt(
    WOLFTPM2_SPDM_CTX* ctx,
    const byte* enc, word32 encSz,
    byte* plain, word32* plainSz)
{
    LIBSPDM_BACKEND_CTX* bctx;
    libspdm_return_t status;
    size_t appMsgSize;
    void* appMsg;
    libspdm_secured_message_callbacks_t secCallbacks;

    if (ctx == NULL || ctx->backendCtx == NULL ||
        enc == NULL || plain == NULL || plainSz == NULL) {
        return BAD_FUNC_ARG;
    }

    bctx = (LIBSPDM_BACKEND_CTX*)ctx->backendCtx;

    /* Set up TCG transport callbacks for secured message */
    XMEMSET(&secCallbacks, 0, sizeof(secCallbacks));
    secCallbacks.version = LIBSPDM_SECURED_MESSAGE_CALLBACKS_VERSION;
    secCallbacks.get_sequence_number = spdm_tcg_get_sequence_number;
    secCallbacks.get_max_random_number_count =
        spdm_tcg_get_max_random_number_count;
    secCallbacks.get_secured_spdm_version =
        spdm_tcg_get_secured_spdm_version;

    /* Copy encrypted data to receiver buffer (libspdm operates in-place) */
    XMEMCPY(bctx->receiverBuffer, enc, encSz);

    appMsgSize = *plainSz;
    appMsg = plain;

    status = libspdm_decode_secured_message(
        bctx->spdmContext,
        bctx->sessionId,
        false, /* is_request_message = false (TPM responding to host) */
        encSz,
        bctx->receiverBuffer,
        &appMsgSize,
        &appMsg,
        &secCallbacks);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return TPM_RC_FAILURE;
    }

    /* appMsg may point inside receiverBuffer after decode */
    if (appMsg != plain && appMsgSize > 0) {
        XMEMCPY(plain, appMsg, appMsgSize);
    }
    *plainSz = (word32)appMsgSize;
    return 0;
}

/* -------------------------------------------------------------------------- */
/* Backend Function: EndSession */
/* -------------------------------------------------------------------------- */

static int libspdm_backend_end_session(WOLFTPM2_SPDM_CTX* ctx)
{
    LIBSPDM_BACKEND_CTX* bctx;
    libspdm_return_t status;

    if (ctx == NULL || ctx->backendCtx == NULL) {
        return BAD_FUNC_ARG;
    }

    bctx = (LIBSPDM_BACKEND_CTX*)ctx->backendCtx;

    status = libspdm_stop_session(
        bctx->spdmContext,
        bctx->sessionId,
        0 /* endSessionAttributes */);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return TPM_RC_FAILURE;
    }

    return 0;
}

/* -------------------------------------------------------------------------- */
/* Backend Function: Cleanup */
/* -------------------------------------------------------------------------- */

static void libspdm_backend_cleanup(WOLFTPM2_SPDM_CTX* ctx)
{
    LIBSPDM_BACKEND_CTX* bctx;

    if (ctx == NULL || ctx->backendCtx == NULL) {
        return;
    }

    bctx = (LIBSPDM_BACKEND_CTX*)ctx->backendCtx;

    if (bctx->scratchBuffer != NULL) {
        XFREE(bctx->scratchBuffer, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (bctx->spdmContext != NULL) {
        libspdm_deinit_context(bctx->spdmContext);
        XFREE(bctx->spdmContext, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    XFREE(bctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    ctx->backendCtx = NULL;
}

/* -------------------------------------------------------------------------- */
/* Exported Backend Instance */
/* -------------------------------------------------------------------------- */

/* This is the ONLY symbol exported from this file. To replace libspdm
 * with wolfSPDM, create tpm2_spdm_wolfspdm.c exporting an identical
 * WOLFTPM2_SPDM_BACKEND struct named spdm_wolfspdm_backend. */
WOLFTPM2_SPDM_BACKEND spdm_libspdm_backend = {
    libspdm_backend_init,
    libspdm_backend_get_version,
    libspdm_backend_key_exchange,
    libspdm_backend_finish,
    libspdm_backend_encrypt,
    libspdm_backend_decrypt,
    libspdm_backend_end_session,
    libspdm_backend_cleanup
};

#endif /* WOLFTPM_SPDM && WOLFTPM_WITH_LIBSPDM */
