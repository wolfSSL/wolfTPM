/* spdm_context.c
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#ifdef WOLFTPM_SPDM

#include "spdm_internal.h"
#include <stdarg.h>
#include <stdio.h>

/* ----- Context Management ----- */

int wolfSPDM_Init(WOLFSPDM_CTX* ctx)
{
    int rc;

    if (ctx == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    /* Clean slate, dont read fields before this */
    XMEMSET(ctx, 0, sizeof(WOLFSPDM_CTX));
    ctx->state = WOLFSPDM_STATE_INIT;

    /* Initialize RNG */
    rc = wc_InitRng(&ctx->rng);
    if (rc != 0) {
        return WOLFSPDM_E_CRYPTO_FAIL;
    }
    ctx->flags.rngInitialized = 1;

    /* Set default session ID (0x0001 is valid; 0x0000/0xFFFF are reserved) */
    ctx->reqSessionId = 0x0001;

    ctx->flags.initialized = 1;
    /* isDynamic remains 0, only wolfSPDM_New sets it */

    return WOLFSPDM_SUCCESS;
}

#ifdef WOLFTPM_SMALL_STACK
WOLFSPDM_CTX* wolfSPDM_New(void)
{
    WOLFSPDM_CTX* ctx;

    ctx = (WOLFSPDM_CTX*)XMALLOC(sizeof(WOLFSPDM_CTX), NULL,
                                  DYNAMIC_TYPE_TMP_BUFFER);
    if (ctx == NULL) {
        return NULL;
    }

    if (wolfSPDM_Init(ctx) != WOLFSPDM_SUCCESS) {
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return NULL;
    }
    ctx->flags.isDynamic = 1;  /* Tag AFTER Init so it isn't wiped */

    return ctx;
}
#endif /* WOLFTPM_SMALL_STACK */

void wolfSPDM_Free(WOLFSPDM_CTX* ctx)
{
    int wasDynamic;

    if (ctx == NULL) {
        return;
    }

    wasDynamic = ctx->flags.isDynamic;

    /* Free RNG */
    if (ctx->flags.rngInitialized) {
        wc_FreeRng(&ctx->rng);
    }

    /* Free ephemeral key */
    if (ctx->flags.ephemeralKeyInit) {
        wc_ecc_free(&ctx->ephemeralKey);
    }

    /* Zero entire struct (covers all sensitive key material) */
    wc_ForceZero(ctx, sizeof(WOLFSPDM_CTX));

#ifdef WOLFTPM_SMALL_STACK
    if (wasDynamic) {
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
#else
    (void)wasDynamic;
#endif
}

int wolfSPDM_GetCtxSize(void)
{
    return (int)sizeof(WOLFSPDM_CTX);
}

int wolfSPDM_InitStatic(WOLFSPDM_CTX* ctx, int size)
{
    if (ctx == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (size < (int)sizeof(WOLFSPDM_CTX)) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    return wolfSPDM_Init(ctx);
}

/* ----- Configuration ----- */

int wolfSPDM_SetIO(WOLFSPDM_CTX* ctx, WOLFSPDM_IO_CB ioCb, void* userCtx)
{
    if (ctx == NULL || ioCb == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    ctx->ioCb = ioCb;
    ctx->ioUserCtx = userCtx;

    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_SetResponderPubKey(WOLFSPDM_CTX* ctx,
    const byte* pubKey, word32 pubKeySz)
{
    if (ctx == NULL || pubKey == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (pubKeySz != WOLFSPDM_ECC_POINT_SIZE) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    XMEMCPY(ctx->rspPubKey, pubKey, pubKeySz);
    ctx->rspPubKeyLen = pubKeySz;
    ctx->flags.hasRspPubKey = 1;

    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_SetRequesterKeyPair(WOLFSPDM_CTX* ctx,
    const byte* privKey, word32 privKeySz,
    const byte* pubKey, word32 pubKeySz)
{
    if (ctx == NULL || privKey == NULL || pubKey == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (privKeySz != WOLFSPDM_ECC_KEY_SIZE ||
        pubKeySz != WOLFSPDM_ECC_POINT_SIZE) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    XMEMCPY(ctx->reqPrivKey, privKey, privKeySz);
    ctx->reqPrivKeyLen = privKeySz;
    XMEMCPY(ctx->reqPubKey, pubKey, pubKeySz);
    ctx->flags.hasReqKeyPair = 1;

    return WOLFSPDM_SUCCESS;
}

#if defined(WOLFSPDM_NUVOTON) || defined(WOLFSPDM_NATIONS)
int wolfSPDM_SetRequesterKeyTPMT(WOLFSPDM_CTX* ctx,
    const byte* tpmtPub, word32 tpmtPubSz)
{
    if (ctx == NULL || tpmtPub == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }
    if (tpmtPubSz > sizeof(ctx->reqPubKeyTPMT)) {
        return WOLFSPDM_E_INVALID_ARG;
    }
    XMEMCPY(ctx->reqPubKeyTPMT, tpmtPub, tpmtPubSz);
    ctx->reqPubKeyTPMTLen = tpmtPubSz;
    return WOLFSPDM_SUCCESS;
}
#endif /* WOLFSPDM_NUVOTON || WOLFSPDM_NATIONS */

/* wolfSPDM_SetPSK moved to spdm_psk.c */

void wolfSPDM_SetDebug(WOLFSPDM_CTX* ctx, int enable)
{
    if (ctx != NULL) {
        ctx->flags.debug = (enable != 0);
    }
}

int wolfSPDM_SetMode(WOLFSPDM_CTX* ctx, WOLFSPDM_MODE mode)
{
    if (ctx == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

#ifdef WOLFSPDM_NUVOTON
    if (mode == WOLFSPDM_MODE_NUVOTON) {
        ctx->mode = WOLFSPDM_MODE_NUVOTON;
        ctx->connectionHandle = WOLFSPDM_NUVOTON_CONN_HANDLE_DEFAULT;
        ctx->fipsIndicator = WOLFSPDM_NUVOTON_FIPS_DEFAULT;
        return WOLFSPDM_SUCCESS;
    }
#endif
#ifdef WOLFSPDM_NATIONS
    if (mode == WOLFSPDM_MODE_NATIONS) {
        ctx->mode = WOLFSPDM_MODE_NATIONS;
        ctx->connectionHandle = 0;
        /* Default to NON_FIPS; overridden by auto-detect if FIPS configured */
        ctx->fipsIndicator = WOLFSPDM_FIPS_NON_FIPS;
        return WOLFSPDM_SUCCESS;
    }
    if (mode == WOLFSPDM_MODE_NATIONS_PSK) {
        ctx->mode = WOLFSPDM_MODE_NATIONS_PSK;
        ctx->connectionHandle = 0;
        ctx->fipsIndicator = WOLFSPDM_FIPS_NON_FIPS;
        return WOLFSPDM_SUCCESS;
    }
#endif

    return WOLFSPDM_E_INVALID_ARG;  /* Unsupported mode */
}

WOLFSPDM_MODE wolfSPDM_GetMode(WOLFSPDM_CTX* ctx)
{
    if (ctx == NULL) {
        return (WOLFSPDM_MODE)0;
    }
    return ctx->mode;
}

/* ----- Session Status ----- */

int wolfSPDM_IsConnected(WOLFSPDM_CTX* ctx)
{
    if (ctx == NULL) {
        return 0;
    }
    return (ctx->state == WOLFSPDM_STATE_CONNECTED) ? 1 : 0;
}

word32 wolfSPDM_GetSessionId(WOLFSPDM_CTX* ctx)
{
    if (ctx == NULL || ctx->state != WOLFSPDM_STATE_CONNECTED) {
        return 0;
    }
    return ctx->sessionId;
}

byte wolfSPDM_GetNegotiatedVersion(WOLFSPDM_CTX* ctx)
{
    if (ctx == NULL || ctx->state < WOLFSPDM_STATE_VERSION) {
        return 0;
    }
    return ctx->spdmVersion;
}

#if defined(WOLFSPDM_NUVOTON) || defined(WOLFSPDM_NATIONS)
word32 wolfSPDM_GetConnectionHandle(WOLFSPDM_CTX* ctx)
{
    if (ctx == NULL) {
        return 0;
    }
    return ctx->connectionHandle;
}

word16 wolfSPDM_GetFipsIndicator(WOLFSPDM_CTX* ctx)
{
    if (ctx == NULL) {
        return 0;
    }
    return ctx->fipsIndicator;
}
#endif

/* ----- Session Establishment - Connect (Full Handshake) ----- */

int wolfSPDM_Connect(WOLFSPDM_CTX* ctx)
{
    if (ctx == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (!ctx->flags.initialized) {
        return WOLFSPDM_E_BAD_STATE;
    }

    if (ctx->ioCb == NULL) {
        return WOLFSPDM_E_IO_FAIL;
    }

#if defined(WOLFSPDM_NUVOTON) || defined(WOLFSPDM_NATIONS)
    if (ctx->mode == WOLFSPDM_MODE_NUVOTON ||
        ctx->mode == WOLFSPDM_MODE_NATIONS) {
        return wolfSPDM_ConnectTCG(ctx);
    }
#endif
#ifdef WOLFTPM_SPDM_PSK
    if (ctx->mode == WOLFSPDM_MODE_NATIONS_PSK) {
        return wolfSPDM_ConnectPsk(ctx);
    }
#endif

    return WOLFSPDM_E_INVALID_ARG; /* Standard mode not available */
}

int wolfSPDM_Disconnect(WOLFSPDM_CTX* ctx)
{
    int rc;
    byte txBuf[8];
    byte rxBuf[16];   /* END_SESSION_ACK: 4 bytes */
    word32 txSz, rxSz;

    if (ctx == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (ctx->state != WOLFSPDM_STATE_CONNECTED) {
        return WOLFSPDM_E_NOT_CONNECTED;
    }

    /* Build END_SESSION */
    txSz = sizeof(txBuf);
    rc = wolfSPDM_BuildEndSession(ctx, txBuf, &txSz);
    if (rc == WOLFSPDM_SUCCESS) {
        rxSz = sizeof(rxBuf);
        rc = wolfSPDM_SecuredExchange(ctx, txBuf, txSz, rxBuf, &rxSz);
    }

    /* Reset state and zero ALL key material */
    ctx->state = WOLFSPDM_STATE_INIT;
    ctx->sessionId = 0;
    ctx->reqSeqNum = 0;
    ctx->rspSeqNum = 0;
    /* App data keys */
    wc_ForceZero(ctx->reqDataKey, sizeof(ctx->reqDataKey));
    wc_ForceZero(ctx->rspDataKey, sizeof(ctx->rspDataKey));
    wc_ForceZero(ctx->reqDataIv, sizeof(ctx->reqDataIv));
    wc_ForceZero(ctx->rspDataIv, sizeof(ctx->rspDataIv));
    /* Handshake keys */
    wc_ForceZero(ctx->reqHsSecret, sizeof(ctx->reqHsSecret));
    wc_ForceZero(ctx->rspHsSecret, sizeof(ctx->rspHsSecret));
    wc_ForceZero(ctx->reqFinishedKey, sizeof(ctx->reqFinishedKey));
    wc_ForceZero(ctx->rspFinishedKey, sizeof(ctx->rspFinishedKey));
    /* Secrets and hashes */
    wc_ForceZero(ctx->handshakeSecret, sizeof(ctx->handshakeSecret));
    wc_ForceZero(ctx->sharedSecret, sizeof(ctx->sharedSecret));
    ctx->sharedSecretSz = 0;
    wc_ForceZero(ctx->th1, sizeof(ctx->th1));
    wc_ForceZero(ctx->th2, sizeof(ctx->th2));
    /* Free ephemeral ECC key */
    if (ctx->flags.ephemeralKeyInit) {
        wc_ecc_free(&ctx->ephemeralKey);
        ctx->flags.ephemeralKeyInit = 0;
    }

    return rc;
}

/* ----- I/O Helper ----- */

int wolfSPDM_SendReceive(WOLFSPDM_CTX* ctx,
    const byte* txBuf, word32 txSz,
    byte* rxBuf, word32* rxSz)
{
    int rc;

    if (ctx == NULL || ctx->ioCb == NULL) {
        return WOLFSPDM_E_IO_FAIL;
    }

#if defined(WOLFSPDM_NUVOTON) || defined(WOLFSPDM_NATIONS)
    if (ctx->mode == WOLFSPDM_MODE_NUVOTON ||
        ctx->mode == WOLFSPDM_MODE_NATIONS ||
        ctx->mode == WOLFSPDM_MODE_NATIONS_PSK) {
        /* Wrap messages with TCG SPDM
         * headers; I/O sends TCG-framed messages. */
        byte tcgTx[WOLFSPDM_MAX_MSG_SIZE + WOLFSPDM_AEAD_OVERHEAD +
                   WOLFSPDM_TCG_HEADER_SIZE];
        byte tcgRx[WOLFSPDM_MAX_MSG_SIZE + WOLFSPDM_AEAD_OVERHEAD +
                   WOLFSPDM_TCG_HEADER_SIZE];
        word32 tcgRxSz = sizeof(tcgRx);
        int tcgTxSz;
        word32 msgSize;
        word32 payloadSz;
        word16 tag;

        /* Detect message type: SPDM version byte 0x10-0x1F = clear message.
         * Secured records start with SessionID (LE, typically 0x01 0x00...),
         * which is never in the SPDM version range. */
        if (txSz > 0 && txBuf[0] >= 0x10 && txBuf[0] <= 0x1F) {
            /* Clear SPDM message - wrap with TCG clear header (0x8101) */
            tcgTxSz = wolfSPDM_BuildTcgClearMessage(ctx, txBuf, txSz,
                tcgTx, sizeof(tcgTx));
        } else {
            /* Secured record - prepend TCG secured header (0x8201) */
            word32 totalSz = WOLFSPDM_TCG_HEADER_SIZE + txSz;
            if (totalSz > sizeof(tcgTx)) {
                return WOLFSPDM_E_BUFFER_SMALL;
            }
            wolfSPDM_WriteTcgHeader(tcgTx, WOLFSPDM_TCG_TAG_SECURED,
                totalSz, ctx->connectionHandle, ctx->fipsIndicator);
            XMEMCPY(tcgTx + WOLFSPDM_TCG_HEADER_SIZE, txBuf, txSz);
            tcgTxSz = (int)totalSz;
        }

        if (tcgTxSz < 0) {
            return tcgTxSz;
        }

        wolfSPDM_DebugHex(ctx, "TCG TX", tcgTx, (word32)tcgTxSz);

        /* Send/receive via I/O callback (raw transport) */
        rc = ctx->ioCb(ctx, tcgTx, (word32)tcgTxSz, tcgRx, &tcgRxSz,
            ctx->ioUserCtx);
        if (rc != 0) {
            wolfSPDM_DebugPrint(ctx, "TCG I/O failed: %d\n", rc);
            return WOLFSPDM_E_IO_FAIL;
        }

        wolfSPDM_DebugHex(ctx, "TCG RX", tcgRx, tcgRxSz);

        /* Strip TCG binding header from response */
        if (tcgRxSz < WOLFSPDM_TCG_HEADER_SIZE) {
            wolfSPDM_DebugPrint(ctx, "SendReceive: response too short (%u)\n",
                tcgRxSz);
            return WOLFSPDM_E_BUFFER_SMALL;
        }

        tag = SPDM_Get16BE(tcgRx);
        if (tag != WOLFSPDM_TCG_TAG_CLEAR && tag != WOLFSPDM_TCG_TAG_SECURED) {
            wolfSPDM_DebugPrint(ctx, "SendReceive: unexpected TCG tag "
                "0x%04x\n", tag);
            return WOLFSPDM_E_PEER_ERROR;
        }

        /* Capture FIPS indicator from response if non-zero */
        tag = SPDM_Get16BE(tcgRx + 10);
        if (tag != 0) {
            ctx->fipsIndicator = tag;
        }

        /* Extract payload (everything after 16-byte TCG header) */
        msgSize = SPDM_Get32BE(tcgRx + 2);

        if (msgSize < WOLFSPDM_TCG_HEADER_SIZE || msgSize > tcgRxSz) {
            wolfSPDM_DebugPrint(ctx, "SendReceive: TCG size %u invalid "
                "(min=%u, received=%u)\n", msgSize,
                WOLFSPDM_TCG_HEADER_SIZE, tcgRxSz);
            return WOLFSPDM_E_BUFFER_SMALL;
        }

        payloadSz = msgSize - WOLFSPDM_TCG_HEADER_SIZE;
        if (payloadSz > *rxSz) {
            return WOLFSPDM_E_BUFFER_SMALL;
        }

        XMEMCPY(rxBuf, tcgRx + WOLFSPDM_TCG_HEADER_SIZE, payloadSz);
        *rxSz = payloadSz;

        return WOLFSPDM_SUCCESS;
    }
#endif /* WOLFSPDM_NUVOTON || WOLFSPDM_NATIONS */

    rc = ctx->ioCb(ctx, txBuf, txSz, rxBuf, rxSz, ctx->ioUserCtx);
    if (rc != 0) {
        return WOLFSPDM_E_IO_FAIL;
    }

    return WOLFSPDM_SUCCESS;
}

/* ----- Debug Utilities ----- */
#ifdef DEBUG_WOLFTPM
void wolfSPDM_DebugPrint(WOLFSPDM_CTX* ctx, const char* fmt, ...)
{
    va_list args;

    if (ctx == NULL || !ctx->flags.debug) {
        return;
    }

    printf("[wolfSPDM] ");
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    fflush(stdout);
}

void wolfSPDM_DebugHex(WOLFSPDM_CTX* ctx, const char* label,
    const byte* data, word32 len)
{
    word32 i;

    if (ctx == NULL || !ctx->flags.debug || data == NULL) {
        return;
    }

    printf("[wolfSPDM] %s (%u bytes): ", label, len);
    for (i = 0; i < len && i < 32; i++) {
        printf("%02x", data[i]);
    }
    if (len > 32) {
        printf("...");
    }
    printf("\n");
    fflush(stdout);
}
#endif

/* ----- Error String ----- */
const char* wolfSPDM_GetErrorString(int error)
{
    switch (error) {
        case WOLFSPDM_SUCCESS:            return "Success";
        case WOLFSPDM_E_INVALID_ARG:      return "Invalid argument";
        case WOLFSPDM_E_BUFFER_SMALL:     return "Buffer too small";
        case WOLFSPDM_E_BAD_STATE:        return "Invalid state";
        case WOLFSPDM_E_VERSION_MISMATCH: return "Version mismatch";
        case WOLFSPDM_E_CRYPTO_FAIL:      return "Crypto operation failed";
        case WOLFSPDM_E_BAD_SIGNATURE:    return "Bad signature";
        case WOLFSPDM_E_BAD_HMAC:         return "HMAC verification failed";
        case WOLFSPDM_E_IO_FAIL:          return "I/O failure";
        case WOLFSPDM_E_TIMEOUT:          return "Timeout";
        case WOLFSPDM_E_PEER_ERROR:       return "Peer error response";
        case WOLFSPDM_E_DECRYPT_FAIL:     return "Decryption failed";
        case WOLFSPDM_E_SEQUENCE:         return "Sequence number error";
        case WOLFSPDM_E_NOT_CONNECTED:    return "Not connected";
        case WOLFSPDM_E_ALREADY_INIT:     return "Already initialized";
        case WOLFSPDM_E_NO_MEMORY:        return "Memory allocation failed";
        case WOLFSPDM_E_SESSION_INVALID:  return "Invalid session";
        case WOLFSPDM_E_KEY_EXCHANGE:     return "Key exchange failed";
        default:                          return "Unknown error";
    }
}

#endif /* WOLFTPM_SPDM */
