/* spdm_psk.c
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

/* Shared SPDM PSK protocol code used by Nations (and future Infineon). */

#include "spdm_internal.h"

#ifdef WOLFTPM_SPDM_PSK

#include <wolftpm/spdm/spdm_psk.h>
#include <wolftpm/spdm/spdm_tcg.h>

/* ----- PSK Context Setup ----- */

int wolfSPDM_SetPSK(WOLFSPDM_CTX* ctx,
    const byte* psk, word32 pskSz,
    const byte* hint, word32 hintSz)
{
    if (ctx == NULL || psk == NULL || pskSz == 0) {
        return WOLFSPDM_E_INVALID_ARG;
    }
    if (pskSz > WOLFSPDM_PSK_MAX_SIZE) {
        return WOLFSPDM_E_INVALID_ARG;
    }
    if (hint != NULL && hintSz > WOLFSPDM_PSK_HINT_MAX) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    XMEMCPY(ctx->psk, psk, pskSz);
    ctx->pskSz = pskSz;

    if (hint != NULL && hintSz > 0) {
        XMEMCPY(ctx->pskHint, hint, hintSz);
        ctx->pskHintSz = hintSz;
    } else {
        XMEMSET(ctx->pskHint, 0, sizeof(ctx->pskHint));
        ctx->pskHintSz = 0;
    }

    return WOLFSPDM_SUCCESS;
}

/* ----- PSK Message Builders/Parsers ----- */

int wolfSPDM_BuildPskExchange(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz)
{
    word32 offset = 0;
    int rc;

    SPDM_CHECK_BUILD_ARGS(ctx, buf, bufSz, 48);

    if (ctx->pskSz == 0) {
        return WOLFSPDM_E_BAD_STATE;
    }

    XMEMSET(buf, 0, *bufSz);

    /* Header */
    buf[offset++] = ctx->spdmVersion;
    buf[offset++] = SPDM_PSK_EXCHANGE;
    buf[offset++] = 0x00;  /* MeasurementSummaryHashType = None */
    buf[offset++] = 0x00;  /* Param2 = Reserved */

    /* ReqSessionID (2 LE) */
    SPDM_Set16LE(&buf[offset], ctx->reqSessionId);
    offset += 2;

    /* PSKHintLength (2 LE) */
    SPDM_Set16LE(&buf[offset], (word16)ctx->pskHintSz);
    offset += 2;

    /* RequesterContextLength (2 LE) = 32 */
    SPDM_Set16LE(&buf[offset], WOLFSPDM_RANDOM_SIZE);
    offset += 2;

    /* OpaqueDataLength (2 LE) = 0 */
    SPDM_Set16LE(&buf[offset], 0);
    offset += 2;

    /* PSKHint */
    if (ctx->pskHintSz > 0) {
        if (offset + ctx->pskHintSz > *bufSz) {
            return WOLFSPDM_E_BUFFER_SMALL;
        }
        XMEMCPY(&buf[offset], ctx->pskHint, ctx->pskHintSz);
        offset += ctx->pskHintSz;
    }

    /* RequesterContext (32 random bytes) */
    if (offset + WOLFSPDM_RANDOM_SIZE > *bufSz) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }
    rc = wolfSPDM_GetRandom(ctx, &buf[offset], WOLFSPDM_RANDOM_SIZE);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }
    offset += WOLFSPDM_RANDOM_SIZE;

    /* OpaqueData - none */

    *bufSz = offset;
    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_ParsePskExchangeRsp(WOLFSPDM_CTX* ctx, const byte* buf,
    word32 bufSz)
{
    word16 rspContextLen, opaqueLen;
    word32 verifyOffset;
    word32 rspPartialLen;
    byte th1Hash[WOLFSPDM_HASH_SIZE];
    byte expectedHmac[WOLFSPDM_HASH_SIZE];
    const byte* rspVerifyData;
    int rc;

    /* Minimum: header(4) + RspSessionID(2) + Reserved(1) + RspContextLen(2) +
     * OpaqueLen(2) + VerifyData(48) = 59 */
    SPDM_CHECK_PARSE_ARGS(ctx, buf, bufSz, 59);
    SPDM_CHECK_RESPONSE(ctx, buf, bufSz, SPDM_PSK_EXCHANGE_RSP,
        WOLFSPDM_E_KEY_EXCHANGE);

    /* Per SPDM 1.3 DSP0274 Table 65:
     * [4-5] RspSessionID, [6] MutAuthRequested, [7] ReqSlotIDParam,
     * [8-9] RspContextLength, [10-11] OpaqueDataLength */
    ctx->rspSessionId = SPDM_Get16LE(&buf[4]);
    ctx->sessionId = (word32)ctx->reqSessionId |
                     ((word32)ctx->rspSessionId << 16);

    rspContextLen = SPDM_Get16LE(&buf[8]);
    opaqueLen = SPDM_Get16LE(&buf[10]);

    verifyOffset = 12 + rspContextLen + opaqueLen;
    rspPartialLen = verifyOffset;

    if (bufSz < verifyOffset + WOLFSPDM_HASH_SIZE) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    rspVerifyData = buf + verifyOffset;

    /* Add PSK_EXCHANGE_RSP (without VerifyData) to transcript */
    rc = wolfSPDM_TranscriptAdd(ctx, buf, rspPartialLen);

    /* Compute TH1 and derive handshake keys from PSK BEFORE verifying */
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_TranscriptHash(ctx, th1Hash);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        XMEMCPY(ctx->th1, th1Hash, WOLFSPDM_HASH_SIZE);
        rc = wolfSPDM_DeriveHandshakeKeysPsk(ctx, th1Hash);
    }

    /* Verify ResponderVerifyData = HMAC(rspFinishedKey, TH1) */
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_ComputeVerifyData(ctx->rspFinishedKey, th1Hash,
            expectedHmac);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        word32 i;
        int diff = 0;
        wolfSPDM_DebugHex(ctx, "Expected HMAC", expectedHmac,
            WOLFSPDM_HASH_SIZE);
        wolfSPDM_DebugHex(ctx, "Received HMAC", rspVerifyData,
            WOLFSPDM_HASH_SIZE);
        for (i = 0; i < WOLFSPDM_HASH_SIZE; i++) {
            diff |= expectedHmac[i] ^ rspVerifyData[i];
        }
        if (diff != 0) {
            wolfSPDM_DebugPrint(ctx, "PSK ResponderVerifyData MISMATCH\n");
            rc = WOLFSPDM_E_BAD_HMAC;
        }
    }
    if (rc == WOLFSPDM_SUCCESS) {
        wolfSPDM_DebugPrint(ctx, "PSK ResponderVerifyData VERIFIED OK\n");
        rc = wolfSPDM_TranscriptAdd(ctx, rspVerifyData, WOLFSPDM_HASH_SIZE);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        ctx->state = WOLFSPDM_STATE_KEY_EX;
    }

    wc_ForceZero(expectedHmac, sizeof(expectedHmac));
    wc_ForceZero(th1Hash, sizeof(th1Hash));
    return rc;
}

int wolfSPDM_BuildPskFinish(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz)
{
    byte th2Hash[WOLFSPDM_HASH_SIZE];
    byte verifyData[WOLFSPDM_HASH_SIZE];
    word32 offset = 0;
    int rc;

    if (ctx == NULL || buf == NULL || bufSz == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    /* PSK_FINISH = header(4) + VerifyData(48) = 52 bytes */
    if (*bufSz < 4 + WOLFSPDM_HASH_SIZE) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    /* Header */
    buf[offset++] = ctx->spdmVersion;
    buf[offset++] = SPDM_PSK_FINISH;
    buf[offset++] = 0x00;  /* Param1 */
    buf[offset++] = 0x00;  /* Param2 */

    /* Add PSK_FINISH header to transcript, compute TH2 */
    rc = wolfSPDM_TranscriptAdd(ctx, buf, offset);
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_TranscriptHash(ctx, th2Hash);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        XMEMCPY(ctx->th2, th2Hash, WOLFSPDM_HASH_SIZE);
    }

    /* RequesterVerifyData = HMAC(reqFinishedKey, TH2) */
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_ComputeVerifyData(ctx->reqFinishedKey, th2Hash,
            verifyData);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        XMEMCPY(&buf[offset], verifyData, WOLFSPDM_HASH_SIZE);
        offset += WOLFSPDM_HASH_SIZE;
        rc = wolfSPDM_TranscriptAdd(ctx, verifyData, WOLFSPDM_HASH_SIZE);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        *bufSz = offset;
    }

    wc_ForceZero(th2Hash, sizeof(th2Hash));
    wc_ForceZero(verifyData, sizeof(verifyData));
    return rc;
}

int wolfSPDM_ParsePskFinishRsp(WOLFSPDM_CTX* ctx, const byte* buf,
    word32 bufSz)
{
    SPDM_CHECK_PARSE_ARGS(ctx, buf, bufSz, 4);

    if (buf[1] == SPDM_PSK_FINISH_RSP) {
        int addRc = wolfSPDM_TranscriptAdd(ctx, buf, 4);
        if (addRc != WOLFSPDM_SUCCESS) {
            return addRc;
        }
        ctx->state = WOLFSPDM_STATE_FINISH;
        wolfSPDM_DebugPrint(ctx, "PSK_FINISH_RSP received\n");
        return WOLFSPDM_SUCCESS;
    }

    if (buf[1] == SPDM_ERROR) {
        wolfSPDM_DebugPrint(ctx, "PSK_FINISH error: 0x%02x\n", buf[2]);
        return WOLFSPDM_E_PEER_ERROR;
    }

    return WOLFSPDM_E_BAD_STATE;
}

/* ----- PSK Key Derivation ----- */

int wolfSPDM_DeriveHandshakeKeysPsk(WOLFSPDM_CTX* ctx, const byte* th1Hash)
{
    byte salt[WOLFSPDM_HASH_SIZE];
    int rc;

    if (ctx == NULL || th1Hash == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }
    if (ctx->pskSz == 0) {
        return WOLFSPDM_E_BAD_STATE;
    }

    /* PSK mode: Salt_0 = 0xFF-filled (per TCG PSK specification). */
    XMEMSET(salt, 0xFF, sizeof(salt));

    /* HandshakeSecret = HKDF-Extract(0xFF-salt, PSK) */
    rc = wc_HKDF_Extract(WC_SHA384, salt, sizeof(salt),
        ctx->psk, ctx->pskSz, ctx->handshakeSecret);
    if (rc != 0) {
        wc_ForceZero(ctx->psk, sizeof(ctx->psk));
        ctx->pskSz = 0;
        return WOLFSPDM_E_CRYPTO_FAIL;
    }

    rc = wolfSPDM_DeriveFromHandshakeSecret(ctx, th1Hash);

    /* Zero PSK immediately after key derivation */
    wc_ForceZero(ctx->psk, sizeof(ctx->psk));
    ctx->pskSz = 0;

    return rc;
}

/* ----- Shared PSK Connection Flow ----- */

/* GET_VERSION -> GET_CAPABILITIES -> NEGOTIATE_ALGORITHMS ->
 * PSK_EXCHANGE -> PSK_FINISH -> app key derivation */
int wolfSPDM_ConnectPsk(WOLFSPDM_CTX* ctx)
{
    int rc;
    byte txBuf[128];
    byte rxBuf[WOLFSPDM_MAX_MSG_SIZE + WOLFSPDM_AEAD_OVERHEAD];
    byte finBuf[64];
    byte encBuf[WOLFSPDM_MAX_MSG_SIZE + WOLFSPDM_AEAD_OVERHEAD];
    byte decBuf[64];
    word32 txSz;
    word32 rxSz;
    word32 finSz;
    word32 encSz;
    word32 decSz;

    if (ctx == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (!ctx->flags.initialized) {
        return WOLFSPDM_E_BAD_STATE;
    }

    if (ctx->pskSz == 0) {
        wolfSPDM_DebugPrint(ctx, "PSK: No PSK set\n");
        return WOLFSPDM_E_BAD_STATE;
    }

    if (ctx->ioCb == NULL) {
        return WOLFSPDM_E_IO_FAIL;
    }

    wolfSPDM_DebugPrint(ctx, "PSK: Starting SPDM connection\n");

    ctx->state = WOLFSPDM_STATE_INIT;
    wolfSPDM_TranscriptReset(ctx);

    /* Step 1: GET_VERSION */
    SPDM_CONNECT_STEP(ctx, "PSK Step 1: GET_VERSION\n",
        wolfSPDM_GetVersion(ctx));

    /* Steps 2-3: GET_CAPABILITIES + NEGOTIATE_ALGORITHMS
     * Not mandatory for PSK mode per TCG PC Client PSK spec.
     * NS350 supports direct GET_VERSION -> PSK_EXCHANGE. */

    /* Step 2: PSK_EXCHANGE / PSK_EXCHANGE_RSP */
    txSz = sizeof(txBuf);
    rxSz = sizeof(rxBuf);

    wolfSPDM_DebugPrint(ctx, "PSK Step 4: PSK_EXCHANGE\n");
    rc = wolfSPDM_BuildPskExchange(ctx, txBuf, &txSz);
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_TranscriptAdd(ctx, txBuf, txSz);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_SendReceive(ctx, txBuf, txSz, rxBuf, &rxSz);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_ParsePskExchangeRsp(ctx, rxBuf, rxSz);
    }

    /* Step 5: PSK_FINISH / PSK_FINISH_RSP (encrypted) */
    if (rc == WOLFSPDM_SUCCESS) {
        finSz = sizeof(finBuf);
        encSz = sizeof(encBuf);
        rxSz = sizeof(rxBuf);
        decSz = sizeof(decBuf);

        wolfSPDM_DebugPrint(ctx, "PSK Step 5: PSK_FINISH\n");
        rc = wolfSPDM_BuildPskFinish(ctx, finBuf, &finSz);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_EncryptInternal(ctx, finBuf, finSz, encBuf, &encSz);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_SendReceive(ctx, encBuf, encSz, rxBuf, &rxSz);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_DecryptInternal(ctx, rxBuf, rxSz, decBuf, &decSz);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_ParsePskFinishRsp(ctx, decBuf, decSz);
    }

    /* Derive application data keys */
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_DeriveAppDataKeys(ctx);
    }

    if (rc == WOLFSPDM_SUCCESS) {
        ctx->state = WOLFSPDM_STATE_CONNECTED;
        wolfSPDM_DebugPrint(ctx, "PSK: SPDM Session Established! "
            "SessionID=0x%08x\n", ctx->sessionId);
    }
    else {
        ctx->state = WOLFSPDM_STATE_ERROR;
    }

    /* Always zero sensitive stack buffers */
    wc_ForceZero(finBuf, sizeof(finBuf));
    wc_ForceZero(encBuf, sizeof(encBuf));
    wc_ForceZero(decBuf, sizeof(decBuf));

    return rc;
}

#endif /* WOLFTPM_SPDM_PSK */

#endif /* WOLFTPM_SPDM */
