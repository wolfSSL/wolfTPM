/* spdm_session.c
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

#include "spdm_internal.h"

/* Callback types for build/parse functions */
typedef int (*wolfSPDM_BuildFn)(WOLFSPDM_CTX*, byte*, word32*);
typedef int (*wolfSPDM_ParseFn)(WOLFSPDM_CTX*, const byte*, word32);

/* Exchange helper: build → transcript(tx) → sendrecv → transcript(rx) → parse */
static int wolfSPDM_ExchangeMsg(WOLFSPDM_CTX* ctx,
    wolfSPDM_BuildFn buildFn, wolfSPDM_ParseFn parseFn,
    byte* txBuf, word32 txBufSz, byte* rxBuf, word32 rxBufSz)
{
    word32 txSz = txBufSz;
    word32 rxSz = rxBufSz;
    int rc;

    rc = buildFn(ctx, txBuf, &txSz);
    if (rc != WOLFSPDM_SUCCESS) return rc;

    rc = wolfSPDM_TranscriptAdd(ctx, txBuf, txSz);
    if (rc != WOLFSPDM_SUCCESS) return rc;

    rc = wolfSPDM_SendReceive(ctx, txBuf, txSz, rxBuf, &rxSz);
    if (rc != WOLFSPDM_SUCCESS) return rc;

    rc = wolfSPDM_TranscriptAdd(ctx, rxBuf, rxSz);
    if (rc != WOLFSPDM_SUCCESS) return rc;

    return parseFn(ctx, rxBuf, rxSz);
}

/* Adapter: BuildGetVersion doesn't take ctx */
static int wolfSPDM_BuildGetVersionAdapter(WOLFSPDM_CTX* ctx, byte* buf,
    word32* bufSz)
{
    (void)ctx;
    return wolfSPDM_BuildGetVersion(buf, bufSz);
}

int wolfSPDM_GetVersion(WOLFSPDM_CTX* ctx)
{
    byte txBuf[8];
    byte rxBuf[32];  /* VERSION: 4 hdr + 2 count + up to 8 entries * 2 = 22 */

    return wolfSPDM_ExchangeMsg(ctx, wolfSPDM_BuildGetVersionAdapter,
        wolfSPDM_ParseVersion, txBuf, sizeof(txBuf), rxBuf, sizeof(rxBuf));
}

int wolfSPDM_GetCapabilities(WOLFSPDM_CTX* ctx)
{
    byte txBuf[24];   /* GET_CAPABILITIES: 20 bytes */
    byte rxBuf[40];   /* CAPABILITIES: 20-36 bytes */

    return wolfSPDM_ExchangeMsg(ctx, wolfSPDM_BuildGetCapabilities,
        wolfSPDM_ParseCapabilities, txBuf, sizeof(txBuf), rxBuf, sizeof(rxBuf));
}

int wolfSPDM_NegotiateAlgorithms(WOLFSPDM_CTX* ctx)
{
    byte txBuf[52];   /* NEGOTIATE_ALGORITHMS: 48 bytes */
    byte rxBuf[80];   /* ALGORITHMS: ~56 bytes with struct tables */
    int rc;

    rc = wolfSPDM_ExchangeMsg(ctx, wolfSPDM_BuildNegotiateAlgorithms,
        wolfSPDM_ParseAlgorithms, txBuf, sizeof(txBuf), rxBuf, sizeof(rxBuf));
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    /* Save VCA transcript length (GET_VERSION through ALGORITHMS).
     * Used by measurement signature verification per DSP0274. */
    ctx->vcaLen = ctx->transcriptLen;

#ifndef NO_WOLFSPDM_CHALLENGE
    /* Initialize M1/M2 running hash for potential CHALLENGE auth.
     * Start with VCA (A portion of the M1/M2 transcript per DSP0274). */
    {
        int hashRc = wc_InitSha384(&ctx->m1m2Hash);
        if (hashRc == 0) {
            hashRc = wc_Sha384Update(&ctx->m1m2Hash, ctx->transcript,
                ctx->vcaLen);
            if (hashRc == 0) {
                ctx->flags.m1m2HashInit = 1;
            }
            else {
                wc_Sha384Free(&ctx->m1m2Hash);
            }
        }
        /* Non-fatal: challenge just won't work if this fails */
    }
#endif

    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_GetDigests(WOLFSPDM_CTX* ctx)
{
    byte txBuf[8];
    byte rxBuf[256];
    word32 txSz = sizeof(txBuf);
    word32 rxSz = sizeof(rxBuf);
    int rc;

    rc = wolfSPDM_BuildGetDigests(ctx, txBuf, &txSz);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    /* Note: GET_DIGESTS/DIGESTS are NOT added to main transcript for TH1,
     * but ARE needed for CHALLENGE M1/M2 (the "B" portion per DSP0274). */
    rc = wolfSPDM_SendReceive(ctx, txBuf, txSz, rxBuf, &rxSz);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

#ifndef NO_WOLFSPDM_CHALLENGE
    /* Feed GET_DIGESTS request + DIGESTS response to M1/M2 challenge hash */
    if (ctx->flags.m1m2HashInit) {
        wc_Sha384Update(&ctx->m1m2Hash, txBuf, txSz);
        wc_Sha384Update(&ctx->m1m2Hash, rxBuf, rxSz);
    }
#endif

    return wolfSPDM_ParseDigests(ctx, rxBuf, rxSz);
}

int wolfSPDM_GetCertificate(WOLFSPDM_CTX* ctx, int slotId)
{
    byte txBuf[16];
    byte rxBuf[1040];  /* 8 hdr + up to 1024 cert data per chunk */
    word32 txSz;
    word32 rxSz;
    word16 offset = 0;
    word16 portionLen;
    word16 remainderLen = 1;
    int rc;

    while (remainderLen > 0) {
        txSz = sizeof(txBuf);
        rc = wolfSPDM_BuildGetCertificate(ctx, txBuf, &txSz, slotId, offset, 1024);
        if (rc != WOLFSPDM_SUCCESS) {
            return rc;
        }

        rxSz = sizeof(rxBuf);
        rc = wolfSPDM_SendReceive(ctx, txBuf, txSz, rxBuf, &rxSz);
        if (rc != WOLFSPDM_SUCCESS) {
            return rc;
        }

#ifndef NO_WOLFSPDM_CHALLENGE
        /* Feed each GET_CERTIFICATE/CERTIFICATE chunk to M1/M2 challenge hash */
        if (ctx->flags.m1m2HashInit) {
            wc_Sha384Update(&ctx->m1m2Hash, txBuf, txSz);
            wc_Sha384Update(&ctx->m1m2Hash, rxBuf, rxSz);
        }
#endif

        rc = wolfSPDM_ParseCertificate(ctx, rxBuf, rxSz, &portionLen, &remainderLen);
        if (rc != WOLFSPDM_SUCCESS) {
            return rc;
        }

        offset += portionLen;
        wolfSPDM_DebugPrint(ctx, "Certificate: offset=%u, portion=%u, remainder=%u\n",
            offset, portionLen, remainderLen);
    }

    /* Compute Ct = Hash(certificate_chain) and add to transcript */
    rc = wolfSPDM_ComputeCertChainHash(ctx);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    rc = wolfSPDM_TranscriptAdd(ctx, ctx->certChainHash, WOLFSPDM_HASH_SIZE);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    /* Auto-extract responder public key from leaf cert.
     * Needed by both measurement signature verification and challenge auth.
     * Non-fatal: caller can still proceed, but signature ops will fail. */
    if (!ctx->flags.hasResponderPubKey) {
        int keyRc = wolfSPDM_ExtractResponderPubKey(ctx);
        if (keyRc != WOLFSPDM_SUCCESS) {
            wolfSPDM_DebugPrint(ctx,
                "Warning: Could not extract responder public key (%d)\n", keyRc);
        }
    }

    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_KeyExchange(WOLFSPDM_CTX* ctx)
{
    byte txBuf[192];  /* KEY_EXCHANGE: ~158 bytes */
    byte rxBuf[384];  /* KEY_EXCHANGE_RSP: ~302 bytes */
    word32 txSz = sizeof(txBuf);
    word32 rxSz = sizeof(rxBuf);
    int rc;

    rc = wolfSPDM_BuildKeyExchange(ctx, txBuf, &txSz);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    wolfSPDM_TranscriptAdd(ctx, txBuf, txSz);

    rc = wolfSPDM_SendReceive(ctx, txBuf, txSz, rxBuf, &rxSz);
    if (rc != WOLFSPDM_SUCCESS) {
        wolfSPDM_DebugPrint(ctx, "KEY_EXCHANGE: SendReceive failed: %d\n", rc);
        return rc;
    }

    wolfSPDM_DebugPrint(ctx, "KEY_EXCHANGE_RSP: received %u bytes\n", rxSz);

    /* ParseKeyExchangeRsp handles transcript updates and key derivation */
    return wolfSPDM_ParseKeyExchangeRsp(ctx, rxBuf, rxSz);
}

int wolfSPDM_Finish(WOLFSPDM_CTX* ctx)
{
    byte finishBuf[152];  /* 148 bytes max for mutual auth FINISH */
    byte encBuf[256];     /* Encrypted: hdr(14) + padded(160) + tag(16) = 190 max */
    byte rxBuf[128];      /* Encrypted FINISH_RSP: ~94 bytes max */
    byte decBuf[64];      /* Decrypted FINISH_RSP: 4 hdr + 48 verify = 52 */
    word32 finishSz = sizeof(finishBuf);
    word32 encSz = sizeof(encBuf);
    word32 rxSz = sizeof(rxBuf);
    word32 decSz = sizeof(decBuf);
    int rc;

    rc = wolfSPDM_BuildFinish(ctx, finishBuf, &finishSz);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    /* FINISH must be sent encrypted (HANDSHAKE_IN_THE_CLEAR not negotiated) */
    rc = wolfSPDM_EncryptInternal(ctx, finishBuf, finishSz, encBuf, &encSz);
    if (rc != WOLFSPDM_SUCCESS) {
        wolfSPDM_DebugPrint(ctx, "FINISH encrypt failed: %d\n", rc);
        return rc;
    }

    rc = wolfSPDM_SendReceive(ctx, encBuf, encSz, rxBuf, &rxSz);
    if (rc != WOLFSPDM_SUCCESS) {
        wolfSPDM_DebugPrint(ctx, "FINISH SendReceive failed: %d\n", rc);
        return rc;
    }

    /* Check if response is unencrypted SPDM message
     * SPDM messages start with version byte (0x10-0x1F).
     * Encrypted records start with session ID. */
    if (rxSz >= 2 && rxBuf[0] >= 0x10 && rxBuf[0] <= 0x1F) {
        /* Unencrypted SPDM message - check for ERROR */
        if (rxBuf[1] == 0x7F) {  /* SPDM_ERROR */
            wolfSPDM_DebugPrint(ctx, "FINISH: peer returned SPDM ERROR 0x%02x\n",
                rxBuf[2]);
            return WOLFSPDM_E_PEER_ERROR;
        }
        wolfSPDM_DebugPrint(ctx, "FINISH: unexpected response code 0x%02x\n",
            rxBuf[1]);
        return WOLFSPDM_E_PEER_ERROR;
    }

    rc = wolfSPDM_DecryptInternal(ctx, rxBuf, rxSz, decBuf, &decSz);
    if (rc != WOLFSPDM_SUCCESS) {
        wolfSPDM_DebugPrint(ctx, "FINISH decrypt failed: %d\n", rc);
        return rc;
    }

    rc = wolfSPDM_ParseFinishRsp(ctx, decBuf, decSz);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    /* Derive application data keys (transition from handshake to app phase) */
    rc = wolfSPDM_DeriveAppDataKeys(ctx);
    if (rc != WOLFSPDM_SUCCESS) {
        wolfSPDM_DebugPrint(ctx, "App data key derivation failed: %d\n", rc);
        return rc;
    }
    return WOLFSPDM_SUCCESS;
}

/* --- Measurements (Device Attestation) --- */

#ifndef NO_WOLFSPDM_MEAS

int wolfSPDM_GetMeasurements(WOLFSPDM_CTX* ctx, byte measOperation,
    int requestSignature)
{
    byte txBuf[48];   /* GET_MEASUREMENTS: max 37 bytes (with sig request) */
    byte rxBuf[WOLFSPDM_MAX_MSG_SIZE];
    word32 txSz = sizeof(txBuf);
    word32 rxSz = sizeof(rxBuf);
    int rc;

    if (ctx == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    /* Must be at least past algorithm negotiation */
    if (ctx->state < WOLFSPDM_STATE_ALGO) {
        return WOLFSPDM_E_BAD_STATE;
    }

    /* Build GET_MEASUREMENTS request */
    rc = wolfSPDM_BuildGetMeasurements(ctx, txBuf, &txSz,
        measOperation, (byte)requestSignature);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

#ifndef NO_WOLFSPDM_MEAS_VERIFY
    /* Save request message for L1 transcript (signature verification) */
    if (txSz <= sizeof(ctx->measReqMsg)) {
        XMEMCPY(ctx->measReqMsg, txBuf, txSz);
        ctx->measReqMsgSz = txSz;
    }
#endif

    /* Send/receive: use secured exchange if session established, else cleartext */
    if (ctx->state == WOLFSPDM_STATE_CONNECTED) {
        rc = wolfSPDM_SecuredExchange(ctx, txBuf, txSz, rxBuf, &rxSz);
    }
    else {
        rc = wolfSPDM_SendReceive(ctx, txBuf, txSz, rxBuf, &rxSz);
    }
    if (rc != WOLFSPDM_SUCCESS) {
        wolfSPDM_DebugPrint(ctx, "GET_MEASUREMENTS exchange failed: %d\n", rc);
        return rc;
    }

    /* Check for SPDM error before parsing measurements */
    {
        int errCode = 0;
        if (wolfSPDM_CheckError(rxBuf, rxSz, &errCode)) {
            wolfSPDM_DebugPrint(ctx,
                "GET_MEASUREMENTS: responder error 0x%02x\n", errCode);
            return WOLFSPDM_E_PEER_ERROR;
        }
    }

    /* Parse the response */
    rc = wolfSPDM_ParseMeasurements(ctx, rxBuf, rxSz);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

#ifndef NO_WOLFSPDM_MEAS_VERIFY
    /* Verify signature if requested and signature was captured */
    if (requestSignature && ctx->measSignatureSize > 0) {
        if (!ctx->flags.hasResponderPubKey) {
            wolfSPDM_DebugPrint(ctx,
                "No responder public key — cannot verify signature\n");
            return WOLFSPDM_E_MEAS_NOT_VERIFIED;
        }

        rc = wolfSPDM_VerifyMeasurementSig(ctx, rxBuf, rxSz,
            ctx->measReqMsg, ctx->measReqMsgSz);
        if (rc != WOLFSPDM_SUCCESS) {
            return WOLFSPDM_E_MEAS_SIG_FAIL;
        }

        ctx->state = WOLFSPDM_STATE_MEASURED;
        return WOLFSPDM_SUCCESS;  /* Verified! */
    }
#else
    (void)requestSignature;
#endif /* !NO_WOLFSPDM_MEAS_VERIFY */

    /* No signature requested or verification not compiled in */
    ctx->state = WOLFSPDM_STATE_MEASURED;
    return WOLFSPDM_E_MEAS_NOT_VERIFIED;
}

#endif /* !NO_WOLFSPDM_MEAS */

/* --- Challenge Authentication (Sessionless Attestation) --- */

#ifndef NO_WOLFSPDM_CHALLENGE

int wolfSPDM_Challenge(WOLFSPDM_CTX* ctx, int slotId, byte measHashType)
{
    byte txBuf[48];   /* CHALLENGE: 36 bytes (1.2) or 46 bytes (1.3+) */
    byte rxBuf[512];  /* CHALLENGE_AUTH: variable, up to ~300+ bytes */
    word32 txSz = sizeof(txBuf);
    word32 rxSz = sizeof(rxBuf);
    word32 sigOffset = 0;
    int rc;

    if (ctx == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    /* Need cert chain for signature verification */
    if (ctx->state < WOLFSPDM_STATE_CERT) {
        return WOLFSPDM_E_BAD_STATE;
    }

    if (!ctx->flags.hasResponderPubKey) {
        wolfSPDM_DebugPrint(ctx,
            "CHALLENGE: No responder public key for verification\n");
        return WOLFSPDM_E_CHALLENGE;
    }

    /* Build CHALLENGE request */
    rc = wolfSPDM_BuildChallenge(ctx, txBuf, &txSz, slotId, measHashType);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    wolfSPDM_DebugPrint(ctx, "Sending CHALLENGE (slot=%d, measHash=0x%02x)\n",
        slotId, measHashType);

    /* Cleartext exchange (no session needed) */
    rc = wolfSPDM_SendReceive(ctx, txBuf, txSz, rxBuf, &rxSz);
    if (rc != WOLFSPDM_SUCCESS) {
        wolfSPDM_DebugPrint(ctx, "CHALLENGE: SendReceive failed: %d\n", rc);
        return rc;
    }

    /* Parse CHALLENGE_AUTH response */
    rc = wolfSPDM_ParseChallengeAuth(ctx, rxBuf, rxSz, &sigOffset);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    /* Verify signature */
    rc = wolfSPDM_VerifyChallengeAuthSig(ctx, rxBuf, rxSz,
        txBuf, txSz, sigOffset);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    wolfSPDM_DebugPrint(ctx, "CHALLENGE authentication PASSED\n");
    return WOLFSPDM_SUCCESS;
}

#endif /* !NO_WOLFSPDM_CHALLENGE */

/* --- Heartbeat (Session Keep-Alive) --- */

int wolfSPDM_Heartbeat(WOLFSPDM_CTX* ctx)
{
    byte txBuf[8];
    byte rxBuf[32];
    word32 txSz = sizeof(txBuf);
    word32 rxSz = sizeof(rxBuf);
    int rc;

    if (ctx == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (ctx->state != WOLFSPDM_STATE_CONNECTED
#ifndef NO_WOLFSPDM_MEAS
        && ctx->state != WOLFSPDM_STATE_MEASURED
#endif
        ) {
        return WOLFSPDM_E_NOT_CONNECTED;
    }

    rc = wolfSPDM_BuildHeartbeat(ctx, txBuf, &txSz);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    /* Must be sent over encrypted channel */
    rc = wolfSPDM_SecuredExchange(ctx, txBuf, txSz, rxBuf, &rxSz);
    if (rc != WOLFSPDM_SUCCESS) {
        wolfSPDM_DebugPrint(ctx, "HEARTBEAT: SecuredExchange failed: %d\n", rc);
        return rc;
    }

    return wolfSPDM_ParseHeartbeatAck(ctx, rxBuf, rxSz);
}

/* --- Key Update (Session Key Rotation) --- */

int wolfSPDM_KeyUpdate(WOLFSPDM_CTX* ctx, int updateAll)
{
    byte txBuf[8];
    byte rxBuf[32];
    word32 txSz, rxSz;
    byte tag, tag2;
    byte operation;
    int rc;

    if (ctx == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (ctx->state != WOLFSPDM_STATE_CONNECTED
#ifndef NO_WOLFSPDM_MEAS
        && ctx->state != WOLFSPDM_STATE_MEASURED
#endif
        ) {
        return WOLFSPDM_E_NOT_CONNECTED;
    }

    operation = updateAll ? SPDM_KEY_UPDATE_OP_UPDATE_ALL_KEYS
                          : SPDM_KEY_UPDATE_OP_UPDATE_KEY;

    /* Step 1: Send KEY_UPDATE encrypted with CURRENT req key */
    txSz = sizeof(txBuf);
    rc = wolfSPDM_BuildKeyUpdate(ctx, txBuf, &txSz, operation, &tag);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    wolfSPDM_DebugPrint(ctx, "Sending KEY_UPDATE\n");

    {
        byte encBuf[64];
        byte rawRxBuf[64];
        word32 encSz = sizeof(encBuf);
        word32 rawRxSz = sizeof(rawRxBuf);

        /* Encrypt with current req key */
        rc = wolfSPDM_EncryptInternal(ctx, txBuf, txSz, encBuf, &encSz);
        if (rc != WOLFSPDM_SUCCESS) {
            return rc;
        }

        /* Send and receive raw (don't decrypt yet) */
        rc = wolfSPDM_SendReceive(ctx, encBuf, encSz, rawRxBuf, &rawRxSz);
        if (rc != WOLFSPDM_SUCCESS) {
            wolfSPDM_DebugPrint(ctx, "KEY_UPDATE: SendReceive failed: %d\n", rc);
            return rc;
        }

        /* Step 2: Derive new keys BEFORE decrypting ACK.
         * The responder derives new keys upon receiving KEY_UPDATE and
         * encrypts the ACK with the NEW response key. */
        rc = wolfSPDM_DeriveUpdatedKeys(ctx, updateAll);
        if (rc != WOLFSPDM_SUCCESS) {
            wolfSPDM_DebugPrint(ctx, "KEY_UPDATE: DeriveUpdatedKeys failed: %d\n", rc);
            return rc;
        }
        ctx->reqSeqNum = 0;
        ctx->rspSeqNum = 0;

        /* Decrypt ACK with new rsp key */
        rxSz = sizeof(rxBuf);
        rc = wolfSPDM_DecryptInternal(ctx, rawRxBuf, rawRxSz, rxBuf, &rxSz);
        if (rc != WOLFSPDM_SUCCESS) {
            wolfSPDM_DebugPrint(ctx, "KEY_UPDATE: ACK decrypt failed: %d\n", rc);
            return rc;
        }
    }

    rc = wolfSPDM_ParseKeyUpdateAck(ctx, rxBuf, rxSz, operation, tag);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    /* Step 3: Verify new key works (send VERIFY_NEW_KEY with new keys) */
    txSz = sizeof(txBuf);
    rc = wolfSPDM_BuildKeyUpdate(ctx, txBuf, &txSz,
        SPDM_KEY_UPDATE_OP_VERIFY_NEW_KEY, &tag2);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    rxSz = sizeof(rxBuf);
    rc = wolfSPDM_SecuredExchange(ctx, txBuf, txSz, rxBuf, &rxSz);
    if (rc != WOLFSPDM_SUCCESS) {
        wolfSPDM_DebugPrint(ctx, "KEY_UPDATE: VerifyNewKey exchange failed: %d\n", rc);
        return rc;
    }

    rc = wolfSPDM_ParseKeyUpdateAck(ctx, rxBuf, rxSz,
        SPDM_KEY_UPDATE_OP_VERIFY_NEW_KEY, tag2);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    wolfSPDM_DebugPrint(ctx, "KEY_UPDATE completed, new keys active\n");
    return WOLFSPDM_SUCCESS;
}
