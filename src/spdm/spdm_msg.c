/* spdm_msg.c
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

int wolfSPDM_BuildGetVersion(byte* buf, word32* bufSz)
{
    /* Note: ctx is not used for GET_VERSION, check buf/bufSz directly */
    if (buf == NULL || bufSz == NULL || *bufSz < 4)
        return WOLFSPDM_E_BUFFER_SMALL;

    /* Per SPDM spec, GET_VERSION always uses version 1.0 */
    buf[0] = SPDM_VERSION_10;
    buf[1] = SPDM_GET_VERSION;
    buf[2] = 0x00;
    buf[3] = 0x00;
    *bufSz = 4;

    return WOLFSPDM_SUCCESS;
}

static int wolfSPDM_BuildSimpleMsg(WOLFSPDM_CTX* ctx, byte msgCode,
    byte* buf, word32* bufSz)
{
    SPDM_CHECK_BUILD_ARGS(ctx, buf, bufSz, 4);
    buf[0] = ctx->spdmVersion;
    buf[1] = msgCode;
    buf[2] = 0x00;
    buf[3] = 0x00;
    *bufSz = 4;
    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_BuildKeyExchange(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz)
{
    word32 offset = 0;
    byte pubKeyX[WOLFSPDM_ECC_KEY_SIZE];
    byte pubKeyY[WOLFSPDM_ECC_KEY_SIZE];
    word32 pubKeyXSz = sizeof(pubKeyX);
    word32 pubKeyYSz = sizeof(pubKeyY);
    int rc;

    SPDM_CHECK_BUILD_ARGS(ctx, buf, bufSz, 180);

    rc = wolfSPDM_GenerateEphemeralKey(ctx);
    if (rc == WOLFSPDM_SUCCESS)
        rc = wolfSPDM_ExportEphemeralPubKey(ctx, pubKeyX, &pubKeyXSz,
            pubKeyY, &pubKeyYSz);

    if (rc == WOLFSPDM_SUCCESS) {
        XMEMSET(buf, 0, *bufSz);

        /* Use negotiated SPDM version (not hardcoded 1.2) */
        buf[offset++] = ctx->spdmVersion;
        buf[offset++] = SPDM_KEY_EXCHANGE;
        buf[offset++] = 0x00;  /* MeasurementSummaryHashType = None */
#ifdef WOLFTPM_SPDM_TCG
        buf[offset++] = 0xFF;  /* SlotID = 0xFF (no cert, use provisioned public key) */
#else
        buf[offset++] = 0x00;  /* SlotID = 0 (certificate slot 0) */
#endif

        /* ReqSessionID (2 LE) */
        buf[offset++] = (byte)(ctx->reqSessionId & 0xFF);
        buf[offset++] = (byte)((ctx->reqSessionId >> 8) & 0xFF);

        buf[offset++] = 0x00;  /* SessionPolicy */
        buf[offset++] = 0x00;  /* Reserved */

        /* RandomData (32 bytes) */
        rc = wolfSPDM_GetRandom(ctx, &buf[offset], WOLFSPDM_RANDOM_SIZE);
        if (rc == WOLFSPDM_SUCCESS) {
            offset += WOLFSPDM_RANDOM_SIZE;

            /* ExchangeData: X || Y */
            XMEMCPY(&buf[offset], pubKeyX, WOLFSPDM_ECC_KEY_SIZE);
            offset += WOLFSPDM_ECC_KEY_SIZE;
            XMEMCPY(&buf[offset], pubKeyY, WOLFSPDM_ECC_KEY_SIZE);
            offset += WOLFSPDM_ECC_KEY_SIZE;

            /* OpaqueData for secured message version negotiation */
#ifdef WOLFSPDM_NUVOTON
            /* Nuvoton vendor format: 12 bytes */
            buf[offset++] = 0x0c; buf[offset++] = 0x00;
            buf[offset++] = 0x00; buf[offset++] = 0x00;
            buf[offset++] = 0x05; buf[offset++] = 0x00;
            buf[offset++] = 0x01; buf[offset++] = 0x01;
            buf[offset++] = 0x01; buf[offset++] = 0x00;
            buf[offset++] = 0x10; buf[offset++] = 0x00;
            buf[offset++] = 0x00; buf[offset++] = 0x00;
#elif defined(WOLFSPDM_NATIONS)
            /* Empty OpaqueData — Nations only accepts OpaqueLength=0 */
            buf[offset++] = 0x00; buf[offset++] = 0x00;
#else
            /* Standard SPDM 1.2+ OpaqueData format: 20 bytes */
            buf[offset++] = 0x14;  /* OpaqueLength = 20 */
            buf[offset++] = 0x00;
            buf[offset++] = 0x01; buf[offset++] = 0x00;  /* TotalElements */
            buf[offset++] = 0x00; buf[offset++] = 0x00;  /* Reserved */
            buf[offset++] = 0x00; buf[offset++] = 0x00;
            buf[offset++] = 0x09; buf[offset++] = 0x00;  /* DataSize */
            buf[offset++] = 0x01;  /* Registry ID */
            buf[offset++] = 0x01;  /* VendorLen */
            buf[offset++] = 0x03; buf[offset++] = 0x00;  /* VersionCount */
            buf[offset++] = 0x10; buf[offset++] = 0x00;  /* 1.0 */
            buf[offset++] = 0x11; buf[offset++] = 0x00;  /* 1.1 */
            buf[offset++] = 0x12; buf[offset++] = 0x00;  /* 1.2 */
            buf[offset++] = 0x00; buf[offset++] = 0x00;  /* Padding */
#endif

            *bufSz = offset;
        }
    }

    return rc;
}

/* ----- Shared Signing Helpers ----- */

/* Build SPDM 1.2+ signed hash per DSP0274:
 * M = combined_spdm_prefix || zero_pad || context_str || inputDigest
 * outputDigest = Hash(M)
 *
 * combined_spdm_prefix = "dmtf-spdm-v1.X.*" x4 = 64 bytes
 * zero_pad = (36 - contextStrLen) bytes of 0x00
 * context_str = signing context string (variable length, max 36) */
static int wolfSPDM_BuildSignedHash(byte spdmVersion,
    const char* contextStr, word32 contextStrLen,
    const byte* inputDigest, byte* outputDigest)
{
    byte signMsg[200]; /* 64 + 36 + 48 = 148 bytes max */
    word32 signMsgLen = 0;
    word32 zeroPadLen;
    byte majorVer, minorVer;
    int i, rc;

    majorVer = (byte)('0' + ((spdmVersion >> 4) & 0xF));
    minorVer = (byte)('0' + (spdmVersion & 0xF));

    /* combined_spdm_prefix: "dmtf-spdm-v1.X.*" x4 = 64 bytes */
    for (i = 0; i < 4; i++) {
        XMEMCPY(&signMsg[signMsgLen], "dmtf-spdm-v1.2.*", 16);
        signMsg[signMsgLen + 11] = majorVer;
        signMsg[signMsgLen + 13] = minorVer;
        signMsg[signMsgLen + 15] = '*';
        signMsgLen += 16;
    }

    /* Zero padding: 36 - contextStrLen bytes */
    if (contextStrLen > 36) {
        return WOLFSPDM_E_INVALID_ARG;
    }
    zeroPadLen = 36 - contextStrLen;
    XMEMSET(&signMsg[signMsgLen], 0x00, zeroPadLen);
    signMsgLen += zeroPadLen;

    /* Signing context string */
    XMEMCPY(&signMsg[signMsgLen], contextStr, contextStrLen);
    signMsgLen += contextStrLen;

    /* Input digest */
    XMEMCPY(&signMsg[signMsgLen], inputDigest, WOLFSPDM_HASH_SIZE);
    signMsgLen += WOLFSPDM_HASH_SIZE;

    /* Hash M */
    rc = wolfSPDM_Sha384Hash(outputDigest, signMsg, signMsgLen,
        NULL, 0, NULL, 0);
    if (rc != WOLFSPDM_SUCCESS) return rc;

    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_BuildFinish(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz)
{
    byte th2Hash[WOLFSPDM_HASH_SIZE];
    byte verifyData[WOLFSPDM_HASH_SIZE];
    byte signature[WOLFSPDM_ECC_POINT_SIZE];  /* 96 bytes for P-384 */
    word32 sigSz = sizeof(signature);
    word32 offset = 4;  /* Start after header */
    word32 minSz;
    int mutualAuth = 0;
    int rc;

    /* Check arguments first before any ctx dereference */
    if (ctx == NULL || buf == NULL || bufSz == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    /* Mutual auth is enabled when the responder requested it (MutAuthRequested
     * bit 0) AND we have a requester key pair to sign with */
    if ((ctx->mutAuthRequested & 0x01) && ctx->flags.hasReqKeyPair) {
        mutualAuth = 1;
        wolfSPDM_DebugPrint(ctx, "FINISH: Mutual auth ENABLED "
            "(MutAuth=0x%02x ReqSlot=0x%02x)\n",
            ctx->mutAuthRequested, ctx->reqSlotIdParam);
    }

    /* Check buffer size: header(4) + [OpaqueLength(2) for 1.4+] +
     * [signature(96) for mutual auth] + HMAC(48) */
    minSz = 4 + WOLFSPDM_HASH_SIZE;  /* header + HMAC */
    if (ctx->spdmVersion >= SPDM_VERSION_14)
        minSz += 2;  /* OpaqueLength */
    if (mutualAuth)
        minSz += WOLFSPDM_ECC_POINT_SIZE;  /* Signature */
    if (*bufSz < minSz)
        return WOLFSPDM_E_BUFFER_SMALL;

    /* Build FINISH header */
    buf[0] = ctx->spdmVersion;
    buf[1] = SPDM_FINISH;
    if (mutualAuth) {
        buf[2] = 0x01;  /* Param1: Signature field is included */
        /* Param2: For PUB_KEY_ID mode, shall be 0xFF per DSP0274 */
        buf[3] = 0xFF;
    } else {
        buf[2] = 0x00;  /* Param1: No signature */
        buf[3] = 0x00;  /* Param2: SlotID = 0 when no signature */
    }

    /* SPDM 1.4 adds OpaqueLength(2) + OpaqueData(var) after header */
    if (ctx->spdmVersion >= SPDM_VERSION_14) {
        buf[offset++] = 0x00;  /* OpaqueLength = 0 (LE) */
        buf[offset++] = 0x00;
    }

    rc = WOLFSPDM_SUCCESS;

    /* Mutual auth: add Hash(Cm_requester) to transcript between message_k
     * and FINISH header. For PUB_KEY_ID mode, Cm = SHA-384(TPMT_PUBLIC)
     * of the requester's public key (matching how Ct is computed for
     * responder per TCG SPDM binding). */
#ifdef WOLFTPM_SPDM_TCG
    if (rc == WOLFSPDM_SUCCESS && mutualAuth && ctx->reqPubKeyTPMTLen > 0) {
        byte cmHash[WOLFSPDM_HASH_SIZE];
        rc = wolfSPDM_Sha384Hash(cmHash, ctx->reqPubKeyTPMT,
            ctx->reqPubKeyTPMTLen, NULL, 0, NULL, 0);
        if (rc == WOLFSPDM_SUCCESS)
            rc = wolfSPDM_TranscriptAdd(ctx, cmHash, WOLFSPDM_HASH_SIZE);
    }
#endif

    /* Add FINISH header to transcript, compute TH2 */
    if (rc == WOLFSPDM_SUCCESS)
        rc = wolfSPDM_TranscriptAdd(ctx, buf, offset);
    if (rc == WOLFSPDM_SUCCESS)
        rc = wolfSPDM_TranscriptHash(ctx, th2Hash);
    if (rc == WOLFSPDM_SUCCESS)
        XMEMCPY(ctx->th2, th2Hash, WOLFSPDM_HASH_SIZE);

    /* Mutual auth: sign TH2, add signature to transcript, recompute TH2 */
    if (rc == WOLFSPDM_SUCCESS && mutualAuth) {
        byte signMsgHash[WOLFSPDM_HASH_SIZE];

        rc = wolfSPDM_BuildSignedHash(ctx->spdmVersion,
            "requester-finish signing", 24, th2Hash, signMsgHash);
        if (rc == WOLFSPDM_SUCCESS)
            rc = wolfSPDM_SignHash(ctx, signMsgHash, WOLFSPDM_HASH_SIZE,
                signature, &sigSz);
        if (rc == WOLFSPDM_SUCCESS) {
            XMEMCPY(&buf[offset], signature, WOLFSPDM_ECC_POINT_SIZE);
            offset += WOLFSPDM_ECC_POINT_SIZE;
            rc = wolfSPDM_TranscriptAdd(ctx, signature,
                WOLFSPDM_ECC_POINT_SIZE);
        }
        if (rc == WOLFSPDM_SUCCESS)
            rc = wolfSPDM_TranscriptHash(ctx, th2Hash);
    }

    /* RequesterVerifyData = HMAC(reqFinishedKey, TH2) */
    if (rc == WOLFSPDM_SUCCESS)
        rc = wolfSPDM_ComputeVerifyData(ctx->reqFinishedKey, th2Hash,
            verifyData);
    if (rc == WOLFSPDM_SUCCESS) {
        XMEMCPY(&buf[offset], verifyData, WOLFSPDM_HASH_SIZE);
        offset += WOLFSPDM_HASH_SIZE;
        rc = wolfSPDM_TranscriptAdd(ctx, verifyData, WOLFSPDM_HASH_SIZE);
    }
    if (rc == WOLFSPDM_SUCCESS)
        *bufSz = offset;

    /* Always zero sensitive stack buffers */
    wc_ForceZero(th2Hash, sizeof(th2Hash));
    wc_ForceZero(verifyData, sizeof(verifyData));
    wc_ForceZero(signature, sizeof(signature));
    return rc;
}

int wolfSPDM_BuildEndSession(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz)
{
    return wolfSPDM_BuildSimpleMsg(ctx, SPDM_END_SESSION, buf, bufSz);
}

int wolfSPDM_CheckError(const byte* buf, word32 bufSz, int* errorCode)
{
    if (buf == NULL || bufSz < 4) {
        return 0;
    }

    if (buf[1] == SPDM_ERROR) {
        if (errorCode != NULL) {
            *errorCode = buf[2];
        }
        return 1;
    }

    return 0;
}

/* Maximum SPDM version we support. Supports SPDM 1.2 through 1.4.
 * Override with -DWOLFSPDM_MAX_SPDM_VERSION at compile time to cap
 * at a lower version. */
#ifndef WOLFSPDM_MAX_SPDM_VERSION
#define WOLFSPDM_MAX_SPDM_VERSION  SPDM_VERSION_14
#endif

/* Minimum SPDM version we require. Our key derivation uses BinConcat
 * format ("spdm1.2 " prefix) which is a 1.2+ feature. SPDM 1.1 uses
 * a different HKDF label format and would require separate key
 * derivation code. Override at compile time if 1.1 support is added. */
#ifndef WOLFSPDM_MIN_SPDM_VERSION
#define WOLFSPDM_MIN_SPDM_VERSION  SPDM_VERSION_12
#endif

int wolfSPDM_ParseVersion(WOLFSPDM_CTX* ctx, const byte* buf, word32 bufSz)
{
    word16 entryCount;
    word16 maxEntries;
    word32 i;
    byte highestVersion = 0;  /* No version found yet */
    byte maxVer;

    SPDM_CHECK_PARSE_ARGS(ctx, buf, bufSz, 6);
    SPDM_CHECK_RESPONSE(ctx, buf, bufSz, SPDM_VERSION, WOLFSPDM_E_VERSION_MISMATCH);

    /* Parse VERSION response:
     * Offset 4-5: VersionNumberEntryCount (LE)
     * Offset 6+: VersionNumberEntry array (2 bytes each, LE) */
    entryCount = SPDM_Get16LE(&buf[4]);

    /* Cap entryCount to what actually fits in the buffer to prevent
     * overflow on exotic compilers where i*2 could wrap */
    maxEntries = (word16)((bufSz - 6) / 2);
    if (entryCount > maxEntries) {
        entryCount = maxEntries;
    }

    /* Find highest mutually supported version.
     * Per DSP0274, negotiated version must be the highest version
     * that both sides support. We support WOLFSPDM_MIN_SPDM_VERSION
     * through WOLFSPDM_MAX_SPDM_VERSION (or ctx->maxVersion if set). */
    maxVer = (ctx->maxVersion != 0) ? ctx->maxVersion
                                          : WOLFSPDM_MAX_SPDM_VERSION;
    for (i = 0; i < entryCount; i++) {
        /* Each entry is 2 bytes; high byte (offset +1) is Major.Minor */
        byte ver = buf[6 + i * 2 + 1];
        if (ver >= WOLFSPDM_MIN_SPDM_VERSION &&
            ver <= maxVer &&
            ver > highestVersion) {
            highestVersion = ver;
        }
    }

    /* If no mutually supported version found, fail */
    if (highestVersion == 0) {
        wolfSPDM_DebugPrint(ctx, "No mutually supported SPDM version found "
            "(require >= 0x%02x)\n", WOLFSPDM_MIN_SPDM_VERSION);
        return WOLFSPDM_E_VERSION_MISMATCH;
    }

    ctx->spdmVersion = highestVersion;
    ctx->state = WOLFSPDM_STATE_VERSION;

    wolfSPDM_DebugPrint(ctx, "Negotiated SPDM version: 0x%02x\n", ctx->spdmVersion);
    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_ParseKeyExchangeRsp(WOLFSPDM_CTX* ctx, const byte* buf, word32 bufSz)
{
    word16 opaqueLen;
    word32 sigOffset;
    word32 keRspPartialLen;
    byte peerPubKeyX[WOLFSPDM_ECC_KEY_SIZE];
    byte peerPubKeyY[WOLFSPDM_ECC_KEY_SIZE];
    byte th1SigHash[WOLFSPDM_HASH_SIZE];
    byte signMsgHash[WOLFSPDM_HASH_SIZE];
    byte expectedHmac[WOLFSPDM_HASH_SIZE];
    const byte* signature;
    const byte* rspVerifyData;
    int rc;

    SPDM_CHECK_PARSE_ARGS(ctx, buf, bufSz, 140);
    SPDM_CHECK_RESPONSE(ctx, buf, bufSz, SPDM_KEY_EXCHANGE_RSP, WOLFSPDM_E_KEY_EXCHANGE);

    ctx->rspSessionId = SPDM_Get16LE(&buf[4]);
    ctx->sessionId = (word32)ctx->reqSessionId | ((word32)ctx->rspSessionId << 16);

    /* Parse MutAuthRequested and ReqSlotIDParam (offsets 6-7) */
    ctx->mutAuthRequested = buf[6];
    ctx->reqSlotIdParam = buf[7];
    wolfSPDM_DebugPrint(ctx, "KEY_EXCHANGE_RSP: MutAuth=0x%02x ReqSlotID=0x%02x\n",
        ctx->mutAuthRequested, ctx->reqSlotIdParam);

    /* Extract responder's ephemeral public key (offset 40 = 4+2+1+1+32) */
    XMEMCPY(peerPubKeyX, &buf[40], WOLFSPDM_ECC_KEY_SIZE);
    XMEMCPY(peerPubKeyY, &buf[88], WOLFSPDM_ECC_KEY_SIZE);

    /* OpaqueLen at offset 136 */
    opaqueLen = SPDM_Get16LE(&buf[136]);
    sigOffset = 138 + opaqueLen;
    keRspPartialLen = sigOffset;

    if (bufSz < sigOffset + WOLFSPDM_ECC_SIG_SIZE + WOLFSPDM_HASH_SIZE) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    signature = buf + sigOffset;
    rspVerifyData = buf + sigOffset + WOLFSPDM_ECC_SIG_SIZE;

    /* Add KEY_EXCHANGE_RSP partial (without sig/verify) to transcript */
    rc = wolfSPDM_TranscriptAdd(ctx, buf, keRspPartialLen);

    /* Verify responder signature over TH1 (DSP0274). Responder public key
     * must be provisioned before KEY_EXCHANGE. */
    if (rc == WOLFSPDM_SUCCESS && !ctx->flags.hasRspPubKey) {
        wolfSPDM_DebugPrint(ctx, "No responder public key set\n");
        rc = WOLFSPDM_E_BAD_STATE;
    }
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_TranscriptHash(ctx, th1SigHash);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_BuildSignedHash(ctx->spdmVersion,
            "responder-key_exchange_rsp signing", 34,
            th1SigHash, signMsgHash);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_VerifySignature(ctx, signMsgHash, WOLFSPDM_HASH_SIZE,
            signature, WOLFSPDM_ECC_SIG_SIZE);
        if (rc != WOLFSPDM_SUCCESS)
            wolfSPDM_DebugPrint(ctx, "KEY_EXCHANGE_RSP signature INVALID\n");
    }
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_TranscriptAdd(ctx, signature, WOLFSPDM_ECC_SIG_SIZE);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_ComputeSharedSecret(ctx, peerPubKeyX, peerPubKeyY);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_TranscriptHash(ctx, ctx->th1);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_DeriveHandshakeKeys(ctx, ctx->th1);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_ComputeVerifyData(ctx->rspFinishedKey, ctx->th1, expectedHmac);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        word32 i;
        int diff = 0;
        for (i = 0; i < WOLFSPDM_HASH_SIZE; i++) {
            diff |= expectedHmac[i] ^ rspVerifyData[i];
        }
        if (diff != 0) {
            wolfSPDM_DebugPrint(ctx, "ResponderVerifyData MISMATCH\n");
            rc = WOLFSPDM_E_BAD_HMAC;
        }
    }
    if (rc == WOLFSPDM_SUCCESS) {
        wolfSPDM_DebugPrint(ctx, "ResponderVerifyData VERIFIED OK\n");
        rc = wolfSPDM_TranscriptAdd(ctx, rspVerifyData, WOLFSPDM_HASH_SIZE);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        ctx->state = WOLFSPDM_STATE_KEY_EX;
    }

    wc_ForceZero(expectedHmac, sizeof(expectedHmac));
    wc_ForceZero(th1SigHash, sizeof(th1SigHash));
    wc_ForceZero(signMsgHash, sizeof(signMsgHash));
    return rc;
}

int wolfSPDM_ParseFinishRsp(WOLFSPDM_CTX* ctx, const byte* buf, word32 bufSz)
{
    SPDM_CHECK_PARSE_ARGS(ctx, buf, bufSz, 4);

    if (buf[1] == SPDM_FINISH_RSP) {
        int addRc;
        word32 rspMsgLen = 4;

        /* SPDM 1.4 adds OpaqueLength(2) + OpaqueData(var) to FINISH_RSP */
        if (ctx->spdmVersion >= SPDM_VERSION_14) {
            word16 opaqueLen;
            if (bufSz < 6) {
                return WOLFSPDM_E_BUFFER_SMALL;
            }
            opaqueLen = SPDM_Get16LE(&buf[4]);
            rspMsgLen = 4 + 2 + opaqueLen;
            if (bufSz < rspMsgLen) {
                return WOLFSPDM_E_BUFFER_SMALL;
            }
        }

        /* Add FINISH_RSP (header + OpaqueData for 1.4) to transcript */
        addRc = wolfSPDM_TranscriptAdd(ctx, buf, rspMsgLen);
        if (addRc != WOLFSPDM_SUCCESS) {
            return addRc;
        }
        ctx->state = WOLFSPDM_STATE_FINISH;
        wolfSPDM_DebugPrint(ctx, "FINISH_RSP received - session established\n");
        return WOLFSPDM_SUCCESS;
    }

    if (buf[1] == SPDM_ERROR) {
        wolfSPDM_DebugPrint(ctx, "FINISH error: 0x%02x\n", buf[2]);
        return WOLFSPDM_E_PEER_ERROR;
    }

    return WOLFSPDM_E_BAD_STATE;
}

/* PSK message builders/parsers moved to spdm_psk.c */

#endif /* WOLFTPM_SPDM */
