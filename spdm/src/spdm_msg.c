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

#include "spdm_internal.h"
#include <wolfssl/wolfcrypt/asn.h>

int wolfSPDM_BuildGetVersion(byte* buf, word32* bufSz)
{
    /* Note: ctx is not used for GET_VERSION, check buf/bufSz directly */
    if (buf == NULL || bufSz == NULL || *bufSz < 4)
        return WOLFSPDM_E_BUFFER_SMALL;

    /* Per SPDM spec, GET_VERSION always uses version 0x10 */
    buf[0] = SPDM_VERSION_10;
    buf[1] = SPDM_GET_VERSION;
    buf[2] = 0x00;
    buf[3] = 0x00;
    *bufSz = 4;

    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_BuildGetCapabilities(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz)
{
    SPDM_CHECK_BUILD_ARGS(ctx, buf, bufSz, 20);

    XMEMSET(buf, 0, 20);
    buf[0] = ctx->spdmVersion;  /* Use negotiated version */
    buf[1] = SPDM_GET_CAPABILITIES;
    buf[2] = 0x00;
    buf[3] = 0x00;
    /* CTExponent and reserved at offsets 4-7 */

    /* Requester flags (4 bytes LE) */
    SPDM_Set32LE(&buf[8], ctx->reqCaps);

    /* DataTransferSize (4 LE) */
    SPDM_Set32LE(&buf[12], WOLFSPDM_MAX_MSG_SIZE);
    /* MaxSPDMmsgSize (4 LE) */
    SPDM_Set32LE(&buf[16], WOLFSPDM_MAX_MSG_SIZE);

    *bufSz = 20;
    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_BuildNegotiateAlgorithms(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz)
{
    SPDM_CHECK_BUILD_ARGS(ctx, buf, bufSz, 48);

    XMEMSET(buf, 0, 48);
    buf[0] = ctx->spdmVersion;  /* Use negotiated version */
    buf[1] = SPDM_NEGOTIATE_ALGORITHMS;
    buf[2] = 0x04;  /* NumAlgoStructTables = 4 */
    buf[3] = 0x00;
    buf[4] = 48; buf[5] = 0x00;  /* Length = 48 */
    buf[6] = 0x01;  /* MeasurementSpecification = DMTF */
    buf[7] = 0x02;  /* OtherParamsSupport = MULTI_KEY_CONN */

    /* BaseAsymAlgo: ECDSA P-384 (bit 7) */
    buf[8] = 0x80; buf[9] = 0x00; buf[10] = 0x00; buf[11] = 0x00;
    /* BaseHashAlgo: SHA-384 (bit 1) */
    buf[12] = 0x02; buf[13] = 0x00; buf[14] = 0x00; buf[15] = 0x00;

    /* Struct tables start at offset 32 */
    /* DHE: SECP_384_R1 */
    buf[32] = 0x02; buf[33] = 0x20; buf[34] = 0x10; buf[35] = 0x00;
    /* AEAD: AES_256_GCM */
    buf[36] = 0x03; buf[37] = 0x20; buf[38] = 0x02; buf[39] = 0x00;
    /* ReqBaseAsymAlg */
    buf[40] = 0x04; buf[41] = 0x20; buf[42] = 0x0F; buf[43] = 0x00;
    /* KeySchedule */
    buf[44] = 0x05; buf[45] = 0x20; buf[46] = 0x01; buf[47] = 0x00;

    *bufSz = 48;
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

int wolfSPDM_BuildGetDigests(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz)
{
    return wolfSPDM_BuildSimpleMsg(ctx, SPDM_GET_DIGESTS, buf, bufSz);
}

int wolfSPDM_BuildGetCertificate(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz,
    int slotId, word16 offset, word16 length)
{
    SPDM_CHECK_BUILD_ARGS(ctx, buf, bufSz, 8);

    buf[0] = ctx->spdmVersion;  /* Use negotiated version */
    buf[1] = SPDM_GET_CERTIFICATE;
    buf[2] = (byte)(slotId & 0x0F);
    buf[3] = 0x00;
    SPDM_Set16LE(&buf[4], offset);
    SPDM_Set16LE(&buf[6], length);
    *bufSz = 8;

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
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    rc = wolfSPDM_ExportEphemeralPubKey(ctx, pubKeyX, &pubKeyXSz,
        pubKeyY, &pubKeyYSz);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    XMEMSET(buf, 0, *bufSz);

    /* Use negotiated SPDM version (not hardcoded 1.2) */
    buf[offset++] = ctx->spdmVersion;
    buf[offset++] = SPDM_KEY_EXCHANGE;
    buf[offset++] = 0x00;  /* MeasurementSummaryHashType = None */
#ifdef WOLFSPDM_NUVOTON
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
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }
    offset += WOLFSPDM_RANDOM_SIZE;

    /* ExchangeData: X || Y */
    XMEMCPY(&buf[offset], pubKeyX, WOLFSPDM_ECC_KEY_SIZE);
    offset += WOLFSPDM_ECC_KEY_SIZE;
    XMEMCPY(&buf[offset], pubKeyY, WOLFSPDM_ECC_KEY_SIZE);
    offset += WOLFSPDM_ECC_KEY_SIZE;

    /* OpaqueData for secured message version negotiation */
#ifdef WOLFSPDM_NUVOTON
    /* Nuvoton format: 12 bytes per spec Rev 1.11 page 19-20
     * OpaqueLength(2 LE) + OpaqueData(12 bytes) = 14 bytes total */
    buf[offset++] = 0x0c;  /* OpaqueLength = 12 (LE) */
    buf[offset++] = 0x00;
    buf[offset++] = 0x00; buf[offset++] = 0x00;  /* SMDataID = 0 */
    buf[offset++] = 0x05; buf[offset++] = 0x00;  /* DataSize = 5 (LE) */
    buf[offset++] = 0x01;  /* Registry ID = 1 (DMTF) */
    buf[offset++] = 0x01;  /* VendorLen = 1 */
    buf[offset++] = 0x01; buf[offset++] = 0x00;  /* VersionCount = 1, Reserved = 0 */
    buf[offset++] = 0x10; buf[offset++] = 0x00;  /* Version 1.0 (0x0010 LE) */
    buf[offset++] = 0x00; buf[offset++] = 0x00;  /* Padding to make OpaqueData 12 bytes */
#else
    /* Standard SPDM 1.2+ OpaqueData format: 20 bytes
     * OpaqueLength must be a multiple of 4 per DSP0274. */
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
    return WOLFSPDM_SUCCESS;
}

/* --- Shared Signing Helpers --- */

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

/* Verify an SPDM ECDSA signature (raw r||s format) against a digest
 * using the responder's public key stored in ctx. */
static int wolfSPDM_VerifyEccSig(WOLFSPDM_CTX* ctx,
    const byte* sigRaw, word32 sigRawSz,
    const byte* digest, word32 digestSz)
{
    byte derSig[256];
    word32 derSigSz = sizeof(derSig);
    const byte* sigR = sigRaw;
    const byte* sigS = sigRaw + (sigRawSz / 2);
    int verified = 0;
    int rc;

    rc = wc_ecc_rs_raw_to_sig(sigR, sigRawSz / 2,
        sigS, sigRawSz / 2, derSig, &derSigSz);
    if (rc != 0) {
        wolfSPDM_DebugPrint(ctx, "ECC rs_raw_to_sig failed: %d\n", rc);
        return WOLFSPDM_E_CRYPTO_FAIL;
    }

    rc = wc_ecc_verify_hash(derSig, derSigSz, digest, digestSz,
        &verified, &ctx->responderPubKey);
    if (rc != 0) {
        wolfSPDM_DebugPrint(ctx, "ECC verify_hash failed: %d\n", rc);
        return WOLFSPDM_E_CRYPTO_FAIL;
    }

    return verified == 1 ? WOLFSPDM_SUCCESS : WOLFSPDM_E_CRYPTO_FAIL;
}

int wolfSPDM_BuildFinish(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz)
{
    byte th2Hash[WOLFSPDM_HASH_SIZE];
    byte verifyData[WOLFSPDM_HASH_SIZE];
    byte signature[WOLFSPDM_ECC_POINT_SIZE];  /* 96 bytes for P-384 */
    word32 sigSz = sizeof(signature);
    word32 offset = 4;  /* Start after header */
    int mutualAuth = 0;
    int rc;

    /* Check arguments first before any ctx dereference */
    if (ctx == NULL || buf == NULL || bufSz == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

#ifdef WOLFSPDM_NUVOTON
    /* Nuvoton requires mutual authentication when we have a requester key */
    if (ctx->mode == WOLFSPDM_MODE_NUVOTON && ctx->flags.hasReqKeyPair) {
        mutualAuth = 1;
        wolfSPDM_DebugPrint(ctx, "Nuvoton: Mutual auth ENABLED (required after GIVE_PUB)\n");
    }
#endif

    /* Check buffer size: header(4) + [OpaqueLength(2) for 1.4+] +
     * [signature(96) for mutual auth] + HMAC(48) */
    {
        word32 minSz = 4 + WOLFSPDM_HASH_SIZE;  /* header + HMAC */
        if (ctx->spdmVersion >= SPDM_VERSION_14)
            minSz += 2;  /* OpaqueLength */
        if (mutualAuth)
            minSz += WOLFSPDM_ECC_POINT_SIZE;  /* Signature */
        if (*bufSz < minSz)
            return WOLFSPDM_E_BUFFER_SMALL;
    }

    /* Build FINISH header */
    buf[0] = ctx->spdmVersion;
    buf[1] = SPDM_FINISH;
    if (mutualAuth) {
        buf[2] = 0x01;  /* Param1: Signature field is included */
        buf[3] = 0xFF;  /* Param2: 0xFF = requester public key provisioned in trusted environment (GIVE_PUB_KEY) */
    }
    else {
        buf[2] = 0x00;  /* Param1: No signature */
        buf[3] = 0x00;  /* Param2: SlotID = 0 when no signature */
    }

    /* SPDM 1.4 adds OpaqueLength(2) + OpaqueData(var) after header */
    if (ctx->spdmVersion >= SPDM_VERSION_14) {
        buf[offset++] = 0x00;  /* OpaqueLength = 0 (LE) */
        buf[offset++] = 0x00;
    }

    /* Per DSP0274 / libspdm: When mutual auth is requested, the transcript
     * for TH2 must include Hash(Cm_requester) - the hash of the requester's
     * public key/cert chain - BETWEEN message_k and message_f (FINISH header).
     *
     * TH2 = Hash(VCA || Ct || message_k || Hash(Cm_req) || FINISH_header)
     *
     * For Nuvoton with PUB_KEY_ID (SlotID=0xFF), Cm is the TPMT_PUBLIC
     * structure that was sent via GIVE_PUB_KEY. */
#ifdef WOLFSPDM_NUVOTON
    if (mutualAuth && ctx->reqPubKeyTPMTLen > 0) {
        byte cmHash[WOLFSPDM_HASH_SIZE];
        rc = wolfSPDM_Sha384Hash(cmHash, ctx->reqPubKeyTPMT,
            ctx->reqPubKeyTPMTLen, NULL, 0, NULL, 0);
        if (rc != WOLFSPDM_SUCCESS) return rc;
        rc = wolfSPDM_TranscriptAdd(ctx, cmHash, WOLFSPDM_HASH_SIZE);
        if (rc != WOLFSPDM_SUCCESS) return rc;
    }
#endif

    /* Add FINISH header (+ OpaqueLength for 1.4) to transcript for TH2 */
    rc = wolfSPDM_TranscriptAdd(ctx, buf, offset);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    /* TH2 = Hash(transcript with FINISH header) */
    rc = wolfSPDM_TranscriptHash(ctx, th2Hash);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    XMEMCPY(ctx->th2, th2Hash, WOLFSPDM_HASH_SIZE);

    /* For mutual auth, use SPDM 1.2+ signing context format per DSP0274 */
    if (mutualAuth) {
        byte signMsgHash[WOLFSPDM_HASH_SIZE];

        rc = wolfSPDM_BuildSignedHash(ctx->spdmVersion,
            "requester-finish signing", 24, th2Hash, signMsgHash);
        if (rc != WOLFSPDM_SUCCESS) {
            return rc;
        }

        /* Sign Hash(M) */
        rc = wolfSPDM_SignHash(ctx, signMsgHash, WOLFSPDM_HASH_SIZE, signature, &sigSz);
        if (rc != WOLFSPDM_SUCCESS) {
            wolfSPDM_DebugPrint(ctx, "Failed to sign FINISH: %d\n", rc);
            return rc;
        }

        /* Copy signature to buffer (96 bytes) */
        XMEMCPY(&buf[offset], signature, WOLFSPDM_ECC_POINT_SIZE);
        offset += WOLFSPDM_ECC_POINT_SIZE;

        /* Per DSP0274: TH2 for RequesterVerifyData MUST include the signature.
         * TH2_sign = Hash(transcript || FINISH_header[4])  - used above for signature
         * TH2_hmac = Hash(transcript || FINISH_header[4] || Signature[96])  - used for HMAC
         * Add signature to transcript and recompute TH2 for HMAC. */
        rc = wolfSPDM_TranscriptAdd(ctx, signature, WOLFSPDM_ECC_POINT_SIZE);
        if (rc != WOLFSPDM_SUCCESS) {
            return rc;
        }

        rc = wolfSPDM_TranscriptHash(ctx, th2Hash);
        if (rc != WOLFSPDM_SUCCESS) {
            return rc;
        }

    }

    /* RequesterVerifyData = HMAC(reqFinishedKey, TH2_hmac)
     * For mutual auth: th2Hash now includes the signature (TH2_hmac)
     * For no mutual auth: th2Hash is just Hash(transcript || FINISH_header) */
    rc = wolfSPDM_ComputeVerifyData(ctx->reqFinishedKey, th2Hash, verifyData);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    XMEMCPY(&buf[offset], verifyData, WOLFSPDM_HASH_SIZE);
    offset += WOLFSPDM_HASH_SIZE;

    /* Add RequesterVerifyData to transcript for TH2_final (app data key derivation) */
    rc = wolfSPDM_TranscriptAdd(ctx, verifyData, WOLFSPDM_HASH_SIZE);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    *bufSz = offset;
    return WOLFSPDM_SUCCESS;
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
 * at a lower version. Runtime override via wolfSPDM_SetMaxVersion(). */
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
    {
        byte maxVer = (ctx->maxVersion != 0) ? ctx->maxVersion
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

int wolfSPDM_ParseCapabilities(WOLFSPDM_CTX* ctx, const byte* buf, word32 bufSz)
{
    SPDM_CHECK_PARSE_ARGS(ctx, buf, bufSz, 12);
    SPDM_CHECK_RESPONSE(ctx, buf, bufSz, SPDM_CAPABILITIES, WOLFSPDM_E_CAPS_MISMATCH);

    ctx->rspCaps = SPDM_Get32LE(&buf[8]);
    ctx->state = WOLFSPDM_STATE_CAPS;

    wolfSPDM_DebugPrint(ctx, "Responder caps: 0x%08x\n", ctx->rspCaps);
    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_ParseAlgorithms(WOLFSPDM_CTX* ctx, const byte* buf, word32 bufSz)
{
    word32 baseAsymAlgo;
    word32 baseHashAlgo;

    SPDM_CHECK_PARSE_ARGS(ctx, buf, bufSz, 36);
    SPDM_CHECK_RESPONSE(ctx, buf, bufSz, SPDM_ALGORITHMS, WOLFSPDM_E_ALGO_MISMATCH);

    /* Validate negotiated algorithms match Algorithm Set B.
     * ALGORITHMS response layout (DSP0274 Table 18):
     *   Offset 8-11:  MeasurementHashAlgo (4 LE)
     *   Offset 12-15: BaseAsymSel (4 LE)
     *   Offset 16-19: BaseHashSel (4 LE)
     * Note: Response has MeasurementHashAlgo before BaseAsymSel,
     * unlike the request which has BaseAsymAlgo at offset 8. */
    baseAsymAlgo = SPDM_Get32LE(&buf[12]);
    baseHashAlgo = SPDM_Get32LE(&buf[16]);

    if (!(baseAsymAlgo & SPDM_ASYM_ALGO_ECDSA_P384)) {
        wolfSPDM_DebugPrint(ctx,
            "ALGORITHMS: responder does not support ECDSA P-384 (0x%08x)\n",
            baseAsymAlgo);
        return WOLFSPDM_E_ALGO_MISMATCH;
    }
    if (!(baseHashAlgo & SPDM_HASH_ALGO_SHA_384)) {
        wolfSPDM_DebugPrint(ctx,
            "ALGORITHMS: responder does not support SHA-384 (0x%08x)\n",
            baseHashAlgo);
        return WOLFSPDM_E_ALGO_MISMATCH;
    }

    wolfSPDM_DebugPrint(ctx, "ALGORITHMS: BaseAsym=0x%08x BaseHash=0x%08x\n",
        baseAsymAlgo, baseHashAlgo);

    ctx->state = WOLFSPDM_STATE_ALGO;
    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_ParseDigests(WOLFSPDM_CTX* ctx, const byte* buf, word32 bufSz)
{
    SPDM_CHECK_PARSE_ARGS(ctx, buf, bufSz, 4);
    SPDM_CHECK_RESPONSE(ctx, buf, bufSz, SPDM_DIGESTS, WOLFSPDM_E_CERT_FAIL);

    ctx->state = WOLFSPDM_STATE_DIGESTS;
    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_ParseCertificate(WOLFSPDM_CTX* ctx, const byte* buf, word32 bufSz,
    word16* portionLen, word16* remainderLen)
{
    if (ctx == NULL || buf == NULL || bufSz < 8 ||
        portionLen == NULL || remainderLen == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    SPDM_CHECK_RESPONSE(ctx, buf, bufSz, SPDM_CERTIFICATE, WOLFSPDM_E_CERT_FAIL);

    *portionLen = SPDM_Get16LE(&buf[4]);
    *remainderLen = SPDM_Get16LE(&buf[6]);

    /* Add certificate chain data (starting at offset 8) */
    if (*portionLen > 0 && bufSz >= (word32)(8 + *portionLen)) {
        wolfSPDM_CertChainAdd(ctx, buf + 8, *portionLen);
    }

    if (*remainderLen == 0) {
        ctx->state = WOLFSPDM_STATE_CERT;
    }

    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_ParseKeyExchangeRsp(WOLFSPDM_CTX* ctx, const byte* buf, word32 bufSz)
{
    word16 opaqueLen;
    word32 sigOffset;
    word32 keRspPartialLen;
    byte peerPubKeyX[WOLFSPDM_ECC_KEY_SIZE];
    byte peerPubKeyY[WOLFSPDM_ECC_KEY_SIZE];
    const byte* signature;
    const byte* rspVerifyData;
    byte expectedHmac[WOLFSPDM_HASH_SIZE];
    int rc;

    SPDM_CHECK_PARSE_ARGS(ctx, buf, bufSz, 140);
    SPDM_CHECK_RESPONSE(ctx, buf, bufSz, SPDM_KEY_EXCHANGE_RSP, WOLFSPDM_E_KEY_EXCHANGE);

    ctx->rspSessionId = SPDM_Get16LE(&buf[4]);
    ctx->sessionId = (word32)ctx->reqSessionId | ((word32)ctx->rspSessionId << 16);

    /* Parse MutAuthRequested (offset 6) and ReqSlotIDParam (offset 7) per DSP0274 */
    ctx->mutAuthRequested = buf[6];
    ctx->reqSlotId = buf[7];

    /* Extract responder's ephemeral public key (offset 40 = 4+2+1+1+32) */
    XMEMCPY(peerPubKeyX, &buf[40], WOLFSPDM_ECC_KEY_SIZE);
    XMEMCPY(peerPubKeyY, &buf[88], WOLFSPDM_ECC_KEY_SIZE);

    /* OpaqueLen at offset 136 */
    opaqueLen = SPDM_Get16LE(&buf[136]);
    sigOffset = 138 + opaqueLen;
    keRspPartialLen = sigOffset;

    (void)opaqueLen;

    if (bufSz < sigOffset + WOLFSPDM_ECC_SIG_SIZE + WOLFSPDM_HASH_SIZE) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    signature = buf + sigOffset;
    rspVerifyData = buf + sigOffset + WOLFSPDM_ECC_SIG_SIZE;

    /* Add KEY_EXCHANGE_RSP partial (without sig/verify) to transcript */
    rc = wolfSPDM_TranscriptAdd(ctx, buf, keRspPartialLen);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    /* TODO: Verify responder signature (DSP0274) - prevents MITM key
     * substitution. Requires correct TH1 transcript construction which
     * differs between standard and Nuvoton modes. */

    /* Add signature to transcript (TH1 includes signature) */
    rc = wolfSPDM_TranscriptAdd(ctx, signature, WOLFSPDM_ECC_SIG_SIZE);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    /* Compute ECDH shared secret */
    rc = wolfSPDM_ComputeSharedSecret(ctx, peerPubKeyX, peerPubKeyY);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    /* Compute TH1 = Hash(transcript including signature) */
    rc = wolfSPDM_TranscriptHash(ctx, ctx->th1);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }
    /* Derive all session keys */
    rc = wolfSPDM_DeriveHandshakeKeys(ctx, ctx->th1);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    /* Verify ResponderVerifyData = HMAC(rspFinishedKey, TH1) */
    rc = wolfSPDM_ComputeVerifyData(ctx->rspFinishedKey, ctx->th1, expectedHmac);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    if (XMEMCMP(expectedHmac, rspVerifyData, WOLFSPDM_HASH_SIZE) != 0) {
        wolfSPDM_DebugPrint(ctx, "ResponderVerifyData MISMATCH\n");
    } else {
        wolfSPDM_DebugPrint(ctx, "ResponderVerifyData VERIFIED OK\n");
    }

    /* Add ResponderVerifyData to transcript (per SPDM spec, always included) */
    rc = wolfSPDM_TranscriptAdd(ctx, rspVerifyData, WOLFSPDM_HASH_SIZE);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    ctx->state = WOLFSPDM_STATE_KEY_EX;
    return WOLFSPDM_SUCCESS;
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

/* --- Measurement Message Building and Parsing --- */

#ifndef NO_WOLFSPDM_MEAS

int wolfSPDM_BuildGetMeasurements(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz,
    byte operation, byte requestSig)
{
    word32 offset = 0;

    if (ctx == NULL || buf == NULL || bufSz == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    /* Size: 4 header + (requestSig ? 32 nonce + 1 slotId : 0)
     * SPDM 1.3+ adds RequesterContext(8) always, plus
     * OpaqueDataLength(2) when signature is requested */
    {
        word32 minSz = 4;
        if (requestSig) {
            minSz += 32 + 1;  /* Nonce + SlotIDParam */
        }
        if (ctx->spdmVersion >= SPDM_VERSION_13) {
            minSz += 8;       /* RequesterContext (always for 1.3+) */
            if (requestSig)
                minSz += 2;   /* OpaqueDataLength */
        }
        if (*bufSz < minSz)
            return WOLFSPDM_E_BUFFER_SMALL;
    }

    buf[offset++] = ctx->spdmVersion;
    buf[offset++] = SPDM_GET_MEASUREMENTS;
    /* Param1: bit 0 = signature requested */
    buf[offset++] = requestSig ? SPDM_MEAS_REQUEST_SIG_BIT : 0x00;
    /* Param2: MeasurementOperation */
    buf[offset++] = operation;

    if (requestSig) {
        /* Nonce (32 bytes) */
        int rc = wolfSPDM_GetRandom(ctx, &buf[offset], 32);
        if (rc != WOLFSPDM_SUCCESS) {
            return rc;
        }
        XMEMCPY(ctx->measNonce, &buf[offset], 32);
        offset += 32;

        /* SlotIDParam (1 byte) — slot 0 */
        buf[offset++] = 0x00;
    }

    /* SPDM 1.3+ adds RequesterContext (8 bytes) for both signed and unsigned.
     * Per DSP0274 Table 51, this field is always present for version >= 1.3. */
    if (ctx->spdmVersion >= SPDM_VERSION_13) {
        int rc = wolfSPDM_GetRandom(ctx, &buf[offset], 8);
        if (rc != WOLFSPDM_SUCCESS) {
            return rc;
        }
        offset += 8;
        /* Note: OpaqueDataLength is NOT part of GET_MEASUREMENTS request
         * per DSP0274 Table 51 / libspdm. Only RequesterContext is added. */
    }

    *bufSz = offset;
    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_ParseMeasurements(WOLFSPDM_CTX* ctx, const byte* buf, word32 bufSz)
{
    word32 offset;
    byte numBlocks;
    word32 recordLen;
    word32 recordEnd;
    word32 blockIdx;

    SPDM_CHECK_PARSE_ARGS(ctx, buf, bufSz, 8);
    SPDM_CHECK_RESPONSE(ctx, buf, bufSz, SPDM_MEASUREMENTS, WOLFSPDM_E_MEASUREMENT);

    numBlocks = buf[4];
    /* MeasurementRecordLength: 3 bytes LE at offset 5..7 */
    recordLen = (word32)buf[5] | ((word32)buf[6] << 8) | ((word32)buf[7] << 16);

    wolfSPDM_DebugPrint(ctx, "MEASUREMENTS: numBlocks=%u, recordLen=%u\n",
        numBlocks, recordLen);

    /* Validate record fits in buffer */
    if (8 + recordLen > bufSz) {
        wolfSPDM_DebugPrint(ctx, "MEASUREMENTS: recordLen %u exceeds bufSz %u\n",
            recordLen, bufSz);
        return WOLFSPDM_E_MEASUREMENT;
    }

    recordEnd = 8 + recordLen;
    offset = 8;  /* Start of measurement record */
    ctx->measBlockCount = 0;

    /* Parse each measurement block */
    for (blockIdx = 0; blockIdx < numBlocks; blockIdx++) {
        word16 measSize;

        /* Check block header fits */
        if (offset + WOLFSPDM_MEAS_BLOCK_HDR_SIZE > recordEnd) {
            wolfSPDM_DebugPrint(ctx, "MEASUREMENTS: block %u header truncated\n",
                blockIdx);
            return WOLFSPDM_E_MEASUREMENT;
        }

        /* Read block header: Index(1) + MeasSpec(1) + MeasSize(2 LE) */
        measSize = SPDM_Get16LE(&buf[offset + 2]);

        /* Check block data fits */
        if (offset + WOLFSPDM_MEAS_BLOCK_HDR_SIZE + measSize > recordEnd) {
            wolfSPDM_DebugPrint(ctx, "MEASUREMENTS: block %u data truncated\n",
                blockIdx);
            return WOLFSPDM_E_MEASUREMENT;
        }

        /* Store if we have room */
        if (ctx->measBlockCount < WOLFSPDM_MAX_MEAS_BLOCKS) {
            WOLFSPDM_MEAS_BLOCK* blk = &ctx->measBlocks[ctx->measBlockCount];
            blk->index = buf[offset];
            blk->measurementSpec = buf[offset + 1];

            /* Parse DMTF measurement value if MeasSpec==1 and size >= 3 */
            if (blk->measurementSpec == 0x01 && measSize >= 3) {
                word16 valueSize;
                word16 copySize;

                blk->dmtfType = buf[offset + WOLFSPDM_MEAS_BLOCK_HDR_SIZE];
                valueSize = (word16)(
                    buf[offset + WOLFSPDM_MEAS_BLOCK_HDR_SIZE + 1] |
                    (buf[offset + WOLFSPDM_MEAS_BLOCK_HDR_SIZE + 2] << 8));

                /* Validate valueSize against measSize */
                if (valueSize > measSize - 3) {
                    wolfSPDM_DebugPrint(ctx,
                        "MEASUREMENTS: block %u valueSize %u > measSize-3 %u\n",
                        blockIdx, valueSize, measSize - 3);
                    return WOLFSPDM_E_MEASUREMENT;
                }

                /* Truncate if value exceeds our buffer */
                copySize = valueSize;
                if (copySize > WOLFSPDM_MAX_MEAS_VALUE_SIZE) {
                    copySize = WOLFSPDM_MAX_MEAS_VALUE_SIZE;
                }
                blk->valueSize = copySize;
                XMEMCPY(blk->value,
                    &buf[offset + WOLFSPDM_MEAS_BLOCK_HDR_SIZE + 3], copySize);
            }
            else {
                /* Non-DMTF or too small: store raw */
                word16 copySize = measSize;
                blk->dmtfType = 0;
                if (copySize > WOLFSPDM_MAX_MEAS_VALUE_SIZE) {
                    copySize = WOLFSPDM_MAX_MEAS_VALUE_SIZE;
                }
                blk->valueSize = copySize;
                if (copySize > 0) {
                    XMEMCPY(blk->value,
                        &buf[offset + WOLFSPDM_MEAS_BLOCK_HDR_SIZE], copySize);
                }
            }

            ctx->measBlockCount++;
        }
        else {
            wolfSPDM_DebugPrint(ctx,
                "MEASUREMENTS: block %u exceeds MAX_MEAS_BLOCKS (%u), skipping\n",
                blockIdx, WOLFSPDM_MAX_MEAS_BLOCKS);
        }

        offset += WOLFSPDM_MEAS_BLOCK_HDR_SIZE + measSize;
    }

    /* After measurement record: Nonce(32) + OpaqueDataLength(2) + OpaqueData + Signature */
    /* Nonce is present only if signature was requested */
    ctx->measSignatureSize = 0;

    if (offset + 32 + 2 <= bufSz) {
        /* Nonce (32 bytes) — skip, we already have our own in ctx->measNonce */
        offset += 32;

        /* OpaqueDataLength (2 LE) */
        word16 opaqueLen = SPDM_Get16LE(&buf[offset]);
        offset += 2;

        /* Skip opaque data */
        if (offset + opaqueLen > bufSz) {
            wolfSPDM_DebugPrint(ctx, "MEASUREMENTS: opaque data truncated\n");
            return WOLFSPDM_E_MEASUREMENT;
        }
        offset += opaqueLen;

        /* Signature (if present) */
        if (offset + WOLFSPDM_ECC_SIG_SIZE <= bufSz) {
            XMEMCPY(ctx->measSignature, &buf[offset], WOLFSPDM_ECC_SIG_SIZE);
            ctx->measSignatureSize = WOLFSPDM_ECC_SIG_SIZE;
        }
    }

    ctx->flags.hasMeasurements = 1;
    wolfSPDM_DebugPrint(ctx, "MEASUREMENTS: parsed %u blocks\n",
        ctx->measBlockCount);

    return WOLFSPDM_SUCCESS;
}

#ifndef NO_WOLFSPDM_MEAS_VERIFY

/* Shared tail: BuildSignedHash → VerifyEccSig → debug print → return */
static int wolfSPDM_VerifySignedDigest(WOLFSPDM_CTX* ctx,
    const char* contextStr, word32 contextStrLen,
    byte* digest,  /* in: hash, overwritten by BuildSignedHash */
    const byte* sig, word32 sigSz,
    const char* passMsg, const char* failMsg, int failErr)
{
    int rc = wolfSPDM_BuildSignedHash(ctx->spdmVersion,
        contextStr, contextStrLen, digest, digest);
    if (rc != WOLFSPDM_SUCCESS) return rc;

    rc = wolfSPDM_VerifyEccSig(ctx, sig, sigSz, digest, WOLFSPDM_HASH_SIZE);
    if (rc == WOLFSPDM_SUCCESS) {
        wolfSPDM_DebugPrint(ctx, "%s\n", passMsg);
        return WOLFSPDM_SUCCESS;
    }
    wolfSPDM_DebugPrint(ctx, "%s\n", failMsg);
    return failErr;
}

int wolfSPDM_VerifyMeasurementSig(WOLFSPDM_CTX* ctx,
    const byte* rspBuf, word32 rspBufSz,
    const byte* reqMsg, word32 reqMsgSz)
{
    byte digest[WOLFSPDM_HASH_SIZE];
    word32 sigOffset;
    int rc;

    if (ctx == NULL || rspBuf == NULL || reqMsg == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (!ctx->flags.hasResponderPubKey) {
        return WOLFSPDM_E_MEAS_NOT_VERIFIED;
    }

    /* Signature is the last WOLFSPDM_ECC_SIG_SIZE bytes of the response */
    if (rspBufSz < WOLFSPDM_ECC_SIG_SIZE) {
        return WOLFSPDM_E_MEASUREMENT;
    }
    sigOffset = rspBufSz - WOLFSPDM_ECC_SIG_SIZE;

    /* Compute L1||L2 hash per DSP0274 Section 10.11.1:
     * L1/L2 = VCA || GET_MEASUREMENTS_request || MEASUREMENTS_response(before sig) */
    rc = wolfSPDM_Sha384Hash(digest,
        ctx->transcript, ctx->vcaLen,
        reqMsg, reqMsgSz,
        rspBuf, sigOffset);
    if (rc != WOLFSPDM_SUCCESS) return rc;

    return wolfSPDM_VerifySignedDigest(ctx,
        "responder-measurements signing", 30, digest,
        rspBuf + sigOffset, WOLFSPDM_ECC_SIG_SIZE,
        "Measurement signature VERIFIED",
        "Measurement signature INVALID",
        WOLFSPDM_E_MEAS_SIG_FAIL);
}

#endif /* !NO_WOLFSPDM_MEAS_VERIFY */
#endif /* !NO_WOLFSPDM_MEAS */

/* --- Responder Public Key Extraction ---
 * Extract responder's ECC P-384 public key from the leaf certificate in the
 * SPDM certificate chain. Used by both measurement signature verification
 * and CHALLENGE authentication, so it lives outside measurement guards. */

/* Helper: find leaf cert in SPDM cert chain buffer.
 * SPDM cert chain header: Length(2 LE) + Reserved(2) + RootHash(48) = 52 bytes
 * After header: concatenated DER certificates, leaf is the last one. */
static int wolfSPDM_FindLeafCert(const byte* certChain, word32 certChainLen,
    const byte** leafCert, word32* leafCertSz)
{
    const byte* certDer;
    word32 certDerSz;
    word32 pos;
    const byte* lastCert;
    word32 lastCertSz;

    if (certChainLen <= 52) {
        return WOLFSPDM_E_CERT_PARSE;
    }

    certDer = certChain + 52;
    certDerSz = certChainLen - 52;
    lastCert = certDer;
    lastCertSz = certDerSz;
    pos = 0;

    while (pos < certDerSz) {
        word32 certLen;
        word32 hdrLen;

        if (certDer[pos] != 0x30) {
            break;
        }

        if (pos + 1 >= certDerSz) break;

        if (certDer[pos + 1] < 0x80) {
            certLen = certDer[pos + 1];
            hdrLen = 2;
        }
        else if (certDer[pos + 1] == 0x81) {
            if (pos + 2 >= certDerSz) break;
            certLen = certDer[pos + 2];
            hdrLen = 3;
        }
        else if (certDer[pos + 1] == 0x82) {
            if (pos + 3 >= certDerSz) break;
            certLen = ((word32)certDer[pos + 2] << 8) | certDer[pos + 3];
            hdrLen = 4;
        }
        else if (certDer[pos + 1] == 0x83) {
            if (pos + 4 >= certDerSz) break;
            certLen = ((word32)certDer[pos + 2] << 16) |
                      ((word32)certDer[pos + 3] << 8) | certDer[pos + 4];
            hdrLen = 5;
        }
        else {
            break;
        }

        if (pos + hdrLen + certLen > certDerSz) break;

        lastCert = certDer + pos;
        lastCertSz = hdrLen + certLen;
        pos += hdrLen + certLen;
    }

    *leafCert = lastCert;
    *leafCertSz = lastCertSz;
    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_ExtractResponderPubKey(WOLFSPDM_CTX* ctx)
{
    DecodedCert cert;
    const byte* leafCert;
    word32 leafCertSz;
    word32 idx;
    int rc;

    if (ctx == NULL || ctx->certChainLen == 0) {
        return WOLFSPDM_E_CERT_PARSE;
    }

    /* Find the leaf (last) certificate in the SPDM cert chain */
    rc = wolfSPDM_FindLeafCert(ctx->certChain, ctx->certChainLen,
        &leafCert, &leafCertSz);
    if (rc != WOLFSPDM_SUCCESS) {
        wolfSPDM_DebugPrint(ctx, "Certificate chain too short for header\n");
        return rc;
    }

    /* Parse the leaf certificate */
    wc_InitDecodedCert(&cert, leafCert, leafCertSz, NULL);
    rc = wc_ParseCert(&cert, CERT_TYPE, NO_VERIFY, NULL);
    if (rc != 0) {
        wolfSPDM_DebugPrint(ctx, "Certificate parse failed: %d\n", rc);
        wc_FreeDecodedCert(&cert);
        return WOLFSPDM_E_CERT_PARSE;
    }

    /* Extract public key from cert and import into ecc_key */
    rc = wc_ecc_init(&ctx->responderPubKey);
    if (rc != 0) {
        wc_FreeDecodedCert(&cert);
        return WOLFSPDM_E_CRYPTO_FAIL;
    }

    idx = 0;
    rc = wc_EccPublicKeyDecode(cert.publicKey, &idx, &ctx->responderPubKey,
        cert.pubKeySize);
    if (rc != 0) {
        wolfSPDM_DebugPrint(ctx, "ECC public key decode failed: %d\n", rc);
        wc_ecc_free(&ctx->responderPubKey);
        wc_FreeDecodedCert(&cert);
        return WOLFSPDM_E_CERT_PARSE;
    }

    wc_FreeDecodedCert(&cert);
    ctx->flags.hasResponderPubKey = 1;
    wolfSPDM_DebugPrint(ctx, "Extracted responder ECC P-384 public key\n");

    return WOLFSPDM_SUCCESS;
}

/* --- Certificate Chain Validation --- */

int wolfSPDM_ValidateCertChain(WOLFSPDM_CTX* ctx)
{
    byte caHash[WOLFSPDM_HASH_SIZE];
    const byte* chainRootHash;
    int rc;

    if (ctx == NULL || ctx->certChainLen == 0) {
        return WOLFSPDM_E_CERT_PARSE;
    }

    if (!ctx->flags.hasTrustedCAs) {
        return WOLFSPDM_E_CERT_PARSE;
    }

    /* SPDM cert chain header: Length(2 LE) + Reserved(2) + RootHash(48) */
    if (ctx->certChainLen <= 52) {
        return WOLFSPDM_E_CERT_PARSE;
    }

    /* Validate the root hash against our trusted CA */
    rc = wolfSPDM_Sha384Hash(caHash, ctx->trustedCAs, ctx->trustedCAsSz,
        NULL, 0, NULL, 0);
    if (rc != WOLFSPDM_SUCCESS) return rc;

    chainRootHash = ctx->certChain + 4;  /* Skip Length(2) + Reserved(2) */
    if (XMEMCMP(caHash, chainRootHash, WOLFSPDM_HASH_SIZE) != 0) {
        wolfSPDM_DebugPrint(ctx,
            "Root cert hash mismatch — chain not from trusted CA\n");
        return WOLFSPDM_E_CERT_PARSE;
    }

    wolfSPDM_DebugPrint(ctx, "Root certificate hash VERIFIED against trusted CA\n");

    /* Extract public key from the leaf cert (reuses FindLeafCert internally) */
    rc = wolfSPDM_ExtractResponderPubKey(ctx);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    wolfSPDM_DebugPrint(ctx, "Certificate chain validated\n");
    return WOLFSPDM_SUCCESS;
}

/* --- Challenge Authentication (DSP0274 Section 10.8) --- */

#ifndef NO_WOLFSPDM_CHALLENGE

int wolfSPDM_BuildChallenge(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz,
    int slotId, byte measHashType)
{
    word32 offset = 0;
    word32 minSz;
    int rc;

    /* SPDM 1.3+ adds RequesterContext(8) per DSP0274 Table 46 */
    minSz = 36;
    if (ctx->spdmVersion >= SPDM_VERSION_13)
        minSz += 8;  /* RequesterContext */
    SPDM_CHECK_BUILD_ARGS(ctx, buf, bufSz, minSz);

    buf[offset++] = ctx->spdmVersion;
    buf[offset++] = SPDM_CHALLENGE;
    buf[offset++] = (byte)(slotId & 0x0F);
    buf[offset++] = measHashType;

    /* Save measHashType for ParseChallengeAuth */
    ctx->challengeMeasHashType = measHashType;

    /* Nonce (32 bytes random) */
    rc = wolfSPDM_GetRandom(ctx, &buf[offset], 32);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }
    XMEMCPY(ctx->challengeNonce, &buf[offset], 32);
    offset += 32;

    /* SPDM 1.3+ adds RequesterContext(8) per DSP0274 Table 46.
     * Note: OpaqueDataLength is NOT part of the CHALLENGE request. */
    if (ctx->spdmVersion >= SPDM_VERSION_13) {
        rc = wolfSPDM_GetRandom(ctx, &buf[offset], 8);
        if (rc != WOLFSPDM_SUCCESS) {
            return rc;
        }
        offset += 8;
    }

    *bufSz = offset;
    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_ParseChallengeAuth(WOLFSPDM_CTX* ctx, const byte* buf,
    word32 bufSz, word32* sigOffset)
{
    word32 offset;
    word16 opaqueLen;

    if (ctx == NULL || buf == NULL || sigOffset == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    /* Minimum size: 4 hdr + 48 certChainHash + 48 nonce + 48 measSummary
     * + 2 opaqueLen + 96 sig = 246 bytes (with meas hash) */
    if (bufSz < 4) {
        return WOLFSPDM_E_CHALLENGE;
    }

    SPDM_CHECK_RESPONSE(ctx, buf, bufSz, SPDM_CHALLENGE_AUTH, WOLFSPDM_E_CHALLENGE);

    offset = 4;

    /* CertChainHash (H bytes, 48 for SHA-384) */
    if (offset + WOLFSPDM_HASH_SIZE > bufSz) {
        wolfSPDM_DebugPrint(ctx, "CHALLENGE_AUTH: too short for CertChainHash\n");
        return WOLFSPDM_E_CHALLENGE;
    }
    /* Verify cert chain hash matches what we computed */
    if (XMEMCMP(&buf[offset], ctx->certChainHash, WOLFSPDM_HASH_SIZE) != 0) {
        wolfSPDM_DebugPrint(ctx, "CHALLENGE_AUTH: CertChainHash mismatch\n");
        return WOLFSPDM_E_CHALLENGE;
    }
    offset += WOLFSPDM_HASH_SIZE;

    /* Nonce (32 bytes per DSP0274) */
    if (offset + 32 > bufSz) {
        wolfSPDM_DebugPrint(ctx, "CHALLENGE_AUTH: too short for Nonce\n");
        return WOLFSPDM_E_CHALLENGE;
    }
    offset += 32;

    /* MeasurementSummaryHash (H bytes if requested, 0 bytes if type=NONE) */
    if (ctx->challengeMeasHashType != SPDM_MEAS_SUMMARY_HASH_NONE) {
        if (offset + WOLFSPDM_HASH_SIZE > bufSz) {
            wolfSPDM_DebugPrint(ctx,
                "CHALLENGE_AUTH: too short for MeasurementSummaryHash\n");
            return WOLFSPDM_E_CHALLENGE;
        }
        offset += WOLFSPDM_HASH_SIZE;
    }

    /* OpaqueDataLength (2 LE) */
    if (offset + 2 > bufSz) {
        return WOLFSPDM_E_CHALLENGE;
    }
    opaqueLen = SPDM_Get16LE(&buf[offset]);
    offset += 2;

    /* Skip opaque data */
    if (offset + opaqueLen > bufSz) {
        return WOLFSPDM_E_CHALLENGE;
    }
    offset += opaqueLen;

    /* SPDM 1.3+ adds RequesterContext (8 bytes echoed from request)
     * Per DSP0274, this comes AFTER OpaqueData and BEFORE Signature */
    if (ctx->spdmVersion >= SPDM_VERSION_13) {
        if (offset + 8 > bufSz) {
            wolfSPDM_DebugPrint(ctx,
                "CHALLENGE_AUTH: too short for RequesterContext\n");
            return WOLFSPDM_E_CHALLENGE;
        }
        offset += 8;
    }

    /* Signature starts here */
    if (offset + WOLFSPDM_ECC_SIG_SIZE > bufSz) {
        wolfSPDM_DebugPrint(ctx, "CHALLENGE_AUTH: no room for signature\n");
        return WOLFSPDM_E_CHALLENGE;
    }

    *sigOffset = offset;
    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_VerifyChallengeAuthSig(WOLFSPDM_CTX* ctx,
    const byte* rspBuf, word32 rspBufSz,
    const byte* reqMsg, word32 reqMsgSz, word32 sigOffset)
{
    byte digest[WOLFSPDM_HASH_SIZE];
    int rc;

    (void)rspBufSz;

    if (ctx == NULL || rspBuf == NULL || reqMsg == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (!ctx->flags.hasResponderPubKey) {
        return WOLFSPDM_E_CHALLENGE;
    }

    /* Build M1/M2 hash per DSP0274 Section 10.8.3:
     * A+B are already accumulated in ctx->m1m2Hash. Now add C and finalize. */
    if (!ctx->flags.m1m2HashInit) {
        wolfSPDM_DebugPrint(ctx, "CHALLENGE: M1/M2 hash not initialized\n");
        return WOLFSPDM_E_CHALLENGE;
    }

    /* Add C: CHALLENGE request + CHALLENGE_AUTH response (before sig) */
    rc = wc_Sha384Update(&ctx->m1m2Hash, reqMsg, reqMsgSz);
    if (rc != 0) return WOLFSPDM_E_CRYPTO_FAIL;
    rc = wc_Sha384Update(&ctx->m1m2Hash, rspBuf, sigOffset);
    if (rc != 0) return WOLFSPDM_E_CRYPTO_FAIL;

    /* Finalize M1/M2 hash */
    rc = wc_Sha384Final(&ctx->m1m2Hash, digest);
    ctx->flags.m1m2HashInit = 0; /* Hash consumed */
    if (rc != 0) return WOLFSPDM_E_CRYPTO_FAIL;

    return wolfSPDM_VerifySignedDigest(ctx,
        "responder-challenge_auth signing", 32, digest,
        rspBuf + sigOffset, WOLFSPDM_ECC_SIG_SIZE,
        "CHALLENGE_AUTH signature VERIFIED",
        "CHALLENGE_AUTH signature INVALID",
        WOLFSPDM_E_CHALLENGE);
}

#endif /* !NO_WOLFSPDM_CHALLENGE */

/* --- Heartbeat (DSP0274 Section 10.10) --- */

int wolfSPDM_BuildHeartbeat(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz)
{
    return wolfSPDM_BuildSimpleMsg(ctx, SPDM_HEARTBEAT, buf, bufSz);
}

int wolfSPDM_ParseHeartbeatAck(WOLFSPDM_CTX* ctx, const byte* buf,
    word32 bufSz)
{
    SPDM_CHECK_PARSE_ARGS(ctx, buf, bufSz, 4);
    SPDM_CHECK_RESPONSE(ctx, buf, bufSz, SPDM_HEARTBEAT_ACK, WOLFSPDM_E_BAD_STATE);

    wolfSPDM_DebugPrint(ctx, "HEARTBEAT_ACK received\n");
    return WOLFSPDM_SUCCESS;
}

/* --- Key Update (DSP0274 Section 10.9) --- */

int wolfSPDM_BuildKeyUpdate(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz,
    byte operation, byte* tag)
{
    int rc;

    SPDM_CHECK_BUILD_ARGS(ctx, buf, bufSz, 4);
    if (tag == NULL)
        return WOLFSPDM_E_INVALID_ARG;

    /* Generate random tag for request/response matching */
    rc = wolfSPDM_GetRandom(ctx, tag, 1);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    buf[0] = ctx->spdmVersion;
    buf[1] = SPDM_KEY_UPDATE;
    buf[2] = operation;
    buf[3] = *tag;
    *bufSz = 4;

    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_ParseKeyUpdateAck(WOLFSPDM_CTX* ctx, const byte* buf,
    word32 bufSz, byte operation, byte tag)
{
    SPDM_CHECK_PARSE_ARGS(ctx, buf, bufSz, 4);
    SPDM_CHECK_RESPONSE(ctx, buf, bufSz, SPDM_KEY_UPDATE_ACK, WOLFSPDM_E_KEY_UPDATE);

    /* Verify echoed operation and tag */
    if (buf[2] != operation) {
        wolfSPDM_DebugPrint(ctx, "KEY_UPDATE_ACK: operation mismatch: 0x%02x != 0x%02x\n",
            buf[2], operation);
        return WOLFSPDM_E_KEY_UPDATE;
    }

    if (buf[3] != tag) {
        wolfSPDM_DebugPrint(ctx, "KEY_UPDATE_ACK: tag mismatch: 0x%02x != 0x%02x\n",
            buf[3], tag);
        return WOLFSPDM_E_KEY_UPDATE;
    }

    wolfSPDM_DebugPrint(ctx, "KEY_UPDATE_ACK received\n");
    return WOLFSPDM_SUCCESS;
}
