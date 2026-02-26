/* spdm_kdf.c
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
#include <string.h>

/*
 * SPDM Key Derivation (DSP0277)
 *
 * SPDM uses HKDF with a BinConcat info format different from TLS 1.3:
 *   info = Length (2 bytes, LE) || "spdm1.2 " || Label || Context
 *
 * Key hierarchy:
 *   HandshakeSecret = HKDF-Extract(salt=zeros, IKM=sharedSecret)
 *   reqHsSecret = HKDF-Expand(HS, "req hs data" || TH1, 48)
 *   rspHsSecret = HKDF-Expand(HS, "rsp hs data" || TH1, 48)
 *   reqFinishedKey = HKDF-Expand(reqHsSecret, "finished", 48)
 *   rspFinishedKey = HKDF-Expand(rspHsSecret, "finished", 48)
 *   reqDataKey = HKDF-Expand(reqHsSecret, "key", 32)
 *   reqDataIV = HKDF-Expand(reqHsSecret, "iv", 12)
 *   (same pattern for rsp keys)
 */

int wolfSPDM_HkdfExpandLabel(byte spdmVersion, const byte* secret, word32 secretSz,
    const char* label, const byte* context, word32 contextSz,
    byte* out, word32 outSz)
{
    byte info[128];
    word32 infoLen = 0;
    const char* prefix;
    int rc;

    if (secret == NULL || label == NULL || out == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    /* Select version-specific prefix */
    if (spdmVersion >= 0x14) {
        prefix = SPDM_BIN_CONCAT_PREFIX_14;  /* "spdm1.4 " */
    } else if (spdmVersion >= 0x13) {
        prefix = SPDM_BIN_CONCAT_PREFIX_13;  /* "spdm1.3 " */
    } else {
        prefix = SPDM_BIN_CONCAT_PREFIX_12;  /* "spdm1.2 " */
    }

    /* BinConcat format: Length (2 LE) || "spdmX.Y " || Label || Context
     * Note: SPDM spec references TLS 1.3 (BE), but Nuvoton uses LE.
     * The ResponderVerifyData match proves LE is correct for this TPM. */
    info[infoLen++] = (byte)(outSz & 0xFF);
    info[infoLen++] = (byte)((outSz >> 8) & 0xFF);

    XMEMCPY(info + infoLen, prefix, SPDM_BIN_CONCAT_PREFIX_LEN);
    infoLen += SPDM_BIN_CONCAT_PREFIX_LEN;

    XMEMCPY(info + infoLen, label, XSTRLEN(label));
    infoLen += (word32)XSTRLEN(label);

    if (context != NULL && contextSz > 0) {
        XMEMCPY(info + infoLen, context, contextSz);
        infoLen += contextSz;
    }

    rc = wc_HKDF_Expand(WC_SHA384, secret, secretSz, info, infoLen, out, outSz);

    return (rc == 0) ? WOLFSPDM_SUCCESS : WOLFSPDM_E_CRYPTO_FAIL;
}

int wolfSPDM_ComputeVerifyData(const byte* finishedKey, const byte* thHash,
    byte* verifyData)
{
    Hmac hmac;
    int rc;

    if (finishedKey == NULL || thHash == NULL || verifyData == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    rc = wc_HmacSetKey(&hmac, WC_SHA384, finishedKey, WOLFSPDM_HASH_SIZE);
    if (rc != 0) {
        return WOLFSPDM_E_CRYPTO_FAIL;
    }

    rc = wc_HmacUpdate(&hmac, thHash, WOLFSPDM_HASH_SIZE);
    if (rc != 0) {
        return WOLFSPDM_E_CRYPTO_FAIL;
    }

    rc = wc_HmacFinal(&hmac, verifyData);

    return (rc == 0) ? WOLFSPDM_SUCCESS : WOLFSPDM_E_CRYPTO_FAIL;
}

/* Derive both data key (AES-256) and IV from a secret using HKDF-Expand */
static int wolfSPDM_DeriveKeyIvPair(byte spdmVersion, const byte* secret,
    byte* key, byte* iv)
{
    int rc;
    rc = wolfSPDM_HkdfExpandLabel(spdmVersion, secret,
        WOLFSPDM_HASH_SIZE, SPDM_LABEL_KEY, NULL, 0,
        key, WOLFSPDM_AEAD_KEY_SIZE);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }
    return wolfSPDM_HkdfExpandLabel(spdmVersion, secret,
        WOLFSPDM_HASH_SIZE, SPDM_LABEL_IV, NULL, 0,
        iv, WOLFSPDM_AEAD_IV_SIZE);
}

int wolfSPDM_DeriveHandshakeKeys(WOLFSPDM_CTX* ctx, const byte* th1Hash)
{
    byte salt[WOLFSPDM_HASH_SIZE];
    int rc;

    if (ctx == NULL || th1Hash == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    /* SPDM uses zero salt (unlike TLS 1.3 which uses Hash("")) */
    XMEMSET(salt, 0, sizeof(salt));

    /* HandshakeSecret = HKDF-Extract(zeros, sharedSecret) */
    rc = wc_HKDF_Extract(WC_SHA384, salt, sizeof(salt),
        ctx->sharedSecret, ctx->sharedSecretSz,
        ctx->handshakeSecret);
    if (rc != 0) {
        return WOLFSPDM_E_CRYPTO_FAIL;
    }

    /* reqHsSecret = HKDF-Expand(HS, "req hs data" || TH1, 48) */
    rc = wolfSPDM_HkdfExpandLabel(ctx->spdmVersion, ctx->handshakeSecret,
        WOLFSPDM_HASH_SIZE, SPDM_LABEL_REQ_HS_DATA, th1Hash, WOLFSPDM_HASH_SIZE,
        ctx->reqHsSecret, WOLFSPDM_HASH_SIZE);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }
    /* rspHsSecret = HKDF-Expand(HS, "rsp hs data" || TH1, 48) */
    rc = wolfSPDM_HkdfExpandLabel(ctx->spdmVersion, ctx->handshakeSecret,
        WOLFSPDM_HASH_SIZE, SPDM_LABEL_RSP_HS_DATA, th1Hash, WOLFSPDM_HASH_SIZE,
        ctx->rspHsSecret, WOLFSPDM_HASH_SIZE);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }
    /* Finished keys (used for VerifyData HMAC) */
    rc = wolfSPDM_HkdfExpandLabel(ctx->spdmVersion, ctx->reqHsSecret,
        WOLFSPDM_HASH_SIZE, SPDM_LABEL_FINISHED, NULL, 0,
        ctx->reqFinishedKey, WOLFSPDM_HASH_SIZE);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    rc = wolfSPDM_HkdfExpandLabel(ctx->spdmVersion, ctx->rspHsSecret,
        WOLFSPDM_HASH_SIZE, SPDM_LABEL_FINISHED, NULL, 0,
        ctx->rspFinishedKey, WOLFSPDM_HASH_SIZE);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    /* Data encryption keys + IVs (AES-256-GCM) */
    rc = wolfSPDM_DeriveKeyIvPair(ctx->spdmVersion, ctx->reqHsSecret,
        ctx->reqDataKey, ctx->reqDataIv);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    return wolfSPDM_DeriveKeyIvPair(ctx->spdmVersion, ctx->rspHsSecret,
        ctx->rspDataKey, ctx->rspDataIv);
}

int wolfSPDM_DeriveAppDataKeys(WOLFSPDM_CTX* ctx)
{
    byte th2Hash[WOLFSPDM_HASH_SIZE];
    byte salt[WOLFSPDM_HASH_SIZE];
    byte masterSecret[WOLFSPDM_HASH_SIZE];
    byte reqAppSecret[WOLFSPDM_HASH_SIZE];
    byte rspAppSecret[WOLFSPDM_HASH_SIZE];
    byte zeroIkm[WOLFSPDM_HASH_SIZE];
    int rc;

    if (ctx == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    /* Compute TH2_final = Hash(full transcript including FINISH + FINISH_RSP) */
    rc = wolfSPDM_TranscriptHash(ctx, th2Hash);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }
    /* salt = HKDF-Expand(HandshakeSecret, BinConcat("derived"), 48)
     * Per DSP0277: "derived" label has NO context (unlike TLS 1.3 which uses Hash(""))
     * libspdm confirms: bin_concat("derived", context=NULL) */
    rc = wolfSPDM_HkdfExpandLabel(ctx->spdmVersion, ctx->handshakeSecret,
        WOLFSPDM_HASH_SIZE, "derived", NULL, 0,
        salt, WOLFSPDM_HASH_SIZE);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    /* MasterSecret = HKDF-Extract(salt, 0^hashSize) */
    XMEMSET(zeroIkm, 0, sizeof(zeroIkm));
    rc = wc_HKDF_Extract(WC_SHA384, salt, WOLFSPDM_HASH_SIZE,
        zeroIkm, WOLFSPDM_HASH_SIZE, masterSecret);
    if (rc != 0) {
        return WOLFSPDM_E_CRYPTO_FAIL;
    }
    /* reqAppSecret = HKDF-Expand(MasterSecret, "req app data" || TH2, 48) */
    rc = wolfSPDM_HkdfExpandLabel(ctx->spdmVersion, masterSecret,
        WOLFSPDM_HASH_SIZE, SPDM_LABEL_REQ_DATA, th2Hash, WOLFSPDM_HASH_SIZE,
        reqAppSecret, WOLFSPDM_HASH_SIZE);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    /* rspAppSecret = HKDF-Expand(MasterSecret, "rsp app data" || TH2, 48) */
    rc = wolfSPDM_HkdfExpandLabel(ctx->spdmVersion, masterSecret,
        WOLFSPDM_HASH_SIZE, SPDM_LABEL_RSP_DATA, th2Hash, WOLFSPDM_HASH_SIZE,
        rspAppSecret, WOLFSPDM_HASH_SIZE);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    /* Save app secrets for KEY_UPDATE re-derivation */
    XMEMCPY(ctx->reqAppSecret, reqAppSecret, WOLFSPDM_HASH_SIZE);
    XMEMCPY(ctx->rspAppSecret, rspAppSecret, WOLFSPDM_HASH_SIZE);

    /* Derive new encryption keys + IVs from app data secrets */
    rc = wolfSPDM_DeriveKeyIvPair(ctx->spdmVersion, reqAppSecret,
        ctx->reqDataKey, ctx->reqDataIv);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    rc = wolfSPDM_DeriveKeyIvPair(ctx->spdmVersion, rspAppSecret,
        ctx->rspDataKey, ctx->rspDataIv);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    /* Reset sequence numbers for application phase */
    ctx->reqSeqNum = 0;
    ctx->rspSeqNum = 0;

    wolfSPDM_DebugPrint(ctx, "App data keys derived, seq nums reset to 0\n");

    return WOLFSPDM_SUCCESS;
}

/* --- Key Update Re-derivation (DSP0277) --- */

int wolfSPDM_DeriveUpdatedKeys(WOLFSPDM_CTX* ctx, int updateAll)
{
    byte newReqAppSecret[WOLFSPDM_HASH_SIZE];
    int rc;

    if (ctx == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    /* Per DSP0277: KEY_UPDATE uses "traffic upd" label with NO context.
     * info = outLen(2 LE) || "spdm1.2 " || "traffic upd" */

    /* Always update requester key */
    rc = wolfSPDM_HkdfExpandLabel(ctx->spdmVersion, ctx->reqAppSecret,
        WOLFSPDM_HASH_SIZE, SPDM_LABEL_UPDATE, NULL, 0,
        newReqAppSecret, WOLFSPDM_HASH_SIZE);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    rc = wolfSPDM_DeriveKeyIvPair(ctx->spdmVersion, newReqAppSecret,
        ctx->reqDataKey, ctx->reqDataIv);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    /* Save new requester secret for future updates */
    XMEMCPY(ctx->reqAppSecret, newReqAppSecret, WOLFSPDM_HASH_SIZE);

    /* Optionally update responder key */
    if (updateAll) {
        byte newRspAppSecret[WOLFSPDM_HASH_SIZE];

        rc = wolfSPDM_HkdfExpandLabel(ctx->spdmVersion, ctx->rspAppSecret,
            WOLFSPDM_HASH_SIZE, SPDM_LABEL_UPDATE, NULL, 0,
            newRspAppSecret, WOLFSPDM_HASH_SIZE);
        if (rc != WOLFSPDM_SUCCESS) {
            return rc;
        }

        rc = wolfSPDM_DeriveKeyIvPair(ctx->spdmVersion, newRspAppSecret,
            ctx->rspDataKey, ctx->rspDataIv);
        if (rc != WOLFSPDM_SUCCESS) {
            return rc;
        }

        /* Save new responder secret for future updates */
        XMEMCPY(ctx->rspAppSecret, newRspAppSecret, WOLFSPDM_HASH_SIZE);
    }

    return WOLFSPDM_SUCCESS;
}
