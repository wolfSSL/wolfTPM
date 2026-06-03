/* spdm_responder.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#ifdef WOLFTPM_SPDM_RESPONDER

#include "spdm_internal.h"
#include <wolftpm/spdm/spdm_responder.h>
/* spdm_tcg.h is included unconditionally - the transport framing
 * constants (TAG_CLEAR/SECURED, HEADER_SIZE) are needed by the
 * responder's frame-discrimination check even in PSK-only builds. */
#include <wolftpm/spdm/spdm_tcg.h>

struct WOLFSPDM_RESP_CTX {
    WOLFSPDM_CTX ctx;

    struct {
        unsigned int useTcg          : 1;
        unsigned int usePsk          : 1;
        unsigned int hasIdKey        : 1;
        unsigned int initialized     : 1;
        unsigned int spdmOnlyLock    : 1;  /* SPDMONLY lock: plaintext TPM
                                            * rejected with TPM_RC_DISABLED */
        unsigned int pskProvisioned  : 1;  /* PSK_SET / PSK_CLR vendor state */
    } flags;

    /* SHA-384(ClearAuth) stored on PSK_SET, verified on PSK_CLR. */
    byte   clearAuthDigest[WOLFSPDM_HASH_SIZE];

    byte   idPrivKey[WOLFSPDM_ECC_KEY_SIZE];
    word32 idPrivKeyLen;
    byte   idPubKey[WOLFSPDM_ECC_POINT_SIZE];
    word32 idPubKeyLen;

    /* Persistent PSK store. wolfSPDM_DeriveHandshakeKeysPsk wipes
     * ctx->psk after each derivation; we reload from here on every
     * PSK_EXCHANGE so the responder can serve multiple sessions. */
    byte   pskStore[WOLFSPDM_PSK_MAX_SIZE];
    word32 pskStoreSz;
    byte   pskHintStore[WOLFSPDM_PSK_HINT_MAX];
    word32 pskHintStoreSz;

    WOLFSPDM_RESP_TPM_CB tpmCb;
    void*                tpmCbUserCtx;

    /* Per-context working buffers. Previously file-scope `static` -
     * moved here so each ctx is independently reentrant. */
    byte   secureInPlain[WOLFSPDM_MAX_MSG_SIZE];
    byte   secureOutPlain[WOLFSPDM_MAX_MSG_SIZE];
    byte   vdInPayload[WOLFSPDM_MAX_MSG_SIZE];
    byte   vdOutPayload[WOLFSPDM_MAX_MSG_SIZE];
};

/* Compile-time guarantee that the public static-size macro is large
 * enough for the actual struct. If this fires, raise the +1024 slack
 * in WOLFSPDM_RESP_CTX_STATIC_SIZE in spdm_responder.h. */
typedef char wolfSPDM_resp_ctx_size_check_[
    (sizeof(struct WOLFSPDM_RESP_CTX) <= WOLFSPDM_RESP_CTX_STATIC_SIZE)
        ? 1 : -1];

int wolfSPDM_RespInit(WOLFSPDM_RESP_CTX* ctx)
{
    int rc;

    if (ctx == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    XMEMSET(ctx, 0, sizeof(*ctx));

    rc = wolfSPDM_Init(&ctx->ctx);
    if (rc == WOLFSPDM_SUCCESS) {
        ctx->flags.initialized = 1;
    }

    return rc;
}

void wolfSPDM_RespFree(WOLFSPDM_RESP_CTX* ctx)
{
    if (ctx == NULL) {
        return;
    }
    wc_ForceZero(ctx->idPrivKey, sizeof(ctx->idPrivKey));
    wc_ForceZero(ctx->pskStore, sizeof(ctx->pskStore));
    wc_ForceZero(ctx->clearAuthDigest, sizeof(ctx->clearAuthDigest));
    wolfSPDM_Free(&ctx->ctx);
    XMEMSET(ctx, 0, sizeof(*ctx));
}

int wolfSPDM_RespGetCtxSize(void)
{
    return (int)sizeof(struct WOLFSPDM_RESP_CTX);
}

int wolfSPDM_RespSetMode(WOLFSPDM_RESP_CTX* ctx, int useTcg, int usePsk)
{
    if (ctx == NULL || !ctx->flags.initialized) {
        return WOLFSPDM_E_INVALID_ARG;
    }
    if (!useTcg && !usePsk) {
        return WOLFSPDM_E_INVALID_ARG;
    }
#ifndef WOLFTPM_SPDM_TCG
    if (useTcg) {
        return WOLFSPDM_E_NOT_AVAILABLE;
    }
#endif
#ifndef WOLFTPM_SPDM_PSK
    if (usePsk) {
        return WOLFSPDM_E_NOT_AVAILABLE;
    }
#endif
    ctx->flags.useTcg = (useTcg != 0);
    ctx->flags.usePsk = (usePsk != 0);
    /* Pick a mode so encrypt/decrypt use the 14-byte TCG AAD format. */
    ctx->ctx.mode = usePsk ? WOLFSPDM_MODE_NATIONS_PSK : WOLFSPDM_MODE_NUVOTON;
    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_RespSetPSK(WOLFSPDM_RESP_CTX* ctx,
    const byte* psk, word32 pskSz,
    const byte* hint, word32 hintSz)
{
#ifndef WOLFTPM_SPDM_PSK
    (void)ctx;
    (void)psk;
    (void)pskSz;
    (void)hint;
    (void)hintSz;
    return WOLFSPDM_E_NOT_AVAILABLE;
#else
    if (ctx == NULL || !ctx->flags.initialized) {
        return WOLFSPDM_E_INVALID_ARG;
    }
    if (psk == NULL || pskSz == 0 || pskSz > sizeof(ctx->pskStore)) {
        return WOLFSPDM_E_INVALID_ARG;
    }
    XMEMCPY(ctx->pskStore, psk, pskSz);
    ctx->pskStoreSz = pskSz;
    if (hint != NULL && hintSz > 0 && hintSz <= sizeof(ctx->pskHintStore)) {
        XMEMCPY(ctx->pskHintStore, hint, hintSz);
        ctx->pskHintStoreSz = hintSz;
    }
    else {
        ctx->pskHintStoreSz = 0;
    }
    ctx->flags.pskProvisioned = 1;
    return wolfSPDM_SetPSK(&ctx->ctx, psk, pskSz, hint, hintSz);
#endif
}

int wolfSPDM_RespSetIdentityKey(WOLFSPDM_RESP_CTX* ctx,
    const byte* privKey, word32 privSz,
    const byte* pubKey, word32 pubSz)
{
    if (ctx == NULL || !ctx->flags.initialized ||
        privKey == NULL || pubKey == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }
    if (privSz != WOLFSPDM_ECC_KEY_SIZE ||
        pubSz != WOLFSPDM_ECC_POINT_SIZE) {
        return WOLFSPDM_E_INVALID_ARG;
    }
    XMEMCPY(ctx->idPrivKey, privKey, privSz);
    ctx->idPrivKeyLen = privSz;
    XMEMCPY(ctx->idPubKey, pubKey, pubSz);
    ctx->idPubKeyLen = pubSz;
    ctx->flags.hasIdKey = 1;
    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_RespSetTpmCallback(WOLFSPDM_RESP_CTX* ctx,
    WOLFSPDM_RESP_TPM_CB cb, void* userCtx)
{
    if (ctx == NULL || !ctx->flags.initialized) {
        return WOLFSPDM_E_INVALID_ARG;
    }
    ctx->tpmCb = cb;
    ctx->tpmCbUserCtx = userCtx;
    return WOLFSPDM_SUCCESS;
}

void wolfSPDM_RespSetDebug(WOLFSPDM_RESP_CTX* ctx, int enable)
{
    if (ctx == NULL) {
        return;
    }
    wolfSPDM_SetDebug(&ctx->ctx, enable);
}

int wolfSPDM_RespIsLocked(const WOLFSPDM_RESP_CTX* ctx)
{
    return (ctx != NULL && ctx->flags.spdmOnlyLock) ? 1 : 0;
}

void wolfSPDM_RespReset(WOLFSPDM_RESP_CTX* ctx)
{
    if (ctx == NULL) {
        return;
    }
    /* Identity key, PSK, mode flags survive; only session-scoped material
     * is wiped. */
    wc_ForceZero(ctx->ctx.reqDataKey, sizeof(ctx->ctx.reqDataKey));
    wc_ForceZero(ctx->ctx.rspDataKey, sizeof(ctx->ctx.rspDataKey));
    wc_ForceZero(ctx->ctx.reqDataIv, sizeof(ctx->ctx.reqDataIv));
    wc_ForceZero(ctx->ctx.rspDataIv, sizeof(ctx->ctx.rspDataIv));
    wc_ForceZero(ctx->ctx.handshakeSecret,
                 sizeof(ctx->ctx.handshakeSecret));
    wc_ForceZero(ctx->ctx.reqHsSecret, sizeof(ctx->ctx.reqHsSecret));
    wc_ForceZero(ctx->ctx.rspHsSecret, sizeof(ctx->ctx.rspHsSecret));
    wc_ForceZero(ctx->ctx.reqFinishedKey,
                 sizeof(ctx->ctx.reqFinishedKey));
    wc_ForceZero(ctx->ctx.rspFinishedKey,
                 sizeof(ctx->ctx.rspFinishedKey));
    wc_ForceZero(ctx->ctx.sharedSecret, sizeof(ctx->ctx.sharedSecret));
    ctx->ctx.sharedSecretSz = 0;
    ctx->ctx.reqSeqNum = 0;
    ctx->ctx.rspSeqNum = 0;
    ctx->ctx.sessionId = 0;
    ctx->ctx.state = WOLFSPDM_STATE_INIT;
}

#ifdef WOLFTPM_SPDM_TCG

#define WOLFSPDM_GET_CAPABILITIES       0xE1
#define WOLFSPDM_CAPABILITIES           0x61
#define WOLFSPDM_NEGOTIATE_ALGORITHMS   0xE3
#define WOLFSPDM_ALGORITHMS             0x63

static int RespHandleVendorDefined(WOLFSPDM_RESP_CTX* rctx,
    const byte* in, word32 inSz, byte* out, word32* outSz);
static int RespBuildKeyExchangeRsp(WOLFSPDM_RESP_CTX* rctx,
    const byte* in, word32 inSz, byte* out, word32* outSz);
static int RespHandleFinish(WOLFSPDM_RESP_CTX* rctx,
    const byte* in, word32 inSz, byte* out, word32* outSz);

static int RespBuildErrorClear(WOLFSPDM_CTX* ctx, byte errCode,
    byte errData, byte* out, word32* outSz)
{
    if (*outSz < 4) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }
    out[0] = (ctx->spdmVersion != 0) ? ctx->spdmVersion : SPDM_VERSION_10;
    out[1] = SPDM_ERROR;
    out[2] = errCode;
    out[3] = errData;
    *outSz = 4;
    return WOLFSPDM_SUCCESS;
}

/* Always paired: swap -> call existing req-side helper -> swap-back. */
static void RespSwapDataDir(WOLFSPDM_CTX* ctx)
{
    byte   tmpKey[WOLFSPDM_AEAD_KEY_SIZE];
    byte   tmpIv[WOLFSPDM_AEAD_IV_SIZE];
    word64 tmpSeq;

    XMEMCPY(tmpKey, ctx->reqDataKey, sizeof(tmpKey));
    XMEMCPY(ctx->reqDataKey, ctx->rspDataKey, sizeof(tmpKey));
    XMEMCPY(ctx->rspDataKey, tmpKey, sizeof(tmpKey));

    XMEMCPY(tmpIv, ctx->reqDataIv, sizeof(tmpIv));
    XMEMCPY(ctx->reqDataIv, ctx->rspDataIv, sizeof(tmpIv));
    XMEMCPY(ctx->rspDataIv, tmpIv, sizeof(tmpIv));

    tmpSeq = ctx->reqSeqNum;
    ctx->reqSeqNum = ctx->rspSeqNum;
    ctx->rspSeqNum = tmpSeq;

    wc_ForceZero(tmpKey, sizeof(tmpKey));
    wc_ForceZero(tmpIv, sizeof(tmpIv));
}

static int RespEncrypt(WOLFSPDM_CTX* ctx,
    const byte* plain, word32 plainSz, byte* enc, word32* encSz)
{
    int rc;
    RespSwapDataDir(ctx);
    rc = wolfSPDM_EncryptInternal(ctx, plain, plainSz, enc, encSz);
    RespSwapDataDir(ctx);
    return rc;
}

static int RespDecrypt(WOLFSPDM_CTX* ctx,
    const byte* enc, word32 encSz, byte* plain, word32* plainSz)
{
    int rc;
    RespSwapDataDir(ctx);
    rc = wolfSPDM_DecryptInternal(ctx, enc, encSz, plain, plainSz);
    RespSwapDataDir(ctx);
    return rc;
}

static int RespBuildVersion(WOLFSPDM_CTX* ctx,
    const byte* req, word32 reqSz,
    byte* out, word32* outSz)
{
    word32 off;

    (void)req;
    (void)reqSz;
    if (*outSz < 12) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }
    off = 0;
    out[off++] = SPDM_VERSION_10;
    out[off++] = SPDM_VERSION;
    out[off++] = 0x00;
    out[off++] = 0x00;
    /* VersionNumberEntryCount (LE) at offset 4. */
    out[off++] = 0x03;
    out[off++] = 0x00;
    /* Entries: 2 bytes each, byte+1 holds the version (Major<<4 | Minor). */
    out[off++] = 0x00; out[off++] = 0x10;
    out[off++] = 0x00; out[off++] = 0x12;
    out[off++] = 0x00; out[off++] = 0x13;
    *outSz = off;
    ctx->spdmVersion = SPDM_VERSION_13;
    return WOLFSPDM_SUCCESS;
}

/* Flags: ENCRYPT/MAC/KEY_EX_CAP always; PSK_CAP iff pskEnabled. */
static int RespBuildCapabilities(WOLFSPDM_CTX* ctx, int pskEnabled,
    const byte* req, word32 reqSz,
    byte* out, word32* outSz)
{
    word32 off;
    word32 flags;

    (void)req;
    (void)reqSz;
    if (*outSz < 20) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }
    flags = 0x000193C0UL;
    if (pskEnabled) {
        flags |= 0x00000400UL;
    }
    off = 0;
    out[off++] = ctx->spdmVersion;
    out[off++] = WOLFSPDM_CAPABILITIES;
    out[off++] = 0x00;
    out[off++] = 0x00;
    out[off++] = 0x00;
    out[off++] = 0x1F;
    out[off++] = 0x00;
    out[off++] = 0x00;
    SPDM_Set32LE(out + off, flags);
    off += 4;
    out[off++] = 0xC0; out[off++] = 0x07; out[off++] = 0x00; out[off++] = 0x00;
    out[off++] = 0xC0; out[off++] = 0x07; out[off++] = 0x00; out[off++] = 0x00;
    *outSz = off;
    return WOLFSPDM_SUCCESS;
}

/* Algorithm Set B (P-384/SHA-384/AES-256-GCM) is the only set we support. */
static int RespBuildAlgorithms(WOLFSPDM_CTX* ctx,
    const byte* req, word32 reqSz,
    byte* out, word32* outSz)
{
    word32 off;

    (void)req;
    (void)reqSz;
    if (*outSz < 52) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }
    off = 0;
    out[off++] = ctx->spdmVersion;
    out[off++] = WOLFSPDM_ALGORITHMS;
    out[off++] = 0x04;
    out[off++] = 0x00;
    out[off++] = 0x34; out[off++] = 0x00;
    out[off++] = 0x00; out[off++] = 0x02;
    out[off++] = 0x80; out[off++] = 0x00; out[off++] = 0x00; out[off++] = 0x00;
    out[off++] = 0x02; out[off++] = 0x00; out[off++] = 0x00; out[off++] = 0x00;
    XMEMSET(out + off, 0, 12); off += 12;
    out[off++] = 0x00; out[off++] = 0x00; out[off++] = 0x00; out[off++] = 0x00;
    out[off++] = 0x02; out[off++] = 0x20; out[off++] = 0x10; out[off++] = 0x00;
    out[off++] = 0x03; out[off++] = 0x20; out[off++] = 0x02; out[off++] = 0x00;
    out[off++] = 0x04; out[off++] = 0x20; out[off++] = 0x80; out[off++] = 0x00;
    out[off++] = 0x05; out[off++] = 0x20; out[off++] = 0x01; out[off++] = 0x00;
    *outSz = off;
    return WOLFSPDM_SUCCESS;
}

#ifdef WOLFTPM_SPDM_PSK
/* Transcript add splits across key derivation, matching the requester. */
static int RespBuildPskExchangeRsp(WOLFSPDM_RESP_CTX* rctx,
    const byte* in, word32 inSz,
    byte* out, word32* outSz)
{
    WOLFSPDM_CTX* ctx = &rctx->ctx;
    word16 reqContextLen;
    word16 reqHintLen;
    word16 reqOpaqueLen;
    word32 off;
    word32 partialLen;
    byte th1Hash[WOLFSPDM_HASH_SIZE];
    byte verifyData[WOLFSPDM_HASH_SIZE];
    int rc;

    if (inSz < 12 || rctx->pskStoreSz == 0) {
        return WOLFSPDM_E_BAD_STATE;
    }
    if (*outSz < 12u + 32u + WOLFSPDM_HASH_SIZE) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }
    /* Reload PSK from the persistent store - the requester-side helper
     * zeroes ctx->psk after derivation. */
    XMEMCPY(ctx->psk, rctx->pskStore, rctx->pskStoreSz);
    ctx->pskSz = rctx->pskStoreSz;
    if (rctx->pskHintStoreSz > 0) {
        XMEMCPY(ctx->pskHint, rctx->pskHintStore, rctx->pskHintStoreSz);
        ctx->pskHintSz = rctx->pskHintStoreSz;
    }

    ctx->reqSessionId = SPDM_Get16LE(&in[4]);
    reqHintLen = SPDM_Get16LE(&in[6]);
    reqContextLen = SPDM_Get16LE(&in[8]);
    reqOpaqueLen = SPDM_Get16LE(&in[10]);
    (void)reqHintLen;
    (void)reqContextLen;
    (void)reqOpaqueLen;

    ctx->rspSessionId = 0xFFFE;
    ctx->sessionId = (word32)ctx->reqSessionId |
                     ((word32)ctx->rspSessionId << 16);

    off = 0;
    out[off++] = ctx->spdmVersion;
    out[off++] = SPDM_PSK_EXCHANGE_RSP;
    out[off++] = 0x00;
    out[off++] = 0x00;
    SPDM_Set16LE(&out[off], ctx->rspSessionId); off += 2;
    out[off++] = 0x00;
    out[off++] = 0x00;
    SPDM_Set16LE(&out[off], 32); off += 2;
    SPDM_Set16LE(&out[off], 0);  off += 2;
    rc = wolfSPDM_GetRandom(ctx, &out[off], 32);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }
    off += 32;
    partialLen = off;

    rc = wolfSPDM_TranscriptAdd(ctx, out, partialLen);
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_TranscriptHash(ctx, th1Hash);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        XMEMCPY(ctx->th1, th1Hash, WOLFSPDM_HASH_SIZE);
        rc = wolfSPDM_DeriveHandshakeKeysPsk(ctx, th1Hash);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_ComputeVerifyData(ctx->rspFinishedKey, th1Hash,
            verifyData);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        XMEMCPY(&out[off], verifyData, WOLFSPDM_HASH_SIZE);
        off += WOLFSPDM_HASH_SIZE;
        rc = wolfSPDM_TranscriptAdd(ctx, verifyData, WOLFSPDM_HASH_SIZE);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        *outSz = off;
        ctx->state = WOLFSPDM_STATE_KEY_EX;
    }

    wc_ForceZero(verifyData, sizeof(verifyData));
    wc_ForceZero(th1Hash, sizeof(th1Hash));
    return rc;
}
#endif /* WOLFTPM_SPDM_PSK */

static int RespDispatchClear(WOLFSPDM_RESP_CTX* rctx,
    const byte* in, word32 inSz,
    byte* out, word32* outSz)
{
    WOLFSPDM_CTX* ctx = &rctx->ctx;
    byte code;
    int rc;
    int handlerManagesTranscript = 0;

    if (inSz < 2) {
        return WOLFSPDM_E_FRAMING;
    }
    code = in[1];

    if (code == SPDM_GET_VERSION) {
        wolfSPDM_TranscriptReset(ctx);
        wolfSPDM_RespReset(rctx);
    }

    /* VENDOR_DEFINED bytes don't go into the SPDM transcript - the
     * requester's wolfSPDM_TCG_VendorCmdClear doesn't add them, so the
     * responder mustn't either. GET_PUBK contributes via Ct = SHA-384
     * of its response payload, added separately below. */
    if (code != SPDM_VENDOR_DEFINED_REQUEST) {
        rc = wolfSPDM_TranscriptAdd(ctx, in, inSz);
        if (rc != WOLFSPDM_SUCCESS) {
            return rc;
        }
    }

    switch (code) {
        case SPDM_GET_VERSION:
            rc = RespBuildVersion(ctx, in, inSz, out, outSz);
            break;
        case WOLFSPDM_GET_CAPABILITIES:
            rc = RespBuildCapabilities(ctx, rctx->flags.usePsk,
                in, inSz, out, outSz);
            break;
        case WOLFSPDM_NEGOTIATE_ALGORITHMS:
            rc = RespBuildAlgorithms(ctx, in, inSz, out, outSz);
            break;
#ifdef WOLFTPM_SPDM_PSK
        case SPDM_PSK_EXCHANGE:
            rc = RespBuildPskExchangeRsp(rctx, in, inSz, out, outSz);
            handlerManagesTranscript = 1;
            break;
#endif
        case SPDM_KEY_EXCHANGE:
            rc = RespBuildKeyExchangeRsp(rctx, in, inSz, out, outSz);
            handlerManagesTranscript = 1;
            break;
        case SPDM_VENDOR_DEFINED_REQUEST:
            rc = RespHandleVendorDefined(rctx, in, inSz, out, outSz);
            handlerManagesTranscript = 1;
            /* For GET_PUBK specifically, mirror what the requester does:
             * add Ct = SHA-384(rspPubKey) to the transcript. Detected by
             * checking the VdCode in the inbound bytes at offset 9. */
            if (rc == WOLFSPDM_SUCCESS && inSz >= 17 &&
                XMEMCMP(in + 9, WOLFSPDM_VDCODE_GET_PUBK,
                        WOLFSPDM_VDCODE_LEN) == 0) {
                byte ct[WOLFSPDM_HASH_SIZE];
                int hrc = wolfSPDM_Sha384Hash(ct,
                    rctx->idPubKey, rctx->idPubKeyLen, NULL, 0, NULL, 0);
                if (hrc == WOLFSPDM_SUCCESS) {
                    hrc = wolfSPDM_TranscriptAdd(ctx, ct, WOLFSPDM_HASH_SIZE);
                }
                wc_ForceZero(ct, sizeof(ct));
                if (hrc != WOLFSPDM_SUCCESS) {
                    rc = hrc;
                }
            }
            break;
        default:
            return RespBuildErrorClear(ctx,
                SPDM_ERROR_UNSUPPORTED_REQUEST, code, out, outSz);
    }

    if (rc == WOLFSPDM_SUCCESS && !handlerManagesTranscript) {
        rc = wolfSPDM_TranscriptAdd(ctx, out, *outSz);
    }
    return rc;
}

#define WOLFSPDM_VENDOR_DEFINED_RSP 0x7E

/* KEY_EXCHANGE (clear) -> KEY_EXCHANGE_RSP (clear). Mirror of
 * wolfSPDM_BuildKeyExchange / wolfSPDM_ParseKeyExchangeRsp flipped to the
 * responder side: receive requester pubkey, generate own ephemeral key,
 * compute shared secret, sign TH1 with the identity key, derive handshake
 * keys, emit ResponderVerifyData. */
static int RespBuildKeyExchangeRsp(WOLFSPDM_RESP_CTX* rctx,
    const byte* in, word32 inSz,
    byte* out, word32* outSz)
{
    WOLFSPDM_CTX* ctx = &rctx->ctx;
    byte peerPubKeyX[WOLFSPDM_ECC_KEY_SIZE];
    byte peerPubKeyY[WOLFSPDM_ECC_KEY_SIZE];
    byte myPubX[WOLFSPDM_ECC_KEY_SIZE];
    byte myPubY[WOLFSPDM_ECC_KEY_SIZE];
    word32 myPubXSz = sizeof(myPubX);
    word32 myPubYSz = sizeof(myPubY);
    byte th1[WOLFSPDM_HASH_SIZE];
    byte signMsgHash[WOLFSPDM_HASH_SIZE];
    byte verifyData[WOLFSPDM_HASH_SIZE];
    byte savedReqPriv[WOLFSPDM_ECC_KEY_SIZE];
    byte savedReqPub[WOLFSPDM_ECC_POINT_SIZE];
    word32 savedReqPrivLen;
    byte savedHasReqKeyPair;
    word32 sigSz = WOLFSPDM_ECC_SIG_SIZE;
    word32 off;
    word32 partialLen;
    int rc;

    if (inSz < 136 || !rctx->flags.hasIdKey) {
        return WOLFSPDM_E_BAD_STATE;
    }
    if (*outSz < 138u + WOLFSPDM_ECC_SIG_SIZE + WOLFSPDM_HASH_SIZE) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    ctx->reqSessionId = SPDM_Get16LE(&in[4]);
    XMEMCPY(peerPubKeyX, &in[40], WOLFSPDM_ECC_KEY_SIZE);
    XMEMCPY(peerPubKeyY, &in[88], WOLFSPDM_ECC_KEY_SIZE);

    ctx->rspSessionId = 0xFFFE;
    ctx->sessionId = (word32)ctx->reqSessionId |
                     ((word32)ctx->rspSessionId << 16);

    off = 0;
    out[off++] = ctx->spdmVersion;
    out[off++] = SPDM_KEY_EXCHANGE_RSP;
    out[off++] = 0x00;
    out[off++] = 0x00;
    SPDM_Set16LE(&out[off], ctx->rspSessionId); off += 2;
    out[off++] = 0x00;  /* MutAuthRequested */
    out[off++] = 0x00;  /* SlotID */

    rc = wolfSPDM_GetRandom(ctx, &out[off], WOLFSPDM_RANDOM_SIZE);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }
    off += WOLFSPDM_RANDOM_SIZE;

    rc = wolfSPDM_GenerateEphemeralKey(ctx);
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_ExportEphemeralPubKey(ctx,
            myPubX, &myPubXSz, myPubY, &myPubYSz);
    }
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }
    XMEMCPY(&out[off], myPubX, WOLFSPDM_ECC_KEY_SIZE); off += WOLFSPDM_ECC_KEY_SIZE;
    XMEMCPY(&out[off], myPubY, WOLFSPDM_ECC_KEY_SIZE); off += WOLFSPDM_ECC_KEY_SIZE;
    SPDM_Set16LE(&out[off], 0); off += 2;  /* OpaqueLength = 0 */

    partialLen = off;

    rc = wolfSPDM_TranscriptAdd(ctx, out, partialLen);
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_TranscriptHash(ctx, th1);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_BuildSignedHash(ctx->spdmVersion,
            "responder-key_exchange_rsp signing", 34, th1, signMsgHash);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        /* wolfSPDM_SignHash signs with ctx->reqPrivKey/reqPubKey. Swap the
         * identity key in temporarily; restore on exit. */
        XMEMCPY(savedReqPriv, ctx->reqPrivKey, WOLFSPDM_ECC_KEY_SIZE);
        XMEMCPY(savedReqPub, ctx->reqPubKey, WOLFSPDM_ECC_POINT_SIZE);
        savedReqPrivLen = ctx->reqPrivKeyLen;
        savedHasReqKeyPair = ctx->flags.hasReqKeyPair;
        XMEMCPY(ctx->reqPrivKey, rctx->idPrivKey, WOLFSPDM_ECC_KEY_SIZE);
        XMEMCPY(ctx->reqPubKey, rctx->idPubKey, WOLFSPDM_ECC_POINT_SIZE);
        ctx->reqPrivKeyLen = WOLFSPDM_ECC_KEY_SIZE;
        ctx->flags.hasReqKeyPair = 1;
        rc = wolfSPDM_SignHash(ctx, signMsgHash, WOLFSPDM_HASH_SIZE,
            &out[off], &sigSz);
        XMEMCPY(ctx->reqPrivKey, savedReqPriv, WOLFSPDM_ECC_KEY_SIZE);
        XMEMCPY(ctx->reqPubKey, savedReqPub, WOLFSPDM_ECC_POINT_SIZE);
        ctx->reqPrivKeyLen = savedReqPrivLen;
        ctx->flags.hasReqKeyPair = savedHasReqKeyPair;
    }
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_TranscriptAdd(ctx, &out[off], WOLFSPDM_ECC_SIG_SIZE);
        off += WOLFSPDM_ECC_SIG_SIZE;
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
        rc = wolfSPDM_ComputeVerifyData(ctx->rspFinishedKey, ctx->th1,
            verifyData);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        XMEMCPY(&out[off], verifyData, WOLFSPDM_HASH_SIZE);
        off += WOLFSPDM_HASH_SIZE;
        rc = wolfSPDM_TranscriptAdd(ctx, verifyData, WOLFSPDM_HASH_SIZE);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        *outSz = off;
        ctx->state = WOLFSPDM_STATE_KEY_EX;
    }

    wc_ForceZero(savedReqPriv, sizeof(savedReqPriv));
    wc_ForceZero(verifyData, sizeof(verifyData));
    wc_ForceZero(signMsgHash, sizeof(signMsgHash));
    wc_ForceZero(th1, sizeof(th1));
    return rc;
}

/* FINISH (encrypted) -> FINISH_RSP (encrypted). Verifies the requester's
 * HMAC over TH2 with reqFinishedKey, then emits a 4-byte FINISH_RSP. App
 * keys derive after encryption (handled in the secured dispatcher). */
static int RespHandleFinish(WOLFSPDM_RESP_CTX* rctx,
    const byte* in, word32 inSz, byte* out, word32* outSz)
{
    WOLFSPDM_CTX* ctx = &rctx->ctx;
    byte th2[WOLFSPDM_HASH_SIZE];
    byte expectedHmac[WOLFSPDM_HASH_SIZE];
    int rc;
    word32 i;
    volatile int diff = 0;

    if (inSz < 4u + WOLFSPDM_HASH_SIZE) {
        return WOLFSPDM_E_FRAMING;
    }
    if (*outSz < 4) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    rc = wolfSPDM_TranscriptAdd(ctx, in, 4);
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_TranscriptHash(ctx, th2);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        XMEMCPY(ctx->th2, th2, WOLFSPDM_HASH_SIZE);
        rc = wolfSPDM_ComputeVerifyData(ctx->reqFinishedKey, th2,
            expectedHmac);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        for (i = 0; i < WOLFSPDM_HASH_SIZE; i++) {
            diff |= expectedHmac[i] ^ in[4 + i];
        }
        if (diff != 0) {
            rc = WOLFSPDM_E_BAD_HMAC;
        }
    }
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_TranscriptAdd(ctx, in + 4, WOLFSPDM_HASH_SIZE);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        out[0] = ctx->spdmVersion;
        out[1] = SPDM_FINISH_RSP;
        out[2] = 0x00;
        out[3] = 0x00;
        *outSz = 4;
        rc = wolfSPDM_TranscriptAdd(ctx, out, 4);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        ctx->state = WOLFSPDM_STATE_CONNECTED;
    }

    wc_ForceZero(expectedHmac, sizeof(expectedHmac));
    wc_ForceZero(th2, sizeof(th2));
    return rc;
}

#ifdef WOLFTPM_SPDM_PSK
static int RespHandlePskFinish(WOLFSPDM_RESP_CTX* rctx,
    const byte* in, word32 inSz, byte* out, word32* outSz)
{
    WOLFSPDM_CTX* ctx = &rctx->ctx;
    byte th2Hash[WOLFSPDM_HASH_SIZE];
    byte expectedHmac[WOLFSPDM_HASH_SIZE];
    int rc;
    word32 i;
    volatile int diff = 0;

    if (inSz < 4u + WOLFSPDM_HASH_SIZE) {
        return WOLFSPDM_E_FRAMING;
    }
    if (*outSz < 4) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    rc = wolfSPDM_TranscriptAdd(ctx, in, 4);
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_TranscriptHash(ctx, th2Hash);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        XMEMCPY(ctx->th2, th2Hash, WOLFSPDM_HASH_SIZE);
        rc = wolfSPDM_ComputeVerifyData(ctx->reqFinishedKey, th2Hash,
            expectedHmac);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        for (i = 0; i < WOLFSPDM_HASH_SIZE; i++) {
            diff |= expectedHmac[i] ^ in[4 + i];
        }
        if (diff != 0) {
            rc = WOLFSPDM_E_BAD_HMAC;
        }
    }
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_TranscriptAdd(ctx, in + 4, WOLFSPDM_HASH_SIZE);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        out[0] = ctx->spdmVersion;
        out[1] = SPDM_PSK_FINISH_RSP;
        out[2] = 0x00;
        out[3] = 0x00;
        *outSz = 4;
        rc = wolfSPDM_TranscriptAdd(ctx, out, 4);
    }
    /* App-key derivation runs in the caller AFTER PSK_FINISH_RSP is
     * encrypted with the still-current handshake keys (otherwise the
     * requester decrypts with handshake keys but we wrote with app keys). */
    if (rc == WOLFSPDM_SUCCESS) {
        ctx->state = WOLFSPDM_STATE_CONNECTED;
    }

    wc_ForceZero(expectedHmac, sizeof(expectedHmac));
    wc_ForceZero(th2Hash, sizeof(th2Hash));
    return rc;
}
#endif /* WOLFTPM_SPDM_PSK */

static int RespBuildEndSessionAck(WOLFSPDM_CTX* ctx,
    const byte* in, word32 inSz, byte* out, word32* outSz)
{
    (void)in;
    (void)inSz;
    if (*outSz < 4) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }
    out[0] = ctx->spdmVersion;
    out[1] = 0x6B;  /* END_SESSION_ACK */
    out[2] = 0x00;
    out[3] = 0x00;
    *outSz = 4;
    return WOLFSPDM_SUCCESS;
}

static int RespHandleVendorDefined(WOLFSPDM_RESP_CTX* rctx,
    const byte* in, word32 inSz, byte* out, word32* outSz)
{
    WOLFSPDM_CTX* ctx = &rctx->ctx;
    char vdCode[WOLFSPDM_VDCODE_LEN + 1];
    /* TPM2_CMD payloads carry large TPM commands (CreatePrimary RSA ~400
     * bytes), so buffers are sized to MAX_MSG_SIZE. Storage lives in the
     * per-context struct so concurrent ctxs don't share working memory. */
    byte* payload = rctx->vdInPayload;
    byte* respPayload = rctx->vdOutPayload;
    word32 payloadSz;
    word32 respPayloadSz = 0;
    word32 totalSz;
    word32 off;
    int rc;

    payloadSz = WOLFSPDM_MAX_MSG_SIZE;
    rc = wolfSPDM_ParseVendorDefined(in, inSz, vdCode, payload, &payloadSz);
    if (rc < 0) {
        return rc;
    }

    if (XSTRCMP(vdCode, WOLFSPDM_VDCODE_TPM2_CMD) == 0) {
        /* Reserve the VENDOR_DEFINED_RSP wrapper overhead
         * (1+1+1+1+2+1+2 = 9 fixed bytes + vdCode) so the TPM callback
         * cannot return more data than will fit inside the response
         * envelope. Otherwise the wrapper below silently returns
         * E_BUFFER_SMALL on the largest TPM responses. */
        word32 tpmRespCap = WOLFSPDM_MAX_MSG_SIZE
            - (9 + WOLFSPDM_VDCODE_LEN);
        if (rctx->tpmCb == NULL) {
            return WOLFSPDM_E_BAD_STATE;
        }
        rc = rctx->tpmCb(rctx->tpmCbUserCtx, payload, payloadSz,
            respPayload, tpmRespCap, &respPayloadSz);
        if (rc != 0) {
            return WOLFSPDM_E_IO_FAIL;
        }
    }
#ifdef WOLFTPM_SPDM_TCG
    else if (XSTRCMP(vdCode, WOLFSPDM_VDCODE_GET_PUBK) == 0) {
        if (!rctx->flags.hasIdKey) {
            return WOLFSPDM_E_BAD_STATE;
        }
        if (rctx->idPubKeyLen > WOLFSPDM_MAX_MSG_SIZE) {
            return WOLFSPDM_E_BUFFER_SMALL;
        }
        XMEMCPY(respPayload, rctx->idPubKey, rctx->idPubKeyLen);
        respPayloadSz = rctx->idPubKeyLen;
    }
    else if (XSTRCMP(vdCode, WOLFSPDM_VDCODE_GIVE_PUB) == 0) {
        if (payloadSz > sizeof(ctx->reqPubKeyTPMT)) {
            return WOLFSPDM_E_BUFFER_SMALL;
        }
        XMEMCPY(ctx->reqPubKeyTPMT, payload, payloadSz);
        ctx->reqPubKeyTPMTLen = payloadSz;
        respPayloadSz = 0;
    }
#if defined(WOLFSPDM_NUVOTON) || defined(WOLFSPDM_NATIONS)
    /* GET_STS_ / SPDMONLY are vendor-format adapters. Nuvoton and Nations
     * share the same vdcode strings and a compatible 4-byte status layout
     * - byte[2] is "Reserved" on Nuvoton and "PSKSet" on Nations (Nuvoton
     * never sets PSK, so a zero here is correct in either mode). */
    else if (XSTRCMP(vdCode, WOLFSPDM_VDCODE_GET_STS) == 0) {
        respPayload[0] = 0x00;
        respPayload[1] = 0x04;
        respPayload[2] = rctx->flags.pskProvisioned ? 0x01 : 0x00;
        respPayload[3] = rctx->flags.spdmOnlyLock   ? 0x01 : 0x00;
        respPayloadSz = 4;
    }
    else if (XSTRCMP(vdCode, WOLFSPDM_VDCODE_SPDMONLY) == 0) {
        if (payloadSz >= 1 && payload[0] == WOLFSPDM_SPDMONLY_LOCK) {
            rctx->flags.spdmOnlyLock = 1;
        }
        else {
            rctx->flags.spdmOnlyLock = 0;
        }
        respPayloadSz = 0;
    }
#endif /* WOLFSPDM_NUVOTON || WOLFSPDM_NATIONS */
#ifdef WOLFSPDM_NATIONS
    /* PSK_SET_ / PSK_CLR_ are Nations-proprietary PSK provisioning carried
     * over SPDM VENDOR_DEFINED. The DSP0274 spec leaves PSK delivery to the
     * implementation; we adopt Nations' NSING format here. */
    else if (XSTRCMP(vdCode, "PSK_SET_") == 0) {
        /* Payload: PSK + SHA-384(ClearAuth). */
        const word32 pskLen = (word32)sizeof(rctx->pskStore);
        if (payloadSz != pskLen + WOLFSPDM_HASH_SIZE) {
            return WOLFSPDM_E_INVALID_ARG;
        }
        XMEMCPY(rctx->pskStore, payload, pskLen);
        rctx->pskStoreSz = pskLen;
        XMEMCPY(rctx->clearAuthDigest, payload + pskLen, WOLFSPDM_HASH_SIZE);
        rctx->flags.pskProvisioned = 1;
        /* Mirror into ctx->psk so the next PSK_EXCHANGE can use it. */
        XMEMCPY(ctx->psk, rctx->pskStore, rctx->pskStoreSz);
        ctx->pskSz = rctx->pskStoreSz;
        respPayloadSz = 0;
    }
    else if (XSTRCMP(vdCode, "PSK_CLR_") == 0) {
        /* Payload: ClearAuth(32 raw bytes). Verify SHA-384 matches stored. */
        byte digest[WOLFSPDM_HASH_SIZE];
        volatile int diff = 0;
        word32 i;
        if (payloadSz != 32 || !rctx->flags.pskProvisioned) {
            return WOLFSPDM_E_INVALID_ARG;
        }
        rc = wolfSPDM_Sha384Hash(digest, payload, payloadSz,
            NULL, 0, NULL, 0);
        if (rc != WOLFSPDM_SUCCESS) {
            return rc;
        }
        /* Constant-time compare, matching the FINISH HMAC paths. */
        for (i = 0; i < WOLFSPDM_HASH_SIZE; i++) {
            diff |= digest[i] ^ rctx->clearAuthDigest[i];
        }
        wc_ForceZero(digest, sizeof(digest));
        if (diff != 0) {
            return WOLFSPDM_E_BAD_HMAC;
        }
        wc_ForceZero(rctx->pskStore, sizeof(rctx->pskStore));
        wc_ForceZero(rctx->clearAuthDigest, sizeof(rctx->clearAuthDigest));
        rctx->pskStoreSz = 0;
        rctx->flags.pskProvisioned = 0;
        wc_ForceZero(ctx->psk, sizeof(ctx->psk));
        ctx->pskSz = 0;
        respPayloadSz = 0;
    }
#endif /* WOLFSPDM_NATIONS */
#endif /* WOLFTPM_SPDM_TCG */
    else {
        return WOLFSPDM_E_NOT_AVAILABLE;
    }

    /* Build VENDOR_DEFINED_RSP frame (response code 0x7E). */
    totalSz = 1 + 1 + 1 + 1 + 2 + 1 + 2 + WOLFSPDM_VDCODE_LEN + respPayloadSz;
    if (*outSz < totalSz) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }
    off = 0;
    out[off++] = ctx->spdmVersion;
    out[off++] = WOLFSPDM_VENDOR_DEFINED_RSP;
    out[off++] = 0x00;
    out[off++] = 0x00;
    SPDM_Set16LE(out + off, 0x0001); off += 2;
    out[off++] = 0x00;
    SPDM_Set16LE(out + off, (word16)(WOLFSPDM_VDCODE_LEN + respPayloadSz));
    off += 2;
    XMEMCPY(out + off, vdCode, WOLFSPDM_VDCODE_LEN);
    off += WOLFSPDM_VDCODE_LEN;
    if (respPayloadSz > 0) {
        XMEMCPY(out + off, respPayload, respPayloadSz);
        off += respPayloadSz;
    }
    *outSz = off;
    return WOLFSPDM_SUCCESS;
}

static int RespDispatchSecured(WOLFSPDM_RESP_CTX* rctx,
    const byte* securedIn, word32 securedInSz,
    byte* securedOut, word32* securedOutSz)
{
    byte* plain = rctx->secureInPlain;
    byte* respPlain = rctx->secureOutPlain;
    WOLFSPDM_CTX* ctx = &rctx->ctx;
    word32 plainSz;
    word32 respPlainSz;
    byte code;
    int rc;
    int sessionEnded = 0;
    int derivedAppKeys = 0;

    plainSz = WOLFSPDM_MAX_MSG_SIZE;
    rc = RespDecrypt(ctx, securedIn, securedInSz, plain, &plainSz);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }
    if (plainSz < 2) {
        return WOLFSPDM_E_FRAMING;
    }
    code = plain[1];

    respPlainSz = WOLFSPDM_MAX_MSG_SIZE;
    switch (code) {
#ifdef WOLFTPM_SPDM_PSK
        case SPDM_PSK_FINISH:
            rc = RespHandlePskFinish(rctx, plain, plainSz,
                respPlain, &respPlainSz);
            derivedAppKeys = (rc == WOLFSPDM_SUCCESS) ? 1 : 0;
            break;
#endif
        case SPDM_FINISH:
            rc = RespHandleFinish(rctx, plain, plainSz,
                respPlain, &respPlainSz);
            derivedAppKeys = (rc == WOLFSPDM_SUCCESS) ? 1 : 0;
            break;
        case SPDM_END_SESSION:
            rc = RespBuildEndSessionAck(ctx, plain, plainSz,
                respPlain, &respPlainSz);
            sessionEnded = 1;
            break;
        case SPDM_VENDOR_DEFINED_REQUEST:
            rc = RespHandleVendorDefined(rctx, plain, plainSz,
                respPlain, &respPlainSz);
            break;
        default:
            rc = RespBuildErrorClear(ctx,
                SPDM_ERROR_UNSUPPORTED_REQUEST, code,
                respPlain, &respPlainSz);
            break;
    }

    if (rc == WOLFSPDM_SUCCESS) {
        rc = RespEncrypt(ctx, respPlain, respPlainSz,
            securedOut, securedOutSz);
    }
    if (rc == WOLFSPDM_SUCCESS && derivedAppKeys) {
        rc = wolfSPDM_DeriveAppDataKeys(ctx);
    }

    if (sessionEnded) {
        wolfSPDM_RespReset(rctx);
    }
    return rc;
}

#endif /* WOLFTPM_SPDM_TCG */

int wolfSPDM_RespHandleMessage(WOLFSPDM_RESP_CTX* ctx,
    const byte* inBuf, word32 inSz,
    byte* outBuf, word32* outSz)
{
#ifdef WOLFTPM_SPDM_TCG
    word16 tag;
    word32 msgSize;
    word32 payloadSz;
    word32 spdmOutSz;
    word32 totalSz;
    int rc;
#endif

    if (ctx == NULL || inBuf == NULL || outBuf == NULL || outSz == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }
    if (!ctx->flags.initialized) {
        return WOLFSPDM_E_BAD_STATE;
    }
    if (!ctx->flags.useTcg && !ctx->flags.usePsk) {
        return WOLFSPDM_E_BAD_STATE;
    }

    /* Bus-snooping defence: only TCG clear (0x8101) or secured (0x8201)
     * frames are accepted; anything else is rejected here. */
    if (inSz < WOLFSPDM_TCG_HEADER_SIZE) {
        return WOLFSPDM_E_FRAMING;
    }

#ifndef WOLFTPM_SPDM_TCG
    (void)inBuf;
    return WOLFSPDM_E_NOT_AVAILABLE;
#else
    tag = SPDM_Get16BE(inBuf);
    if (tag != WOLFSPDM_TCG_TAG_CLEAR && tag != WOLFSPDM_TCG_TAG_SECURED) {
        return WOLFSPDM_E_FRAMING;
    }
    msgSize = SPDM_Get32BE(inBuf + 2);
    if (msgSize < WOLFSPDM_TCG_HEADER_SIZE || msgSize > inSz) {
        return WOLFSPDM_E_FRAMING;
    }
    ctx->ctx.connectionHandle = SPDM_Get32BE(inBuf + 6);
    ctx->ctx.fipsIndicator = SPDM_Get16BE(inBuf + 10);
    payloadSz = msgSize - WOLFSPDM_TCG_HEADER_SIZE;

    if (*outSz < WOLFSPDM_TCG_HEADER_SIZE) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }
    spdmOutSz = *outSz - WOLFSPDM_TCG_HEADER_SIZE;

    if (tag == WOLFSPDM_TCG_TAG_CLEAR) {
        rc = RespDispatchClear(ctx,
            inBuf + WOLFSPDM_TCG_HEADER_SIZE, payloadSz,
            outBuf + WOLFSPDM_TCG_HEADER_SIZE, &spdmOutSz);
    }
    else {
        rc = RespDispatchSecured(ctx,
            inBuf + WOLFSPDM_TCG_HEADER_SIZE, payloadSz,
            outBuf + WOLFSPDM_TCG_HEADER_SIZE, &spdmOutSz);
    }

    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    totalSz = WOLFSPDM_TCG_HEADER_SIZE + spdmOutSz;
    wolfSPDM_WriteTcgHeader(outBuf, tag, totalSz,
        ctx->ctx.connectionHandle, ctx->ctx.fipsIndicator);
    *outSz = totalSz;
    return WOLFSPDM_SUCCESS;
#endif /* WOLFTPM_SPDM_TCG */
}

#endif /* WOLFTPM_SPDM_RESPONDER */
