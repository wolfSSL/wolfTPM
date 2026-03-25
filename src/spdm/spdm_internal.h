/* spdm_internal.h
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

#ifndef WOLFSPDM_INTERNAL_H
#define WOLFSPDM_INTERNAL_H

/* Include autoconf generated config.h for feature detection */
#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

/* spdm_types.h pulls in wolfSSL options via tpm2_types.h */
#include <wolftpm/spdm/spdm.h>
#include <wolftpm/spdm/spdm_types.h>
#include <wolftpm/spdm/spdm_error.h>

/* wolfCrypt includes - verify required algorithms */
#ifndef HAVE_ECC
    #error "wolfSPDM requires ECC (--enable-ecc in wolfSSL)"
#endif
#ifndef WOLFSSL_SHA384
    #error "wolfSPDM requires SHA-384 (--enable-sha384 in wolfSSL)"
#endif
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/kdf.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/memory.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ----- State Machine Constants ----- */

#define WOLFSPDM_STATE_INIT         0   /* Initial state */
#define WOLFSPDM_STATE_VERSION      1   /* GET_VERSION complete */
#define WOLFSPDM_STATE_CERT         2   /* GET_CERTIFICATE / GET_PUB_KEY complete */
#define WOLFSPDM_STATE_KEY_EX       3   /* KEY_EXCHANGE complete */
#define WOLFSPDM_STATE_FINISH       4   /* FINISH complete */
#define WOLFSPDM_STATE_CONNECTED    5   /* Session established */
#define WOLFSPDM_STATE_ERROR        6   /* Error state */

/* ----- Internal Context Structure ----- */

struct WOLFSPDM_CTX {
    /* State machine */
    int state;

    /* Protocol mode */
    WOLFSPDM_MODE mode;

    /* I/O callback */
    WOLFSPDM_IO_CB ioCb;
    void* ioUserCtx;

#ifdef WOLFTPM_SPDM_TCG
    /* TCG binding fields (shared by Nuvoton + Nations) */
    word32 connectionHandle;    /* Connection handle (usually 0) */
    word16 fipsIndicator;       /* FIPS service indicator */

    /* Host's public key in TPMT_PUBLIC format */
    byte reqPubKeyTPMT[WOLFSPDM_PUBKEY_BUF_SZ / 2]; /* TPMT_PUBLIC (~120 bytes) */
    word32 reqPubKeyTPMTLen;
#endif

#ifdef WOLFTPM_SPDM_PSK
    /* PSK fields */
    byte psk[WOLFSPDM_PSK_MAX_SIZE];
    word32 pskSz;               /* pskSz > 0 means PSK is set */
    byte pskHint[WOLFSPDM_PSK_HINT_MAX];
    word32 pskHintSz;
#endif

    /* Random number generator */
    WC_RNG rng;

    /* Negotiated parameters */
    byte maxVersion;            /* Runtime max version cap (0 = use compile-time default) */
    byte spdmVersion;           /* Negotiated SPDM version */

    /* Ephemeral ECDHE key (generated for KEY_EXCHANGE) */
    ecc_key ephemeralKey;

    /* ECDH shared secret (P-384 X-coordinate = 48 bytes) */
    byte sharedSecret[WOLFSPDM_ECC_KEY_SIZE];
    word32 sharedSecretSz;

    /* Transcript hash for TH1/TH2 computation */
    byte transcript[WOLFSPDM_MAX_TRANSCRIPT];
    word32 transcriptLen;

    /* Computed hashes */
    byte certChainHash[WOLFSPDM_HASH_SIZE]; /* Ct = Hash(cert_chain) */
    byte th1[WOLFSPDM_HASH_SIZE];           /* TH1 after KEY_EXCHANGE_RSP */
    byte th2[WOLFSPDM_HASH_SIZE];           /* TH2 after FINISH */

    /* Derived keys */
    byte handshakeSecret[WOLFSPDM_HASH_SIZE];
    byte reqHsSecret[WOLFSPDM_HASH_SIZE];
    byte rspHsSecret[WOLFSPDM_HASH_SIZE];
    byte reqFinishedKey[WOLFSPDM_HASH_SIZE];
    byte rspFinishedKey[WOLFSPDM_HASH_SIZE];

    /* Session encryption keys (AES-256-GCM) */
    byte reqDataKey[WOLFSPDM_AEAD_KEY_SIZE];   /* Outgoing encryption key */
    byte rspDataKey[WOLFSPDM_AEAD_KEY_SIZE];   /* Incoming decryption key */
    byte reqDataIv[WOLFSPDM_AEAD_IV_SIZE];     /* Base IV for outgoing */
    byte rspDataIv[WOLFSPDM_AEAD_IV_SIZE];     /* Base IV for incoming */

    /* Sequence numbers for IV generation */
    word64 reqSeqNum;           /* Outgoing message sequence */
    word64 rspSeqNum;           /* Incoming message sequence (expected) */

    /* Session IDs */
    word16 reqSessionId;        /* Our session ID (chosen by us) */
    word16 rspSessionId;        /* Responder's session ID */
    word32 sessionId;           /* Combined: reqSessionId | (rspSessionId << 16) */

    /* Responder's identity public key (for cert-less mode like Nuvoton) */
    byte rspPubKey[WOLFSPDM_PUBKEY_BUF_SZ / 2]; /* TPMT_PUBLIC or raw X||Y */
    word32 rspPubKeyLen;

    /* Mutual auth fields from KEY_EXCHANGE_RSP */
    byte mutAuthRequested;      /* MutAuthRequested from KEY_EXCHANGE_RSP */
    byte reqSlotIdParam;        /* ReqSlotIDParam from KEY_EXCHANGE_RSP */

    /* Requester's identity key pair (for mutual auth) */
    byte reqPrivKey[WOLFSPDM_ECC_KEY_SIZE];
    word32 reqPrivKeyLen;
    byte reqPubKey[WOLFSPDM_ECC_POINT_SIZE];

    /* Boolean flag bit field (at end for better struct packing) */
    struct {
        unsigned int debug              : 1;
        unsigned int initialized        : 1;
        unsigned int isDynamic          : 1;  /* Set by wolfSPDM_New(), checked by Free */
        unsigned int rngInitialized     : 1;
        unsigned int ephemeralKeyInit   : 1;
        unsigned int hasRspPubKey       : 1;
        unsigned int hasReqKeyPair      : 1;
    } flags;
};

/* ----- Byte-Order Helpers ----- */

static WC_INLINE void SPDM_Set16LE(byte* buf, word16 val) {
    buf[0] = (byte)(val & 0xFF); buf[1] = (byte)(val >> 8);
}
static WC_INLINE word16 SPDM_Get16LE(const byte* buf) {
    return (word16)(buf[0] | (buf[1] << 8));
}
static WC_INLINE void SPDM_Set16BE(byte* buf, word16 val) {
    buf[0] = (byte)(val >> 8); buf[1] = (byte)(val & 0xFF);
}
static WC_INLINE word16 SPDM_Get16BE(const byte* buf) {
    return (word16)((buf[0] << 8) | buf[1]);
}
static WC_INLINE void SPDM_Set32LE(byte* buf, word32 val) {
    buf[0] = (byte)(val & 0xFF);       buf[1] = (byte)((val >> 8) & 0xFF);
    buf[2] = (byte)((val >> 16) & 0xFF); buf[3] = (byte)((val >> 24) & 0xFF);
}
static WC_INLINE word32 SPDM_Get32LE(const byte* buf) {
    return (word32)buf[0] | ((word32)buf[1] << 8) |
           ((word32)buf[2] << 16) | ((word32)buf[3] << 24);
}
static WC_INLINE void SPDM_Set32BE(byte* buf, word32 val) {
    buf[0] = (byte)(val >> 24);         buf[1] = (byte)((val >> 16) & 0xFF);
    buf[2] = (byte)((val >> 8) & 0xFF); buf[3] = (byte)(val & 0xFF);
}
static WC_INLINE word32 SPDM_Get32BE(const byte* buf) {
    return ((word32)buf[0] << 24) | ((word32)buf[1] << 16) |
           ((word32)buf[2] << 8) | (word32)buf[3];
}
static WC_INLINE void SPDM_Set64LE(byte* buf, word64 val) {
    buf[0] = (byte)(val & 0xFF);         buf[1] = (byte)((val >> 8) & 0xFF);
    buf[2] = (byte)((val >> 16) & 0xFF); buf[3] = (byte)((val >> 24) & 0xFF);
    buf[4] = (byte)((val >> 32) & 0xFF); buf[5] = (byte)((val >> 40) & 0xFF);
    buf[6] = (byte)((val >> 48) & 0xFF); buf[7] = (byte)((val >> 56) & 0xFF);
}
static WC_INLINE word64 SPDM_Get64LE(const byte* buf) {
    return (word64)buf[0] | ((word64)buf[1] << 8) |
           ((word64)buf[2] << 16) | ((word64)buf[3] << 24) |
           ((word64)buf[4] << 32) | ((word64)buf[5] << 40) |
           ((word64)buf[6] << 48) | ((word64)buf[7] << 56);
}

/* ----- Write TCG SPDM Binding header ----- */
/* tag(2/BE) + size(4/BE) +
 * connHandle(4/BE) + fips(2/BE) + reserved(4) */
#ifdef WOLFTPM_SPDM_TCG
static WC_INLINE void wolfSPDM_WriteTcgHeader(byte* buf, word16 tag,
    word32 totalSz, word32 connHandle, word16 fips)
{
    SPDM_Set16BE(buf, tag);
    SPDM_Set32BE(buf + 2, totalSz);
    SPDM_Set32BE(buf + 6, connHandle);
    SPDM_Set16BE(buf + 10, fips);
    XMEMSET(buf + 12, 0, 4);  /* Reserved */
}
#endif

/* ----- Build IV ----- */
static WC_INLINE void wolfSPDM_BuildIV(byte* iv, const byte* baseIv,
    word64 seqNum)
{
    byte seq[8]; int i;
    XMEMCPY(iv, baseIv, WOLFSPDM_AEAD_IV_SIZE);
    SPDM_Set64LE(seq, seqNum);
    for (i = 0; i < 8; i++) iv[i] ^= seq[i];
}

/* ----- Connect Step Macro ----- */

#define SPDM_CONNECT_STEP(ctx, msg, func) do { \
    wolfSPDM_DebugPrint(ctx, msg); \
    rc = func; \
    if (rc != WOLFSPDM_SUCCESS) { ctx->state = WOLFSPDM_STATE_ERROR; return rc; } \
} while (0)

/* ----- Argument Validation Macros ----- */

#define SPDM_CHECK_BUILD_ARGS(ctx, buf, bufSz, minSz) \
    do { \
        if ((ctx) == NULL || (buf) == NULL || (bufSz) == NULL) \
            return WOLFSPDM_E_INVALID_ARG; \
        if (*(bufSz) < (minSz)) \
            return WOLFSPDM_E_BUFFER_SMALL; \
    } while(0)

#define SPDM_CHECK_PARSE_ARGS(ctx, buf, bufSz, minSz) \
    do { \
        if ((ctx) == NULL || (buf) == NULL || (bufSz) < (minSz)) \
            return WOLFSPDM_E_INVALID_ARG; \
    } while(0)

/* ----- Response Code Check Macro ----- */

#define SPDM_CHECK_RESPONSE(ctx, buf, bufSz, expected, fallbackErr) \
    do { \
        if ((buf)[1] != (expected)) { \
            int _ec; \
            if (wolfSPDM_CheckError((buf), (bufSz), &_ec)) { \
                wolfSPDM_DebugPrint((ctx), "SPDM error: 0x%02x\n", _ec); \
                return WOLFSPDM_E_PEER_ERROR; \
            } \
            return (fallbackErr); \
        } \
    } while (0)

/* ----- Internal Function Declarations - Transcript ----- */

WOLFTPM_LOCAL void wolfSPDM_TranscriptReset(WOLFSPDM_CTX* ctx);
WOLFTPM_LOCAL int wolfSPDM_TranscriptAdd(WOLFSPDM_CTX* ctx, const byte* data, word32 len);
WOLFTPM_LOCAL int wolfSPDM_TranscriptHash(WOLFSPDM_CTX* ctx, byte* hash);
WOLFTPM_LOCAL int wolfSPDM_Sha384Hash(byte* out,
    const byte* d1, word32 d1Sz,
    const byte* d2, word32 d2Sz,
    const byte* d3, word32 d3Sz);

/* ----- Internal Function Declarations - Crypto ----- */

WOLFTPM_LOCAL int wolfSPDM_GenerateEphemeralKey(WOLFSPDM_CTX* ctx);
WOLFTPM_LOCAL int wolfSPDM_ExportEphemeralPubKey(WOLFSPDM_CTX* ctx,
    byte* pubKeyX, word32* pubKeyXSz,
    byte* pubKeyY, word32* pubKeyYSz);
WOLFTPM_LOCAL int wolfSPDM_ComputeSharedSecret(WOLFSPDM_CTX* ctx,
    const byte* peerPubKeyX, const byte* peerPubKeyY);
WOLFTPM_LOCAL int wolfSPDM_GetRandom(WOLFSPDM_CTX* ctx, byte* out, word32 outSz);
WOLFTPM_LOCAL int wolfSPDM_SignHash(WOLFSPDM_CTX* ctx, const byte* hash, word32 hashSz,
    byte* sig, word32* sigSz);
WOLFTPM_LOCAL int wolfSPDM_VerifySignature(WOLFSPDM_CTX* ctx,
    const byte* hash, word32 hashSz,
    const byte* sig, word32 sigSz);

/* ----- Internal Function Declarations - Key Derivation ----- */

WOLFTPM_LOCAL int wolfSPDM_DeriveHandshakeKeys(WOLFSPDM_CTX* ctx, const byte* th1Hash);
WOLFTPM_LOCAL int wolfSPDM_DeriveFromHandshakeSecret(WOLFSPDM_CTX* ctx, const byte* th1Hash);
WOLFTPM_LOCAL int wolfSPDM_DeriveAppDataKeys(WOLFSPDM_CTX* ctx);
WOLFTPM_LOCAL int wolfSPDM_HkdfExpandLabel(byte spdmVersion, const byte* secret, word32 secretSz,
    const char* label, const byte* context, word32 contextSz,
    byte* out, word32 outSz);
WOLFTPM_LOCAL int wolfSPDM_ComputeVerifyData(const byte* finishedKey, const byte* thHash,
    byte* verifyData);

/* ----- Internal Function Declarations - Message Building ----- */

WOLFTPM_LOCAL int wolfSPDM_BuildGetVersion(byte* buf, word32* bufSz);
WOLFTPM_LOCAL int wolfSPDM_BuildKeyExchange(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz);
WOLFTPM_LOCAL int wolfSPDM_BuildFinish(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz);
WOLFTPM_LOCAL int wolfSPDM_BuildEndSession(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz);
/* PSK message builders/parsers declared in spdm_psk.h */

/* ----- Internal Function Declarations - Message Parsing ----- */

WOLFTPM_LOCAL int wolfSPDM_ParseVersion(WOLFSPDM_CTX* ctx, const byte* buf, word32 bufSz);
WOLFTPM_LOCAL int wolfSPDM_ParseKeyExchangeRsp(WOLFSPDM_CTX* ctx, const byte* buf, word32 bufSz);
WOLFTPM_LOCAL int wolfSPDM_ParseFinishRsp(WOLFSPDM_CTX* ctx, const byte* buf, word32 bufSz);
WOLFTPM_LOCAL int wolfSPDM_CheckError(const byte* buf, word32 bufSz, int* errorCode);

/* ----- Internal Function Declarations - Secured Messaging ----- */

WOLFTPM_LOCAL int wolfSPDM_EncryptInternal(WOLFSPDM_CTX* ctx,
    const byte* plain, word32 plainSz,
    byte* enc, word32* encSz);
WOLFTPM_LOCAL int wolfSPDM_DecryptInternal(WOLFSPDM_CTX* ctx,
    const byte* enc, word32 encSz,
    byte* plain, word32* plainSz);

/* ----- Internal Utility Functions ----- */

WOLFTPM_LOCAL int wolfSPDM_SendReceive(WOLFSPDM_CTX* ctx,
    const byte* txBuf, word32 txSz,
    byte* rxBuf, word32* rxSz);

#ifdef DEBUG_WOLFTPM
WOLFTPM_LOCAL void wolfSPDM_DebugPrint(WOLFSPDM_CTX* ctx, const char* fmt, ...)
#ifdef __GNUC__
    __attribute__((format(printf, 2, 3)))
#endif
    ;

WOLFTPM_LOCAL void wolfSPDM_DebugHex(WOLFSPDM_CTX* ctx, const char* label,
    const byte* data, word32 len);
#else
#define wolfSPDM_DebugPrint(ctx, fmt, ...) do { (void)(ctx); (void)fmt; } while(0)
#define wolfSPDM_DebugHex(ctx, label, data, len) do { (void)(ctx); (void)(label); (void)(data); (void)(len); } while(0)
#endif

#ifdef __cplusplus
}
#endif

#endif /* WOLFSPDM_INTERNAL_H */
