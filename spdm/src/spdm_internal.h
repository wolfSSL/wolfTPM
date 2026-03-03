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

/* wolfSSL options MUST be included first */
#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>

#include <wolfspdm/spdm.h>
#include <wolfspdm/spdm_types.h>
#include <wolfspdm/spdm_error.h>

/* wolfCrypt includes */
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/kdf.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/memory.h>
#include <wolfssl/wolfcrypt/asn_public.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --- State Machine Constants --- */

#define WOLFSPDM_STATE_INIT         0   /* Initial state */
#define WOLFSPDM_STATE_VERSION      1   /* GET_VERSION complete */
#define WOLFSPDM_STATE_CAPS         2   /* GET_CAPABILITIES complete */
#define WOLFSPDM_STATE_ALGO         3   /* NEGOTIATE_ALGORITHMS complete */
#define WOLFSPDM_STATE_DIGESTS      4   /* GET_DIGESTS complete */
#define WOLFSPDM_STATE_CERT         5   /* GET_CERTIFICATE complete */
#define WOLFSPDM_STATE_KEY_EX       6   /* KEY_EXCHANGE complete */
#define WOLFSPDM_STATE_FINISH       7   /* FINISH complete */
#define WOLFSPDM_STATE_CONNECTED    8   /* Session established */
#define WOLFSPDM_STATE_ERROR        9   /* Error state */
#ifndef NO_WOLFSPDM_MEAS
#define WOLFSPDM_STATE_MEASURED     10  /* Measurements retrieved */
#endif

/* --- Measurement Block Structure --- */

#ifndef NO_WOLFSPDM_MEAS
typedef struct WOLFSPDM_MEAS_BLOCK {
    byte   index;                                   /* SPDM measurement index (1-based) */
    byte   measurementSpec;                         /* Measurement specification (1=DMTF) */
    byte   dmtfType;                                /* DMTFSpecMeasurementValueType */
    word16 valueSize;                               /* Actual value size in bytes */
    byte   value[WOLFSPDM_MAX_MEAS_VALUE_SIZE];     /* Measurement value (digest/raw) */
} WOLFSPDM_MEAS_BLOCK;
#endif /* !NO_WOLFSPDM_MEAS */

/* --- Internal Context Structure --- */

struct WOLFSPDM_CTX {
    /* State machine */
    int state;

    /* Boolean flags — packed into a bit-field struct to save ~28 bytes */
    struct {
        byte debug              : 1;
        byte initialized        : 1;
        byte isDynamic          : 1;  /* Set by wolfSPDM_New(), checked by Free */
        byte rngInitialized     : 1;
        byte ephemeralKeyInit   : 1;
        byte hasRspPubKey       : 1;
        byte hasReqKeyPair      : 1;
        byte hasMeasurements    : 1;
        byte hasResponderPubKey : 1;
        byte hasTrustedCAs      : 1;
        byte m1m2HashInit       : 1;
    } flags;

    /* Protocol mode (standard SPDM or Nuvoton) */
    WOLFSPDM_MODE mode;

    /* I/O callback */
    WOLFSPDM_IO_CB ioCb;
    void* ioUserCtx;

#ifdef WOLFSPDM_NUVOTON
    /* Nuvoton-specific: TCG binding fields */
    word32 connectionHandle;    /* Connection handle (usually 0) */
    word16 fipsIndicator;       /* FIPS service indicator */

    /* Nuvoton-specific: Host's public key in TPMT_PUBLIC format */
    byte reqPubKeyTPMT[128];    /* TPMT_PUBLIC serialized (~120 bytes) */
    word32 reqPubKeyTPMTLen;
#endif

    /* Random number generator */
    WC_RNG rng;

    /* Negotiated parameters */
    byte maxVersion;            /* Runtime max version cap (0 = use compile-time default) */
    byte spdmVersion;           /* Negotiated SPDM version */
    word32 rspCaps;             /* Responder capabilities */
    word32 reqCaps;             /* Our (requester) capabilities */
    byte mutAuthRequested;      /* MutAuthRequested from KEY_EXCHANGE_RSP (offset 6) */
    byte reqSlotId;             /* ReqSlotIDParam from KEY_EXCHANGE_RSP (offset 7) */

    /* Ephemeral ECDHE key (generated for KEY_EXCHANGE) */
    ecc_key ephemeralKey;

    /* ECDH shared secret (P-384 X-coordinate = 48 bytes) */
    byte sharedSecret[WOLFSPDM_ECC_KEY_SIZE];
    word32 sharedSecretSz;

    /* Transcript hash for TH1/TH2 computation */
    byte transcript[WOLFSPDM_MAX_TRANSCRIPT];
    word32 transcriptLen;
    word32 vcaLen;  /* VCA transcript size (after ALGORITHMS, used by measurement sig) */

    /* Certificate chain buffer for Ct computation */
    byte certChain[WOLFSPDM_MAX_CERT_CHAIN];
    word32 certChainLen;

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
    byte rspPubKey[128];  /* TPMT_PUBLIC (120 bytes for P-384) or raw X||Y (96) */
    word32 rspPubKeyLen;

    /* Requester's identity key pair (for mutual auth) */
    byte reqPrivKey[WOLFSPDM_ECC_KEY_SIZE];
    word32 reqPrivKeyLen;
    byte reqPubKey[WOLFSPDM_ECC_POINT_SIZE];
    word32 reqPubKeyLen;

#ifndef NO_WOLFSPDM_MEAS
    /* Measurement data */
    WOLFSPDM_MEAS_BLOCK measBlocks[WOLFSPDM_MAX_MEAS_BLOCKS];
    word32 measBlockCount;
    byte   measNonce[32];                           /* Nonce for signed measurements */
    byte   measSummaryHash[WOLFSPDM_HASH_SIZE];     /* Summary hash from response */
    byte   measSignature[WOLFSPDM_ECC_SIG_SIZE];    /* Captured signature (96 bytes P-384) */
    word32 measSignatureSize;                       /* 0 if unsigned, 96 if signed */

#ifndef NO_WOLFSPDM_MEAS_VERIFY
    /* Saved GET_MEASUREMENTS request for L1/L2 transcript */
    byte            measReqMsg[48];                 /* Saved request (max 37 bytes) */
    word32          measReqMsgSz;
#endif /* !NO_WOLFSPDM_MEAS_VERIFY */
#endif /* !NO_WOLFSPDM_MEAS */

    /* Responder identity for signature verification (measurements + challenge) */
    ecc_key         responderPubKey;                /* Extracted from cert chain leaf */

    /* Certificate chain validation */
    byte   trustedCAs[WOLFSPDM_MAX_CERT_CHAIN];    /* DER-encoded root CAs */
    word32 trustedCAsSz;

#ifndef NO_WOLFSPDM_CHALLENGE
    /* Challenge authentication */
    byte   challengeNonce[32];                      /* Saved nonce from CHALLENGE request */
    byte   challengeMeasHashType;                   /* MeasurementSummaryHashType from req */

    /* Running M1/M2 hash for CHALLENGE_AUTH signature verification.
     * Per DSP0274, M1/M2 = A || B || C where:
     *   A = VCA (GET_VERSION..ALGORITHMS)
     *   B = GET_DIGESTS + DIGESTS + GET_CERTIFICATE + CERTIFICATE (all chunks)
     *   C = CHALLENGE + CHALLENGE_AUTH (before sig)
     * This hash accumulates A+B during NegAlgo/GetDigests/GetCertificate,
     * then C is added in VerifyChallengeAuthSig. */
    wc_Sha384 m1m2Hash;
#endif

    /* Key update state — app secrets for re-derivation */
    byte   reqAppSecret[WOLFSPDM_HASH_SIZE];        /* 48 bytes */
    byte   rspAppSecret[WOLFSPDM_HASH_SIZE];        /* 48 bytes */
};

/* --- Byte-Order Helpers --- */

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

/* Write TCG SPDM Binding header (16 bytes): tag(2/BE) + size(4/BE) +
 * connHandle(4/BE) + fips(2/BE) + reserved(4) */
#ifdef WOLFSPDM_NUVOTON
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

/* Build IV: BaseIV XOR zero-extended sequence number (DSP0277) */
static WC_INLINE void wolfSPDM_BuildIV(byte* iv, const byte* baseIv,
    word64 seqNum, int nuvotonMode)
{
    XMEMCPY(iv, baseIv, WOLFSPDM_AEAD_IV_SIZE);
#ifdef WOLFSPDM_NUVOTON
    if (nuvotonMode) {
        byte seq[8]; int i;
        SPDM_Set64LE(seq, seqNum);
        for (i = 0; i < 8; i++) iv[i] ^= seq[i];
    }
    else
#endif
    {
        (void)nuvotonMode;
        iv[0] ^= (byte)(seqNum & 0xFF);
        iv[1] ^= (byte)((seqNum >> 8) & 0xFF);
    }
}

/* --- Connect Step Macro --- */

#define SPDM_CONNECT_STEP(ctx, msg, func) do { \
    wolfSPDM_DebugPrint(ctx, msg); \
    rc = func; \
    if (rc != WOLFSPDM_SUCCESS) { ctx->state = WOLFSPDM_STATE_ERROR; return rc; } \
} while (0)

/* --- Argument Validation Macros --- */

#define SPDM_CHECK_BUILD_ARGS(ctx, buf, bufSz, minSz) \
    if ((ctx) == NULL || (buf) == NULL || (bufSz) == NULL) \
        return WOLFSPDM_E_INVALID_ARG; \
    if (*(bufSz) < (minSz)) \
        return WOLFSPDM_E_BUFFER_SMALL

#define SPDM_CHECK_PARSE_ARGS(ctx, buf, bufSz, minSz) \
    if ((ctx) == NULL || (buf) == NULL || (bufSz) < (minSz)) \
        return WOLFSPDM_E_INVALID_ARG

/* --- Response Code Check Macro --- */

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

/* --- Internal Function Declarations - Transcript --- */

/* Reset transcript buffer */
WOLFSPDM_API void wolfSPDM_TranscriptReset(WOLFSPDM_CTX* ctx);

/* Add data to transcript */
WOLFSPDM_API int wolfSPDM_TranscriptAdd(WOLFSPDM_CTX* ctx, const byte* data, word32 len);

/* Add data to certificate chain buffer */
WOLFSPDM_API int wolfSPDM_CertChainAdd(WOLFSPDM_CTX* ctx, const byte* data, word32 len);

/* Compute hash of current transcript */
WOLFSPDM_API int wolfSPDM_TranscriptHash(WOLFSPDM_CTX* ctx, byte* hash);

/* Compute Ct = Hash(certificate_chain) */
WOLFSPDM_API int wolfSPDM_ComputeCertChainHash(WOLFSPDM_CTX* ctx);

/* SHA-384 hash helper: Hash(d1 || d2 || d3), pass NULL/0 for unused buffers */
WOLFSPDM_API int wolfSPDM_Sha384Hash(byte* out,
    const byte* d1, word32 d1Sz,
    const byte* d2, word32 d2Sz,
    const byte* d3, word32 d3Sz);

/* --- Internal Function Declarations - Crypto --- */

/* Generate ephemeral P-384 key for ECDHE */
WOLFSPDM_API int wolfSPDM_GenerateEphemeralKey(WOLFSPDM_CTX* ctx);

/* Export ephemeral public key (X||Y) */
WOLFSPDM_API int wolfSPDM_ExportEphemeralPubKey(WOLFSPDM_CTX* ctx,
    byte* pubKeyX, word32* pubKeyXSz,
    byte* pubKeyY, word32* pubKeyYSz);

/* Compute ECDH shared secret from responder's public key */
WOLFSPDM_API int wolfSPDM_ComputeSharedSecret(WOLFSPDM_CTX* ctx,
    const byte* peerPubKeyX, const byte* peerPubKeyY);

/* Generate random bytes */
WOLFSPDM_API int wolfSPDM_GetRandom(WOLFSPDM_CTX* ctx, byte* out, word32 outSz);

/* Sign hash with requester's private key (for mutual auth FINISH) */
WOLFSPDM_API int wolfSPDM_SignHash(WOLFSPDM_CTX* ctx, const byte* hash, word32 hashSz,
    byte* sig, word32* sigSz);

/* --- Internal Function Declarations - Key Derivation --- */

/* Derive all keys from shared secret and TH1 */
WOLFSPDM_API int wolfSPDM_DeriveHandshakeKeys(WOLFSPDM_CTX* ctx, const byte* th1Hash);

/* Derive application data keys from MasterSecret and TH2_final */
WOLFSPDM_API int wolfSPDM_DeriveAppDataKeys(WOLFSPDM_CTX* ctx);

/* HKDF-Expand with SPDM BinConcat format (uses version-specific prefix) */
WOLFSPDM_API int wolfSPDM_HkdfExpandLabel(byte spdmVersion, const byte* secret, word32 secretSz,
    const char* label, const byte* context, word32 contextSz,
    byte* out, word32 outSz);

/* Compute HMAC for VerifyData */
WOLFSPDM_API int wolfSPDM_ComputeVerifyData(const byte* finishedKey, const byte* thHash,
    byte* verifyData);

/* --- Internal Function Declarations - Message Building --- */

/* Build GET_VERSION request */
WOLFSPDM_API int wolfSPDM_BuildGetVersion(byte* buf, word32* bufSz);

/* Build GET_CAPABILITIES request */
WOLFSPDM_API int wolfSPDM_BuildGetCapabilities(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz);

/* Build NEGOTIATE_ALGORITHMS request */
WOLFSPDM_API int wolfSPDM_BuildNegotiateAlgorithms(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz);

/* Build GET_DIGESTS request */
WOLFSPDM_API int wolfSPDM_BuildGetDigests(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz);

/* Build GET_CERTIFICATE request */
WOLFSPDM_API int wolfSPDM_BuildGetCertificate(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz,
    int slotId, word16 offset, word16 length);

/* Build KEY_EXCHANGE request */
WOLFSPDM_API int wolfSPDM_BuildKeyExchange(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz);

/* Build FINISH request */
WOLFSPDM_API int wolfSPDM_BuildFinish(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz);

/* Build END_SESSION request */
WOLFSPDM_API int wolfSPDM_BuildEndSession(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz);

/* --- Internal Function Declarations - Message Parsing --- */

/* Parse VERSION response */
WOLFSPDM_API int wolfSPDM_ParseVersion(WOLFSPDM_CTX* ctx, const byte* buf, word32 bufSz);

/* Parse CAPABILITIES response */
WOLFSPDM_API int wolfSPDM_ParseCapabilities(WOLFSPDM_CTX* ctx, const byte* buf, word32 bufSz);

/* Parse ALGORITHMS response */
WOLFSPDM_API int wolfSPDM_ParseAlgorithms(WOLFSPDM_CTX* ctx, const byte* buf, word32 bufSz);

/* Parse DIGESTS response */
WOLFSPDM_API int wolfSPDM_ParseDigests(WOLFSPDM_CTX* ctx, const byte* buf, word32 bufSz);

/* Parse CERTIFICATE response */
WOLFSPDM_API int wolfSPDM_ParseCertificate(WOLFSPDM_CTX* ctx, const byte* buf, word32 bufSz,
    word16* portionLen, word16* remainderLen);

/* Parse KEY_EXCHANGE_RSP */
WOLFSPDM_API int wolfSPDM_ParseKeyExchangeRsp(WOLFSPDM_CTX* ctx, const byte* buf, word32 bufSz);

/* Parse FINISH_RSP (after decryption) */
WOLFSPDM_API int wolfSPDM_ParseFinishRsp(WOLFSPDM_CTX* ctx, const byte* buf, word32 bufSz);

/* Check for ERROR response */
WOLFSPDM_API int wolfSPDM_CheckError(const byte* buf, word32 bufSz, int* errorCode);

/* --- Internal Function Declarations - Secured Messaging --- */

/* Encrypt plaintext using session keys */
WOLFSPDM_API int wolfSPDM_EncryptInternal(WOLFSPDM_CTX* ctx,
    const byte* plain, word32 plainSz,
    byte* enc, word32* encSz);

/* Decrypt ciphertext using session keys */
WOLFSPDM_API int wolfSPDM_DecryptInternal(WOLFSPDM_CTX* ctx,
    const byte* enc, word32 encSz,
    byte* plain, word32* plainSz);

/* --- Internal Utility Functions --- */

/* Send message via I/O callback and receive response */
WOLFSPDM_API int wolfSPDM_SendReceive(WOLFSPDM_CTX* ctx,
    const byte* txBuf, word32 txSz,
    byte* rxBuf, word32* rxSz);

/* Debug print (if enabled) */
WOLFSPDM_API void wolfSPDM_DebugPrint(WOLFSPDM_CTX* ctx, const char* fmt, ...)
#ifdef __GNUC__
    __attribute__((format(printf, 2, 3)))
#endif
    ;

/* Hex dump for debugging */
WOLFSPDM_API void wolfSPDM_DebugHex(WOLFSPDM_CTX* ctx, const char* label,
    const byte* data, word32 len);

/* --- Internal Function Declarations - Measurements --- */

#ifndef NO_WOLFSPDM_MEAS
/* Build GET_MEASUREMENTS request */
WOLFSPDM_API int wolfSPDM_BuildGetMeasurements(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz,
    byte operation, byte requestSig);

/* Parse MEASUREMENTS response */
WOLFSPDM_API int wolfSPDM_ParseMeasurements(WOLFSPDM_CTX* ctx, const byte* buf, word32 bufSz);

#ifndef NO_WOLFSPDM_MEAS_VERIFY
/* Verify measurement signature (L1/L2 transcript) */
WOLFSPDM_API int wolfSPDM_VerifyMeasurementSig(WOLFSPDM_CTX* ctx,
    const byte* rspBuf, word32 rspBufSz,
    const byte* reqMsg, word32 reqMsgSz);
#endif /* !NO_WOLFSPDM_MEAS_VERIFY */
#endif /* !NO_WOLFSPDM_MEAS */

/* --- Internal Function Declarations - Certificate Chain Validation --- */

/* Extract responder's public key from certificate chain leaf cert */
WOLFSPDM_API int wolfSPDM_ExtractResponderPubKey(WOLFSPDM_CTX* ctx);

/* Validate certificate chain using trusted CAs and extract public key */
WOLFSPDM_API int wolfSPDM_ValidateCertChain(WOLFSPDM_CTX* ctx);

/* --- Internal Function Declarations - Challenge --- */

#ifndef NO_WOLFSPDM_CHALLENGE
/* Build CHALLENGE request */
WOLFSPDM_API int wolfSPDM_BuildChallenge(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz,
    int slotId, byte measHashType);

/* Parse CHALLENGE_AUTH response */
WOLFSPDM_API int wolfSPDM_ParseChallengeAuth(WOLFSPDM_CTX* ctx, const byte* buf,
    word32 bufSz, word32* sigOffset);

/* Verify CHALLENGE_AUTH signature */
WOLFSPDM_API int wolfSPDM_VerifyChallengeAuthSig(WOLFSPDM_CTX* ctx,
    const byte* rspBuf, word32 rspBufSz,
    const byte* reqMsg, word32 reqMsgSz, word32 sigOffset);
#endif /* !NO_WOLFSPDM_CHALLENGE */

/* --- Internal Function Declarations - Heartbeat --- */

/* Build HEARTBEAT request */
WOLFSPDM_API int wolfSPDM_BuildHeartbeat(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz);

/* Parse HEARTBEAT_ACK response */
WOLFSPDM_API int wolfSPDM_ParseHeartbeatAck(WOLFSPDM_CTX* ctx, const byte* buf,
    word32 bufSz);

/* --- Internal Function Declarations - Key Update --- */

/* Build KEY_UPDATE request */
WOLFSPDM_API int wolfSPDM_BuildKeyUpdate(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz,
    byte operation, byte* tag);

/* Parse KEY_UPDATE_ACK response */
WOLFSPDM_API int wolfSPDM_ParseKeyUpdateAck(WOLFSPDM_CTX* ctx, const byte* buf,
    word32 bufSz, byte operation, byte tag);

/* Derive updated keys from saved app secrets */
WOLFSPDM_API int wolfSPDM_DeriveUpdatedKeys(WOLFSPDM_CTX* ctx, int updateAll);

#ifdef __cplusplus
}
#endif

#endif /* WOLFSPDM_INTERNAL_H */
