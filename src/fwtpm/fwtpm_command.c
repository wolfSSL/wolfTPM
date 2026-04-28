/* fwtpm_command.c
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

/* fwTPM Command Dispatch and Handlers
 * Implements TPM 2.0 command processing for the fwTPM server.
 * Uses TPM2_Packet API from tpm2_packet.c (compiled directly into fwtpm_server).
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2_types.h>

#ifdef WOLFTPM_FWTPM

#include <wolftpm/tpm2_packet.h>
#include <wolftpm/tpm2_param_enc.h>
#include <wolftpm/fwtpm/fwtpm.h>
#include <wolftpm/fwtpm/fwtpm_command.h>
#include <wolftpm/fwtpm/fwtpm_nv.h>
#include <wolftpm/fwtpm/fwtpm_crypto.h>

#include <stdio.h>
#include <string.h>

/* fwTPM requires wolfCrypt for all cryptographic operations */
#ifdef WOLFTPM2_NO_WOLFCRYPT
    #error "fwTPM requires wolfCrypt. Do not use --disable-wolfcrypt with --enable-fwtpm."
#endif

#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/random.h>
#ifndef NO_RSA
#include <wolfssl/wolfcrypt/rsa.h>
#endif
#ifdef HAVE_ECC
#include <wolfssl/wolfcrypt/ecc.h>
#endif
#ifndef NO_AES
#include <wolfssl/wolfcrypt/aes.h>
#endif
#include <wolfssl/wolfcrypt/hmac.h>

/* --- Forward declarations for command-local helpers --- */
#ifndef FWTPM_NO_ATTESTATION
static TPM_RC FwParseAttestParams(TPM2_Packet* cmd, int cmdSize,
    UINT16 cmdTag, TPM2B_DATA* qualifyingData,
    UINT16* sigScheme, UINT16* sigHashAlg);
#endif /* !FWTPM_NO_ATTESTATION */

#ifndef FWTPM_NO_NV
static FWTPM_NvIndex* FwFindNvIndex(FWTPM_CTX* ctx, TPMI_RH_NV_INDEX nvIndex);
#endif
static FWTPM_Object* FwFindObject(FWTPM_CTX* ctx, TPM_HANDLE handle);
static FWTPM_HashSeq* FwFindHashSeq(FWTPM_CTX* ctx, TPM_HANDLE handle);

/* Command table accessors (fwCmdTable is defined near end of file) */
static int    FwGetCmdCount(void);
static TPM_CC FwGetCmdCcAt(int idx);
/* --- Response helpers using TPM2_Packet --- */

/* Initialize a response packet on the given buffer */
static void FwRspInit(TPM2_Packet* pkt, byte* buf, int bufSize)
{
    pkt->buf = buf;
    pkt->pos = TPM2_HEADER_SIZE; /* skip header, filled by Finalize */
    pkt->size = bufSize;
    /* Zero header area so stale data doesn't confuse session detection */
    XMEMSET(buf, 0, TPM2_HEADER_SIZE);
}

/* Finalize response: writes tag + size + rc into header */
static int FwRspFinalize(TPM2_Packet* pkt, UINT16 tag, TPM_RC rc)
{
    int totalSz = pkt->pos;
    pkt->pos = 0;
    TPM2_Packet_AppendU16(pkt, tag);
    TPM2_Packet_AppendU32(pkt, (UINT32)totalSz);
    TPM2_Packet_AppendU32(pkt, rc);
    pkt->pos = totalSz;
    return totalSz;
}

/* Build a minimal error-only response */
static int FwBuildErrorResponse(byte* rsp, UINT16 tag, TPM_RC rc)
{
    TPM2_Packet pkt;
    FwRspInit(&pkt, rsp, FWTPM_MAX_COMMAND_SIZE);
    return FwRspFinalize(&pkt, tag, rc);
}

/* Mark the start of response parameters. Writes a parameterSize placeholder
 * when sessions are present. Returns the position where parameters begin.
 * Caller must call FwRspParamsEnd() after writing parameters. */
int FwRspParamsBegin(TPM2_Packet* rsp, UINT16 cmdTag, int* paramSzPos)
{
    if (cmdTag == TPM_ST_SESSIONS) {
        *paramSzPos = rsp->pos;
        TPM2_Packet_AppendU32(rsp, 0); /* parameterSize placeholder */
    }
    else {
        *paramSzPos = -1;
    }
    return rsp->pos;
}

/* Patch the parameterSize placeholder and finalize the response.
 * If no sessions, writes the response header (tag + size + rc). */
void FwRspParamsEnd(TPM2_Packet* rsp, UINT16 cmdTag,
    int paramSzPos, int paramStart)
{
    /* Patch parameterSize if sessions */
    if (paramSzPos >= 0 && rsp->pos >= paramStart) {
        int paramSize = rsp->pos - paramStart;
        int savedPos = rsp->pos;
        rsp->pos = paramSzPos;
        TPM2_Packet_AppendU32(rsp, (UINT32)paramSize);
        rsp->pos = savedPos;
    }
    /* Finalize if no sessions (otherwise ProcessCommand handles it) */
    if (cmdTag != TPM_ST_SESSIONS) {
        FwRspFinalize(rsp, TPM_ST_NO_SESSIONS, TPM_RC_SUCCESS);
    }
}

/* Response with no output parameters (common for policy/management cmds) */
static void FwRspNoParams(TPM2_Packet* rsp, UINT16 cmdTag)
{
    int paramSzPos, paramStart;
    paramStart = FwRspParamsBegin(rsp, cmdTag, &paramSzPos);
    FwRspParamsEnd(rsp, cmdTag, paramSzPos, paramStart);
}

/* Skip authorization area with bounds checking.
 * Parses the 4-byte authAreaSize and advances cmd->pos past it.
 * Returns TPM_RC_COMMAND_SIZE if the area extends past cmdSize. */
static TPM_RC FwSkipAuthArea(TPM2_Packet* cmd, int cmdSize)
{
    UINT32 authAreaSize;
    if (cmd->pos + 4 > cmdSize) {
        return TPM_RC_COMMAND_SIZE;
    }
    TPM2_Packet_ParseU32(cmd, &authAreaSize);
    if (authAreaSize > (UINT32)(cmdSize - cmd->pos)) {
        return TPM_RC_COMMAND_SIZE;
    }
    cmd->pos += (int)authAreaSize;
    return TPM_RC_SUCCESS;
}

/* Map hash alg to fwTPM PCR bank index */
static int FwGetPcrBankIndex(UINT16 hashAlg)
{
    switch (hashAlg) {
        case TPM_ALG_SHA256:
            return FWTPM_PCR_BANK_SHA256;
    #ifdef WOLFSSL_SHA384
        case TPM_ALG_SHA384:
            return FWTPM_PCR_BANK_SHA384;
    #endif
    #ifndef NO_SHA
        case TPM_ALG_SHA1:
            return FWTPM_PCR_BANK_SHA1;
    #endif
        default:
            return -1;
    }
}

/* KDFa, KDFe, and param encryption/decryption are now shared via
 * tpm2_param_enc.c (TPM2_KDFa, TPM2_KDFe, TPM2_ParamEnc_XOR,
 * TPM2_ParamEnc_AESCFB). See wolftpm/tpm2_param_enc.h */

#ifndef FWTPM_NO_PARAM_ENC
/* Decrypt first TPM2B parameter of incoming command (param encryption) */
static int FwParamDecryptCmd(FWTPM_CTX* ctx, FWTPM_Session* sess,
    byte* paramData, UINT32 paramSz)
{
    int rc = 0;

    if (sess->symmetric.algorithm == TPM_ALG_XOR) {
        rc = TPM2_ParamEnc_XOR(sess->authHash,
            sess->sessionKey.buffer, sess->sessionKey.size,
            sess->nonceCaller.buffer, sess->nonceCaller.size,
            sess->nonceTPM.buffer, sess->nonceTPM.size,
            paramData, paramSz);
    }
    else if (sess->symmetric.algorithm == TPM_ALG_AES &&
             sess->symmetric.mode.aes == TPM_ALG_CFB) {
        rc = TPM2_ParamEnc_AESCFB(sess->authHash,
            sess->symmetric.keyBits.aes,
            sess->sessionKey.buffer, sess->sessionKey.size,
            sess->nonceCaller.buffer, sess->nonceCaller.size,
            sess->nonceTPM.buffer, sess->nonceTPM.size,
            paramData, paramSz, 0); /* decrypt */
    }

    (void)ctx;
    return rc;
}

/* Encrypt first TPM2B parameter of outgoing response (param encryption) */
static int FwParamEncryptRsp(FWTPM_CTX* ctx, FWTPM_Session* sess,
    byte* paramData, UINT32 paramSz)
{
    int rc = 0;

    if (sess->symmetric.algorithm == TPM_ALG_XOR) {
        /* Response direction: nonceTPM first, nonceCaller second */
        rc = TPM2_ParamEnc_XOR(sess->authHash,
            sess->sessionKey.buffer, sess->sessionKey.size,
            sess->nonceTPM.buffer, sess->nonceTPM.size,
            sess->nonceCaller.buffer, sess->nonceCaller.size,
            paramData, paramSz);
    }
    else if (sess->symmetric.algorithm == TPM_ALG_AES &&
             sess->symmetric.mode.aes == TPM_ALG_CFB) {
        /* Response direction: nonceTPM first, nonceCaller second */
        rc = TPM2_ParamEnc_AESCFB(sess->authHash,
            sess->symmetric.keyBits.aes,
            sess->sessionKey.buffer, sess->sessionKey.size,
            sess->nonceTPM.buffer, sess->nonceTPM.size,
            sess->nonceCaller.buffer, sess->nonceCaller.size,
            paramData, paramSz, 1); /* encrypt */
    }

    (void)ctx;
    return rc;
}
#endif /* !FWTPM_NO_PARAM_ENC */

/** \brief One-shot hash over up to two input buffers.
 *
 * Initializes, updates with d1 (and optionally d2), finalizes, and frees a
 * hash context for the requested TPM algorithm. wc_HashFree is only called
 * when wc_HashInit succeeded, so a failing Init cannot corrupt an
 * uninitialized context. Either input pointer may be NULL when its length
 * is zero. */
static int FwHashOneShot(TPMI_ALG_HASH hashAlg,
    const byte* d1, word32 d1Sz,
    const byte* d2, word32 d2Sz,
    byte* digestOut)
{
    FWTPM_DECLARE_VAR(hashCtx, wc_HashAlg);
    enum wc_HashType wcHash = FwGetWcHashType(hashAlg);
    int dSize = TPM2_GetHashDigestSize(hashAlg);
    int rc;
    int initOk = 0;

    if (dSize <= 0)
        return TPM_RC_FAILURE;

    FWTPM_ALLOC_VAR(hashCtx, wc_HashAlg);

    rc = wc_HashInit(hashCtx, wcHash);
    if (rc == 0) {
        initOk = 1;
        if (d1 != NULL && d1Sz > 0)
            rc = wc_HashUpdate(hashCtx, wcHash, d1, d1Sz);
    }
    if (rc == 0 && d2 != NULL && d2Sz > 0) {
        rc = wc_HashUpdate(hashCtx, wcHash, d2, d2Sz);
    }
    if (rc == 0) {
        rc = wc_HashFinal(hashCtx, wcHash, digestOut);
    }

    if (initOk)
        wc_HashFree(hashCtx, wcHash);
    FWTPM_FREE_VAR(hashCtx);
    return rc;
}

/* Compute rpHash = H(responseCode=0 || commandCode || responseParameters)
 * Per TPM 2.0 spec Part 1 Section 18.8 */
static int FwComputeRpHash(TPMI_ALG_HASH hashAlg, TPM_CC cmdCode,
    const byte* rpBytes, int rpSize, byte* hashOut, int* hashOutSz)
{
    FWTPM_DECLARE_VAR(hashCtx, wc_HashAlg);
    enum wc_HashType wcHash = FwGetWcHashType(hashAlg);
    int dSize = TPM2_GetHashDigestSize(hashAlg);
    UINT32 rcZero = 0; /* responseCode is always 0 for success HMAC */
    UINT32 ccSwap;
    int rc;

    if (dSize <= 0)
        return TPM_RC_FAILURE;

    FWTPM_ALLOC_VAR(hashCtx, wc_HashAlg);

    rc = wc_HashInit(hashCtx, wcHash);

    /* responseCode = 0 (success) - in native byte order like client */
    if (rc == 0)
        rc = wc_HashUpdate(hashCtx, wcHash, (byte*)&rcZero, 4);

    /* commandCode in big-endian */
    if (rc == 0) {
        ccSwap = TPM2_Packet_SwapU32(cmdCode);
        rc = wc_HashUpdate(hashCtx, wcHash, (byte*)&ccSwap, 4);
    }

    /* response parameters */
    if (rc == 0 && rpBytes != NULL && rpSize > 0)
        rc = wc_HashUpdate(hashCtx, wcHash, rpBytes, rpSize);

    if (rc == 0)
        rc = wc_HashFinal(hashCtx, wcHash, hashOut);

    if (rc == 0)
        *hashOutSz = dSize;

    wc_HashFree(hashCtx, wcHash);
    FWTPM_FREE_VAR(hashCtx);
    return rc;
}

/** \brief Get the TPM name for an entity handle.
 *  Hierarchies/sessions: 4-byte big-endian handle.
 *  NV indices: nameAlg || H(nvPublic).
 *  Objects: nameAlg || H(publicArea).
 *  Returns name size, or 0 if handle not found. */
static int FwGetEntityName(FWTPM_CTX* ctx, TPM_HANDLE handle,
    byte* nameBuf, int nameBufSz)
{
    UINT32 hType = handle & 0xFF000000;
    if (handle == TPM_RH_OWNER || handle == TPM_RH_ENDORSEMENT ||
        handle == TPM_RH_PLATFORM || handle == TPM_RH_LOCKOUT ||
        handle == TPM_RH_NULL || handle == TPM_RS_PW ||
        hType == HMAC_SESSION_FIRST ||
        hType == POLICY_SESSION_FIRST ||
        handle <= PCR_LAST) {
        if (nameBufSz < 4) return 0;
        FwStoreU32BE(nameBuf, handle);
        return 4;
    }
#ifndef FWTPM_NO_NV
    else if (hType == (NV_INDEX_FIRST & 0xFF000000)) {
        FWTPM_NvIndex* nv = FwFindNvIndex(ctx, handle);
        if (nv != NULL) {
            UINT16 nvNameSz = 0;
            FwComputeNvName(nv, nameBuf, &nvNameSz);
            if (nvNameSz <= nameBufSz) {
                return (int)nvNameSz;
            }
        }
    }
#endif /* !FWTPM_NO_NV */
    else {
        FWTPM_Object* obj = FwFindObject(ctx, handle);
        if (obj != NULL) {
            if (obj->name.size == 0) {
                FwComputeObjectName(obj);
            }
            if (obj->name.size <= nameBufSz) {
                XMEMCPY(nameBuf, obj->name.name, obj->name.size);
                return obj->name.size;
            }
        }
    }
    return 0;
}

/** \brief Look up the authValue for an entity by its TPM handle.
 *  Searches hierarchies, NV indices, loaded objects, and hash sequences. */
static void FwLookupEntityAuth(FWTPM_CTX* ctx, TPM_HANDLE handle,
    const byte** authVal, int* authValSz)
{
    *authVal = NULL;
    *authValSz = 0;

    if (handle == TPM_RH_OWNER) {
        *authVal = ctx->ownerAuth.buffer;
        *authValSz = ctx->ownerAuth.size;
    }
    else if (handle == TPM_RH_ENDORSEMENT) {
        *authVal = ctx->endorsementAuth.buffer;
        *authValSz = ctx->endorsementAuth.size;
    }
    else if (handle == TPM_RH_PLATFORM) {
        *authVal = ctx->platformAuth.buffer;
        *authValSz = ctx->platformAuth.size;
    }
    else if (handle == TPM_RH_LOCKOUT) {
        *authVal = ctx->lockoutAuth.buffer;
        *authValSz = ctx->lockoutAuth.size;
    }
#ifndef FWTPM_NO_NV
    else if ((handle & 0xFF000000) == (NV_INDEX_FIRST & 0xFF000000)) {
        FWTPM_NvIndex* nvEnt = FwFindNvIndex(ctx, handle);
        if (nvEnt != NULL) {
            *authVal = nvEnt->authValue.buffer;
            *authValSz = nvEnt->authValue.size;
        }
    }
#endif /* !FWTPM_NO_NV */
    else {
        FWTPM_Object* objEnt = FwFindObject(ctx, handle);
        if (objEnt != NULL) {
            *authVal = objEnt->authValue.buffer;
            *authValSz = objEnt->authValue.size;
        }
        else {
            FWTPM_HashSeq* seqEnt = FwFindHashSeq(ctx, handle);
            if (seqEnt != NULL) {
                *authVal = seqEnt->authValue.buffer;
                *authValSz = seqEnt->authValue.size;
            }
        }
    }
}

/* Constant-time password vs authValue comparison.
 * Iterates a fixed upper bound (TPM_MAX_DIGEST_SIZE) with bitwise masks so
 * neither the trip count nor per-iteration work depends on the secret
 * authValSz. Trailing zeros on either side are treated as insignificant
 * (matches TCG reference for authValues padded to nameAlg digest size).
 * Returns 1 on mismatch, 0 on match. Precondition: pwSz and avSz must
 * each be <= TPM_MAX_DIGEST_SIZE; out-of-range inputs fail closed. */
static int FwCtAuthCompare(const byte* password, int pwSz,
    const byte* authVal, int avSz)
{
    byte zeroAuth[TPM_MAX_DIGEST_SIZE];
    const byte* avPtr;
    volatile byte diff = 0;
    int ci;

    if (pwSz < 0 || avSz < 0 ||
            pwSz > TPM_MAX_DIGEST_SIZE || avSz > TPM_MAX_DIGEST_SIZE) {
        return 1;
    }

    XMEMSET(zeroAuth, 0, sizeof(zeroAuth));
    avPtr = (authVal != NULL) ? authVal : zeroAuth;

    for (ci = 0; ci < TPM_MAX_DIGEST_SIZE; ci++) {
        /* 0xFF if ci < bound, else 0x00. Use UINT32 (guaranteed 32-bit
         * wolfTPM typedef) so the >> 31 shift is always well-defined. */
        byte pwMask = (byte)-((UINT32)(ci - pwSz) >> 31);
        byte avMask = (byte)-((UINT32)(ci - avSz) >> 31);
        byte overlap = (byte)(pwMask & avMask);
        /* Overlap region: bytes must match */
        diff |= (byte)((password[ci] ^ avPtr[ci]) & overlap);
        /* Trailing bytes of pw past avSz must be zero */
        diff |= (byte)(password[ci] & (pwMask & (byte)~avMask));
        /* Trailing bytes of av past pwSz must be zero */
        diff |= (byte)(avPtr[ci] & (avMask & (byte)~pwMask));
    }

    return ((int)diff != 0) ? 1 : 0;
}

/* Compute cpHash = H(commandCode || name1 || ... || cpBuffer)
 * Per TPM 2.0 Part 1 Section 18.7 */
static int FwComputeCpHash(TPMI_ALG_HASH hashAlg, TPM_CC cmdCode,
    const byte* cmdBuf, int cmdSize,
    const TPM_HANDLE* handles, int handleCnt,
    FWTPM_CTX* ctx, int cpStart,
    byte* hashOut, int* hashOutSz)
{
    FWTPM_DECLARE_VAR(hashCtx, wc_HashAlg);
    enum wc_HashType wcHash = FwGetWcHashType(hashAlg);
    int dSize = TPM2_GetHashDigestSize(hashAlg);
    UINT32 ccSwap;
    int rc;
    int i;

    if (dSize <= 0)
        return TPM_RC_FAILURE;

    FWTPM_ALLOC_VAR(hashCtx, wc_HashAlg);

    rc = wc_HashInit(hashCtx, wcHash);

    /* commandCode in big-endian */
    if (rc == 0) {
        ccSwap = TPM2_Packet_SwapU32(cmdCode);
        rc = wc_HashUpdate(hashCtx, wcHash, (byte*)&ccSwap, 4);
    }

    /* Handle names */
    for (i = 0; i < handleCnt && rc == 0; i++) {
        byte hName[2 + TPM_MAX_DIGEST_SIZE];
        int hNameSz = FwGetEntityName(ctx, handles[i],
            hName, (int)sizeof(hName));
        if (hNameSz > 0)
            rc = wc_HashUpdate(hashCtx, wcHash, hName, hNameSz);
    }

    /* Command parameters (everything after auth area) */
    if (rc == 0 && cpStart > 0 && cpStart < cmdSize) {
        rc = wc_HashUpdate(hashCtx, wcHash,
            cmdBuf + cpStart, cmdSize - cpStart);
    }

    if (rc == 0)
        rc = wc_HashFinal(hashCtx, wcHash, hashOut);

    if (rc == 0)
        *hashOutSz = dSize;

    wc_HashFree(hashCtx, wcHash);
    FWTPM_FREE_VAR(hashCtx);
    return rc;
}

/** \brief Compute session HMAC for command or response authorization.
 * Command:  HMAC(key, cpHash  || nonceCaller || nonceTPM    || attrs)
 * Response: HMAC(key, rpHash  || nonceTPM    || nonceCaller || attrs)
 * The isResponse flag controls nonce order. */
static int FwComputeSessionHmac(FWTPM_Session* sess,
    const byte* pHash, int pHashSz, UINT8 sessionAttributes,
    const byte* authValue, int authValueSz,
    int isResponse,
    byte* hmacOut, int* hmacOutSz)
{
    FWTPM_DECLARE_VAR(hmac, Hmac);
    enum wc_HashType hashType = FwGetWcHashType(sess->authHash);
    int dSize = TPM2_GetHashDigestSize(sess->authHash);
    byte hmacKey[TPM_MAX_DIGEST_SIZE * 2]; /* sessionKey || authValue */
    int hmacKeySz = 0;
    int rc;

    if (dSize <= 0)
        return TPM_RC_FAILURE;

    /* Build HMAC key = sessionKey || authValue */
    if (sess->sessionKey.size > 0 &&
        sess->sessionKey.size <= TPM_MAX_DIGEST_SIZE) {
        XMEMCPY(hmacKey, sess->sessionKey.buffer, sess->sessionKey.size);
        hmacKeySz = sess->sessionKey.size;
    }
    if (authValue != NULL && authValueSz > 0 &&
        hmacKeySz + authValueSz <= (int)sizeof(hmacKey)) {
        XMEMCPY(hmacKey + hmacKeySz, authValue, authValueSz);
        hmacKeySz += authValueSz;
    }

    FWTPM_ALLOC_VAR(hmac, Hmac);

    rc = wc_HmacInit(hmac, NULL, INVALID_DEVID);

    if (rc == 0) {
        rc = wc_HmacSetKey(hmac, (int)hashType,
            hmacKeySz > 0 ? hmacKey : NULL, (word32)hmacKeySz);
    }

    /* pHash (cpHash or rpHash) */
    if (rc == 0)
        rc = wc_HmacUpdate(hmac, pHash, pHashSz);

    if (isResponse) {
        /* Response: nonceTPM first, then nonceCaller */
        if (rc == 0)
            rc = wc_HmacUpdate(hmac, sess->nonceTPM.buffer,
                sess->nonceTPM.size);
        if (rc == 0)
            rc = wc_HmacUpdate(hmac, sess->nonceCaller.buffer,
                sess->nonceCaller.size);
    }
    else {
        /* Command: nonceCaller first, then nonceTPM */
        if (rc == 0)
            rc = wc_HmacUpdate(hmac, sess->nonceCaller.buffer,
                sess->nonceCaller.size);
        if (rc == 0)
            rc = wc_HmacUpdate(hmac, sess->nonceTPM.buffer,
                sess->nonceTPM.size);
    }

    /* sessionAttributes (1 byte) */
    if (rc == 0)
        rc = wc_HmacUpdate(hmac, &sessionAttributes, 1);

    if (rc == 0)
        rc = wc_HmacFinal(hmac, hmacOut);

    if (rc == 0)
        *hmacOutSz = dSize;

    TPM2_ForceZero(hmacKey, sizeof(hmacKey));
    wc_HmacFree(hmac);
    FWTPM_FREE_VAR(hmac);
    return rc;
}

/* ================================================================== */
/* Command Handlers                                                    */
/* Each handler receives a parsed command packet (pos at header end)   */
/* and builds the response using TPM2_Packet API.                      */
/* ================================================================== */

/* Forward declarations for helpers used by Startup */
static void FwFlushAllObjects(FWTPM_CTX* ctx);
static void FwFlushAllSessions(FWTPM_CTX* ctx);
static void FwFreeHashSeq(FWTPM_HashSeq* seq);

/* --- TPM2_Startup (CC 0x0144) --- */
static TPM_RC FwCmd_Startup(FWTPM_CTX* ctx, TPM2_Packet* cmd, int cmdSize,
    TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT16 startupType = 0;
    int i, b;

    (void)cmdTag;

    if (cmdSize < TPM2_HEADER_SIZE + 2) {
        rc = TPM_RC_COMMAND_SIZE;
    }

    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &startupType);
        if (startupType != TPM_SU_CLEAR && startupType != TPM_SU_STATE) {
            rc = TPM_RC_VALUE;
        }
    }

    if (rc == 0 && ctx->wasStarted) {
        rc = TPM_RC_INITIALIZE;
    }

    if (rc == 0 && !ctx->powerOn) {
        rc = TPM_RC_FAILURE;
    }

    if (rc == 0) {
        if (startupType == TPM_SU_CLEAR) {
            /* Flush all transient objects, sessions, hash sequences,
             * primary cache, and reset PCRs */
            FwFlushAllObjects(ctx);
            FwFlushAllSessions(ctx);
            for (i = 0; i < FWTPM_MAX_HASH_SEQ; i++) {
                if (ctx->hashSeq[i].used) {
                    FwFreeHashSeq(&ctx->hashSeq[i]);
                }
            }
            for (i = 0; i < FWTPM_MAX_PRIMARY_CACHE; i++) {
                XMEMSET(&ctx->primaryCache[i], 0,
                    sizeof(ctx->primaryCache[i]));
            }
            for (b = 0; b < FWTPM_PCR_BANKS; b++) {
                for (i = 0; i < IMPLEMENTATION_PCR; i++) {
                    XMEMSET(ctx->pcrDigest[i][b], 0, TPM_MAX_DIGEST_SIZE);
                }
            }
            ctx->globalNvWriteLock = 0;
#ifdef HAVE_ECC
            ctx->ecEphemeralCounter = 0;
            ctx->ecEphemeralKeySz = 0;
#endif

            /* Null seed: re-randomize on every Startup(CLEAR) per spec */
            rc = wc_RNG_GenerateBlock(&ctx->rng, ctx->nullSeed,
                FWTPM_SEED_SIZE);
            if (rc != 0) rc = TPM_RC_FAILURE;
        }

        ctx->wasStarted = 1;

    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: Startup(%s)\n",
            startupType == TPM_SU_CLEAR ? "CLEAR" : "STATE");
    #endif

        FwRspFinalize(rsp, TPM_ST_NO_SESSIONS, TPM_RC_SUCCESS);
    }

    return rc;
}

/* --- TPM2_Shutdown (CC 0x0145) --- */
static TPM_RC FwCmd_Shutdown(FWTPM_CTX* ctx, TPM2_Packet* cmd, int cmdSize,
    TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT16 shutdownType = 0;

    (void)cmdTag;

    if (cmdSize < TPM2_HEADER_SIZE + 2) {
        rc = TPM_RC_COMMAND_SIZE;
    }

    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &shutdownType);
        if (shutdownType != TPM_SU_CLEAR && shutdownType != TPM_SU_STATE) {
            rc = TPM_RC_VALUE;
        }
    }

    if (rc == 0) {
    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: Shutdown(%s)\n",
            shutdownType == TPM_SU_CLEAR ? "CLEAR" : "STATE");
    #endif

        /* Flush sessions on Shutdown(CLEAR). Per TPM 2.0 spec, sessions
         * do not survive Shutdown(CLEAR). Transient objects remain in
         * volatile memory until the actual power cycle — Startup(CLEAR)
         * handles flushing them (see FwCmd_Startup). */
        if (shutdownType == TPM_SU_CLEAR) {
            FwFlushAllSessions(ctx);
        }

        rc = FWTPM_NV_Save(ctx);
        if (rc != TPM_RC_SUCCESS) {
            return rc;
        }

        FwRspFinalize(rsp, TPM_ST_NO_SESSIONS, TPM_RC_SUCCESS);
    }

    return rc;
}

/* --- TPM2_SelfTest (CC 0x0143) --- */
static TPM_RC FwCmd_SelfTest(FWTPM_CTX* ctx, TPM2_Packet* cmd, int cmdSize,
    TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT8 fullTest = 0;

    (void)cmdTag;

    if (cmdSize < TPM2_HEADER_SIZE + 1) {
        rc = TPM_RC_COMMAND_SIZE;
    }

    if (rc == 0) {
        TPM2_Packet_ParseU8(cmd, &fullTest);

    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: SelfTest(fullTest=%d)\n", fullTest);
    #endif
    }

    /* TODO: When built against wolfCrypt FIPS, invoke the full CAST suite
     * (e.g. wc_RunAllCast_fips / wc_GetCastStatus_fips) rather than the
     * placeholder SHA-256 KAT + RNG check below. The current checks are a
     * minimal smoke test, not a conformant TPM self-test. */

    /* Verify wolfCrypt hash produces known answer (SHA-256 KAT) */
    if (rc == 0) {
        static const byte katInput[] = "abc";
        static const byte katExpect[] = {
            0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA,
            0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE, 0x22, 0x23,
            0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C,
            0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00, 0x15, 0xAD
        };
        byte digest[TPM_SHA256_DIGEST_SIZE];
        rc = wc_Sha256Hash(katInput, 3, digest);
        if (rc == 0) {
            if (XMEMCMP(digest, katExpect, TPM_SHA256_DIGEST_SIZE) != 0) {
                rc = TPM_RC_FAILURE;
            }
        }
        else {
            rc = TPM_RC_FAILURE;
        }
    }

    /* Verify RNG can generate bytes */
    if (rc == 0) {
        byte rngTest[16];
        rc = wc_RNG_GenerateBlock(&ctx->rng, rngTest, sizeof(rngTest));
        TPM2_ForceZero(rngTest, sizeof(rngTest));
        if (rc != 0) {
            rc = TPM_RC_FAILURE;
        }
    }

    if (rc == 0) {
        FwRspFinalize(rsp, TPM_ST_NO_SESSIONS, TPM_RC_SUCCESS);
    }

    return rc;
}

/* --- TPM2_IncrementalSelfTest (CC 0x0142) --- */
static TPM_RC FwCmd_IncrementalSelfTest(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    (void)ctx;
    (void)cmd;
    (void)cmdSize;
    (void)cmdTag;

#ifdef DEBUG_WOLFTPM
    printf("fwTPM: IncrementalSelfTest\n");
#endif

    /* TODO: IncrementalSelfTest is currently a no-op stub. A real
     * implementation would track per-algorithm CAST status and run any
     * tests from toTest[] that have not yet passed. Returning an empty
     * toDoList signals "nothing left to test" which is acceptable for the
     * non-FIPS configuration but must be revisited for FIPS builds. */
    TPM2_Packet_AppendU32(rsp, 0); /* toDoList count = 0 */
    FwRspFinalize(rsp, TPM_ST_NO_SESSIONS, TPM_RC_SUCCESS);
    return TPM_RC_SUCCESS; /* always succeeds */
}

/* --- TPM2_GetTestResult (CC 0x017C) --- */
static TPM_RC FwCmd_GetTestResult(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    (void)ctx; (void)cmd; (void)cmdSize; (void)cmdTag;

    /* outData (TPM2B_MAX_BUFFER) - empty */
    TPM2_Packet_AppendU16(rsp, 0);
    /* testResult (TPM_RC) - success */
    TPM2_Packet_AppendU32(rsp, TPM_RC_SUCCESS);

    FwRspFinalize(rsp, TPM_ST_NO_SESSIONS, TPM_RC_SUCCESS);
    return TPM_RC_SUCCESS; /* always succeeds */
}

/* --- TPM2_GetRandom (CC 0x017B) --- */
static TPM_RC FwCmd_GetRandom(FWTPM_CTX* ctx, TPM2_Packet* cmd, int cmdSize,
    TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT16 bytesRequested = 0;

    (void)cmdTag;

    if (cmdSize < TPM2_HEADER_SIZE + 2) {
        rc = TPM_RC_COMMAND_SIZE;
    }

    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &bytesRequested);
        if (bytesRequested > FWTPM_MAX_RANDOM_BYTES) {
            bytesRequested = FWTPM_MAX_RANDOM_BYTES;
        }

    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: GetRandom(%d)\n", bytesRequested);
    #endif

        /* TPM2B_DIGEST: size + data */
        TPM2_Packet_AppendU16(rsp, bytesRequested);

        rc = wc_RNG_GenerateBlock(&ctx->rng,
            rsp->buf + rsp->pos, bytesRequested);
        if (rc != 0) {
            rc = TPM_RC_FAILURE;
        }
    }

    if (rc == 0) {
        rsp->pos += bytesRequested;
        FwRspFinalize(rsp, TPM_ST_NO_SESSIONS, TPM_RC_SUCCESS);
    }

    return rc;
}

/* --- TPM2_StirRandom (CC 0x0146) --- */
static TPM_RC FwCmd_StirRandom(FWTPM_CTX* ctx, TPM2_Packet* cmd, int cmdSize,
    TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT16 inDataSize = 0;

    (void)cmdTag;

    if (cmdSize < TPM2_HEADER_SIZE + 2) {
        rc = TPM_RC_COMMAND_SIZE;
    }

    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &inDataSize);
        if (cmd->pos + inDataSize > cmdSize) {
            rc = TPM_RC_COMMAND_SIZE;
        }
    }

    if (rc == 0) {
    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: StirRandom(%d bytes)\n", inDataSize);
    #endif

        /* Reseed the Hash DRBG with the caller-provided additional input.
         * When the port uses CUSTOM_RAND_GENERATE_BLOCK (HW RNG) or the
         * Hash DRBG is not compiled in, there is nothing to reseed -
         * treat as a no-op, which is TCG-compliant for HW-RNG-backed TPMs. */
    #if defined(HAVE_HASHDRBG) && !defined(CUSTOM_RAND_GENERATE_BLOCK)
        rc = wc_RNG_DRBG_Reseed(&ctx->rng, cmd->buf + cmd->pos, inDataSize);
        if (rc != 0) {
            rc = TPM_RC_FAILURE;
        }
    #else
        (void)inDataSize;
    #endif
    }

    if (rc == 0) {
        FwRspFinalize(rsp, TPM_ST_NO_SESSIONS, TPM_RC_SUCCESS);
    }

    return rc;
}

/* --- TPM2_GetCapability (CC 0x017A) --- */
static TPM_RC FwCmd_GetCapability(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 capability = 0;
    UINT32 property = 0;
    UINT32 propertyCount = 0;
    UINT32 i;
    int paramSzPos, paramStart;

    (void)ctx;

    if (cmdSize < TPM2_HEADER_SIZE + 12) {
        rc = TPM_RC_COMMAND_SIZE;
    }

    if (rc != 0) {
        return rc;
    }

    TPM2_Packet_ParseU32(cmd, &capability);
    TPM2_Packet_ParseU32(cmd, &property);
    TPM2_Packet_ParseU32(cmd, &propertyCount);

#ifdef DEBUG_WOLFTPM
    printf("fwTPM: GetCapability(cap=0x%x, prop=0x%x, count=%d)\n",
        capability, property, propertyCount);
#endif

    paramStart = FwRspParamsBegin(rsp, cmdTag, &paramSzPos);

    /* moreData (TPMI_YES_NO) */
    TPM2_Packet_AppendU8(rsp, 0); /* NO */

    /* capability */
    TPM2_Packet_AppendU32(rsp, capability);

    switch (capability) {
        case TPM_CAP_ALGS: {
            static const struct {
                UINT16 alg;
                UINT32 attrs;
            } algList[] = {
            #ifndef NO_RSA
                { TPM_ALG_RSA,     0x0009 },
            #endif
                { TPM_ALG_SHA256,  0x0004 },
            #ifdef WOLFSSL_SHA384
                { TPM_ALG_SHA384,  0x0004 },
            #endif
                { TPM_ALG_HMAC,    0x0044 },
            #ifndef NO_AES
                { TPM_ALG_AES,     0x0060 },
            #endif
            #ifdef HAVE_ECC
                { TPM_ALG_ECC,     0x0009 },
            #endif
            #ifndef NO_RSA
                { TPM_ALG_RSASSA,  0x0040 },
                { TPM_ALG_RSAPSS,  0x0040 },
            #endif
            #ifdef HAVE_ECC
                { TPM_ALG_ECDSA,   0x0040 },
                { TPM_ALG_ECDH,    0x0080 },
            #endif
            #ifndef NO_RSA
                { TPM_ALG_OAEP,    0x0020 },
            #endif
            #ifndef NO_AES
                { TPM_ALG_CFB,     0x0020 },
            #endif
                { TPM_ALG_KEYEDHASH, 0x0008 },
            #ifndef NO_AES
                { TPM_ALG_SYMCIPHER, 0x0060 },
            #endif
                { TPM_ALG_NULL,      0x0000 },
            };
            int numAlgs = (int)(sizeof(algList) / sizeof(algList[0]));
            if (propertyCount < (UINT32)numAlgs)
                numAlgs = (int)propertyCount;

            TPM2_Packet_AppendU32(rsp, (UINT32)numAlgs);
            for (i = 0; i < (UINT32)numAlgs; i++) {
                TPM2_Packet_AppendU16(rsp, algList[i].alg);
                TPM2_Packet_AppendU32(rsp, algList[i].attrs);
            }
            break;
        }

        case TPM_CAP_COMMANDS: {
            /* Iterate the single source-of-truth dispatch table instead of
             * a parallel hand-maintained list. */
            int numCmds = FwGetCmdCount();
            if (propertyCount < (UINT32)numCmds)
                numCmds = (int)propertyCount;

            TPM2_Packet_AppendU32(rsp, (UINT32)numCmds);
            for (i = 0; i < (UINT32)numCmds; i++) {
                TPM2_Packet_AppendU32(rsp,
                    (UINT32)FwGetCmdCcAt((int)i) & 0x0000FFFF);
            }
            break;
        }

        case TPM_CAP_TPM_PROPERTIES: {
            const struct {
                UINT32 prop;
                UINT32 val;
            } allProps[] = {
                { TPM_PT_FAMILY_INDICATOR,  0x322E3000 },
                { TPM_PT_LEVEL,             0 },
                { TPM_PT_REVISION,          FWTPM_REVISION },
                { TPM_PT_DAY_OF_YEAR,       FWTPM_BUILD_DAY_OF_YEAR },
                { TPM_PT_YEAR,              FWTPM_BUILD_YEAR },
                { TPM_PT_MANUFACTURER,
                  ((UINT32)'W' << 24) | ((UINT32)'O' << 16) |
                  ((UINT32)'L' << 8)  | (UINT32)'F' },
                { TPM_PT_VENDOR_STRING_1,
                  ((UINT32)'w' << 24) | ((UINT32)'o' << 16) |
                  ((UINT32)'l' << 8)  | (UINT32)'f' },
                { TPM_PT_VENDOR_STRING_2,
                  ((UINT32)'T' << 24) | ((UINT32)'P' << 16) |
                  ((UINT32)'M' << 8)  | (UINT32)0 },
                { TPM_PT_VENDOR_STRING_3,   0 },
                { TPM_PT_VENDOR_STRING_4,   0 },
                { TPM_PT_FIRMWARE_VERSION_1, FWTPM_VERSION_MAJOR },
                { TPM_PT_FIRMWARE_VERSION_2, FWTPM_VERSION_MINOR },
                { TPM_PT_INPUT_BUFFER,      FWTPM_MAX_COMMAND_SIZE },
                { TPM_PT_PCR_COUNT,         IMPLEMENTATION_PCR },
                { TPM_PT_MAX_COMMAND_SIZE,  FWTPM_MAX_COMMAND_SIZE },
                { TPM_PT_MAX_RESPONSE_SIZE, FWTPM_MAX_COMMAND_SIZE },
            #ifdef WOLFSSL_SHA384
                { TPM_PT_MAX_DIGEST,        TPM_SHA384_DIGEST_SIZE },
            #else
                { TPM_PT_MAX_DIGEST,        TPM_SHA256_DIGEST_SIZE },
            #endif
                { TPM_PT_TOTAL_COMMANDS,    0 }, /* patched to FwGetCmdCount() at emission */
                { TPM_PT_MODES,             0 },
                { TPM_PT_HR_LOADED,         0 },
                { TPM_PT_HR_LOADED_AVAIL,   FWTPM_MAX_OBJECTS },
                { TPM_PT_HR_TRANSIENT_AVAIL, 0 },
                { TPM_PT_HR_PERSISTENT,     0 },
                { TPM_PT_HR_PERSISTENT_AVAIL, FWTPM_MAX_PERSISTENT },
            };
            int totalProps = (int)(sizeof(allProps) / sizeof(allProps[0]));
            int startIdx = 0;
            int numOut;

            for (startIdx = 0; startIdx < totalProps; startIdx++) {
                if (allProps[startIdx].prop >= property)
                    break;
            }
            numOut = totalProps - startIdx;
            if (numOut < 0)
                numOut = 0;
            if ((UINT32)numOut > propertyCount)
                numOut = (int)propertyCount;

            TPM2_Packet_AppendU32(rsp, (UINT32)numOut);
            for (i = 0; i < (UINT32)numOut; i++) {
                UINT32 prop = allProps[startIdx + i].prop;
                UINT32 val  = allProps[startIdx + i].val;
                if (prop == TPM_PT_TOTAL_COMMANDS)
                    val = (UINT32)FwGetCmdCount();
                TPM2_Packet_AppendU32(rsp, prop);
                TPM2_Packet_AppendU32(rsp, val);
            }
            break;
        }

        case TPM_CAP_PCR_PROPERTIES: {
            int numBanks = FWTPM_PCR_BANKS;
            if (propertyCount < (UINT32)numBanks)
                numBanks = (int)propertyCount;

            TPM2_Packet_AppendU32(rsp, (UINT32)numBanks);
            if (numBanks > 0) {
                TPM2_Packet_AppendU32(rsp, TPM_ALG_SHA256);
                TPM2_Packet_AppendU8(rsp, PCR_SELECT_MAX);
                TPM2_Packet_AppendU8(rsp, 0xFF);
                TPM2_Packet_AppendU8(rsp, 0xFF);
                TPM2_Packet_AppendU8(rsp, 0xFF);
            }
            if (numBanks > 1) {
                TPM2_Packet_AppendU32(rsp, TPM_ALG_SHA384);
                TPM2_Packet_AppendU8(rsp, PCR_SELECT_MAX);
                TPM2_Packet_AppendU8(rsp, 0xFF);
                TPM2_Packet_AppendU8(rsp, 0xFF);
                TPM2_Packet_AppendU8(rsp, 0xFF);
            }
            break;
        }

        case TPM_CAP_PCRS: {
            TPM2_Packet_AppendU32(rsp, FWTPM_PCR_BANKS);
            TPM2_Packet_AppendU16(rsp, TPM_ALG_SHA256);
            TPM2_Packet_AppendU8(rsp, PCR_SELECT_MAX);
            TPM2_Packet_AppendU8(rsp, 0xFF);
            TPM2_Packet_AppendU8(rsp, 0xFF);
            TPM2_Packet_AppendU8(rsp, 0xFF);
        #ifdef WOLFSSL_SHA384
            TPM2_Packet_AppendU16(rsp, TPM_ALG_SHA384);
            TPM2_Packet_AppendU8(rsp, PCR_SELECT_MAX);
            TPM2_Packet_AppendU8(rsp, 0xFF);
            TPM2_Packet_AppendU8(rsp, 0xFF);
            TPM2_Packet_AppendU8(rsp, 0xFF);
        #endif
            break;
        }

        case TPM_CAP_HANDLES: {
            int count = 0;
            int idx;
            UINT32 handleClass = property & 0xFF000000;

            /* Filter by handle class per TPM 2.0 spec Part 2 Section 8.4:
             * only return handles whose upper byte matches property */
            if (handleClass == 0x80000000) {
                /* Transient objects */
                for (idx = 0; idx < FWTPM_MAX_OBJECTS; idx++) {
                    if (ctx->objects[idx].used &&
                        ctx->objects[idx].handle >= property) {
                        count++;
                    }
                }
            }
            else if (handleClass == 0x81000000) {
                /* Persistent objects */
                for (idx = 0; idx < FWTPM_MAX_PERSISTENT; idx++) {
                    if (ctx->persistent[idx].used &&
                        ctx->persistent[idx].handle >= property) {
                        count++;
                    }
                }
            }
        #ifndef FWTPM_NO_NV
            else if (handleClass == 0x01000000) {
                /* NV indices */
                for (idx = 0; idx < FWTPM_MAX_NV_INDICES; idx++) {
                    if (ctx->nvIndices[idx].inUse &&
                        ctx->nvIndices[idx].nvPublic.nvIndex >= property) {
                        count++;
                    }
                }
            }
        #endif
            else if (handleClass == 0x02000000 ||
                     handleClass == 0x03000000) {
                /* HMAC / policy sessions */
                for (idx = 0; idx < FWTPM_MAX_SESSIONS; idx++) {
                    if (ctx->sessions[idx].used &&
                        ctx->sessions[idx].handle >= property) {
                        count++;
                    }
                }
            }
            /* Other classes (PCR, permanent): report 0 */

            if ((UINT32)count > propertyCount)
                count = (int)propertyCount;
            TPM2_Packet_AppendU32(rsp, (UINT32)count);
            if (count > 0) {
                int emitted = 0;
                if (handleClass == 0x81000000) {
                    for (idx = 0; idx < FWTPM_MAX_PERSISTENT &&
                         emitted < count; idx++) {
                        if (ctx->persistent[idx].used &&
                            ctx->persistent[idx].handle >= property) {
                            TPM2_Packet_AppendU32(rsp,
                                ctx->persistent[idx].handle);
                            emitted++;
                        }
                    }
                }
                else if (handleClass == 0x80000000) {
                    for (idx = 0; idx < FWTPM_MAX_OBJECTS &&
                         emitted < count; idx++) {
                        if (ctx->objects[idx].used &&
                            ctx->objects[idx].handle >= property) {
                            TPM2_Packet_AppendU32(rsp,
                                ctx->objects[idx].handle);
                            emitted++;
                        }
                    }
                }
            #ifndef FWTPM_NO_NV
                else if (handleClass == 0x01000000) {
                    for (idx = 0; idx < FWTPM_MAX_NV_INDICES &&
                         emitted < count; idx++) {
                        if (ctx->nvIndices[idx].inUse &&
                            ctx->nvIndices[idx].nvPublic.nvIndex >= property) {
                            TPM2_Packet_AppendU32(rsp,
                                ctx->nvIndices[idx].nvPublic.nvIndex);
                            emitted++;
                        }
                    }
                }
            #endif
                else if (handleClass == 0x02000000 ||
                         handleClass == 0x03000000) {
                    for (idx = 0; idx < FWTPM_MAX_SESSIONS &&
                         emitted < count; idx++) {
                        if (ctx->sessions[idx].used &&
                            ctx->sessions[idx].handle >= property) {
                            TPM2_Packet_AppendU32(rsp,
                                ctx->sessions[idx].handle);
                            emitted++;
                        }
                    }
                }
            }
            break;
        }
        case TPM_CAP_PP_COMMANDS:
        case TPM_CAP_AUDIT_COMMANDS:
        case TPM_CAP_ECC_CURVES:
            TPM2_Packet_AppendU32(rsp, 0);
            break;

        default:
            TPM2_Packet_AppendU32(rsp, 0);
            break;
    }

    FwRspParamsEnd(rsp, cmdTag, paramSzPos, paramStart);
    return rc;
}

/* --- TPM2_TestParms (CC 0x018A) --- */
/* Validates that the given algorithm parameters are supported.
 * No auth, no output params. */
static TPM_RC FwCmd_TestParms(FWTPM_CTX* ctx, TPM2_Packet* cmd, int cmdSize,
    TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT16 algType = 0;

    (void)ctx;
    (void)cmdTag;

    if (cmdSize < TPM2_HEADER_SIZE + 2) {
        rc = TPM_RC_COMMAND_SIZE;
    }

    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &algType);

    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: TestParms(type=0x%x)\n", algType);
    #endif

        /* Check if the algorithm type is supported */
        switch (algType) {
        #ifndef NO_RSA
            case TPM_ALG_RSA:
        #endif
        #ifdef HAVE_ECC
            case TPM_ALG_ECC:
        #endif
            case TPM_ALG_KEYEDHASH:
            case TPM_ALG_SYMCIPHER:
            case TPM_ALG_AES:
            case TPM_ALG_SHA256:
        #ifdef WOLFSSL_SHA384
            case TPM_ALG_SHA384:
        #endif
            case TPM_ALG_HMAC:
            case TPM_ALG_NULL:
                /* Supported - skip remaining type-specific params */
                break;
            default:
                rc = TPM_RC_VALUE;
                break;
        }
    }

    if (rc == 0) {
        FwRspFinalize(rsp, TPM_ST_NO_SESSIONS, TPM_RC_SUCCESS);
    }

    return rc;
}

/* --- TPM2_PCR_Read (CC 0x017E) --- */
static TPM_RC FwCmd_PCR_Read(FWTPM_CTX* ctx, TPM2_Packet* cmd, int cmdSize,
    TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 pcrSelCount = 0;
    UINT32 s;
    UINT32 numSel;
    int totalDigests = 0;
    int digestCountPos = 0;
    int savedPos = 0;
    struct {
        UINT16 hashAlg;
        UINT8 sizeOfSelect;
        byte pcrSelect[PCR_SELECT_MAX];
    } selections[HASH_COUNT];

    (void)cmdTag;

    if (cmdSize < TPM2_HEADER_SIZE + 4) {
        rc = TPM_RC_COMMAND_SIZE;
    }

    if (rc == 0) {
        TPM2_Packet_ParseU32(cmd, &pcrSelCount);

    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: PCR_Read(selCount=%d)\n", pcrSelCount);
    #endif

        /* pcrUpdateCounter */
        TPM2_Packet_AppendU32(rsp, ctx->pcrUpdateCounter);

        /* Echo TPML_PCR_SELECTION */
        TPM2_Packet_AppendU32(rsp, pcrSelCount);

        numSel = pcrSelCount;
        if (numSel > HASH_COUNT) {
            numSel = HASH_COUNT;
        }

        for (s = 0; s < numSel && rc == 0; s++) {
            int j;
            if (cmd->pos + 4 > cmdSize) {
                rc = TPM_RC_COMMAND_SIZE;
                break;
            }

            TPM2_Packet_ParseU16(cmd, &selections[s].hashAlg);
            TPM2_Packet_ParseU8(cmd, &selections[s].sizeOfSelect);
            if (selections[s].sizeOfSelect > PCR_SELECT_MAX) {
                selections[s].sizeOfSelect = PCR_SELECT_MAX;
            }
            for (j = 0; j < selections[s].sizeOfSelect; j++) {
                if (cmd->pos >= cmdSize) {
                    rc = TPM_RC_COMMAND_SIZE;
                    break;
                }
                TPM2_Packet_ParseU8(cmd, &selections[s].pcrSelect[j]);
            }
            if (rc != 0) {
                break;
            }

            /* Echo selection to response */
            TPM2_Packet_AppendU16(rsp, selections[s].hashAlg);
            TPM2_Packet_AppendU8(rsp, selections[s].sizeOfSelect);
            for (j = 0; j < selections[s].sizeOfSelect; j++) {
                TPM2_Packet_AppendU8(rsp, selections[s].pcrSelect[j]);
            }
        }
    }

    if (rc == 0) {
        /* TPML_DIGEST: placeholder for count, then digests */
        digestCountPos = rsp->pos;
        TPM2_Packet_AppendU32(rsp, 0);

        for (s = 0; s < numSel; s++) {
            int bank = FwGetPcrBankIndex(selections[s].hashAlg);
            int dSize = TPM2_GetHashDigestSize(selections[s].hashAlg);
            int j, pcr;

            if (bank < 0 || dSize == 0) {
                continue;
            }

            for (j = 0; j < selections[s].sizeOfSelect; j++) {
                for (pcr = 0; pcr < 8; pcr++) {
                    if (selections[s].pcrSelect[j] & (1 << pcr)) {
                        int pcrIndex = j * 8 + pcr;
                        if (pcrIndex < IMPLEMENTATION_PCR) {
                            TPM2_Packet_AppendU16(rsp, (UINT16)dSize);
                            TPM2_Packet_AppendBytes(rsp,
                                ctx->pcrDigest[pcrIndex][bank], dSize);
                            totalDigests++;
                        }
                    }
                }
            }
        }

        /* Patch digest count */
        savedPos = rsp->pos;
        rsp->pos = digestCountPos;
        TPM2_Packet_AppendU32(rsp, (UINT32)totalDigests);
        rsp->pos = savedPos;

        FwRspFinalize(rsp, TPM_ST_NO_SESSIONS, TPM_RC_SUCCESS);
    }

    return rc;
}

/* --- TPM2_PCR_Extend (CC 0x0182) --- */
static TPM_RC FwCmd_PCR_Extend(FWTPM_CTX* ctx, TPM2_Packet* cmd, int cmdSize,
    TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 pcrHandle = 0;
    UINT32 digestCount = 0;
    UINT32 d;
    UINT16 hashAlg;
    int bank, dSize, pcrIndex;
    enum wc_HashType wcHash;
    byte newDigest[TPM_MAX_DIGEST_SIZE];
    byte concat[TPM_MAX_DIGEST_SIZE * 2];

    if (cmdSize < TPM2_HEADER_SIZE + 4) {
        rc = TPM_RC_COMMAND_SIZE;
    }

    if (rc == 0) {
        TPM2_Packet_ParseU32(cmd, &pcrHandle);
        if (pcrHandle > PCR_LAST) {
            rc = TPM_RC_VALUE;
        }
    }

    /* Skip authorization area if sessions tag */
    if (rc == 0 && cmdTag == TPM_ST_SESSIONS) {
        rc = FwSkipAuthArea(cmd, cmdSize);
    }

    if (rc == 0) {
        if (cmd->pos + 4 > cmdSize) {
            rc = TPM_RC_COMMAND_SIZE;
        }
    }

    if (rc == 0) {
        TPM2_Packet_ParseU32(cmd, &digestCount);

    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: PCR_Extend(pcr=%d, digests=%d)\n",
            pcrHandle - PCR_FIRST, digestCount);
    #endif
    }

    for (d = 0; d < digestCount && rc == 0; d++) {
        pcrIndex = pcrHandle - PCR_FIRST;

        if (cmd->pos + 2 > cmdSize) {
            rc = TPM_RC_COMMAND_SIZE;
            break;
        }

        TPM2_Packet_ParseU16(cmd, &hashAlg);
        bank = FwGetPcrBankIndex(hashAlg);
        dSize = TPM2_GetHashDigestSize(hashAlg);

        if (dSize == 0) {
            /* Unknown hash algorithm — cannot determine digest size to skip,
             * so reject rather than desync the command buffer parser. */
            rc = TPM_RC_HASH;
            break;
        }
        if (bank < 0) {
            /* Known algorithm but unsupported bank — skip the digest bytes */
            cmd->pos += dSize;
            continue;
        }

        if (cmd->pos + dSize > cmdSize) {
            rc = TPM_RC_COMMAND_SIZE;
            break;
        }

        /* PCR_new = H(PCR_old || digest_in) */
        wcHash = FwGetWcHashType(hashAlg);
        XMEMCPY(concat, ctx->pcrDigest[pcrIndex][bank], dSize);
        XMEMCPY(concat + dSize, cmd->buf + cmd->pos, dSize);
        rc = wc_Hash(wcHash, concat, dSize * 2, newDigest, dSize);
        if (rc != 0) {
            rc = TPM_RC_FAILURE;
            break;
        }
        XMEMCPY(ctx->pcrDigest[pcrIndex][bank], newDigest, dSize);
        cmd->pos += dSize;
    }

    if (rc == 0) {
        ctx->pcrUpdateCounter++;
        FwRspNoParams(rsp, cmdTag);
    }

    return rc;
}

/* --- TPM2_PCR_Reset (CC 0x013D) --- */
static TPM_RC FwCmd_PCR_Reset(FWTPM_CTX* ctx, TPM2_Packet* cmd, int cmdSize,
    TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 pcrHandle = 0;
    int pcrIndex = 0;
    int b;

    if (cmdSize < TPM2_HEADER_SIZE + 4) {
        rc = TPM_RC_COMMAND_SIZE;
    }

    if (rc == 0) {
        TPM2_Packet_ParseU32(cmd, &pcrHandle);
        if (pcrHandle > PCR_LAST) {
            rc = TPM_RC_VALUE;
        }
    }

    if (rc == 0) {
        pcrIndex = pcrHandle - PCR_FIRST;
        if (pcrIndex < 16) {
            rc = TPM_RC_LOCALITY;
        }
    }

    if (rc == 0 && cmdTag == TPM_ST_SESSIONS) {
        rc = FwSkipAuthArea(cmd, cmdSize);
    }

    if (rc == 0) {
    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: PCR_Reset(pcr=%d)\n", pcrIndex);
    #endif

        for (b = 0; b < FWTPM_PCR_BANKS; b++) {
            XMEMSET(ctx->pcrDigest[pcrIndex][b], 0, TPM_MAX_DIGEST_SIZE);
        }

        ctx->pcrUpdateCounter++;
        FwRspNoParams(rsp, cmdTag);
    }

    return rc;
}

/* --- TPM2_PCR_Event (CC 0x013C) --- */
/* Hash eventData with each active PCR bank algorithm, then extend.
 * Returns TPML_DIGEST_VALUES with the computed hash digests. */
static TPM_RC FwCmd_PCR_Event(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 pcrHandle = 0;
    UINT16 eventSize = 0;
    FWTPM_DECLARE_BUF(eventData, FWTPM_MAX_DATA_BUF);
    FWTPM_DECLARE_BUF(digestBuf, FWTPM_PCR_BANKS * TPM_MAX_DIGEST_SIZE);
    int pcrIndex;
    int paramSzPos, paramStart;
    int bankCount = 0;
    int digestSz[FWTPM_PCR_BANKS];
    UINT16 bankAlgs[FWTPM_PCR_BANKS];
    byte concat[TPM_MAX_DIGEST_SIZE * 2];
    byte newPcr[TPM_MAX_DIGEST_SIZE];
    int b;

    if (cmdSize < TPM2_HEADER_SIZE + 4) {
        rc = TPM_RC_COMMAND_SIZE;
    }

    if (rc == 0) {
        TPM2_Packet_ParseU32(cmd, &pcrHandle);
        if (pcrHandle > PCR_LAST) {
            rc = TPM_RC_VALUE;
        }
    }

    if (rc == 0 && cmdTag == TPM_ST_SESSIONS) {
        rc = FwSkipAuthArea(cmd, cmdSize);
    }

    /* Parse eventData size before allocating scratch buffers */
    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &eventSize);
        if (eventSize > FWTPM_MAX_DATA_BUF)
            rc = TPM_RC_SIZE;
    }
    if (rc == 0 && cmd->pos + eventSize > cmdSize) {
        rc = TPM_RC_COMMAND_SIZE;
    }

    if (rc == 0) {
        FWTPM_ALLOC_BUF(eventData, FWTPM_MAX_DATA_BUF);
    }
    if (rc == 0) {
        FWTPM_ALLOC_BUF(digestBuf, FWTPM_PCR_BANKS * TPM_MAX_DIGEST_SIZE);
    }

    if (rc == 0 && eventSize > 0) {
        TPM2_Packet_ParseBytes(cmd, eventData, eventSize);
    }

    if (rc == 0) {
        pcrIndex = pcrHandle - PCR_FIRST;

        /* SHA-256 bank */
        bankAlgs[0] = TPM_ALG_SHA256;
        digestSz[0] = TPM2_GetHashDigestSize(TPM_ALG_SHA256);
        if (digestSz[0] > 0) {
            byte* dRow = digestBuf + 0 * TPM_MAX_DIGEST_SIZE;
            enum wc_HashType wc0 = FwGetWcHashType(TPM_ALG_SHA256);
            rc = wc_Hash(wc0, eventData, eventSize, dRow, digestSz[0]);
            if (rc != 0) {
                rc = TPM_RC_FAILURE;
            }
            if (rc == 0) {
                XMEMCPY(concat,
                    ctx->pcrDigest[pcrIndex][FWTPM_PCR_BANK_SHA256],
                    digestSz[0]);
                XMEMCPY(concat + digestSz[0], dRow, digestSz[0]);
                rc = wc_Hash(wc0, concat, digestSz[0] * 2,
                    newPcr, digestSz[0]);
                if (rc != 0) {
                    rc = TPM_RC_FAILURE;
                }
            }
            if (rc == 0) {
                XMEMCPY(ctx->pcrDigest[pcrIndex][FWTPM_PCR_BANK_SHA256],
                    newPcr, digestSz[0]);
                bankCount++;
            }
        }

    #ifdef WOLFSSL_SHA384
        /* SHA-384 bank */
        if (rc == 0) {
            bankAlgs[1] = TPM_ALG_SHA384;
            digestSz[1] = TPM2_GetHashDigestSize(TPM_ALG_SHA384);
            if (digestSz[1] > 0) {
                byte* dRow = digestBuf + 1 * TPM_MAX_DIGEST_SIZE;
                enum wc_HashType wc1 = FwGetWcHashType(TPM_ALG_SHA384);
                rc = wc_Hash(wc1, eventData, eventSize,
                    dRow, digestSz[1]);
                if (rc != 0) {
                    rc = TPM_RC_FAILURE;
                }
                if (rc == 0) {
                    XMEMCPY(concat,
                        ctx->pcrDigest[pcrIndex][FWTPM_PCR_BANK_SHA384],
                        digestSz[1]);
                    XMEMCPY(concat + digestSz[1], dRow, digestSz[1]);
                    rc = wc_Hash(wc1, concat, digestSz[1] * 2,
                        newPcr, digestSz[1]);
                    if (rc != 0) {
                        rc = TPM_RC_FAILURE;
                    }
                }
                if (rc == 0) {
                    XMEMCPY(
                        ctx->pcrDigest[pcrIndex][FWTPM_PCR_BANK_SHA384],
                        newPcr, digestSz[1]);
                    bankCount++;
                }
            }
        }
    #endif
    }

    if (rc == 0) {
        ctx->pcrUpdateCounter++;

    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: PCR_Event(pcr=%d, eventSz=%d, banks=%d)\n",
            pcrHandle - PCR_FIRST, eventSize, bankCount);
    #endif

        /* Build response: TPML_DIGEST_VALUES */
        paramStart = FwRspParamsBegin(rsp, cmdTag, &paramSzPos);
        TPM2_Packet_AppendU32(rsp, (UINT32)bankCount);
        for (b = 0; b < bankCount; b++) {
            TPM2_Packet_AppendU16(rsp, bankAlgs[b]);
            TPM2_Packet_AppendBytes(rsp,
                digestBuf + b * TPM_MAX_DIGEST_SIZE, digestSz[b]);
        }
        FwRspParamsEnd(rsp, cmdTag, paramSzPos, paramStart);
    }

    FWTPM_FREE_BUF(digestBuf);
    FWTPM_FREE_BUF(eventData);
    return rc;
}

/* --- TPM2_PCR_Allocate (CC 0x012B) --- */
/* Allocate PCR banks. Per spec Section 22.5, takes effect after next Startup(CLEAR).
 * For software TPM, we always succeed. */
static TPM_RC FwCmd_PCR_Allocate(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 authHandle = 0;
    UINT32 count = 0;
    UINT32 c;
    UINT8 newBanks = 0;
    int paramSzPos, paramStart;
    UINT32 sizeNeeded = 0;
    UINT32 sizeAvailable;

    (void)cmdSize;

    TPM2_Packet_ParseU32(cmd, &authHandle);
    if (cmdTag == TPM_ST_SESSIONS)
        rc = FwSkipAuthArea(cmd, cmdSize);

    if (rc == 0 && authHandle != TPM_RH_PLATFORM) {
        rc = TPM_RC_AUTH_TYPE;
    }

    /* Parse TPML_PCR_SELECTION */
    if (rc == 0) {
        TPM2_Packet_ParseU32(cmd, &count);
        if (count > FWTPM_PCR_BANKS * 4) {
            rc = TPM_RC_SIZE;
        }
        for (c = 0; c < count && rc == 0; c++) {
            UINT16 hashAlg;
            UINT8 sizeOfSelect;
            int bank;

            TPM2_Packet_ParseU16(cmd, &hashAlg);
            TPM2_Packet_ParseU8(cmd, &sizeOfSelect);
            cmd->pos += sizeOfSelect; /* skip pcrSelect bytes */

            bank = FwGetPcrBankIndex(hashAlg);
            if (bank >= 0) {
                newBanks |= (UINT8)(1 << bank);
                sizeNeeded += (UINT32)(IMPLEMENTATION_PCR *
                    TPM2_GetHashDigestSize(hashAlg));
            }
            /* Unsupported hash algorithms are silently ignored per spec */
        }
    }

    if (rc == 0) {
    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: PCR_Allocate(banks=0x%02x)\n", newBanks);
    #endif
        ctx->pcrAllocatedBanks = newBanks;
        rc = FWTPM_NV_Save(ctx);
        if (rc != TPM_RC_SUCCESS) {
            return rc;
        }

        sizeAvailable = (UINT32)(IMPLEMENTATION_PCR * FWTPM_PCR_BANKS *
            TPM_MAX_DIGEST_SIZE);

        paramStart = FwRspParamsBegin(rsp, cmdTag, &paramSzPos);
        TPM2_Packet_AppendU8(rsp, 1); /* allocationSuccess = YES */
        TPM2_Packet_AppendU32(rsp, (UINT32)IMPLEMENTATION_PCR);
        TPM2_Packet_AppendU32(rsp, sizeNeeded);
        TPM2_Packet_AppendU32(rsp, sizeAvailable);
        FwRspParamsEnd(rsp, cmdTag, paramSzPos, paramStart);
    }

    return rc;
}

/* --- TPM2_PCR_SetAuthPolicy (CC 0x012C) --- */
/* Set the authorization policy for a PCR. Platform auth required.
 * Per spec Section 22.6. */
static TPM_RC FwCmd_PCR_SetAuthPolicy(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 authHandle = 0;
    UINT16 policySz = 0;
    byte policyBuf[TPM_MAX_DIGEST_SIZE];
    UINT16 hashAlg = TPM_ALG_NULL;
    UINT32 pcrNum = 0;
    int pcrIndex;

    (void)cmdSize;

    TPM2_Packet_ParseU32(cmd, &authHandle);
    if (cmdTag == TPM_ST_SESSIONS)
        rc = FwSkipAuthArea(cmd, cmdSize);

    if (rc == 0 && authHandle != TPM_RH_PLATFORM) {
        rc = TPM_RC_AUTH_TYPE;
    }

    /* Parse authPolicy (TPM2B_DIGEST) */
    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &policySz);
        if (policySz > sizeof(policyBuf))
            rc = TPM_RC_SIZE;
    }
    if (rc == 0 && policySz > 0) {
        TPM2_Packet_ParseBytes(cmd, policyBuf, policySz);
    }

    /* Parse hashAlg and pcrNum */
    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &hashAlg);
        TPM2_Packet_ParseU32(cmd, &pcrNum);
        if (pcrNum > PCR_LAST) {
            rc = TPM_RC_VALUE;
        }
    }

    if (rc == 0) {
        pcrIndex = (int)(pcrNum - PCR_FIRST);

    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: PCR_SetAuthPolicy(pcr=%d, policySz=%d, alg=0x%x)\n",
            pcrIndex, policySz, hashAlg);
    #endif

        ctx->pcrPolicy[pcrIndex].size = policySz;
        if (policySz > 0) {
            XMEMCPY(ctx->pcrPolicy[pcrIndex].buffer, policyBuf, policySz);
        }
        ctx->pcrPolicyAlg[pcrIndex] = (policySz > 0) ?
                                      hashAlg : (TPMI_ALG_HASH)TPM_ALG_NULL;
        FWTPM_NV_SavePcrAuth(ctx);
        FwRspNoParams(rsp, cmdTag);
    }

    return rc;
}

/* --- TPM2_PCR_SetAuthValue (CC 0x0183) --- */
/* Set the auth value for a PCR. Per spec Section 22.7. */
static TPM_RC FwCmd_PCR_SetAuthValue(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 pcrHandle = 0;
    UINT16 newAuthSz = 0;
    byte newAuthBuf[TPM_MAX_DIGEST_SIZE];
    int pcrIndex;

    (void)cmdSize;

    TPM2_Packet_ParseU32(cmd, &pcrHandle);
    if (cmdTag == TPM_ST_SESSIONS)
        rc = FwSkipAuthArea(cmd, cmdSize);

    if (rc == 0 && pcrHandle > PCR_LAST) {
        rc = TPM_RC_VALUE;
    }

    /* Parse auth (TPM2B_AUTH) */
    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &newAuthSz);
        if (newAuthSz > sizeof(newAuthBuf))
            rc = TPM_RC_SIZE;
    }
    if (rc == 0 && newAuthSz > 0) {
        TPM2_Packet_ParseBytes(cmd, newAuthBuf, newAuthSz);
    }

    if (rc == 0) {
        pcrIndex = (int)(pcrHandle - PCR_FIRST);

    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: PCR_SetAuthValue(pcr=%d, authSz=%d)\n",
            pcrIndex, newAuthSz);
    #endif

        TPM2_ForceZero(ctx->pcrAuth[pcrIndex].buffer,
            sizeof(ctx->pcrAuth[pcrIndex].buffer));
        ctx->pcrAuth[pcrIndex].size = newAuthSz;
        if (newAuthSz > 0) {
            XMEMCPY(ctx->pcrAuth[pcrIndex].buffer, newAuthBuf, newAuthSz);
        }
        FWTPM_NV_SavePcrAuth(ctx);
        FwRspNoParams(rsp, cmdTag);
    }

    TPM2_ForceZero(newAuthBuf, sizeof(newAuthBuf));
    return rc;
}

/* --- TPM2_ReadClock (CC 0x0181) --- */
static TPM_RC FwCmd_ReadClock(FWTPM_CTX* ctx, TPM2_Packet* cmd, int cmdSize,
    TPM2_Packet* rsp, UINT16 cmdTag)
{
    UINT64 clockMs;

    (void)cmd;
    (void)cmdSize;
    (void)ctx;
    (void)cmdTag;

#ifdef DEBUG_WOLFTPM
    printf("fwTPM: ReadClock\n");
#endif

    /* TPMS_TIME_INFO: time(8) + clock(8) + resetCount(4) +
     *                 restartCount(4) + safe(1)
     * Uses clock HAL (if set) + clockOffset. clockOffset is persisted to NV
     * and can be advanced via ClockSet. */
    clockMs = FWTPM_Clock_GetMs(ctx);
    TPM2_Packet_AppendU64(rsp, clockMs); /* time */
    TPM2_Packet_AppendU64(rsp, clockMs); /* clock */
    TPM2_Packet_AppendU32(rsp, 0); /* resetCount */
    TPM2_Packet_AppendU32(rsp, 0); /* restartCount */
    TPM2_Packet_AppendU8(rsp, 1);  /* safe = YES */

    FwRspFinalize(rsp, TPM_ST_NO_SESSIONS, TPM_RC_SUCCESS);
    return TPM_RC_SUCCESS; /* always succeeds */
}

/* --- TPM2_ClockSet (CC 0x0128) --- */
/* Sets the TPM clock to a new value. newTime must be >= current clock. */
static TPM_RC FwCmd_ClockSet(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 authHandle = 0;
    UINT64 newTime = 0;

    (void)cmdSize;

    TPM2_Packet_ParseU32(cmd, &authHandle);
    if (cmdTag == TPM_ST_SESSIONS) rc = FwSkipAuthArea(cmd, cmdSize);

    TPM2_Packet_ParseU64(cmd, &newTime);

#ifdef DEBUG_WOLFTPM
    printf("fwTPM: ClockSet(auth=0x%x, newTime=%llu)\n",
        authHandle, (unsigned long long)newTime);
#endif

    /* Only owner or platform hierarchy can set clock */
    if (authHandle != TPM_RH_OWNER && authHandle != TPM_RH_PLATFORM) {
        rc = TPM_RC_AUTH_TYPE;
    }

    /* New time must be >= current (can only advance) */
    if (rc == 0) {
        UINT64 currentTime = FWTPM_Clock_GetMs(ctx);
        if (newTime < currentTime) {
            rc = TPM_RC_VALUE;
        }
    }

    if (rc == 0) {
        /* Calculate offset: if clock HAL is set, offset = newTime - halTime.
         * If no HAL, offset = newTime directly (original behavior). */
        if (ctx->clockHal.get_ms != NULL) {
            UINT64 halTime = ctx->clockHal.get_ms(ctx->clockHal.ctx);
            ctx->clockOffset = newTime - halTime;
        }
        else {
            ctx->clockOffset = newTime;
        }
        FWTPM_NV_SaveClock(ctx);
        FwRspNoParams(rsp, cmdTag);
    }

    return rc;
}

/* --- TPM2_ClockRateAdjust (CC 0x0130) --- */
/* Adjusts the rate at which Clock is updated. Software TPM stores the
 * value but does not actually adjust the rate. Per spec Section 29.3. */
static TPM_RC FwCmd_ClockRateAdjust(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 authHandle = 0;

    (void)cmdSize;
    (void)ctx;

    TPM2_Packet_ParseU32(cmd, &authHandle);
    if (cmdTag == TPM_ST_SESSIONS)
        rc = FwSkipAuthArea(cmd, cmdSize);

    /* Only owner or platform can adjust clock rate */
    if (rc == 0 && authHandle != TPM_RH_OWNER &&
        authHandle != TPM_RH_PLATFORM) {
        rc = TPM_RC_AUTH_TYPE;
    }

    if (rc == 0) {
        /* rateAdjust is TPM_CLOCK_ADJUST (INT8 on wire, -3 to +3).
         * Skip past the byte - no-op for software TPM. */
        cmd->pos += 1;

    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: ClockRateAdjust(auth=0x%x)\n", authHandle);
    #endif
        FwRspNoParams(rsp, cmdTag);
    }

    return rc;
}

/* --- Object management helpers --- */

/** \brief Allocate a free transient object slot and assign a handle.
 *  \return pointer to the object, or NULL if all slots are full. */
static FWTPM_Object* FwAllocObject(FWTPM_CTX* ctx, TPM_HANDLE* outHandle)
{
    int i;
    for (i = 0; i < FWTPM_MAX_OBJECTS; i++) {
        if (!ctx->objects[i].used) {
            XMEMSET(&ctx->objects[i], 0, sizeof(FWTPM_Object));
            ctx->objects[i].used = 1;
            ctx->objects[i].handle = TRANSIENT_FIRST + (TPM_HANDLE)i;
            if (outHandle != NULL) {
                *outHandle = ctx->objects[i].handle;
            }
            return &ctx->objects[i];
        }
    }
    return NULL;
}

/** \brief Find a loaded object by handle (transient or persistent). */
static FWTPM_Object* FwFindObject(FWTPM_CTX* ctx, TPM_HANDLE handle)
{
    int i;
    /* Search transient objects */
    for (i = 0; i < FWTPM_MAX_OBJECTS; i++) {
        if (ctx->objects[i].used && ctx->objects[i].handle == handle) {
            return &ctx->objects[i];
        }
    }
    /* Search persistent objects */
    for (i = 0; i < FWTPM_MAX_PERSISTENT; i++) {
        if (ctx->persistent[i].used && ctx->persistent[i].handle == handle) {
            return &ctx->persistent[i];
        }
    }
    return NULL;
}

/** \brief Free an object slot, securely zeroing all key material. */
static void FwFreeObject(FWTPM_Object* obj)
{
    if (obj != NULL) {
        TPM2_ForceZero(obj, sizeof(FWTPM_Object));
    }
}

static void FwFlushAllObjects(FWTPM_CTX* ctx)
{
    int i;
    for (i = 0; i < FWTPM_MAX_OBJECTS; i++) {
        if (ctx->objects[i].used) {
            FwFreeObject(&ctx->objects[i]);
        }
    }
}

/* --- Session management helpers --- */

/** \brief Allocate a free session slot for HMAC, policy, or trial session. */
static FWTPM_Session* FwAllocSession(FWTPM_CTX* ctx, TPM_SE sessionType,
    TPM_HANDLE* outHandle)
{
    int i;
    for (i = 0; i < FWTPM_MAX_SESSIONS; i++) {
        if (!ctx->sessions[i].used) {
            XMEMSET(&ctx->sessions[i], 0, sizeof(FWTPM_Session));
            ctx->sessions[i].used = 1;
            if (sessionType == TPM_SE_HMAC) {
                ctx->sessions[i].handle = HMAC_SESSION_FIRST +
                    (TPM_HANDLE)i;
            }
            else {
                /* Policy and Trial sessions both use policy handle space */
                ctx->sessions[i].handle = POLICY_SESSION_FIRST +
                    (TPM_HANDLE)i;
            }
            ctx->sessions[i].sessionType = sessionType;
            if (outHandle != NULL) {
                *outHandle = ctx->sessions[i].handle;
            }
            return &ctx->sessions[i];
        }
    }
    return NULL;
}

/** \brief Find an active session by handle. */
static FWTPM_Session* FwFindSession(FWTPM_CTX* ctx, TPM_HANDLE handle)
{
    int i;
    for (i = 0; i < FWTPM_MAX_SESSIONS; i++) {
        if (ctx->sessions[i].used && ctx->sessions[i].handle == handle) {
            return &ctx->sessions[i];
        }
    }
    return NULL;
}

/** \brief Free a session slot, securely zeroing session key material. */
static void FwFreeSession(FWTPM_Session* sess)
{
    if (sess != NULL) {
        TPM2_ForceZero(sess, sizeof(FWTPM_Session));
    }
}

static void FwFlushAllSessions(FWTPM_CTX* ctx)
{
    int i;
    for (i = 0; i < FWTPM_MAX_SESSIONS; i++) {
        if (ctx->sessions[i].used) {
            FwFreeSession(&ctx->sessions[i]);
        }
    }
}

/* --- TPM2_CreatePrimary (CC 0x0131) --- */
static TPM_RC FwCmd_CreatePrimary(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 primaryHandle = 0;
    TPM2B_AUTH userAuth;
    FWTPM_DECLARE_VAR(inPublic, TPM2B_PUBLIC);
    UINT16 outsideInfoSize = 0;
    UINT32 creationPcrCount = 0;
    FWTPM_Object* obj = NULL;
    TPM_HANDLE objHandle = 0;
    byte* seed;
    int paramSzPos = 0, paramStart = 0;
    byte templateHash[WC_SHA256_DIGEST_SIZE];
    FWTPM_PrimaryCache* cached = NULL;
    int cacheIdx;
    int cdStart;
    FWTPM_DECLARE_BUF(sensData, FWTPM_MAX_DATA_BUF);
    UINT16 sensDataSize = 0;
    byte hashUnique[TPM_MAX_DIGEST_SIZE];
    int hashUniqueSz = 0;

    FWTPM_CALLOC_VAR(inPublic, TPM2B_PUBLIC);
    FWTPM_CALLOC_BUF(sensData, FWTPM_MAX_DATA_BUF);

    if (cmdSize < TPM2_HEADER_SIZE + 4) {
        rc = TPM_RC_COMMAND_SIZE;
    }

    /* Parse primary handle (hierarchy) */
    if (rc == 0) {
        TPM2_Packet_ParseU32(cmd, &primaryHandle);
        seed = FwGetHierarchySeed(ctx, primaryHandle);
        if (seed == NULL) {
            rc = TPM_RC_HIERARCHY;
        }
    }

    /* Skip auth area if sessions tag */
    if (rc == 0 && cmdTag == TPM_ST_SESSIONS) rc = FwSkipAuthArea(cmd, cmdSize);

    /* Parse inSensitive (TPM2B_SENSITIVE_CREATE) — capture data for
     * symmetric primary key derivation and hashUnique computation */
    if (rc == 0) {
        rc = TPM2_Packet_ParseSensitiveCreate(cmd, cmdSize, &userAuth,
            sensData, (int)FWTPM_SIZEOF_BUF(sensData, FWTPM_MAX_DATA_BUF), &sensDataSize);
    }

    /* Parse inPublic (TPM2B_PUBLIC) */
    if (rc == 0) {
        TPM2_Packet_ParsePublic(cmd, inPublic);
    }

    /* Parse outsideInfo (TPM2B_DATA) - skip */
    if (rc == 0) {
        if (cmd->pos + 2 > cmdSize) {
            rc = TPM_RC_COMMAND_SIZE;
        }
    }
    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &outsideInfoSize);
        if (cmd->pos + outsideInfoSize > cmdSize) {
            rc = TPM_RC_COMMAND_SIZE;
        }
    }
    if (rc == 0) {
        cmd->pos += outsideInfoSize;
    }

    /* Parse creationPCR (TPML_PCR_SELECTION) - skip */
    if (rc == 0) {
        if (cmd->pos + 4 > cmdSize) {
            rc = TPM_RC_COMMAND_SIZE;
        }
    }
    if (rc == 0) {
        UINT32 s;
        TPM2_Packet_ParseU32(cmd, &creationPcrCount);
        for (s = 0; s < creationPcrCount && rc == 0; s++) {
            UINT8 selectSize;
            if (cmd->pos + 3 > cmdSize) {
                rc = TPM_RC_COMMAND_SIZE;
                break;
            }
            cmd->pos += 2; /* hashAlg */
            TPM2_Packet_ParseU8(cmd, &selectSize);
            if (cmd->pos + selectSize > cmdSize) {
                rc = TPM_RC_COMMAND_SIZE;
                break;
            }
            cmd->pos += selectSize;
        }
    }

    /* Compute hashUnique = H(sensData || unique) for seed-based derivation.
     * Per TPM 2.0 Part 1 Section 26.1. */
    if (rc == 0) {
        const byte* uBuf = NULL;
        int uSz = 0;
#ifdef HAVE_ECC
        byte eccUniqueBuf[MAX_ECC_KEY_BYTES * 2];
#endif
        switch (inPublic->publicArea.type) {
#ifndef NO_RSA
            case TPM_ALG_RSA:
                uBuf = inPublic->publicArea.unique.rsa.buffer;
                uSz = (int)inPublic->publicArea.unique.rsa.size;
                break;
#endif
#ifdef HAVE_ECC
            case TPM_ALG_ECC: {
                /* Concatenate x || y into a temp buffer */
                int xSz = (int)inPublic->publicArea.unique.ecc.x.size;
                int ySz = (int)inPublic->publicArea.unique.ecc.y.size;
                if (xSz + ySz <= (int)sizeof(eccUniqueBuf)) {
                    XMEMCPY(eccUniqueBuf,
                        inPublic->publicArea.unique.ecc.x.buffer, xSz);
                    XMEMCPY(eccUniqueBuf + xSz,
                        inPublic->publicArea.unique.ecc.y.buffer, ySz);
                    uBuf = eccUniqueBuf;
                    uSz = xSz + ySz;
                }
                break;
            }
#endif
            case TPM_ALG_KEYEDHASH:
                uBuf = inPublic->publicArea.unique.keyedHash.buffer;
                uSz = (int)inPublic->publicArea.unique.keyedHash.size;
                break;
            case TPM_ALG_SYMCIPHER:
                uBuf = inPublic->publicArea.unique.sym.buffer;
                uSz = (int)inPublic->publicArea.unique.sym.size;
                break;
            default:
                break;
        }
        hashUniqueSz = FwComputeHashUnique(inPublic->publicArea.nameAlg,
            sensData, (int)sensDataSize, uBuf, uSz, hashUnique);
    }

    /* Hash the public template + sensData for cache lookup */
    if (rc == 0) {
        rc = FwHashOneShot(TPM_ALG_SHA256,
            (byte*)&inPublic->publicArea,
            (word32)sizeof(inPublic->publicArea),
            sensData, (word32)sensDataSize,
            templateHash);
        if (rc != 0) {
            rc = TPM_RC_FAILURE;
        }
    }

    /* Check primary key cache for matching hierarchy + template */
    if (rc == 0) {
        for (cacheIdx = 0; cacheIdx < FWTPM_MAX_PRIMARY_CACHE; cacheIdx++) {
            if (ctx->primaryCache[cacheIdx].used &&
                ctx->primaryCache[cacheIdx].hierarchy == primaryHandle &&
                XMEMCMP(ctx->primaryCache[cacheIdx].templateHash, templateHash,
                    WC_SHA256_DIGEST_SIZE) == 0) {
                cached = &ctx->primaryCache[cacheIdx];
                break;
            }
        }
    }

    /* Allocate transient object slot */
    if (rc == 0) {
        obj = FwAllocObject(ctx, &objHandle);
        if (obj == NULL) {
            rc = TPM_RC_OBJECT_MEMORY;
        }
    }

    if (rc == 0) {
        /* Copy template to object's public area */
        XMEMCPY(&obj->pub, &inPublic->publicArea, sizeof(TPMT_PUBLIC));
        XMEMCPY(&obj->authValue, &userAuth, sizeof(TPM2B_AUTH));

    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: CreatePrimary(hierarchy=0x%x, type=%d, handle=0x%x%s)\n",
            primaryHandle, inPublic->publicArea.type, objHandle,
            cached ? ", cached" : "");
    #endif
    }

    if (rc == 0 && cached != NULL) {
        /* Use cached key material */
        XMEMCPY(&obj->pub, &cached->pub, sizeof(TPMT_PUBLIC));
        XMEMCPY(obj->privKey, cached->privKey, cached->privKeySize);
        obj->privKeySize = cached->privKeySize;
    }

    if (rc == 0 && cached == NULL) {
        /* Derive key from hierarchy seed per TPM 2.0 Part 1 Section 26.
         * Same seed + same template = same key (deterministic). */
        switch (inPublic->publicArea.type) {
#ifndef NO_RSA
            case TPM_ALG_RSA: {
            #ifdef WOLFSSL_KEY_GEN
                int derSz = 0;
                rc = FwDeriveRsaPrimaryKey(inPublic->publicArea.nameAlg,
                    seed, hashUnique, hashUniqueSz,
                    inPublic->publicArea.parameters.rsaDetail.keyBits,
                    inPublic->publicArea.parameters.rsaDetail.exponent,
                    &ctx->rng,
                    &obj->pub.unique.rsa,
                    obj->privKey, FWTPM_MAX_PRIVKEY_DER, &derSz);
                if (rc == 0) {
                    obj->privKeySize = derSz;
                }
            #else
                rc = TPM_RC_COMMAND_CODE;
            #endif /* WOLFSSL_KEY_GEN */
                break;
            }
#endif /* !NO_RSA */

#ifdef HAVE_ECC
            case TPM_ALG_ECC: {
                int derSz = 0;
                rc = FwDeriveEccPrimaryKey(inPublic->publicArea.nameAlg,
                    seed, hashUnique, hashUniqueSz,
                    inPublic->publicArea.parameters.eccDetail.curveID,
                    &obj->pub.unique.ecc,
                    obj->privKey, FWTPM_MAX_PRIVKEY_DER, &derSz);
                if (rc == 0) {
                    obj->privKeySize = derSz;
                }
                break;
            }
#endif /* HAVE_ECC */

            case TPM_ALG_KEYEDHASH: {
                /* HMAC key or sealed data object.
                 * If caller supplied sensitive.data, use it directly;
                 * otherwise derive from seed via KDFa. */
                TPMI_ALG_HASH hashAlg;
                TPMI_ALG_KEYEDHASH_SCHEME scheme;
                int keySz;

                scheme = inPublic->publicArea.parameters.keyedHashDetail
                    .scheme.scheme;
                if (scheme == TPM_ALG_HMAC) {
                    hashAlg = inPublic->publicArea.parameters.keyedHashDetail
                        .scheme.details.hmac.hashAlg;
                    keySz = TPM2_GetHashDigestSize(hashAlg);
                    if (keySz <= 0) {
                        rc = TPM_RC_HASH;
                    }
                }
                else {
                    keySz = TPM2_GetHashDigestSize(
                        inPublic->publicArea.nameAlg);
                    if (keySz <= 0)
                        keySz = TPM_SHA256_DIGEST_SIZE;
                }

                if (rc == 0 && sensDataSize > 0) {
                    /* Use caller-supplied key material */
                    if (sensDataSize > (UINT16)FWTPM_MAX_PRIVKEY_DER) {
                        rc = TPM_RC_SIZE;
                    }
                    if (rc == 0) {
                        XMEMCPY(obj->privKey, sensData, sensDataSize);
                        obj->privKeySize = (int)sensDataSize;
                    }
                }
                else if (rc == 0) {
                    /* Derive from hierarchy seed per spec Section 26.1 */
                    rc = FwDeriveSymmetricPrimaryKey(
                        inPublic->publicArea.nameAlg, seed,
                        hashUnique, hashUniqueSz,
                        "KEYEDHASH", obj->privKey, keySz);
                    if (rc == 0) {
                        obj->privKeySize = keySz;
                    }
                }

                /* unique = H(key bytes) */
                if (rc == 0) {
                    obj->pub.unique.keyedHash.size = (UINT16)
                        FwComputeUniqueHash(inPublic->publicArea.nameAlg,
                            obj->privKey, obj->privKeySize,
                            obj->pub.unique.keyedHash.buffer);
                }
                break;
            }

#ifndef NO_AES
            case TPM_ALG_SYMCIPHER: {
                /* AES symmetric key — derive from hierarchy seed */
                int keyBits = (int)inPublic->publicArea.parameters
                    .symDetail.sym.keyBits.sym;
                int keySz = keyBits / 8;

                if (keySz <= 0 || keySz > 32) {
                    rc = TPM_RC_KEY_SIZE;
                }

                if (rc == 0) {
                    rc = FwDeriveSymmetricPrimaryKey(
                        inPublic->publicArea.nameAlg, seed,
                        hashUnique, hashUniqueSz,
                        "SYMCIPHER", obj->privKey, keySz);
                }
                if (rc == 0) {
                    obj->privKeySize = keySz;

                    /* unique = H(key bytes) */
                    obj->pub.unique.sym.size = (UINT16)
                        FwComputeUniqueHash(inPublic->publicArea.nameAlg,
                            obj->privKey, keySz,
                            obj->pub.unique.sym.buffer);
                }
                break;
            }
#endif /* !NO_AES */

            default:
                rc = TPM_RC_TYPE;
                break;
        }
    }

    /* Store in primary key cache */
    if (rc == 0 && cached == NULL) {
        for (cacheIdx = 0; cacheIdx < FWTPM_MAX_PRIMARY_CACHE; cacheIdx++) {
            if (!ctx->primaryCache[cacheIdx].used) {
                ctx->primaryCache[cacheIdx].used = 1;
                ctx->primaryCache[cacheIdx].hierarchy = primaryHandle;
                XMEMCPY(ctx->primaryCache[cacheIdx].templateHash, templateHash,
                    WC_SHA256_DIGEST_SIZE);
                XMEMCPY(&ctx->primaryCache[cacheIdx].pub, &obj->pub,
                    sizeof(TPMT_PUBLIC));
                XMEMCPY(ctx->primaryCache[cacheIdx].privKey, obj->privKey,
                    obj->privKeySize);
                ctx->primaryCache[cacheIdx].privKeySize = obj->privKeySize;
                /* Persist cache entry to NV journal */
                FWTPM_NV_SavePrimaryCache(ctx, cacheIdx);
                break;
            }
        }
    }

    /* Compute object name */
    if (rc == 0) {
        rc = FwComputeObjectName(obj);
    }

    /* --- Build response --- */
    if (rc == 0) {
        TPM2B_PUBLIC outPub;
        int cdMarkPos;

        /* objectHandle */
        TPM2_Packet_AppendU32(rsp, objHandle);

        paramStart = FwRspParamsBegin(rsp, cmdTag, &paramSzPos);

        /* outPublic (TPM2B_PUBLIC) */
        outPub.size = 0; /* filled by AppendPublic */
        XMEMCPY(&outPub.publicArea, &obj->pub, sizeof(TPMT_PUBLIC));
        TPM2_Packet_AppendPublic(rsp, &outPub);

        /* creationData (TPM2B_CREATION_DATA) */
        TPM2_Packet_MarkU16(rsp, &cdMarkPos);
        cdStart = rsp->pos; /* start of TPMS_CREATION_DATA */
        /* TPMS_CREATION_DATA */
        TPM2_Packet_AppendU32(rsp, 0); /* pcrSelect count = 0 */
        TPM2_Packet_AppendU16(rsp, 0); /* pcrDigest size = 0 */
        TPM2_Packet_AppendU8(rsp, 0);  /* locality */
        TPM2_Packet_AppendU16(rsp, TPM_ALG_SHA256); /* parentNameAlg */
        TPM2_Packet_AppendU16(rsp, 4); /* parentName */
        TPM2_Packet_AppendU32(rsp, primaryHandle);
        TPM2_Packet_AppendU16(rsp, 4); /* parentQualifiedName */
        TPM2_Packet_AppendU32(rsp, primaryHandle);
        TPM2_Packet_AppendU16(rsp, 0); /* outsideInfo */
        TPM2_Packet_PlaceU16(rsp, cdMarkPos);

        FwAppendCreationHashAndTicket(ctx, rsp, primaryHandle,
            obj->pub.nameAlg, cdStart, rsp->pos - cdStart,
            (byte*)obj->name.name, obj->name.size);

        /* name (TPM2B_NAME) - inside parameter area per spec */
        TPM2_Packet_AppendU16(rsp, obj->name.size);
        TPM2_Packet_AppendBytes(rsp, obj->name.name, obj->name.size);

        FwRspParamsEnd(rsp, cmdTag, paramSzPos, paramStart);
    }

    /* Cleanup on error */
    if (rc != 0 && obj != NULL) {
        FwFreeObject(obj);
    }

    TPM2_ForceZero(&userAuth, sizeof(userAuth));
    TPM2_ForceZero(sensData, FWTPM_SIZEOF_BUF(sensData, FWTPM_MAX_DATA_BUF));
    FWTPM_FREE_BUF(sensData);
    FWTPM_FREE_VAR(inPublic);
    return rc;
}

/* --- TPM2_FlushContext (CC 0x0165) --- */
static TPM_RC FwCmd_FlushContext(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 flushHandle = 0;

    (void)cmdTag;

    if (cmdSize < TPM2_HEADER_SIZE + 4) {
        rc = TPM_RC_COMMAND_SIZE;
    }

    if (rc == 0) {
        TPM2_Packet_ParseU32(cmd, &flushHandle);

    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: FlushContext(handle=0x%x)\n", flushHandle);
    #endif

        /* Check if it's a session handle */
        if ((flushHandle & 0xFF000000) == HMAC_SESSION_FIRST ||
            (flushHandle & 0xFF000000) == POLICY_SESSION_FIRST) {
            FWTPM_Session* sess = FwFindSession(ctx, flushHandle);
            if (sess == NULL) {
                rc = TPM_RC_HANDLE;
            }
            else {
                FwFreeSession(sess);
            }
        }
        else if ((flushHandle & 0xFF000000) ==
                 (PERSISTENT_FIRST & 0xFF000000)) {
            /* Persistent objects cannot be flushed — use EvictControl */
            rc = TPM_RC_HANDLE;
        }
        else {
            /* Transient object handle */
            FWTPM_Object* obj = FwFindObject(ctx, flushHandle);
            if (obj == NULL) {
                rc = TPM_RC_HANDLE;
            }
            else {
                FwFreeObject(obj);
            }
        }
    }

    if (rc == 0) {
        FwRspFinalize(rsp, TPM_ST_NO_SESSIONS, TPM_RC_SUCCESS);
    }

    return rc;
}

/* --- TPM2_ContextSave (CC 0x0162) --- */
/* Serializes a transient object or session into a context blob that can be
 * stored externally (e.g. a .ctx file) and later reloaded with ContextLoad.
 * We use an opaque blob that stores the handle number; the object remains
 * in its slot so ContextLoad can find it for the lifetime of the server. */
#define FWTPM_CTX_MAGIC  0x4657544Du  /* 'FWTM' */
#define FWTPM_CTX_VER    1u
static TPM_RC FwCmd_ContextSave(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 saveHandle = 0;
    UINT32 hierarchy = 0;
    UINT32 tmp32;
    UINT16 blobSz;
    UINT32 seqHi, seqLo;
    int isSession = 0;
    FWTPM_Session* sess = NULL;

    (void)cmdTag;

    if (cmdSize < TPM2_HEADER_SIZE + 4) {
        rc = TPM_RC_COMMAND_SIZE;
    }

    if (rc == 0) {
        TPM2_Packet_ParseU32(cmd, &saveHandle);

    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: ContextSave(handle=0x%x)\n", saveHandle);
    #endif

        /* Validate handle */
        if ((saveHandle & 0xFF000000) == TRANSIENT_FIRST) {
            if (FwFindObject(ctx, saveHandle) == NULL) {
                rc = TPM_RC_HANDLE;
            }
            else {
                hierarchy = TPM_RH_OWNER;
            }
        }
        else if ((saveHandle & 0xFF000000) == HMAC_SESSION_FIRST ||
                 (saveHandle & 0xFF000000) == POLICY_SESSION_FIRST) {
            sess = FwFindSession(ctx, saveHandle);
            if (sess == NULL) {
                rc = TPM_RC_HANDLE;
            }
            else {
                hierarchy = TPM_RH_NULL;
                isSession = 1;
            }
        }
        else {
            rc = TPM_RC_HANDLE;
        }
    }

    if (rc == 0) {
        /* TPMS_CONTEXT: sequence(8) | savedHandle(4) | hierarchy(4) | blob */
        ctx->contextSeqCounter++;
        seqHi = (UINT32)(ctx->contextSeqCounter >> 32);
        seqLo = (UINT32)(ctx->contextSeqCounter & 0xFFFFFFFFu);
        TPM2_Packet_AppendU32(rsp, seqHi);
        TPM2_Packet_AppendU32(rsp, seqLo);
        TPM2_Packet_AppendU32(rsp, saveHandle);
        TPM2_Packet_AppendU32(rsp, hierarchy);

        if (isSession && sess != NULL) {
            /* Session: HMAC + AES-CFB protected blob per TPM 2.0 Section 30.
             * Format: magic(4) | version(4) | wrappedBlob(iv+cipher+hmac) */
            byte wrappedBuf[AES_BLOCK_SIZE + sizeof(FWTPM_Session) +
                WC_SHA256_DIGEST_SIZE];
            int wrappedSz = 0;
            rc = FwWrapContextBlob(ctx, (const byte*)sess,
                (int)sizeof(FWTPM_Session),
                wrappedBuf, (int)sizeof(wrappedBuf), &wrappedSz);
            if (rc == 0) {
                blobSz = 4 + 4 + (UINT16)wrappedSz;
                TPM2_Packet_AppendU16(rsp, blobSz);
                tmp32 = TPM2_Packet_SwapU32(FWTPM_CTX_MAGIC);
                TPM2_Packet_AppendBytes(rsp, (byte*)&tmp32, 4);
                tmp32 = TPM2_Packet_SwapU32(FWTPM_CTX_VER);
                TPM2_Packet_AppendBytes(rsp, (byte*)&tmp32, 4);
                TPM2_Packet_AppendBytes(rsp, wrappedBuf, wrappedSz);
            }
            TPM2_ForceZero(wrappedBuf, sizeof(wrappedBuf));
            /* Free the session slot only on success — preserve session
             * if wrapping failed so client can retry */
            if (rc == 0) {
                TPM2_ForceZero(sess, sizeof(FWTPM_Session));
            }
        }
        else {
            /* Object: opaque handle reference (object stays in slot).
             * Format: magic(4) | version(4) | handle(4) | pad(4) */
            byte objBlob[16];
            blobSz = sizeof(objBlob);
            tmp32 = TPM2_Packet_SwapU32(FWTPM_CTX_MAGIC);
            XMEMCPY(objBlob + 0, &tmp32, 4);
            tmp32 = TPM2_Packet_SwapU32(FWTPM_CTX_VER);
            XMEMCPY(objBlob + 4, &tmp32, 4);
            tmp32 = TPM2_Packet_SwapU32(saveHandle);
            XMEMCPY(objBlob + 8, &tmp32, 4);
            XMEMSET(objBlob + 12, 0, 4);
            TPM2_Packet_AppendU16(rsp, blobSz);
            TPM2_Packet_AppendBytes(rsp, objBlob, blobSz);
        }

        FwRspFinalize(rsp, TPM_ST_NO_SESSIONS, TPM_RC_SUCCESS);
    }

    return rc;
}

/* --- TPM2_ContextLoad (CC 0x0161) --- */
static TPM_RC FwCmd_ContextLoad(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    /* Parse TPMS_CONTEXT: sequence(8) | savedHandle(4) | hierarchy(4) | blob */
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 seqHi, seqLo, savedHandle, hierarchy;
    UINT16 blobSz = 0;
    UINT32 magic = 0, version = 0;

    (void)cmdTag;
    (void)seqHi; (void)seqLo; (void)hierarchy;

    if (cmdSize < TPM2_HEADER_SIZE + 18) {
        rc = TPM_RC_COMMAND_SIZE;
    }

    if (rc == 0) {
        TPM2_Packet_ParseU32(cmd, &seqHi);
        TPM2_Packet_ParseU32(cmd, &seqLo);
        TPM2_Packet_ParseU32(cmd, &savedHandle);
        TPM2_Packet_ParseU32(cmd, &hierarchy);
        TPM2_Packet_ParseU16(cmd, &blobSz);
    }

    /* Validate minimum blob size (magic + version = 8 bytes) */
    if (rc == 0 && blobSz < 8) {
        rc = TPM_RC_SIZE;
    }

    /* Parse magic and version from start of blob.
     * ContextSave writes these via AppendBytes of pre-swapped U32, so
     * ParseU32 (which swaps big-endian → host) gives host-order values. */
    if (rc == 0) {
        TPM2_Packet_ParseU32(cmd, &magic);
        TPM2_Packet_ParseU32(cmd, &version);
        if (magic != FWTPM_CTX_MAGIC || version != FWTPM_CTX_VER) {
            rc = TPM_RC_VALUE;
        }
    }

    if (rc == 0) {
        UINT16 dataLen = blobSz - 8; /* remaining after magic + version */

        if ((savedHandle & 0xFF000000) == HMAC_SESSION_FIRST ||
            (savedHandle & 0xFF000000) == POLICY_SESSION_FIRST) {
            /* Session context: verify integrity + decrypt, then restore.
             * Wrapped blob: iv(16) + ciphertext(sizeof(FWTPM_Session)) + hmac(32) */
            int expectedWrapSz = AES_BLOCK_SIZE +
                (int)sizeof(FWTPM_Session) + WC_SHA256_DIGEST_SIZE;
            FWTPM_Session restored;
            int restoredSz = 0;
            int si;
            int found = 0;

            if ((int)dataLen != expectedWrapSz) {
                rc = TPM_RC_SIZE;
            }
            if (rc == 0) {
                byte wrappedBuf[AES_BLOCK_SIZE + sizeof(FWTPM_Session) +
                    WC_SHA256_DIGEST_SIZE];
                TPM2_Packet_ParseBytes(cmd, wrappedBuf, (int)dataLen);
                rc = FwUnwrapContextBlob(ctx, wrappedBuf, (int)dataLen,
                    (byte*)&restored, (int)sizeof(restored), &restoredSz);
                TPM2_ForceZero(wrappedBuf, sizeof(wrappedBuf));
                if (rc != 0) {
                    /* HMAC mismatch or decrypt failure */
                    if (rc != TPM_RC_INTEGRITY)
                        rc = TPM_RC_INTEGRITY;
                }
            }
            /* Validate deserialized session fields */
            if (rc == 0) {
                if (restored.sessionType != TPM_SE_HMAC &&
                    restored.sessionType != TPM_SE_POLICY &&
                    restored.sessionType != TPM_SE_TRIAL) {
                    rc = TPM_RC_VALUE;
                }
                if (TPM2_GetHashDigestSize(restored.authHash) <= 0) {
                    rc = TPM_RC_VALUE;
                }
            }
            if (rc == 0) {
                /* Find a free session slot */
                for (si = 0; si < FWTPM_MAX_SESSIONS; si++) {
                    if (!ctx->sessions[si].used) {
                        found = 1;
                        break;
                    }
                }
                if (!found) {
                    rc = TPM_RC_SESSION_MEMORY;
                }
            }
            if (rc == 0) {
                XMEMCPY(&ctx->sessions[si], &restored,
                    sizeof(FWTPM_Session));
                /* Keep the original handle — cpHash includes session
                 * handle as entity name, so it must match what ESYS
                 * computed. FwFindSession searches by handle value. */
            }
            TPM2_ForceZero(&restored, sizeof(restored));
        }
        else if ((savedHandle & 0xFF000000) == TRANSIENT_FIRST) {
            /* Object context: verify object still in slot (opaque handle) */
            UINT32 origHandle = 0;
            if (dataLen >= 4) {
                TPM2_Packet_ParseU32(cmd, &origHandle);
            }
            if (FwFindObject(ctx, origHandle) == NULL) {
                rc = TPM_RC_HANDLE;
            }
            savedHandle = origHandle;
        }
        else {
            rc = TPM_RC_HANDLE;
        }
    }

    if (rc == 0) {
    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: ContextLoad(handle=0x%x)\n", savedHandle);
    #endif
        TPM2_Packet_AppendU32(rsp, savedHandle);
        FwRspFinalize(rsp, TPM_ST_NO_SESSIONS, TPM_RC_SUCCESS);
    }

    return rc;
}

/* --- TPM2_ReadPublic (CC 0x0173) --- */
static TPM_RC FwCmd_ReadPublic(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 objectHandle = 0;
    FWTPM_Object* obj = NULL;
    TPM2B_PUBLIC outPub;

    (void)cmdTag;

    if (cmdSize < TPM2_HEADER_SIZE + 4) {
        rc = TPM_RC_COMMAND_SIZE;
    }

    if (rc == 0) {
        TPM2_Packet_ParseU32(cmd, &objectHandle);

    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: ReadPublic(handle=0x%x)\n", objectHandle);
    #endif

        obj = FwFindObject(ctx, objectHandle);
        if (obj == NULL) {
            rc = TPM_RC_HANDLE;
        }
    }

    if (rc == 0) {
        /* outPublic */
        outPub.size = 0;
        XMEMCPY(&outPub.publicArea, &obj->pub, sizeof(TPMT_PUBLIC));
        TPM2_Packet_AppendPublic(rsp, &outPub);

        /* name */
        TPM2_Packet_AppendU16(rsp, obj->name.size);
        TPM2_Packet_AppendBytes(rsp, obj->name.name, obj->name.size);

        /* qualifiedName - same as name for primary keys */
        TPM2_Packet_AppendU16(rsp, obj->name.size);
        TPM2_Packet_AppendBytes(rsp, obj->name.name, obj->name.size);

        FwRspFinalize(rsp, TPM_ST_NO_SESSIONS, TPM_RC_SUCCESS);
    }

    return rc;
}

/* --- TPM2_Clear (CC 0x0126) --- */
static TPM_RC FwCmd_Clear(FWTPM_CTX* ctx, TPM2_Packet* cmd, int cmdSize,
    TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 authHandle = 0;
    int ci;

    if (cmdSize < TPM2_HEADER_SIZE + 4) {
        rc = TPM_RC_COMMAND_SIZE;
    }

    if (rc == 0) {
        TPM2_Packet_ParseU32(cmd, &authHandle);
        /* Only platform and lockout can clear */
        if (authHandle != TPM_RH_PLATFORM && authHandle != TPM_RH_LOCKOUT) {
            rc = TPM_RC_HIERARCHY;
        }
    }

    /* Skip auth area */
    if (rc == 0 && cmdTag == TPM_ST_SESSIONS) {
        rc = FwSkipAuthArea(cmd, cmdSize);
    }

    /* Check if Clear is disabled by ClearControl (TPM 2.0 spec Section 24.6) */
    if (rc == 0 && ctx->disableClear) {
        rc = TPM_RC_DISABLED;
    }

    if (rc == 0) {
    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: Clear(authHandle=0x%x)\n", authHandle);
    #endif

        /* Defer object flush until after response auth is computed.
         * Sessions must remain valid for response HMAC generation.
         * Per TPM spec, Clear flushes transient objects but not sessions. */
        ctx->pendingClear = 1;

        /* Reset owner and endorsement auth */
        XMEMSET(&ctx->ownerAuth, 0, sizeof(ctx->ownerAuth));
        XMEMSET(&ctx->endorsementAuth, 0, sizeof(ctx->endorsementAuth));

        /* Generate new owner and endorsement seeds */
        rc = wc_RNG_GenerateBlock(&ctx->rng, ctx->ownerSeed, FWTPM_SEED_SIZE);
        if (rc == 0)
            rc = wc_RNG_GenerateBlock(&ctx->rng, ctx->endorsementSeed,
                FWTPM_SEED_SIZE);
        if (rc != 0) rc = TPM_RC_FAILURE;

        /* Only commit state changes if seed generation succeeded —
         * avoid partial mutation on RNG failure */
        if (rc == 0) {
            /* Flush primary cache — stale entries from old seeds would
             * produce wrong keys now that CreatePrimary derives from the
             * seed via KDFa */
            for (ci = 0; ci < FWTPM_MAX_PRIMARY_CACHE; ci++) {
                if (ctx->primaryCache[ci].used &&
                    (ctx->primaryCache[ci].hierarchy == TPM_RH_OWNER ||
                     ctx->primaryCache[ci].hierarchy == TPM_RH_ENDORSEMENT)) {
                    XMEMSET(&ctx->primaryCache[ci], 0,
                        sizeof(ctx->primaryCache[ci]));
                }
            }

            /* Reset PCRs */
            XMEMSET(ctx->pcrDigest, 0, sizeof(ctx->pcrDigest));
            ctx->pcrUpdateCounter = 0;

            /* Reset owner and endorsement hierarchy policies
             * (not platform/lockout) */
            XMEMSET(&ctx->ownerPolicy, 0, sizeof(ctx->ownerPolicy));
            ctx->ownerPolicyAlg = TPM_ALG_NULL;
            XMEMSET(&ctx->endorsementPolicy, 0, sizeof(ctx->endorsementPolicy));
            ctx->endorsementPolicyAlg = TPM_ALG_NULL;

            /* Reset disableClear per spec */
            ctx->disableClear = 0;

            FwRspNoParams(rsp, cmdTag);
        }
        else {
            /* RNG failure: undo pendingClear so state is not corrupted */
            ctx->pendingClear = 0;
        }
    }

    return rc;
}

/* --- TPM2_ChangeEPS (CC 0x0124) --- */
/* Replace endorsement primary seed. Auth: platform only.
 * Per TPM 2.0 Part 3 Section 24.5. */
static TPM_RC FwCmd_ChangeEPS(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 authHandle = 0;
    int i;

    if (cmdSize < TPM2_HEADER_SIZE + 4) {
        rc = TPM_RC_COMMAND_SIZE;
    }

    if (rc == 0) {
        TPM2_Packet_ParseU32(cmd, &authHandle);
        if (authHandle != TPM_RH_PLATFORM) {
            rc = TPM_RC_HIERARCHY;
        }
    }

    if (rc == 0 && cmdTag == TPM_ST_SESSIONS) {
        rc = FwSkipAuthArea(cmd, cmdSize);
    }

    if (rc == 0) {
    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: ChangeEPS\n");
    #endif

        /* Generate new endorsement seed */
        rc = wc_RNG_GenerateBlock(&ctx->rng, ctx->endorsementSeed,
            FWTPM_SEED_SIZE);
        if (rc != 0) rc = TPM_RC_FAILURE;

        /* Only commit state changes if seed generation succeeded */
        if (rc == 0) {
            /* Reset endorsement auth and policy */
            XMEMSET(&ctx->endorsementAuth, 0, sizeof(ctx->endorsementAuth));
            XMEMSET(&ctx->endorsementPolicy, 0,
                sizeof(ctx->endorsementPolicy));
            ctx->endorsementPolicyAlg = TPM_ALG_NULL;

            /* Clear endorsement primary cache entries */
            for (i = 0; i < FWTPM_MAX_PRIMARY_CACHE; i++) {
                if (ctx->primaryCache[i].used &&
                    ctx->primaryCache[i].hierarchy == TPM_RH_ENDORSEMENT) {
                    XMEMSET(&ctx->primaryCache[i], 0,
                        sizeof(ctx->primaryCache[i]));
                }
            }

            /* Defer object flush until after response auth */
            ctx->pendingClear = 1;

            FwRspNoParams(rsp, cmdTag);
        }
    }

    return rc;
}

/* --- TPM2_ChangePPS (CC 0x0125) --- */
/* Replace platform primary seed. Auth: platform only.
 * Per TPM 2.0 Part 3 Section 24.4. */
static TPM_RC FwCmd_ChangePPS(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 authHandle = 0;
    int i;

    if (cmdSize < TPM2_HEADER_SIZE + 4) {
        rc = TPM_RC_COMMAND_SIZE;
    }

    if (rc == 0) {
        TPM2_Packet_ParseU32(cmd, &authHandle);
        if (authHandle != TPM_RH_PLATFORM) {
            rc = TPM_RC_HIERARCHY;
        }
    }

    if (rc == 0 && cmdTag == TPM_ST_SESSIONS) {
        rc = FwSkipAuthArea(cmd, cmdSize);
    }

    if (rc == 0) {
    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: ChangePPS\n");
    #endif

        /* Generate new platform seed */
        rc = wc_RNG_GenerateBlock(&ctx->rng, ctx->platformSeed,
            FWTPM_SEED_SIZE);
        if (rc != 0) rc = TPM_RC_FAILURE;

        /* Only commit state changes if seed generation succeeded */
        if (rc == 0) {
            /* Clear platform primary cache entries */
            for (i = 0; i < FWTPM_MAX_PRIMARY_CACHE; i++) {
                if (ctx->primaryCache[i].used &&
                    ctx->primaryCache[i].hierarchy == TPM_RH_PLATFORM) {
                    XMEMSET(&ctx->primaryCache[i], 0,
                        sizeof(ctx->primaryCache[i]));
                }
            }

            /* Defer object flush until after response auth */
            ctx->pendingClear = 1;

            FwRspNoParams(rsp, cmdTag);
        }
    }

    return rc;
}

/* --- TPM2_ClearControl (CC 0x0127) --- */
/* Set or clear the disableClear flag. Only TPM_RH_PLATFORM can set
 * disable=YES. Both platform and lockout can set disable=NO. */
static TPM_RC FwCmd_ClearControl(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 authHandle = 0;
    UINT8 disable = 0;

    (void)cmdSize;

    TPM2_Packet_ParseU32(cmd, &authHandle);
    if (cmdTag == TPM_ST_SESSIONS)
        rc = FwSkipAuthArea(cmd, cmdSize);

    if (rc == 0) {
        TPM2_Packet_ParseU8(cmd, &disable);
    }

    if (rc == 0 && authHandle != TPM_RH_PLATFORM &&
        authHandle != TPM_RH_LOCKOUT) {
        rc = TPM_RC_HIERARCHY;
    }

    /* Only platform can SET disable (disable=YES=1) */
    if (rc == 0 && disable == 1 && authHandle != TPM_RH_PLATFORM) {
        rc = TPM_RC_AUTH_TYPE;
    }

    if (rc == 0) {
    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: ClearControl(auth=0x%x, disable=%d)\n",
            authHandle, disable);
    #endif
        ctx->disableClear = (int)disable;
        FWTPM_NV_SaveFlags(ctx);
        FwRspNoParams(rsp, cmdTag);
    }

    return rc;
}

/* --- TPM2_HierarchyControl (CC 0x0121) --- */
/* Enable or disable a hierarchy. For fwTPM, validates params and returns
 * success (hierarchies are always enabled in this implementation). */
static TPM_RC FwCmd_HierarchyControl(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 authHandle = 0;
    UINT32 enable = 0;
    UINT8 state = 0;

    (void)cmdSize;

    TPM2_Packet_ParseU32(cmd, &authHandle);
    if (cmdTag == TPM_ST_SESSIONS) rc = FwSkipAuthArea(cmd, cmdSize);

    TPM2_Packet_ParseU32(cmd, &enable);
    TPM2_Packet_ParseU8(cmd, &state);

#ifdef DEBUG_WOLFTPM
    printf("fwTPM: HierarchyControl(auth=0x%x, enable=0x%x, state=%d)\n",
        authHandle, enable, state);
#endif

    /* Only platform hierarchy can control other hierarchies */
    if (authHandle != TPM_RH_PLATFORM) {
        rc = TPM_RC_AUTH_TYPE;
    }

    /* Validate enable handle */
    if (rc == 0 && enable != TPM_RH_OWNER &&
        enable != TPM_RH_ENDORSEMENT &&
        enable != TPM_RH_PLATFORM &&
        enable != TPM_RH_PLATFORM_NV) {
        rc = TPM_RC_VALUE;
    }

    if (rc == 0) {
        /* fwTPM does not actually disable hierarchies; just accept */
        (void)state;
        (void)ctx;

        FwRspNoParams(rsp, cmdTag);
    }

    return rc;
}

/* --- TPM2_HierarchyChangeAuth (CC 0x0129) --- */
/* Change the auth value for a hierarchy. */
static TPM_RC FwCmd_HierarchyChangeAuth(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 authHandle = 0;
    UINT16 newAuthSize = 0;
    byte newAuthBuf[TPM_MAX_DIGEST_SIZE];

    (void)cmdSize;

    TPM2_Packet_ParseU32(cmd, &authHandle);
    if (cmdTag == TPM_ST_SESSIONS) rc = FwSkipAuthArea(cmd, cmdSize);

    /* Parse newAuth (TPM2B_AUTH) */
    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &newAuthSize);
        if (newAuthSize > (UINT16)sizeof(newAuthBuf)) {
            rc = TPM_RC_SIZE;
        }
        else if (newAuthSize > 0 && cmd->pos + newAuthSize > cmdSize) {
            rc = TPM_RC_COMMAND_SIZE;
        }
    }
    if (rc == 0 && newAuthSize > 0) {
        TPM2_Packet_ParseBytes(cmd, newAuthBuf, newAuthSize);
    }

#ifdef DEBUG_WOLFTPM
    printf("fwTPM: HierarchyChangeAuth(auth=0x%x, newAuthSz=%d)\n",
        authHandle, newAuthSize);
#endif

    if (rc == 0) {
        switch (authHandle) {
            case TPM_RH_OWNER:
                TPM2_ForceZero(ctx->ownerAuth.buffer,
                    sizeof(ctx->ownerAuth.buffer));
                ctx->ownerAuth.size = newAuthSize;
                if (newAuthSize > 0) {
                    XMEMCPY(ctx->ownerAuth.buffer, newAuthBuf, newAuthSize);
                }
                break;
            case TPM_RH_ENDORSEMENT:
                TPM2_ForceZero(ctx->endorsementAuth.buffer,
                    sizeof(ctx->endorsementAuth.buffer));
                ctx->endorsementAuth.size = newAuthSize;
                if (newAuthSize > 0) {
                    XMEMCPY(ctx->endorsementAuth.buffer, newAuthBuf,
                        newAuthSize);
                }
                break;
            case TPM_RH_PLATFORM:
                TPM2_ForceZero(ctx->platformAuth.buffer,
                    sizeof(ctx->platformAuth.buffer));
                ctx->platformAuth.size = newAuthSize;
                if (newAuthSize > 0) {
                    XMEMCPY(ctx->platformAuth.buffer, newAuthBuf, newAuthSize);
                }
                break;
            case TPM_RH_LOCKOUT:
                TPM2_ForceZero(ctx->lockoutAuth.buffer,
                    sizeof(ctx->lockoutAuth.buffer));
                ctx->lockoutAuth.size = newAuthSize;
                if (newAuthSize > 0) {
                    XMEMCPY(ctx->lockoutAuth.buffer, newAuthBuf, newAuthSize);
                }
                break;
            default:
                rc = TPM_RC_HIERARCHY;
                break;
        }
    }

    if (rc == 0) {
        FWTPM_NV_SaveAuth(ctx, authHandle);
        FwRspNoParams(rsp, cmdTag);
    }

    TPM2_ForceZero(newAuthBuf, sizeof(newAuthBuf));
    return rc;
}

/* --- TPM2_SetPrimaryPolicy (CC 0x012E) --- */
/* Set the authorization policy for a hierarchy. */
static TPM_RC FwCmd_SetPrimaryPolicy(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 authHandle = 0;
    UINT16 policySz = 0;
    byte policyBuf[TPM_MAX_DIGEST_SIZE];
    UINT16 hashAlg = TPM_ALG_NULL;

    (void)cmdSize;

    TPM2_Packet_ParseU32(cmd, &authHandle);
    if (cmdTag == TPM_ST_SESSIONS)
        rc = FwSkipAuthArea(cmd, cmdSize);

    /* Parse authPolicy (TPM2B_DIGEST) */
    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &policySz);
        if (policySz > sizeof(policyBuf))
            rc = TPM_RC_SIZE;
    }
    if (rc == 0 && policySz > 0) {
        TPM2_Packet_ParseBytes(cmd, policyBuf, policySz);
    }

    /* Parse hashAlg */
    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &hashAlg);
        if (policySz > 0 && TPM2_GetHashDigestSize(hashAlg) <= 0) {
            rc = TPM_RC_HASH;
        }
        if (policySz == 0) {
            hashAlg = TPM_ALG_NULL;
        }
    }

    if (rc == 0) {
        TPM2B_DIGEST* policy = NULL;
        TPMI_ALG_HASH* policyAlg = NULL;

    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: SetPrimaryPolicy(auth=0x%x, policySz=%d, alg=0x%x)\n",
            authHandle, policySz, hashAlg);
    #endif

        switch (authHandle) {
            case TPM_RH_OWNER:
                policy = &ctx->ownerPolicy;
                policyAlg = &ctx->ownerPolicyAlg;
                break;
            case TPM_RH_ENDORSEMENT:
                policy = &ctx->endorsementPolicy;
                policyAlg = &ctx->endorsementPolicyAlg;
                break;
            case TPM_RH_PLATFORM:
                policy = &ctx->platformPolicy;
                policyAlg = &ctx->platformPolicyAlg;
                break;
            case TPM_RH_LOCKOUT:
                policy = &ctx->lockoutPolicy;
                policyAlg = &ctx->lockoutPolicyAlg;
                break;
            default:
                rc = TPM_RC_HIERARCHY;
                break;
        }
        if (rc == 0 && policy != NULL) {
            policy->size = policySz;
            if (policySz > 0) {
                XMEMCPY(policy->buffer, policyBuf, policySz);
            }
            *policyAlg = hashAlg;
            FWTPM_NV_SaveHierarchyPolicy(ctx, authHandle);
            FwRspNoParams(rsp, cmdTag);
        }
    }

    return rc;
}

/* --- TPM2_EvictControl (CC 0x0120) --- */
static TPM_RC FwCmd_EvictControl(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 authHandle = 0;
    UINT32 objectHandle = 0;
    UINT32 persistentHandle = 0;
    FWTPM_Object* obj = NULL;
    int i;
    int found = 0;

    if (cmdSize < TPM2_HEADER_SIZE + 8) {
        rc = TPM_RC_COMMAND_SIZE;
    }

    /* Parse handles */
    if (rc == 0) {
        TPM2_Packet_ParseU32(cmd, &authHandle);
        TPM2_Packet_ParseU32(cmd, &objectHandle);
    }

    /* Skip auth area */
    if (rc == 0 && cmdTag == TPM_ST_SESSIONS) {
        rc = FwSkipAuthArea(cmd, cmdSize);
    }

    /* Parse persistent handle */
    if (rc == 0) {
        TPM2_Packet_ParseU32(cmd, &persistentHandle);
    }

    /* Validate auth handle: owner or platform required by spec,
     * endorsement also accepted for EH-created objects */
    if (rc == 0 && authHandle != TPM_RH_OWNER &&
        authHandle != TPM_RH_PLATFORM &&
        authHandle != TPM_RH_ENDORSEMENT) {
        rc = TPM_RC_HIERARCHY;
    }

#ifdef DEBUG_WOLFTPM
    if (rc == 0) {
        printf("fwTPM: EvictControl(auth=0x%x, obj=0x%x, persist=0x%x)\n",
            authHandle, objectHandle, persistentHandle);
    }
#endif

    /* If objectHandle is persistent and matches persistentHandle -> evict */
    if (rc == 0 && (objectHandle & 0xFF000000) == 0x81000000 &&
        objectHandle == persistentHandle) {
        /* Find and remove the persistent object */
        found = 0;
        for (i = 0; i < FWTPM_MAX_PERSISTENT; i++) {
            if (ctx->persistent[i].used &&
                ctx->persistent[i].handle == persistentHandle) {
                TPM2_ForceZero(&ctx->persistent[i], sizeof(FWTPM_Object));
                found = 1;
                break;
            }
        }
        if (!found) {
            rc = TPM_RC_HANDLE;
        }
    }
    /* objectHandle is transient -> make persistent */
    else if (rc == 0) {
        obj = FwFindObject(ctx, objectHandle);
        if (obj == NULL) {
            rc = TPM_RC_HANDLE;
        }

        /* Check if persistent handle already in use */
        if (rc == 0) {
            for (i = 0; i < FWTPM_MAX_PERSISTENT; i++) {
                if (ctx->persistent[i].used &&
                    ctx->persistent[i].handle == persistentHandle) {
                    rc = TPM_RC_NV_DEFINED;
                    break;
                }
            }
        }

        /* Find free persistent slot */
        if (rc == 0) {
            found = 0;
            for (i = 0; i < FWTPM_MAX_PERSISTENT; i++) {
                if (!ctx->persistent[i].used) {
                    XMEMCPY(&ctx->persistent[i], obj, sizeof(FWTPM_Object));
                    ctx->persistent[i].handle = persistentHandle;
                    found = 1;
                    break;
                }
            }
            if (!found) {
                rc = TPM_RC_NV_SPACE;
            }
        }
    }

    if (rc == 0) {
        if ((objectHandle & 0xFF000000) == 0x81000000 &&
            objectHandle == persistentHandle) {
            /* Was evict: delete from journal */
            FWTPM_NV_DeletePersistent(ctx, persistentHandle);
        }
        else {
            /* Was make-persistent: save to journal */
            FWTPM_NV_SavePersistent(ctx, i);
        }
        FwRspNoParams(rsp, cmdTag);
    }

    return rc;
}

/* ================================================================== */
/* Create, Load, Sign, Verify, RSA Encrypt/Decrypt                     */
/* ================================================================== */

/* --- TPM2_Create (CC 0x0153) --- */
static TPM_RC FwCmd_Create(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 parentHandle = 0;
    TPM2B_AUTH userAuth;
    FWTPM_DECLARE_BUF(sensData, FWTPM_MAX_DATA_BUF);
    UINT16 sensDataSize = 0;
    FWTPM_DECLARE_VAR(inPublic, TPM2B_PUBLIC);
    UINT16 outsideInfoSize = 0;
    UINT32 creationPcrCount = 0;
    FWTPM_Object* parent = NULL;
    FWTPM_DECLARE_VAR(outPrivate, TPM2B_PRIVATE);
    FWTPM_DECLARE_BUF(privKeyDer, FWTPM_MAX_PRIVKEY_DER);
    int privKeyDerSz = 0;
    int paramSzPos = 0, paramStart = 0;
    FWTPM_DECLARE_VAR(outPub, TPM2B_PUBLIC);
    int cdMarkPos = 0;
    int cdStart2;
    UINT32 s;
    UINT8 selectSize = 0;

    FWTPM_ALLOC_BUF(privKeyDer, FWTPM_MAX_PRIVKEY_DER);
    FWTPM_CALLOC_BUF(sensData, FWTPM_MAX_DATA_BUF);
    FWTPM_CALLOC_VAR(inPublic, TPM2B_PUBLIC);
    FWTPM_CALLOC_VAR(outPrivate, TPM2B_PRIVATE);
    FWTPM_CALLOC_VAR(outPub, TPM2B_PUBLIC);

    /* Zero stack-resident locals (heap-allocated TPM2B vars are pre-zeroed
     * via FWTPM_CALLOC_VAR/BUF above). */
    XMEMSET(&userAuth, 0, sizeof(userAuth));

    if (cmdSize < TPM2_HEADER_SIZE + 4) {
        rc = TPM_RC_COMMAND_SIZE;
    }

    /* Parse parent handle */
    if (rc == 0) {
        TPM2_Packet_ParseU32(cmd, &parentHandle);

        /* Find parent object */
        parent = FwFindObject(ctx, parentHandle);
        if (parent == NULL) {
            rc = TPM_RC_HANDLE;
        }
    }

    /* Skip auth area */
    if (rc == 0 && cmdTag == TPM_ST_SESSIONS) {
        rc = FwSkipAuthArea(cmd, cmdSize);
    }

    /* Parse inSensitive (TPM2B_SENSITIVE_CREATE) — capture data */
    if (rc == 0) {
        rc = TPM2_Packet_ParseSensitiveCreate(cmd, cmdSize, &userAuth,
            sensData, (int)FWTPM_SIZEOF_BUF(sensData, FWTPM_MAX_DATA_BUF),
            &sensDataSize);
    }

    /* Parse inPublic */
    if (rc == 0) {
        TPM2_Packet_ParsePublic(cmd, inPublic);
    }

    /* Skip outsideInfo */
    if (rc == 0) {
        if (cmd->pos + 2 > cmdSize) {
            rc = TPM_RC_COMMAND_SIZE;
        }
    }
    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &outsideInfoSize);
        if (cmd->pos + outsideInfoSize > cmdSize) {
            rc = TPM_RC_COMMAND_SIZE;
        }
        else {
            cmd->pos += outsideInfoSize;
        }
    }

    /* Parse creationPCR (TPML_PCR_SELECTION) - skip */
    if (rc == 0) {
        if (cmd->pos + 4 > cmdSize) {
            rc = TPM_RC_COMMAND_SIZE;
        }
    }
    if (rc == 0) {
        TPM2_Packet_ParseU32(cmd, &creationPcrCount);
        for (s = 0; s < creationPcrCount && rc == 0; s++) {
            if (cmd->pos + 3 > cmdSize) {
                rc = TPM_RC_COMMAND_SIZE;
                break;
            }
            cmd->pos += 2; /* hashAlg */
            TPM2_Packet_ParseU8(cmd, &selectSize);
            if (cmd->pos + selectSize > cmdSize) {
                rc = TPM_RC_COMMAND_SIZE;
                break;
            }
            cmd->pos += selectSize;
        }
    }

#ifdef DEBUG_WOLFTPM
    if (rc == 0) {
        printf("fwTPM: Create(parent=0x%x, type=%d)\n",
            parentHandle, inPublic->publicArea.type);
    }
#endif

    /* Generate key */
    if (rc == 0) {
        switch (inPublic->publicArea.type) {
#ifndef NO_RSA
            case TPM_ALG_RSA: {
            #ifdef WOLFSSL_KEY_GEN
                rc = FwGenerateRsaKey(&ctx->rng,
                    inPublic->publicArea.parameters.rsaDetail.keyBits,
                    inPublic->publicArea.parameters.rsaDetail.exponent,
                    &inPublic->publicArea.unique.rsa,
                    privKeyDer, FWTPM_MAX_PRIVKEY_DER, &privKeyDerSz);
            #else
                rc = TPM_RC_COMMAND_CODE;
            #endif /* WOLFSSL_KEY_GEN */
                break;
            }
#endif /* !NO_RSA */
#ifdef HAVE_ECC
            case TPM_ALG_ECC: {
                rc = FwGenerateEccKey(&ctx->rng,
                    inPublic->publicArea.parameters.eccDetail.curveID,
                    &inPublic->publicArea.unique.ecc,
                    privKeyDer, FWTPM_MAX_PRIVKEY_DER, &privKeyDerSz);
                break;
            }
#endif /* HAVE_ECC */
            case TPM_ALG_KEYEDHASH: {
                /* HMAC key or data object.
                 * If caller supplied sensitive.data, use it as the key
                 * material; otherwise generate random bytes. */
                TPMI_ALG_HASH hashAlg = TPM_ALG_SHA256;
                TPMI_ALG_KEYEDHASH_SCHEME scheme =
                    inPublic->publicArea.parameters.keyedHashDetail
                        .scheme.scheme;
                int keySz = 0;

                if (scheme == TPM_ALG_HMAC) {
                    hashAlg =
                        inPublic->publicArea.parameters.keyedHashDetail
                            .scheme.details.hmac.hashAlg;
                    keySz = TPM2_GetHashDigestSize(hashAlg);
                    if (keySz <= 0) {
                        rc = TPM_RC_HASH;
                    }
                }
                else {
                    /* XOR or NULL scheme -- use nameAlg digest size */
                    keySz = TPM2_GetHashDigestSize(
                        inPublic->publicArea.nameAlg);
                    if (keySz <= 0)
                        keySz = TPM_SHA256_DIGEST_SIZE;
                }

                if (rc == 0 && sensDataSize > 0) {
                    /* Use caller-supplied key material */
                    if (sensDataSize > (UINT16)FWTPM_MAX_DATA_BUF) {
                        rc = TPM_RC_SIZE;
                    }
                    if (rc == 0) {
                        XMEMCPY(privKeyDer, sensData, sensDataSize);
                        privKeyDerSz = (int)sensDataSize;
                    }
                }
                else if (rc == 0) {
                    rc = wc_RNG_GenerateBlock(&ctx->rng, privKeyDer,
                        (word32)keySz);
                    if (rc != 0) {
                        rc = TPM_RC_FAILURE;
                    }
                    if (rc == 0) {
                        privKeyDerSz = keySz;
                    }
                }

                /* unique = H(key bytes) */
                if (rc == 0) {
                    inPublic->publicArea.unique.keyedHash.size = (UINT16)
                        FwComputeUniqueHash(inPublic->publicArea.nameAlg,
                            privKeyDer, keySz,
                            inPublic->publicArea.unique.keyedHash.buffer);
                }
                break;
            }
            case TPM_ALG_SYMCIPHER: {
                /* AES symmetric key */
                int keyBits = (int)inPublic->publicArea.parameters
                    .symDetail.sym.keyBits.sym;
                int keySz = keyBits / 8;

                if (keySz <= 0 || keySz > 32) {
                    rc = TPM_RC_KEY_SIZE;
                }

                if (rc == 0) {
                    rc = wc_RNG_GenerateBlock(&ctx->rng, privKeyDer,
                        (word32)keySz);
                    if (rc != 0) {
                        rc = TPM_RC_FAILURE;
                    }
                }
                if (rc == 0) {
                    privKeyDerSz = keySz;

                    /* unique = H(key bytes) */
                    inPublic->publicArea.unique.sym.size = (UINT16)
                        FwComputeUniqueHash(inPublic->publicArea.nameAlg,
                            privKeyDer, keySz,
                            inPublic->publicArea.unique.sym.buffer);
                }
                break;
            }
            default:
                rc = TPM_RC_TYPE;
                break;
        }
    }

    /* Wrap private key into TPM2B_PRIVATE */
    if (rc == 0) {
        XMEMSET(outPrivate, 0, sizeof(*outPrivate));
        rc = FwWrapPrivate(parent, inPublic->publicArea.type, &userAuth,
            privKeyDer, privKeyDerSz, outPrivate);
    }

    /* --- Build response (no handle for Create) --- */
    if (rc == 0) {
        byte objName[2 + TPM_MAX_DIGEST_SIZE];
        int objNameSz = 0;
        int nameDigSz;
        FWTPM_DECLARE_BUF(pubBuf2, FWTPM_MAX_PUB_BUF);
        TPM2_Packet tmpPkt2;

        paramStart = FwRspParamsBegin(rsp, cmdTag, &paramSzPos);

        /* outPrivate (TPM2B_PRIVATE) */
        TPM2_Packet_AppendU16(rsp, outPrivate->size);
        TPM2_Packet_AppendBytes(rsp, outPrivate->buffer, outPrivate->size);

        /* outPublic (TPM2B_PUBLIC) */
        outPub->size = 0;
        XMEMCPY(&outPub->publicArea, &inPublic->publicArea,
            sizeof(TPMT_PUBLIC));
        TPM2_Packet_AppendPublic(rsp, outPub);

        /* creationData (TPM2B_CREATION_DATA) */
        TPM2_Packet_MarkU16(rsp, &cdMarkPos);
        cdStart2 = rsp->pos;
        TPM2_Packet_AppendU32(rsp, 0); /* pcrSelect count = 0 */
        TPM2_Packet_AppendU16(rsp, 0); /* pcrDigest size = 0 */
        TPM2_Packet_AppendU8(rsp, 0);  /* locality */
        TPM2_Packet_AppendU16(rsp, inPublic->publicArea.nameAlg);
        TPM2_Packet_AppendU16(rsp, 4); /* parentName */
        TPM2_Packet_AppendU32(rsp, parentHandle);
        TPM2_Packet_AppendU16(rsp, 4); /* parentQualifiedName */
        TPM2_Packet_AppendU32(rsp, parentHandle);
        TPM2_Packet_AppendU16(rsp, 0); /* outsideInfo */
        TPM2_Packet_PlaceU16(rsp, cdMarkPos);

        /* Compute object name from public area for creation ticket */
        nameDigSz = TPM2_GetHashDigestSize(inPublic->publicArea.nameAlg);
        FWTPM_ALLOC_BUF(pubBuf2, FWTPM_MAX_PUB_BUF);
        tmpPkt2.buf = pubBuf2;
        tmpPkt2.pos = 0;
        tmpPkt2.size = (int)FWTPM_MAX_PUB_BUF;
        TPM2_Packet_AppendPublicArea(&tmpPkt2, &inPublic->publicArea);
        FwStoreU16BE(objName, inPublic->publicArea.nameAlg);
        if (nameDigSz > 0) {
            int hashRc = wc_Hash(FwGetWcHashType(inPublic->publicArea.nameAlg),
                pubBuf2, tmpPkt2.pos, objName + 2, nameDigSz);
            if (hashRc == 0)
                objNameSz = 2 + nameDigSz;
        }
        FWTPM_FREE_BUF(pubBuf2);

        FwAppendCreationHashAndTicket(ctx, rsp, TPM_RH_OWNER,
            inPublic->publicArea.nameAlg, cdStart2, rsp->pos - cdStart2,
            objName, objNameSz);

        FwRspParamsEnd(rsp, cmdTag, paramSzPos, paramStart);
    }

    TPM2_ForceZero(&userAuth, sizeof(userAuth));
    TPM2_ForceZero(sensData, FWTPM_SIZEOF_BUF(sensData, FWTPM_MAX_DATA_BUF));
    FWTPM_FREE_BUF(sensData);
    /* outPrivate carries an HMAC-protected blob; XFREE alone is sufficient. */
    TPM2_ForceZero(privKeyDer, FWTPM_MAX_PRIVKEY_DER);
    FWTPM_FREE_BUF(privKeyDer);
    FWTPM_FREE_VAR(inPublic);
    FWTPM_FREE_VAR(outPrivate);
    FWTPM_FREE_VAR(outPub);
    return rc;
}

/* --- TPM2_ObjectChangeAuth (CC 0x0150) ---
 * Changes auth of a loaded object. Re-wraps private and returns new outPrivate.
 * Input:  objectHandle + parentHandle + [auth area] + newAuth(2+N)
 * Output: [paramSz] + outPrivate(2+N) */
static TPM_RC FwCmd_ObjectChangeAuth(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 objectHandle = 0, parentHandle = 0;
    TPM2B_AUTH newAuth;
    FWTPM_Object* obj = NULL;
    FWTPM_Object* parent = NULL;
    TPM2B_PRIVATE outPrivate;
    int paramSzPos = 0, paramStart = 0;

    XMEMSET(&newAuth, 0, sizeof(newAuth));
    XMEMSET(&outPrivate, 0, sizeof(outPrivate));

    if (cmdSize < TPM2_HEADER_SIZE + 8) {
        rc = TPM_RC_COMMAND_SIZE;
    }

    if (rc == 0) {
        TPM2_Packet_ParseU32(cmd, &objectHandle);
        TPM2_Packet_ParseU32(cmd, &parentHandle);

        obj = FwFindObject(ctx, objectHandle);
        if (obj == NULL) {
            rc = TPM_RC_HANDLE;
        }
    }

    if (rc == 0) {
        parent = FwFindObject(ctx, parentHandle);
        if (parent == NULL) {
            rc = TPM_RC_HANDLE;
        }
    }

    /* Skip auth area */
    if (rc == 0 && cmdTag == TPM_ST_SESSIONS) {
        rc = FwSkipAuthArea(cmd, cmdSize);
    }

    /* Parse newAuth */
    if (rc == 0) {
        if (cmd->pos + 2 > cmdSize) {
            rc = TPM_RC_COMMAND_SIZE;
        }
    }
    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &newAuth.size);
        if (newAuth.size > sizeof(newAuth.buffer)) {
            rc = TPM_RC_SIZE;
        }
    }
    if (rc == 0 && newAuth.size > 0) {
        if (cmd->pos + newAuth.size > cmdSize) {
            rc = TPM_RC_COMMAND_SIZE;
        }
        if (rc == 0) {
            TPM2_Packet_ParseBytes(cmd, newAuth.buffer, newAuth.size);
        }
    }

    /* Update auth on live object */
    if (rc == 0) {
        XMEMCPY(&obj->authValue, &newAuth, sizeof(newAuth));
    }

    /* Re-wrap private key with new auth */
    if (rc == 0) {
        rc = FwWrapPrivate(parent, obj->pub.type, &newAuth,
            obj->privKey, obj->privKeySize, &outPrivate);
        if (rc != 0) {
            rc = TPM_RC_FAILURE;
        }
    }

#ifdef DEBUG_WOLFTPM
    if (rc == 0) {
        printf("fwTPM: ObjectChangeAuth(obj=0x%x, parent=0x%x)\n",
            objectHandle, parentHandle);
    }
#endif

    /* Response */
    if (rc == 0) {
        paramStart = FwRspParamsBegin(rsp, cmdTag, &paramSzPos);
        TPM2_Packet_AppendU16(rsp, outPrivate.size);
        TPM2_Packet_AppendBytes(rsp, outPrivate.buffer, outPrivate.size);
        FwRspParamsEnd(rsp, cmdTag, paramSzPos, paramStart);
    }

    TPM2_ForceZero(&newAuth, sizeof(newAuth));
    TPM2_ForceZero(&outPrivate, sizeof(outPrivate));

    return rc;
}

/* --- TPM2_Load (CC 0x0157) --- */
static TPM_RC FwCmd_Load(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 parentHandle = 0;
    TPM2B_PRIVATE inPrivate;
    TPM2B_PUBLIC inPublic;
    FWTPM_Object* parent = NULL;
    FWTPM_Object* obj = NULL;
    TPM_HANDLE objHandle = 0;
    UINT16 sensitiveType = 0;
    int paramSzPos = 0, paramStart = 0;

    if (cmdSize < TPM2_HEADER_SIZE + 4) {
        rc = TPM_RC_COMMAND_SIZE;
    }

    /* Parse parent handle */
    if (rc == 0) {
        TPM2_Packet_ParseU32(cmd, &parentHandle);
        parent = FwFindObject(ctx, parentHandle);
        if (parent == NULL) {
            rc = TPM_RC_HANDLE;
        }
    }

    /* Skip auth area */
    if (rc == 0 && cmdTag == TPM_ST_SESSIONS) {
        rc = FwSkipAuthArea(cmd, cmdSize);
    }

    /* Parse inPrivate (TPM2B_PRIVATE) */
    if (rc == 0) {
        XMEMSET(&inPrivate, 0, sizeof(inPrivate));
        if (cmd->pos + 2 > cmdSize) {
            rc = TPM_RC_COMMAND_SIZE;
        }
    }
    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &inPrivate.size);
        if (inPrivate.size > sizeof(inPrivate.buffer)) {
            rc = TPM_RC_SIZE;
        }
    }
    if (rc == 0) {
        if (cmd->pos + inPrivate.size > cmdSize) {
            rc = TPM_RC_COMMAND_SIZE;
        }
    }
    if (rc == 0) {
        TPM2_Packet_ParseBytes(cmd, inPrivate.buffer, inPrivate.size);
    }

    /* Parse inPublic (TPM2B_PUBLIC) */
    if (rc == 0) {
        XMEMSET(&inPublic, 0, sizeof(inPublic));
        TPM2_Packet_ParsePublic(cmd, &inPublic);
    }

#ifdef DEBUG_WOLFTPM
    if (rc == 0) {
        printf("fwTPM: Load(parent=0x%x, type=%d, privSz=%d)\n",
            parentHandle, inPublic.publicArea.type, inPrivate.size);
    }
#endif

    /* Allocate object slot */
    if (rc == 0) {
        obj = FwAllocObject(ctx, &objHandle);
        if (obj == NULL) {
            rc = TPM_RC_OBJECT_MEMORY;
        }
    }

    /* Copy public area */
    if (rc == 0) {
        XMEMCPY(&obj->pub, &inPublic.publicArea, sizeof(TPMT_PUBLIC));
    }

    /* Unwrap private */
    if (rc == 0) {
        rc = FwUnwrapPrivate(parent, &inPrivate,
            &sensitiveType, &obj->authValue,
            obj->privKey, &obj->privKeySize);
    #ifdef DEBUG_WOLFTPM
        if (rc != TPM_RC_SUCCESS) {
            printf("fwTPM: Load unwrap failed rc=%d (0x%x)\n", rc, rc);
        }
    #endif
    }

    /* Verify type matches */
    if (rc == 0) {
        if (sensitiveType != inPublic.publicArea.type) {
            rc = TPM_RC_TYPE;
        }
    }

    /* Compute name */
    if (rc == 0) {
        rc = FwComputeObjectName(obj);
    }

    /* --- Build response --- */
    if (rc == 0) {
        /* objectHandle */
        TPM2_Packet_AppendU32(rsp, objHandle);

        paramStart = FwRspParamsBegin(rsp, cmdTag, &paramSzPos);

            /* name (TPM2B_NAME) */
            TPM2_Packet_AppendU16(rsp, obj->name.size);
            TPM2_Packet_AppendBytes(rsp, obj->name.name, obj->name.size);

        FwRspParamsEnd(rsp, cmdTag, paramSzPos, paramStart);
    }

    /* Cleanup on error */
    if (rc != 0 && obj != NULL) {
        FwFreeObject(obj);
    }
    return rc;
}

/* --- TPM2_LoadExternal (CC 0x167) ---
 * Load an external key (public-only or public+private) without a parent.
 * Response: objectHandle | [paramSz] | name */
static TPM_RC FwCmd_LoadExternal(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT16 inPrivSize = 0;
    TPM2B_AUTH authValue;
    UINT16 sensitiveType = 0;
    FWTPM_DECLARE_BUF(qBuf, FWTPM_MAX_DER_SIG_BUF);
    UINT16 qSz = 0;
    UINT16 seedSz = 0;
    TPM2B_PUBLIC inPublic;
    UINT32 hierarchy = 0;
    FWTPM_Object* obj = NULL;
    TPM_HANDLE objHandle = 0;
    FWTPM_DECLARE_BUF(privKeyDer, FWTPM_MAX_PRIVKEY_DER);
    int privKeyDerSz = 0;
    int paramSzPos = 0, paramStart = 0;

    FWTPM_ALLOC_BUF(qBuf, FWTPM_MAX_DER_SIG_BUF);
    FWTPM_ALLOC_BUF(privKeyDer, FWTPM_MAX_PRIVKEY_DER);

    if (cmdSize < TPM2_HEADER_SIZE) {
        rc = TPM_RC_COMMAND_SIZE;
    }

    /* Skip auth area */
    if (rc == 0 && cmdTag == TPM_ST_SESSIONS) {
        rc = FwSkipAuthArea(cmd, cmdSize);
    }

    /* Parse inPrivate */
    if (rc == 0) {
        if (cmd->pos + 2 > cmdSize) {
            rc = TPM_RC_COMMAND_SIZE;
        }
    }
    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &inPrivSize);
        if (inPrivSize > 0 && cmd->pos + inPrivSize > cmdSize) {
            rc = TPM_RC_COMMAND_SIZE;
        }
    }

    XMEMSET(&authValue, 0, sizeof(authValue));
    if (rc == 0 && inPrivSize > 0) {
        /* sensitiveType */
        if (cmd->pos + 2 > cmdSize) {
            rc = TPM_RC_COMMAND_SIZE;
        }
        if (rc == 0) {
            TPM2_Packet_ParseU16(cmd, &sensitiveType);
        }
        /* authValue */
        if (rc == 0) {
            if (cmd->pos + 2 > cmdSize) {
                rc = TPM_RC_COMMAND_SIZE;
            }
        }
        if (rc == 0) {
            TPM2_Packet_ParseU16(cmd, &authValue.size);
            if (authValue.size > sizeof(authValue.buffer)) {
                rc = TPM_RC_SIZE;
            }
        }
        if (rc == 0 && authValue.size > 0) {
            if (cmd->pos + authValue.size > cmdSize) {
                rc = TPM_RC_COMMAND_SIZE;
            }
            if (rc == 0) {
                TPM2_Packet_ParseBytes(cmd, authValue.buffer, authValue.size);
            }
        }
        /* seedValue (skip) */
        if (rc == 0) {
            if (cmd->pos + 2 > cmdSize) {
                rc = TPM_RC_COMMAND_SIZE;
            }
        }
        if (rc == 0) {
            TPM2_Packet_ParseU16(cmd, &seedSz);
            if (cmd->pos + seedSz > cmdSize) {
                rc = TPM_RC_COMMAND_SIZE;
            }
        }
        if (rc == 0) {
            cmd->pos += seedSz;
        }
        /* sensitive.any (prime q for RSA) */
        if (rc == 0) {
            if (cmd->pos + 2 > cmdSize) {
                rc = TPM_RC_COMMAND_SIZE;
            }
        }
        if (rc == 0) {
            TPM2_Packet_ParseU16(cmd, &qSz);
            if (qSz > (UINT16)FWTPM_MAX_DER_SIG_BUF) {
                rc = TPM_RC_SIZE;
            }
        }
        if (rc == 0 && qSz > 0) {
            if (cmd->pos + qSz > cmdSize) {
                rc = TPM_RC_COMMAND_SIZE;
            }
            if (rc == 0) {
                TPM2_Packet_ParseBytes(cmd, qBuf, qSz);
            }
        }
    }

    /* Parse inPublic */
    if (rc == 0) {
        XMEMSET(&inPublic, 0, sizeof(inPublic));
        TPM2_Packet_ParsePublic(cmd, &inPublic);
    }

    /* Parse hierarchy */
    if (rc == 0) {
        if (cmd->pos + 4 > cmdSize) {
            rc = TPM_RC_COMMAND_SIZE;
        }
    }
    if (rc == 0) {
        TPM2_Packet_ParseU32(cmd, &hierarchy);
        (void)hierarchy;
    }

#ifdef DEBUG_WOLFTPM
    if (rc == 0) {
        printf("fwTPM: LoadExternal(type=%d, privSz=%u)\n",
            inPublic.publicArea.type, inPrivSize);
    }
#endif

    /* Reconstruct/store private key if private area was provided */
    if (rc == 0 && inPrivSize > 0 && sensitiveType == TPM_ALG_SYMCIPHER &&
            qSz > 0) {
        /* For SYMCIPHER, qBuf contains the raw AES key bytes */
        if (qSz > (UINT16)FWTPM_MAX_DER_SIG_BUF) {
            rc = TPM_RC_SIZE;
        }
        if (rc == 0) {
            XMEMCPY(privKeyDer, qBuf, qSz);
            privKeyDerSz = (int)qSz;
        }
    }
#ifdef HAVE_ECC
    else if (rc == 0 && inPrivSize > 0 && sensitiveType == TPM_ALG_ECC &&
            qSz > 0) {
        /* For ECC LoadExternal: qBuf is the raw private scalar d */
        FWTPM_DECLARE_VAR(eccKey, ecc_key);
        UINT16 curveId = inPublic.publicArea.parameters.eccDetail.curveID;
        int wcCurveExt = FwGetWcCurveId(curveId);

        FWTPM_ALLOC_VAR(eccKey, ecc_key);

        if (wcCurveExt < 0) {
            rc = TPM_RC_CURVE;
        }
        if (rc == 0) {
            rc = wc_ecc_init(eccKey);
            if (rc != 0) {
                rc = TPM_RC_FAILURE;
            }
        }
        if (rc == 0) {
            rc = wc_ecc_import_unsigned(eccKey,
                inPublic.publicArea.unique.ecc.x.buffer,
                inPublic.publicArea.unique.ecc.y.buffer,
                qBuf, wcCurveExt);
            if (rc == 0) {
                privKeyDerSz = wc_EccKeyToDer(eccKey, privKeyDer,
                    FWTPM_MAX_PRIVKEY_DER);
                if (privKeyDerSz <= 0) {
                    rc = TPM_RC_FAILURE;
                }
            }
            else {
                rc = TPM_RC_FAILURE;
            }
            wc_ecc_free(eccKey);
        }
        FWTPM_FREE_VAR(eccKey);
    }
#endif /* HAVE_ECC */
#ifndef NO_RSA
    else if (rc == 0 && inPrivSize > 0 && sensitiveType == TPM_ALG_RSA &&
            qSz > 0) {
        FWTPM_DECLARE_VAR(rsaKey, RsaKey);
        UINT32 exponent = inPublic.publicArea.parameters.rsaDetail.exponent;
        const byte* modBuf = inPublic.publicArea.unique.rsa.buffer;
        word32 modSz = (word32)inPublic.publicArea.unique.rsa.size;

        FWTPM_ALLOC_VAR(rsaKey, RsaKey);

        if (exponent == 0) {
            exponent = WC_RSA_EXPONENT;
        }

        rc = wc_InitRsaKey(rsaKey, NULL);
        if (rc != 0) {
            rc = TPM_RC_FAILURE;
        }
        if (rc == 0) {
            rc = mp_read_unsigned_bin(&rsaKey->n, modBuf, modSz);
        }
        if (rc == 0) {
            rc = mp_set_int(&rsaKey->e, (unsigned long)exponent);
        }
        if (rc == 0) {
            rc = mp_read_unsigned_bin(&rsaKey->q, qBuf, (word32)qSz);
        }
        if (rc != 0 && rc != TPM_RC_FAILURE) {
            rc = TPM_RC_FAILURE;
        }

        /* p = n / q */
        if (rc == 0) {
            rc = mp_div(&rsaKey->n, &rsaKey->q, &rsaKey->p, NULL);
            if (rc != 0) {
                rc = TPM_RC_FAILURE;
            }
        }

        if (rc == 0) {
            rc = FwRsaComputeCRT(rsaKey);
        }

        if (rc == 0) {
            rsaKey->type = RSA_PRIVATE;
            privKeyDerSz = wc_RsaKeyToDer(rsaKey, privKeyDer,
                FWTPM_MAX_PRIVKEY_DER);
            if (privKeyDerSz < 0) {
                rc = TPM_RC_FAILURE;
            }
        }
        wc_FreeRsaKey(rsaKey);
        FWTPM_FREE_VAR(rsaKey);
    }
#endif /* !NO_RSA */

    /* Allocate transient object */
    if (rc == 0) {
        obj = FwAllocObject(ctx, &objHandle);
        if (obj == NULL) {
            rc = TPM_RC_OBJECT_MEMORY;
        }
    }

    if (rc == 0) {
        XMEMCPY(&obj->pub, &inPublic.publicArea, sizeof(TPMT_PUBLIC));
        XMEMCPY(&obj->authValue, &authValue, sizeof(TPM2B_AUTH));
        if (privKeyDerSz > 0) {
            XMEMCPY(obj->privKey, privKeyDer, (size_t)privKeyDerSz);
        }
        obj->privKeySize = privKeyDerSz;
    }

    if (rc == 0) {
        rc = FwComputeObjectName(obj);
    }

    /* --- Build response --- */
    if (rc == 0) {
        /* objectHandle (before parameterSize) */
        TPM2_Packet_AppendU32(rsp, objHandle);

        paramStart = FwRspParamsBegin(rsp, cmdTag, &paramSzPos);

            /* name */
            TPM2_Packet_AppendU16(rsp, obj->name.size);
            TPM2_Packet_AppendBytes(rsp, obj->name.name, obj->name.size);

        FwRspParamsEnd(rsp, cmdTag, paramSzPos, paramStart);
    }

    /* Cleanup on error */
    if (rc != 0 && obj != NULL) {
        FwFreeObject(obj);
    }
    TPM2_ForceZero(qBuf, FWTPM_MAX_DER_SIG_BUF);
    FWTPM_FREE_BUF(qBuf);
    TPM2_ForceZero(privKeyDer, FWTPM_MAX_PRIVKEY_DER);
    FWTPM_FREE_BUF(privKeyDer);
    return rc;
}


/* --- TPM2_Import (CC 0x156) ---
 * Import an externally created key (outer-wrapped) under a parent key.
 * Response: [paramSz] | outPrivate */
static TPM_RC FwCmd_Import(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    UINT32 parentHandle;
    FWTPM_Object* parent;
    UINT16 encKeySz;
    byte encKeyBuf[64];
    FWTPM_DECLARE_VAR(objectPublic, TPM2B_PUBLIC);
    UINT16 dupSz;
    FWTPM_DECLARE_BUF(dupBuf, FWTPM_MAX_PRIVKEY_DER + 256);
    UINT16 symSeedSz;
    FWTPM_DECLARE_BUF(symSeedBuf, FWTPM_MAX_PUB_BUF);
    UINT16 symAlg, symKeyBits, symMode;
    byte seedBuf[FWTPM_MAX_HMAC_DIGEST_SIZE];
    int seedSz = 0;
    byte aesKey[FWTPM_MAX_SYM_KEY_SIZE];
    byte hmacKeyBuf[FWTPM_MAX_HMAC_KEY_SIZE];
    byte nameBuf[2 + TPM_MAX_DIGEST_SIZE];
    int nameSz = 0;
    FWTPM_DECLARE_VAR(outPrivate, TPM2B_PRIVATE);
    FWTPM_DECLARE_BUF(privKeyDer, FWTPM_MAX_PRIVKEY_DER);
    int privKeyDerSz = 0;
    int paramSzPos, paramStart;
    TPMI_ALG_HASH parentNameAlg;
    int symKeySz;
    int digestSz;
    enum wc_HashType wcHash;
    FWTPM_DECLARE_BUF(pubAreaBuf, FWTPM_MAX_PUB_BUF);
    TPM2_Packet tmpPkt;
    int pubAreaSz;
    TPMI_ALG_HASH objNameAlg;
    int objDigestSz;
    enum wc_HashType objWcHash;
    FWTPM_DECLARE_BUF(plainSens, FWTPM_MAX_SENSITIVE_SIZE);
    int plainSensSz = 0;
    UINT16 sensType = 0;
    UINT16 primeSz = 0;
    FWTPM_DECLARE_VAR(innerHashCtx, wc_HashAlg);
    FWTPM_DECLARE_BUF(primeBuf, FWTPM_MAX_DER_SIG_BUF);
    TPM2B_AUTH importedAuth;
    TPM_RC rc = TPM_RC_SUCCESS;

    FWTPM_ALLOC_BUF(dupBuf, FWTPM_MAX_PRIVKEY_DER + 256);
    FWTPM_ALLOC_BUF(symSeedBuf, FWTPM_MAX_PUB_BUF);
    FWTPM_ALLOC_BUF(privKeyDer, FWTPM_MAX_PRIVKEY_DER);
    FWTPM_ALLOC_BUF(pubAreaBuf, FWTPM_MAX_PUB_BUF);
    FWTPM_ALLOC_BUF(plainSens, FWTPM_MAX_SENSITIVE_SIZE);
    FWTPM_ALLOC_BUF(primeBuf, FWTPM_MAX_DER_SIG_BUF);
    FWTPM_ALLOC_VAR(innerHashCtx, wc_HashAlg);
    FWTPM_CALLOC_VAR(objectPublic, TPM2B_PUBLIC);
    FWTPM_CALLOC_VAR(outPrivate, TPM2B_PRIVATE);

    if (cmdSize < TPM2_HEADER_SIZE + 4) {
        rc = TPM_RC_COMMAND_SIZE;
    }

    /* Parse parentHandle */
    if (rc == 0) {
        TPM2_Packet_ParseU32(cmd, &parentHandle);
        parent = FwFindObject(ctx, parentHandle);
        if (parent == NULL) {
            rc = TPM_RC_HANDLE;
        }
    }

    /* Skip auth area */
    if (rc == 0 && cmdTag == TPM_ST_SESSIONS) {
        rc = FwSkipAuthArea(cmd, cmdSize);
    }

    /* Parse encryptionKey */
    if (rc == 0) {
        if (cmd->pos + 2 > cmdSize) {
            rc = TPM_RC_COMMAND_SIZE;
        }
    }
    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &encKeySz);
        if (encKeySz > (UINT16)sizeof(encKeyBuf)) {
            rc = TPM_RC_SIZE;
        }
    }
    if (rc == 0 && encKeySz > 0) {
        if (cmd->pos + encKeySz > cmdSize) {
            rc = TPM_RC_COMMAND_SIZE;
        }
        if (rc == 0) {
            TPM2_Packet_ParseBytes(cmd, encKeyBuf, encKeySz);
        }
    }
    /* encKeyBuf used later for inner decryption if symmetricAlg != NULL */

    /* Parse objectPublic */
    if (rc == 0) {
        XMEMSET(objectPublic, 0, sizeof(*objectPublic));
        TPM2_Packet_ParsePublic(cmd, objectPublic);
    }

    /* Parse duplicate */
    if (rc == 0) {
        if (cmd->pos + 2 > cmdSize) {
            rc = TPM_RC_COMMAND_SIZE;
        }
    }
    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &dupSz);
        if (dupSz > (UINT16)(FWTPM_MAX_PRIVKEY_DER + 256)) {
            rc = TPM_RC_SIZE;
        }
    }
    if (rc == 0 && dupSz > 0) {
        if (cmd->pos + dupSz > cmdSize) {
            rc = TPM_RC_COMMAND_SIZE;
        }
        if (rc == 0) {
            TPM2_Packet_ParseBytes(cmd, dupBuf, dupSz);
        }
    }

    /* Parse inSymSeed */
    if (rc == 0) {
        if (cmd->pos + 2 > cmdSize) {
            rc = TPM_RC_COMMAND_SIZE;
        }
    }
    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &symSeedSz);
        if (symSeedSz > (UINT16)FWTPM_MAX_PUB_BUF) {
            rc = TPM_RC_SIZE;
        }
    }
    if (rc == 0 && symSeedSz > 0) {
        if (cmd->pos + symSeedSz > cmdSize) {
            rc = TPM_RC_COMMAND_SIZE;
        }
        if (rc == 0) {
            TPM2_Packet_ParseBytes(cmd, symSeedBuf, symSeedSz);
        }
    }

    /* Parse symmetricAlg (TPMT_SYM_DEF_OBJECT) */
    if (rc == 0) {
        if (cmd->pos + 2 > cmdSize) {
            rc = TPM_RC_COMMAND_SIZE;
        }
    }
    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &symAlg);
        symKeyBits = 0;
        symMode = 0;
        if (symAlg == TPM_ALG_AES ||
            (symAlg != TPM_ALG_NULL && symAlg != TPM_ALG_XOR)) {
            if (cmd->pos + 4 > cmdSize) {
                rc = TPM_RC_COMMAND_SIZE;
            }
            if (rc == 0) {
                TPM2_Packet_ParseU16(cmd, &symKeyBits);
                TPM2_Packet_ParseU16(cmd, &symMode);
            }
        }
    }
    (void)symMode;

#ifdef DEBUG_WOLFTPM
    if (rc == 0) {
        printf("fwTPM: Import(parent=0x%x, objectType=%d, symAlg=0x%x, "
            "encKeySz=%d, dupSz=%d, symSeedSz=%d)\n",
            parentHandle, objectPublic->publicArea.type, symAlg,
            encKeySz, dupSz, symSeedSz);
    }
#endif

    /* Determine parent nameAlg and symmetric key size */
    if (rc == 0) {
        parentNameAlg = parent->pub.nameAlg;
        if (parent->pub.type == TPM_ALG_RSA) {
            symKeySz = (int)(parent->pub.parameters.rsaDetail.symmetric.keyBits.sym / 8);
        }
        else {
            symKeySz = (int)(parent->pub.parameters.eccDetail.symmetric.keyBits.sym / 8);
        }
        if (symKeySz <= 0) {
            symKeySz = 16;
        }
        if (symKeySz > FWTPM_MAX_SYM_KEY_SIZE) {
            rc = TPM_RC_SYMMETRIC;
        }
        digestSz = TPM2_GetHashDigestSize(parentNameAlg);
        wcHash = FwGetWcHashType(parentNameAlg);
        if (digestSz <= 0 || wcHash == WC_HASH_TYPE_NONE) {
            rc = TPM_RC_HASH;
        }
    }
    if (rc == 0 && parent->privKeySize == 0) {
        rc = TPM_RC_KEY;
    }

    /* Decrypt inSymSeed with parent key */
    if (rc == 0) {
        rc = FwDecryptSeed(ctx, parent,
            symSeedBuf, symSeedSz,
            (const byte*)"DUPLICATE", 10, "DUPLICATE",
            seedBuf, (int)sizeof(seedBuf), &seedSz);
    }

    /* Compute name of objectPublic: nameAlg(2) || Hash(publicArea) */
    if (rc == 0) {
        objNameAlg = objectPublic->publicArea.nameAlg;
        objDigestSz = TPM2_GetHashDigestSize(objNameAlg);
        objWcHash = FwGetWcHashType(objNameAlg);
        if (objDigestSz <= 0 || objWcHash == WC_HASH_TYPE_NONE) {
            rc = TPM_RC_HASH;
        }
    }
    if (rc == 0) {
        tmpPkt.buf = pubAreaBuf;
        tmpPkt.pos = 0;
        tmpPkt.size = (int)FWTPM_MAX_PUB_BUF;
        TPM2_Packet_AppendPublicArea(&tmpPkt, &objectPublic->publicArea);
        pubAreaSz = tmpPkt.pos;
        FwStoreU16BE(nameBuf, objNameAlg);
        rc = wc_Hash(objWcHash, pubAreaBuf, pubAreaSz,
            nameBuf + 2, objDigestSz);
        if (rc != 0) {
            rc = TPM_RC_FAILURE;
        }
        else {
            nameSz = 2 + objDigestSz;
        }
    }

    /* KDFa for storage key (AES wrap key) */
    if (rc == 0) {
        rc = TPM2_KDFa_ex(parentNameAlg, seedBuf, seedSz,
            "STORAGE", nameBuf, nameSz, NULL, 0, aesKey, symKeySz);
        if (rc != symKeySz) {
            rc = TPM_RC_FAILURE;
        }
        else {
            rc = 0;
        }
    }

    /* KDFa for integrity key (HMAC key) */
    if (rc == 0) {
        rc = TPM2_KDFa_ex(parentNameAlg, seedBuf, seedSz,
            "INTEGRITY", NULL, 0, NULL, 0, hmacKeyBuf, digestSz);
        if (rc != digestSz) {
            rc = TPM_RC_FAILURE;
        }
        else {
            rc = 0;
        }
    }


    /* Verify integrity and decrypt duplicate */
    if (rc == 0) {
        rc = FwImportVerifyAndDecrypt(parentNameAlg,
            hmacKeyBuf, digestSz, aesKey, symKeySz,
            nameBuf, nameSz, dupBuf, dupSz,
            plainSens, (int)(FWTPM_MAX_SENSITIVE_SIZE), &plainSensSz);
    }


    /* Inner decryption: if symmetricAlg != NULL and encryptionKey provided,
     * the plainSens contains inner wrapping that must be removed.
     * Per TPM spec Part 1 Section 23.4:
     *   innerWrapped = innerIntegrity(TPM2B) || AES-CFB(encryptionKey, sens)
     * innerIntegrity = HMAC(nameAlg, sensitive || objectName) */
    if (rc == 0 && symAlg != TPM_ALG_NULL && encKeySz > 0 &&
        plainSensSz > 2) {
        UINT16 innerIntegSz;
        int innerStart;
        byte* encInner;
        int encInnerSz;
        byte innerHash[TPM_MAX_DIGEST_SIZE];
        int ihRc;

        /* Parse inner integrity size */
        innerIntegSz = FwLoadU16BE(plainSens);
        innerStart = 2 + innerIntegSz;

        if (innerStart >= plainSensSz) {
        #ifdef DEBUG_WOLFTPM
            printf("fwTPM: Import inner integrity fail: "
                "innerIntegSz=%d, innerStart=%d, plainSensSz=%d\n",
                innerIntegSz, innerStart, plainSensSz);
        #endif
            rc = TPM_RC_INTEGRITY;
        }

        /* AES-CFB decrypt inner sensitive using encryptionKey */
        if (rc == 0) {
            encInner = plainSens + innerStart;
            encInnerSz = plainSensSz - innerStart;
            rc = TPM2_AesCfbDecrypt(encKeyBuf, encKeySz,
                NULL, encInner, (word32)encInnerSz);
            if (rc != 0) {
                rc = TPM_RC_FAILURE;
            }
        }

        /* Verify inner integrity: Hash(decryptedSensitive || objectName)
         * Per TPM 2.0 Part 1 Section 23.4 */
        if (rc == 0 && objDigestSz > 0 &&
            (UINT16)objDigestSz != innerIntegSz) {
            rc = TPM_RC_INTEGRITY;
        }
        if (rc == 0) {
            ihRc = wc_HashInit(innerHashCtx, objWcHash);
            if (ihRc == 0) {
                ihRc = wc_HashUpdate(innerHashCtx, objWcHash,
                    encInner, (word32)encInnerSz);
            }
            if (ihRc == 0) {
                ihRc = wc_HashUpdate(innerHashCtx, objWcHash,
                    nameBuf, (word32)nameSz);
            }
            if (ihRc == 0) {
                ihRc = wc_HashFinal(innerHashCtx, objWcHash, innerHash);
            }
            wc_HashFree(innerHashCtx, objWcHash);
            if (ihRc != 0) {
                rc = TPM_RC_FAILURE;
            }
            if (rc == 0) {
                if (TPM2_ConstantCompare(innerHash, plainSens + 2,
                        innerIntegSz) != 0) {
                    rc = TPM_RC_INTEGRITY;
                }
            }
            TPM2_ForceZero(innerHash, sizeof(innerHash));
        }

        /* Shift decrypted sensitive to beginning of plainSens buffer */
        if (rc == 0) {
            XMEMMOVE(plainSens, plainSens + innerStart, encInnerSz);
            plainSensSz = encInnerSz;
        }

    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: Import inner decrypt: rc=0x%x, innerIntegSz=%d, "
            "plainSensSz=%d, first4=0x%02x%02x%02x%02x\n",
            rc, innerIntegSz, plainSensSz,
            (rc == 0 && plainSensSz >= 4) ? plainSens[0] : 0,
            (rc == 0 && plainSensSz >= 4) ? plainSens[1] : 0,
            (rc == 0 && plainSensSz >= 4) ? plainSens[2] : 0,
            (rc == 0 && plainSensSz >= 4) ? plainSens[3] : 0);
    #endif
    }
    (void)encKeyBuf;

    /* Parse decrypted sensitive area */
    if (rc == 0) {
        rc = FwImportParseSensitive(plainSens, plainSensSz,
            &sensType, &importedAuth,
            &primeSz, primeBuf, (int)FWTPM_MAX_DER_SIG_BUF);
    }


    /* Reconstruct private key from sensitive data */
    if (rc == 0 && primeSz > 0) {
        rc = FwImportReconstructKey(objectPublic, sensType,
            primeBuf, primeSz,
            privKeyDer, (int)FWTPM_MAX_PRIVKEY_DER, &privKeyDerSz);
    }


    /* Wrap private for output */
    if (rc == 0) {
        XMEMSET(outPrivate, 0, sizeof(*outPrivate));
        rc = FwWrapPrivate(parent, sensType, &importedAuth,
            privKeyDer, privKeyDerSz, outPrivate);
    }

    /* Build response */
    if (rc == 0) {
        paramStart = FwRspParamsBegin(rsp, cmdTag, &paramSzPos);
        TPM2_Packet_AppendU16(rsp, outPrivate->size);
        TPM2_Packet_AppendBytes(rsp, outPrivate->buffer, outPrivate->size);
        FwRspParamsEnd(rsp, cmdTag, paramSzPos, paramStart);
    }

    TPM2_ForceZero(seedBuf, sizeof(seedBuf));
    TPM2_ForceZero(aesKey, sizeof(aesKey));
    TPM2_ForceZero(hmacKeyBuf, sizeof(hmacKeyBuf));
    FWTPM_FREE_BUF(dupBuf);
    FWTPM_FREE_BUF(symSeedBuf);
    TPM2_ForceZero(privKeyDer, FWTPM_MAX_PRIVKEY_DER);
    FWTPM_FREE_BUF(privKeyDer);
    FWTPM_FREE_BUF(pubAreaBuf);
    TPM2_ForceZero(plainSens, FWTPM_MAX_SENSITIVE_SIZE);
    FWTPM_FREE_BUF(plainSens);
    TPM2_ForceZero(primeBuf, FWTPM_MAX_DER_SIG_BUF);
    FWTPM_FREE_BUF(primeBuf);
    FWTPM_FREE_VAR(innerHashCtx);
    FWTPM_FREE_VAR(objectPublic);
    FWTPM_FREE_VAR(outPrivate);
    return rc;
}

/* --- TPM2_Duplicate (CC 0x014B) --- */
/* Export (duplicate) a key for transfer to another TPM.
 * Wire: objectHandle (U32) → newParentHandle (U32) → auth area →
 *       encryptionKeyIn (TPM2B) → symmetricAlg (TPMT_SYM_DEF_OBJECT)
 * Response: encryptionKeyOut (TPM2B) + duplicate (TPM2B) + outSymSeed (TPM2B)
 */
static TPM_RC FwCmd_Duplicate(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 objectHandle, newParentHandle;
    UINT16 encKeyInSz = 0;
    byte encKeyIn[32]; /* max AES-256 key */
    UINT16 symAlg = 0;
    UINT16 symKeyBits = 0;
    FWTPM_Object* obj = NULL;
    FWTPM_Object* newParent = NULL;
    FWTPM_DECLARE_VAR(outPrivate, TPM2B_PRIVATE);
    int paramSzPos, paramStart;
    byte seedBuf[FWTPM_MAX_HMAC_DIGEST_SIZE];
    int seedSz = 0;
    FWTPM_DECLARE_BUF(encSeedBuf, FWTPM_MAX_PUB_BUF);
    int encSeedSz = 0;

    FWTPM_ALLOC_BUF(encSeedBuf, FWTPM_MAX_PUB_BUF);
    FWTPM_CALLOC_VAR(outPrivate, TPM2B_PRIVATE);

    TPM2_Packet_ParseU32(cmd, &objectHandle);
    TPM2_Packet_ParseU32(cmd, &newParentHandle);
    if (cmdTag == TPM_ST_SESSIONS) rc = FwSkipAuthArea(cmd, cmdSize);

    /* Parse encryptionKeyIn (TPM2B) - save for inner wrapping */
    TPM2_Packet_ParseU16(cmd, &encKeyInSz);
    if (encKeyInSz > sizeof(encKeyIn)) {
        rc = TPM_RC_SIZE;
    }
    else if (cmd->pos + encKeyInSz > cmdSize) {
        rc = TPM_RC_COMMAND_SIZE;
    }
    if (rc == 0 && encKeyInSz > 0) {
        TPM2_Packet_ParseBytes(cmd, encKeyIn, encKeyInSz);
    }

    /* Parse symmetricAlg (TPMT_SYM_DEF_OBJECT) - save keyBits */
    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &symAlg);
        if (symAlg != TPM_ALG_NULL) {
            if (cmd->pos + 4 > cmdSize) {
                rc = TPM_RC_COMMAND_SIZE;
            }
            else {
                TPM2_Packet_ParseU16(cmd, &symKeyBits);
                cmd->pos += 2; /* skip mode */
            }
        }
    }

    /* Find the object to duplicate */
    obj = FwFindObject(ctx, objectHandle);
    if (obj == NULL) {
        rc = TPM_RC_HANDLE;
    }

    /* Check object is duplicable: fixedTPM and fixedParent must be clear */
    if (rc == 0 && (obj->pub.objectAttributes &
        TPMA_OBJECT_fixedTPM)) {
        rc = TPM_RC_ATTRIBUTES;
    }
    if (rc == 0 && (obj->pub.objectAttributes &
        TPMA_OBJECT_fixedParent)) {
        rc = TPM_RC_ATTRIBUTES;
    }
    /* Per TPM 2.0 Part 3 Section 12.5: if encryptedDuplication is set,
     * caller must supply a non-null symmetric algorithm */
    if (rc == 0 && (obj->pub.objectAttributes &
        TPMA_OBJECT_encryptedDuplication)) {
        if (symAlg == TPM_ALG_NULL) {
            rc = TPM_RC_SYMMETRIC;
        }
    }

    /* Find new parent (if not TPM_RH_NULL) */
    if (rc == 0 && newParentHandle != TPM_RH_NULL) {
        newParent = FwFindObject(ctx, newParentHandle);
        if (newParent == NULL) {
            rc = TPM_RC_HANDLE;
        }
    }

    /* Wrap the object's private data for export */
    if (rc == 0) {
        if (newParent != NULL) {
            /* Outer wrapping under new parent per TPM 2.0 Part 1 Section 24:
             * 1. Encrypt seed to newParent's public key → outSymSeed
             * 2. KDFa(seed, "STORAGE") → AES key
             * 3. KDFa(seed, "INTEGRITY") → HMAC key
             * 4. AES-CFB encrypt sensitive, HMAC for integrity */
            TPMI_ALG_HASH parentNameAlg = newParent->pub.nameAlg;
            int digestSz = TPM2_GetHashDigestSize(parentNameAlg);
            int symKeySz;
            byte aesKey[FWTPM_MAX_SYM_KEY_SIZE];
            byte hmacKey[FWTPM_MAX_HMAC_KEY_SIZE];
            FWTPM_DECLARE_BUF(sensBuf, FWTPM_MAX_SENSITIVE_SIZE);
            int sensSz = 0;
            byte hmacDigest[FWTPM_MAX_HMAC_DIGEST_SIZE];
            int outPos = 0;

            FWTPM_ALLOC_BUF(sensBuf, FWTPM_MAX_SENSITIVE_SIZE);

            if (digestSz <= 0) {
                rc = TPM_RC_HASH;
            }

            /* Get parent's symmetric key size from its public template */
            if (rc == 0) {
                if (newParent->pub.type == TPM_ALG_RSA) {
                    symKeySz = (int)(newParent->pub.parameters.rsaDetail
                        .symmetric.keyBits.sym / 8);
                }
                else {
                    symKeySz = (int)(newParent->pub.parameters.eccDetail
                        .symmetric.keyBits.sym / 8);
                }
                if (symKeySz <= 0) {
                    symKeySz = 16; /* default AES-128 */
                }
                if (symKeySz > FWTPM_MAX_SYM_KEY_SIZE) {
                    rc = TPM_RC_SYMMETRIC;
                }
            }

            /* Ensure object name is computed */
            if (rc == 0 && obj->name.size == 0) {
                FwComputeObjectName(obj);
            }

            /* Encrypt seed to newParent's public key */
            if (rc == 0) {
                rc = FwEncryptSeed(ctx, newParent,
                    (const byte*)"DUPLICATE", 10, "DUPLICATE",
                    seedBuf, (int)sizeof(seedBuf), &seedSz,
                    encSeedBuf, FWTPM_MAX_PUB_BUF, &encSeedSz);
            }

            /* KDFa for AES wrap key */
            if (rc == 0) {
                rc = TPM2_KDFa_ex(parentNameAlg, seedBuf, seedSz,
                    "STORAGE",
                    (const byte*)obj->name.name, obj->name.size,
                    NULL, 0, aesKey, symKeySz);
                if (rc != symKeySz) {
                    rc = TPM_RC_FAILURE;
                }
                else {
                    rc = 0;
                }
            }

            /* KDFa for HMAC integrity key */
            if (rc == 0) {
                rc = TPM2_KDFa_ex(parentNameAlg, seedBuf, seedSz,
                    "INTEGRITY", NULL, 0, NULL, 0,
                    hmacKey, digestSz);
                if (rc != digestSz) {
                    rc = TPM_RC_FAILURE;
                }
                else {
                    rc = 0;
                }
            }

            /* Extract raw sensitive component from DER key:
             * RSA: prime p, ECC: private scalar d */
            if (rc == 0) {
                byte sensComp[FWTPM_MAX_DER_SIG_BUF];
                int sensCompSz = 0;
            #ifndef NO_RSA
                if (obj->pub.type == TPM_ALG_RSA) {
                    FWTPM_DECLARE_VAR(tmpRsa, RsaKey);
                    FWTPM_ALLOC_VAR(tmpRsa, RsaKey);
                    rc = FwImportRsaKeyFromDer(obj, tmpRsa);
                    if (rc == 0) {
                        word32 pSz = (word32)sizeof(sensComp);
                        rc = mp_to_unsigned_bin(&tmpRsa->p, sensComp);
                        if (rc == 0) {
                            pSz = (word32)mp_unsigned_bin_size(&tmpRsa->p);
                            sensCompSz = (int)pSz;
                        }
                        else {
                            rc = TPM_RC_FAILURE;
                        }
                        wc_FreeRsaKey(tmpRsa);
                    }
                    else {
                        rc = TPM_RC_KEY;
                    }
                    FWTPM_FREE_VAR(tmpRsa);
                }
                else
            #endif
            #ifdef HAVE_ECC
                if (obj->pub.type == TPM_ALG_ECC) {
                    FWTPM_DECLARE_VAR(tmpEcc, ecc_key);
                    FWTPM_ALLOC_VAR(tmpEcc, ecc_key);
                    if (rc == 0) {
                        rc = FwImportEccKeyFromDer(obj, tmpEcc);
                    }
                    if (rc == 0) {
                        word32 dSz = (word32)sizeof(sensComp);
                        rc = wc_ecc_export_private_only(tmpEcc,
                            sensComp, &dSz);
                        if (rc == 0) {
                            sensCompSz = (int)dSz;
                        }
                        else {
                            rc = TPM_RC_FAILURE;
                        }
                        wc_ecc_free(tmpEcc);
                    }
                    else {
                        rc = TPM_RC_KEY;
                    }
                    FWTPM_FREE_VAR(tmpEcc);
                }
                else
            #endif
                {
                    rc = TPM_RC_KEY;
                }

                /* Marshal in standard TPM 2.0 format */
                if (rc == 0) {
                    sensSz = FwMarshalSensitiveStd(sensBuf,
                        FWTPM_MAX_SENSITIVE_SIZE,
                        obj->pub.type, &obj->authValue,
                        sensComp, sensCompSz);
                    if (sensSz < 0) {
                        rc = TPM_RC_SIZE;
                    }
                }
                TPM2_ForceZero(sensComp, sizeof(sensComp));
            }

            /* AES-CFB encrypt (zero IV) */
            if (rc == 0) {
                rc = TPM2_AesCfbEncrypt(aesKey, symKeySz,
                    NULL, sensBuf, (word32)sensSz);
                if (rc != 0)
                    rc = TPM_RC_FAILURE;
            }

            /* HMAC(hmacKey, encSens || objectName) */
            if (rc == 0) {
                rc = TPM2_HmacCompute(parentNameAlg,
                    hmacKey, (word32)digestSz,
                    sensBuf, (word32)sensSz,
                    (byte*)obj->name.name, obj->name.size,
                    hmacDigest, NULL);
                if (rc != 0)
                    rc = TPM_RC_FAILURE;
            }

            /* Pack outPrivate: integritySize(2) + integrity + encSens */
            if (rc == 0) {
                FwStoreU16BE(outPrivate->buffer + outPos, (UINT16)digestSz);
                outPos += 2;
                XMEMCPY(outPrivate->buffer + outPos, hmacDigest, digestSz);
                outPos += digestSz;
                if (outPos + sensSz > (int)sizeof(outPrivate->buffer)) {
                    rc = TPM_RC_SIZE;
                }
            }
            if (rc == 0) {
                XMEMCPY(outPrivate->buffer + outPos, sensBuf, sensSz);
                outPos += sensSz;
                outPrivate->size = (UINT16)outPos;
            }

            TPM2_ForceZero(seedBuf, sizeof(seedBuf));
            TPM2_ForceZero(aesKey, sizeof(aesKey));
            TPM2_ForceZero(hmacKey, sizeof(hmacKey));
            TPM2_ForceZero(sensBuf, FWTPM_MAX_SENSITIVE_SIZE);
            FWTPM_FREE_BUF(sensBuf);
        }
        else if (symAlg != TPM_ALG_NULL) {
            /* Inner wrapping with AES-CFB + HMAC integrity per
             * TPM 2.0 Part 3 Section 12.5 */
            byte innerKey[32];
            int innerKeySz = symKeyBits / 8;
            FWTPM_DECLARE_BUF(sensBuf, FWTPM_MAX_PRIVKEY_DER + 64);
            int sensSz;
            byte innerHmac[TPM_SHA256_DIGEST_SIZE];
            int innerHmacSz = TPM_SHA256_DIGEST_SIZE;
            int outPos = 0;

            FWTPM_ALLOC_BUF(sensBuf, FWTPM_MAX_PRIVKEY_DER + 64);

            if (innerKeySz <= 0 || innerKeySz > (int)sizeof(innerKey)) {
                rc = TPM_RC_KEY_SIZE;
            }

            /* Get or generate inner key */
            if (rc == 0) {
                if (encKeyInSz > 0) {
                    XMEMCPY(innerKey, encKeyIn, encKeyInSz);
                    innerKeySz = encKeyInSz;
                }
                else {
                    rc = wc_RNG_GenerateBlock(&ctx->rng, innerKey,
                        (word32)innerKeySz);
                    /* Save generated key for response encryptionKeyOut */
                    if (rc == 0) {
                        XMEMCPY(encKeyIn, innerKey, innerKeySz);
                    }
                }
            }

            /* Marshal sensitive */
            if (rc == 0) {
                sensSz = FwMarshalSensitive(sensBuf,
                    FWTPM_MAX_PRIVKEY_DER + 64,
                    obj->pub.type, &obj->authValue,
                    obj->privKey, obj->privKeySize);
                if (sensSz < 0) {
                    rc = TPM_RC_SIZE;
                }
            }

            /* AES-CFB encrypt (zero IV) */
            if (rc == 0) {
                rc = TPM2_AesCfbEncrypt(innerKey, innerKeySz,
                    NULL, sensBuf, (word32)sensSz);
                if (rc != 0)
                    rc = TPM_RC_FAILURE;
            }

            /* HMAC(innerKey, encSens || objectName) */
            if (rc == 0) {
                if (obj->name.size == 0) {
                    FwComputeObjectName(obj);
                }
                rc = TPM2_HmacCompute(TPM_ALG_SHA256,
                    innerKey, (word32)innerKeySz,
                    sensBuf, (word32)sensSz,
                    (byte*)obj->name.name, obj->name.size,
                    innerHmac, NULL);
                if (rc != 0)
                    rc = TPM_RC_FAILURE;
            }

            /* Pack: integritySize(2) || integrity || encSens */
            if (rc == 0) {
                FwStoreU16BE(outPrivate->buffer + outPos, (UINT16)innerHmacSz);
                outPos += 2;
                XMEMCPY(outPrivate->buffer + outPos, innerHmac, innerHmacSz);
                outPos += innerHmacSz;
                if (outPos + sensSz > (int)sizeof(outPrivate->buffer)) {
                    rc = TPM_RC_SIZE;
                }
            }
            if (rc == 0) {
                XMEMCPY(outPrivate->buffer + outPos, sensBuf, sensSz);
                outPos += sensSz;
                outPrivate->size = (UINT16)outPos;
            }

            TPM2_ForceZero(innerKey, sizeof(innerKey));
            TPM2_ForceZero(sensBuf, FWTPM_MAX_PRIVKEY_DER + 64);
            FWTPM_FREE_BUF(sensBuf);
        }
        else {
            /* symAlg == NULL and newParent == NULL: output plaintext
             * sensitive (no wrapping) */
            int pos = 0;
            if (obj->privKeySize + 6 + (int)obj->authValue.size >
                (int)sizeof(outPrivate->buffer)) {
                rc = TPM_RC_SIZE;
            }
            if (rc == 0) {
                FwStoreU16BE(outPrivate->buffer + pos, obj->pub.type);
                pos += 2;
                FwStoreU16BE(outPrivate->buffer + pos, obj->authValue.size);
                pos += 2;
                if (obj->authValue.size > 0) {
                    XMEMCPY(outPrivate->buffer + pos,
                        obj->authValue.buffer, obj->authValue.size);
                    pos += obj->authValue.size;
                }
                FwStoreU16BE(outPrivate->buffer + pos,
                    (UINT16)obj->privKeySize);
                pos += 2;
                if (obj->privKeySize > 0) {
                    XMEMCPY(outPrivate->buffer + pos, obj->privKey,
                        obj->privKeySize);
                    pos += obj->privKeySize;
                }
                outPrivate->size = (UINT16)pos;
            }
        }
    }

    if (rc == 0) {
    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: Duplicate(obj=0x%x, newParent=0x%x)\n",
            objectHandle, newParentHandle);
    #endif

        /* Build response */
        paramStart = FwRspParamsBegin(rsp, cmdTag, &paramSzPos);

        /* encryptionKeyOut (TPM2B) - return generated key if we made one */
        if (newParentHandle == TPM_RH_NULL && symAlg != TPM_ALG_NULL &&
            encKeyInSz == 0) {
            int innerKeySz2 = symKeyBits / 8;
            TPM2_Packet_AppendU16(rsp, (UINT16)innerKeySz2);
            TPM2_Packet_AppendBytes(rsp, encKeyIn, innerKeySz2);
        }
        else {
            TPM2_Packet_AppendU16(rsp, 0);
        }

        /* duplicate (TPM2B_PRIVATE) */
        TPM2_Packet_AppendU16(rsp, outPrivate->size);
        if (outPrivate->size > 0) {
            TPM2_Packet_AppendBytes(rsp, outPrivate->buffer, outPrivate->size);
        }

        /* outSymSeed (TPM2B_ENCRYPTED_SECRET) */
        if (encSeedSz > 0) {
            TPM2_Packet_AppendU16(rsp, (UINT16)encSeedSz);
            TPM2_Packet_AppendBytes(rsp, encSeedBuf, encSeedSz);
        }
        else {
            TPM2_Packet_AppendU16(rsp, 0);
        }

        FwRspParamsEnd(rsp, cmdTag, paramSzPos, paramStart);
    }

    TPM2_ForceZero(encKeyIn, sizeof(encKeyIn));
    /* outPrivate is the encrypted/HMAC-protected blob — no zero needed. */
    TPM2_ForceZero(seedBuf, sizeof(seedBuf));
    FWTPM_FREE_BUF(encSeedBuf);
    FWTPM_FREE_VAR(outPrivate);
    return rc;
}

/* --- TPM2_Rewrap (CC 0x0152) --- */
/* Decrypt duplicate blob from oldParent's protection, re-encrypt under
 * newParent. Per TPM 2.0 spec Section 13.2. */
static TPM_RC FwCmd_Rewrap(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 oldParentH, newParentH;
    FWTPM_Object* oldParent = NULL;
    FWTPM_Object* newParent = NULL;
    UINT16 dupSz = 0;
    FWTPM_DECLARE_BUF(dupBuf, FWTPM_MAX_PRIVKEY_DER + 256);
    UINT16 nameSz = 0;
    byte nameBuf[2 + TPM_MAX_DIGEST_SIZE];
    UINT16 symSeedSz = 0;
    FWTPM_DECLARE_BUF(symSeedBuf, FWTPM_MAX_PUB_BUF);
    FWTPM_DECLARE_BUF(plainSens, FWTPM_MAX_SENSITIVE_SIZE);
    FWTPM_DECLARE_BUF(encSeedBuf, FWTPM_MAX_PUB_BUF);
    int plainSensSz = 0;
    byte seedBuf[FWTPM_MAX_HMAC_DIGEST_SIZE];
    int seedSz = 0;
    byte aesKey[FWTPM_MAX_SYM_KEY_SIZE];
    byte hmacKeyBuf[FWTPM_MAX_HMAC_KEY_SIZE];
    int paramSzPos, paramStart;

    (void)cmdSize;

    FWTPM_ALLOC_BUF(dupBuf, FWTPM_MAX_PRIVKEY_DER + 256);
    FWTPM_ALLOC_BUF(symSeedBuf, FWTPM_MAX_PUB_BUF);
    FWTPM_ALLOC_BUF(plainSens, FWTPM_MAX_SENSITIVE_SIZE);
    FWTPM_ALLOC_BUF(encSeedBuf, FWTPM_MAX_PUB_BUF);

    /* Parse handles */
    TPM2_Packet_ParseU32(cmd, &oldParentH);
    TPM2_Packet_ParseU32(cmd, &newParentH);
    if (cmdTag == TPM_ST_SESSIONS)
        rc = FwSkipAuthArea(cmd, cmdSize);

    /* Parse inDuplicate (TPM2B) */
    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &dupSz);
        if (dupSz > (UINT16)(FWTPM_MAX_PRIVKEY_DER + 256))
            rc = TPM_RC_SIZE;
    }
    if (rc == 0 && dupSz > 0) {
        TPM2_Packet_ParseBytes(cmd, dupBuf, dupSz);
    }

    /* Parse name (TPM2B_NAME) */
    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &nameSz);
        if (nameSz > (UINT16)sizeof(nameBuf))
            rc = TPM_RC_SIZE;
    }
    if (rc == 0 && nameSz > 0) {
        TPM2_Packet_ParseBytes(cmd, nameBuf, nameSz);
    }

    /* Parse inSymSeed (TPM2B) */
    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &symSeedSz);
        if (symSeedSz > FWTPM_MAX_PUB_BUF)
            rc = TPM_RC_SIZE;
    }
    if (rc == 0 && symSeedSz > 0) {
        TPM2_Packet_ParseBytes(cmd, symSeedBuf, symSeedSz);
    }

    /* Look up oldParent (TPM_RH_NULL means no outer protection) */
    if (rc == 0 && oldParentH != TPM_RH_NULL) {
        oldParent = FwFindObject(ctx, oldParentH);
        if (oldParent == NULL)
            rc = (TPM_RC_HANDLE | TPM_RC_1);
    }

    /* Look up newParent */
    if (rc == 0 && newParentH != TPM_RH_NULL) {
        newParent = FwFindObject(ctx, newParentH);
        if (newParent == NULL)
            rc = (TPM_RC_HANDLE | TPM_RC_2);
    }

#ifdef DEBUG_WOLFTPM
    if (rc == 0) {
        printf("fwTPM: Rewrap(old=0x%x, new=0x%x, dupSz=%d, nameSz=%d, "
            "seedSz=%d)\n", oldParentH, newParentH, dupSz, nameSz,
            symSeedSz);
    }
#endif

    /* === Unwrap from oldParent === */
    if (rc == 0 && oldParent != NULL) {
        TPMI_ALG_HASH parentNameAlg = oldParent->pub.nameAlg;
        int symKeySz, digestSz;

        if (oldParent->pub.type == TPM_ALG_RSA) {
            symKeySz = (int)(oldParent->pub.parameters.rsaDetail.symmetric.keyBits.sym / 8);
        }
        else {
            symKeySz = (int)(oldParent->pub.parameters.eccDetail.symmetric.keyBits.sym / 8);
        }
        if (symKeySz <= 0) symKeySz = 16;
        if (symKeySz > FWTPM_MAX_SYM_KEY_SIZE) {
            rc = TPM_RC_SYMMETRIC;
        }
        digestSz = TPM2_GetHashDigestSize(parentNameAlg);
        if (digestSz <= 0) {
            rc = TPM_RC_HASH;
        }

        /* Decrypt seed with oldParent's private key */
        if (rc == 0) {
            rc = FwDecryptSeed(ctx, oldParent,
                symSeedBuf, symSeedSz,
                (const byte*)"DUPLICATE", 10, "DUPLICATE",
                seedBuf, (int)sizeof(seedBuf), &seedSz);
        }
        /* Derive AES + HMAC keys */
        if (rc == 0) {
            rc = TPM2_KDFa_ex(parentNameAlg, seedBuf, seedSz,
                "STORAGE", nameBuf, nameSz, NULL, 0, aesKey, symKeySz);
            rc = (rc == symKeySz) ? 0 : TPM_RC_FAILURE;
        }
        if (rc == 0) {
            rc = TPM2_KDFa_ex(parentNameAlg, seedBuf, seedSz,
                "INTEGRITY", NULL, 0, NULL, 0, hmacKeyBuf, digestSz);
            rc = (rc == digestSz) ? 0 : TPM_RC_FAILURE;
        }
        /* Verify integrity and decrypt */
        if (rc == 0) {
            rc = FwImportVerifyAndDecrypt(parentNameAlg,
                hmacKeyBuf, digestSz, aesKey, symKeySz,
                nameBuf, nameSz, dupBuf, dupSz,
                plainSens, FWTPM_MAX_SENSITIVE_SIZE, &plainSensSz);
        }
        TPM2_ForceZero(seedBuf, sizeof(seedBuf));
        TPM2_ForceZero(aesKey, sizeof(aesKey));
        TPM2_ForceZero(hmacKeyBuf, sizeof(hmacKeyBuf));
    }
    else if (rc == 0) {
        /* oldParent == NULL: inDuplicate is plaintext */
        if (dupSz > (UINT16)(FWTPM_MAX_SENSITIVE_SIZE))
            rc = TPM_RC_SIZE;
    }
    if (rc == 0 && oldParent == NULL) {
        XMEMCPY(plainSens, dupBuf, dupSz);
        plainSensSz = dupSz;
    }

    /* === Re-wrap under newParent === */
    if (rc == 0 && newParent != NULL) {
        TPMI_ALG_HASH parentNameAlg = newParent->pub.nameAlg;
        int symKeySz, digestSz;
        int encSeedSz = 0;
        byte hmacDigest[TPM_MAX_DIGEST_SIZE];
        int outPos = 0;

        if (newParent->pub.type == TPM_ALG_RSA) {
            symKeySz = (int)(newParent->pub.parameters.rsaDetail.symmetric.keyBits.sym / 8);
        }
        else {
            symKeySz = (int)(newParent->pub.parameters.eccDetail.symmetric.keyBits.sym / 8);
        }
        if (symKeySz <= 0) symKeySz = 16;
        if (symKeySz > FWTPM_MAX_SYM_KEY_SIZE) {
            rc = TPM_RC_SYMMETRIC;
        }
        digestSz = TPM2_GetHashDigestSize(parentNameAlg);
        if (digestSz <= 0)
            rc = TPM_RC_HASH;

        /* Generate seed and encrypt to newParent */
        if (rc == 0) {
            rc = FwEncryptSeed(ctx, newParent,
                (const byte*)"DUPLICATE", 10, "DUPLICATE",
                seedBuf, (int)sizeof(seedBuf), &seedSz,
                encSeedBuf, (int)FWTPM_MAX_PUB_BUF, &encSeedSz);
        }
        /* Derive new AES + HMAC keys */
        if (rc == 0) {
            rc = TPM2_KDFa_ex(parentNameAlg, seedBuf, seedSz,
                "STORAGE", nameBuf, nameSz, NULL, 0, aesKey, symKeySz);
            rc = (rc == symKeySz) ? 0 : TPM_RC_FAILURE;
        }
        if (rc == 0) {
            rc = TPM2_KDFa_ex(parentNameAlg, seedBuf, seedSz,
                "INTEGRITY", NULL, 0, NULL, 0, hmacKeyBuf, digestSz);
            rc = (rc == digestSz) ? 0 : TPM_RC_FAILURE;
        }
        /* AES-CFB encrypt plainSens */
        if (rc == 0) {
            rc = TPM2_AesCfbEncrypt(aesKey, symKeySz,
                NULL, plainSens, (word32)plainSensSz);
            if (rc != 0)
                rc = TPM_RC_FAILURE;
        }
        /* HMAC(hmacKey, encSens || name) */
        if (rc == 0) {
            rc = TPM2_HmacCompute(parentNameAlg,
                hmacKeyBuf, (word32)digestSz,
                plainSens, (word32)plainSensSz,
                (nameSz > 0) ? nameBuf : NULL, (word32)nameSz,
                hmacDigest, NULL);
            if (rc != 0)
                rc = TPM_RC_FAILURE;
        }
        /* Pack outDuplicate: integritySize(2) || integrity || encSens */
        if (rc == 0) {
            if (2 + digestSz + plainSensSz > (int)(FWTPM_MAX_PRIVKEY_DER + 256)) {
                rc = TPM_RC_SIZE;
            }
        }
        if (rc == 0) {
            FwStoreU16BE(dupBuf + outPos, (UINT16)digestSz);
            outPos += 2;
            XMEMCPY(dupBuf + outPos, hmacDigest, digestSz);
            outPos += digestSz;
            XMEMCPY(dupBuf + outPos, plainSens, plainSensSz);
            outPos += plainSensSz;
            dupSz = (UINT16)outPos;
        }

        /* Build response: outDuplicate(TPM2B) + outSymSeed(TPM2B) */
        if (rc == 0) {
            paramStart = FwRspParamsBegin(rsp, cmdTag, &paramSzPos);
            TPM2_Packet_AppendU16(rsp, dupSz);
            TPM2_Packet_AppendBytes(rsp, dupBuf, dupSz);
            TPM2_Packet_AppendU16(rsp, (UINT16)encSeedSz);
            TPM2_Packet_AppendBytes(rsp, encSeedBuf, encSeedSz);
            FwRspParamsEnd(rsp, cmdTag, paramSzPos, paramStart);
        }

        TPM2_ForceZero(seedBuf, sizeof(seedBuf));
        TPM2_ForceZero(aesKey, sizeof(aesKey));
        TPM2_ForceZero(hmacKeyBuf, sizeof(hmacKeyBuf));
    }
    else if (rc == 0) {
        /* newParent == NULL: output plaintext + empty seed */
        paramStart = FwRspParamsBegin(rsp, cmdTag, &paramSzPos);
        TPM2_Packet_AppendU16(rsp, (UINT16)plainSensSz);
        if (plainSensSz > 0) {
            TPM2_Packet_AppendBytes(rsp, plainSens, plainSensSz);
        }
        TPM2_Packet_AppendU16(rsp, 0); /* empty outSymSeed */
        FwRspParamsEnd(rsp, cmdTag, paramSzPos, paramStart);
    }

    TPM2_ForceZero(plainSens, FWTPM_MAX_SENSITIVE_SIZE);
    FWTPM_FREE_BUF(dupBuf);
    FWTPM_FREE_BUF(symSeedBuf);
    FWTPM_FREE_BUF(plainSens);
    FWTPM_FREE_BUF(encSeedBuf);
    return rc;
}

/* --- TPM2_CreateLoaded (CC 0x0191) ---
 * Like Create but also loads the key into a transient slot.
 * Response: objectHandle | [paramSz] | outPrivate | outPublic | name */
static TPM_RC FwCmd_CreateLoaded(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    int ret;
    UINT32 parentHandle;
    TPM2B_AUTH userAuth;
    FWTPM_DECLARE_BUF(sensData, FWTPM_MAX_DATA_BUF);
    UINT16 sensDataSize = 0;
    FWTPM_DECLARE_VAR(inPublic, TPM2B_PUBLIC);
    FWTPM_Object* parent = NULL;
    FWTPM_Object* obj = NULL;
    TPM_HANDLE objHandle = 0;
    FWTPM_DECLARE_VAR(outPrivate, TPM2B_PRIVATE);
    FWTPM_DECLARE_BUF(privKeyDer, FWTPM_MAX_PRIVKEY_DER);
    int privKeyDerSz = 0;
    int paramSzPos = 0;
    int paramStart = 0;
    FWTPM_DECLARE_VAR(outPub, TPM2B_PUBLIC);

    FWTPM_ALLOC_BUF(privKeyDer, FWTPM_MAX_PRIVKEY_DER);
    FWTPM_CALLOC_BUF(sensData, FWTPM_MAX_DATA_BUF);
    FWTPM_CALLOC_VAR(inPublic, TPM2B_PUBLIC);
    FWTPM_CALLOC_VAR(outPrivate, TPM2B_PRIVATE);
    FWTPM_CALLOC_VAR(outPub, TPM2B_PUBLIC);
    XMEMSET(&userAuth, 0, sizeof(userAuth));

    (void)ret;

    if (cmdSize < TPM2_HEADER_SIZE + 4) {
        rc = TPM_RC_COMMAND_SIZE;
    }

    /* Parse parent handle */
    if (rc == 0) {
        TPM2_Packet_ParseU32(cmd, &parentHandle);

        /* Find parent object */
        parent = FwFindObject(ctx, parentHandle);
        if (parent == NULL) {
            rc = TPM_RC_HANDLE;
        }
    }

    /* Skip auth area */
    if (rc == 0 && cmdTag == TPM_ST_SESSIONS) {
        rc = FwSkipAuthArea(cmd, cmdSize);
    }

    /* Parse inSensitive (TPM2B_SENSITIVE_CREATE) — capture data */
    if (rc == 0) {
        rc = TPM2_Packet_ParseSensitiveCreate(cmd, cmdSize, &userAuth,
            sensData, (int)FWTPM_SIZEOF_BUF(sensData, FWTPM_MAX_DATA_BUF),
            &sensDataSize);
    }

    /* Parse inPublic (TPM2B_TEMPLATE = TPM2B_PUBLIC) */
    if (rc == 0) {
        TPM2_Packet_ParsePublic(cmd, inPublic);
    }

    /* Note: CreateLoaded does NOT include outsideInfo or creationPCR
     * (unlike TPM2_Create). The input is: parentHandle + inSensitive + inPublic */

#ifdef DEBUG_WOLFTPM
    if (rc == 0) {
        printf("fwTPM: CreateLoaded(parent=0x%x, type=%d)\n",
            parentHandle, inPublic->publicArea.type);
    }
#endif

    /* Generate key -- same logic as Create */
    if (rc == 0) {
        switch (inPublic->publicArea.type) {
#ifndef NO_RSA
            case TPM_ALG_RSA: {
            #ifdef WOLFSSL_KEY_GEN
                rc = FwGenerateRsaKey(&ctx->rng,
                    inPublic->publicArea.parameters.rsaDetail.keyBits,
                    inPublic->publicArea.parameters.rsaDetail.exponent,
                    &inPublic->publicArea.unique.rsa,
                    privKeyDer, FWTPM_MAX_PRIVKEY_DER, &privKeyDerSz);
            #else
                rc = TPM_RC_COMMAND_CODE;
            #endif /* WOLFSSL_KEY_GEN */
                break;
            }
#endif /* !NO_RSA */
#ifdef HAVE_ECC
            case TPM_ALG_ECC: {
                rc = FwGenerateEccKey(&ctx->rng,
                    inPublic->publicArea.parameters.eccDetail.curveID,
                    &inPublic->publicArea.unique.ecc,
                    privKeyDer, FWTPM_MAX_PRIVKEY_DER, &privKeyDerSz);
                break;
            }
#endif /* HAVE_ECC */
            case TPM_ALG_KEYEDHASH: {
                TPMI_ALG_HASH hashAlg;
                TPMI_ALG_KEYEDHASH_SCHEME scheme =
                    inPublic->publicArea.parameters.keyedHashDetail
                        .scheme.scheme;
                int keySz;

                if (scheme == TPM_ALG_HMAC) {
                    hashAlg = inPublic->publicArea.parameters.keyedHashDetail
                                  .scheme.details.hmac.hashAlg;
                    keySz = TPM2_GetHashDigestSize(hashAlg);
                    if (keySz <= 0) {
                        rc = TPM_RC_HASH;
                    }
                }
                else {
                    keySz = TPM2_GetHashDigestSize(
                        inPublic->publicArea.nameAlg);
                    if (keySz <= 0) {
                        keySz = TPM_SHA256_DIGEST_SIZE;
                    }
                }

                if (rc == 0 && sensDataSize > 0) {
                    if (sensDataSize > (UINT16)FWTPM_MAX_DATA_BUF) {
                        rc = TPM_RC_SIZE;
                    }
                    if (rc == 0) {
                        XMEMCPY(privKeyDer, sensData, sensDataSize);
                        privKeyDerSz = (int)sensDataSize;
                    }
                }
                else if (rc == 0) {
                    ret = wc_RNG_GenerateBlock(&ctx->rng, privKeyDer,
                        (word32)keySz);
                    if (ret != 0) {
                        rc = TPM_RC_FAILURE;
                    }
                    else {
                        privKeyDerSz = keySz;
                    }
                }

                if (rc == 0) {
                    inPublic->publicArea.unique.keyedHash.size = (UINT16)
                        FwComputeUniqueHash(inPublic->publicArea.nameAlg,
                            privKeyDer, privKeyDerSz,
                            inPublic->publicArea.unique.keyedHash.buffer);
                }
                break;
            }
            case TPM_ALG_SYMCIPHER: {
                int keyBits = (int)inPublic->publicArea.parameters
                    .symDetail.sym.keyBits.sym;
                int keySz = keyBits / 8;

                if (keySz <= 0 || keySz > 32) {
                    rc = TPM_RC_KEY_SIZE;
                }

                if (rc == 0 && sensDataSize > 0) {
                    if (sensDataSize > (UINT16)FWTPM_MAX_DATA_BUF) {
                        rc = TPM_RC_SIZE;
                    }
                    if (rc == 0) {
                        XMEMCPY(privKeyDer, sensData, sensDataSize);
                        privKeyDerSz = (int)sensDataSize;
                    }
                }
                else if (rc == 0) {
                    ret = wc_RNG_GenerateBlock(&ctx->rng, privKeyDer,
                        (word32)keySz);
                    if (ret != 0) {
                        rc = TPM_RC_FAILURE;
                    }
                    else {
                        privKeyDerSz = keySz;
                    }
                }

                if (rc == 0) {
                    inPublic->publicArea.unique.sym.size = (UINT16)
                        FwComputeUniqueHash(inPublic->publicArea.nameAlg,
                            privKeyDer, keySz,
                            inPublic->publicArea.unique.sym.buffer);
                }
                break;
            }
            default:
                rc = TPM_RC_TYPE;
                break;
        }
    }

    /* Wrap private key */
    if (rc == 0) {
        rc = FwWrapPrivate(parent, inPublic->publicArea.type, &userAuth,
            privKeyDer, privKeyDerSz, outPrivate);
    }

    /* Load into transient slot */
    if (rc == 0) {
        obj = FwAllocObject(ctx, &objHandle);
        if (obj == NULL) {
            rc = TPM_RC_OBJECT_MEMORY;
        }
    }

    if (rc == 0) {
        XMEMCPY(&obj->pub, &inPublic->publicArea, sizeof(TPMT_PUBLIC));
        XMEMCPY(obj->privKey, privKeyDer, (size_t)privKeyDerSz);
        obj->privKeySize = privKeyDerSz;
        XMEMCPY(&obj->authValue, &userAuth, sizeof(TPM2B_AUTH));

        rc = FwComputeObjectName(obj);
    }

    /* --- Build response --- */
    if (rc == 0) {
        /* objectHandle (before parameterSize) */
        TPM2_Packet_AppendU32(rsp, objHandle);

        paramStart = FwRspParamsBegin(rsp, cmdTag, &paramSzPos);

            /* outPrivate */
            TPM2_Packet_AppendU16(rsp, outPrivate->size);
            TPM2_Packet_AppendBytes(rsp, outPrivate->buffer, outPrivate->size);

            /* outPublic */
            outPub->size = 0;
            XMEMCPY(&outPub->publicArea, &inPublic->publicArea,
                sizeof(TPMT_PUBLIC));
            TPM2_Packet_AppendPublic(rsp, outPub);

            /* name */
            TPM2_Packet_AppendU16(rsp, obj->name.size);
            TPM2_Packet_AppendBytes(rsp, obj->name.name, obj->name.size);

        FwRspParamsEnd(rsp, cmdTag, paramSzPos, paramStart);
    }

    if (rc != 0 && obj != NULL) {
        FwFreeObject(obj);
    }

    TPM2_ForceZero(&userAuth, sizeof(userAuth));
    TPM2_ForceZero(sensData, FWTPM_SIZEOF_BUF(sensData, FWTPM_MAX_DATA_BUF));
    FWTPM_FREE_BUF(sensData);
    /* outPrivate is the wrapped (HMAC-protected) private blob, not raw key
     * material — XFREE alone is sufficient. */
    TPM2_ForceZero(privKeyDer, FWTPM_MAX_PRIVKEY_DER);
    FWTPM_FREE_BUF(privKeyDer);
    FWTPM_FREE_VAR(inPublic);
    FWTPM_FREE_VAR(outPrivate);
    FWTPM_FREE_VAR(outPub);
    return rc;
}


/* --- TPM2_Sign (CC 0x015D) --- */
static TPM_RC FwCmd_Sign(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 keyHandle = 0;
    TPM2B_DIGEST digest;
    UINT16 sigScheme = 0;
    UINT16 sigHashAlg = 0;
    UINT16 vdSz = 0;
    UINT16 ticketTag = 0;
    UINT32 ticketHier = 0;
    byte ticketDigest[TPM_MAX_DIGEST_SIZE];
    byte expectedHmac[TPM_MAX_DIGEST_SIZE];
    int expectedSz = 0;
    int ticketSupplied = 0;
    FWTPM_Object* obj = NULL;
    int paramSzPos = 0;
    int paramStart = 0;

    if (cmdSize < TPM2_HEADER_SIZE + 4) {
        rc = TPM_RC_COMMAND_SIZE;
    }

    if (rc == 0) {
        TPM2_Packet_ParseU32(cmd, &keyHandle);

        obj = FwFindObject(ctx, keyHandle);
        if (obj == NULL)
            rc = TPM_RC_HANDLE;
    }
    /* Verify key has sign attribute */
    if (rc == 0) {
        if (!(obj->pub.objectAttributes & TPMA_OBJECT_sign))
            rc = TPM_RC_KEY;
    }

    /* Skip auth area */
    if (rc == 0 && cmdTag == TPM_ST_SESSIONS) {
        if (cmd->pos + 4 > cmdSize)
            rc = TPM_RC_COMMAND_SIZE;
        if (rc == 0) rc = FwSkipAuthArea(cmd, cmdSize);
    }

    /* Parse digest */
    if (rc == 0) {
        XMEMSET(&digest, 0, sizeof(digest));
        if (cmd->pos + 2 > cmdSize)
            rc = TPM_RC_COMMAND_SIZE;
    }
    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &digest.size);
        if (digest.size > sizeof(digest.buffer))
            rc = TPM_RC_SIZE;
    }
    if (rc == 0) {
        if (cmd->pos + digest.size > cmdSize)
            rc = TPM_RC_COMMAND_SIZE;
    }
    if (rc == 0) {
        TPM2_Packet_ParseBytes(cmd, digest.buffer, digest.size);
    }

    /* Parse inScheme */
    if (rc == 0) {
        if (cmd->pos + 2 > cmdSize)
            rc = TPM_RC_COMMAND_SIZE;
    }
    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &sigScheme);
        sigHashAlg = TPM_ALG_NULL;
        if (sigScheme != TPM_ALG_NULL) {
            if (cmd->pos + 2 > cmdSize)
                rc = TPM_RC_COMMAND_SIZE;
            if (rc == 0)
                TPM2_Packet_ParseU16(cmd, &sigHashAlg);
        }
    }

    if (rc == 0) {
        /* Use key's scheme if command scheme is NULL */
        FwResolveSignScheme(obj, &sigScheme, &sigHashAlg);
    }

    /* Parse validation ticket (TPMT_TK_HASHCHECK) */
    if (rc == 0) {
        if (cmd->pos + 8 > cmdSize) {
            rc = TPM_RC_COMMAND_SIZE;
        }
    }
    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &ticketTag);
        TPM2_Packet_ParseU32(cmd, &ticketHier);
        TPM2_Packet_ParseU16(cmd, &vdSz);
        if (vdSz > sizeof(ticketDigest)) {
            rc = TPM_RC_SIZE;
        }
        else if (vdSz > 0) {
            if (cmd->pos + vdSz > cmdSize) {
                rc = TPM_RC_COMMAND_SIZE;
            }
            else {
                TPM2_Packet_ParseBytes(cmd, ticketDigest, vdSz);
            }
        }
    }

    /* Validate TK_HASHCHECK ticket per TPM 2.0 Part 3 Section 18.7 / 12.4:
     *   - Restricted signing keys REQUIRE a valid ticket.
     *   - For any key, if a ticket is supplied, it must verify. */
    if (rc == 0) {
        ticketSupplied = (ticketHier != TPM_RH_NULL && vdSz > 0);
        if ((obj->pub.objectAttributes & TPMA_OBJECT_restricted) &&
                !ticketSupplied) {
            rc = TPM_RC_TICKET;
        }
    }
    if (rc == 0 && ticketSupplied) {
        if (ticketTag != TPM_ST_HASHCHECK) {
            rc = TPM_RC_TICKET;
        }
    }
    if (rc == 0 && ticketSupplied) {
        rc = FwComputeTicketHmac(ctx, ticketHier, obj->pub.nameAlg,
            digest.buffer, digest.size, expectedHmac, &expectedSz);
        if (rc != 0 || vdSz != (UINT16)expectedSz ||
                TPM2_ConstantCompare(ticketDigest, expectedHmac,
                    (word32)expectedSz) != 0) {
            rc = TPM_RC_TICKET;
        }
        TPM2_ForceZero(expectedHmac, sizeof(expectedHmac));
    }

#ifdef DEBUG_WOLFTPM
    if (rc == 0) {
        printf("fwTPM: Sign(handle=0x%x, scheme=0x%x, hash=0x%x, "
            "digestSz=%d)\n", keyHandle, sigScheme, sigHashAlg, digest.size);
    }
#endif

    if (rc == 0) {
        /* parameterSize */
        paramStart = FwRspParamsBegin(rsp, cmdTag, &paramSzPos);

        rc = FwSignDigestAndAppend(ctx, obj, sigScheme, sigHashAlg,
            digest.buffer, digest.size, rsp);
    }

    if (rc == 0) {
        FwRspParamsEnd(rsp, cmdTag, paramSzPos, paramStart);
    }
    return rc;
}


static TPM_RC FwCmd_VerifySignature(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 keyHandle = 0;
    TPM2B_DIGEST digest;
    TPMT_SIGNATURE sig;
    FWTPM_Object* obj = NULL;
    int paramSzPos = 0;
    int paramStart = 0;

    if (cmdSize < TPM2_HEADER_SIZE + 4) {
        rc = TPM_RC_COMMAND_SIZE;
    }

    if (rc == 0) {
        TPM2_Packet_ParseU32(cmd, &keyHandle);

        obj = FwFindObject(ctx, keyHandle);
        if (obj == NULL)
            rc = TPM_RC_HANDLE;
    }

    /* Skip auth area */
    if (rc == 0 && cmdTag == TPM_ST_SESSIONS) {
        if (cmd->pos + 4 > cmdSize)
            rc = TPM_RC_COMMAND_SIZE;
        if (rc == 0) rc = FwSkipAuthArea(cmd, cmdSize);
    }

    /* Parse digest */
    if (rc == 0) {
        XMEMSET(&digest, 0, sizeof(digest));
        if (cmd->pos + 2 > cmdSize)
            rc = TPM_RC_COMMAND_SIZE;
    }
    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &digest.size);
        if (digest.size > sizeof(digest.buffer))
            rc = TPM_RC_SIZE;
    }
    if (rc == 0) {
        TPM2_Packet_ParseBytes(cmd, digest.buffer, digest.size);
    }

    /* Parse signature */
    if (rc == 0) {
        XMEMSET(&sig, 0, sizeof(sig));
        TPM2_Packet_ParseSignature(cmd, &sig);
    }

#ifdef DEBUG_WOLFTPM
    if (rc == 0) {
        printf("fwTPM: VerifySignature(handle=0x%x, sigAlg=0x%x)\n",
            keyHandle, sig.sigAlg);
    }
#endif

    if (rc == 0) {
        /* parameterSize */
        paramStart = FwRspParamsBegin(rsp, cmdTag, &paramSzPos);

        rc = FwVerifySignatureCore(obj, digest.buffer, digest.size, &sig);
    }

    if (rc == 0) {
        /* Validation ticket: HMAC(proofValue, digest || keyName) */
        UINT32 ticketHier = TPM_RH_OWNER;
        byte ticketData[TPM_MAX_DIGEST_SIZE + sizeof(TPM2B_NAME)];
        int ticketDataSz = 0;

        if (obj->name.size == 0) {
            FwComputeObjectName(obj);
        }
        XMEMCPY(ticketData, digest.buffer, digest.size);
        ticketDataSz = digest.size;
        XMEMCPY(ticketData + ticketDataSz, obj->name.name, obj->name.size);
        ticketDataSz += obj->name.size;

        rc = FwAppendTicket(ctx, rsp, TPM_ST_VERIFIED,
            ticketHier, obj->pub.nameAlg, ticketData, ticketDataSz);

        if (rc == 0) {
            FwRspParamsEnd(rsp, cmdTag, paramSzPos, paramStart);
        }
    }
    return rc;
}

#ifndef NO_RSA
/* --- TPM2_RSA_Encrypt (CC 0x0174) --- */
static TPM_RC FwCmd_RSA_Encrypt(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 keyHandle;
    FWTPM_DECLARE_VAR(message, TPM2B_PUBLIC_KEY_RSA);
    UINT16 encScheme, encHashAlg;
    UINT16 labelSize;
    FWTPM_Object* obj = NULL;
    FWTPM_DECLARE_VAR(rsaKey, RsaKey);
    int rsaKeyInit = 0;
    FWTPM_DECLARE_BUF(outBuf, FWTPM_MAX_PUB_BUF);
    int outSz = 0;
    int paramSzPos, paramStart;

    FWTPM_ALLOC_VAR(rsaKey, RsaKey);
    FWTPM_CALLOC_VAR(message, TPM2B_PUBLIC_KEY_RSA);
    FWTPM_ALLOC_BUF(outBuf, FWTPM_MAX_PUB_BUF);

    if (cmdSize < TPM2_HEADER_SIZE + 4) {
        rc = TPM_RC_COMMAND_SIZE;
    }

    if (rc == 0) {
        TPM2_Packet_ParseU32(cmd, &keyHandle);

        obj = FwFindObject(ctx, keyHandle);
        if (obj == NULL) {
            rc = TPM_RC_HANDLE;
        }
    }
    if (rc == 0) {
        if (obj->pub.type != TPM_ALG_RSA) {
            rc = TPM_RC_KEY;
        }
    }
    /* Verify key has decrypt attribute (encrypt uses public portion) */
    if (rc == 0) {
        if (!(obj->pub.objectAttributes & TPMA_OBJECT_decrypt))
            rc = TPM_RC_KEY;
    }

    /* Skip auth area */
    if (rc == 0 && cmdTag == TPM_ST_SESSIONS) {
        rc = FwSkipAuthArea(cmd, cmdSize);
    }

    /* Parse message */
    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &message->size);
        if (message->size > sizeof(message->buffer)) {
            rc = TPM_RC_SIZE;
        }
        else if (cmd->pos + message->size > cmdSize) {
            rc = TPM_RC_COMMAND_SIZE;
        }
    }
    if (rc == 0) {
        TPM2_Packet_ParseBytes(cmd, message->buffer, message->size);

        /* Parse inScheme */
        TPM2_Packet_ParseU16(cmd, &encScheme);
        encHashAlg = TPM_ALG_NULL;
        if (encScheme != TPM_ALG_NULL && encScheme != TPM_ALG_RSAES) {
            TPM2_Packet_ParseU16(cmd, &encHashAlg);
        }

        /* Parse label */
        TPM2_Packet_ParseU16(cmd, &labelSize);
        if (cmd->pos + labelSize > cmdSize) {
            rc = TPM_RC_COMMAND_SIZE;
        }
        else {
            cmd->pos += labelSize;
        }

        if (rc == 0 && encScheme == TPM_ALG_NULL) {
            /* Use the key's scheme if set, otherwise keep NULL */
            if (obj->pub.parameters.rsaDetail.scheme.scheme != TPM_ALG_NULL) {
                encScheme = obj->pub.parameters.rsaDetail.scheme.scheme;
            }
        }

    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: RSA_Encrypt(handle=0x%x, scheme=0x%x, msgSz=%d)\n",
            keyHandle, encScheme, message->size);
    #endif
    }

    /* Import key (can use private or public) */
    if (rc == 0) {
        rc = FwImportRsaKey(obj, rsaKey);
        if (rc != 0) {
            rc = TPM_RC_FAILURE;
        }
        else {
            rsaKeyInit = 1;
        }
    }

    if (rc == 0) {
        if (encScheme == TPM_ALG_OAEP) {
            TPMI_ALG_HASH oaepHash = (encHashAlg != TPM_ALG_NULL) ?
                encHashAlg : (TPMI_ALG_HASH)TPM_ALG_SHA256;
            int wcHashType = FwGetRsaHashOid(oaepHash);
            outSz = wc_RsaPublicEncrypt_ex(message->buffer, message->size,
                outBuf, (word32)FWTPM_MAX_PUB_BUF, rsaKey, &ctx->rng,
                WC_RSA_OAEP_PAD, (enum wc_HashType)wcHashType,
                FwGetMgfType(oaepHash),
                NULL, 0);
        }
        else if (encScheme == TPM_ALG_NULL) {
            /* Raw RSA (no padding) */
        #ifdef WC_RSA_NO_PADDING
            outSz = wc_RsaPublicEncrypt_ex(message->buffer, message->size,
                outBuf, (word32)FWTPM_MAX_PUB_BUF, rsaKey, &ctx->rng,
                WC_RSA_NO_PAD, WC_HASH_TYPE_NONE, 0, NULL, 0);
        #else
            rc = TPM_RC_SCHEME;
        #endif
        }
        else {
            /* RSAES PKCS1 v1.5 */
            outSz = wc_RsaPublicEncrypt(message->buffer, message->size,
                outBuf, (word32)FWTPM_MAX_PUB_BUF, rsaKey, &ctx->rng);
        }
        if (outSz < 0) {
            rc = TPM_RC_FAILURE;
        }
    }

    if (rc == 0) {
        /* parameterSize */
        paramStart = FwRspParamsBegin(rsp, cmdTag, &paramSzPos);

        TPM2_Packet_AppendU16(rsp, (UINT16)outSz);
        TPM2_Packet_AppendBytes(rsp, outBuf, outSz);

        FwRspParamsEnd(rsp, cmdTag, paramSzPos, paramStart);
    }

    if (rsaKeyInit) {
        wc_FreeRsaKey(rsaKey);
    }
    FWTPM_FREE_VAR(rsaKey);
    FWTPM_FREE_VAR(message);
    TPM2_ForceZero(outBuf, FWTPM_MAX_PUB_BUF);
    FWTPM_FREE_BUF(outBuf);
    return rc;
}

/* --- TPM2_RSA_Decrypt (CC 0x0159) --- */
static TPM_RC FwCmd_RSA_Decrypt(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 keyHandle;
    FWTPM_DECLARE_VAR(cipherText, TPM2B_PUBLIC_KEY_RSA);
    UINT16 decScheme, decHashAlg;
    UINT16 labelSize;
    FWTPM_Object* obj = NULL;
    FWTPM_DECLARE_VAR(rsaKey, RsaKey);
    int rsaKeyInit = 0;
    FWTPM_DECLARE_BUF(outBuf, FWTPM_MAX_PUB_BUF);
    int outSz = 0;
    int paramSzPos, paramStart;

    FWTPM_ALLOC_VAR(rsaKey, RsaKey);
    FWTPM_CALLOC_VAR(cipherText, TPM2B_PUBLIC_KEY_RSA);
    FWTPM_ALLOC_BUF(outBuf, FWTPM_MAX_PUB_BUF);

    if (cmdSize < TPM2_HEADER_SIZE + 4) {
        rc = TPM_RC_COMMAND_SIZE;
    }

    if (rc == 0) {
        TPM2_Packet_ParseU32(cmd, &keyHandle);

        obj = FwFindObject(ctx, keyHandle);
        if (obj == NULL) {
            rc = TPM_RC_HANDLE;
        }
    }
    if (rc == 0) {
        if (obj->pub.type != TPM_ALG_RSA) {
            rc = TPM_RC_KEY;
        }
    }
    /* Verify key has decrypt attribute */
    if (rc == 0) {
        if (!(obj->pub.objectAttributes & TPMA_OBJECT_decrypt))
            rc = TPM_RC_KEY;
    }
    if (rc == 0) {
        if (obj->privKeySize == 0) {
            rc = TPM_RC_KEY; /* need private key */
        }
    }

    /* Skip auth area */
    if (rc == 0 && cmdTag == TPM_ST_SESSIONS) {
        rc = FwSkipAuthArea(cmd, cmdSize);
    }

    /* Parse cipherText */
    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &cipherText->size);
        if (cipherText->size > sizeof(cipherText->buffer)) {
            rc = TPM_RC_SIZE;
        }
    }
    if (rc == 0) {
        TPM2_Packet_ParseBytes(cmd, cipherText->buffer, cipherText->size);

        /* Parse inScheme */
        TPM2_Packet_ParseU16(cmd, &decScheme);
        decHashAlg = TPM_ALG_NULL;
        if (decScheme != TPM_ALG_NULL && decScheme != TPM_ALG_RSAES) {
            TPM2_Packet_ParseU16(cmd, &decHashAlg);
        }

        /* Parse label */
        TPM2_Packet_ParseU16(cmd, &labelSize);
        if (cmd->pos + labelSize > cmdSize) {
            rc = TPM_RC_COMMAND_SIZE;
        }
        else {
            cmd->pos += labelSize;
        }

        if (rc == 0 && decScheme == TPM_ALG_NULL) {
            if (obj->pub.parameters.rsaDetail.scheme.scheme != TPM_ALG_NULL) {
                decScheme = obj->pub.parameters.rsaDetail.scheme.scheme;
            }
        }

    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: RSA_Decrypt(handle=0x%x, scheme=0x%x, ctSz=%d)\n",
            keyHandle, decScheme, cipherText->size);
    #endif
    }

    if (rc == 0) {
        rc = FwImportRsaKeyFromDer(obj, rsaKey);
        if (rc != 0) {
            rc = TPM_RC_FAILURE;
        }
        else {
            rsaKeyInit = 1;
            wc_RsaSetRNG(rsaKey, &ctx->rng);
        }
    }

    if (rc == 0) {
        if (decScheme == TPM_ALG_OAEP) {
            TPMI_ALG_HASH oaepHash = (decHashAlg != TPM_ALG_NULL) ?
                decHashAlg : (TPMI_ALG_HASH)TPM_ALG_SHA256;
            int wcHashType = FwGetRsaHashOid(oaepHash);
            outSz = wc_RsaPrivateDecrypt_ex(cipherText->buffer, cipherText->size,
                outBuf, (word32)FWTPM_MAX_PUB_BUF, rsaKey,
                WC_RSA_OAEP_PAD, (enum wc_HashType)wcHashType,
                FwGetMgfType(oaepHash),
                NULL, 0);
        }
        else if (decScheme == TPM_ALG_NULL) {
            /* Raw RSA (no padding) */
        #ifdef WC_RSA_NO_PADDING
            outSz = wc_RsaPrivateDecrypt_ex(cipherText->buffer, cipherText->size,
                outBuf, (word32)FWTPM_MAX_PUB_BUF, rsaKey,
                WC_RSA_NO_PAD, WC_HASH_TYPE_NONE, 0, NULL, 0);
        #else
            rc = TPM_RC_SCHEME;
        #endif
        }
        else {
            /* RSAES PKCS1 v1.5 */
            outSz = wc_RsaPrivateDecrypt(cipherText->buffer, cipherText->size,
                outBuf, (word32)FWTPM_MAX_PUB_BUF, rsaKey);
        }
        if (outSz < 0) {
            rc = TPM_RC_FAILURE;
        }
    }

    if (rc == 0) {
        /* parameterSize */
        paramStart = FwRspParamsBegin(rsp, cmdTag, &paramSzPos);

        TPM2_Packet_AppendU16(rsp, (UINT16)outSz);
        TPM2_Packet_AppendBytes(rsp, outBuf, outSz);

        FwRspParamsEnd(rsp, cmdTag, paramSzPos, paramStart);
    }

    if (rsaKeyInit) {
        wc_FreeRsaKey(rsaKey);
    }
    FWTPM_FREE_VAR(rsaKey);
    FWTPM_FREE_VAR(cipherText);
    TPM2_ForceZero(outBuf, FWTPM_MAX_PUB_BUF);
    FWTPM_FREE_BUF(outBuf);
    return rc;
}
#endif /* !NO_RSA */

/* ================================================================== */
/* Hash, HMAC, HashSequence, ECDH                                     */
/* ================================================================== */

/* --- TPM2_Hash (CC 0x017D) --- */
static TPM_RC FwCmd_Hash(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT16 dataSize = 0;
    TPMI_ALG_HASH hashAlg;
    UINT32 hierarchy;
    FWTPM_DECLARE_BUF(dataBuf, FWTPM_MAX_DATA_BUF);
    byte digest[TPM_MAX_DIGEST_SIZE];
    int digestSz = 0;
    enum wc_HashType wcHash;
    int paramSzPos, paramStart;
    int trc;

    FWTPM_ALLOC_BUF(dataBuf, FWTPM_MAX_DATA_BUF);

    (void)ctx;
    if (cmdSize < TPM2_HEADER_SIZE + 2) {
        rc = TPM_RC_COMMAND_SIZE;
    }

    /* No handles, no auth area for Hash */

    /* Parse data (TPM2B_MAX_BUFFER) */
    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &dataSize);
        if (dataSize > (UINT16)FWTPM_MAX_DATA_BUF) {
            rc = TPM_RC_SIZE;
        }
    }
    if (rc == 0 && cmd->pos + dataSize > cmdSize) {
        rc = TPM_RC_COMMAND_SIZE;
    }
    if (rc == 0) {
        TPM2_Packet_ParseBytes(cmd, dataBuf, dataSize);

        /* Parse hashAlg */
        TPM2_Packet_ParseU16(cmd, (UINT16*)&hashAlg);

        /* Parse hierarchy (ignored for simple hash) */
        TPM2_Packet_ParseU32(cmd, &hierarchy);

        wcHash = FwGetWcHashType(hashAlg);
        if (wcHash == WC_HASH_TYPE_NONE) {
            rc = TPM_RC_HASH;
        }
    }

    if (rc == 0) {
        digestSz = TPM2_GetHashDigestSize(hashAlg);
        if (digestSz <= 0) {
            rc = TPM_RC_HASH;
        }
    }

    if (rc == 0) {
        rc = wc_Hash(wcHash, dataBuf, dataSize, digest, digestSz);
        if (rc != 0) {
            rc = TPM_RC_FAILURE;
        }
    }

    if (rc == 0) {
        /* Build response */
        paramStart = FwRspParamsBegin(rsp, cmdTag, &paramSzPos);

        /* outHash (TPM2B_DIGEST) */
        TPM2_Packet_AppendU16(rsp, (UINT16)digestSz);
        TPM2_Packet_AppendBytes(rsp, digest, digestSz);

        /* validation (TPMT_TK_HASHCHECK) */
        trc = FwAppendTicket(ctx, rsp, TPM_ST_HASHCHECK,
            hierarchy, hashAlg, digest, digestSz);
        if (trc != 0) rc = TPM_RC_FAILURE;

        FwRspParamsEnd(rsp, cmdTag, paramSzPos, paramStart);
    }

    TPM2_ForceZero(digest, sizeof(digest));
    FWTPM_FREE_BUF(dataBuf);
    return rc;
}

/* --- TPM2_HMAC (CC 0x0155) --- */
static TPM_RC FwCmd_HMAC(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 keyHandle;
    UINT16 dataSize = 0;
    TPMI_ALG_HASH hashAlg = TPM_ALG_NULL;
    FWTPM_DECLARE_BUF(dataBuf, FWTPM_MAX_DATA_BUF);
    byte digest[TPM_MAX_DIGEST_SIZE];
    int digestSz = 0;
    FWTPM_Object* obj;
    FWTPM_DECLARE_VAR(hmac, Hmac);
    int wcHashType = WC_HASH_TYPE_NONE;
    int paramSzPos, paramStart;
    enum wc_HashType ht;

    FWTPM_ALLOC_BUF(dataBuf, FWTPM_MAX_DATA_BUF);
    FWTPM_ALLOC_VAR(hmac, Hmac);

    if (cmdSize < TPM2_HEADER_SIZE + 4) {
        rc = TPM_RC_COMMAND_SIZE;
    }

    /* Parse handle */
    if (rc == 0) {
        TPM2_Packet_ParseU32(cmd, &keyHandle);

        obj = FwFindObject(ctx, keyHandle);
        if (obj == NULL) {
            rc = TPM_RC_HANDLE;
        }
    }
    /* Verify key has sign attribute for HMAC */
    if (rc == 0) {
        if (!(obj->pub.objectAttributes & TPMA_OBJECT_sign))
            rc = TPM_RC_KEY;
    }

    /* Skip auth area */
    if (rc == 0 && cmdTag == TPM_ST_SESSIONS) {
        rc = FwSkipAuthArea(cmd, cmdSize);
    }

    /* Parse data (TPM2B_MAX_BUFFER) */
    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &dataSize);
        if (dataSize > (UINT16)FWTPM_MAX_DATA_BUF) {
            rc = TPM_RC_SIZE;
        }
    }
    if (rc == 0 && cmd->pos + dataSize > cmdSize) {
        rc = TPM_RC_COMMAND_SIZE;
    }
    if (rc == 0) {
        TPM2_Packet_ParseBytes(cmd, dataBuf, dataSize);

        /* Parse hashAlg */
        TPM2_Packet_ParseU16(cmd, (UINT16*)&hashAlg);

        /* If hashAlg is NULL, use the key's nameAlg */
        if (hashAlg == TPM_ALG_NULL) {
            hashAlg = obj->pub.nameAlg;
        }

        ht = FwGetWcHashType(hashAlg);
        wcHashType = (int)ht;
        if (wcHashType == WC_HASH_TYPE_NONE) {
            rc = TPM_RC_HASH;
        }
    }

    if (rc == 0) {
        digestSz = TPM2_GetHashDigestSize(hashAlg);
        if (digestSz <= 0) {
            rc = TPM_RC_HASH;
        }
    }

    /* For KEYEDHASH objects the HMAC key is in privKey.
     * For other object types fall back to authValue. */
    if (rc == 0) {
        if (obj->pub.type == TPM_ALG_KEYEDHASH && obj->privKeySize > 0) {
            rc = wc_HmacSetKey(hmac, wcHashType,
                obj->privKey, (word32)obj->privKeySize);
        }
        else {
            rc = wc_HmacSetKey(hmac, wcHashType,
                obj->authValue.buffer, obj->authValue.size);
        }
    }
    if (rc == 0) {
        rc = wc_HmacUpdate(hmac, dataBuf, dataSize);
    }
    if (rc == 0) {
        rc = wc_HmacFinal(hmac, digest);
    }
    if (rc != 0 && rc != TPM_RC_COMMAND_SIZE && rc != TPM_RC_HANDLE &&
        rc != TPM_RC_SIZE && rc != TPM_RC_HASH) {
        rc = TPM_RC_FAILURE;
    }

    if (rc == 0) {
        /* Build response */
        paramStart = FwRspParamsBegin(rsp, cmdTag, &paramSzPos);

        /* outHMAC (TPM2B_DIGEST) */
        TPM2_Packet_AppendU16(rsp, (UINT16)digestSz);
        TPM2_Packet_AppendBytes(rsp, digest, digestSz);

        FwRspParamsEnd(rsp, cmdTag, paramSzPos, paramStart);
    }

    TPM2_ForceZero(digest, sizeof(digest));
    FWTPM_FREE_BUF(dataBuf);
    FWTPM_FREE_VAR(hmac);
    return rc;
}

/* --- Hash Sequence helpers --- */
static FWTPM_HashSeq* FwAllocHashSeq(FWTPM_CTX* ctx, TPM_HANDLE* handle)
{
    int i;
    for (i = 0; i < FWTPM_MAX_HASH_SEQ; i++) {
        if (!ctx->hashSeq[i].used) {
            ctx->hashSeq[i].used = 1;
            ctx->hashSeq[i].handle = TRANSIENT_FIRST +
                FWTPM_MAX_OBJECTS + (TPM_HANDLE)i;
            *handle = ctx->hashSeq[i].handle;
            return &ctx->hashSeq[i];
        }
    }
    return NULL;
}

static FWTPM_HashSeq* FwFindHashSeq(FWTPM_CTX* ctx, TPM_HANDLE handle)
{
    int i;
    for (i = 0; i < FWTPM_MAX_HASH_SEQ; i++) {
        if (ctx->hashSeq[i].used && ctx->hashSeq[i].handle == handle) {
            return &ctx->hashSeq[i];
        }
    }
    return NULL;
}

static void FwFreeHashSeq(FWTPM_HashSeq* seq)
{
    if (seq->isHmac) {
        wc_HmacFree(&seq->ctx.hmac);
    }
    else {
        wc_HashFree(&seq->ctx.hash, FwGetWcHashType(seq->hashAlg));
    }
    XMEMSET(seq, 0, sizeof(*seq));
}

/* --- TPM2_HMAC_Start (CC 0x015B) --- */
/* Starts an HMAC sequence using a loaded KEYEDHASH key. */
static TPM_RC FwCmd_HMAC_Start(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 keyHandle;
    TPM2B_AUTH auth;
    TPMI_ALG_HASH hashAlg;
    FWTPM_Object* obj;
    FWTPM_HashSeq* seq = NULL;
    TPM_HANDLE seqHandle = 0;
    enum wc_HashType wcHashType;

    (void)cmdSize;

    /* Parse keyHandle */
    TPM2_Packet_ParseU32(cmd, &keyHandle);

    /* Find loaded KEYEDHASH object */
    obj = FwFindObject(ctx, keyHandle);
    if (obj == NULL) {
        rc = TPM_RC_HANDLE;
    }
    if (rc == 0 && obj->pub.type != TPM_ALG_KEYEDHASH) {
        rc = TPM_RC_TYPE;
    }
    /* Verify key has sign attribute for HMAC */
    if (rc == 0) {
        if (!(obj->pub.objectAttributes & TPMA_OBJECT_sign))
            rc = TPM_RC_KEY;
    }

    /* Skip auth area */
    if (rc == 0 && cmdTag == TPM_ST_SESSIONS) {
        rc = FwSkipAuthArea(cmd, cmdSize);
    }

    /* Parse auth (TPM2B_AUTH) - auth for the sequence itself */
    if (rc == 0) {
        XMEMSET(&auth, 0, sizeof(auth));
        TPM2_Packet_ParseU16(cmd, &auth.size);
        if (auth.size > sizeof(auth.buffer)) {
            rc = TPM_RC_SIZE;
        }
        if (rc == 0 && auth.size > 0) {
            TPM2_Packet_ParseBytes(cmd, auth.buffer, auth.size);
        }
    }

    /* Parse hashAlg */
    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, (UINT16*)&hashAlg);

        wcHashType = FwGetWcHashType(hashAlg);
        if (wcHashType == WC_HASH_TYPE_NONE) {
            rc = TPM_RC_HASH;
        }
    }

    if (rc == 0) {
        seq = FwAllocHashSeq(ctx, &seqHandle);
        if (seq == NULL) {
            rc = TPM_RC_OBJECT_MEMORY;
        }
    }

    if (rc == 0) {
        seq->hashAlg = hashAlg;
        seq->isHmac = 1;
        XMEMCPY(&seq->authValue, &auth, sizeof(TPM2B_AUTH));

        /* Initialize HMAC with the KEYEDHASH key material */
        rc = wc_HmacSetKey(&seq->ctx.hmac, wcHashType,
            obj->privKey, (word32)obj->privKeySize);
        if (rc != 0) {
            rc = TPM_RC_FAILURE;
        }
    }

    if (rc == 0) {
    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: HMAC_Start(key=0x%x, hashAlg=0x%x) -> seqHandle=0x%x\n",
            keyHandle, hashAlg, seqHandle);
    #endif

        /* Response: sequenceHandle (output handle) */
        TPM2_Packet_AppendU32(rsp, seqHandle);

        FwRspNoParams(rsp, cmdTag);
    }

    if (rc != 0 && seq != NULL) {
        FwFreeHashSeq(seq);
    }

    return rc;
}

/* --- TPM2_HashSequenceStart (CC 0x0186) --- */
static TPM_RC FwCmd_HashSequenceStart(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT16 authSize;
    TPM2B_AUTH auth;
    TPMI_ALG_HASH hashAlg;
    FWTPM_HashSeq* seq = NULL;
    TPM_HANDLE seqHandle = 0;
    enum wc_HashType wcHash;

    (void)cmdSize;

    /* Parse auth (TPM2B_AUTH) */
    XMEMSET(&auth, 0, sizeof(auth));
    TPM2_Packet_ParseU16(cmd, &authSize);
    if (authSize > sizeof(auth.buffer)) {
        rc = TPM_RC_SIZE;
    }
    if (rc == 0) {
        auth.size = authSize;
        if (authSize > 0) {
            TPM2_Packet_ParseBytes(cmd, auth.buffer, authSize);
        }

        /* Parse hashAlg */
        TPM2_Packet_ParseU16(cmd, (UINT16*)&hashAlg);

        wcHash = FwGetWcHashType(hashAlg);
        if (wcHash == WC_HASH_TYPE_NONE) {
            rc = TPM_RC_HASH;
        }
    }

    if (rc == 0) {
        seq = FwAllocHashSeq(ctx, &seqHandle);
        if (seq == NULL) {
            rc = TPM_RC_OBJECT_MEMORY;
        }
    }

    if (rc == 0) {
        seq->hashAlg = hashAlg;
        seq->isHmac = 0;
        XMEMCPY(&seq->authValue, &auth, sizeof(TPM2B_AUTH));

        rc = wc_HashInit(&seq->ctx.hash, wcHash);
        if (rc != 0) {
            rc = TPM_RC_FAILURE;
        }
    }

    if (rc == 0) {
        /* Response: sequenceHandle */
        TPM2_Packet_AppendU32(rsp, seqHandle);

        FwRspNoParams(rsp, cmdTag);
    }

    if (rc != 0 && seq != NULL) {
        FwFreeHashSeq(seq);
    }

    return rc;
}

/* --- TPM2_SequenceUpdate (CC 0x015C) --- */
static TPM_RC FwCmd_SequenceUpdate(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 seqHandle;
    UINT16 dataSize = 0;
    FWTPM_DECLARE_BUF(dataBuf, FWTPM_MAX_DATA_BUF);
    FWTPM_HashSeq* seq;

    FWTPM_ALLOC_BUF(dataBuf, FWTPM_MAX_DATA_BUF);

    if (cmdSize < TPM2_HEADER_SIZE + 4) {
        rc = TPM_RC_COMMAND_SIZE;
    }

    if (rc == 0) {
        TPM2_Packet_ParseU32(cmd, &seqHandle);

        seq = FwFindHashSeq(ctx, seqHandle);
        if (seq == NULL) {
            rc = TPM_RC_HANDLE;
        }
    }

    /* Skip auth area */
    if (rc == 0 && cmdTag == TPM_ST_SESSIONS) {
        rc = FwSkipAuthArea(cmd, cmdSize);
    }

    /* Parse buffer (TPM2B_MAX_BUFFER) */
    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &dataSize);
        if (dataSize > (UINT16)FWTPM_MAX_DATA_BUF) {
            rc = TPM_RC_SIZE;
        }
    }
    if (rc == 0 && cmd->pos + dataSize > cmdSize) {
        rc = TPM_RC_COMMAND_SIZE;
    }
    if (rc == 0) {
        TPM2_Packet_ParseBytes(cmd, dataBuf, dataSize);

        if (seq->isHmac) {
            rc = wc_HmacUpdate(&seq->ctx.hmac, dataBuf, dataSize);
        }
        else {
            rc = wc_HashUpdate(&seq->ctx.hash, FwGetWcHashType(seq->hashAlg),
                dataBuf, dataSize);
        }
        if (rc != 0) {
            rc = TPM_RC_FAILURE;
        }
    }

    if (rc == 0) {
        /* Response: no output params */
        FwRspNoParams(rsp, cmdTag);
    }

    FWTPM_FREE_BUF(dataBuf);
    return rc;
}

/* --- TPM2_SequenceComplete (CC 0x013E) --- */
static TPM_RC FwCmd_SequenceComplete(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 seqHandle;
    UINT16 dataSize = 0;
    UINT32 hierarchy;
    FWTPM_DECLARE_BUF(dataBuf, FWTPM_MAX_DATA_BUF);
    byte digest[TPM_MAX_DIGEST_SIZE];
    int digestSz = 0;
    FWTPM_HashSeq* seq = NULL;
    TPMI_ALG_HASH hashAlg = TPM_ALG_NULL;
    int paramSzPos, paramStart;
    int trc;

    FWTPM_ALLOC_BUF(dataBuf, FWTPM_MAX_DATA_BUF);

    if (cmdSize < TPM2_HEADER_SIZE + 4) {
        rc = TPM_RC_COMMAND_SIZE;
    }

    if (rc == 0) {
        TPM2_Packet_ParseU32(cmd, &seqHandle);

        seq = FwFindHashSeq(ctx, seqHandle);
        if (seq == NULL) {
            rc = TPM_RC_HANDLE;
        }
        else {
            hashAlg = seq->hashAlg;
        }
    }

    /* Skip auth area */
    if (rc == 0 && cmdTag == TPM_ST_SESSIONS) {
        rc = FwSkipAuthArea(cmd, cmdSize);
    }

    /* Parse final buffer (TPM2B_MAX_BUFFER) */
    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &dataSize);
        if (dataSize > (UINT16)FWTPM_MAX_DATA_BUF) {
            rc = TPM_RC_SIZE;
        }
    }
    if (rc == 0 && cmd->pos + dataSize > cmdSize) {
        rc = TPM_RC_COMMAND_SIZE;
    }
    if (rc == 0) {
        if (dataSize > 0) {
            TPM2_Packet_ParseBytes(cmd, dataBuf, dataSize);
        }

        /* Parse hierarchy */
        TPM2_Packet_ParseU32(cmd, &hierarchy);

        digestSz = TPM2_GetHashDigestSize(seq->hashAlg);
    }

    /* Feed final data and finalize */
    if (rc == 0) {
        if (seq->isHmac) {
            if (dataSize > 0) {
                rc = wc_HmacUpdate(&seq->ctx.hmac, dataBuf, dataSize);
                if (rc != 0) {
                    rc = TPM_RC_FAILURE;
                }
            }
            if (rc == 0) {
                rc = wc_HmacFinal(&seq->ctx.hmac, digest);
                if (rc != 0) {
                    rc = TPM_RC_FAILURE;
                }
            }
        }
        else {
            if (dataSize > 0) {
                rc = wc_HashUpdate(&seq->ctx.hash,
                    FwGetWcHashType(seq->hashAlg), dataBuf, dataSize);
                if (rc != 0) {
                    rc = TPM_RC_FAILURE;
                }
            }
            if (rc == 0) {
                rc = wc_HashFinal(&seq->ctx.hash,
                    FwGetWcHashType(seq->hashAlg), digest);
                if (rc != 0) {
                    rc = TPM_RC_FAILURE;
                }
            }
        }
    }

    if (seq != NULL) {
        FwFreeHashSeq(seq);
    }

    if (rc == 0) {
        /* Build response */
        paramStart = FwRspParamsBegin(rsp, cmdTag, &paramSzPos);

        /* result (TPM2B_DIGEST) */
        TPM2_Packet_AppendU16(rsp, (UINT16)digestSz);
        TPM2_Packet_AppendBytes(rsp, digest, digestSz);

        /* validation (TPMT_TK_HASHCHECK) */
        trc = FwAppendTicket(ctx, rsp, TPM_ST_HASHCHECK,
            hierarchy, hashAlg, digest, digestSz);
        if (trc != 0) rc = TPM_RC_FAILURE;

        FwRspParamsEnd(rsp, cmdTag, paramSzPos, paramStart);
    }

    FWTPM_FREE_BUF(dataBuf);
    return rc;
}

/* --- TPM2_EventSequenceComplete (CC 0x0185) --- */
/* Like SequenceComplete but also extends the result into a PCR.
 * Wire: pcrHandle (U32) → sequenceHandle (U32) → auth area → buffer
 * Response: TPML_DIGEST_VALUES (count + array of hashAlg + digest) */
static TPM_RC FwCmd_EventSequenceComplete(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 pcrHandle;
    UINT32 seqHandle;
    UINT16 dataSize = 0;
    FWTPM_DECLARE_BUF(dataBuf, FWTPM_MAX_DATA_BUF);
    byte digest[TPM_MAX_DIGEST_SIZE];
    int digestSz = 0;
    UINT16 seqHashAlg = 0;
    FWTPM_HashSeq* seq = NULL;
    int paramSzPos, paramStart;
    int pcrIndex;
    int bank;
    enum wc_HashType wcHash;
    byte concat[TPM_MAX_DIGEST_SIZE * 2];
    byte newPcrDigest[TPM_MAX_DIGEST_SIZE];

    FWTPM_ALLOC_BUF(dataBuf, FWTPM_MAX_DATA_BUF);

    if (cmdSize < TPM2_HEADER_SIZE + 8) {
        rc = TPM_RC_COMMAND_SIZE;
    }

    if (rc == 0) {
        TPM2_Packet_ParseU32(cmd, &pcrHandle);
        TPM2_Packet_ParseU32(cmd, &seqHandle);

        seq = FwFindHashSeq(ctx, seqHandle);
        if (seq == NULL) {
            rc = TPM_RC_HANDLE;
        }
    }

    /* Skip auth area */
    if (rc == 0 && cmdTag == TPM_ST_SESSIONS) {
        rc = FwSkipAuthArea(cmd, cmdSize);
    }

    /* Parse final buffer (TPM2B_MAX_BUFFER) */
    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &dataSize);
        if (dataSize > (UINT16)FWTPM_MAX_DATA_BUF) {
            rc = TPM_RC_SIZE;
        }
    }
    if (rc == 0 && cmd->pos + dataSize > cmdSize) {
        rc = TPM_RC_COMMAND_SIZE;
    }

    if (rc == 0) {
        if (dataSize > 0) {
            TPM2_Packet_ParseBytes(cmd, dataBuf, dataSize);
        }

        digestSz = TPM2_GetHashDigestSize(seq->hashAlg);
    }

    /* Feed final data and finalize the hash */
    if (rc == 0) {
        if (seq->isHmac) {
            if (dataSize > 0) {
                rc = wc_HmacUpdate(&seq->ctx.hmac, dataBuf, dataSize);
                if (rc != 0) {
                    rc = TPM_RC_FAILURE;
                }
            }
            if (rc == 0) {
                rc = wc_HmacFinal(&seq->ctx.hmac, digest);
                if (rc != 0) {
                    rc = TPM_RC_FAILURE;
                }
            }
        }
        else {
            if (dataSize > 0) {
                rc = wc_HashUpdate(&seq->ctx.hash,
                    FwGetWcHashType(seq->hashAlg), dataBuf, dataSize);
                if (rc != 0) {
                    rc = TPM_RC_FAILURE;
                }
            }
            if (rc == 0) {
                rc = wc_HashFinal(&seq->ctx.hash,
                    FwGetWcHashType(seq->hashAlg), digest);
                if (rc != 0) {
                    rc = TPM_RC_FAILURE;
                }
            }
        }
    }

    /* Save hash alg before freeing sequence */
    if (rc == 0) {
        seqHashAlg = seq->hashAlg;
    }

    /* Extend the result into the PCR */
    if (rc == 0 && pcrHandle <= PCR_LAST) {
        pcrIndex = pcrHandle - PCR_FIRST;
        bank = FwGetPcrBankIndex(seqHashAlg);
        if (bank >= 0 && digestSz > 0) {
            wcHash = FwGetWcHashType(seqHashAlg);
            XMEMCPY(concat, ctx->pcrDigest[pcrIndex][bank], digestSz);
            XMEMCPY(concat + digestSz, digest, digestSz);
            if (wc_Hash(wcHash, concat, digestSz * 2,
                    newPcrDigest, digestSz) == 0) {
                XMEMCPY(ctx->pcrDigest[pcrIndex][bank],
                    newPcrDigest, digestSz);
                ctx->pcrUpdateCounter++;
            }
        }
    }

    if (seq != NULL) {
        FwFreeHashSeq(seq);
    }

    if (rc == 0) {
    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: EventSequenceComplete(pcr=%d, seq=0x%x)\n",
            pcrHandle - PCR_FIRST, seqHandle);
    #endif

        /* Build response: TPML_DIGEST_VALUES */
        paramStart = FwRspParamsBegin(rsp, cmdTag, &paramSzPos);

        /* count = 1 (only the hash alg used by the sequence) */
        TPM2_Packet_AppendU32(rsp, 1);
        /* hashAlg + digest */
        TPM2_Packet_AppendU16(rsp, seqHashAlg);
        TPM2_Packet_AppendBytes(rsp, digest, digestSz);

        FwRspParamsEnd(rsp, cmdTag, paramSzPos, paramStart);
    }

    FWTPM_FREE_BUF(dataBuf);
    return rc;
}

#ifdef HAVE_ECC
/* --- TPM2_ECDH_KeyGen (CC 0x0163) --- */
static TPM_RC FwCmd_ECDH_KeyGen(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 keyHandle;
    FWTPM_Object* obj = NULL;
    FWTPM_DECLARE_VAR(pubKey, ecc_key);
    FWTPM_DECLARE_VAR(ephKey, ecc_key);
    int pubKeyInit = 0, ephKeyInit = 0;
    int wcCurve, keySz;
    UINT16 curveId;
    byte zBuf[MAX_ECC_BYTES];
    word32 zSz;
    byte qxBuf[MAX_ECC_BYTES], qyBuf[MAX_ECC_BYTES];
    word32 qxSz, qySz;
    int paramSzPos, paramStart;
    int markPos;

    FWTPM_ALLOC_VAR(pubKey, ecc_key);
    FWTPM_ALLOC_VAR(ephKey, ecc_key);

    if (cmdSize < TPM2_HEADER_SIZE + 4) {
        rc = TPM_RC_COMMAND_SIZE;
    }

    /* Parse keyHandle (no auth for ECDH_KeyGen) */
    if (rc == 0) {
        TPM2_Packet_ParseU32(cmd, &keyHandle);

        obj = FwFindObject(ctx, keyHandle);
        if (obj == NULL) {
            rc = TPM_RC_HANDLE;
        }
    }
    if (rc == 0) {
        if (obj->pub.type != TPM_ALG_ECC) {
            rc = TPM_RC_KEY;
        }
    }

    if (rc == 0) {
        curveId = obj->pub.parameters.eccDetail.curveID;
        wcCurve = FwGetWcCurveId(curveId);
        keySz = FwGetEccKeySize(curveId);
        if (wcCurve < 0 || keySz == 0) {
            rc = TPM_RC_CURVE;
        }
    }

    /* Import the TPM key's public point */
    if (rc == 0) {
        rc = FwImportEccPubFromPublic(&obj->pub, pubKey);
        if (rc != 0) {
            rc = TPM_RC_FAILURE;
        }
        else {
            pubKeyInit = 1;
        }
    }

    /* Generate ephemeral key */
    if (rc == 0) {
        rc = wc_ecc_init(ephKey);
        if (rc != 0) {
            rc = TPM_RC_FAILURE;
        }
        else {
            ephKeyInit = 1;
            wc_ecc_set_rng(ephKey, &ctx->rng);
        }
    }
    if (rc == 0) {
        rc = wc_ecc_make_key_ex(&ctx->rng, keySz, ephKey, wcCurve);
        if (rc != 0) {
            rc = TPM_RC_FAILURE;
        }
    }

    /* Compute shared secret Z = ephPriv * pubKey */
    if (rc == 0) {
        zSz = (word32)sizeof(zBuf);
        rc = wc_ecc_shared_secret(ephKey, pubKey, zBuf, &zSz);
        if (rc != 0) {
            rc = TPM_RC_FAILURE;
        }
    }

    /* Export ephemeral public key */
    if (rc == 0) {
        qxSz = (word32)sizeof(qxBuf);
        qySz = (word32)sizeof(qyBuf);
        rc = wc_ecc_export_public_raw(ephKey, qxBuf, &qxSz, qyBuf, &qySz);
        if (rc != 0) {
            rc = TPM_RC_FAILURE;
        }
    }

    if (rc == 0) {
        /* Build response */
        paramStart = FwRspParamsBegin(rsp, cmdTag, &paramSzPos);

        /* zPoint (TPM2B_ECC_POINT) */
        TPM2_Packet_MarkU16(rsp, &markPos);
        TPM2_Packet_AppendU16(rsp, (UINT16)zSz);
        TPM2_Packet_AppendBytes(rsp, zBuf, zSz);
        TPM2_Packet_AppendU16(rsp, 0); /* y = empty for x-only */
        TPM2_Packet_PlaceU16(rsp, markPos);

        /* pubPoint (TPM2B_ECC_POINT) */
        TPM2_Packet_MarkU16(rsp, &markPos);
        TPM2_Packet_AppendU16(rsp, (UINT16)qxSz);
        TPM2_Packet_AppendBytes(rsp, qxBuf, qxSz);
        TPM2_Packet_AppendU16(rsp, (UINT16)qySz);
        TPM2_Packet_AppendBytes(rsp, qyBuf, qySz);
        TPM2_Packet_PlaceU16(rsp, markPos);

        FwRspParamsEnd(rsp, cmdTag, paramSzPos, paramStart);
    }

    TPM2_ForceZero(zBuf, sizeof(zBuf));
    if (ephKeyInit) {
        wc_ecc_free(ephKey);
    }
    if (pubKeyInit) {
        wc_ecc_free(pubKey);
    }
    FWTPM_FREE_VAR(pubKey);
    FWTPM_FREE_VAR(ephKey);
    return rc;
}

/* --- TPM2_ECDH_ZGen (CC 0x0154) --- */
static TPM_RC FwCmd_ECDH_ZGen(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 keyHandle;
    FWTPM_Object* obj = NULL;
    FWTPM_DECLARE_VAR(privKey, ecc_key);
    FWTPM_DECLARE_VAR(peerPub, ecc_key);
    int privKeyInit = 0, peerPubInit = 0;
    int wcCurve, keySz;
    UINT16 curveId;
    UINT16 inPointSize;
    FWTPM_DECLARE_VAR(inPoint, TPM2B_ECC_POINT);
    byte zBuf[MAX_ECC_BYTES];
    word32 zSz;
    int paramSzPos, paramStart;
    int markPos;

    FWTPM_ALLOC_VAR(privKey, ecc_key);
    FWTPM_ALLOC_VAR(peerPub, ecc_key);
    FWTPM_CALLOC_VAR(inPoint, TPM2B_ECC_POINT);

    if (cmdSize < TPM2_HEADER_SIZE + 4) {
        rc = TPM_RC_COMMAND_SIZE;
    }

    if (rc == 0) {
        TPM2_Packet_ParseU32(cmd, &keyHandle);

        obj = FwFindObject(ctx, keyHandle);
        if (obj == NULL) {
            rc = TPM_RC_HANDLE;
        }
    }
    if (rc == 0) {
        if (obj->pub.type != TPM_ALG_ECC) {
            rc = TPM_RC_KEY;
        }
    }
    if (rc == 0) {
        if (obj->privKeySize == 0) {
            rc = TPM_RC_KEY;
        }
    }

    /* Skip auth area */
    if (rc == 0 && cmdTag == TPM_ST_SESSIONS) {
        rc = FwSkipAuthArea(cmd, cmdSize);
    }

    /* Parse inPoint (TPM2B_ECC_POINT) */
    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &inPointSize); /* outer size */
        TPM2_Packet_ParseU16(cmd, &inPoint->point.x.size);
        if (inPoint->point.x.size > sizeof(inPoint->point.x.buffer)) {
            rc = TPM_RC_SIZE;
        }
    }
    if (rc == 0) {
        TPM2_Packet_ParseBytes(cmd, inPoint->point.x.buffer,
            inPoint->point.x.size);
        TPM2_Packet_ParseU16(cmd, &inPoint->point.y.size);
        if (inPoint->point.y.size > sizeof(inPoint->point.y.buffer)) {
            rc = TPM_RC_SIZE;
        }
    }
    if (rc == 0) {
        TPM2_Packet_ParseBytes(cmd, inPoint->point.y.buffer,
            inPoint->point.y.size);

        curveId = obj->pub.parameters.eccDetail.curveID;
        wcCurve = FwGetWcCurveId(curveId);
        keySz = FwGetEccKeySize(curveId);
        if (wcCurve < 0 || keySz == 0) {
            rc = TPM_RC_CURVE;
        }
    }

    /* Import our private key */
    if (rc == 0) {
        rc = FwImportEccKeyFromDer(obj, privKey);
        if (rc != 0) {
            rc = TPM_RC_FAILURE;
        }
        else {
            privKeyInit = 1;
            wc_ecc_set_rng(privKey, &ctx->rng);
        }
    }

    /* Import peer's public point */
    if (rc == 0) {
        rc = wc_ecc_init(peerPub);
        if (rc != 0) {
            rc = TPM_RC_FAILURE;
        }
        else {
            peerPubInit = 1;
        }
    }
    if (rc == 0) {
        rc = wc_ecc_import_unsigned(peerPub,
            inPoint->point.x.buffer, inPoint->point.y.buffer,
            NULL, wcCurve);
        if (rc != 0) {
            rc = TPM_RC_FAILURE;
        }
    }
    /* Validate peer point is on the expected curve (invalid curve attack) */
    if (rc == 0) {
        rc = wc_ecc_check_key(peerPub);
        if (rc != 0) {
            rc = TPM_RC_ECC_POINT;
        }
    }

    /* Compute shared secret */
    if (rc == 0) {
        zSz = (word32)sizeof(zBuf);
        rc = wc_ecc_shared_secret(privKey, peerPub, zBuf, &zSz);
        if (rc != 0) {
            rc = TPM_RC_FAILURE;
        }
    }

    if (rc == 0) {
        /* Build response */
        paramStart = FwRspParamsBegin(rsp, cmdTag, &paramSzPos);

        /* outPoint (TPM2B_ECC_POINT) - x-only shared secret */
        TPM2_Packet_MarkU16(rsp, &markPos);
        TPM2_Packet_AppendU16(rsp, (UINT16)zSz);
        TPM2_Packet_AppendBytes(rsp, zBuf, zSz);
        TPM2_Packet_AppendU16(rsp, 0); /* y = empty */
        TPM2_Packet_PlaceU16(rsp, markPos);

        FwRspParamsEnd(rsp, cmdTag, paramSzPos, paramStart);
    }

    TPM2_ForceZero(zBuf, sizeof(zBuf));
    if (peerPubInit) {
        wc_ecc_free(peerPub);
    }
    if (privKeyInit) {
        wc_ecc_free(privKey);
    }
    FWTPM_FREE_VAR(privKey);
    FWTPM_FREE_VAR(peerPub);
    FWTPM_FREE_VAR(inPoint);
    return rc;
}
#endif /* HAVE_ECC */

/* --- TPM2_StartAuthSession (CC 0x0176) --- */
static TPM_RC FwCmd_StartAuthSession(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 tpmKey;
    UINT32 bind;
    UINT16 nonceCallerSize = 0;
    byte nonceCaller[TPM_MAX_DIGEST_SIZE];
    UINT16 encSaltSize = 0;
    FWTPM_DECLARE_BUF(encSalt, FWTPM_MAX_PUB_BUF);
    byte salt[TPM_MAX_DIGEST_SIZE]; /* Decrypted salt */
    int saltSize = 0;
    UINT8 sessionType = 0;
    TPMT_SYM_DEF symmetric;
    UINT16 authHash = 0;
    FWTPM_Session* sess = NULL;
    TPM_HANDLE sessHandle = 0;
    int nonceSize = 0;

    FWTPM_ALLOC_BUF(encSalt, FWTPM_MAX_PUB_BUF);

    (void)cmdTag;
    (void)cmdSize;

    /* Parse: tpmKey(U32), bind(U32) */
    TPM2_Packet_ParseU32(cmd, &tpmKey);
    TPM2_Packet_ParseU32(cmd, &bind);

    /* Parse: nonceCaller (TPM2B) */
    TPM2_Packet_ParseU16(cmd, &nonceCallerSize);
    if (nonceCallerSize > sizeof(nonceCaller)) {
        rc = TPM_RC_SIZE;
    }
    if (rc == 0 && nonceCallerSize > 0) {
        TPM2_Packet_ParseBytes(cmd, nonceCaller, nonceCallerSize);
    }

    /* Parse: encryptedSalt (TPM2B) */
    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &encSaltSize);
        if (encSaltSize > FWTPM_MAX_PUB_BUF) {
            rc = TPM_RC_SIZE;
        }
        else if (encSaltSize > 0) {
            TPM2_Packet_ParseBytes(cmd, encSalt, encSaltSize);
        }
    }

    /* Parse: sessionType(U8), symmetric(TPMT_SYM_DEF), authHash(U16) */
    if (rc == 0) {
        TPM2_Packet_ParseU8(cmd, &sessionType);
        TPM2_Packet_ParseSymmetric(cmd, &symmetric);
        TPM2_Packet_ParseU16(cmd, &authHash);
    }

    /* Validate session type */
    if (rc == 0) {
        if (sessionType != TPM_SE_HMAC && sessionType != TPM_SE_POLICY &&
            sessionType != TPM_SE_TRIAL) {
            rc = TPM_RC_VALUE;
        }
    }

    /* Validate hash algorithm */
    if (rc == 0) {
        nonceSize = TPM2_GetHashDigestSize(authHash);
        if (nonceSize == 0) {
            rc = TPM_RC_HASH;
        }
    }

#ifdef DEBUG_WOLFTPM
    if (rc == 0) {
        printf("fwTPM: StartAuthSession(type=%d, hash=0x%x, tpmKey=0x%x, "
            "bind=0x%x)\n", sessionType, authHash, tpmKey, bind);
    }
#endif

    /* Allocate a session slot */
    if (rc == 0) {
        sess = FwAllocSession(ctx, (TPM_SE)sessionType, &sessHandle);
        if (sess == NULL) {
            rc = TPM_RC_SESSION_HANDLES;
        }
    }

    /* Fill session state */
    if (rc == 0) {
        sess->authHash = authHash;
#ifdef FWTPM_NO_PARAM_ENC
        /* Param encryption disabled - force symmetric to NULL.
         * Sessions still work for HMAC auth. */
        XMEMSET(&symmetric, 0, sizeof(TPMT_SYM_DEF));
        symmetric.algorithm = TPM_ALG_NULL;
#endif
        XMEMCPY(&sess->symmetric, &symmetric, sizeof(TPMT_SYM_DEF));

        /* Store caller nonce */
        sess->nonceCaller.size = nonceCallerSize;
        if (nonceCallerSize > 0) {
            XMEMCPY(sess->nonceCaller.buffer, nonceCaller, nonceCallerSize);
        }

        /* Generate TPM nonce */
        sess->nonceTPM.size = nonceSize;
        if (wc_RNG_GenerateBlock(&ctx->rng, sess->nonceTPM.buffer,
                sess->nonceTPM.size) != 0) {
            rc = TPM_RC_FAILURE;
        }
    }

    /* If tpmKey is specified, decrypt the encrypted salt */
    if (rc == 0 && tpmKey != TPM_RH_NULL && encSaltSize > 0) {
        FWTPM_Object* keyObj = FwFindObject(ctx, tpmKey);
        if (keyObj == NULL) {
            rc = TPM_RC_HANDLE;
        }
        if (rc == 0) {
            rc = FwDecryptSeed(ctx, keyObj,
                encSalt, encSaltSize,
                (const byte*)"SECRET", 7, "SECRET",
                salt, (int)sizeof(salt), &saltSize);
        }
    }

    /* Compute session key: KDFa(authHash, salt||bindAuth, "ATH",
     * nonceTPM, nonceCaller, digestSize)
     * Per TPM 2.0 Part 1 Section 19.6.8: if both tpmKey and bind are
     * TPM_RH_NULL (no salt, no bind auth) then sessionKey = {} (empty). */
    if (rc == 0) {
        byte keyIn[TPM_MAX_DIGEST_SIZE * 2]; /* salt || bindAuth */
        int keyInSz = 0;

        /* Append salt if present */
        if (saltSize > 0) {
            XMEMCPY(keyIn, salt, saltSize);
            keyInSz = saltSize;
        }
        /* Append bind entity auth if bound */
        if (bind != TPM_RH_NULL) {
            TPM2B_AUTH bindAuth;
            XMEMSET(&bindAuth, 0, sizeof(bindAuth));
            /* Hierarchy handles: use hierarchy auth from ctx */
            if (bind == TPM_RH_OWNER) {
                XMEMCPY(&bindAuth, &ctx->ownerAuth, sizeof(TPM2B_AUTH));
            }
            else if (bind == TPM_RH_ENDORSEMENT) {
                XMEMCPY(&bindAuth, &ctx->endorsementAuth, sizeof(TPM2B_AUTH));
            }
            else if (bind == TPM_RH_PLATFORM) {
                XMEMCPY(&bindAuth, &ctx->platformAuth, sizeof(TPM2B_AUTH));
            }
#ifndef FWTPM_NO_NV
            else if ((bind & 0xFF000000)
                == (NV_INDEX_FIRST & 0xFF000000)) {
                /* NV index: look up auth value from NV index slot */
                FWTPM_NvIndex* nvBind = FwFindNvIndex(ctx, bind);
                if (nvBind != NULL) {
                    XMEMCPY(&bindAuth, &nvBind->authValue, sizeof(TPM2B_AUTH));
                }
            }
#endif /* !FWTPM_NO_NV */
            else {
                FWTPM_Object* bindObj = FwFindObject(ctx, bind);
                if (bindObj != NULL) {
                    XMEMCPY(&bindAuth, &bindObj->authValue, sizeof(TPM2B_AUTH));
                }
            }
            if (bindAuth.size > sizeof(bindAuth.buffer)) {
                rc = TPM_RC_FAILURE;
            }
            if (rc == 0 && bindAuth.size > 0) {
                if (keyInSz + bindAuth.size <= (int)sizeof(keyIn)) {
                    XMEMCPY(keyIn + keyInSz, bindAuth.buffer, bindAuth.size);
                    keyInSz += bindAuth.size;
                }
            }
            TPM2_ForceZero(&bindAuth, sizeof(bindAuth));
        }

        if (keyInSz == 0) {
            /* Unsalted, unbound: sessionKey is empty per spec */
            sess->sessionKey.size = 0;
        }
        else {
            int sessKeyRc;
            sess->sessionKey.size = (UINT16)nonceSize;
            sessKeyRc = TPM2_KDFa_ex(authHash,
                keyIn, keyInSz, "ATH",
                sess->nonceTPM.buffer, sess->nonceTPM.size,
                nonceCaller, nonceCallerSize,
                sess->sessionKey.buffer, nonceSize);
            if (sessKeyRc != nonceSize) {
                rc = TPM_RC_FAILURE;
            }
        }
        TPM2_ForceZero(keyIn, sizeof(keyIn));
    }

    /* If bound to an entity, note for future bind exclusion */
    if (rc == 0 && bind != TPM_RH_NULL) {
        /* Bind entity auth is incorporated into session key via KDFa above.
         * Per TPM 2.0 Part 1 Section 19.6.8, when the session is used to
         * authorize the bound entity, authValue should be excluded from the
         * HMAC key (since it's already in the session key). */
    }

    /* Initialize policy digest to zero for policy/trial sessions */
    if (rc == 0) {
        if (sessionType == TPM_SE_POLICY || sessionType == TPM_SE_TRIAL) {
            sess->policyDigest.size = nonceSize;
            XMEMSET(sess->policyDigest.buffer, 0, nonceSize);
        }
    }

    /* Build response */
    if (rc == 0) {
        /* sessionHandle(U32) + nonceTPM(TPM2B) */
        TPM2_Packet_AppendU32(rsp, sessHandle);
        TPM2_Packet_AppendU16(rsp, sess->nonceTPM.size);
        TPM2_Packet_AppendBytes(rsp, sess->nonceTPM.buffer,
            sess->nonceTPM.size);
        FwRspFinalize(rsp, TPM_ST_NO_SESSIONS, TPM_RC_SUCCESS);
    }

    /* Cleanup on error: free session if it was allocated */
    if (rc != 0 && sess != NULL) {
        FwFreeSession(sess);
    }
    TPM2_ForceZero(salt, sizeof(salt));
    TPM2_ForceZero(encSalt, FWTPM_MAX_PUB_BUF);
    FWTPM_FREE_BUF(encSalt);
    return rc;
}

#ifndef FWTPM_NO_POLICY
/* --- TPM2_PolicyGetDigest (CC 0x0189) --- */
static TPM_RC FwCmd_PolicyGetDigest(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 sessHandle;
    FWTPM_Session* sess;
    int paramSzPos, paramStart;

    (void)cmdSize;

    /* Parse handle */
    TPM2_Packet_ParseU32(cmd, &sessHandle);

    /* Skip auth area if present (TPM_ST_SESSIONS) */
    if (cmdTag == TPM_ST_SESSIONS) rc = FwSkipAuthArea(cmd, cmdSize);

#ifdef DEBUG_WOLFTPM
    printf("fwTPM: PolicyGetDigest(session=0x%x)\n", sessHandle);
#endif

    sess = FwFindSession(ctx, sessHandle);
    if (sess == NULL) {
        rc = TPM_RC_VALUE;
    }

    /* Only policy/trial sessions have a policy digest */
    if (rc == 0 && sess->sessionType != TPM_SE_POLICY &&
        sess->sessionType != TPM_SE_TRIAL) {
        rc = TPM_RC_AUTH_TYPE;
    }

    if (rc == 0) {
        /* Build response */
        paramStart = FwRspParamsBegin(rsp, cmdTag, &paramSzPos);

        /* policyDigest (TPM2B_DIGEST) */
        TPM2_Packet_AppendU16(rsp, sess->policyDigest.size);
        TPM2_Packet_AppendBytes(rsp, sess->policyDigest.buffer,
            sess->policyDigest.size);

        FwRspParamsEnd(rsp, cmdTag, paramSzPos, paramStart);
    }

    return rc;
}

/* --- TPM2_PolicyRestart (CC 0x0180) --- */
static TPM_RC FwCmd_PolicyRestart(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 sessHandle;
    FWTPM_Session* sess;

    (void)cmdSize;
    (void)cmdTag;

    /* Parse handle */
    TPM2_Packet_ParseU32(cmd, &sessHandle);

#ifdef DEBUG_WOLFTPM
    printf("fwTPM: PolicyRestart(session=0x%x)\n", sessHandle);
#endif

    sess = FwFindSession(ctx, sessHandle);
    if (sess == NULL) {
        rc = TPM_RC_VALUE;
    }

    /* Only policy/trial sessions can be restarted */
    if (rc == 0 && sess->sessionType != TPM_SE_POLICY &&
        sess->sessionType != TPM_SE_TRIAL) {
        rc = TPM_RC_AUTH_TYPE;
    }

    if (rc == 0) {
        /* Reset policy digest to all zeros */
        XMEMSET(sess->policyDigest.buffer, 0, sess->policyDigest.size);

        /* Reset all policy-related session flags so stale assertions from
         * prior policy evaluations don't affect future HMAC computation
         * or authorization checks. */
        sess->isPasswordPolicy = 0;
        sess->isAuthValuePolicy = 0;
        sess->isPPRequired = 0;
        sess->cpHashA.size = 0;
        sess->nameHash.size = 0;

        FwRspFinalize(rsp, TPM_ST_NO_SESSIONS, TPM_RC_SUCCESS);
    }

    return rc;
}

/* --- TPM2_PolicyPCR (CC 0x017F) --- */
static TPM_RC FwCmd_PolicyPCR(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 sessHandle;
    UINT16 pcrDigestSize;
    byte pcrDigest[TPM_MAX_DIGEST_SIZE];
    TPML_PCR_SELECTION pcrs;
    FWTPM_Session* sess = NULL;
    int digestSz = 0;
    byte pcrsBuf[128]; /* Serialized PCR selection */
    TPM2_Packet tmpPkt;
    int pcrsSz = 0;
    UINT32 ccPolicyPCR = TPM_CC_PolicyPCR;
    byte ccBuf[4];
    FWTPM_DECLARE_VAR(hashCtx, wc_HashAlg);
    int hashInit = 0;
    enum wc_HashType wcHash;
    int i, j;
    int bankIdx, pcrDSz;

    (void)cmdSize;

    FWTPM_ALLOC_VAR(hashCtx, wc_HashAlg);

    /* Parse handle */
    TPM2_Packet_ParseU32(cmd, &sessHandle);

    /* Skip auth area if present */
    if (cmdTag == TPM_ST_SESSIONS) rc = FwSkipAuthArea(cmd, cmdSize);

    /* Parse pcrDigest (TPM2B) */
    TPM2_Packet_ParseU16(cmd, &pcrDigestSize);
    if (pcrDigestSize > sizeof(pcrDigest)) {
        rc = TPM_RC_SIZE;
    }
    if (rc == 0 && pcrDigestSize > 0) {
        TPM2_Packet_ParseBytes(cmd, pcrDigest, pcrDigestSize);
    }

    /* Parse PCR selection */
    if (rc == 0) {
        TPM2_Packet_ParsePCR(cmd, &pcrs);
    }

#ifdef DEBUG_WOLFTPM
    if (rc == 0) {
        printf("fwTPM: PolicyPCR(session=0x%x, digestSz=%d, pcrCount=%d)\n",
            sessHandle, pcrDigestSize, pcrs.count);
    }
#endif

    if (rc == 0) {
        sess = FwFindSession(ctx, sessHandle);
        if (sess == NULL) {
            rc = TPM_RC_VALUE;
        }
    }

    if (rc == 0) {
        if (sess->sessionType != TPM_SE_POLICY &&
            sess->sessionType != TPM_SE_TRIAL) {
            rc = TPM_RC_AUTH_TYPE;
        }
    }

    if (rc == 0) {
        digestSz = TPM2_GetHashDigestSize(sess->authHash);
        if (digestSz == 0) {
            rc = TPM_RC_HASH;
        }
    }

    /* If pcrDigest.size == 0, compute it from current PCR values */
    if (rc == 0 && pcrDigestSize == 0) {
        /* Hash together all selected PCR values */
        wcHash = FwGetWcHashType(sess->authHash);
        if (wc_HashInit_ex(hashCtx, wcHash, NULL, INVALID_DEVID) != 0) {
            rc = TPM_RC_FAILURE;
        }
        else {
            hashInit = 1;
        }
        if (rc == 0) {
            for (i = 0; i < (int)pcrs.count; i++) {
                bankIdx = FwGetPcrBankIndex(pcrs.pcrSelections[i].hash);
                pcrDSz = TPM2_GetHashDigestSize(
                    pcrs.pcrSelections[i].hash);
                if (bankIdx < 0 || pcrDSz == 0)
                    continue;
                for (j = 0; j < IMPLEMENTATION_PCR; j++) {
                    if (j / 8 < pcrs.pcrSelections[i].sizeofSelect &&
                        (pcrs.pcrSelections[i].pcrSelect[j / 8] &
                            (1 << (j % 8)))) {
                        wc_HashUpdate(hashCtx, wcHash,
                            ctx->pcrDigest[j][bankIdx], pcrDSz);
                    }
                }
            }
            pcrDigestSize = digestSz;
            wc_HashFinal(hashCtx, wcHash, pcrDigest);
        }
        if (hashInit) {
            wc_HashFree(hashCtx, wcHash);
            hashInit = 0;
        }
    }

    /* Serialize PCR selection for policy digest computation */
    if (rc == 0) {
        tmpPkt.buf = pcrsBuf;
        tmpPkt.pos = 0;
        tmpPkt.size = sizeof(pcrsBuf);
        TPM2_Packet_AppendPCR(&tmpPkt, &pcrs);
        pcrsSz = tmpPkt.pos;
    }

    /* Extend policy digest:
     * policyDigest = H(policyDigest || TPM_CC_PolicyPCR || pcrs || pcrDigest) */
    if (rc == 0) {
        wcHash = FwGetWcHashType(sess->authHash);
        if (wc_HashInit_ex(hashCtx, wcHash, NULL, INVALID_DEVID) != 0) {
            rc = TPM_RC_FAILURE;
        }
        else {
            hashInit = 1;
        }
    }

    if (rc == 0) {
        /* Old policy digest */
        wc_HashUpdate(hashCtx, wcHash,
            sess->policyDigest.buffer, sess->policyDigest.size);

        /* Command code (big-endian) */
        FwStoreU32BE(ccBuf, ccPolicyPCR);
        wc_HashUpdate(hashCtx, wcHash, ccBuf, 4);

        /* Serialized PCR selection */
        wc_HashUpdate(hashCtx, wcHash, pcrsBuf, pcrsSz);

        /* PCR digest */
        wc_HashUpdate(hashCtx, wcHash, pcrDigest, pcrDigestSize);

        wc_HashFinal(hashCtx, wcHash, sess->policyDigest.buffer);
        sess->policyDigest.size = digestSz;
    }
    if (hashInit) {
        wc_HashFree(hashCtx, wcHash);
    }

    /* No response parameters for PolicyPCR */
    if (rc == 0) {
        FwRspNoParams(rsp, cmdTag);
    }

    FWTPM_FREE_VAR(hashCtx);
    return rc;
}
#endif /* !FWTPM_NO_POLICY */

/* --- TPM2_Unseal (CC 0x015E) --- */
/* Returns the sealed data from a KEYEDHASH object created with sensitive.data.
 * Authorization is verified by the session matching the object's authPolicy. */
static TPM_RC FwCmd_Unseal(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 itemHandle;
    FWTPM_Object* obj;
    int paramSzPos, paramStart;
    (void)cmdSize;

    TPM2_Packet_ParseU32(cmd, &itemHandle);
    if (cmdTag == TPM_ST_SESSIONS) rc = FwSkipAuthArea(cmd, cmdSize);

#ifdef DEBUG_WOLFTPM
    printf("fwTPM: Unseal(handle=0x%x)\n", itemHandle);
#endif

    obj = FwFindObject(ctx, itemHandle);
    if (obj == NULL) {
        rc = TPM_RC_HANDLE;
    }

    if (rc == 0 && obj->pub.type != TPM_ALG_KEYEDHASH) {
        rc = TPM_RC_TYPE;
    }
    /* Per TPM 2.0 Part 3 Section 12.7.2: Unseal requires that the object
     * has neither sign nor decrypt attributes (sealed data, not an HMAC key) */
    if (rc == 0) {
        if (obj->pub.objectAttributes &
                (TPMA_OBJECT_sign | TPMA_OBJECT_decrypt)) {
            rc = TPM_RC_ATTRIBUTES;
        }
    }

    if (rc == 0) {
        /* Response: outData (TPM2B_SENSITIVE_DATA) = the sealed bytes */
        paramStart = FwRspParamsBegin(rsp, cmdTag, &paramSzPos);
        TPM2_Packet_AppendU16(rsp, (UINT16)obj->privKeySize);
        if (obj->privKeySize > 0) {
            TPM2_Packet_AppendBytes(rsp, obj->privKey, obj->privKeySize);
        }
        FwRspParamsEnd(rsp, cmdTag, paramSzPos, paramStart);
    }

    return rc;
}

#ifndef FWTPM_NO_POLICY
/* ================================================================== */
/* Policy Engine Commands                                              */
/* ================================================================== */

/* Helper: extend session policyDigest = H(policyDigest || cc32be || extra...) */
/* Stage 1: policyDigest = H(policyDigest || cc || name)
 * Stage 2 (if hasRef): policyDigest = H(policyDigest || policyRef)
 * Per TPM 2.0 spec Part 3, PolicyContextUpdate always does stage 2 when
 * policyRef is passed (even if empty). PolicySecret and PolicySigned pass
 * policyRef; other policy commands do not. */
static int FwPolicyExtend(FWTPM_Session* sess, UINT32 cc,
    const byte* name, int nameSz,
    const byte* policyRef, int policyRefSz, int hasRef)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    FWTPM_DECLARE_VAR(hashCtx, wc_HashAlg);
    enum wc_HashType wcHash = FwGetWcHashType(sess->authHash);
    int digestSz = TPM2_GetHashDigestSize(sess->authHash);
    byte ccBuf[4];

    FWTPM_ALLOC_VAR(hashCtx, wc_HashAlg);

    if (rc == 0 && digestSz <= 0) {
        rc = TPM_RC_HASH;
    }

    /* Stage 1: H(policyDigest || commandCode || name) */
    if (rc == 0) {
        if (wc_HashInit_ex(hashCtx, wcHash, NULL, INVALID_DEVID) != 0) {
            rc = TPM_RC_FAILURE;
        }
    }
    if (rc == 0) {
        wc_HashUpdate(hashCtx, wcHash,
            sess->policyDigest.buffer, sess->policyDigest.size);
        FwStoreU32BE(ccBuf, cc);
        wc_HashUpdate(hashCtx, wcHash, ccBuf, 4);
        if (name != NULL && nameSz > 0) {
            wc_HashUpdate(hashCtx, wcHash, name, nameSz);
        }
        wc_HashFinal(hashCtx, wcHash, sess->policyDigest.buffer);
        sess->policyDigest.size = (UINT16)digestSz;
        wc_HashFree(hashCtx, wcHash);
    }

    /* Stage 2: H(policyDigest || policyRef) — always done when hasRef is set,
     * even if policyRef is empty (matches MS reference PolicyContextUpdate) */
    if (rc == 0 && hasRef) {
        if (wc_HashInit_ex(hashCtx, wcHash, NULL, INVALID_DEVID) != 0) {
            rc = TPM_RC_FAILURE;
        }
        else {
            wc_HashUpdate(hashCtx, wcHash,
                sess->policyDigest.buffer, sess->policyDigest.size);
            if (policyRef != NULL && policyRefSz > 0) {
                wc_HashUpdate(hashCtx, wcHash, policyRef, policyRefSz);
            }
            wc_HashFinal(hashCtx, wcHash, sess->policyDigest.buffer);
            wc_HashFree(hashCtx, wcHash);
        }
    }

    FWTPM_FREE_VAR(hashCtx);
    return rc;
}

/* FwRspNoParams is now defined at the top of the file */

#endif /* !FWTPM_NO_POLICY (resume below for policy NV commands) */

/* NV handle error codes (used by policy and NV commands) */
#define FW_NV_HANDLE_ERR_1  (TPM_RC_HANDLE | TPM_RC_1)  /* 1st handle invalid */
#define FW_NV_HANDLE_ERR_2  (TPM_RC_HANDLE | TPM_RC_2)  /* 2nd handle invalid */

#ifndef FWTPM_NO_POLICY
/* Helper: parse session handle + skip auth area, return session */
static FWTPM_Session* FwPolicyParseSession(FWTPM_CTX* ctx,
    TPM2_Packet* cmd, int cmdSize, UINT16 cmdTag)
{
    UINT32 sessHandle;
    TPM2_Packet_ParseU32(cmd, &sessHandle);
    if (cmdTag == TPM_ST_SESSIONS) {
        (void)FwSkipAuthArea(cmd, cmdSize);
    }
    return FwFindSession(ctx, sessHandle);
}

/* --- TPM2_PolicyPassword (CC 0x018C) --- */
/* policyDigest = H(policyDigest || TPM_CC_PolicyPassword) */
static TPM_RC FwCmd_PolicyPassword(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    FWTPM_Session* sess;
    (void)cmdSize;

    sess = FwPolicyParseSession(ctx, cmd, cmdSize, cmdTag);
    if (sess == NULL) {
        rc = TPM_RC_VALUE;
    }
    if (rc == 0 && sess->sessionType != TPM_SE_POLICY &&
        sess->sessionType != TPM_SE_TRIAL) {
        rc = TPM_RC_AUTH_TYPE;
    }

    if (rc == 0) {
    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: PolicyPassword(session=0x%x)\n", sess->handle);
    #endif
        if (FwPolicyExtend(sess, TPM_CC_PolicyPassword, NULL, 0,
                NULL, 0, 0) != 0) {
            rc = TPM_RC_FAILURE;
        }
    }
    if (rc == 0) {
        sess->isPasswordPolicy = 1;
        FwRspNoParams(rsp, cmdTag);
    }

    return rc;
}

/* --- TPM2_PolicyAuthValue (CC 0x016B) --- */
/* policyDigest = H(policyDigest || TPM_CC_PolicyAuthValue) */
static TPM_RC FwCmd_PolicyAuthValue(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    FWTPM_Session* sess;
    (void)cmdSize;

    sess = FwPolicyParseSession(ctx, cmd, cmdSize, cmdTag);
    if (sess == NULL) {
        rc = TPM_RC_VALUE;
    }
    if (rc == 0 && sess->sessionType != TPM_SE_POLICY &&
        sess->sessionType != TPM_SE_TRIAL) {
        rc = TPM_RC_AUTH_TYPE;
    }

    if (rc == 0) {
    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: PolicyAuthValue(session=0x%x)\n", sess->handle);
    #endif
        if (FwPolicyExtend(sess, TPM_CC_PolicyAuthValue, NULL, 0,
                NULL, 0, 0) != 0) {
            rc = TPM_RC_FAILURE;
        }
    }
    if (rc == 0) {
        sess->isAuthValuePolicy = 1;
        FwRspNoParams(rsp, cmdTag);
    }

    return rc;
}

/* --- TPM2_PolicyCommandCode (CC 0x016C) --- */
/* policyDigest = H(policyDigest || TPM_CC_PolicyCommandCode || commandCode) */
static TPM_RC FwCmd_PolicyCommandCode(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    FWTPM_Session* sess;
    UINT32 commandCode;
    byte ccBuf[4];
    (void)cmdSize;

    sess = FwPolicyParseSession(ctx, cmd, cmdSize, cmdTag);
    if (sess == NULL) {
        rc = TPM_RC_VALUE;
    }

    if (rc == 0) {
        TPM2_Packet_ParseU32(cmd, &commandCode);

        if (sess->sessionType != TPM_SE_POLICY &&
            sess->sessionType != TPM_SE_TRIAL) {
            rc = TPM_RC_AUTH_TYPE;
        }
    }

    if (rc == 0) {
    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: PolicyCommandCode(session=0x%x, cc=0x%x)\n",
            sess->handle, commandCode);
    #endif

        FwStoreU32BE(ccBuf, commandCode);
        if (FwPolicyExtend(sess, TPM_CC_PolicyCommandCode, ccBuf, 4,
                NULL, 0, 0) != 0) {
            rc = TPM_RC_FAILURE;
        }
    }
    if (rc == 0) {
        FwRspNoParams(rsp, cmdTag);
    }

    return rc;
}

/* --- TPM2_PolicyOR (CC 0x0171) --- */
/* Replaces policyDigest with H(0x00...00 || CC_PolicyOR || d0 || d1 || ...).
 * Current policyDigest must match one of the provided branches. */
static TPM_RC FwCmd_PolicyOR(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 sessHandle, digestCount;
    byte digests[8][TPM_MAX_DIGEST_SIZE];
    UINT16 digestSizes[8];
    FWTPM_Session* sess = NULL;
    int i, found = 0, dSz = 0;
    FWTPM_DECLARE_VAR(hashCtx, wc_HashAlg);
    int hashInit = 0;
    enum wc_HashType wcHash;
    byte ccBuf[4];
    byte zeroBuf[TPM_MAX_DIGEST_SIZE];
    UINT32 ccPolicyOR = TPM_CC_PolicyOR;
    (void)cmdSize;

    FWTPM_ALLOC_VAR(hashCtx, wc_HashAlg);

    TPM2_Packet_ParseU32(cmd, &sessHandle);
    if (cmdTag == TPM_ST_SESSIONS) rc = FwSkipAuthArea(cmd, cmdSize);

    TPM2_Packet_ParseU32(cmd, &digestCount);
    if (digestCount < 2 || digestCount > 8) {
        rc = TPM_RC_VALUE;
    }
    if (rc == 0) {
        sess = FwFindSession(ctx, sessHandle);
        if (sess == NULL) {
            rc = TPM_RC_VALUE;
        }
    }
    if (rc == 0) {
        if (sess->sessionType != TPM_SE_POLICY &&
            sess->sessionType != TPM_SE_TRIAL) {
            rc = TPM_RC_AUTH_TYPE;
        }
    }
    /* Per TPM 2.0 Part 3 Section 23.5: each digest must be the size of
     * the session's hash algorithm digest */
    if (rc == 0) {
        dSz = TPM2_GetHashDigestSize(sess->authHash);
        for (i = 0; i < (int)digestCount; i++) {
            TPM2_Packet_ParseU16(cmd, &digestSizes[i]);
            if (digestSizes[i] != (UINT16)dSz) {
                rc = TPM_RC_SIZE;
                break;
            }
            TPM2_Packet_ParseBytes(cmd, digests[i], digestSizes[i]);
        }
    }

    if (rc == 0) {
        dSz = TPM2_GetHashDigestSize(sess->authHash);
        if (dSz <= 0) {
            rc = TPM_RC_HASH;
        }
    }

    if (rc == 0) {
    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: PolicyOR(session=0x%x, count=%d)\n",
            sessHandle, digestCount);
    #endif

        /* For non-trial sessions: current policyDigest must match one branch */
        if (sess->sessionType == TPM_SE_POLICY) {
            for (i = 0; i < (int)digestCount; i++) {
                if (digestSizes[i] == sess->policyDigest.size &&
                    TPM2_ConstantCompare(digests[i], sess->policyDigest.buffer,
                        sess->policyDigest.size) == 0) {
                    found = 1;
                    break;
                }
            }
            if (!found) {
                rc = TPM_RC_VALUE;
            }
        }
    }

    /* New policyDigest = H(0x00...0 || CC_PolicyOR || d0 || d1 || ...) */
    if (rc == 0) {
        wcHash = FwGetWcHashType(sess->authHash);
        if (wc_HashInit_ex(hashCtx, wcHash, NULL, INVALID_DEVID) != 0) {
            rc = TPM_RC_FAILURE;
        }
        else {
            hashInit = 1;
        }
    }

    if (rc == 0) {
        XMEMSET(zeroBuf, 0, dSz);
        wc_HashUpdate(hashCtx, wcHash, zeroBuf, dSz);

        FwStoreU32BE(ccBuf, ccPolicyOR);
        wc_HashUpdate(hashCtx, wcHash, ccBuf, 4);

        for (i = 0; i < (int)digestCount; i++) {
            if (digestSizes[i] > 0)
                wc_HashUpdate(hashCtx, wcHash, digests[i], digestSizes[i]);
        }

        wc_HashFinal(hashCtx, wcHash, sess->policyDigest.buffer);
        sess->policyDigest.size = (UINT16)dSz;
    }

    if (hashInit) {
        wc_HashFree(hashCtx, wcHash);
    }

    if (rc == 0) {
        FwRspNoParams(rsp, cmdTag);
    }
    FWTPM_FREE_VAR(hashCtx);
    return rc;
}

/* --- TPM2_PolicySecret (CC 0x0151) --- */
/* Proves knowledge of authHandle's auth value.
 * policyDigest = H(policyDigest || CC_PolicySecret || entityName || policyRef) */
static TPM_RC FwCmd_PolicySecret(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 authHandle, sessHandle;
    UINT16 nonceTpmSz, cpHashASz, policyRefSz = 0;
    INT32 expiration;
    byte policyRef[64];
    byte entityName[sizeof(TPM2B_NAME)];
    int entityNameSz = 0;
    FWTPM_Session* sess;
    int paramSzPos, paramStart;
    (void)cmdSize;

    TPM2_Packet_ParseU32(cmd, &authHandle);
    TPM2_Packet_ParseU32(cmd, &sessHandle);
    if (cmdTag == TPM_ST_SESSIONS) rc = FwSkipAuthArea(cmd, cmdSize);

    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &nonceTpmSz);
        if (cmd->pos + nonceTpmSz > cmdSize) {
            rc = TPM_RC_COMMAND_SIZE;
        }
    }
    if (rc == 0) {
        cmd->pos += nonceTpmSz;
        TPM2_Packet_ParseU16(cmd, &cpHashASz);
        if (cmd->pos + cpHashASz > cmdSize) {
            rc = TPM_RC_COMMAND_SIZE;
        }
    }
    if (rc == 0) {
        cmd->pos += cpHashASz;
        TPM2_Packet_ParseU16(cmd, &policyRefSz);
        if (policyRefSz > (UINT16)sizeof(policyRef)) {
            rc = TPM_RC_SIZE;
        }
    }
    if (rc == 0) {
        if (policyRefSz > 0) {
            TPM2_Packet_ParseBytes(cmd, policyRef, policyRefSz);
        }
        TPM2_Packet_ParseU32(cmd, (UINT32*)&expiration);
        (void)expiration;

    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: PolicySecret(authHandle=0x%x, session=0x%x)\n",
            authHandle, sessHandle);
    #endif

        sess = FwFindSession(ctx, sessHandle);
        if (sess == NULL) {
            rc = TPM_RC_VALUE;
        }
    }

    if (rc == 0 && sess->sessionType != TPM_SE_POLICY &&
        sess->sessionType != TPM_SE_TRIAL) {
        rc = TPM_RC_AUTH_TYPE;
    }

    if (rc == 0) {
        /* Auth verification for authHandle is handled by the command dispatch
         * framework (FWTPM_ProcessCommand) via the authorization area, not
         * within this handler. PolicySecret extends the policy digest after
         * the dispatch layer has already validated the caller's auth. */

        /* Build entity name */
        entityNameSz = FwGetEntityName(ctx, authHandle,
            entityName, (int)sizeof(entityName));

        if (FwPolicyExtend(sess, TPM_CC_PolicySecret,
                entityName, entityNameSz,
                policyRef, policyRefSz, 1) != 0) {
            rc = TPM_RC_FAILURE;
        }
    }

    if (rc == 0) {
        /* Response: timeout(TPM2B size=0) + ticket(TPMT_TK_AUTH) */
        paramStart = FwRspParamsBegin(rsp, cmdTag, &paramSzPos);
        TPM2_Packet_AppendU16(rsp, 0);
        TPM2_Packet_AppendU16(rsp, TPM_ST_AUTH_SECRET);
        TPM2_Packet_AppendU32(rsp, TPM_RH_NULL);
        TPM2_Packet_AppendU16(rsp, 0);
        FwRspParamsEnd(rsp, cmdTag, paramSzPos, paramStart);
    }

    return rc;
}

/* --- TPM2_PolicyAuthorize (CC 0x016A) --- */
/* Replaces policyDigest with H(approvedPolicy || CC_PolicyAuthorize ||
 * keySignName || policyRef) after verifying a ticket. */
static TPM_RC FwCmd_PolicyAuthorize(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 sessHandle;
    UINT16 approvedPolicySz, policyRefSz, keySignNameSz;
    byte approvedPolicy[TPM_MAX_DIGEST_SIZE];
    byte policyRef[64];
    byte keySignName[sizeof(TPM2B_NAME)];
    UINT16 ticketTag, ticketDigestSz;
    UINT32 ticketHier;
    byte ticketDigest[TPM_MAX_DIGEST_SIZE];
    FWTPM_Session* sess = NULL;
    int dSz = 0;
    int match = 0;
    FWTPM_DECLARE_VAR(hashCtx, wc_HashAlg);
    int hashInit = 0;
    enum wc_HashType wcHash = WC_HASH_TYPE_NONE;
    byte ccBuf[4];
    UINT32 cc = TPM_CC_PolicyAuthorize;
    TPMI_ALG_HASH keyNameAlg = TPM_ALG_SHA256; /* from keySignName */
    (void)cmdSize;

    FWTPM_ALLOC_VAR(hashCtx, wc_HashAlg);

    TPM2_Packet_ParseU32(cmd, &sessHandle);
    if (cmdTag == TPM_ST_SESSIONS) rc = FwSkipAuthArea(cmd, cmdSize);

    TPM2_Packet_ParseU16(cmd, &approvedPolicySz);
    if (approvedPolicySz > sizeof(approvedPolicy)) {
        rc = TPM_RC_SIZE;
    }
    if (rc == 0) {
        if (approvedPolicySz > 0)
            TPM2_Packet_ParseBytes(cmd, approvedPolicy, approvedPolicySz);

        TPM2_Packet_ParseU16(cmd, &policyRefSz);
        if (policyRefSz > sizeof(policyRef)) {
            rc = TPM_RC_SIZE;
        }
    }
    if (rc == 0) {
        if (policyRefSz > 0)
            TPM2_Packet_ParseBytes(cmd, policyRef, policyRefSz);

        TPM2_Packet_ParseU16(cmd, &keySignNameSz);
        if (keySignNameSz > sizeof(keySignName)) {
            rc = TPM_RC_SIZE;
        }
    }
    if (rc == 0) {
        if (keySignNameSz > 0)
            TPM2_Packet_ParseBytes(cmd, keySignName, keySignNameSz);

        /* Extract nameAlg from keySignName (first 2 bytes, big-endian).
         * This determines the hash algorithm for aHash and ticket HMAC. */
        if (keySignNameSz >= 2) {
            keyNameAlg = (TPMI_ALG_HASH)(
                ((UINT16)keySignName[0] << 8) | keySignName[1]);
        }

        /* checkTicket: TPMT_TK_VERIFIED: tag(2) + hierarchy(4) + digest(TPM2B)
         * Per TPM 2.0 Part 3 Section 23.16: verify ticket was produced by
         * VerifySignature for the approvedPolicy + keySignName. */
        TPM2_Packet_ParseU16(cmd, &ticketTag);
        TPM2_Packet_ParseU32(cmd, &ticketHier);
        TPM2_Packet_ParseU16(cmd, &ticketDigestSz);
        if (ticketDigestSz > sizeof(ticketDigest)) {
            rc = TPM_RC_SIZE;
        }
        else if (ticketDigestSz > 0) {
            if (cmd->pos + ticketDigestSz > cmdSize) {
                rc = TPM_RC_COMMAND_SIZE;
            }
            else {
                TPM2_Packet_ParseBytes(cmd, ticketDigest, ticketDigestSz);
            }
        }
        if (rc == 0 && ticketTag != TPM_ST_VERIFIED) {
            rc = TPM_RC_TICKET;
        }
        /* Verify ticket HMAC per TPM 2.0 Part 3 Section 23.16:
         * 1. Compute aHash = H(approvedPolicy || policyRef)
         * 2. Ticket from VerifySignature is HMAC(proofValue, aHash || keyName)
         * 3. Recompute and compare ticket HMAC */
        if (rc == 0 && ticketDigestSz > 0) {
            byte aHash[TPM_MAX_DIGEST_SIZE];
            int aHashSz = 0;
            byte ticketInput[TPM_MAX_DIGEST_SIZE + sizeof(TPM2B_NAME)];
            int ticketInputSz = 0;
            byte expectedHmac[TPM_MAX_DIGEST_SIZE];
            int expectedSz = 0;
            wc_HashAlg aCtx;
            enum wc_HashType aWcHash;
            int hmacRc;
            int sizeMismatch;
            int ticketDiff;
            word32 cmpSz;

            /* Step 1: aHash = H(approvedPolicy || policyRef)
             * Hash algorithm comes from signing key's nameAlg */
            aWcHash = FwGetWcHashType(keyNameAlg);
            aHashSz = TPM2_GetHashDigestSize(keyNameAlg);
            if (wc_HashInit(&aCtx, aWcHash) == 0) {
                wc_HashUpdate(&aCtx, aWcHash,
                    approvedPolicy, approvedPolicySz);
                if (policyRefSz > 0)
                    wc_HashUpdate(&aCtx, aWcHash, policyRef, policyRefSz);
                wc_HashFinal(&aCtx, aWcHash, aHash);
                wc_HashFree(&aCtx, aWcHash);
            }
            else {
                rc = TPM_RC_FAILURE;
            }

            /* Step 2: ticketInput = aHash || keySignName */
            if (rc == 0) {
                XMEMCPY(ticketInput, aHash, aHashSz);
                ticketInputSz = aHashSz;
                XMEMCPY(ticketInput + ticketInputSz,
                    keySignName, keySignNameSz);
                ticketInputSz += keySignNameSz;
            }

            /* Step 3: verify ticket HMAC — always run TPM2_ConstantCompare
             * so timing doesn't leak size match */
            if (rc == 0) {
                hmacRc = FwComputeTicketHmac(ctx, ticketHier, keyNameAlg,
                    ticketInput, ticketInputSz, expectedHmac, &expectedSz);
                sizeMismatch = (ticketDigestSz != (UINT16)expectedSz);
                cmpSz = (ticketDigestSz < (UINT16)expectedSz) ?
                    ticketDigestSz : (word32)expectedSz;
                ticketDiff = TPM2_ConstantCompare(ticketDigest, expectedHmac,
                    cmpSz);
                if (hmacRc != 0 || (sizeMismatch | ticketDiff)) {
                #ifdef DEBUG_WOLFTPM
                    printf("fwTPM: PolicyAuthorize ticket verify failed "
                        "(tag=0x%x, hier=0x%x, ticketSz=%d, expectedSz=%d)\n",
                        ticketTag, ticketHier, ticketDigestSz, expectedSz);
                #endif
                    rc = TPM_RC_POLICY_FAIL;
                }
            }
            TPM2_ForceZero(aHash, sizeof(aHash));
            TPM2_ForceZero(expectedHmac, sizeof(expectedHmac));
        }

        sess = FwFindSession(ctx, sessHandle);
        if (sess == NULL) {
            rc = TPM_RC_VALUE;
        }
    }
    if (rc == 0) {
        if (sess->sessionType != TPM_SE_POLICY &&
            sess->sessionType != TPM_SE_TRIAL) {
            rc = TPM_RC_AUTH_TYPE;
        }
    }

    if (rc == 0) {
        dSz = TPM2_GetHashDigestSize(sess->authHash);
        if (dSz <= 0) {
            rc = TPM_RC_HASH;
        }
    }

    if (rc == 0) {
    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: PolicyAuthorize(session=0x%x, approvedPolSz=%d)\n",
            sessHandle, approvedPolicySz);
    #endif

        /* Per TPM 2.0 Part 3, Section 23.16:
         * 1. For policy sessions (not trial): verify policyDigest ==
         *    approvedPolicy
         * 2. Reset policyDigest to zero
         * 3. PolicyUpdate(CC_PolicyAuthorize, keySignName, policyRef) */

        /* Step 1: Compare current policyDigest with approvedPolicy */
        if (sess->sessionType == TPM_SE_POLICY) {
            if (approvedPolicySz == (UINT16)dSz &&
                approvedPolicySz == sess->policyDigest.size) {
                match = (TPM2_ConstantCompare(sess->policyDigest.buffer,
                    approvedPolicy, approvedPolicySz) == 0);
            }
            else if (approvedPolicySz == 0 &&
                     sess->policyDigest.size == 0) {
                match = 1;
            }
            if (!match) {
            #ifdef DEBUG_WOLFTPM
                printf("fwTPM: PolicyAuthorize: "
                    "approvedPolicy != policyDigest\n");
            #endif
                rc = TPM_RC_POLICY_FAIL;
            }
        }
    }

    /* Step 2: Reset policyDigest to zero */
    if (rc == 0) {
        XMEMSET(sess->policyDigest.buffer, 0, dSz);
        sess->policyDigest.size = (UINT16)dSz;
    }

    /* Step 3: PolicyUpdate(CC_PolicyAuthorize, keySignName, policyRef)
     * Stage 1: policyDigest = H(policyDigest || CC || keySignName)
     * Stage 2: policyDigest = H(policyDigest || policyRef) */

    /* Stage 1 */
    if (rc == 0) {
        wcHash = FwGetWcHashType(sess->authHash);
        if (wc_HashInit_ex(hashCtx, wcHash, NULL, INVALID_DEVID) != 0) {
            rc = TPM_RC_FAILURE;
        }
        else {
            hashInit = 1;
        }
    }
    if (rc == 0) {
        wc_HashUpdate(hashCtx, wcHash,
            sess->policyDigest.buffer, sess->policyDigest.size);
        FwStoreU32BE(ccBuf, cc);
        wc_HashUpdate(hashCtx, wcHash, ccBuf, 4);
        if (keySignNameSz > 0)
            wc_HashUpdate(hashCtx, wcHash, keySignName, keySignNameSz);
        wc_HashFinal(hashCtx, wcHash, sess->policyDigest.buffer);
        sess->policyDigest.size = (UINT16)dSz;
    }
    if (hashInit) {
        wc_HashFree(hashCtx, wcHash);
        hashInit = 0;
    }

    /* Stage 2: H(policyDigest || policyRef) -- always done per spec */
    if (rc == 0) {
        if (wc_HashInit_ex(hashCtx, wcHash, NULL, INVALID_DEVID) != 0) {
            rc = TPM_RC_FAILURE;
        }
        else {
            hashInit = 1;
        }
    }
    if (rc == 0) {
        wc_HashUpdate(hashCtx, wcHash,
            sess->policyDigest.buffer, sess->policyDigest.size);
        if (policyRefSz > 0)
            wc_HashUpdate(hashCtx, wcHash, policyRef, policyRefSz);
        wc_HashFinal(hashCtx, wcHash, sess->policyDigest.buffer);
    }
    if (hashInit) {
        wc_HashFree(hashCtx, wcHash);
    }

    if (rc == 0) {
        FwRspNoParams(rsp, cmdTag);
    }
    FWTPM_FREE_VAR(hashCtx);
    return rc;
}

/* --- TPM2_PolicyLocality (CC 0x016F) --- */
/* Extend policyDigest: H(policyDigest || TPM_CC_PolicyLocality || locality)
 * Wire: policySession (U32) → locality (U8). No auth area. */
static TPM_RC FwCmd_PolicyLocality(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 sessHandle;
    UINT8 locality = 0;
    FWTPM_Session* sess;
    byte locBuf[1];
    (void)cmdSize;

    TPM2_Packet_ParseU32(cmd, &sessHandle);
    if (cmdTag == TPM_ST_SESSIONS) rc = FwSkipAuthArea(cmd, cmdSize);

    TPM2_Packet_ParseU8(cmd, &locality);

    sess = FwFindSession(ctx, sessHandle);
    if (sess == NULL) {
        rc = TPM_RC_VALUE;
    }
    if (rc == 0 && sess->sessionType != TPM_SE_POLICY &&
        sess->sessionType != TPM_SE_TRIAL) {
        rc = TPM_RC_AUTH_TYPE;
    }

    if (rc == 0) {
    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: PolicyLocality(session=0x%x, locality=%d)\n",
            sessHandle, locality);
    #endif

        locBuf[0] = locality;
        if (FwPolicyExtend(sess, TPM_CC_PolicyLocality, locBuf, 1,
                NULL, 0, 0) != 0) {
            rc = TPM_RC_FAILURE;
        }
    }
    if (rc == 0) {
        FwRspNoParams(rsp, cmdTag);
    }

    return rc;
}

/* --- TPM2_PolicySigned (CC 0x0160) --- */
/* Simplified: verify signature and extend policyDigest with
 * H(policyDigest || TPM_CC_PolicySigned || authObject.name).
 * Wire: authObject (U32) → policySession (U32) → [auth area] →
 *       nonceTPM (TPM2B) → cpHashA (TPM2B) → policyRef (TPM2B) →
 *       expiration (S32) → auth (TPMT_SIGNATURE)
 * Response: timeout (TPM2B) + policyTicket (TPMT_TK_AUTH) */
static TPM_RC FwCmd_PolicySigned(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 authObjHandle, sessHandle;
    UINT16 nonceTpmSz = 0, cpHashASz = 0, policyRefSz = 0;
    INT32 expiration = 0;
    byte nonceBuf[TPM_MAX_DIGEST_SIZE];
    byte cpHashBuf[TPM_MAX_DIGEST_SIZE];
    byte policyRef[64];
    TPMT_SIGNATURE sig;
    FWTPM_Session* sess = NULL;
    FWTPM_Object* authObj = NULL;
    int paramSzPos, paramStart;

    TPM2_Packet_ParseU32(cmd, &authObjHandle);
    TPM2_Packet_ParseU32(cmd, &sessHandle);
    if (cmdTag == TPM_ST_SESSIONS) rc = FwSkipAuthArea(cmd, cmdSize);

    /* Find session early - need nonceTPM for aHash computation */
    if (rc == 0) {
        sess = FwFindSession(ctx, sessHandle);
        if (sess == NULL) {
            rc = TPM_RC_VALUE;
        }
    }
    if (rc == 0 && sess->sessionType != TPM_SE_POLICY &&
        sess->sessionType != TPM_SE_TRIAL) {
        rc = TPM_RC_AUTH_TYPE;
    }

    /* Parse nonceTPM (save for aHash) */
    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &nonceTpmSz);
        if (nonceTpmSz > sizeof(nonceBuf) ||
                cmd->pos + nonceTpmSz > cmdSize) {
            rc = TPM_RC_COMMAND_SIZE;
        }
    }
    if (rc == 0 && nonceTpmSz > 0) {
        TPM2_Packet_ParseBytes(cmd, nonceBuf, nonceTpmSz);
    }

    /* Parse cpHashA (save for aHash) */
    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &cpHashASz);
        if (cpHashASz > sizeof(cpHashBuf) ||
                cmd->pos + cpHashASz > cmdSize) {
            rc = TPM_RC_COMMAND_SIZE;
        }
    }
    if (rc == 0 && cpHashASz > 0) {
        TPM2_Packet_ParseBytes(cmd, cpHashBuf, cpHashASz);
    }

    /* Parse policyRef */
    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &policyRefSz);
        if (policyRefSz > (UINT16)sizeof(policyRef)) {
            rc = TPM_RC_SIZE;
        }
    }
    if (rc == 0) {
        if (policyRefSz > 0) {
            TPM2_Packet_ParseBytes(cmd, policyRef, policyRefSz);
        }
        TPM2_Packet_ParseU32(cmd, (UINT32*)&expiration);
    }

    /* Parse TPMT_SIGNATURE */
    if (rc == 0) {
        XMEMSET(&sig, 0, sizeof(sig));
        TPM2_Packet_ParseSignature(cmd, &sig);
    }

#ifdef DEBUG_WOLFTPM
    if (rc == 0) {
        printf("fwTPM: PolicySigned(authObj=0x%x, session=0x%x, sigAlg=0x%x)\n",
            authObjHandle, sessHandle, sig.sigAlg);
    }
#endif

    /* For policy sessions (not trial): verify signature per TPM 2.0 Part 3
     * Section 23.3. Compute aHash = H(nonceTPM || expiration || cpHashA ||
     * policyRef), then verify signature against aHash using authObject's
     * public key. */
    if (rc == 0 && sess->sessionType == TPM_SE_POLICY) {
        FWTPM_DECLARE_VAR(hashCtx, wc_HashAlg);
        enum wc_HashType wcHash = FwGetWcHashType(sess->authHash);
        int dSz = TPM2_GetHashDigestSize(sess->authHash);
        byte aHash[TPM_MAX_DIGEST_SIZE];
        byte expBuf[4];
        int hrc;

        FWTPM_ALLOC_VAR(hashCtx, wc_HashAlg);

        /* Compute aHash */
        hrc = wc_HashInit(hashCtx, wcHash);
        if (hrc == 0 && sess->nonceTPM.size > 0) {
            hrc = wc_HashUpdate(hashCtx, wcHash,
                sess->nonceTPM.buffer, sess->nonceTPM.size);
        }
        if (hrc == 0) {
            FwStoreU32BE(expBuf, (UINT32)expiration);
            hrc = wc_HashUpdate(hashCtx, wcHash, expBuf, 4);
        }
        if (hrc == 0 && cpHashASz > 0) {
            hrc = wc_HashUpdate(hashCtx, wcHash, cpHashBuf, cpHashASz);
        }
        if (hrc == 0 && policyRefSz > 0) {
            hrc = wc_HashUpdate(hashCtx, wcHash, policyRef, policyRefSz);
        }
        if (hrc == 0) {
            hrc = wc_HashFinal(hashCtx, wcHash, aHash);
        }
        wc_HashFree(hashCtx, wcHash);
        FWTPM_FREE_VAR(hashCtx);

        if (hrc != 0) {
            rc = TPM_RC_FAILURE;
        }

        /* Verify signature against aHash using authObject's public key */
        if (rc == 0) {
            authObj = FwFindObject(ctx, authObjHandle);
            if (authObj == NULL) {
                rc = TPM_RC_HANDLE;
            }
        }
        if (rc == 0) {
            rc = FwVerifySignatureCore(authObj, aHash, dSz, &sig);
        }
        TPM2_ForceZero(aHash, sizeof(aHash));
    }

    if (rc == 0) {
        /* Build entity name for the auth object */
        byte entityName[sizeof(TPM2B_NAME)];
        int entityNameSz = FwGetEntityName(ctx, authObjHandle,
            entityName, (int)sizeof(entityName));
        if (entityNameSz > 0) {
            if (FwPolicyExtend(sess, TPM_CC_PolicySigned,
                    entityName, entityNameSz,
                    policyRef, policyRefSz, 1) != 0) {
                rc = TPM_RC_FAILURE;
            }
        }
    }

    if (rc == 0) {
        /* Response: timeout(TPM2B size=0) + ticket(TPMT_TK_AUTH) */
        paramStart = FwRspParamsBegin(rsp, cmdTag, &paramSzPos);
        TPM2_Packet_AppendU16(rsp, 0); /* timeout size = 0 */
        TPM2_Packet_AppendU16(rsp, TPM_ST_AUTH_SIGNED);
        TPM2_Packet_AppendU32(rsp, TPM_RH_NULL);
        TPM2_Packet_AppendU16(rsp, 0); /* ticket digest size = 0 */
        FwRspParamsEnd(rsp, cmdTag, paramSzPos, paramStart);
    }

    return rc;
}

#ifndef FWTPM_NO_NV
/* --- TPM2_PolicyNV (CC 0x0149) --- */
/* Compares NV index data with operandB using operation, extends policy.
 * Wire format: authHandle(4) | nvIndex(4) | policySession(4) |
 *              authArea | operandB(TPM2B) | offset(2) | operation(2) */
static TPM_RC FwCmd_PolicyNV(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 authHandle, nvIndex, sessHandle;
    UINT16 operandBSz = 0;
    UINT16 offset = 0;
    UINT16 operation = 0;
    byte operandB[64];
    FWTPM_NvIndex* nv = NULL;
    FWTPM_Session* sess = NULL;
    int dSz = 0;
    int cmpResult = 0;
    int signedCmpResult = 0;
    int i;
    FWTPM_DECLARE_VAR(hashCtx, wc_HashAlg);
    enum wc_HashType wcHash;
    int hashCtxInit = 0;
    byte argsHash[TPM_MAX_DIGEST_SIZE];
    byte ccBuf[4];
    byte tmpBuf[4]; /* for offset(2) + operation(2) */
    byte nvName[2 + TPM_MAX_DIGEST_SIZE];
    UINT16 nvNameSz = 0;
    UINT32 cc = TPM_CC_PolicyNV;

    (void)cmdSize;

    FWTPM_ALLOC_VAR(hashCtx, wc_HashAlg);

    /* Parse 3 handles */
    TPM2_Packet_ParseU32(cmd, &authHandle);
    TPM2_Packet_ParseU32(cmd, &nvIndex);
    TPM2_Packet_ParseU32(cmd, &sessHandle);

    /* Skip auth area */
    if (cmdTag == TPM_ST_SESSIONS) rc = FwSkipAuthArea(cmd, cmdSize);

    /* Parse operandB (TPM2B) */
    TPM2_Packet_ParseU16(cmd, &operandBSz);
    if (operandBSz > sizeof(operandB)) {
        rc = TPM_RC_SIZE;
    }
    if (rc == 0 && operandBSz > 0) {
        TPM2_Packet_ParseBytes(cmd, operandB, operandBSz);
    }

    /* Parse offset and operation */
    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &offset);
        TPM2_Packet_ParseU16(cmd, &operation);
    }

#ifdef DEBUG_WOLFTPM
    if (rc == 0) {
        printf("fwTPM: PolicyNV(auth=0x%x, nv=0x%x, sess=0x%x, "
            "operandSz=%d, offset=%d, op=%d)\n",
            authHandle, nvIndex, sessHandle, operandBSz, offset, operation);
    }
#endif

    (void)authHandle;

    /* Find NV index */
    if (rc == 0) {
        nv = FwFindNvIndex(ctx, nvIndex);
        if (nv == NULL) {
            rc = TPM_RC_HANDLE | TPM_RC_2;
        }
    }

    /* Find policy session */
    if (rc == 0) {
        sess = FwFindSession(ctx, sessHandle);
        if (sess == NULL) {
            rc = TPM_RC_VALUE;
        }
    }
    if (rc == 0) {
        if (sess->sessionType != TPM_SE_POLICY &&
            sess->sessionType != TPM_SE_TRIAL) {
            rc = TPM_RC_AUTH_TYPE;
        }
    }

    if (rc == 0) {
        dSz = TPM2_GetHashDigestSize(sess->authHash);
        if (dSz <= 0) {
            rc = TPM_RC_HASH;
        }
    }

    /* Validate range */
    if (rc == 0) {
        if ((UINT32)offset + operandBSz > nv->nvPublic.dataSize) {
            rc = TPM_RC_NV_RANGE;
        }
    }

    /* NV must have been written */
    if (rc == 0) {
        if (!nv->written) {
            rc = TPM_RC_NV_UNINITIALIZED;
        }
    }

    /* For policy sessions (not trial), compare NV data with operandB.
     * Trial sessions skip comparison - just compute the digest. */
    if (rc == 0 && sess->sessionType == TPM_SE_POLICY) {
        /* Compare operandB with NV data at offset */
        byte* nvData = nv->data + offset;
        int pass = 0;

        /* Byte-by-byte comparison for relational operators */
        cmpResult = 0;
        for (i = 0; i < (int)operandBSz; i++) {
            if (nvData[i] < operandB[i]) {
                cmpResult = -1;
                break;
            }
            else if (nvData[i] > operandB[i]) {
                cmpResult = 1;
                break;
            }
        }

        /* For signed comparisons, check sign bits (big-endian MSB) */
        signedCmpResult = cmpResult;
        if (operandBSz > 0) {
            int nvSign = (nvData[0] & 0x80) ? 1 : 0;
            int opSign = (operandB[0] & 0x80) ? 1 : 0;
            if (nvSign != opSign) {
                signedCmpResult = nvSign ? -1 : 1;
            }
        }

        switch (operation) {
            case TPM_EO_EQ:
                pass = (cmpResult == 0);
                break;
            case TPM_EO_NEQ:
                pass = (cmpResult != 0);
                break;
            case TPM_EO_SIGNED_GT:
                pass = (signedCmpResult > 0);
                break;
            case TPM_EO_UNSIGNED_GT:
                pass = (cmpResult > 0);
                break;
            case TPM_EO_SIGNED_LT:
                pass = (signedCmpResult < 0);
                break;
            case TPM_EO_UNSIGNED_LT:
                pass = (cmpResult < 0);
                break;
            case TPM_EO_SIGNED_GE:
                pass = (signedCmpResult >= 0);
                break;
            case TPM_EO_UNSIGNED_GE:
                pass = (cmpResult >= 0);
                break;
            case TPM_EO_SIGNED_LE:
                pass = (signedCmpResult <= 0);
                break;
            case TPM_EO_UNSIGNED_LE:
                pass = (cmpResult <= 0);
                break;
            case TPM_EO_BITSET:
                pass = 1;
                for (i = 0; i < (int)operandBSz; i++) {
                    if ((nvData[i] & operandB[i]) != operandB[i]) {
                        pass = 0;
                        break;
                    }
                }
                break;
            case TPM_EO_BITCLEAR:
                pass = 1;
                for (i = 0; i < (int)operandBSz; i++) {
                    if ((nvData[i] & operandB[i]) != 0) {
                        pass = 0;
                        break;
                    }
                }
                break;
            default:
                rc = TPM_RC_VALUE;
                break;
        }

        if (rc == 0 && !pass) {
            rc = TPM_RC_POLICY;
        }
    }

    /* Extend policy digest:
     * policyDigest = H(policyDigest || TPM_CC_PolicyNV || operandB ||
     *                   offset || operation) */

    /* Get hash type (avoid bad-function-cast) */
    if (rc == 0) {
        enum wc_HashType ht = FwGetWcHashType(sess->authHash);
        wcHash = ht;
    }

    /* Compute args = H(operandB || offset || operation) */
    if (rc == 0) {
        if (wc_HashInit_ex(hashCtx, wcHash, NULL, INVALID_DEVID) != 0) {
            rc = TPM_RC_FAILURE;
        }
        else {
            hashCtxInit = 1;
        }
    }
    if (rc == 0 && operandBSz > 0) {
        wc_HashUpdate(hashCtx, wcHash, operandB, operandBSz);
    }
    if (rc == 0) {
        FwStoreU16BE(tmpBuf, offset);
        wc_HashUpdate(hashCtx, wcHash, tmpBuf, 2);
        FwStoreU16BE(tmpBuf, operation);
        wc_HashUpdate(hashCtx, wcHash, tmpBuf, 2);
        wc_HashFinal(hashCtx, wcHash, argsHash);
        wc_HashFree(hashCtx, wcHash);
        hashCtxInit = 0;
    }

    /* policyDigest = H(policyDigest || CC || argsHash || nvIndexName) */
    if (rc == 0) {
        FwComputeNvName(nv, nvName, &nvNameSz);

        if (wc_HashInit_ex(hashCtx, wcHash, NULL, INVALID_DEVID) != 0) {
            rc = TPM_RC_FAILURE;
        }
        else {
            hashCtxInit = 1;
        }
    }
    if (rc == 0) {
        wc_HashUpdate(hashCtx, wcHash,
            sess->policyDigest.buffer, sess->policyDigest.size);
        FwStoreU32BE(ccBuf, cc);
        wc_HashUpdate(hashCtx, wcHash, ccBuf, 4);
        wc_HashUpdate(hashCtx, wcHash, argsHash, dSz);
        if (nvNameSz > 0) {
            wc_HashUpdate(hashCtx, wcHash, nvName, nvNameSz);
        }
        wc_HashFinal(hashCtx, wcHash, sess->policyDigest.buffer);
        sess->policyDigest.size = (UINT16)dSz;
        wc_HashFree(hashCtx, wcHash);
        hashCtxInit = 0;
    }

    if (rc == 0) {
        FwRspNoParams(rsp, cmdTag);
    }

    /* Cleanup hash context on error */
    if (hashCtxInit) {
        wc_HashFree(hashCtx, wcHash);
    }
    FWTPM_FREE_VAR(hashCtx);
    return rc;
}
#endif /* !FWTPM_NO_NV (PolicyNV) */

/* --- TPM2_PolicyPhysicalPresence (CC 0x0187) --- */
/* policyDigest = H(policyDigest || TPM_CC_PolicyPhysicalPresence) */
static TPM_RC FwCmd_PolicyPhysicalPresence(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    FWTPM_Session* sess;
    (void)cmdSize;

    sess = FwPolicyParseSession(ctx, cmd, cmdSize, cmdTag);
    if (sess == NULL) {
        rc = TPM_RC_VALUE;
    }
    if (rc == 0 && sess->sessionType != TPM_SE_POLICY &&
        sess->sessionType != TPM_SE_TRIAL) {
        rc = TPM_RC_AUTH_TYPE;
    }

    if (rc == 0) {
    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: PolicyPhysicalPresence(session=0x%x)\n", sess->handle);
    #endif
        if (FwPolicyExtend(sess, TPM_CC_PolicyPhysicalPresence,
                NULL, 0, NULL, 0, 0) != 0) {
            rc = TPM_RC_FAILURE;
        }
    }
    if (rc == 0) {
        sess->isPPRequired = 1;
        FwRspNoParams(rsp, cmdTag);
    }

    return rc;
}

/* --- TPM2_PolicyNvWritten (CC 0x018F) --- */
/* policyDigest = H(policyDigest || TPM_CC_PolicyNvWritten || writtenSet) */
static TPM_RC FwCmd_PolicyNvWritten(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    FWTPM_Session* sess;
    UINT8 writtenSet;
    (void)cmdSize;

    sess = FwPolicyParseSession(ctx, cmd, cmdSize, cmdTag);
    if (sess == NULL) {
        rc = TPM_RC_VALUE;
    }
    if (rc == 0 && sess->sessionType != TPM_SE_POLICY &&
        sess->sessionType != TPM_SE_TRIAL) {
        rc = TPM_RC_AUTH_TYPE;
    }

    if (rc == 0) {
        TPM2_Packet_ParseU8(cmd, &writtenSet);
        if (writtenSet > 1) {
            rc = TPM_RC_VALUE;
        }
    }
    if (rc == 0) {
    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: PolicyNvWritten(session=0x%x, writtenSet=%d)\n",
            sess->handle, writtenSet);
    #endif
        if (FwPolicyExtend(sess, TPM_CC_PolicyNvWritten,
                &writtenSet, 1, NULL, 0, 0) != 0) {
            rc = TPM_RC_FAILURE;
        }
    }
    if (rc == 0) {
        FwRspNoParams(rsp, cmdTag);
    }

    return rc;
}

/* --- TPM2_PolicyTemplate (CC 0x0190) --- */
/* policyDigest = H(policyDigest || TPM_CC_PolicyTemplate || templateHash) */
static TPM_RC FwCmd_PolicyTemplate(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    FWTPM_Session* sess;
    UINT16 templateHashSz = 0;
    byte templateHash[TPM_MAX_DIGEST_SIZE];
    (void)cmdSize;

    sess = FwPolicyParseSession(ctx, cmd, cmdSize, cmdTag);
    if (sess == NULL) {
        rc = TPM_RC_VALUE;
    }
    if (rc == 0 && sess->sessionType != TPM_SE_POLICY &&
        sess->sessionType != TPM_SE_TRIAL) {
        rc = TPM_RC_AUTH_TYPE;
    }

    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &templateHashSz);
        if (templateHashSz > sizeof(templateHash)) {
            rc = TPM_RC_SIZE;
        }
    }
    if (rc == 0) {
        if (templateHashSz > 0) {
            TPM2_Packet_ParseBytes(cmd, templateHash, templateHashSz);
        }
    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: PolicyTemplate(session=0x%x, hashSz=%d)\n",
            sess->handle, templateHashSz);
    #endif
        if (FwPolicyExtend(sess, TPM_CC_PolicyTemplate,
                templateHash, templateHashSz, NULL, 0, 0) != 0) {
            rc = TPM_RC_FAILURE;
        }
    }
    if (rc == 0) {
        FwRspNoParams(rsp, cmdTag);
    }

    return rc;
}

/* --- TPM2_PolicyCpHash (CC 0x0171) --- */
/* policyDigest = H(policyDigest || TPM_CC_PolicyCpHash || cpHashA)
 * cpHashA is stored in session; once set, cannot be changed. */
static TPM_RC FwCmd_PolicyCpHash(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    FWTPM_Session* sess;
    UINT16 cpHashSz = 0;
    byte cpHashBuf[TPM_MAX_DIGEST_SIZE];
    int sizeMismatch;
    int cpDiff;
    word32 cmpSz;
    (void)cmdSize;

    sess = FwPolicyParseSession(ctx, cmd, cmdSize, cmdTag);
    if (sess == NULL) {
        rc = TPM_RC_VALUE;
    }
    if (rc == 0 && sess->sessionType != TPM_SE_POLICY &&
        sess->sessionType != TPM_SE_TRIAL) {
        rc = TPM_RC_AUTH_TYPE;
    }

    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &cpHashSz);
        if (cpHashSz > sizeof(cpHashBuf) || cpHashSz == 0) {
            rc = TPM_RC_SIZE;
        }
    }
    if (rc == 0) {
        TPM2_Packet_ParseBytes(cmd, cpHashBuf, cpHashSz);

        /* If cpHashA already set, must be identical — always run
         * TPM2_ConstantCompare so timing doesn't leak size match */
        if (sess->cpHashA.size > 0) {
            sizeMismatch = (sess->cpHashA.size != cpHashSz);
            cmpSz = (sess->cpHashA.size < cpHashSz) ?
                sess->cpHashA.size : cpHashSz;
            cpDiff = TPM2_ConstantCompare(sess->cpHashA.buffer, cpHashBuf,
                cmpSz);
            if (sizeMismatch | cpDiff) {
                rc = TPM_RC_CPHASH;
            }
        }
    }
    if (rc == 0) {
    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: PolicyCpHash(session=0x%x, cpHashSz=%d)\n",
            sess->handle, cpHashSz);
    #endif
        sess->cpHashA.size = cpHashSz;
        XMEMCPY(sess->cpHashA.buffer, cpHashBuf, cpHashSz);

        if (FwPolicyExtend(sess, TPM_CC_PolicyCpHash,
                cpHashBuf, cpHashSz, NULL, 0, 0) != 0) {
            rc = TPM_RC_FAILURE;
        }
    }
    if (rc == 0) {
        FwRspNoParams(rsp, cmdTag);
    }

    return rc;
}

/* --- TPM2_PolicyNameHash (CC 0x0170) --- */
/* policyDigest = H(policyDigest || TPM_CC_PolicyNameHash || nameHash)
 * nameHash is stored in session; once set, cannot be changed. */
static TPM_RC FwCmd_PolicyNameHash(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    FWTPM_Session* sess;
    UINT16 nameHashSz = 0;
    byte nameHashBuf[TPM_MAX_DIGEST_SIZE];
    int sizeMismatch;
    int nameDiff;
    word32 cmpSz;
    (void)cmdSize;

    sess = FwPolicyParseSession(ctx, cmd, cmdSize, cmdTag);
    if (sess == NULL) {
        rc = TPM_RC_VALUE;
    }
    if (rc == 0 && sess->sessionType != TPM_SE_POLICY &&
        sess->sessionType != TPM_SE_TRIAL) {
        rc = TPM_RC_AUTH_TYPE;
    }

    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &nameHashSz);
        if (nameHashSz > sizeof(nameHashBuf) || nameHashSz == 0) {
            rc = TPM_RC_SIZE;
        }
    }
    if (rc == 0) {
        TPM2_Packet_ParseBytes(cmd, nameHashBuf, nameHashSz);

        /* If nameHash already set, must be identical — always run
         * TPM2_ConstantCompare so timing doesn't leak size match */
        if (sess->nameHash.size > 0) {
            sizeMismatch = (sess->nameHash.size != nameHashSz);
            cmpSz = (sess->nameHash.size < nameHashSz) ?
                sess->nameHash.size : nameHashSz;
            nameDiff = TPM2_ConstantCompare(sess->nameHash.buffer, nameHashBuf,
                cmpSz);
            if (sizeMismatch | nameDiff) {
                rc = TPM_RC_CPHASH;
            }
        }
    }
    if (rc == 0) {
    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: PolicyNameHash(session=0x%x, nameHashSz=%d)\n",
            sess->handle, nameHashSz);
    #endif
        sess->nameHash.size = nameHashSz;
        XMEMCPY(sess->nameHash.buffer, nameHashBuf, nameHashSz);

        if (FwPolicyExtend(sess, TPM_CC_PolicyNameHash,
                nameHashBuf, nameHashSz, NULL, 0, 0) != 0) {
            rc = TPM_RC_FAILURE;
        }
    }
    if (rc == 0) {
        FwRspNoParams(rsp, cmdTag);
    }

    return rc;
}

/* --- TPM2_PolicyDuplicationSelect (CC 0x0188) --- */
/* If includeObject:
 *   policyDigest = H(policyDigest || CC || objectName || newParentName || 1)
 * Else:
 *   policyDigest = H(policyDigest || CC || newParentName || 0)
 */
static TPM_RC FwCmd_PolicyDuplicationSelect(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    FWTPM_Session* sess;
    UINT16 objectNameSz = 0, newParentNameSz = 0;
    byte objectName[2 + TPM_MAX_DIGEST_SIZE];
    byte newParentName[2 + TPM_MAX_DIGEST_SIZE];
    UINT8 includeObject = 0;
    (void)cmdSize;

    sess = FwPolicyParseSession(ctx, cmd, cmdSize, cmdTag);
    if (sess == NULL) {
        rc = TPM_RC_VALUE;
    }
    if (rc == 0 && sess->sessionType != TPM_SE_POLICY &&
        sess->sessionType != TPM_SE_TRIAL) {
        rc = TPM_RC_AUTH_TYPE;
    }

    /* Parse TPM2B_NAME objectName */
    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &objectNameSz);
        if (objectNameSz > sizeof(objectName)) {
            rc = TPM_RC_SIZE;
        }
    }
    if (rc == 0 && objectNameSz > 0) {
        TPM2_Packet_ParseBytes(cmd, objectName, objectNameSz);
    }

    /* Parse TPM2B_NAME newParentName */
    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &newParentNameSz);
        if (newParentNameSz > sizeof(newParentName)) {
            rc = TPM_RC_SIZE;
        }
    }
    if (rc == 0 && newParentNameSz > 0) {
        TPM2_Packet_ParseBytes(cmd, newParentName, newParentNameSz);
    }

    /* Parse includeObject (TPMI_YES_NO = UINT8) */
    if (rc == 0) {
        TPM2_Packet_ParseU8(cmd, &includeObject);
        if (includeObject > 1) {
            rc = TPM_RC_VALUE;
        }
    }

    if (rc == 0) {
        FWTPM_DECLARE_VAR(hashCtx, wc_HashAlg);
        enum wc_HashType wcHash = FwGetWcHashType(sess->authHash);
        int digestSz = TPM2_GetHashDigestSize(sess->authHash);
        byte ccBuf[4];
        UINT32 cc = TPM_CC_PolicyDuplicationSelect;

        FWTPM_ALLOC_VAR(hashCtx, wc_HashAlg);

    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: PolicyDuplicationSelect(session=0x%x, include=%d)\n",
            sess->handle, includeObject);
    #endif

        if (digestSz <= 0) {
            rc = TPM_RC_HASH;
        }
        if (rc == 0) {
            if (wc_HashInit_ex(hashCtx, wcHash, NULL, INVALID_DEVID) != 0) {
                rc = TPM_RC_FAILURE;
            }
        }
        if (rc == 0) {
            wc_HashUpdate(hashCtx, wcHash,
                sess->policyDigest.buffer, sess->policyDigest.size);
            FwStoreU32BE(ccBuf, cc);
            wc_HashUpdate(hashCtx, wcHash, ccBuf, 4);
            if (includeObject && objectNameSz > 0) {
                wc_HashUpdate(hashCtx, wcHash, objectName, objectNameSz);
            }
            if (newParentNameSz > 0) {
                wc_HashUpdate(hashCtx, wcHash,
                    newParentName, newParentNameSz);
            }
            wc_HashUpdate(hashCtx, wcHash, &includeObject, 1);
            wc_HashFinal(hashCtx, wcHash, sess->policyDigest.buffer);
            sess->policyDigest.size = (UINT16)digestSz;
            wc_HashFree(hashCtx, wcHash);
        }

        FWTPM_FREE_VAR(hashCtx);
    }
    if (rc == 0) {
        FwRspNoParams(rsp, cmdTag);
    }

    return rc;
}

/* --- TPM2_PolicyCounterTimer (CC 0x016D) --- */
/* Compare TPMS_TIME_INFO fields against operand with operation enum.
 * policyDigest = H(policyDigest || CC || H(operandB || offset || operation))
 * Per TPM 2.0 spec Section 23.10. */
static TPM_RC FwCmd_PolicyCounterTimer(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    FWTPM_Session* sess;
    UINT16 operandBSz = 0;
    byte operandB[32];
    UINT16 offset = 0;
    UINT16 operation = 0;
    byte timeInfo[25]; /* time(8)+clock(8)+resetCount(4)+restartCount(4)+safe(1) */
    FWTPM_DECLARE_VAR(hashCtx, wc_HashAlg);
    enum wc_HashType wcHash;
    int dSz;
    byte argsHash[TPM_MAX_DIGEST_SIZE];
    byte ccBuf[4];
    byte tmpBuf[4];
    UINT32 cc = TPM_CC_PolicyCounterTimer;
    int hashCtxInit = 0;

    (void)cmdSize;

    FWTPM_ALLOC_VAR(hashCtx, wc_HashAlg);

    sess = FwPolicyParseSession(ctx, cmd, cmdSize, cmdTag);
    if (sess == NULL) {
        rc = TPM_RC_VALUE;
    }
    if (rc == 0 && sess->sessionType != TPM_SE_POLICY &&
        sess->sessionType != TPM_SE_TRIAL) {
        rc = TPM_RC_AUTH_TYPE;
    }

    /* Parse operandB (TPM2B) */
    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &operandBSz);
        if (operandBSz > sizeof(operandB))
            rc = TPM_RC_SIZE;
    }
    if (rc == 0 && operandBSz > 0) {
        TPM2_Packet_ParseBytes(cmd, operandB, operandBSz);
    }
    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &offset);
        TPM2_Packet_ParseU16(cmd, &operation);
    }

    /* Marshal TPMS_TIME_INFO into timeInfo buffer */
    if (rc == 0) {
        int p = 0;
        UINT64 t = FWTPM_Clock_GetMs(ctx);
        /* time (8 bytes big-endian) */
        FwStoreU64BE(timeInfo + p, t); p += 8;
        /* clockInfo.clock (8 bytes) */
        FwStoreU64BE(timeInfo + p, t); p += 8;
        /* resetCount(4) + restartCount(4) + safe(1) */
        timeInfo[p++] = 0; timeInfo[p++] = 0;
        timeInfo[p++] = 0; timeInfo[p++] = 0;
        timeInfo[p++] = 0; timeInfo[p++] = 0;
        timeInfo[p++] = 0; timeInfo[p++] = 0;
        timeInfo[p++] = 1; /* safe = YES */

        if ((UINT32)offset + operandBSz > (UINT32)p) {
            rc = TPM_RC_RANGE;
        }
    }

    /* For policy sessions (not trial): compare timeInfo with operandB */
    if (rc == 0 && sess->sessionType == TPM_SE_POLICY) {
        byte* data = timeInfo + offset;
        int pass = 0;
        int cmpResult = 0;
        int signedCmpResult = 0;
        int i;

        for (i = 0; i < (int)operandBSz; i++) {
            if (data[i] < operandB[i]) {
                cmpResult = -1;
                break;
            }
            else if (data[i] > operandB[i]) {
                cmpResult = 1;
                break;
            }
        }

        /* For signed comparisons, check sign bits (big-endian MSB) */
        signedCmpResult = cmpResult;
        if (operandBSz > 0) {
            int nvSign = (data[0] & 0x80) ? 1 : 0;
            int opSign = (operandB[0] & 0x80) ? 1 : 0;
            if (nvSign != opSign) {
                signedCmpResult = nvSign ? -1 : 1;
            }
        }

        switch (operation) {
            case TPM_EO_EQ:          pass = (cmpResult == 0); break;
            case TPM_EO_NEQ:         pass = (cmpResult != 0); break;
            case TPM_EO_SIGNED_GT:   pass = (signedCmpResult > 0); break;
            case TPM_EO_UNSIGNED_GT: pass = (cmpResult > 0); break;
            case TPM_EO_SIGNED_LT:   pass = (signedCmpResult < 0); break;
            case TPM_EO_UNSIGNED_LT: pass = (cmpResult < 0); break;
            case TPM_EO_SIGNED_GE:   pass = (signedCmpResult >= 0); break;
            case TPM_EO_UNSIGNED_GE: pass = (cmpResult >= 0); break;
            case TPM_EO_SIGNED_LE:   pass = (signedCmpResult <= 0); break;
            case TPM_EO_UNSIGNED_LE: pass = (cmpResult <= 0); break;
            case TPM_EO_BITSET:
                pass = 1;
                for (i = 0; i < (int)operandBSz; i++) {
                    if ((data[i] & operandB[i]) != operandB[i]) {
                        pass = 0; break;
                    }
                }
                break;
            case TPM_EO_BITCLEAR:
                pass = 1;
                for (i = 0; i < (int)operandBSz; i++) {
                    if ((data[i] & operandB[i]) != 0) {
                        pass = 0; break;
                    }
                }
                break;
            default:
                rc = TPM_RC_VALUE;
                break;
        }
        if (rc == 0 && !pass) {
            rc = TPM_RC_POLICY;
        }
    }

#ifdef DEBUG_WOLFTPM
    if (rc == 0) {
        printf("fwTPM: PolicyCounterTimer(session=0x%x, offset=%d, op=%d)\n",
            sess->handle, offset, operation);
    }
#endif

    /* Extend: policyDigest = H(policyDigest || CC || H(operandB || offset || operation)) */
    if (rc == 0) {
        dSz = TPM2_GetHashDigestSize(sess->authHash);
        wcHash = FwGetWcHashType(sess->authHash);
        if (dSz <= 0)
            rc = TPM_RC_HASH;
    }
    /* Compute argsHash = H(operandB || offset || operation) */
    if (rc == 0) {
        if (wc_HashInit_ex(hashCtx, wcHash, NULL, INVALID_DEVID) != 0) {
            rc = TPM_RC_FAILURE;
        }
        else {
            hashCtxInit = 1;
        }
    }
    if (rc == 0 && operandBSz > 0) {
        wc_HashUpdate(hashCtx, wcHash, operandB, operandBSz);
    }
    if (rc == 0) {
        FwStoreU16BE(tmpBuf, offset);
        wc_HashUpdate(hashCtx, wcHash, tmpBuf, 2);
        FwStoreU16BE(tmpBuf, operation);
        wc_HashUpdate(hashCtx, wcHash, tmpBuf, 2);
        wc_HashFinal(hashCtx, wcHash, argsHash);
        wc_HashFree(hashCtx, wcHash);
        hashCtxInit = 0;
    }
    /* policyDigest = H(policyDigest || CC || argsHash) */
    if (rc == 0) {
        if (wc_HashInit_ex(hashCtx, wcHash, NULL, INVALID_DEVID) != 0) {
            rc = TPM_RC_FAILURE;
        }
        else {
            hashCtxInit = 1;
        }
    }
    if (rc == 0) {
        wc_HashUpdate(hashCtx, wcHash,
            sess->policyDigest.buffer, sess->policyDigest.size);
        FwStoreU32BE(ccBuf, cc);
        wc_HashUpdate(hashCtx, wcHash, ccBuf, 4);
        wc_HashUpdate(hashCtx, wcHash, argsHash, dSz);
        wc_HashFinal(hashCtx, wcHash, sess->policyDigest.buffer);
        sess->policyDigest.size = (UINT16)dSz;
    }
    if (hashCtxInit) {
        wc_HashFree(hashCtx, wcHash);
    }

    if (rc == 0) {
        FwRspNoParams(rsp, cmdTag);
    }

    FWTPM_FREE_VAR(hashCtx);
    return rc;
}

/* --- TPM2_PolicyTicket (CC 0x0172) --- */
/* Like PolicySigned/PolicySecret but using a ticket from a prior
 * authorization. Per TPM 2.0 spec Section 23.5. */
static TPM_RC FwCmd_PolicyTicket(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 sessHandle;
    UINT16 timeoutSz, cpHashASz, policyRefSz, authNameSz;
    byte cpHashABuf[TPM_MAX_DIGEST_SIZE];
    byte policyRefBuf[64];
    byte authNameBuf[sizeof(TPM2B_NAME)];
    UINT16 ticketTag, ticketDigestSz;
    UINT32 ticketHier;
    byte ticketDigest[TPM_MAX_DIGEST_SIZE];
    FWTPM_Session* sess;
    INT32 expiration = 0;
    UINT32 extendCC;
    int cpaSizeMismatch;
    int cpaDiff;
    word32 cpaCmpSz;
    (void)cmdSize;

    TPM2_Packet_ParseU32(cmd, &sessHandle);
    if (cmdTag == TPM_ST_SESSIONS)
        rc = FwSkipAuthArea(cmd, cmdSize);

    /* Parse timeout (TPM2B) - skip, we use expiration=0 for ticket verify */
    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &timeoutSz);
        if (timeoutSz > 8)
            rc = TPM_RC_SIZE;
    }
    if (rc == 0) {
        cmd->pos += timeoutSz;
    }

    /* Parse cpHashA (TPM2B) */
    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &cpHashASz);
        if (cpHashASz > sizeof(cpHashABuf))
            rc = TPM_RC_SIZE;
    }
    if (rc == 0 && cpHashASz > 0) {
        TPM2_Packet_ParseBytes(cmd, cpHashABuf, cpHashASz);
    }

    /* Parse policyRef (TPM2B) */
    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &policyRefSz);
        if (policyRefSz > sizeof(policyRefBuf))
            rc = TPM_RC_SIZE;
    }
    if (rc == 0 && policyRefSz > 0) {
        TPM2_Packet_ParseBytes(cmd, policyRefBuf, policyRefSz);
    }

    /* Parse authName (TPM2B_NAME) */
    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &authNameSz);
        if (authNameSz > sizeof(authNameBuf))
            rc = TPM_RC_SIZE;
    }
    if (rc == 0 && authNameSz > 0) {
        TPM2_Packet_ParseBytes(cmd, authNameBuf, authNameSz);
    }

    /* Parse ticket (TPMT_TK_AUTH): tag(2) + hierarchy(4) + digest(TPM2B) */
    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &ticketTag);
        TPM2_Packet_ParseU32(cmd, &ticketHier);
        TPM2_Packet_ParseU16(cmd, &ticketDigestSz);
        if (ticketDigestSz > sizeof(ticketDigest))
            rc = TPM_RC_SIZE;
    }
    if (rc == 0 && ticketDigestSz > 0) {
        TPM2_Packet_ParseBytes(cmd, ticketDigest, ticketDigestSz);
    }

    /* Validate ticket tag */
    if (rc == 0 && ticketTag != TPM_ST_AUTH_SIGNED &&
        ticketTag != TPM_ST_AUTH_SECRET) {
        rc = TPM_RC_TICKET;
    }

    sess = FwFindSession(ctx, sessHandle);
    if (sess == NULL) {
        rc = TPM_RC_VALUE;
    }
    if (rc == 0 && sess->sessionType != TPM_SE_POLICY &&
        sess->sessionType != TPM_SE_TRIAL) {
        rc = TPM_RC_AUTH_TYPE;
    }

    /* Verify ticket HMAC:
     * aHash = H(nonceTPM || expiration || cpHashA || policyRef)
     * ticket = HMAC(proofValue, ticketTag || aHash || authName) */
    if (rc == 0 && ticketDigestSz > 0) {
        byte aHash[TPM_MAX_DIGEST_SIZE];
        byte ticketInput[2 + TPM_MAX_DIGEST_SIZE + sizeof(TPM2B_NAME)];
        int ticketInputSz = 0;
        byte expectedHmac[TPM_MAX_DIGEST_SIZE];
        int expectedSz = 0;
        wc_HashAlg aCtx;
        enum wc_HashType aWcHash;
        int aHashSz;
        byte expBuf[4];
        int hmacRc;
        int sizeMismatch;
        int ticketDiff;
        word32 cmpSz;

        aWcHash = FwGetWcHashType(sess->authHash);
        aHashSz = TPM2_GetHashDigestSize(sess->authHash);

        /* aHash = H(nonceTPM || expiration || cpHashA || policyRef) */
        if (wc_HashInit(&aCtx, aWcHash) == 0) {
            wc_HashUpdate(&aCtx, aWcHash,
                sess->nonceTPM.buffer, sess->nonceTPM.size);
            FwStoreU32BE(expBuf, (UINT32)expiration);
            wc_HashUpdate(&aCtx, aWcHash, expBuf, 4);
            if (cpHashASz > 0)
                wc_HashUpdate(&aCtx, aWcHash, cpHashABuf, cpHashASz);
            if (policyRefSz > 0)
                wc_HashUpdate(&aCtx, aWcHash, policyRefBuf, policyRefSz);
            wc_HashFinal(&aCtx, aWcHash, aHash);
            wc_HashFree(&aCtx, aWcHash);
        }
        else {
            rc = TPM_RC_FAILURE;
        }

        /* ticketInput = aHash || authName */
        if (rc == 0) {
            XMEMCPY(ticketInput, aHash, aHashSz);
            ticketInputSz = aHashSz;
            XMEMCPY(ticketInput + ticketInputSz, authNameBuf, authNameSz);
            ticketInputSz += authNameSz;
        }

        /* Verify HMAC — always run TPM2_ConstantCompare so timing doesn't
         * leak whether size matched */
        if (rc == 0) {
            hmacRc = FwComputeTicketHmac(ctx, ticketHier, sess->authHash,
                ticketInput, ticketInputSz, expectedHmac, &expectedSz);
            sizeMismatch = (ticketDigestSz != (UINT16)expectedSz);
            cmpSz = (ticketDigestSz < (UINT16)expectedSz) ?
                ticketDigestSz : (word32)expectedSz;
            ticketDiff = TPM2_ConstantCompare(ticketDigest, expectedHmac,
                cmpSz);
            if (hmacRc != 0 || (sizeMismatch | ticketDiff)) {
                rc = TPM_RC_POLICY_FAIL;
            }
        }
        TPM2_ForceZero(aHash, sizeof(aHash));
        TPM2_ForceZero(expectedHmac, sizeof(expectedHmac));
    }

    if (rc == 0) {
    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: PolicyTicket(session=0x%x, tag=0x%x)\n",
            sessHandle, ticketTag);
    #endif
        /* Use the CC that originally produced the ticket:
         * PolicySigned for AUTH_SIGNED, PolicySecret for AUTH_SECRET */
        extendCC = (ticketTag == TPM_ST_AUTH_SIGNED) ?
            TPM_CC_PolicySigned : TPM_CC_PolicySecret;
        /* Extend policyDigest with authName + policyRef */
        if (FwPolicyExtend(sess, extendCC,
                authNameBuf, authNameSz,
                policyRefBuf, policyRefSz, 1) != 0) {
            rc = TPM_RC_FAILURE;
        }
    }

    /* Store cpHashA constraint if provided — always run TPM2_ConstantCompare
     * so timing doesn't leak size match */
    if (rc == 0 && cpHashASz > 0) {
        if (sess->cpHashA.size > 0) {
            cpaSizeMismatch = (sess->cpHashA.size != cpHashASz);
            cpaCmpSz = (sess->cpHashA.size < cpHashASz) ?
                sess->cpHashA.size : cpHashASz;
            cpaDiff = TPM2_ConstantCompare(sess->cpHashA.buffer, cpHashABuf,
                cpaCmpSz);
            if (cpaSizeMismatch | cpaDiff) {
                rc = TPM_RC_CPHASH;
            }
        }
        if (rc == 0) {
            sess->cpHashA.size = cpHashASz;
            XMEMCPY(sess->cpHashA.buffer, cpHashABuf, cpHashASz);
        }
    }

    if (rc == 0) {
        FwRspNoParams(rsp, cmdTag);
    }

    return rc;
}

#ifndef FWTPM_NO_NV
/* --- TPM2_PolicyAuthorizeNV (CC 0x0192) --- */
/* Read approved policy from NV index and authorize it.
 * Per TPM 2.0 spec Section 23.22. */
static TPM_RC FwCmd_PolicyAuthorizeNV(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 authHandle, nvHandle, sessHandle;
    FWTPM_NvIndex* nv;
    FWTPM_Session* sess;
    int dSz;
    byte nvName[2 + TPM_MAX_DIGEST_SIZE];
    UINT16 nvNameSz = 0;
    FWTPM_DECLARE_VAR(hashCtx, wc_HashAlg);
    enum wc_HashType wcHash;
    byte ccBuf[4];
    UINT32 cc = TPM_CC_PolicyAuthorizeNV;
    int hashInit = 0;
    int nvSizeMismatch;
    int sessSizeMismatch;
    int policyDiff;
    word32 policyCmpSz;

    (void)cmdSize;

    FWTPM_ALLOC_VAR(hashCtx, wc_HashAlg);

    TPM2_Packet_ParseU32(cmd, &authHandle);
    TPM2_Packet_ParseU32(cmd, &nvHandle);
    TPM2_Packet_ParseU32(cmd, &sessHandle);
    if (cmdTag == TPM_ST_SESSIONS)
        rc = FwSkipAuthArea(cmd, cmdSize);

    nv = FwFindNvIndex(ctx, nvHandle);
    if (nv == NULL) {
        rc = FW_NV_HANDLE_ERR_2;
    }

    if (rc == 0 && !nv->written) {
        rc = TPM_RC_NV_UNINITIALIZED;
    }

    sess = FwFindSession(ctx, sessHandle);
    if (sess == NULL) {
        rc = TPM_RC_VALUE;
    }
    if (rc == 0 && sess->sessionType != TPM_SE_POLICY &&
        sess->sessionType != TPM_SE_TRIAL) {
        rc = TPM_RC_AUTH_TYPE;
    }

    if (rc == 0) {
        dSz = TPM2_GetHashDigestSize(sess->authHash);
        if (dSz <= 0)
            rc = TPM_RC_HASH;
    }

    /* For policy sessions (not trial): verify policyDigest == NV data.
     * Always run TPM2_ConstantCompare over min(sizes) so timing doesn't
     * leak size match. */
    if (rc == 0 && sess->sessionType == TPM_SE_POLICY) {
        nvSizeMismatch = ((int)nv->nvPublic.dataSize != dSz);
        sessSizeMismatch = ((int)sess->policyDigest.size != dSz);
        policyCmpSz = (sess->policyDigest.size < nv->nvPublic.dataSize) ?
            sess->policyDigest.size : nv->nvPublic.dataSize;
        if (policyCmpSz > (word32)dSz)
            policyCmpSz = (word32)dSz;
        policyDiff = TPM2_ConstantCompare(sess->policyDigest.buffer,
            nv->data, policyCmpSz);
        if (nvSizeMismatch | sessSizeMismatch | policyDiff) {
            rc = TPM_RC_POLICY_FAIL;
        }
    }

    if (rc == 0) {
    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: PolicyAuthorizeNV(auth=0x%x, nv=0x%x, sess=0x%x)\n",
            authHandle, nvHandle, sessHandle);
    #endif
        (void)authHandle;

        /* Step 1: Reset policyDigest to zero */
        XMEMSET(sess->policyDigest.buffer, 0, dSz);
        sess->policyDigest.size = (UINT16)dSz;

        /* Compute nvIndexName */
        FwComputeNvName(nv, nvName, &nvNameSz);

        /* Step 2: policyDigest = H(policyDigest || CC || nvIndexName) */
        wcHash = FwGetWcHashType(sess->authHash);
        if (wc_HashInit_ex(hashCtx, wcHash, NULL, INVALID_DEVID) != 0) {
            rc = TPM_RC_FAILURE;
        }
        else {
            hashInit = 1;
        }
        if (rc == 0) {
            wc_HashUpdate(hashCtx, wcHash,
                sess->policyDigest.buffer, sess->policyDigest.size);
            FwStoreU32BE(ccBuf, cc);
            wc_HashUpdate(hashCtx, wcHash, ccBuf, 4);
            if (nvNameSz > 0)
                wc_HashUpdate(hashCtx, wcHash, nvName, nvNameSz);
            wc_HashFinal(hashCtx, wcHash, sess->policyDigest.buffer);
            sess->policyDigest.size = (UINT16)dSz;
        }
        if (hashInit) {
            wc_HashFree(hashCtx, wcHash);
        }
    }

    if (rc == 0) {
        FwRspNoParams(rsp, cmdTag);
    }

    FWTPM_FREE_VAR(hashCtx);
    return rc;
}
#endif /* !FWTPM_NO_NV (PolicyAuthorizeNV) */

#endif /* !FWTPM_NO_POLICY */

/* ================================================================== */
/* NV RAM Helper                                                       */
/* ================================================================== */

#ifndef FWTPM_NO_NV
/* Find NV index slot by handle (returns NULL if not found) */
static FWTPM_NvIndex* FwFindNvIndex(FWTPM_CTX* ctx, TPMI_RH_NV_INDEX nvIndex)
{
    int i;
    for (i = 0; i < FWTPM_MAX_NV_INDICES; i++) {
        if (ctx->nvIndices[i].inUse &&
            ctx->nvIndices[i].nvPublic.nvIndex == nvIndex) {
            return &ctx->nvIndices[i];
        }
    }
    return NULL;
}
#endif /* !FWTPM_NO_NV */

/* NV handle error codes (include handle reference bits per TPM 2.0 spec) */
/* (FW_NV_HANDLE_ERR_1/2 defined earlier - before policy section) */


#ifndef FWTPM_NO_NV
/* ================================================================== */
/* NV RAM Commands                                                     */
/* ================================================================== */

/* Check NV access authorization per TPM 2.0 Part 3 Section 31.
 * Returns TPM_RC_SUCCESS if authorized, TPM_RC_NV_AUTHORIZATION otherwise.
 * isWrite: 1 = write/extend/increment/setbits/writelock,
 *          0 = read/readlock/certify */
static TPM_RC FwNvCheckAccess(TPM_HANDLE authHandle,
    TPMI_RH_NV_INDEX nvHandle, UINT32 attributes, int isWrite)
{
    if (isWrite) {
        if (authHandle == TPM_RH_PLATFORM) {
            if (!(attributes & TPMA_NV_PPWRITE))
                return TPM_RC_NV_AUTHORIZATION;
        }
        else if (authHandle == TPM_RH_OWNER) {
            if (!(attributes & TPMA_NV_OWNERWRITE))
                return TPM_RC_NV_AUTHORIZATION;
            if (attributes & TPMA_NV_PLATFORMCREATE)
                return TPM_RC_NV_AUTHORIZATION;
        }
        else if (authHandle == (TPM_HANDLE)nvHandle) {
            if (!(attributes & (TPMA_NV_AUTHWRITE | TPMA_NV_POLICYWRITE)))
                return TPM_RC_NV_AUTHORIZATION;
        }
        else {
            return TPM_RC_NV_AUTHORIZATION;
        }
    }
    else {
        if (authHandle == TPM_RH_PLATFORM) {
            if (!(attributes & TPMA_NV_PPREAD))
                return TPM_RC_NV_AUTHORIZATION;
        }
        else if (authHandle == TPM_RH_OWNER) {
            if (!(attributes & TPMA_NV_OWNERREAD))
                return TPM_RC_NV_AUTHORIZATION;
            if (attributes & TPMA_NV_PLATFORMCREATE)
                return TPM_RC_NV_AUTHORIZATION;
        }
        else if (authHandle == (TPM_HANDLE)nvHandle) {
            if (!(attributes & (TPMA_NV_AUTHREAD | TPMA_NV_POLICYREAD)))
                return TPM_RC_NV_AUTHORIZATION;
        }
        else {
            return TPM_RC_NV_AUTHORIZATION;
        }
    }
    return TPM_RC_SUCCESS;
}

/* --- TPM2_NV_DefineSpace (CC 0x012A) --- */
static TPM_RC FwCmd_NV_DefineSpace(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    TPM_HANDLE authHandle = 0;
    TPM2B_AUTH auth;
    TPM2B_NV_PUBLIC publicInfo;
    FWTPM_NvIndex* slot = NULL;
    int i;

    (void)cmdSize;
    XMEMSET(&auth, 0, sizeof(auth));
    XMEMSET(&publicInfo, 0, sizeof(publicInfo));

    /* Parse handle */
    TPM2_Packet_ParseU32(cmd, &authHandle);

    /* Skip auth area */
    if (cmdTag == TPM_ST_SESSIONS) rc = FwSkipAuthArea(cmd, cmdSize);

    /* 1st param: TPM2B_AUTH (NV auth value) */
    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &auth.size);
        if (auth.size > sizeof(auth.buffer)) {
            rc = TPM_RC_SIZE;
        }
        else if (cmd->pos + auth.size > cmdSize) {
            rc = TPM_RC_COMMAND_SIZE;
        }
    }
    if (rc == 0) {
        TPM2_Packet_ParseBytes(cmd, auth.buffer, auth.size);
    }

    /* 2nd param: TPM2B_NV_PUBLIC */
    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &publicInfo.size);
        TPM2_Packet_ParseU32(cmd, &publicInfo.nvPublic.nvIndex);
        TPM2_Packet_ParseU16(cmd, &publicInfo.nvPublic.nameAlg);
        TPM2_Packet_ParseU32(cmd, &publicInfo.nvPublic.attributes);
        TPM2_Packet_ParseU16(cmd, &publicInfo.nvPublic.authPolicy.size);
        if (publicInfo.nvPublic.authPolicy.size >
                sizeof(publicInfo.nvPublic.authPolicy.buffer)) {
            rc = TPM_RC_SIZE;
        }
    }
    if (rc == 0) {
        TPM2_Packet_ParseBytes(cmd, publicInfo.nvPublic.authPolicy.buffer,
            publicInfo.nvPublic.authPolicy.size);
        TPM2_Packet_ParseU16(cmd, &publicInfo.nvPublic.dataSize);
        if (publicInfo.nvPublic.dataSize > FWTPM_MAX_NV_DATA) {
            rc = TPM_RC_NV_SIZE;
        }
    }

    /* Validate NV index handle range */
    if (rc == 0) {
        UINT32 nvIdx = publicInfo.nvPublic.nvIndex;
        if (nvIdx < NV_INDEX_FIRST || nvIdx > NV_INDEX_LAST) {
            rc = TPM_RC_NV_RANGE;
        }
    }

    /* Validate NV type (TPM_NT) — reject reserved values */
    if (rc == 0) {
        UINT32 nt = (publicInfo.nvPublic.attributes & TPMA_NV_TPM_NT) >> 4;
        if (nt > TPM_NT_PIN_PASS && nt != TPM_NT_PIN_FAIL) {
            rc = TPM_RC_ATTRIBUTES;
        }
    }

    /* Check for duplicate */
    if (rc == 0 && FwFindNvIndex(ctx, publicInfo.nvPublic.nvIndex) != NULL) {
        rc = TPM_RC_NV_DEFINED;
    }

    /* Find free slot */
    if (rc == 0) {
        for (i = 0; i < FWTPM_MAX_NV_INDICES; i++) {
            if (!ctx->nvIndices[i].inUse) {
                slot = &ctx->nvIndices[i];
                break;
            }
        }
        if (slot == NULL) {
            rc = TPM_RC_NV_SPACE;
        }
    }

    /* Initialize slot */
    if (rc == 0) {
        int nt;
        XMEMSET(slot, 0, sizeof(FWTPM_NvIndex));
        slot->inUse = 1;
        XMEMCPY(&slot->nvPublic, &publicInfo.nvPublic,
            sizeof(TPMS_NV_PUBLIC));
        slot->authValue.size = auth.size;
        if (auth.size > 0) {
            XMEMCPY(slot->authValue.buffer, auth.buffer, auth.size);
        }
        slot->written = 0;

        /* Initialize NV_COUNTER/NV_BITS to zero */
        nt = (int)((slot->nvPublic.attributes & TPMA_NV_TPM_NT) >> 4);
        if (nt == TPM_NT_COUNTER || nt == TPM_NT_BITS) {
            XMEMSET(slot->data, 0, 8);
            slot->written = 1;
        }
        else if (nt == TPM_NT_EXTEND) {
            int hSz = TPM2_GetHashDigestSize(slot->nvPublic.nameAlg);
            if (hSz > 0) {
                XMEMSET(slot->data, 0, hSz);
            }
            slot->written = 1;
        }

        FWTPM_NV_SaveNvIndex(ctx,
            (int)(slot - ctx->nvIndices));
        (void)authHandle;
        FwRspNoParams(rsp, cmdTag);
    }

    TPM2_ForceZero(&auth, sizeof(auth));
    return rc;
}

/* --- TPM2_NV_UndefineSpace (CC 0x0122) --- */
static TPM_RC FwCmd_NV_UndefineSpace(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    TPM_HANDLE authHandle = 0;
    FWTPM_NvIndex* nv = NULL;
    TPMI_RH_NV_INDEX nvHandle = 0;

    (void)cmdSize;

    TPM2_Packet_ParseU32(cmd, &authHandle);
    TPM2_Packet_ParseU32(cmd, &nvHandle);
    if (cmdTag == TPM_ST_SESSIONS) rc = FwSkipAuthArea(cmd, cmdSize);

    nv = FwFindNvIndex(ctx, nvHandle);
    if (nv == NULL) {
        rc = FW_NV_HANDLE_ERR_2;
    }

    /* Cannot delete POLICY_DELETE without special command */
    if (rc == 0 && (nv->nvPublic.attributes & TPMA_NV_POLICY_DELETE)) {
        rc = TPM_RC_ATTRIBUTES;
    }

    if (rc == 0) {
        XMEMSET(nv, 0, sizeof(FWTPM_NvIndex));
        FWTPM_NV_DeleteNvIndex(ctx, nvHandle);
        FwRspNoParams(rsp, cmdTag);
    }

    return rc;
}

/* --- TPM2_NV_UndefineSpaceSpecial (CC 0x011F) --- */
/* Delete an NV index that has TPMA_NV_POLICY_DELETE set.
 * Requires platform auth + policy session on the NV index. */
static TPM_RC FwCmd_NV_UndefineSpaceSpecial(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    TPMI_RH_NV_INDEX nvHandle = 0;
    UINT32 platformHandle = 0;
    FWTPM_NvIndex* nv = NULL;

    (void)cmdSize;

    TPM2_Packet_ParseU32(cmd, &nvHandle);
    TPM2_Packet_ParseU32(cmd, &platformHandle);
    if (cmdTag == TPM_ST_SESSIONS)
        rc = FwSkipAuthArea(cmd, cmdSize);

    /* Second handle must be TPM_RH_PLATFORM */
    if (rc == 0 && platformHandle != TPM_RH_PLATFORM) {
        rc = TPM_RC_HIERARCHY;
    }

    nv = FwFindNvIndex(ctx, nvHandle);
    if (nv == NULL) {
        rc = FW_NV_HANDLE_ERR_1;
    }

    /* Must have TPMA_NV_POLICY_DELETE attribute */
    if (rc == 0 && !(nv->nvPublic.attributes & TPMA_NV_POLICY_DELETE)) {
        rc = TPM_RC_ATTRIBUTES;
    }

    if (rc == 0) {
    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: NV_UndefineSpaceSpecial(nv=0x%x)\n", nvHandle);
    #endif
        XMEMSET(nv, 0, sizeof(FWTPM_NvIndex));
        FWTPM_NV_DeleteNvIndex(ctx, nvHandle);
        FwRspNoParams(rsp, cmdTag);
    }

    return rc;
}

/* --- TPM2_NV_ReadPublic (CC 0x0169) --- */
static TPM_RC FwCmd_NV_ReadPublic(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    TPMI_RH_NV_INDEX nvHandle;
    FWTPM_NvIndex* nv;
    int paramSzPos, paramStart;
    int markPos;
    byte nameBuf[2 + TPM_MAX_DIGEST_SIZE];
    UINT16 nameSz = 0;

    (void)cmdSize;

    TPM2_Packet_ParseU32(cmd, &nvHandle);
    if (cmdTag == TPM_ST_SESSIONS) rc = FwSkipAuthArea(cmd, cmdSize);

    nv = FwFindNvIndex(ctx, nvHandle);
    if (nv == NULL) {
        rc = FW_NV_HANDLE_ERR_1;
    }

    if (rc == 0) {
        paramStart = FwRspParamsBegin(rsp, cmdTag, &paramSzPos);

        /* TPM2B_NV_PUBLIC: size + marshaled fields */
        TPM2_Packet_MarkU16(rsp, &markPos);
        TPM2_Packet_AppendU32(rsp, nv->nvPublic.nvIndex);
        TPM2_Packet_AppendU16(rsp, nv->nvPublic.nameAlg);
        TPM2_Packet_AppendU32(rsp, nv->nvPublic.attributes);
        TPM2_Packet_AppendU16(rsp, nv->nvPublic.authPolicy.size);
        TPM2_Packet_AppendBytes(rsp, nv->nvPublic.authPolicy.buffer,
            nv->nvPublic.authPolicy.size);
        TPM2_Packet_AppendU16(rsp, nv->nvPublic.dataSize);
        TPM2_Packet_PlaceU16(rsp, markPos);

        /* TPM2B_NAME: nameAlg || Hash(nvPublic) */
        FwComputeNvName(nv, nameBuf, &nameSz);
        TPM2_Packet_AppendU16(rsp, nameSz);
        TPM2_Packet_AppendBytes(rsp, nameBuf, nameSz);

        FwRspParamsEnd(rsp, cmdTag, paramSzPos, paramStart);
    }

    return rc;
}

/* --- TPM2_NV_Write (CC 0x0137) --- */
static TPM_RC FwCmd_NV_Write(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    TPM_HANDLE authHandle;
    TPMI_RH_NV_INDEX nvHandle;
    FWTPM_NvIndex* nv;
    UINT16 dataSize = 0, offset = 0;
    FWTPM_DECLARE_BUF(dataBuf, FWTPM_MAX_NV_DATA);

    (void)cmdSize;

    FWTPM_ALLOC_BUF(dataBuf, FWTPM_MAX_NV_DATA);

    TPM2_Packet_ParseU32(cmd, &authHandle);
    TPM2_Packet_ParseU32(cmd, &nvHandle);
    if (cmdTag == TPM_ST_SESSIONS) rc = FwSkipAuthArea(cmd, cmdSize);

    nv = FwFindNvIndex(ctx, nvHandle);
    if (nv == NULL) {
        rc = FW_NV_HANDLE_ERR_2;
    }
    if (rc == 0) {
        rc = FwNvCheckAccess(authHandle, nvHandle,
            nv->nvPublic.attributes, 1);
    }

    /* Per TPM 2.0 Part 3 Section 31.3, NV_Write only valid for ordinary and PIN
     * indices. Counter, Bits, and Extend types must use their dedicated
     * commands (NV_Increment, NV_SetBits, NV_Extend). Allowing NV_Write on
     * counters would let an attacker reset a monotonic counter to zero. */
    if (rc == 0) {
        UINT32 nt = (nv->nvPublic.attributes & TPMA_NV_TPM_NT) >> 4;
        if (nt != TPM_NT_ORDINARY && nt != TPM_NT_PIN_FAIL &&
            nt != TPM_NT_PIN_PASS) {
            rc = TPM_RC_ATTRIBUTES;
        }
    }

    if (rc == 0 && (nv->nvPublic.attributes & TPMA_NV_WRITELOCKED)) {
        rc = TPM_RC_NV_LOCKED;
    }
    if (rc == 0 && ctx->globalNvWriteLock &&
        (nv->nvPublic.attributes & TPMA_NV_GLOBALLOCK)) {
        rc = TPM_RC_NV_LOCKED;
    }

    /* Parse: TPM2B data + offset */
    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &dataSize);
        if (dataSize > FWTPM_MAX_NV_DATA) {
            rc = TPM_RC_SIZE;
        }
        else if (cmd->pos + dataSize > cmdSize) {
            rc = TPM_RC_COMMAND_SIZE;
        }
    }
    if (rc == 0) {
        TPM2_Packet_ParseBytes(cmd, dataBuf, dataSize);
        TPM2_Packet_ParseU16(cmd, &offset);

        if ((UINT32)offset + dataSize > nv->nvPublic.dataSize) {
            rc = TPM_RC_NV_RANGE;
        }
    }

    /* For WRITEALL: entire space must be written at once */
    if (rc == 0 && (nv->nvPublic.attributes & TPMA_NV_WRITEALL) &&
        (dataSize != nv->nvPublic.dataSize || offset != 0)) {
        rc = TPM_RC_NV_RANGE;
    }

    if (rc == 0) {
        XMEMCPY(nv->data + offset, dataBuf, dataSize);
        nv->written = 1;

        /* Set WRITTEN attribute */
        nv->nvPublic.attributes |= 0x20000000UL; /* TPMA_NV_WRITTEN */

        /* Note: TPMA_NV_WRITEDEFINE means the index CAN be write-locked via
         * explicit NV_WriteLock command. It does NOT auto-lock on each write.
         * TPMA_NV_WRITE_STCLEAR auto-locks on write (cleared on SU_CLEAR). */
        if (nv->nvPublic.attributes & TPMA_NV_WRITE_STCLEAR) {
            nv->nvPublic.attributes |= TPMA_NV_WRITELOCKED;
        }

        FWTPM_NV_SaveNvIndex(ctx, (int)(nv - ctx->nvIndices));

        FwRspNoParams(rsp, cmdTag);
    }

    FWTPM_FREE_BUF(dataBuf);
    return rc;
}

/* --- TPM2_NV_Read (CC 0x014E) --- */
static TPM_RC FwCmd_NV_Read(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    TPM_HANDLE authHandle;
    TPMI_RH_NV_INDEX nvHandle;
    FWTPM_NvIndex* nv;
    UINT16 readSize = 0, offset = 0;
    int paramSzPos, paramStart;

    (void)cmdSize;

    TPM2_Packet_ParseU32(cmd, &authHandle);
    TPM2_Packet_ParseU32(cmd, &nvHandle);
    if (cmdTag == TPM_ST_SESSIONS) rc = FwSkipAuthArea(cmd, cmdSize);

    nv = FwFindNvIndex(ctx, nvHandle);
    if (nv == NULL) {
        rc = FW_NV_HANDLE_ERR_2;
    }
    if (rc == 0) {
        rc = FwNvCheckAccess(authHandle, nvHandle,
            nv->nvPublic.attributes, 0);
    }

    if (rc == 0 && (nv->nvPublic.attributes & TPMA_NV_READLOCKED)) {
        rc = TPM_RC_NV_LOCKED;
    }
    if (rc == 0 && !nv->written) {
        rc = TPM_RC_NV_UNINITIALIZED;
    }

    /* Parse: size + offset */
    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &readSize);
        TPM2_Packet_ParseU16(cmd, &offset);

        if (readSize == 0) {
            readSize = nv->nvPublic.dataSize;
        }
        if ((UINT32)offset + readSize > nv->nvPublic.dataSize) {
            rc = TPM_RC_NV_RANGE;
        }
    }

    if (rc == 0) {
        paramStart = FwRspParamsBegin(rsp, cmdTag, &paramSzPos);
        TPM2_Packet_AppendU16(rsp, readSize);
        TPM2_Packet_AppendBytes(rsp, nv->data + offset, readSize);
        FwRspParamsEnd(rsp, cmdTag, paramSzPos, paramStart);
    }

    return rc;
}

/* --- TPM2_NV_Extend (CC 0x0136) --- */
static TPM_RC FwCmd_NV_Extend(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    TPM_HANDLE authHandle;
    TPMI_RH_NV_INDEX nvHandle;
    FWTPM_NvIndex* nv;
    UINT16 dataSize = 0;
    byte dataBuf[TPM_MAX_DIGEST_SIZE * 2]; /* input data */
    int hSz = 0;
    FWTPM_DECLARE_VAR(hashCtx, wc_HashAlg);
    enum wc_HashType wcHash;
    byte newVal[TPM_MAX_DIGEST_SIZE];
    int hashInit = 0;

    (void)cmdSize;

    FWTPM_ALLOC_VAR(hashCtx, wc_HashAlg);

    TPM2_Packet_ParseU32(cmd, &authHandle);
    TPM2_Packet_ParseU32(cmd, &nvHandle);
    if (cmdTag == TPM_ST_SESSIONS) rc = FwSkipAuthArea(cmd, cmdSize);

    nv = FwFindNvIndex(ctx, nvHandle);
    if (nv == NULL) {
        rc = FW_NV_HANDLE_ERR_2;
    }
    if (rc == 0) {
        rc = FwNvCheckAccess(authHandle, nvHandle,
            nv->nvPublic.attributes, 1);
    }

    if (rc == 0 && (nv->nvPublic.attributes & TPMA_NV_WRITELOCKED)) {
        rc = TPM_RC_NV_LOCKED;
    }
    if (rc == 0 && ctx->globalNvWriteLock &&
        (nv->nvPublic.attributes & TPMA_NV_GLOBALLOCK)) {
        rc = TPM_RC_NV_LOCKED;
    }
    if (rc == 0 && ((nv->nvPublic.attributes & TPMA_NV_TPM_NT) >> 4)
        != TPM_NT_EXTEND) {
        rc = TPM_RC_ATTRIBUTES;
    }

    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &dataSize);
        if (dataSize > sizeof(dataBuf)) {
            rc = TPM_RC_SIZE;
        }
        else if (cmd->pos + dataSize > cmdSize) {
            rc = TPM_RC_COMMAND_SIZE;
        }
    }
    if (rc == 0) {
        TPM2_Packet_ParseBytes(cmd, dataBuf, dataSize);

        hSz = TPM2_GetHashDigestSize(nv->nvPublic.nameAlg);
        if (hSz <= 0 || hSz > FWTPM_MAX_NV_DATA) {
            rc = TPM_RC_HASH;
        }
    }

    /* Extend: newVal = H(oldVal || data) */
    if (rc == 0) {
        wcHash = FwGetWcHashType(nv->nvPublic.nameAlg);
        if (wc_HashInit_ex(hashCtx, wcHash, NULL, INVALID_DEVID) != 0) {
            rc = TPM_RC_FAILURE;
        }
        else {
            hashInit = 1;
        }
    }
    if (rc == 0) {
        wc_HashUpdate(hashCtx, wcHash, nv->data, hSz);
        wc_HashUpdate(hashCtx, wcHash, dataBuf, dataSize);
        wc_HashFinal(hashCtx, wcHash, newVal);
        XMEMCPY(nv->data, newVal, hSz);

        nv->written = 1;
        nv->nvPublic.attributes |= 0x20000000UL; /* TPMA_NV_WRITTEN */

        FWTPM_NV_SaveNvIndex(ctx, (int)(nv - ctx->nvIndices));

        FwRspNoParams(rsp, cmdTag);
    }
    if (hashInit) {
        wc_HashFree(hashCtx, wcHash);
    }

    FWTPM_FREE_VAR(hashCtx);
    return rc;
}

/* --- TPM2_NV_Increment (CC 0x0134) --- */
static TPM_RC FwCmd_NV_Increment(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    TPM_HANDLE authHandle;
    TPMI_RH_NV_INDEX nvHandle;
    FWTPM_NvIndex* nv;
    UINT64 counter;

    (void)cmdSize;

    TPM2_Packet_ParseU32(cmd, &authHandle);
    TPM2_Packet_ParseU32(cmd, &nvHandle);
    if (cmdTag == TPM_ST_SESSIONS) rc = FwSkipAuthArea(cmd, cmdSize);

    nv = FwFindNvIndex(ctx, nvHandle);
    if (nv == NULL) {
        rc = FW_NV_HANDLE_ERR_2;
    }
    if (rc == 0) {
        rc = FwNvCheckAccess(authHandle, nvHandle,
            nv->nvPublic.attributes, 1);
    }

    if (rc == 0 && (nv->nvPublic.attributes & TPMA_NV_WRITELOCKED)) {
        rc = TPM_RC_NV_LOCKED;
    }
    if (rc == 0 && ctx->globalNvWriteLock &&
        (nv->nvPublic.attributes & TPMA_NV_GLOBALLOCK)) {
        rc = TPM_RC_NV_LOCKED;
    }
    if (rc == 0 && ((nv->nvPublic.attributes & TPMA_NV_TPM_NT) >> 4)
        != TPM_NT_COUNTER) {
        rc = TPM_RC_ATTRIBUTES;
    }

    if (rc == 0) {
        /* Read big-endian counter, increment, write back */
        counter = FwLoadU64BE(nv->data);
        counter++;
        FwStoreU64BE(nv->data, counter);
        nv->written = 1;
        nv->nvPublic.attributes |= 0x20000000UL; /* TPMA_NV_WRITTEN */

        FWTPM_NV_SaveNvIndex(ctx, (int)(nv - ctx->nvIndices));

        FwRspNoParams(rsp, cmdTag);
    }

    return rc;
}

/* --- TPM2_NV_WriteLock (CC 0x0138) --- */
static TPM_RC FwCmd_NV_WriteLock(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    TPM_HANDLE authHandle;
    TPMI_RH_NV_INDEX nvHandle;
    FWTPM_NvIndex* nv;

    (void)cmdSize;

    TPM2_Packet_ParseU32(cmd, &authHandle);
    TPM2_Packet_ParseU32(cmd, &nvHandle);
    if (cmdTag == TPM_ST_SESSIONS) rc = FwSkipAuthArea(cmd, cmdSize);

    nv = FwFindNvIndex(ctx, nvHandle);
    if (nv == NULL) {
        rc = FW_NV_HANDLE_ERR_2;
    }
    if (rc == 0) {
        rc = FwNvCheckAccess(authHandle, nvHandle,
            nv->nvPublic.attributes, 1);
    }

    /* Per TPM 2.0 Part 3 Section 31.5.2: NV_WriteLock requires
     * TPMA_NV_WRITEDEFINE or TPMA_NV_WRITE_STCLEAR */
    if (rc == 0) {
        if (!(nv->nvPublic.attributes &
                (TPMA_NV_WRITEDEFINE | TPMA_NV_WRITE_STCLEAR))) {
            rc = TPM_RC_ATTRIBUTES;
        }
    }

    if (rc == 0) {
        nv->nvPublic.attributes |= TPMA_NV_WRITELOCKED;
        FWTPM_NV_SaveNvIndex(ctx, (int)(nv - ctx->nvIndices));

        FwRspNoParams(rsp, cmdTag);
    }

    return rc;
}

/* --- TPM2_NV_ReadLock (CC 0x014F) --- */
static TPM_RC FwCmd_NV_ReadLock(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    TPM_HANDLE authHandle;
    TPMI_RH_NV_INDEX nvHandle;
    FWTPM_NvIndex* nv;

    (void)cmdSize;

    TPM2_Packet_ParseU32(cmd, &authHandle);
    TPM2_Packet_ParseU32(cmd, &nvHandle);
    if (cmdTag == TPM_ST_SESSIONS) rc = FwSkipAuthArea(cmd, cmdSize);

    nv = FwFindNvIndex(ctx, nvHandle);
    if (nv == NULL) {
        rc = FW_NV_HANDLE_ERR_2;
    }
    if (rc == 0) {
        rc = FwNvCheckAccess(authHandle, nvHandle,
            nv->nvPublic.attributes, 0);
    }

    /* Per TPM 2.0 Part 3 Section 31.4.2: NV_ReadLock requires
     * TPMA_NV_READ_STCLEAR */
    if (rc == 0) {
        if (!(nv->nvPublic.attributes & TPMA_NV_READ_STCLEAR)) {
            rc = TPM_RC_ATTRIBUTES;
        }
    }

    if (rc == 0) {
        nv->nvPublic.attributes |= TPMA_NV_READLOCKED;
        FWTPM_NV_SaveNvIndex(ctx, (int)(nv - ctx->nvIndices));

        FwRspNoParams(rsp, cmdTag);
    }

    return rc;
}

/* --- TPM2_NV_SetBits (CC 0x0135) --- */
/* OR bits into an NV index that has TPMA_NV_BITS type.
 * Wire: authHandle (U32) → nvIndex (U32) → auth area → bits (U64) */
static TPM_RC FwCmd_NV_SetBits(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    TPM_HANDLE authHandle;
    TPMI_RH_NV_INDEX nvHandle;
    UINT64 bits = 0;
    UINT64 existing = 0;
    FWTPM_NvIndex* nv;

    (void)cmdSize;

    TPM2_Packet_ParseU32(cmd, &authHandle);
    TPM2_Packet_ParseU32(cmd, &nvHandle);
    if (cmdTag == TPM_ST_SESSIONS) rc = FwSkipAuthArea(cmd, cmdSize);

    TPM2_Packet_ParseU64(cmd, &bits);

    nv = FwFindNvIndex(ctx, nvHandle);
    if (nv == NULL) {
        rc = FW_NV_HANDLE_ERR_2;
    }
    if (rc == 0) {
        rc = FwNvCheckAccess(authHandle, nvHandle,
            nv->nvPublic.attributes, 1);
    }

    if (rc == 0 && (nv->nvPublic.attributes & TPMA_NV_WRITELOCKED)) {
        rc = TPM_RC_NV_LOCKED;
    }
    if (rc == 0 && ctx->globalNvWriteLock &&
        (nv->nvPublic.attributes & TPMA_NV_GLOBALLOCK)) {
        rc = TPM_RC_NV_LOCKED;
    }
    if (rc == 0 && ((nv->nvPublic.attributes & TPMA_NV_TPM_NT) >> 4)
        != TPM_NT_BITS) {
        rc = TPM_RC_ATTRIBUTES;
    }

    if (rc == 0) {
    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: NV_SetBits(nv=0x%x, bits=0x%llx)\n",
            nvHandle, (unsigned long long)bits);
    #endif

        /* Read existing big-endian value, OR in bits, write back */
        existing = FwLoadU64BE(nv->data);
        existing |= bits;
        FwStoreU64BE(nv->data, existing);
        nv->written = 1;
        nv->nvPublic.attributes |= 0x20000000UL; /* TPMA_NV_WRITTEN */

        FWTPM_NV_SaveNvIndex(ctx, (int)(nv - ctx->nvIndices));

        FwRspNoParams(rsp, cmdTag);
    }

    return rc;
}

/* --- TPM2_NV_ChangeAuth (CC 0x013B) --- */
/* Change the auth value of an NV index.
 * Wire: nvIndex (U32) → auth area → newAuth (TPM2B_AUTH) */
static TPM_RC FwCmd_NV_ChangeAuth(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    TPMI_RH_NV_INDEX nvHandle;
    UINT16 newAuthSize = 0;
    byte newAuthBuf[TPM_MAX_DIGEST_SIZE];
    FWTPM_NvIndex* nv;

    (void)cmdSize;

    TPM2_Packet_ParseU32(cmd, &nvHandle);
    if (cmdTag == TPM_ST_SESSIONS) rc = FwSkipAuthArea(cmd, cmdSize);

    /* Parse newAuth (TPM2B_AUTH) */
    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &newAuthSize);
        if (newAuthSize > (UINT16)sizeof(newAuthBuf)) {
            rc = TPM_RC_SIZE;
        }
        else if (newAuthSize > 0 && cmd->pos + newAuthSize > cmdSize) {
            rc = TPM_RC_COMMAND_SIZE;
        }
    }
    if (rc == 0 && newAuthSize > 0) {
        TPM2_Packet_ParseBytes(cmd, newAuthBuf, newAuthSize);
    }

    nv = FwFindNvIndex(ctx, nvHandle);
    if (nv == NULL) {
        rc = FW_NV_HANDLE_ERR_1;
    }

    if (rc == 0) {
    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: NV_ChangeAuth(nv=0x%x, newAuthSz=%d)\n",
            nvHandle, newAuthSize);
    #endif

        /* Clear old auth value before overwriting */
        TPM2_ForceZero(nv->authValue.buffer, sizeof(nv->authValue.buffer));
        nv->authValue.size = newAuthSize;
        if (newAuthSize > 0) {
            XMEMCPY(nv->authValue.buffer, newAuthBuf, newAuthSize);
        }

        FWTPM_NV_SaveNvIndex(ctx, (int)(nv - ctx->nvIndices));

        FwRspNoParams(rsp, cmdTag);
    }

    /* Zero stack copy of new auth value before returning */
    TPM2_ForceZero(newAuthBuf, sizeof(newAuthBuf));

    return rc;
}

/* --- TPM2_NV_GlobalWriteLock (CC 0x0132) --- */
/* Set the global NV write lock. All NV indices with TPMA_NV_GLOBALLOCK
 * become write-locked until the next Startup(CLEAR). */
static TPM_RC FwCmd_NV_GlobalWriteLock(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 authHandle = 0;

    (void)cmdSize;

    TPM2_Packet_ParseU32(cmd, &authHandle);
    if (cmdTag == TPM_ST_SESSIONS)
        rc = FwSkipAuthArea(cmd, cmdSize);

    if (rc == 0 && authHandle != TPM_RH_OWNER &&
        authHandle != TPM_RH_PLATFORM) {
        rc = TPM_RC_HIERARCHY;
    }

    if (rc == 0) {
    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: NV_GlobalWriteLock(auth=0x%x)\n", authHandle);
    #endif
        ctx->globalNvWriteLock = 1;
        FwRspNoParams(rsp, cmdTag);
    }

    return rc;
}
#endif /* !FWTPM_NO_NV */

#ifndef FWTPM_NO_DA
/* --- TPM2_DictionaryAttackLockReset (CC 0x0139) --- */
/* Reset the DA lockout counter. Per TPM 2.0 spec Section 25.2. */
static TPM_RC FwCmd_DictionaryAttackLockReset(FWTPM_CTX* ctx,
    TPM2_Packet* cmd, int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 lockHandle = 0;

    (void)cmdSize;

    TPM2_Packet_ParseU32(cmd, &lockHandle);
    if (cmdTag == TPM_ST_SESSIONS)
        rc = FwSkipAuthArea(cmd, cmdSize);

    if (rc == 0 && lockHandle != TPM_RH_LOCKOUT) {
        rc = TPM_RC_HIERARCHY;
    }

    if (rc == 0) {
    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: DictionaryAttackLockReset\n");
    #endif
        ctx->daFailedTries = 0;
        FwRspNoParams(rsp, cmdTag);
    }

    return rc;
}

/* --- TPM2_DictionaryAttackParameters (CC 0x013A) --- */
/* Set DA protection parameters. Per TPM 2.0 spec Section 25.3. */
static TPM_RC FwCmd_DictionaryAttackParameters(FWTPM_CTX* ctx,
    TPM2_Packet* cmd, int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 lockHandle = 0;
    UINT32 newMaxTries = 0;
    UINT32 newRecoveryTime = 0;
    UINT32 lockoutRecovery = 0;

    (void)cmdSize;

    TPM2_Packet_ParseU32(cmd, &lockHandle);
    if (cmdTag == TPM_ST_SESSIONS)
        rc = FwSkipAuthArea(cmd, cmdSize);

    if (rc == 0) {
        TPM2_Packet_ParseU32(cmd, &newMaxTries);
        TPM2_Packet_ParseU32(cmd, &newRecoveryTime);
        TPM2_Packet_ParseU32(cmd, &lockoutRecovery);
    }

    if (rc == 0 && lockHandle != TPM_RH_LOCKOUT) {
        rc = TPM_RC_HIERARCHY;
    }

    if (rc == 0) {
    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: DictionaryAttackParameters(max=%u, recovery=%u, "
            "lockout=%u)\n", newMaxTries, newRecoveryTime, lockoutRecovery);
    #endif
        ctx->daMaxTries = newMaxTries;
        ctx->daRecoveryTime = newRecoveryTime;
        ctx->daLockoutRecovery = lockoutRecovery;
        FWTPM_NV_SaveFlags(ctx);
        FwRspNoParams(rsp, cmdTag);
    }

    return rc;
}
#endif /* !FWTPM_NO_DA */

#ifndef NO_AES
/* --- TPM2_EncryptDecrypt (CC 0x0164) and EncryptDecrypt2 (CC 0x0187) ---
 * Symmetric encrypt/decrypt using a loaded SYMCIPHER key.
 * EncryptDecrypt:  keyHandle, decrypt, mode, ivIn, inData
 * EncryptDecrypt2: keyHandle, decrypt, mode, inData, ivIn  (inData/ivIn swapped) */
static TPM_RC FwEncryptDecryptCore(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag, int isVariant2)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    int ret;
    UINT32 keyHandle = 0;
    UINT8  decrypt = 0;
    UINT16 mode = TPM_ALG_NULL;
    byte   ivBuf[AES_BLOCK_SIZE];
    UINT16 ivSize = 0;
    FWTPM_DECLARE_BUF(inData, FWTPM_MAX_COMMAND_SIZE / 2);
    UINT16 inDataSize = 0;
    FWTPM_Object* obj = NULL;
    FWTPM_DECLARE_VAR(aes, Aes);
    int aesInit = 0;
    int paramSzPos = 0, paramStart = 0;
    word32 blk = 0;

    (void)ctx;
    (void)ret;

    FWTPM_ALLOC_BUF(inData, FWTPM_MAX_COMMAND_SIZE / 2);
    FWTPM_ALLOC_VAR(aes, Aes);

    XMEMSET(ivBuf, 0, sizeof(ivBuf));
    XMEMSET(inData, 0, FWTPM_MAX_COMMAND_SIZE / 2);

    if (cmdSize < TPM2_HEADER_SIZE + 4) {
        rc = TPM_RC_COMMAND_SIZE;
    }

    /* Parse keyHandle */
    if (rc == 0) {
        TPM2_Packet_ParseU32(cmd, &keyHandle);
        obj = FwFindObject(ctx, keyHandle);
        if (obj == NULL) {
            rc = TPM_RC_HANDLE;
        }
    }

    /* Only SYMCIPHER keys supported */
    if (rc == 0) {
        if (obj->pub.type != TPM_ALG_SYMCIPHER) {
            rc = TPM_RC_TYPE;
        }
    }
    /* Verify key has decrypt attribute */
    if (rc == 0) {
        if (!(obj->pub.objectAttributes & TPMA_OBJECT_decrypt)) {
            rc = TPM_RC_KEY;
        }
    }
    if (rc == 0) {
        if (obj->privKeySize <= 0 || obj->privKeySize > 32) {
            rc = TPM_RC_KEY;
        }
    }

    /* Skip auth area */
    if (rc == 0 && cmdTag == TPM_ST_SESSIONS) {
        rc = FwSkipAuthArea(cmd, cmdSize);
    }

    /* Wire format:
     * EncryptDecrypt:  decrypt(1) | mode(2) | ivIn(2+N) | inData(2+M)
     * EncryptDecrypt2: inData(2+M) | decrypt(1) | mode(2) | ivIn(2+N) */
    if (rc == 0 && isVariant2) {
        /* EncryptDecrypt2: inData | decrypt | mode | ivIn */
        TPM2_Packet_ParseU16(cmd, &inDataSize);
        if (inDataSize > (UINT16)(FWTPM_MAX_COMMAND_SIZE / 2)) {
            rc = TPM_RC_SIZE;
        }
        if (rc == 0 && cmd->pos + inDataSize > cmdSize) {
            rc = TPM_RC_COMMAND_SIZE;
        }
        if (rc == 0) {
            TPM2_Packet_ParseBytes(cmd, inData, inDataSize);
            TPM2_Packet_ParseU8(cmd, &decrypt);
            TPM2_Packet_ParseU16(cmd, &mode);
            TPM2_Packet_ParseU16(cmd, &ivSize);
            if (ivSize > (UINT16)sizeof(ivBuf)) {
                rc = TPM_RC_SIZE;
            }
            if (rc == 0 && ivSize > 0) {
                if (cmd->pos + ivSize > cmdSize) {
                    rc = TPM_RC_COMMAND_SIZE;
                }
                else {
                    TPM2_Packet_ParseBytes(cmd, ivBuf, ivSize);
                }
            }
        }
    }
    if (rc == 0 && !isVariant2) {
        /* EncryptDecrypt: decrypt | mode | ivIn | inData */
        TPM2_Packet_ParseU8(cmd, &decrypt);
        TPM2_Packet_ParseU16(cmd, &mode);
        TPM2_Packet_ParseU16(cmd, &ivSize);
        if (ivSize > (UINT16)sizeof(ivBuf)) {
            rc = TPM_RC_SIZE;
        }
        if (rc == 0) {
            if (ivSize > 0) {
                if (cmd->pos + ivSize > cmdSize) {
                    rc = TPM_RC_COMMAND_SIZE;
                }
                else {
                    TPM2_Packet_ParseBytes(cmd, ivBuf, ivSize);
                }
            }
            /* then inData */
            TPM2_Packet_ParseU16(cmd, &inDataSize);
            if (inDataSize > (UINT16)(FWTPM_MAX_COMMAND_SIZE / 2)) {
                rc = TPM_RC_SIZE;
            }
        }
        if (rc == 0 && cmd->pos + inDataSize > cmdSize) {
            rc = TPM_RC_COMMAND_SIZE;
        }
        if (rc == 0) {
            TPM2_Packet_ParseBytes(cmd, inData, inDataSize);
        }
    }

    /* If mode is NULL, use the key's default mode */
    if (rc == 0 && mode == TPM_ALG_NULL) {
        mode = obj->pub.parameters.symDetail.sym.mode.sym;
    }

#ifdef DEBUG_WOLFTPM
    if (rc == 0) {
        printf("fwTPM: EncryptDecrypt%s(key=0x%x, decrypt=%d, mode=0x%x, "
            "sz=%d)\n",
            isVariant2 ? "2" : "", keyHandle, decrypt, mode, inDataSize);
    }
#endif

    /* Perform AES operation */
    if (rc == 0) {
        ret = wc_AesInit(aes, NULL, INVALID_DEVID);
        if (ret != 0) {
            rc = TPM_RC_FAILURE;
        }
        else {
            aesInit = 1;
        }
    }

    if (rc == 0) {
        switch (mode) {
            case TPM_ALG_CFB:
            default:
                /* CFB always uses the forward AES cipher (AES_ENCRYPTION key
                 * schedule) for both encrypt and decrypt operations */
                ret = wc_AesSetKey(aes, obj->privKey,
                    (word32)obj->privKeySize, ivBuf, AES_ENCRYPTION);
                if (ret != 0) {
                    rc = TPM_RC_FAILURE;
                }
                if (rc == 0) {
                    if (decrypt) {
                        ret = wc_AesCfbDecrypt(aes, inData, inData,
                            inDataSize);
                    }
                    else {
                        ret = wc_AesCfbEncrypt(aes, inData, inData,
                            inDataSize);
                    }
                    if (ret != 0) {
                        rc = TPM_RC_FAILURE;
                    }
                }
                break;
            case TPM_ALG_CBC:
                /* CBC requires 16-byte aligned blocks */
                if (inDataSize % AES_BLOCK_SIZE != 0) {
                    rc = TPM_RC_SIZE;
                    break;
                }
                ret = wc_AesSetKey(aes, obj->privKey,
                    (word32)obj->privKeySize, ivBuf,
                    decrypt ? AES_DECRYPTION : AES_ENCRYPTION);
                if (ret != 0) {
                    rc = TPM_RC_FAILURE;
                }
                if (rc == 0) {
                    if (decrypt) {
                        ret = wc_AesCbcDecrypt(aes, inData, inData,
                            inDataSize);
                    }
                    else {
                        ret = wc_AesCbcEncrypt(aes, inData, inData,
                            inDataSize);
                    }
                    if (ret != 0) {
                        rc = TPM_RC_FAILURE;
                    }
                }
                break;
            case TPM_ALG_ECB:
                if (inDataSize % AES_BLOCK_SIZE != 0) {
                    rc = TPM_RC_SIZE;
                    break;
                }
                ret = wc_AesSetKey(aes, obj->privKey,
                    (word32)obj->privKeySize, NULL,
                    decrypt ? AES_DECRYPTION : AES_ENCRYPTION);
                if (ret != 0) {
                    rc = TPM_RC_FAILURE;
                }
                if (rc == 0) {
                    for (blk = 0; blk < inDataSize;
                            blk += AES_BLOCK_SIZE) {
                        if (decrypt) {
                            ret = wc_AesDecryptDirect(aes,
                                inData + blk, inData + blk);
                        }
                        else {
                            ret = wc_AesEncryptDirect(aes,
                                inData + blk, inData + blk);
                        }
                        if (ret != 0) {
                            rc = TPM_RC_FAILURE;
                            break;
                        }
                    }
                }
                break;
        }
    }

    /* Extract updated IV before freeing AES context.
     * Per TPM 2.0 Part 3 Section 12.6.1, ivOut is the chaining value for
     * a subsequent operation. */
    if (rc == 0 && aesInit) {
        if (mode == TPM_ALG_CBC && inDataSize >= AES_BLOCK_SIZE) {
            /* For both encrypt and decrypt, the AES struct reg field
             * holds the updated IV state after the operation */
            XMEMCPY(ivBuf, (byte*)aes->reg, AES_BLOCK_SIZE);
        }
        else if (mode == TPM_ALG_CFB) {
            /* CFB: wolfCrypt updates aes->reg with the IV state */
            XMEMCPY(ivBuf, (byte*)aes->reg, AES_BLOCK_SIZE);
        }
    }

    /* Cleanup AES */
    if (aesInit) {
        wc_AesFree(aes);
    }

    /* --- Build response --- */
    if (rc == 0) {
        paramStart = FwRspParamsBegin(rsp, cmdTag, &paramSzPos);

        /* outData (TPM2B_MAX_BUFFER) */
        TPM2_Packet_AppendU16(rsp, inDataSize);
        TPM2_Packet_AppendBytes(rsp, inData, inDataSize);

        /* ivOut (TPM2B_IV) */
        TPM2_Packet_AppendU16(rsp, (UINT16)sizeof(ivBuf));
        TPM2_Packet_AppendBytes(rsp, ivBuf, sizeof(ivBuf));

        FwRspParamsEnd(rsp, cmdTag, paramSzPos, paramStart);
    }

    TPM2_ForceZero(inData, FWTPM_MAX_COMMAND_SIZE / 2);
    FWTPM_FREE_BUF(inData);
    FWTPM_FREE_VAR(aes);
    return rc;
}

static TPM_RC FwCmd_EncryptDecrypt(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    return FwEncryptDecryptCore(ctx, cmd, cmdSize, rsp, cmdTag, 0);
}

static TPM_RC FwCmd_EncryptDecrypt2(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    return FwEncryptDecryptCore(ctx, cmd, cmdSize, rsp, cmdTag, 1);
}
#endif /* !NO_AES */

/* ================================================================== */
/* Attestation Commands                                                */
/* ================================================================== */

/* Helper: Serialize TPMS_ATTEST common header into pkt.
 * Returns: number of bytes written (up to serialized position in pkt). */
#ifndef FWTPM_NO_ATTESTATION
static void FwAppendAttestCommonHeader(TPM2_Packet* pkt, UINT16 type,
    const TPM2B_NAME* qualifiedSigner, const TPM2B_DATA* extraData)
{
    /* magic */
    TPM2_Packet_AppendU32(pkt, TPM_GENERATED_VALUE);
    /* type */
    TPM2_Packet_AppendU16(pkt, type);
    /* qualifiedSigner (TPM2B_NAME) */
    TPM2_Packet_AppendU16(pkt, qualifiedSigner->size);
    TPM2_Packet_AppendBytes(pkt, (byte*)qualifiedSigner->name,
        qualifiedSigner->size);
    /* extraData (TPM2B_DATA) */
    TPM2_Packet_AppendU16(pkt, extraData->size);
    TPM2_Packet_AppendBytes(pkt, (byte*)extraData->buffer, extraData->size);
    /* clockInfo: clock(8) + resetCount(4) + restartCount(4) + safe(1) */
    TPM2_Packet_AppendU64(pkt, 0); /* clock */
    TPM2_Packet_AppendU32(pkt, 0); /* resetCount */
    TPM2_Packet_AppendU32(pkt, 0); /* restartCount */
    TPM2_Packet_AppendU8(pkt, 1);  /* safe = YES */
    /* firmwareVersion */
    TPM2_Packet_AppendU64(pkt, ((UINT64)FWTPM_VERSION_MAJOR << 32) |
        FWTPM_VERSION_MINOR);
}
#endif /* !FWTPM_NO_ATTESTATION */

#ifndef FWTPM_NO_ATTESTATION
/* Helper: parse common attestation command parameters.
 * Skips auth area, parses qualifyingData (TPM2B_DATA), and inScheme
 * (sigScheme + sigHashAlg). Called after handle parsing is complete. */
static TPM_RC FwParseAttestParams(TPM2_Packet* cmd, int cmdSize,
    UINT16 cmdTag, TPM2B_DATA* qualifyingData,
    UINT16* sigScheme, UINT16* sigHashAlg)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    /* Skip auth area */
    if (cmdTag == TPM_ST_SESSIONS) {
        rc = FwSkipAuthArea(cmd, cmdSize);
    }

    /* qualifyingData */
    if (rc == 0) {
        XMEMSET(qualifyingData, 0, sizeof(*qualifyingData));
        TPM2_Packet_ParseU16(cmd, &qualifyingData->size);
        if (qualifyingData->size > sizeof(qualifyingData->buffer)) {
            rc = TPM_RC_SIZE;
        }
    }
    if (rc == 0) {
        TPM2_Packet_ParseBytes(cmd, qualifyingData->buffer,
            qualifyingData->size);
    }

    /* inScheme */
    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, sigScheme);
        *sigHashAlg = TPM_ALG_NULL;
        if (*sigScheme != TPM_ALG_NULL)
            TPM2_Packet_ParseU16(cmd, sigHashAlg);
    }

    return rc;
}
#endif /* !FWTPM_NO_ATTESTATION */

#ifndef FWTPM_NO_ATTESTATION
/* --- TPM2_Quote (CC 0x0158) ---
 * signHandle authHandle | qualifyingData | inScheme | PCRselect
 * Response: TPM2B_ATTEST + TPMT_SIGNATURE */
static TPM_RC FwCmd_Quote(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 signHandle;
    TPM2B_DATA qualifyingData;
    UINT16 sigScheme, sigHashAlg;
    UINT32 pcrSelCount;
    struct {
        UINT16 hashAlg;
        UINT8 sizeOfSelect;
        byte pcrSelect[PCR_SELECT_MAX];
    } selections[HASH_COUNT];
    UINT32 numSel;
    FWTPM_Object* sigObj;
    FWTPM_DECLARE_BUF(attestBuf, FWTPM_MAX_ATTEST_BUF);
    TPM2_Packet attestPkt;
    UINT32 s;
    byte pcrDigestBuf[TPM_MAX_DIGEST_SIZE];
    int pcrDigestSz = 0;
    UINT16 pcrHashAlg;
    enum wc_HashType wcH;
    int dSz;
    FWTPM_DECLARE_VAR(hashCtx, wc_HashAlg);

    FWTPM_ALLOC_BUF(attestBuf, FWTPM_MAX_ATTEST_BUF);
    FWTPM_ALLOC_VAR(hashCtx, wc_HashAlg);

    if (cmdSize < TPM2_HEADER_SIZE + 4) {
        rc = TPM_RC_COMMAND_SIZE;
    }

    if (rc == 0) {
        TPM2_Packet_ParseU32(cmd, &signHandle);
        sigObj = FwFindObject(ctx, signHandle);
        if (sigObj == NULL) {
            rc = TPM_RC_HANDLE;
        }
    }

    if (rc == 0) {
        rc = FwParseAttestParams(cmd, cmdSize, cmdTag,
            &qualifyingData, &sigScheme, &sigHashAlg);
    }

    /* PCRselect */
    if (rc == 0) {
        TPM2_Packet_ParseU32(cmd, &pcrSelCount);
        numSel = pcrSelCount;
        if (numSel > HASH_COUNT)
            numSel = HASH_COUNT;
        for (s = 0; s < numSel; s++) {
            UINT32 j;
            TPM2_Packet_ParseU16(cmd, &selections[s].hashAlg);
            TPM2_Packet_ParseU8(cmd, &selections[s].sizeOfSelect);
            if (selections[s].sizeOfSelect > PCR_SELECT_MAX)
                selections[s].sizeOfSelect = PCR_SELECT_MAX;
            for (j = 0; j < selections[s].sizeOfSelect; j++)
                TPM2_Packet_ParseU8(cmd, &selections[s].pcrSelect[j]);
        }
    }

    /* Build TPMS_ATTEST for QUOTE */
    if (rc == 0) {
        XMEMSET(attestBuf, 0, FWTPM_MAX_ATTEST_BUF);
        attestPkt.buf = attestBuf;
        attestPkt.pos = 0;
        attestPkt.size = (int)FWTPM_MAX_ATTEST_BUF;

        FwAppendAttestCommonHeader(&attestPkt, TPM_ST_ATTEST_QUOTE,
            &sigObj->name, &qualifyingData);

        /* attested.quote: pcrSelect (TPML_PCR_SELECTION) +
         * pcrDigest (TPM2B_DIGEST) */
        TPM2_Packet_AppendU32(&attestPkt, pcrSelCount);
        for (s = 0; s < numSel; s++) {
            UINT32 j;
            TPM2_Packet_AppendU16(&attestPkt, selections[s].hashAlg);
            TPM2_Packet_AppendU8(&attestPkt, selections[s].sizeOfSelect);
            for (j = 0; j < selections[s].sizeOfSelect; j++)
                TPM2_Packet_AppendU8(&attestPkt,
                    selections[s].pcrSelect[j]);
        }

        /* pcrDigest = hash of concatenated selected PCR values */
        pcrHashAlg = (sigHashAlg != TPM_ALG_NULL) ? sigHashAlg :
            (numSel > 0 ? selections[0].hashAlg : (UINT16)TPM_ALG_SHA256);
        wcH = FwGetWcHashType(pcrHashAlg);
        dSz = TPM2_GetHashDigestSize(pcrHashAlg);
        if (wcH != WC_HASH_TYPE_NONE && dSz > 0) {
            if (wc_HashInit(hashCtx, wcH) != 0) {
                rc = TPM_RC_FAILURE;
            }
            if (rc == 0) {
                for (s = 0; s < numSel && rc == 0; s++) {
                    int bank = FwGetPcrBankIndex(selections[s].hashAlg);
                    int bankDSz = TPM2_GetHashDigestSize(
                        selections[s].hashAlg);
                    UINT32 j;
                    if (bank < 0 || bankDSz == 0)
                        continue;
                    for (j = 0; j < selections[s].sizeOfSelect &&
                            rc == 0; j++) {
                        int pcr;
                        for (pcr = 0; pcr < 8; pcr++) {
                            if (selections[s].pcrSelect[j] & (1 << pcr)) {
                                int pcrIdx = j * 8 + pcr;
                                if (pcrIdx < IMPLEMENTATION_PCR) {
                                    if (wc_HashUpdate(hashCtx, wcH,
                                            ctx->pcrDigest[pcrIdx][bank],
                                            bankDSz) != 0) {
                                        rc = TPM_RC_FAILURE;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
                if (rc == 0) {
                    if (wc_HashFinal(hashCtx, wcH,
                            pcrDigestBuf) != 0) {
                        rc = TPM_RC_FAILURE;
                    }
                    else {
                        pcrDigestSz = dSz;
                    }
                }
                wc_HashFree(hashCtx, wcH);
            }
        }
        TPM2_Packet_AppendU16(&attestPkt, (UINT16)pcrDigestSz);
        TPM2_Packet_AppendBytes(&attestPkt, pcrDigestBuf, pcrDigestSz);
    }

    /* Build response */
    if (rc == 0) {
        rc = FwBuildAttestResponse(ctx, rsp, cmdTag, sigObj,
            sigScheme, sigHashAlg, attestBuf, attestPkt.pos);
    }
    FWTPM_FREE_BUF(attestBuf);
    FWTPM_FREE_VAR(hashCtx);
    return rc;
}

/* --- TPM2_Certify (CC 0x0148) ---
 * objectHandle, signHandle | qualifyingData | inScheme
 * Response: TPM2B_ATTEST + TPMT_SIGNATURE */
static TPM_RC FwCmd_Certify(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 objectHandle, signHandle;
    TPM2B_DATA qualifyingData;
    UINT16 sigScheme, sigHashAlg;
    FWTPM_Object* objToSign;
    FWTPM_Object* sigObj;
    FWTPM_DECLARE_BUF(attestBuf, FWTPM_MAX_ATTEST_BUF);
    TPM2_Packet attestPkt;

    FWTPM_ALLOC_BUF(attestBuf, FWTPM_MAX_ATTEST_BUF);

    if (cmdSize < TPM2_HEADER_SIZE + 8) {
        rc = TPM_RC_COMMAND_SIZE;
    }

    if (rc == 0) {
        TPM2_Packet_ParseU32(cmd, &objectHandle);
        TPM2_Packet_ParseU32(cmd, &signHandle);

        objToSign = FwFindObject(ctx, objectHandle);
        if (objToSign == NULL) {
            rc = TPM_RC_HANDLE;
        }
    }
    if (rc == 0) {
        sigObj = FwFindObject(ctx, signHandle);
        if (sigObj == NULL) {
            rc = TPM_RC_HANDLE;
        }
    }

    if (rc == 0) {
        rc = FwParseAttestParams(cmd, cmdSize, cmdTag,
            &qualifyingData, &sigScheme, &sigHashAlg);
    }

    /* Make sure certified object has a name */
    if (rc == 0) {
        if (objToSign->name.size == 0)
            FwComputeObjectName(objToSign);

        /* Build TPMS_ATTEST for CERTIFY */
        XMEMSET(attestBuf, 0, FWTPM_MAX_ATTEST_BUF);
        attestPkt.buf = attestBuf;
        attestPkt.pos = 0;
        attestPkt.size = (int)FWTPM_MAX_ATTEST_BUF;

        FwAppendAttestCommonHeader(&attestPkt, TPM_ST_ATTEST_CERTIFY,
            &sigObj->name, &qualifyingData);

        /* attested.certify: name + qualifiedName */
        TPM2_Packet_AppendU16(&attestPkt, objToSign->name.size);
        TPM2_Packet_AppendBytes(&attestPkt, (byte*)objToSign->name.name,
            objToSign->name.size);
        /* qualifiedName = same as name in our simple hierarchy */
        TPM2_Packet_AppendU16(&attestPkt, objToSign->name.size);
        TPM2_Packet_AppendBytes(&attestPkt, (byte*)objToSign->name.name,
            objToSign->name.size);

        /* Build response */
        rc = FwBuildAttestResponse(ctx, rsp, cmdTag, sigObj,
            sigScheme, sigHashAlg, attestBuf, attestPkt.pos);
    }
    FWTPM_FREE_BUF(attestBuf);
    return rc;
}

/* --- TPM2_CertifyCreation (CC 0x014A) ---
 * signHandle, objectHandle | qualifyingData | creationHash | inScheme |
 *   creationTicket
 * Response: TPM2B_ATTEST (CREATION) + TPMT_SIGNATURE */
static TPM_RC FwCmd_CertifyCreation(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 signHandle, objectHandle;
    TPM2B_DATA qualifyingData;
    TPM2B_DIGEST creationHash;
    UINT16 sigScheme, sigHashAlg;
    FWTPM_Object* sigObj;
    FWTPM_Object* objToSign;
    FWTPM_DECLARE_BUF(attestBuf, FWTPM_MAX_ATTEST_BUF);
    TPM2_Packet attestPkt;
    UINT16 tag, tickDSz;
    UINT32 hier;

    FWTPM_ALLOC_BUF(attestBuf, FWTPM_MAX_ATTEST_BUF);

    if (cmdSize < TPM2_HEADER_SIZE + 8) {
        rc = TPM_RC_COMMAND_SIZE;
    }

    if (rc == 0) {
        TPM2_Packet_ParseU32(cmd, &signHandle);
        TPM2_Packet_ParseU32(cmd, &objectHandle);

        sigObj = FwFindObject(ctx, signHandle);
        if (sigObj == NULL) {
            rc = TPM_RC_HANDLE;
        }
    }
    if (rc == 0) {
        objToSign = FwFindObject(ctx, objectHandle);
        if (objToSign == NULL) {
            rc = TPM_RC_HANDLE;
        }
    }

    /* Skip auth area */
    if (rc == 0 && cmdTag == TPM_ST_SESSIONS) {
        rc = FwSkipAuthArea(cmd, cmdSize);
    }

    /* qualifyingData */
    if (rc == 0) {
        XMEMSET(&qualifyingData, 0, sizeof(qualifyingData));
        TPM2_Packet_ParseU16(cmd, &qualifyingData.size);
        if (qualifyingData.size > sizeof(qualifyingData.buffer)) {
            rc = TPM_RC_SIZE;
        }
    }
    if (rc == 0) {
        TPM2_Packet_ParseBytes(cmd, qualifyingData.buffer,
            qualifyingData.size);
    }

    /* creationHash (between qualifyingData and inScheme) */
    if (rc == 0) {
        XMEMSET(&creationHash, 0, sizeof(creationHash));
        TPM2_Packet_ParseU16(cmd, &creationHash.size);
        if (creationHash.size > sizeof(creationHash.buffer)) {
            rc = TPM_RC_SIZE;
        }
    }
    if (rc == 0) {
        TPM2_Packet_ParseBytes(cmd, creationHash.buffer, creationHash.size);
    }

    /* inScheme */
    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &sigScheme);
        sigHashAlg = TPM_ALG_NULL;
        if (sigScheme != TPM_ALG_NULL)
            TPM2_Packet_ParseU16(cmd, &sigHashAlg);
    }

    /* creationTicket verification per TPM 2.0 Part 3 Section 18.3 */
    if (rc == 0 && cmd->pos + 8 <= cmdSize) {
        byte ticketDigest[TPM_MAX_DIGEST_SIZE];

        TPM2_Packet_ParseU16(cmd, &tag);
        TPM2_Packet_ParseU32(cmd, &hier);
        TPM2_Packet_ParseU16(cmd, &tickDSz);

        if (tickDSz > sizeof(ticketDigest)) {
            rc = TPM_RC_SIZE;
        }
        else if (tickDSz > 0 && cmd->pos + tickDSz <= cmdSize) {
            TPM2_Packet_ParseBytes(cmd, ticketDigest, tickDSz);
        }
        else if (tickDSz > 0) {
            rc = TPM_RC_COMMAND_SIZE;
        }

        /* Verify ticket: tag must be TPM_ST_CREATION and HMAC must match */
        if (rc == 0 && tag != TPM_ST_CREATION) {
            rc = TPM_RC_TICKET;
        }
        if (rc == 0 && tickDSz > 0) {
            byte ticketData[TPM_MAX_DIGEST_SIZE + sizeof(TPM2B_NAME)];
            int ticketDataSz = 0;
            byte expectedHmac[TPM_MAX_DIGEST_SIZE];
            int expectedSz = 0;

            /* Ensure object name is computed for ticket verification */
            if (objToSign->name.size == 0) {
                FwComputeObjectName(objToSign);
            }

            /* ticketData = creationHash || objectName */
            XMEMCPY(ticketData, creationHash.buffer, creationHash.size);
            ticketDataSz = creationHash.size;
            XMEMCPY(ticketData + ticketDataSz, objToSign->name.name,
                objToSign->name.size);
            ticketDataSz += objToSign->name.size;

            if (FwComputeTicketHmac(ctx, hier, objToSign->pub.nameAlg,
                    ticketData, ticketDataSz,
                    expectedHmac, &expectedSz) != 0 ||
                tickDSz != (UINT16)expectedSz ||
                TPM2_ConstantCompare(ticketDigest, expectedHmac,
                    (word32)expectedSz) != 0) {
                rc = TPM_RC_TICKET;
            }
            TPM2_ForceZero(expectedHmac, sizeof(expectedHmac));
        }
    }

    /* Make sure certified object has a name */
    if (rc == 0) {
        if (objToSign->name.size == 0)
            FwComputeObjectName(objToSign);

        /* Build TPMS_ATTEST for CREATION */
        XMEMSET(attestBuf, 0, FWTPM_MAX_ATTEST_BUF);
        attestPkt.buf = attestBuf;
        attestPkt.pos = 0;
        attestPkt.size = (int)FWTPM_MAX_ATTEST_BUF;

        FwAppendAttestCommonHeader(&attestPkt, TPM_ST_ATTEST_CREATION,
            &sigObj->name, &qualifyingData);

        /* attested.creation: objectName (TPM2B_NAME) +
         * creationHash (TPM2B_DIGEST) */
        TPM2_Packet_AppendU16(&attestPkt, objToSign->name.size);
        TPM2_Packet_AppendBytes(&attestPkt, (byte*)objToSign->name.name,
            objToSign->name.size);
        TPM2_Packet_AppendU16(&attestPkt, creationHash.size);
        TPM2_Packet_AppendBytes(&attestPkt, creationHash.buffer,
            creationHash.size);

        /* Build response */
        rc = FwBuildAttestResponse(ctx, rsp, cmdTag, sigObj,
            sigScheme, sigHashAlg, attestBuf, attestPkt.pos);
    }
    FWTPM_FREE_BUF(attestBuf);
    return rc;
}

/* --- TPM2_GetTime (CC 0x014C) ---
 * privacyAdminHandle, signHandle | qualifyingData | inScheme
 * Response: TPM2B_ATTEST (TIME) + TPMT_SIGNATURE */
static TPM_RC FwCmd_GetTime(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 privHandle, signHandle;
    TPM2B_DATA qualifyingData;
    UINT16 sigScheme, sigHashAlg;
    FWTPM_Object* sigObj;
    FWTPM_DECLARE_BUF(attestBuf, FWTPM_MAX_PUB_BUF);
    TPM2_Packet attestPkt;

    FWTPM_ALLOC_BUF(attestBuf, FWTPM_MAX_PUB_BUF);

    if (cmdSize < TPM2_HEADER_SIZE + 8) {
        rc = TPM_RC_COMMAND_SIZE;
    }

    if (rc == 0) {
        TPM2_Packet_ParseU32(cmd, &privHandle);
        TPM2_Packet_ParseU32(cmd, &signHandle);
        (void)privHandle;

        sigObj = FwFindObject(ctx, signHandle);
        if (sigObj == NULL) {
            rc = TPM_RC_HANDLE;
        }
    }

    if (rc == 0) {
        rc = FwParseAttestParams(cmd, cmdSize, cmdTag,
            &qualifyingData, &sigScheme, &sigHashAlg);
    }

    /* Build TPMS_ATTEST for TIME */
    if (rc == 0) {
        XMEMSET(attestBuf, 0, FWTPM_MAX_PUB_BUF);
        attestPkt.buf = attestBuf;
        attestPkt.pos = 0;
        attestPkt.size = (int)FWTPM_MAX_PUB_BUF;

        FwAppendAttestCommonHeader(&attestPkt, TPM_ST_ATTEST_TIME,
            &sigObj->name, &qualifyingData);

        /* attested.time: TPMS_TIME_INFO (time + clockInfo) +
         * firmwareVersion */
        TPM2_Packet_AppendU64(&attestPkt, 0); /* time */
        TPM2_Packet_AppendU64(&attestPkt, 0); /* clockInfo.clock */
        TPM2_Packet_AppendU32(&attestPkt, 0); /* clockInfo.resetCount */
        TPM2_Packet_AppendU32(&attestPkt, 0); /* clockInfo.restartCount */
        TPM2_Packet_AppendU8(&attestPkt, 1);  /* clockInfo.safe */
        TPM2_Packet_AppendU64(&attestPkt,
            ((UINT64)FWTPM_VERSION_MAJOR << 32) |
            FWTPM_VERSION_MINOR); /* firmwareVersion */

        /* Build response */
        rc = FwBuildAttestResponse(ctx, rsp, cmdTag, sigObj,
            sigScheme, sigHashAlg, attestBuf, attestPkt.pos);
    }
    FWTPM_FREE_BUF(attestBuf);
    return rc;
}

#ifndef FWTPM_NO_NV
/* --- TPM2_NV_Certify (CC 0x0184) ---
 * signHandle, authHandle, nvIndex | qualifyingData | inScheme | size | offset
 * Response: TPM2B_ATTEST + TPMT_SIGNATURE */
static TPM_RC FwCmd_NV_Certify(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 signHandle, authHandle, nvHandle;
    TPM2B_DATA qualifyingData;
    UINT16 sigScheme, sigHashAlg;
    UINT16 readSize, readOffset;
    FWTPM_Object* sigObj;
    FWTPM_NvIndex* nv;
    FWTPM_DECLARE_BUF(attestBuf, FWTPM_MAX_ATTEST_BUF);
    TPM2_Packet attestPkt;
    TPM2B_NAME nvName;
    byte nvPubBuf[128];
    TPM2_Packet tmpPkt;
    enum wc_HashType wcH;
    int dSz;

    FWTPM_ALLOC_BUF(attestBuf, FWTPM_MAX_ATTEST_BUF);

    if (cmdSize < TPM2_HEADER_SIZE + 12) {
        rc = TPM_RC_COMMAND_SIZE;
    }

    if (rc == 0) {
        TPM2_Packet_ParseU32(cmd, &signHandle);
        TPM2_Packet_ParseU32(cmd, &authHandle);
        TPM2_Packet_ParseU32(cmd, &nvHandle);

        sigObj = FwFindObject(ctx, signHandle);
        if (sigObj == NULL) {
            rc = TPM_RC_HANDLE;
        }
    }
    if (rc == 0) {
        nv = FwFindNvIndex(ctx, nvHandle);
        if (nv == NULL) {
            rc = TPM_RC_HANDLE;
        }
    }
    if (rc == 0) {
        rc = FwNvCheckAccess(authHandle, nvHandle,
            nv->nvPublic.attributes, 0);
    }
    if (rc == 0 && (nv->nvPublic.attributes & TPMA_NV_READLOCKED)) {
        rc = TPM_RC_NV_LOCKED;
    }
    if (rc == 0 && !nv->written) {
        rc = TPM_RC_NV_UNINITIALIZED;
    }

    if (rc == 0) {
        rc = FwParseAttestParams(cmd, cmdSize, cmdTag,
            &qualifyingData, &sigScheme, &sigHashAlg);
    }

    /* size, offset */
    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &readSize);
        TPM2_Packet_ParseU16(cmd, &readOffset);

        if (readOffset > nv->nvPublic.dataSize) {
            rc = TPM_RC_NV_RANGE;
        }
    }
    if (rc == 0) {
        if (readSize == 0)
            readSize = nv->nvPublic.dataSize - readOffset;
        if ((UINT32)(readOffset + readSize) > nv->nvPublic.dataSize) {
            rc = TPM_RC_NV_RANGE;
        }
        if (rc == 0 && readSize > FWTPM_MAX_NV_DATA) {
            rc = TPM_RC_SIZE;
        }
    }

    /* Build NV index name: nameAlg(2) || Hash(nvPublic) */
    if (rc == 0) {
        XMEMSET(&nvName, 0, sizeof(nvName));
        tmpPkt.buf = nvPubBuf;
        tmpPkt.pos = 0;
        tmpPkt.size = (int)sizeof(nvPubBuf);
        /* nvPublic wire: nvIndex(4) + nameAlg(2) + attributes(4) +
         * authPolicy(2+N) + dataSize(2) */
        TPM2_Packet_AppendU32(&tmpPkt, nv->nvPublic.nvIndex);
        TPM2_Packet_AppendU16(&tmpPkt, nv->nvPublic.nameAlg);
        TPM2_Packet_AppendU32(&tmpPkt, nv->nvPublic.attributes);
        TPM2_Packet_AppendU16(&tmpPkt, nv->nvPublic.authPolicy.size);
        TPM2_Packet_AppendBytes(&tmpPkt, nv->nvPublic.authPolicy.buffer,
            nv->nvPublic.authPolicy.size);
        TPM2_Packet_AppendU16(&tmpPkt, nv->nvPublic.dataSize);
        wcH = FwGetWcHashType(nv->nvPublic.nameAlg);
        dSz = TPM2_GetHashDigestSize(nv->nvPublic.nameAlg);
        if (wcH != WC_HASH_TYPE_NONE && dSz > 0) {
            FwStoreU16BE(nvName.name, nv->nvPublic.nameAlg);
            if (wc_Hash(wcH, nvPubBuf, tmpPkt.pos,
                    nvName.name + 2, dSz) == 0) {
                nvName.size = (UINT16)(2 + dSz);
            }
            else {
                rc = TPM_RC_FAILURE;
            }
        }
    }

    /* Build TPMS_ATTEST for NV */
    if (rc == 0) {
        XMEMSET(attestBuf, 0, FWTPM_MAX_ATTEST_BUF);
        attestPkt.buf = attestBuf;
        attestPkt.pos = 0;
        attestPkt.size = (int)FWTPM_MAX_ATTEST_BUF;

        FwAppendAttestCommonHeader(&attestPkt, TPM_ST_ATTEST_NV,
            &sigObj->name, &qualifyingData);

        /* attested.nv: indexName + offset + nvContents */
        TPM2_Packet_AppendU16(&attestPkt, nvName.size);
        TPM2_Packet_AppendBytes(&attestPkt, (byte*)nvName.name,
            nvName.size);
        TPM2_Packet_AppendU16(&attestPkt, readOffset);
        TPM2_Packet_AppendU16(&attestPkt, readSize);
        TPM2_Packet_AppendBytes(&attestPkt, nv->data + readOffset,
            readSize);

        /* Build response */
        rc = FwBuildAttestResponse(ctx, rsp, cmdTag, sigObj,
            sigScheme, sigHashAlg, attestBuf, attestPkt.pos);
    }
    FWTPM_FREE_BUF(attestBuf);
    return rc;
}
#endif /* !FWTPM_NO_NV */
#endif /* !FWTPM_NO_ATTESTATION */

#ifndef FWTPM_NO_CREDENTIAL

/* --- TPM2_MakeCredential (CC 0x0168) ---
 * handle (AIK public key used to wrap seed) | credential | objectName
 * Response: TPM2B_ID_OBJECT + TPM2B_ENCRYPTED_SECRET
 *
 * Per TPM2 spec Part 1 Section 24:
 *   seed = FwEncryptSeed(pubKey, "IDENTITY")
 *   symKey = KDFa(SHA256, seed, "STORAGE", objectName, "", 128)
 *   HMACkey = KDFa(SHA256, seed, "INTEGRITY", "", "", 256)
 *   credentialBlob = FwCredentialWrap(symKey, HMACkey, credential, objectName)
 *   secret = TPM2B_ENCRYPTED_SECRET(encSeed) */
static TPM_RC FwCmd_MakeCredential(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 handle;
    TPM2B_DIGEST credential;
    TPM2B_NAME objectName;
    FWTPM_Object* keyObj = NULL;
    int paramSzPos = 0;
    int paramStart = 0;
    byte seed[64];
    int seedSz = 0;
    FWTPM_DECLARE_BUF(encSeed, FWTPM_MAX_PUB_BUF);
    int encSeedSz = 0;
    byte symKey[16];  /* AES-128 */
    byte hmacKey[TPM_SHA256_DIGEST_SIZE];
    FWTPM_DECLARE_BUF(encCred, FWTPM_MAX_NV_DATA + 2);
    word32 encCredSz = 0;
    byte outerHmac[TPM_SHA256_DIGEST_SIZE];
    byte oaepLabel[64];
    int oaepLabelSz = 0;

    FWTPM_ALLOC_BUF(encSeed, FWTPM_MAX_PUB_BUF);
    FWTPM_ALLOC_BUF(encCred, FWTPM_MAX_NV_DATA + 2);

    /* Zero stack TPM2B structs up front so partial-parse error paths cannot
     * read or echo uninitialized stack bytes. */
    XMEMSET(&credential, 0, sizeof(credential));
    XMEMSET(&objectName, 0, sizeof(objectName));

    if (cmdSize < TPM2_HEADER_SIZE + 4) {
        rc = TPM_RC_COMMAND_SIZE;
    }

    if (rc == 0) {
        TPM2_Packet_ParseU32(cmd, &handle);
        keyObj = FwFindObject(ctx, handle);
        if (keyObj == NULL) {
            rc = TPM_RC_HANDLE;
        }
    }

    /* MakeCredential has no auth area */

    /* credential (TPM2B_DIGEST) */
    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &credential.size);
        if (credential.size > sizeof(credential.buffer)) {
            rc = TPM_RC_SIZE;
        }
    }
    if (rc == 0) {
        if (cmd->pos + credential.size > cmdSize) {
            rc = TPM_RC_COMMAND_SIZE;
        }
    }
    if (rc == 0) {
        TPM2_Packet_ParseBytes(cmd, credential.buffer, credential.size);
    }

    /* objectName (TPM2B_NAME) */
    if (rc == 0) {
        XMEMSET(&objectName, 0, sizeof(objectName));
        TPM2_Packet_ParseU16(cmd, (UINT16*)&objectName.size);
        if (objectName.size > sizeof(objectName.name)) {
            rc = TPM_RC_SIZE;
        }
    }
    if (rc == 0) {
        if (cmd->pos + objectName.size > cmdSize) {
            rc = TPM_RC_COMMAND_SIZE;
        }
    }
    if (rc == 0) {
        TPM2_Packet_ParseBytes(cmd, objectName.name, objectName.size);
    }

#ifdef DEBUG_WOLFTPM
    if (rc == 0) {
        printf("fwTPM: MakeCredential(handle=0x%x, credSz=%d, nameSz=%d)\n",
            handle, credential.size, objectName.size);
    }
#endif

    /* Build OAEP label: "IDENTITY\0" + objectName */
    if (rc == 0) {
        XMEMCPY(oaepLabel, "IDENTITY", 8);
        oaepLabelSz = 8;
        oaepLabel[oaepLabelSz++] = 0x00;
        if (objectName.size + oaepLabelSz > (int)sizeof(oaepLabel)) {
            rc = TPM_RC_SIZE;
        }
        else {
            XMEMCPY(oaepLabel + oaepLabelSz, objectName.name,
                objectName.size);
            oaepLabelSz += objectName.size;
        }
    }

    /* Generate seed and encrypt to key's public key */
    if (rc == 0) {
        rc = FwEncryptSeed(ctx, keyObj,
            oaepLabel, oaepLabelSz, "IDENTITY",
            seed, (int)sizeof(seed), &seedSz,
            encSeed, FWTPM_MAX_PUB_BUF, &encSeedSz);
    }

    /* Derive symmetric and HMAC keys from seed */
    if (rc == 0) {
        rc = FwCredentialDeriveKeys(seed, seedSz,
            objectName.name, objectName.size,
            symKey, (int)sizeof(symKey),
            hmacKey, (int)sizeof(hmacKey));
    }

    /* Encrypt credential and compute outer HMAC */
    if (rc == 0) {
        rc = FwCredentialWrap(
            symKey, (int)sizeof(symKey),
            hmacKey, (int)sizeof(hmacKey),
            credential.buffer, credential.size,
            objectName.name, objectName.size,
            encCred, &encCredSz, outerHmac);
    }

    /* Build response */
    if (rc == 0) {
        int blobSzPos;
        int blobStart;
        int blobSz;
        int savedPos;
        paramStart = FwRspParamsBegin(rsp, cmdTag, &paramSzPos);
        /* credentialBlob = TPM2B_ID_OBJECT:
         *   size(2) | integrity(TPM2B) | encIdentity(raw) */
        blobSzPos = rsp->pos;
        TPM2_Packet_AppendU16(rsp, 0); /* placeholder */
        blobStart = rsp->pos;
        /* integrity HMAC as TPM2B */
        TPM2_Packet_AppendU16(rsp, TPM_SHA256_DIGEST_SIZE);
        TPM2_Packet_AppendBytes(rsp, outerHmac, TPM_SHA256_DIGEST_SIZE);
        /* encIdentity as raw bytes (encCredential) */
        TPM2_Packet_AppendBytes(rsp, encCred, (int)encCredSz);
        /* patch blob size */
        blobSz = rsp->pos - blobStart;
        if (blobSz < 0 || blobSz > 0xFFFF ||
            encSeedSz < 0 || encSeedSz > (int)FWTPM_MAX_PUB_BUF) {
            rc = TPM_RC_SIZE;
        }
        if (rc == 0) {
            savedPos = rsp->pos;
            rsp->pos = blobSzPos;
            TPM2_Packet_AppendU16(rsp, (UINT16)blobSz);
            rsp->pos = savedPos;
            /* secret = TPM2B_ENCRYPTED_SECRET */
            TPM2_Packet_AppendU16(rsp, (UINT16)encSeedSz);
            TPM2_Packet_AppendBytes(rsp, encSeed, encSeedSz);
            FwRspParamsEnd(rsp, cmdTag, paramSzPos, paramStart);
        }
    }

    TPM2_ForceZero(seed, sizeof(seed));
    TPM2_ForceZero(symKey, sizeof(symKey));
    TPM2_ForceZero(hmacKey, sizeof(hmacKey));
    TPM2_ForceZero(encSeed, FWTPM_MAX_PUB_BUF);
    FWTPM_FREE_BUF(encSeed);
    TPM2_ForceZero(encCred, FWTPM_MAX_NV_DATA + 2);
    FWTPM_FREE_BUF(encCred);
    return rc;
}

/* --- TPM2_ActivateCredential (CC 0x0147) ---
 * activateHandle, keyHandle | credentialBlob | secret
 * Response: TPM2B_DIGEST (the decrypted credential)
 *
 * Reverse of MakeCredential: decrypt seed with keyHandle private key,
 * derive keys via FwCredentialDeriveKeys, then FwCredentialUnwrap. */
static TPM_RC FwCmd_ActivateCredential(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 activateHandle, keyHandle;
    FWTPM_Object* keyObj = NULL;
    FWTPM_Object* activateObj = NULL;
    UINT16 blobSz = 0;
    FWTPM_DECLARE_BUF(blobBuf, FWTPM_MAX_DATA_BUF);
    UINT16 secretSz = 0;
    FWTPM_DECLARE_BUF(secretBuf, FWTPM_MAX_PUB_BUF);
    int paramSzPos, paramStart;
    byte seed[64];
    int seedSzInt = 0;
    byte symKey[16];
    byte hmacKey[TPM_SHA256_DIGEST_SIZE];
    byte oaepLabel[64];
    int oaepLabelSz = 0;
    byte credOut[sizeof(TPMU_HA)];
    UINT16 credSz = 0;
    TPM2B_NAME* objName;

    FWTPM_ALLOC_BUF(blobBuf, FWTPM_MAX_DATA_BUF);
    FWTPM_ALLOC_BUF(secretBuf, FWTPM_MAX_PUB_BUF);

    if (cmdSize < TPM2_HEADER_SIZE + 8) {
        rc = TPM_RC_COMMAND_SIZE;
    }

    if (rc == 0) {
        TPM2_Packet_ParseU32(cmd, &activateHandle);
        TPM2_Packet_ParseU32(cmd, &keyHandle);

        activateObj = FwFindObject(ctx, activateHandle);
        if (activateObj == NULL) {
            rc = TPM_RC_HANDLE;
        }
    }
    if (rc == 0) {
        keyObj = FwFindObject(ctx, keyHandle);
        if (keyObj == NULL) {
            rc = TPM_RC_HANDLE;
        }
    }

    /* Skip auth area */
    if (rc == 0 && cmdTag == TPM_ST_SESSIONS) {
        rc = FwSkipAuthArea(cmd, cmdSize);
    }

    /* credentialBlob (TPM2B_ID_OBJECT) */
    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &blobSz);
        if (blobSz > FWTPM_MAX_DATA_BUF) {
            rc = TPM_RC_SIZE;
        }
    }
    if (rc == 0) {
        if (cmd->pos + blobSz > cmdSize) {
            rc = TPM_RC_COMMAND_SIZE;
        }
    }
    if (rc == 0) {
        TPM2_Packet_ParseBytes(cmd, blobBuf, blobSz);
    }

    /* secret (TPM2B_ENCRYPTED_SECRET) */
    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &secretSz);
        if (secretSz > FWTPM_MAX_PUB_BUF) {
            rc = TPM_RC_SIZE;
        }
    }
    if (rc == 0) {
        if (cmd->pos + secretSz > cmdSize) {
            rc = TPM_RC_COMMAND_SIZE;
        }
    }
    if (rc == 0) {
        TPM2_Packet_ParseBytes(cmd, secretBuf, secretSz);
    }

    if (rc == 0) {
        if (keyObj->pub.type != TPM_ALG_RSA &&
            keyObj->pub.type != TPM_ALG_ECC) {
            rc = TPM_RC_KEY;
        }
    }

#ifdef DEBUG_WOLFTPM
    if (rc == 0) {
        printf("fwTPM: ActivateCredential(activate=0x%x, key=0x%x type=%d)\n",
            activateHandle, keyHandle, keyObj->pub.type);
    }
#endif

    /* Compute activateObj name if not already done */
    if (rc == 0) {
        if (activateObj->name.size == 0) {
            FwComputeObjectName(activateObj);
        }
    }

    /* Build OAEP label: "IDENTITY\0" + activateObj->name */
    if (rc == 0) {
        objName = &activateObj->name;
        XMEMCPY(oaepLabel, "IDENTITY", 8);
        oaepLabelSz = 8;
        oaepLabel[oaepLabelSz++] = 0x00;
        if (objName->size + oaepLabelSz > (int)sizeof(oaepLabel)) {
            rc = TPM_RC_SIZE;
        }
        else {
            XMEMCPY(oaepLabel + oaepLabelSz, objName->name, objName->size);
            oaepLabelSz += objName->size;
        }
    }

    /* Decrypt seed using keyHandle's private key */
    if (rc == 0) {
        rc = FwDecryptSeed(ctx, keyObj,
            secretBuf, secretSz,
            oaepLabel, oaepLabelSz, "IDENTITY",
            seed, (int)sizeof(seed), &seedSzInt);
    }

    /* Derive symmetric and HMAC keys from seed */
    if (rc == 0) {
        objName = &activateObj->name;
        rc = FwCredentialDeriveKeys(seed, seedSzInt,
            objName->name, objName->size,
            symKey, (int)sizeof(symKey),
            hmacKey, (int)sizeof(hmacKey));
    }

    /* Verify HMAC and decrypt credential */
    if (rc == 0) {
        objName = &activateObj->name;
        rc = FwCredentialUnwrap(
            symKey, (int)sizeof(symKey),
            hmacKey, (int)sizeof(hmacKey),
            blobBuf, blobSz,
            objName->name, objName->size,
            credOut, (int)sizeof(credOut), &credSz);
    }
    if (rc == 0 && credSz > (UINT16)sizeof(credOut)) {
        rc = TPM_RC_SIZE;
    }

    /* Build response: TPM2B_DIGEST */
    if (rc == 0) {
        paramStart = FwRspParamsBegin(rsp, cmdTag, &paramSzPos);
        TPM2_Packet_AppendU16(rsp, credSz);
        TPM2_Packet_AppendBytes(rsp, credOut, credSz);
        FwRspParamsEnd(rsp, cmdTag, paramSzPos, paramStart);
    }

    TPM2_ForceZero(seed, sizeof(seed));
    TPM2_ForceZero(symKey, sizeof(symKey));
    TPM2_ForceZero(hmacKey, sizeof(hmacKey));
    TPM2_ForceZero(credOut, sizeof(credOut));
    TPM2_ForceZero(blobBuf, FWTPM_MAX_DATA_BUF);
    FWTPM_FREE_BUF(blobBuf);
    TPM2_ForceZero(secretBuf, FWTPM_MAX_PUB_BUF);
    FWTPM_FREE_BUF(secretBuf);
    return rc;
}
#endif /* !FWTPM_NO_CREDENTIAL */

#ifdef HAVE_ECC
/* ================================================================== */
/* ECC Parameters                                                      */
/* ================================================================== */

/* Convert hex string to binary. Returns byte count, or -1 on error. */
static int FwHexToBin(const char* hex, byte* out, int outSz)
{
    int i, len;
    if (hex == NULL) return -1;
    len = (int)XSTRLEN(hex);
    if (len & 1) return -1;
    len /= 2;
    if (len > outSz) return -1;
    for (i = 0; i < len; i++) {
        byte hi, lo;
        char ch = hex[i * 2];
        char cl = hex[i * 2 + 1];
        hi = (byte)((ch >= 'A' && ch <= 'F') ? (ch - 'A' + 10) :
             (ch >= 'a' && ch <= 'f') ? (ch - 'a' + 10) : (ch - '0'));
        lo = (byte)((cl >= 'A' && cl <= 'F') ? (cl - 'A' + 10) :
             (cl >= 'a' && cl <= 'f') ? (cl - 'a' + 10) : (cl - '0'));
        out[i] = (byte)((hi << 4) | lo);
    }
    return len;
}

/* --- TPM2_ECC_Parameters (CC 0x0178) ---
 * Returns curve parameters from wolfCrypt's ecc_set_type via
 * wc_ecc_get_curve_params(). Automatically supports P-256, P-384,
 * and P-521 (when HAVE_ECC521 is defined). */
static TPM_RC FwCmd_ECC_Parameters(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT16 curveID;
    int wcCurve, curveIdx, f;
    const ecc_set_type* params = NULL;
    byte paramBuf[MAX_ECC_BYTES];
    int paramSz;
    const char* fields[6];

    (void)ctx; (void)cmdSize; (void)cmdTag;

    TPM2_Packet_ParseU16(cmd, &curveID);

    wcCurve = FwGetWcCurveId(curveID);
    if (wcCurve < 0) {
        rc = TPM_RC_CURVE;
    }

    if (rc == 0) {
        curveIdx = wc_ecc_get_curve_idx(wcCurve);
        params = wc_ecc_get_curve_params(curveIdx);
        if (params == NULL) {
            rc = TPM_RC_CURVE;
        }
    }

#ifdef DEBUG_WOLFTPM
    if (rc == 0) {
        printf("fwTPM: ECC_Parameters(curveID=0x%x, size=%d)\n",
            curveID, params->size);
    }
#endif

    if (rc == 0) {
        TPM2_Packet_AppendU16(rsp, curveID);
        TPM2_Packet_AppendU16(rsp, (UINT16)(params->size * 8)); /* bits */
        TPM2_Packet_AppendU16(rsp, TPM_ALG_NULL); /* kdf */
        TPM2_Packet_AppendU16(rsp, TPM_ALG_NULL); /* sign */

        /* p, a, b, Gx, Gy, n from ecc_set_type (hex strings → binary) */
        fields[0] = params->prime;
        fields[1] = params->Af;
        fields[2] = params->Bf;
        fields[3] = params->Gx;
        fields[4] = params->Gy;
        fields[5] = params->order;

        for (f = 0; f < 6 && rc == 0; f++) {
            paramSz = FwHexToBin(fields[f], paramBuf,
                (int)sizeof(paramBuf));
            if (paramSz < 0) {
                rc = TPM_RC_FAILURE;
                break;
            }
            TPM2_Packet_AppendU16(rsp, (UINT16)paramSz);
            TPM2_Packet_AppendBytes(rsp, paramBuf, paramSz);
        }

        /* cofactor h */
        if (rc == 0) {
            byte h = (byte)params->cofactor;
            TPM2_Packet_AppendU16(rsp, 1);
            TPM2_Packet_AppendU8(rsp, h);
        }
    }

    if (rc == 0) {
        FwRspFinalize(rsp, TPM_ST_NO_SESSIONS, TPM_RC_SUCCESS);
    }

    return rc;
}

/* --- TPM2_EC_Ephemeral (CC 0x018E) --- */
/* Generate an ephemeral ECC key pair Q = [r]G and return Q + counter.
 * The private key r is stored for the subsequent ZGen_2Phase call.
 * Per TPM 2.0 spec Section 19.3. */
static TPM_RC FwCmd_EC_Ephemeral(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT16 curveID;
    int wcCurve, keySz;
    FWTPM_DECLARE_VAR(ephKey, ecc_key);
    byte qxBuf[66], qyBuf[66]; /* max P-521 */
    word32 qxSz = 0, qySz = 0;
    int markPos;
    int paramSzPos, paramStart;
    word32 derSz;
    int keyInit = 0;

    (void)cmdSize;

    FWTPM_ALLOC_VAR(ephKey, ecc_key);

    if (cmdSize < TPM2_HEADER_SIZE + 2) {
        rc = TPM_RC_COMMAND_SIZE;
    }

    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &curveID);

        wcCurve = FwGetWcCurveId(curveID);
        keySz = FwGetEccKeySize(curveID);
        if (wcCurve < 0 || keySz <= 0) {
            rc = TPM_RC_CURVE;
        }
    }

    /* Generate ephemeral key pair */
    if (rc == 0) {
        rc = wc_ecc_init(ephKey);
        if (rc == 0) {
            keyInit = 1;
        }
    }
    if (rc == 0) {
        rc = wc_ecc_make_key_ex(&ctx->rng, keySz, ephKey, wcCurve);
        if (rc != 0) {
            rc = TPM_RC_FAILURE;
        }
    }

    /* Export public point */
    if (rc == 0) {
        qxSz = (word32)sizeof(qxBuf);
        qySz = (word32)sizeof(qyBuf);
        rc = wc_ecc_export_public_raw(ephKey, qxBuf, &qxSz, qyBuf, &qySz);
        if (rc != 0) {
            rc = TPM_RC_FAILURE;
        }
    }

    /* Store private key DER for ZGen_2Phase */
    if (rc == 0) {
        derSz = (word32)sizeof(ctx->ecEphemeralKey);
        rc = wc_EccKeyToDer(ephKey, ctx->ecEphemeralKey, derSz);
        if (rc > 0) {
            ctx->ecEphemeralKeySz = rc;
            ctx->ecEphemeralCurve = curveID;
            rc = 0;
        }
        else {
            rc = TPM_RC_FAILURE;
        }
    }

    if (keyInit) {
        wc_ecc_free(ephKey);
    }

    if (rc == 0) {
        ctx->ecEphemeralCounter++;

    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: EC_Ephemeral(curve=0x%x, counter=%d)\n",
            curveID, ctx->ecEphemeralCounter);
    #endif

        /* Response: TPM2B_ECC_POINT Q + UINT16 counter */
        paramStart = FwRspParamsBegin(rsp, cmdTag, &paramSzPos);

        /* TPM2B_ECC_POINT: size(2) + {x(TPM2B) + y(TPM2B)} */
        TPM2_Packet_MarkU16(rsp, &markPos);
        TPM2_Packet_AppendU16(rsp, (UINT16)qxSz);
        TPM2_Packet_AppendBytes(rsp, qxBuf, qxSz);
        TPM2_Packet_AppendU16(rsp, (UINT16)qySz);
        TPM2_Packet_AppendBytes(rsp, qyBuf, qySz);
        TPM2_Packet_PlaceU16(rsp, markPos);

        TPM2_Packet_AppendU16(rsp, ctx->ecEphemeralCounter);
        FwRspParamsEnd(rsp, cmdTag, paramSzPos, paramStart);
    }

    FWTPM_FREE_VAR(ephKey);
    return rc;
}

/* --- TPM2_ZGen_2Phase (CC 0x018D) --- */
/* Two-phase key exchange. Uses keyA (static) + ephemeral from EC_Ephemeral.
 * Computes outZ1 = ECDH(keyA.priv, inQsB) and
 *          outZ2 = ECDH(ephemeral.priv, inQeB).
 * Per TPM 2.0 spec Section 14.7. Only TPM_ALG_ECDH scheme supported. */
static TPM_RC FwCmd_ZGen_2Phase(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT32 keyAHandle;
    FWTPM_Object* keyA;
    TPM2B_ECC_POINT inQsB, inQeB;
    UINT16 inScheme, counter;
    FWTPM_DECLARE_VAR(privKeyA, ecc_key);
    FWTPM_DECLARE_VAR(privEph, ecc_key);
    FWTPM_DECLARE_VAR(peerPub, ecc_key);
    byte z1xBuf[66], z1yBuf[66]; /* shared point coordinates (outZ1) */
    byte z2xBuf[66], z2yBuf[66]; /* shared point coordinates (outZ2) */
    word32 z1xSz, z1ySz, z2xSz, z2ySz;
    int wcCurve;
    int markPos;
    int paramSzPos, paramStart;
    int ephInit = 0, privAInit = 0, peerInit = 0;

    (void)cmdSize;

    FWTPM_ALLOC_VAR(privKeyA, ecc_key);
    FWTPM_ALLOC_VAR(privEph, ecc_key);
    FWTPM_ALLOC_VAR(peerPub, ecc_key);

    /* Parse keyA handle */
    TPM2_Packet_ParseU32(cmd, &keyAHandle);
    if (cmdTag == TPM_ST_SESSIONS)
        rc = FwSkipAuthArea(cmd, cmdSize);

    keyA = FwFindObject(ctx, keyAHandle);
    if (keyA == NULL) {
        rc = TPM_RC_HANDLE;
    }
    if (rc == 0 && keyA->pub.type != TPM_ALG_ECC) {
        rc = TPM_RC_KEY;
    }

    /* Parse inQsB (TPM2B_ECC_POINT) */
    if (rc == 0) {
        UINT16 ptSz;
        TPM2_Packet_ParseU16(cmd, &ptSz); /* point size */
        (void)ptSz;
        TPM2_Packet_ParseU16(cmd, &inQsB.point.x.size);
        if (inQsB.point.x.size > sizeof(inQsB.point.x.buffer))
            rc = TPM_RC_SIZE;
        if (rc == 0 && inQsB.point.x.size > 0)
            TPM2_Packet_ParseBytes(cmd, inQsB.point.x.buffer,
                inQsB.point.x.size);
        if (rc == 0) {
            TPM2_Packet_ParseU16(cmd, &inQsB.point.y.size);
            if (inQsB.point.y.size > sizeof(inQsB.point.y.buffer))
                rc = TPM_RC_SIZE;
        }
        if (rc == 0 && inQsB.point.y.size > 0)
            TPM2_Packet_ParseBytes(cmd, inQsB.point.y.buffer,
                inQsB.point.y.size);
    }

    /* Parse inQeB (TPM2B_ECC_POINT) */
    if (rc == 0) {
        UINT16 ptSz;
        TPM2_Packet_ParseU16(cmd, &ptSz);
        (void)ptSz;
        TPM2_Packet_ParseU16(cmd, &inQeB.point.x.size);
        if (inQeB.point.x.size > sizeof(inQeB.point.x.buffer))
            rc = TPM_RC_SIZE;
        if (rc == 0 && inQeB.point.x.size > 0)
            TPM2_Packet_ParseBytes(cmd, inQeB.point.x.buffer,
                inQeB.point.x.size);
        if (rc == 0) {
            TPM2_Packet_ParseU16(cmd, &inQeB.point.y.size);
            if (inQeB.point.y.size > sizeof(inQeB.point.y.buffer))
                rc = TPM_RC_SIZE;
        }
        if (rc == 0 && inQeB.point.y.size > 0)
            TPM2_Packet_ParseBytes(cmd, inQeB.point.y.buffer,
                inQeB.point.y.size);
    }

    /* Parse scheme and counter */
    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &inScheme);
        TPM2_Packet_ParseU16(cmd, &counter);
    }

    /* Only ECDH scheme supported */
    if (rc == 0 && inScheme != TPM_ALG_ECDH) {
        rc = TPM_RC_SCHEME;
    }

    /* Verify counter matches */
    if (rc == 0 && counter != ctx->ecEphemeralCounter) {
        rc = TPM_RC_VALUE;
    }
    if (rc == 0 && ctx->ecEphemeralKeySz == 0) {
        rc = TPM_RC_VALUE; /* no ephemeral key available */
    }

    wcCurve = (rc == 0) ?
        FwGetWcCurveId(keyA->pub.parameters.eccDetail.curveID) : -1;
    if (rc == 0 && wcCurve < 0) {
        rc = TPM_RC_CURVE;
    }

#ifdef DEBUG_WOLFTPM
    if (rc == 0) {
        printf("fwTPM: ZGen_2Phase(keyA=0x%x, scheme=0x%x, counter=%d)\n",
            keyAHandle, inScheme, counter);
    }
#endif

    /* Compute outZ1 = ECDH(keyA.priv, inQsB) */
    if (rc == 0) {
        rc = FwImportEccKeyFromDer(keyA, privKeyA);
        if (rc == 0) {
            privAInit = 1;
            wc_ecc_set_rng(privKeyA, &ctx->rng);
        }
    }
    if (rc == 0) {
        rc = wc_ecc_init(peerPub);
        if (rc == 0) peerInit = 1;
    }
    if (rc == 0) {
        rc = wc_ecc_import_unsigned(peerPub,
            inQsB.point.x.buffer, inQsB.point.y.buffer, NULL, wcCurve);
    }
    if (rc == 0) {
        rc = wc_ecc_check_key(peerPub);
        if (rc != 0) rc = TPM_RC_ECC_POINT;
    }
    if (rc == 0) {
        rc = FwEccSharedPoint(privKeyA, peerPub,
            z1xBuf, &z1xSz, z1yBuf, &z1ySz);
        if (rc != 0) rc = TPM_RC_FAILURE;
    }

    /* Compute outZ2 = ECDH(ephemeral.priv, inQeB) */
    if (rc == 0) {
        word32 idx = 0;
        rc = wc_ecc_init(privEph);
        if (rc == 0) {
            ephInit = 1;
            rc = wc_EccPrivateKeyDecode(ctx->ecEphemeralKey, &idx,
                privEph, (word32)ctx->ecEphemeralKeySz);
            if (rc == 0) {
                wc_ecc_set_rng(privEph, &ctx->rng);
            }
        }
        if (rc != 0) rc = TPM_RC_FAILURE;
    }
    if (rc == 0 && peerInit) {
        wc_ecc_free(peerPub);
        peerInit = 0;
    }
    if (rc == 0) {
        rc = wc_ecc_init(peerPub);
        if (rc == 0) peerInit = 1;
    }
    if (rc == 0) {
        rc = wc_ecc_import_unsigned(peerPub,
            inQeB.point.x.buffer, inQeB.point.y.buffer, NULL, wcCurve);
    }
    if (rc == 0) {
        rc = wc_ecc_check_key(peerPub);
        if (rc != 0) rc = TPM_RC_ECC_POINT;
    }
    if (rc == 0) {
        rc = FwEccSharedPoint(privEph, peerPub,
            z2xBuf, &z2xSz, z2yBuf, &z2ySz);
        if (rc != 0) rc = TPM_RC_FAILURE;
    }

    /* Build response: outZ1 + outZ2 as TPM2B_ECC_POINT with full (x,y).
     * TPM 2.0 Part 3 §14.7: Z value is the x-coordinate; y is populated
     * for spec-strictness and TPM_ALG_ECMQV compatibility. */
    if (rc == 0) {
        paramStart = FwRspParamsBegin(rsp, cmdTag, &paramSzPos);

        /* outZ1 */
        TPM2_Packet_MarkU16(rsp, &markPos);
        TPM2_Packet_AppendU16(rsp, (UINT16)z1xSz);
        TPM2_Packet_AppendBytes(rsp, z1xBuf, z1xSz);
        TPM2_Packet_AppendU16(rsp, (UINT16)z1ySz);
        TPM2_Packet_AppendBytes(rsp, z1yBuf, z1ySz);
        TPM2_Packet_PlaceU16(rsp, markPos);

        /* outZ2 */
        TPM2_Packet_MarkU16(rsp, &markPos);
        TPM2_Packet_AppendU16(rsp, (UINT16)z2xSz);
        TPM2_Packet_AppendBytes(rsp, z2xBuf, z2xSz);
        TPM2_Packet_AppendU16(rsp, (UINT16)z2ySz);
        TPM2_Packet_AppendBytes(rsp, z2yBuf, z2ySz);
        TPM2_Packet_PlaceU16(rsp, markPos);

        FwRspParamsEnd(rsp, cmdTag, paramSzPos, paramStart);
    }

    /* Cleanup */
    TPM2_ForceZero(z1xBuf, sizeof(z1xBuf));
    TPM2_ForceZero(z1yBuf, sizeof(z1yBuf));
    TPM2_ForceZero(z2xBuf, sizeof(z2xBuf));
    TPM2_ForceZero(z2yBuf, sizeof(z2yBuf));
    /* Zero ephemeral key — it was consumed and must not be reused */
    TPM2_ForceZero(ctx->ecEphemeralKey, sizeof(ctx->ecEphemeralKey));
    ctx->ecEphemeralKeySz = 0;
    if (privAInit) wc_ecc_free(privKeyA);
    if (ephInit) wc_ecc_free(privEph);
    if (peerInit) wc_ecc_free(peerPub);
    FWTPM_FREE_VAR(privKeyA);
    FWTPM_FREE_VAR(privEph);
    FWTPM_FREE_VAR(peerPub);
    return rc;
}
#endif /* HAVE_ECC */

/* --- TPM2_Vendor_TCG_Test (CC 0x20000000) --- */
/* Vendor-specific test command. Echoes input data as output. */
static TPM_RC FwCmd_Vendor_TCG_Test(FWTPM_CTX* ctx, TPM2_Packet* cmd,
    int cmdSize, TPM2_Packet* rsp, UINT16 cmdTag)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT16 dataSize = 0;
    byte dataBuf[128];
    int paramSzPos, paramStart;

    (void)ctx;

    if (cmdSize < TPM2_HEADER_SIZE + 2) {
        rc = TPM_RC_COMMAND_SIZE;
    }

    if (rc == 0) {
        TPM2_Packet_ParseU16(cmd, &dataSize);
        if (dataSize > sizeof(dataBuf))
            rc = TPM_RC_SIZE;
    }
    if (rc == 0 && dataSize > 0) {
        if (cmd->pos + dataSize > cmdSize) {
            rc = TPM_RC_COMMAND_SIZE;
        }
    }
    if (rc == 0 && dataSize > 0) {
        TPM2_Packet_ParseBytes(cmd, dataBuf, dataSize);
    }

    if (rc == 0) {
    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: Vendor_TCG_Test(dataSz=%d)\n", dataSize);
    #endif
        /* Echo back the input data */
        paramStart = FwRspParamsBegin(rsp, cmdTag, &paramSzPos);
        TPM2_Packet_AppendU16(rsp, dataSize);
        if (dataSize > 0) {
            TPM2_Packet_AppendBytes(rsp, dataBuf, dataSize);
        }
        FwRspParamsEnd(rsp, cmdTag, paramSzPos, paramStart);
    }

    return rc;
}

/* ================================================================== */
/* Command Dispatch Table                                              */
/* ================================================================== */

typedef TPM_RC (*FwCmdHandler)(FWTPM_CTX* ctx, TPM2_Packet* cmd, int cmdSize,
    TPM2_Packet* rsp, UINT16 cmdTag);

/* Command dispatch table entry with metadata for auth area parsing */
typedef struct {
    TPM_CC cc;
    FwCmdHandler handler;
    UINT8 inHandleCnt;      /* Number of input handles after header */
    UINT8 authHandleCnt;    /* Number of handles requiring authorization */
    UINT8 outHandleCnt;     /* Number of output handles in response */
    UINT8 encDecFlags;      /* Bit 0: first cmd param is TPM2B (can decrypt) */
                            /* Bit 1: first rsp param is TPM2B (can encrypt) */
} FWTPM_CMD_ENTRY;

#ifndef FWTPM_NO_PARAM_ENC
#define FW_CMD_FLAG_ENC  0x01   /* First command param can be encrypted */
#define FW_CMD_FLAG_DEC  0x02   /* First response param can be encrypted */
#else
#define FW_CMD_FLAG_ENC  0      /* Param encryption disabled */
#define FW_CMD_FLAG_DEC  0      /* Param encryption disabled */
#endif

/*                                                    inH aH oH flags */
static const FWTPM_CMD_ENTRY fwCmdTable[] = {
    /* --- Basic (always enabled) --- */
    { TPM_CC_Startup,            FwCmd_Startup,            0, 0, 0, 0 },
    { TPM_CC_Shutdown,           FwCmd_Shutdown,            0, 0, 0, 0 },
    { TPM_CC_SelfTest,           FwCmd_SelfTest,            0, 0, 0, 0 },
    { TPM_CC_IncrementalSelfTest, FwCmd_IncrementalSelfTest, 0, 0, 0, 0 },
    { TPM_CC_GetTestResult,      FwCmd_GetTestResult,       0, 0, 0, 0 },
    { TPM_CC_GetRandom,          FwCmd_GetRandom,           0, 0, 0, FW_CMD_FLAG_DEC },
    { TPM_CC_StirRandom,         FwCmd_StirRandom,          0, 0, 0, FW_CMD_FLAG_ENC },
    { TPM_CC_GetCapability,      FwCmd_GetCapability,       0, 0, 0, 0 },
    { TPM_CC_TestParms,          FwCmd_TestParms,            0, 0, 0, 0 },
    { TPM_CC_PCR_Read,           FwCmd_PCR_Read,            0, 0, 0, 0 },
    { TPM_CC_PCR_Extend,         FwCmd_PCR_Extend,          1, 1, 0, 0 },
    { TPM_CC_PCR_Reset,          FwCmd_PCR_Reset,           1, 1, 0, 0 },
    { TPM_CC_PCR_Event,          FwCmd_PCR_Event,            1, 1, 0, FW_CMD_FLAG_ENC },
    { TPM_CC_PCR_Allocate,       FwCmd_PCR_Allocate,         1, 1, 0, 0 },
    { TPM_CC_PCR_SetAuthPolicy,  FwCmd_PCR_SetAuthPolicy,    1, 1, 0, FW_CMD_FLAG_ENC },
    { TPM_CC_PCR_SetAuthValue,   FwCmd_PCR_SetAuthValue,     1, 1, 0, FW_CMD_FLAG_ENC },
    { TPM_CC_ReadClock,          FwCmd_ReadClock,            0, 0, 0, 0 },
    { TPM_CC_ClockSet,           FwCmd_ClockSet,             1, 1, 0, 0 },
    { TPM_CC_ClockRateAdjust,    FwCmd_ClockRateAdjust,      1, 1, 0, 0 },
    /* --- Key management (always enabled, algorithm checks inside) --- */
    { TPM_CC_CreatePrimary,      FwCmd_CreatePrimary,       1, 1, 1, FW_CMD_FLAG_ENC | FW_CMD_FLAG_DEC },
    { TPM_CC_FlushContext,       FwCmd_FlushContext,         1, 0, 0, 0 },
    { TPM_CC_ContextSave,        FwCmd_ContextSave,          1, 0, 0, 0 },
    { TPM_CC_ContextLoad,        FwCmd_ContextLoad,          0, 0, 1, 0 },
    { TPM_CC_ReadPublic,         FwCmd_ReadPublic,           1, 0, 0, FW_CMD_FLAG_DEC },
    { TPM_CC_Clear,              FwCmd_Clear,                1, 1, 0, 0 },
    { TPM_CC_ClearControl,       FwCmd_ClearControl,         1, 1, 0, 0 },
    { TPM_CC_ChangeEPS,          FwCmd_ChangeEPS,            1, 1, 0, 0 },
    { TPM_CC_ChangePPS,          FwCmd_ChangePPS,            1, 1, 0, 0 },
    { TPM_CC_HierarchyControl,   FwCmd_HierarchyControl,     1, 1, 0, 0 },
    { TPM_CC_HierarchyChangeAuth, FwCmd_HierarchyChangeAuth, 1, 1, 0, FW_CMD_FLAG_ENC },
    { TPM_CC_SetPrimaryPolicy,   FwCmd_SetPrimaryPolicy,     1, 1, 0, FW_CMD_FLAG_ENC },
    { TPM_CC_EvictControl,       FwCmd_EvictControl,         2, 1, 0, 0 },
    { TPM_CC_Create,             FwCmd_Create,               1, 1, 0, FW_CMD_FLAG_ENC | FW_CMD_FLAG_DEC },
    { TPM_CC_ObjectChangeAuth,   FwCmd_ObjectChangeAuth,     2, 1, 0, FW_CMD_FLAG_ENC | FW_CMD_FLAG_DEC },
    { TPM_CC_Load,               FwCmd_Load,                 1, 1, 1, FW_CMD_FLAG_ENC | FW_CMD_FLAG_DEC },
    { TPM_CC_Sign,               FwCmd_Sign,                 1, 1, 0, FW_CMD_FLAG_ENC },
    { TPM_CC_VerifySignature,    FwCmd_VerifySignature,      1, 0, 0, 0 },
#ifndef NO_RSA
    { TPM_CC_RSA_Encrypt,        FwCmd_RSA_Encrypt,          1, 0, 0, FW_CMD_FLAG_ENC | FW_CMD_FLAG_DEC },
    { TPM_CC_RSA_Decrypt,        FwCmd_RSA_Decrypt,          1, 1, 0, FW_CMD_FLAG_ENC | FW_CMD_FLAG_DEC },
#endif
    /* --- Hash/HMAC --- */
    { TPM_CC_Hash,               FwCmd_Hash,                 0, 0, 0, FW_CMD_FLAG_ENC | FW_CMD_FLAG_DEC },
    { TPM_CC_HMAC,               FwCmd_HMAC,                 1, 1, 0, FW_CMD_FLAG_ENC | FW_CMD_FLAG_DEC },
    { TPM_CC_HMAC_Start,         FwCmd_HMAC_Start,           1, 1, 1, FW_CMD_FLAG_ENC },
    { TPM_CC_HashSequenceStart,  FwCmd_HashSequenceStart,    0, 0, 0, FW_CMD_FLAG_ENC },
    { TPM_CC_SequenceUpdate,     FwCmd_SequenceUpdate,       1, 1, 0, FW_CMD_FLAG_ENC },
    { TPM_CC_SequenceComplete,   FwCmd_SequenceComplete,     1, 1, 0, FW_CMD_FLAG_ENC | FW_CMD_FLAG_DEC },
    { TPM_CC_EventSequenceComplete, FwCmd_EventSequenceComplete, 2, 2, 0, FW_CMD_FLAG_ENC },
    /* --- ECC --- */
#ifdef HAVE_ECC
    { TPM_CC_ECDH_KeyGen,        FwCmd_ECDH_KeyGen,          1, 0, 0, FW_CMD_FLAG_DEC },
    { TPM_CC_ECDH_ZGen,          FwCmd_ECDH_ZGen,            1, 1, 0, FW_CMD_FLAG_ENC | FW_CMD_FLAG_DEC },
    { TPM_CC_EC_Ephemeral,       FwCmd_EC_Ephemeral,         0, 0, 0, FW_CMD_FLAG_DEC },
    { TPM_CC_ZGen_2Phase,        FwCmd_ZGen_2Phase,          1, 1, 0, FW_CMD_FLAG_ENC | FW_CMD_FLAG_DEC },
#endif
    /* --- Sessions --- */
    { TPM_CC_StartAuthSession,   FwCmd_StartAuthSession,     2, 0, 0, 0 },
    { TPM_CC_Unseal,             FwCmd_Unseal,               1, 1, 0, FW_CMD_FLAG_DEC },
    /* --- Policy --- */
#ifndef FWTPM_NO_POLICY
    { TPM_CC_PolicyGetDigest,    FwCmd_PolicyGetDigest,      1, 0, 0, FW_CMD_FLAG_DEC },
    { TPM_CC_PolicyRestart,      FwCmd_PolicyRestart,        1, 0, 0, 0 },
    { TPM_CC_PolicyPCR,          FwCmd_PolicyPCR,            1, 0, 0, FW_CMD_FLAG_ENC },
    { TPM_CC_PolicyPassword,     FwCmd_PolicyPassword,       1, 0, 0, 0 },
    { TPM_CC_PolicyAuthValue,    FwCmd_PolicyAuthValue,      1, 0, 0, 0 },
    { TPM_CC_PolicyCommandCode,  FwCmd_PolicyCommandCode,    1, 0, 0, 0 },
    { TPM_CC_PolicyOR,           FwCmd_PolicyOR,             1, 0, 0, 0 },
    { TPM_CC_PolicySecret,       FwCmd_PolicySecret,         2, 1, 0, 0 },
    { TPM_CC_PolicyAuthorize,    FwCmd_PolicyAuthorize,      1, 0, 0, 0 },
    { TPM_CC_PolicyLocality,     FwCmd_PolicyLocality,       1, 0, 0, 0 },
    { TPM_CC_PolicySigned,       FwCmd_PolicySigned,         2, 0, 0, 0 },
#ifndef FWTPM_NO_NV
    { TPM_CC_PolicyNV,           FwCmd_PolicyNV,             3, 1, 0, 0 },
#endif
    { TPM_CC_PolicyPhysicalPresence, FwCmd_PolicyPhysicalPresence, 1, 0, 0, 0 },
    { TPM_CC_PolicyCpHash,       FwCmd_PolicyCpHash,         1, 0, 0, 0 },
    { TPM_CC_PolicyNameHash,     FwCmd_PolicyNameHash,       1, 0, 0, 0 },
    { TPM_CC_PolicyDuplicationSelect, FwCmd_PolicyDuplicationSelect, 1, 0, 0, 0 },
    { TPM_CC_PolicyNvWritten,    FwCmd_PolicyNvWritten,      1, 0, 0, 0 },
    { TPM_CC_PolicyTemplate,     FwCmd_PolicyTemplate,       1, 0, 0, 0 },
    { TPM_CC_PolicyCounterTimer, FwCmd_PolicyCounterTimer,   1, 0, 0, 0 },
    { TPM_CC_PolicyTicket,       FwCmd_PolicyTicket,         1, 0, 0, 0 },
#ifndef FWTPM_NO_NV
    { TPM_CC_PolicyAuthorizeNV,  FwCmd_PolicyAuthorizeNV,    3, 1, 0, 0 },
#endif
#endif /* !FWTPM_NO_POLICY */
    /* --- Key import/export --- */
    { TPM_CC_LoadExternal,       FwCmd_LoadExternal,         0, 0, 1, FW_CMD_FLAG_ENC | FW_CMD_FLAG_DEC },
    { TPM_CC_Import,             FwCmd_Import,               1, 1, 0, FW_CMD_FLAG_ENC | FW_CMD_FLAG_DEC },
    { TPM_CC_Duplicate,          FwCmd_Duplicate,            2, 1, 0, FW_CMD_FLAG_DEC },
    { TPM_CC_Rewrap,             FwCmd_Rewrap,               2, 1, 0, 0 },
    { TPM_CC_CreateLoaded,       FwCmd_CreateLoaded,         1, 1, 1, FW_CMD_FLAG_ENC | FW_CMD_FLAG_DEC },
    /* --- Symmetric --- */
#ifndef NO_AES
    { TPM_CC_EncryptDecrypt,     FwCmd_EncryptDecrypt,        1, 1, 0, FW_CMD_FLAG_ENC | FW_CMD_FLAG_DEC },
    { TPM_CC_EncryptDecrypt2,    FwCmd_EncryptDecrypt2,       1, 1, 0, FW_CMD_FLAG_ENC | FW_CMD_FLAG_DEC },
#endif
    /* --- NV RAM --- */
#ifndef FWTPM_NO_NV
    { TPM_CC_NV_DefineSpace,     FwCmd_NV_DefineSpace,       1, 1, 0, FW_CMD_FLAG_ENC },
    { TPM_CC_NV_UndefineSpace,   FwCmd_NV_UndefineSpace,     2, 1, 0, 0 },
    { TPM_CC_NV_UndefineSpaceSpecial, FwCmd_NV_UndefineSpaceSpecial, 2, 2, 0, 0 },
    { TPM_CC_NV_ReadPublic,      FwCmd_NV_ReadPublic,        1, 0, 0, FW_CMD_FLAG_DEC },
    { TPM_CC_NV_Write,           FwCmd_NV_Write,             2, 1, 0, FW_CMD_FLAG_ENC },
    { TPM_CC_NV_Read,            FwCmd_NV_Read,              2, 1, 0, FW_CMD_FLAG_DEC },
    { TPM_CC_NV_Extend,          FwCmd_NV_Extend,            2, 1, 0, FW_CMD_FLAG_ENC },
    { TPM_CC_NV_Increment,       FwCmd_NV_Increment,         2, 1, 0, 0 },
    { TPM_CC_NV_WriteLock,       FwCmd_NV_WriteLock,         2, 1, 0, 0 },
    { TPM_CC_NV_ReadLock,        FwCmd_NV_ReadLock,          2, 1, 0, 0 },
    { TPM_CC_NV_SetBits,         FwCmd_NV_SetBits,           2, 1, 0, 0 },
    { TPM_CC_NV_ChangeAuth,      FwCmd_NV_ChangeAuth,        1, 1, 0, FW_CMD_FLAG_ENC },
    { TPM_CC_NV_GlobalWriteLock, FwCmd_NV_GlobalWriteLock,   1, 1, 0, 0 },
#endif /* !FWTPM_NO_NV */
    /* --- ECC Parameters --- */
#ifdef HAVE_ECC
    { TPM_CC_ECC_Parameters,     FwCmd_ECC_Parameters,       0, 0, 0, 0 },
#endif
    /* --- Attestation --- */
#ifndef FWTPM_NO_ATTESTATION
    { TPM_CC_Quote,              FwCmd_Quote,                1, 1, 0, FW_CMD_FLAG_DEC },
    { TPM_CC_Certify,            FwCmd_Certify,              2, 2, 0, FW_CMD_FLAG_DEC },
    { TPM_CC_CertifyCreation,   FwCmd_CertifyCreation,      2, 1, 0, FW_CMD_FLAG_DEC },
    { TPM_CC_GetTime,            FwCmd_GetTime,              2, 2, 0, FW_CMD_FLAG_DEC },
#ifndef FWTPM_NO_NV
    { TPM_CC_NV_Certify,         FwCmd_NV_Certify,           3, 2, 0, FW_CMD_FLAG_DEC },
#endif
#endif /* !FWTPM_NO_ATTESTATION */
    /* --- Credentials --- */
#ifndef FWTPM_NO_CREDENTIAL
    { TPM_CC_MakeCredential,     FwCmd_MakeCredential,       1, 0, 0, FW_CMD_FLAG_DEC },
    { TPM_CC_ActivateCredential, FwCmd_ActivateCredential,   2, 2, 0, FW_CMD_FLAG_DEC },
#endif /* !FWTPM_NO_CREDENTIAL */
    /* --- Dictionary Attack --- */
#ifndef FWTPM_NO_DA
    { TPM_CC_DictionaryAttackLockReset, FwCmd_DictionaryAttackLockReset, 1, 1, 0, 0 },
    { TPM_CC_DictionaryAttackParameters, FwCmd_DictionaryAttackParameters, 1, 1, 0, 0 },
#endif
    /* --- Vendor --- */
    { TPM_CC_Vendor_TCG_Test,    FwCmd_Vendor_TCG_Test,      0, 0, 0, FW_CMD_FLAG_ENC | FW_CMD_FLAG_DEC },
};

#define FWTPM_CMD_TABLE_SIZE \
    (int)(sizeof(fwCmdTable) / sizeof(fwCmdTable[0]))

static int FwGetCmdCount(void)
{
    return FWTPM_CMD_TABLE_SIZE;
}

static TPM_CC FwGetCmdCcAt(int idx)
{
    if (idx < 0 || idx >= FWTPM_CMD_TABLE_SIZE)
        return 0;
    return fwCmdTable[idx].cc;
}

static const FWTPM_CMD_ENTRY* FwFindCmdEntry(TPM_CC cc)
{
    int i;
    for (i = 0; i < FWTPM_CMD_TABLE_SIZE; i++) {
        if (fwCmdTable[i].cc == cc) {
            return &fwCmdTable[i];
        }
    }
    return NULL;
}

/* ================================================================== */
/* Public API: FWTPM_ProcessCommand                                    */
/* ================================================================== */

int FWTPM_ProcessCommand(FWTPM_CTX* ctx,
    const byte* cmdBuf, int cmdSize,
    byte* rspBuf, int* rspSize, int locality)
{
    TPM2_Packet cmdPkt, rspPkt;
    UINT16 cmdTag;
    UINT32 cmdSizeHdr;
    UINT32 cmdCode;
    const FWTPM_CMD_ENTRY* entry;
    TPM_RC rc = TPM_RC_SUCCESS;
#ifndef FWTPM_NO_PARAM_ENC
    FWTPM_Session* encSess = NULL;  /* Session requesting param encryption */
    int doEncCmd = 0;               /* Decrypt incoming encrypted param */
    int doEncRsp = 0;               /* Encrypt outgoing response param */
#endif
    int pj, hj;                     /* Loop indices for auth validation */
    int authFail;                   /* Password comparison result */

    if (ctx == NULL || cmdBuf == NULL || rspBuf == NULL || rspSize == NULL) {
        return BAD_FUNC_ARG;
    }

    if (cmdSize < TPM2_HEADER_SIZE) {
        *rspSize = FwBuildErrorResponse(rspBuf, TPM_ST_NO_SESSIONS,
            TPM_RC_COMMAND_SIZE);
        return TPM_RC_SUCCESS;
    }

    /* Set up command packet for parsing (cast away const - we only read) */
    cmdPkt.buf = (byte*)(size_t)cmdBuf;
    cmdPkt.pos = 0;
    cmdPkt.size = cmdSize;

    /* Parse header */
    TPM2_Packet_ParseU16(&cmdPkt, &cmdTag);
    TPM2_Packet_ParseU32(&cmdPkt, &cmdSizeHdr);
    TPM2_Packet_ParseU32(&cmdPkt, &cmdCode);

    if (cmdTag != TPM_ST_NO_SESSIONS && cmdTag != TPM_ST_SESSIONS) {
        *rspSize = FwBuildErrorResponse(rspBuf, TPM_ST_NO_SESSIONS,
            TPM_RC_BAD_TAG);
        return TPM_RC_SUCCESS;
    }

    if ((int)cmdSizeHdr != cmdSize) {
        *rspSize = FwBuildErrorResponse(rspBuf, TPM_ST_NO_SESSIONS,
            TPM_RC_COMMAND_SIZE);
        return TPM_RC_SUCCESS;
    }

    if (!ctx->wasStarted && cmdCode != TPM_CC_Startup &&
        cmdCode != TPM_CC_GetCapability) {
        *rspSize = FwBuildErrorResponse(rspBuf, TPM_ST_NO_SESSIONS,
            TPM_RC_INITIALIZE);
        return TPM_RC_SUCCESS;
    }

    ctx->activeLocality = locality;

#ifdef DEBUG_WOLFTPM
    printf("fwTPM: Dispatch CC=0x%08X tag=0x%04X size=%d locality=%d\n",
        cmdCode, cmdTag, cmdSize, locality);
#endif

    entry = FwFindCmdEntry(cmdCode);
    if (entry == NULL) {
        *rspSize = FwBuildErrorResponse(rspBuf, TPM_ST_NO_SESSIONS,
            TPM_RC_COMMAND_CODE);
        return TPM_RC_SUCCESS;
    }

    /* Validate minimum command size: header + 4 bytes per input handle */
    if (cmdSize < TPM2_HEADER_SIZE + (entry->inHandleCnt * 4)) {
        *rspSize = FwBuildErrorResponse(rspBuf, TPM_ST_NO_SESSIONS,
            TPM_RC_COMMAND_SIZE);
        return TPM_RC_SUCCESS;
    }

    /* Track all auth sessions from command for response auth generation */
    struct {
        TPM_HANDLE handle;
        FWTPM_Session* sess;   /* NULL for TPM_RS_PW */
        UINT8 attributes;
        byte password[TPM_MAX_DIGEST_SIZE]; /* password for TPM_RS_PW */
        UINT16 passwordSize;
        byte cmdHmac[TPM_MAX_DIGEST_SIZE];  /* HMAC from command */
        UINT16 cmdHmacSize;
    } cmdAuths[FWTPM_MAX_CMD_AUTHS];
    int cmdAuthCnt = 0;
    int cpStart = 0; /* Start of command parameters (after auth area) */
    TPM_HANDLE cmdHandles[4]; /* Input handles for authValue lookup */
    int cmdHandleCnt = 0;
    XMEMSET(cmdAuths, 0, sizeof(cmdAuths));
    XMEMSET(cmdHandles, 0, sizeof(cmdHandles));

    /* For TPM_ST_SESSIONS commands, parse auth area to detect param encryption
     * and track all auth sessions for response auth generation.
     * We peek without advancing cmdPkt.pos so handler re-parses normally. */
    if (cmdTag == TPM_ST_SESSIONS) {
        int savedPos = cmdPkt.pos;
        int i;
        UINT32 authAreaSz;

        /* Save input handles for authValue lookup in response HMAC */
        for (i = 0; i < entry->inHandleCnt && i < 4; i++) {
            TPM2_Packet_ParseU32(&cmdPkt, &cmdHandles[i]);
            cmdHandleCnt++;
        }

        /* Parse auth area */
        if (cmdPkt.pos + 4 <= cmdSize) {
            TPM2_Packet_ParseU32(&cmdPkt, &authAreaSz);

            if (authAreaSz > 0) {
                int authEnd;
                /* Reject if authAreaSz exceeds remaining command bytes */
                if (authAreaSz > (UINT32)(cmdSize - cmdPkt.pos)) {
                    *rspSize = FwBuildErrorResponse(rspBuf,
                        TPM_ST_NO_SESSIONS, TPM_RC_AUTHSIZE);
                    return TPM_RC_SUCCESS;
                }
                authEnd = cmdPkt.pos + (int)authAreaSz;

                while (cmdPkt.pos + 7 <= authEnd && cmdPkt.pos < cmdSize &&
                       cmdAuthCnt < FWTPM_MAX_CMD_AUTHS) {
                    UINT32 sessHandle;
                    UINT16 nonceSize, hmacSize;
                    UINT8 attribs;
                    byte nonceBuf[TPM_MAX_DIGEST_SIZE];

                    TPM2_Packet_ParseU32(&cmdPkt, &sessHandle);
                    TPM2_Packet_ParseU16(&cmdPkt, &nonceSize);
                    if (nonceSize > sizeof(nonceBuf) ||
                        cmdPkt.pos + nonceSize > authEnd) {
                        break;
                    }
                    if (nonceSize > 0) {
                        TPM2_Packet_ParseBytes(&cmdPkt, nonceBuf, nonceSize);
                    }
                    TPM2_Packet_ParseU8(&cmdPkt, &attribs);
                    TPM2_Packet_ParseU16(&cmdPkt, &hmacSize);
                    if (cmdPkt.pos + hmacSize > authEnd) {
                        break;
                    }

                    /* Save auth session info */
                    cmdAuths[cmdAuthCnt].handle = sessHandle;
                    cmdAuths[cmdAuthCnt].attributes = attribs;
                    cmdAuths[cmdAuthCnt].sess = NULL;
                    cmdAuths[cmdAuthCnt].passwordSize = 0;
                    cmdAuths[cmdAuthCnt].cmdHmacSize = 0;

                    /* For password sessions, save the password (HMAC field) */
                    if (sessHandle == TPM_RS_PW && hmacSize > 0 &&
                        hmacSize <= TPM_MAX_DIGEST_SIZE) {
                        TPM2_Packet_ParseBytes(&cmdPkt, cmdAuths[cmdAuthCnt].password,
                            hmacSize);
                        cmdAuths[cmdAuthCnt].passwordSize = hmacSize;
                    }
                    else if (hmacSize > 0 &&
                             hmacSize <= TPM_MAX_DIGEST_SIZE) {
                        /* Save HMAC for command verification */
                        TPM2_Packet_ParseBytes(&cmdPkt,
                            cmdAuths[cmdAuthCnt].cmdHmac, hmacSize);
                        cmdAuths[cmdAuthCnt].cmdHmacSize = hmacSize;
                    }
                    else if (hmacSize > 0) {
                        /* Reject oversized HMAC — do not silently skip,
                         * as that would leave cmdHmacSize=0 and bypass
                         * session HMAC verification */
                        rc = TPM_RC_AUTHSIZE;
                        break;
                    }

                    if (sessHandle != TPM_RS_PW) {
                        FWTPM_Session* sess = FwFindSession(ctx, sessHandle);
                        if (sess != NULL) {
                            cmdAuths[cmdAuthCnt].sess = sess;

                            /* Update session's caller nonce */
                            sess->nonceCaller.size = nonceSize;
                            if (nonceSize > 0) {
                                XMEMCPY(sess->nonceCaller.buffer, nonceBuf,
                                    nonceSize);
                            }

#ifndef FWTPM_NO_PARAM_ENC
                            /* Detect encryption session (first non-PW with
                             * symmetric alg) */
                            if (encSess == NULL &&
                                sess->symmetric.algorithm != TPM_ALG_NULL) {
                                encSess = sess;
                                /* decrypt attr = client encrypted cmd param */
                                if ((attribs & TPMA_SESSION_decrypt)
                                    &&
                                    (entry->encDecFlags & FW_CMD_FLAG_ENC)) {
                                    doEncCmd = 1;
                                }
                                /* encrypt attr = TPM encrypts rsp param */
                                if ((attribs & TPMA_SESSION_encrypt)
                                    &&
                                    (entry->encDecFlags & FW_CMD_FLAG_DEC)) {
                                    doEncRsp = 1;
                                }
                            }
#endif /* !FWTPM_NO_PARAM_ENC */
                        }
                        else {
                            /* Non-existent session handle — reject.
                             * Without this, sess remains NULL and all
                             * downstream HMAC/auth checks are skipped. */
                            rc = TPM_RC_VALUE;
                            break;
                        }
                    }

                    /* HMAC sessions require a non-empty HMAC per TPM 2.0
                     * Part 1 Section 19.6. Accepting hmacSize=0 would
                     * bypass command HMAC verification. Policy sessions
                     * may have empty HMAC when PolicyAuthValue/PolicyPassword
                     * has not been called. */
                    if (rc == 0 && cmdAuths[cmdAuthCnt].sess != NULL &&
                        cmdAuths[cmdAuthCnt].sess->sessionType == TPM_SE_HMAC &&
                        cmdAuths[cmdAuthCnt].cmdHmacSize == 0) {
                        rc = TPM_RC_AUTH_FAIL;
                        break;
                    }

                    cmdAuthCnt++;
                }

                cpStart = authEnd; /* cpBuffer starts after auth area */
            }
        }

        /* Restore position for handler (before decryption, after HMAC check) */
        cmdPkt.pos = savedPos;
    }

    /* Check if auth area parsing encountered an error */
    if (rc != TPM_RC_SUCCESS) {
        *rspSize = FwBuildErrorResponse(rspBuf,
            TPM_ST_NO_SESSIONS, rc);
        return TPM_RC_SUCCESS;
    }

    /* Policy digest validation: for policy sessions authorizing access to
     * entities with an authPolicy, verify session policyDigest matches.
     * Per TPM 2.0 spec Part 1, Section 19.7.1: "A policy session can only
     * authorize access if the session's policyDigest matches the entity's
     * authPolicy at the time the command is executed."
     * Skip for trial sessions (TPM_SE_TRIAL) which compute but don't enforce. */
    for (pj = 0; pj < cmdAuthCnt && pj < (int)entry->authHandleCnt; pj++) {
        if (cmdAuths[pj].sess != NULL &&
            cmdAuths[pj].sess->sessionType == TPM_SE_POLICY) {
            FWTPM_Session* pSess = cmdAuths[pj].sess;
            TPM_HANDLE entityH = cmdHandles[pj];
            TPM2B_DIGEST* authPolicy = NULL;
            int sizeMismatch;
            int policyDiff;
            word32 cmpSz;

            /* Find entity's authPolicy by handle type */
#ifndef FWTPM_NO_NV
            if ((entityH & 0xFF000000) == (NV_INDEX_FIRST & 0xFF000000)) {
                FWTPM_NvIndex* nvEnt = FwFindNvIndex(ctx, entityH);
                if (nvEnt != NULL) {
                    authPolicy = &nvEnt->nvPublic.authPolicy;
                }
            }
            else
#endif /* !FWTPM_NO_NV */
            if ((entityH & 0xFF000000) ==
                (TRANSIENT_FIRST & 0xFF000000)) {
                FWTPM_Object* objEnt = FwFindObject(ctx, entityH);
                if (objEnt != NULL) {
                    authPolicy = &objEnt->pub.authPolicy;
                }
            }
            else if ((entityH & 0xFF000000) ==
                (PERSISTENT_FIRST & 0xFF000000)) {
                FWTPM_Object* objEnt = FwFindObject(ctx, entityH);
                if (objEnt != NULL) {
                    authPolicy = &objEnt->pub.authPolicy;
                }
            }
            /* Hierarchy handles: check SetPrimaryPolicy-assigned policy */
            else if (entityH == TPM_RH_OWNER) {
                authPolicy = &ctx->ownerPolicy;
            }
            else if (entityH == TPM_RH_ENDORSEMENT) {
                authPolicy = &ctx->endorsementPolicy;
            }
            else if (entityH == TPM_RH_PLATFORM) {
                authPolicy = &ctx->platformPolicy;
            }
            else if (entityH == TPM_RH_LOCKOUT) {
                authPolicy = &ctx->lockoutPolicy;
            }

            /* If entity has a non-empty authPolicy, it must match */
            if (authPolicy != NULL && authPolicy->size > 0) {
                /* Always run TPM2_ConstantCompare so timing doesn't leak size */
                sizeMismatch = (pSess->policyDigest.size != authPolicy->size);
                cmpSz = (pSess->policyDigest.size < authPolicy->size) ?
                    pSess->policyDigest.size : authPolicy->size;
                policyDiff = TPM2_ConstantCompare(pSess->policyDigest.buffer,
                    authPolicy->buffer, cmpSz);
                if (sizeMismatch | policyDiff) {
                #ifdef DEBUG_WOLFTPM
                    printf("fwTPM: Policy digest mismatch for handle "
                        "0x%x (CC=0x%x)\n", entityH, cmdCode);
                #endif
                    *rspSize = FwBuildErrorResponse(rspBuf,
                        TPM_ST_NO_SESSIONS, TPM_RC_POLICY_FAIL);
                    return TPM_RC_SUCCESS;
                }
            }
        }
    }

    /* DA lockout check: reject auth attempts if lockout threshold exceeded.
     * Per TPM 2.0 spec, certain commands must still be allowed during lockout
     * (e.g., GetCapability, DictionaryAttackLockReset for recovery). */
#ifndef FWTPM_NO_DA
    if (ctx->daFailedTries >= ctx->daMaxTries && ctx->daMaxTries > 0) {
        if (cmdCode != TPM_CC_GetCapability &&
            cmdCode != TPM_CC_SelfTest &&
            cmdCode != TPM_CC_GetRandom &&
            cmdCode != TPM_CC_DictionaryAttackLockReset &&
            cmdCode != TPM_CC_DictionaryAttackParameters &&
            cmdCode != TPM_CC_StartAuthSession &&
            cmdCode != TPM_CC_FlushContext) {
            *rspSize = FwBuildErrorResponse(rspBuf,
                TPM_ST_NO_SESSIONS, TPM_RC_LOCKOUT);
            return TPM_RC_SUCCESS;
        }
    }
#endif

    /* userWithAuth enforcement: per TPM 2.0 spec Part 1, Section 19.7.1,
     * if an object has authPolicy set and userWithAuth is CLEAR, only a
     * policy session can authorize the object. Reject password and HMAC
     * sessions for such objects. */
    for (pj = 0; pj < cmdAuthCnt && pj < (int)entry->authHandleCnt; pj++) {
        if (cmdAuths[pj].handle == TPM_RS_PW ||
            (cmdAuths[pj].sess != NULL &&
             cmdAuths[pj].sess->sessionType == TPM_SE_HMAC)) {
            TPM_HANDLE entityH = cmdHandles[pj];
            FWTPM_Object* uwObj = NULL;
            if ((entityH & 0xFF000000) == (TRANSIENT_FIRST & 0xFF000000) ||
                (entityH & 0xFF000000) == (PERSISTENT_FIRST & 0xFF000000)) {
                uwObj = FwFindObject(ctx, entityH);
            }
            if (uwObj != NULL && uwObj->pub.authPolicy.size > 0 &&
                !(uwObj->pub.objectAttributes & TPMA_OBJECT_userWithAuth)) {
            #ifdef DEBUG_WOLFTPM
                printf("fwTPM: Password/HMAC auth rejected for handle "
                    "0x%x — policy required (userWithAuth clear)\n", entityH);
            #endif
                *rspSize = FwBuildErrorResponse(rspBuf,
                    TPM_ST_NO_SESSIONS, TPM_RC_AUTH_UNAVAILABLE);
                return TPM_RC_SUCCESS;
            }
        }
    }

    /* Password auth validation: for password sessions (TPM_RS_PW),
     * verify the password matches the entity's authValue.
     * Per TPM 2.0 spec Part 1, Section 19.8.4: password authorization
     * requires the authValue to be provided in cleartext in the HMAC
     * field of the authorization area. */
    for (pj = 0; pj < cmdAuthCnt && pj < (int)entry->authHandleCnt; pj++) {
        if (cmdAuths[pj].handle == TPM_RS_PW) {
            TPM_HANDLE entityH = cmdHandles[pj];
            const byte* authVal = NULL;
            int authValSz = 0;

            FwLookupEntityAuth(ctx, entityH, &authVal, &authValSz);

            authFail = FwCtAuthCompare(cmdAuths[pj].password,
                (int)cmdAuths[pj].passwordSize, authVal, authValSz);
            if (authFail) {
            #ifdef DEBUG_WOLFTPM
                printf("fwTPM: Password auth failed for handle "
                    "0x%x (CC=0x%x)\n", entityH, cmdCode);
            #endif
            #ifndef FWTPM_NO_DA
                ctx->daFailedTries++;
                if (ctx->daFailedTries >= ctx->daMaxTries) {
                    *rspSize = FwBuildErrorResponse(rspBuf,
                        TPM_ST_NO_SESSIONS, TPM_RC_LOCKOUT);
                    return TPM_RC_SUCCESS;
                }
            #endif
                *rspSize = FwBuildErrorResponse(rspBuf,
                    TPM_ST_NO_SESSIONS, TPM_RC_AUTH_FAIL);
                return TPM_RC_SUCCESS;
            }
        }
    }

    /* HMAC session command verification per TPM 2.0 Part 1 Section 19.6.
     * Compute cpHash and verify the command HMAC for each HMAC session. */
    for (hj = 0; hj < cmdAuthCnt && hj < (int)entry->authHandleCnt; hj++) {
        if (cmdAuths[hj].sess != NULL && cmdAuths[hj].cmdHmacSize > 0) {
            FWTPM_Session* hSess = cmdAuths[hj].sess;
            byte cpHash[TPM_MAX_DIGEST_SIZE];
            int cpHashSz = 0;
            byte expectedHmac[TPM_MAX_DIGEST_SIZE];
            int expectedSz = 0;
            const byte* authVal = NULL;
            int authValSz = 0;
            TPM_HANDLE entityH;
            int sizeMismatch;
            int hmacDiff;
            word32 cmpSz;

            /* Compute cpHash = H(commandCode || handleNames || cpBuffer) */
            if (FwComputeCpHash(hSess->authHash, cmdCode,
                    cmdBuf, cmdSize, cmdHandles, cmdHandleCnt,
                    ctx, cpStart, cpHash, &cpHashSz) != 0) {
                *rspSize = FwBuildErrorResponse(rspBuf,
                    TPM_ST_NO_SESSIONS, TPM_RC_FAILURE);
                return TPM_RC_SUCCESS;
            }

            /* Look up entity authValue for HMAC key */
            entityH = cmdHandles[hj];
            FwLookupEntityAuth(ctx, entityH, &authVal, &authValSz);

            /* PolicyPassword with no sessionKey (unsalted/unbound):
             * HMAC field contains plaintext authValue per spec Section 19.6.13.
             * Always run TPM2_ConstantCompare so timing doesn't leak auth
             * length match. */
            if (hSess->sessionType == TPM_SE_POLICY &&
                hSess->isPasswordPolicy &&
                hSess->sessionKey.size == 0) {
                sizeMismatch = ((int)cmdAuths[hj].cmdHmacSize != authValSz);
                cmpSz = (cmdAuths[hj].cmdHmacSize < (UINT16)authValSz) ?
                    cmdAuths[hj].cmdHmacSize : (word32)authValSz;
                hmacDiff = TPM2_ConstantCompare(cmdAuths[hj].cmdHmac,
                    authVal, cmpSz);
                if (sizeMismatch | hmacDiff) {
                #ifdef DEBUG_WOLFTPM
                    printf("fwTPM: PolicyPassword auth failed for handle "
                        "0x%x (CC=0x%x)\n", entityH, cmdCode);
                #endif
                    *rspSize = FwBuildErrorResponse(rspBuf,
                        TPM_ST_NO_SESSIONS, TPM_RC_AUTH_FAIL);
                    return TPM_RC_SUCCESS;
                }
                TPM2_ForceZero(cpHash, sizeof(cpHash));
                continue;
            }

            /* Policy sessions: include authValue in HMAC key only for
             * PolicyPassword (with sessionKey) or PolicyAuthValue */
            if (hSess->sessionType == TPM_SE_POLICY &&
                !hSess->isPasswordPolicy && !hSess->isAuthValuePolicy) {
                authVal = NULL;
                authValSz = 0;
            }

            /* Compute expected command HMAC (nonceCaller first, then nonceTPM) */
            FwComputeSessionHmac(hSess, cpHash, cpHashSz,
                cmdAuths[hj].attributes, authVal, authValSz,
                0, /* isResponse=0 for command HMAC */
                expectedHmac, &expectedSz);

            /* Always run TPM2_ConstantCompare so timing doesn't leak size */
            sizeMismatch = (cmdAuths[hj].cmdHmacSize != (UINT16)expectedSz);
            cmpSz = (cmdAuths[hj].cmdHmacSize < (UINT16)expectedSz) ?
                cmdAuths[hj].cmdHmacSize : (word32)expectedSz;
            hmacDiff = TPM2_ConstantCompare(cmdAuths[hj].cmdHmac,
                expectedHmac, cmpSz);
            if (sizeMismatch | hmacDiff) {
            #ifdef DEBUG_WOLFTPM
                printf("fwTPM: HMAC session auth failed for handle "
                    "0x%x (CC=0x%x)\n", entityH, cmdCode);
            #endif
            #ifndef FWTPM_NO_DA
                ctx->daFailedTries++;
                if (ctx->daFailedTries >= ctx->daMaxTries) {
                    *rspSize = FwBuildErrorResponse(rspBuf,
                        TPM_ST_NO_SESSIONS, TPM_RC_LOCKOUT);
                    return TPM_RC_SUCCESS;
                }
            #endif
                *rspSize = FwBuildErrorResponse(rspBuf,
                    TPM_ST_NO_SESSIONS, TPM_RC_AUTH_FAIL);
                return TPM_RC_SUCCESS;
            }

            TPM2_ForceZero(cpHash, sizeof(cpHash));
            TPM2_ForceZero(expectedHmac, sizeof(expectedHmac));
        }
    }

#ifndef FWTPM_NO_PARAM_ENC
    /* Command parameter decryption (after HMAC verification, before handler).
     * Per TPM 2.0 spec Part 1 Section 19.6.5: cpHash is computed over the encrypted
     * command parameters. Decryption happens after HMAC verification. */
    if (doEncCmd && encSess != NULL && cpStart > 0 && cpStart + 2 <= cmdSize) {
        UINT16 paramSz;
        paramSz = FwLoadU16BE(cmdBuf + cpStart);
        if (paramSz > 0 && cpStart + 2 + paramSz <= cmdSize) {
            rc = (TPM_RC)FwParamDecryptCmd(ctx, encSess,
                (byte*)cmdBuf + cpStart + 2, paramSz);
            if (rc != 0) {
            #ifdef DEBUG_WOLFTPM
                printf("fwTPM: ParamDecrypt failed %d\n", (int)rc);
            #endif
                *rspSize = FwBuildErrorResponse(rspBuf,
                    TPM_ST_NO_SESSIONS, TPM_RC_FAILURE);
                return TPM_RC_SUCCESS;
            }
        }
    }
#endif /* !FWTPM_NO_PARAM_ENC */

    /* Set up response packet */
    FwRspInit(&rspPkt, rspBuf, FWTPM_MAX_COMMAND_SIZE);

    rc = entry->handler(ctx, &cmdPkt, cmdSize, &rspPkt, cmdTag);
    if (rc != TPM_RC_SUCCESS) {
        *rspSize = FwBuildErrorResponse(rspBuf, TPM_ST_NO_SESSIONS, rc);
    }
    else if (cmdTag != TPM_ST_SESSIONS) {
        /* Non-session: handler already finalized the response */
        *rspSize = rspPkt.pos;
    }
    else if (rspPkt.pos >= 2 &&
             FwLoadU16BE(rspBuf) == TPM_ST_NO_SESSIONS) {
        /* Handler already finalized with TPM_ST_NO_SESSIONS (command does not
         * support sessions). Return the handler's response as-is. */
        *rspSize = rspPkt.pos;
    }
    else {
        /* Session response: handler wrote handles + parameterSize + params.
         * We now add response parameter encryption, auth area, and finalize. */
        int rspHandleEnd = TPM2_HEADER_SIZE + (entry->outHandleCnt * 4);
        UINT32 rspParamSzVal = 0;
        int rspParamStart;
#ifndef FWTPM_NO_PARAM_ENC
        int rspParamEnd;
#endif
        int j;
        int rngRc;
        byte rpHash[TPM_MAX_DIGEST_SIZE];
        int rpHashSz = 0;
        const byte* rpBytes = NULL;
        int rpBytesSz = 0;

        /* Read parameterSize from response buffer */
        if (rspHandleEnd + 4 <= rspPkt.pos) {
            rspParamSzVal = (UINT32)(
                (rspBuf[rspHandleEnd] << 24) |
                (rspBuf[rspHandleEnd + 1] << 16) |
                (rspBuf[rspHandleEnd + 2] << 8) |
                rspBuf[rspHandleEnd + 3]);
        }
        rspParamStart = rspHandleEnd + 4;
#ifndef FWTPM_NO_PARAM_ENC
        rspParamEnd = rspParamStart + (int)rspParamSzVal;
#endif

        /* Generate fresh nonceTPM BEFORE response encryption (encryption
         * uses the new nonceTPM, matching what client receives in auth) */
        for (j = 0; j < cmdAuthCnt; j++) {
            if (cmdAuths[j].sess != NULL) {
                FWTPM_Session* sess = cmdAuths[j].sess;
                int digestSz = TPM2_GetHashDigestSize(sess->authHash);
                if (digestSz > 0) {
                    rngRc = wc_RNG_GenerateBlock(&ctx->rng,
                        sess->nonceTPM.buffer, digestSz);
                    if (rngRc == 0) {
                        sess->nonceTPM.size = digestSz;
                    }
                    else {
                        sess->nonceTPM.size = 0;
                    }
                }
            }
        }

#ifndef FWTPM_NO_PARAM_ENC
        /* Response parameter encryption (encrypt first TPM2B param) */
        if (doEncRsp && encSess != NULL && rspParamSzVal > 2) {
            UINT16 firstParamSz;
            firstParamSz = FwLoadU16BE(rspBuf + rspParamStart);
            if (firstParamSz > 0 &&
                rspParamStart + 2 + firstParamSz <= rspParamEnd) {
                int encRc = FwParamEncryptRsp(ctx, encSess,
                    rspBuf + rspParamStart + 2, firstParamSz);
                if (encRc != 0) {
                #ifdef DEBUG_WOLFTPM
                    printf("fwTPM: ParamEncrypt failed %d\n", encRc);
                #endif
                }
            }
        }
#endif /* !FWTPM_NO_PARAM_ENC */

        /* Compute rpHash on (possibly encrypted) response parameters */
        if (rspParamSzVal > 0) {
            rpBytes = rspBuf + rspParamStart;
            rpBytesSz = (int)rspParamSzVal;
        }
        /* Append auth area: one entry per command auth session.
         * rpHash is computed per-session using each session's authHash,
         * per TPM 2.0 Part 1 Section 19.6.5. */
        for (j = 0; j < cmdAuthCnt; j++) {
            UINT8 rspAttribs = cmdAuths[j].attributes &
                TPMA_SESSION_continueSession;
#ifndef FWTPM_NO_PARAM_ENC
            /* Echo encrypt bit if response encryption was applied */
            if (doEncRsp && cmdAuths[j].sess == encSess) {
                rspAttribs |= TPMA_SESSION_encrypt;
            }
#endif /* !FWTPM_NO_PARAM_ENC */

            if (cmdAuths[j].sess == NULL) {
                /* Password session: empty nonce + attributes + empty hmac */
                TPM2_Packet_AppendU16(&rspPkt, 0); /* nonce size = 0 */
                TPM2_Packet_AppendU8(&rspPkt, rspAttribs);
                TPM2_Packet_AppendU16(&rspPkt, 0); /* hmac size = 0 */
            }
            else {
                /* HMAC/Policy session: nonce + attributes + computed HMAC */
                FWTPM_Session* sess = cmdAuths[j].sess;
                int digestSz = TPM2_GetHashDigestSize(sess->authHash);
                byte hmacBuf[TPM_MAX_DIGEST_SIZE];
                int hmacSz = 0;

                /* Append nonceTPM */
                TPM2_Packet_AppendU16(&rspPkt, sess->nonceTPM.size);
                TPM2_Packet_AppendBytes(&rspPkt, sess->nonceTPM.buffer,
                    sess->nonceTPM.size);

                /* Append session attributes */
                TPM2_Packet_AppendU8(&rspPkt, rspAttribs);

                /* PolicyPassword with no sessionKey (unsalted/unbound):
                 * response HMAC is zero-length per spec Section 19.6.13 */
                if (sess->sessionType == TPM_SE_POLICY &&
                    sess->isPasswordPolicy && sess->sessionKey.size == 0) {
                    TPM2_Packet_AppendU16(&rspPkt, 0);
                    continue;
                }

                /* Compute rpHash for this session's hash algorithm */
                rpHashSz = 0;
                FwComputeRpHash(sess->authHash, (TPM_CC)cmdCode,
                    rpBytes, rpBytesSz, rpHash, &rpHashSz);

                /* Compute and append response HMAC.
                 * authValue is the auth of the j-th command entity handle,
                 * but only for authorization sessions (j < authHandleCnt).
                 * Extra sessions (param enc only) use empty authValue. */
                if (rpHashSz > 0 && digestSz > 0) {
                    const byte* authVal = NULL;
                    int authValSz = 0;
                    /* Look up entity authValue from j-th command handle,
                     * only for authorization sessions */
                    if (j < entry->authHandleCnt && j < cmdHandleCnt) {
                        FwLookupEntityAuth(ctx, cmdHandles[j],
                            &authVal, &authValSz);
                    }
                    /* Policy sessions: include authValue in HMAC key only for
                     * PolicyPassword (with sessionKey) or PolicyAuthValue */
                    if (sess->sessionType == TPM_SE_POLICY &&
                        !sess->isPasswordPolicy && !sess->isAuthValuePolicy) {
                        authVal = NULL;
                        authValSz = 0;
                    }
                    FwComputeSessionHmac(sess, rpHash, rpHashSz, rspAttribs,
                        authVal, authValSz, 1 /* isResponse */,
                        hmacBuf, &hmacSz);
                }
                TPM2_Packet_AppendU16(&rspPkt, (UINT16)hmacSz);
                if (hmacSz > 0) {
                    TPM2_Packet_AppendBytes(&rspPkt, hmacBuf, hmacSz);
                }
            }
        }

        /* Finalize response header */
        FwRspFinalize(&rspPkt, TPM_ST_SESSIONS, TPM_RC_SUCCESS);
        *rspSize = rspPkt.pos;
    }

    /* Per TPM 2.0 spec Part 1 Section 19.6.4: flush sessions where the caller
     * did NOT set the continueSession bit in the command attributes.
     * This must happen AFTER the response auth area is built. */
    for (pj = 0; pj < cmdAuthCnt; pj++) {
        if (cmdAuths[pj].sess != NULL &&
            !(cmdAuths[pj].attributes & TPMA_SESSION_continueSession)) {
            FwFreeSession(cmdAuths[pj].sess);
        }
    }

    /* Deferred clear: flush transient objects after response auth is built. */
    if (ctx->pendingClear) {
        int nvRc;
        ctx->pendingClear = 0;
        FwFlushAllObjects(ctx);
        nvRc = FWTPM_NV_Save(ctx);
        if (nvRc != TPM_RC_SUCCESS) {
            return nvRc;
        }
    }

    return TPM_RC_SUCCESS;
}

#endif /* WOLFTPM_FWTPM */
