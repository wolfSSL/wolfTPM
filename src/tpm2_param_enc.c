/* tpm2_param_enc.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

#include <wolftpm/tpm2_param_enc.h>
#include <wolftpm/tpm2_crypto.h>
#include <wolftpm/tpm2_packet.h>

#ifndef WOLFTPM2_NO_WOLFCRYPT
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/hmac.h>
#endif

/* Routines for performing TPM Parameter Encryption
 *
 * NB: Only TPM2B_DATA parameters can be encrypted
 *
 * Only the first parameter of a TPM command can be encrypted.
 * For example, the password auth of a TPM key. The encryption
 * of command response and request are separate. There can be a
 * communication exchange between the TPM and a client program
 * where only the parameter in the request command is encrypted.
 *
 * This behavior depends on the sessionAttributes:
 * - TPMA_SESSION_encrypt for command request
 * - TPMA_SESSION_decrypt for command response
 * Either one can be set separately or both can be set in one
 * authorization session. This is up to the user(developer).
 *
 * Note: TPM2_KDFa and TPM2_KDFe have been moved to tpm2_crypto.c.
 * They are declared in tpm2_crypto.h and included via tpm2_param_enc.h
 * for backward compatibility.
 */

/******************************************************************************/
/* --- Param Enc/Dec Functions -- */
/******************************************************************************/

/* Maximum XOR mask size. RSA-2048 inSensitive parameter blobs on Create can
 * exceed MAX_DIGEST_BUFFER (1024), so leave headroom to ~1250 bytes. Keep
 * stack usage bounded by switching to heap under WOLFTPM_SMALL_STACK. */
#ifndef TPM2_XOR_MASK_MAX
#define TPM2_XOR_MASK_MAX 1280
#endif

/* XOR parameter encryption/decryption (shared by client and fwTPM).
 * XOR is symmetric so encrypt and decrypt are the same operation.
 * nonceA/nonceB order determines direction (caller/TPM or TPM/caller). */
int TPM2_ParamEnc_XOR(
    TPMI_ALG_HASH authHash,
    const BYTE *keyIn, UINT32 keyInSz,
    const BYTE *nonceA, UINT32 nonceASz,
    const BYTE *nonceB, UINT32 nonceBSz,
    BYTE *paramData, UINT32 paramSz)
{
    int rc;
    UINT32 i;
#ifdef WOLFTPM_SMALL_STACK
    BYTE *mask = (BYTE*)XMALLOC(TPM2_XOR_MASK_MAX, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (mask == NULL) {
        return MEMORY_E;
    }
#else
    BYTE mask[TPM2_XOR_MASK_MAX];
#endif

    if (paramSz > TPM2_XOR_MASK_MAX) {
        rc = BUFFER_E;
        goto out;
    }

    XMEMSET(mask, 0, TPM2_XOR_MASK_MAX);
    rc = TPM2_KDFa_ex(authHash, keyIn, keyInSz, "XOR",
        nonceA, nonceASz, nonceB, nonceBSz, mask, paramSz);
    if ((UINT32)rc == paramSz) {
        for (i = 0; i < paramSz; i++) {
            paramData[i] ^= mask[i];
        }
        rc = TPM_RC_SUCCESS;
    }
    else {
    #ifdef DEBUG_WOLFTPM
        printf("KDFa XOR Gen Error %d\n", rc);
    #endif
        rc = TPM_RC_FAILURE;
    }

    TPM2_ForceZero(mask, TPM2_XOR_MASK_MAX);
out:
#ifdef WOLFTPM_SMALL_STACK
    XFREE(mask, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    return rc;
}

/* AES-CFB parameter encryption or decryption (shared by client and fwTPM).
 * nonceA/nonceB order determines direction.
 * doEncrypt: 1 = encrypt, 0 = decrypt */
int TPM2_ParamEnc_AESCFB(
    TPMI_ALG_HASH authHash, UINT16 keyBits,
    const BYTE *keyIn, UINT32 keyInSz,
    const BYTE *nonceA, UINT32 nonceASz,
    const BYTE *nonceB, UINT32 nonceBSz,
    BYTE *paramData, UINT32 paramSz, int doEncrypt)
{
#if !defined(WOLFTPM2_NO_WOLFCRYPT) && defined(WOLFSSL_AES_CFB)
    int rc;
    BYTE symKey[32 + 16]; /* AES key (max 256-bit) + IV (16 bytes) */
    int symKeySz = keyBits / 8;
    const int symKeyIvSz = 16;
    Aes aes;

    if (symKeySz > 32) {
        return BUFFER_E;
    }

    XMEMSET(symKey, 0, sizeof(symKey));
    rc = TPM2_KDFa_ex(authHash, keyIn, keyInSz, "CFB",
        nonceA, nonceASz, nonceB, nonceBSz,
        symKey, symKeySz + symKeyIvSz);
    if (rc != symKeySz + symKeyIvSz) {
    #ifdef DEBUG_WOLFTPM
        printf("KDFa CFB Gen Error %d\n", rc);
    #endif
        rc = TPM_RC_FAILURE;
    }
    else {
        rc = wc_AesInit(&aes, NULL, INVALID_DEVID);
        if (rc == 0) {
            rc = wc_AesSetKey(&aes, symKey, symKeySz, &symKey[symKeySz],
                AES_ENCRYPTION);
            if (rc == 0) {
                if (doEncrypt) {
                    rc = wc_AesCfbEncrypt(&aes, paramData, paramData, paramSz);
                }
                else {
                    rc = wc_AesCfbDecrypt(&aes, paramData, paramData, paramSz);
                }
            }
            wc_AesFree(&aes); /* the free handles zeroizing sensitive data */
        }
    }

    TPM2_ForceZero(symKey, sizeof(symKey));
    return rc;
#else
    (void)authHash; (void)keyBits; (void)keyIn; (void)keyInSz;
    (void)nonceA; (void)nonceASz; (void)nonceB; (void)nonceBSz;
    (void)paramData; (void)paramSz; (void)doEncrypt;
    return NOT_COMPILED_IN;
#endif
}


/******************************************************************************/
/* --- Client-side wrapper functions (use TPM2_AUTH_SESSION) -- */
/******************************************************************************/

#ifndef WOLFTPM_FWTPM

/* Build combined HMAC key from session key + bind key */
static int TPM2_BuildParamKey(TPM2B_AUTH* sessKey, TPM2B_AUTH* bindKey,
    BYTE* keyBuf, UINT32* keyBufSz)
{
    UINT16 bindKeySz = (bindKey != NULL) ? bindKey->size : 0;

    if (sessKey->size > sizeof(sessKey->buffer)) {
        return BUFFER_E;
    }
    if (bindKey != NULL && bindKey->size > sizeof(bindKey->buffer)) {
        return BUFFER_E;
    }
    if (sessKey->size + bindKeySz > MAX_SYM_DATA) {
        return BUFFER_E;
    }

    XMEMCPY(keyBuf, sessKey->buffer, sessKey->size);
    *keyBufSz = sessKey->size;
    if (bindKey != NULL && bindKey->size > 0) {
        XMEMCPY(keyBuf + *keyBufSz, bindKey->buffer, bindKey->size);
        *keyBufSz += bindKey->size;
    }
    return 0;
}

TPM_RC TPM2_ParamEnc_CmdRequest(TPM2_AUTH_SESSION *session,
                                BYTE *paramData, UINT32 paramSz)
{
    TPM_RC rc = TPM_RC_FAILURE;
    BYTE keyBuf[MAX_SYM_DATA];
    UINT32 keyBufSz = 0;

#ifdef WOLFTPM_DEBUG_VERBOSE
    printf("CmdEnc Session Key %d\n", session->auth.size);
#ifdef WOLFTPM_DEBUG_SECRETS
    TPM2_PrintBin(session->auth.buffer, session->auth.size);
#endif
    if (session->bind != NULL) {
        printf("CmdEnc Extra Key %d\n", session->bind->size);
    #ifdef WOLFTPM_DEBUG_SECRETS
        TPM2_PrintBin(session->bind->buffer, session->bind->size);
    #endif
    }
    printf("CmdEnc Nonce caller %d\n", session->nonceCaller.size);
    TPM2_PrintBin(session->nonceCaller.buffer, session->nonceCaller.size);
    printf("CmdEnc Nonce TPM %d\n", session->nonceTPM.size);
    TPM2_PrintBin(session->nonceTPM.buffer, session->nonceTPM.size);
#endif

    rc = TPM2_BuildParamKey(&session->auth, session->bind, keyBuf, &keyBufSz);
    if (rc != 0) {
        return rc;
    }

    if (session->symmetric.algorithm == TPM_ALG_XOR) {
        rc = TPM2_ParamEnc_XOR(session->authHash, keyBuf, keyBufSz,
            session->nonceCaller.buffer, session->nonceCaller.size,
            session->nonceTPM.buffer, session->nonceTPM.size,
            paramData, paramSz);
    }
    else if (session->symmetric.algorithm == TPM_ALG_AES &&
             session->symmetric.mode.aes == TPM_ALG_CFB) {
        rc = TPM2_ParamEnc_AESCFB(session->authHash,
            session->symmetric.keyBits.aes, keyBuf, keyBufSz,
            session->nonceCaller.buffer, session->nonceCaller.size,
            session->nonceTPM.buffer, session->nonceTPM.size,
            paramData, paramSz, 1);
    }
    else {
        rc = TPM_RC_FAILURE;
    }

    TPM2_ForceZero(keyBuf, sizeof(keyBuf));
    return rc;
}

TPM_RC TPM2_ParamDec_CmdResponse(TPM2_AUTH_SESSION *session,
                                 BYTE *paramData, UINT32 paramSz)
{
    TPM_RC rc = TPM_RC_FAILURE;
    BYTE keyBuf[MAX_SYM_DATA];
    UINT32 keyBufSz = 0;

#ifdef WOLFTPM_DEBUG_VERBOSE
    printf("RspDec Session Key %d\n", session->auth.size);
#ifdef WOLFTPM_DEBUG_SECRETS
    TPM2_PrintBin(session->auth.buffer, session->auth.size);
#endif
    if (session->bind != NULL) {
        printf("RspDec Extra Key %d\n", session->bind->size);
    #ifdef WOLFTPM_DEBUG_SECRETS
        TPM2_PrintBin(session->bind->buffer, session->bind->size);
    #endif
    }
    printf("RspDec Nonce caller %d\n", session->nonceCaller.size);
    TPM2_PrintBin(session->nonceCaller.buffer, session->nonceCaller.size);
    printf("RspDec Nonce TPM %d\n", session->nonceTPM.size);
    TPM2_PrintBin(session->nonceTPM.buffer, session->nonceTPM.size);
#endif

    rc = TPM2_BuildParamKey(&session->auth, session->bind, keyBuf, &keyBufSz);
    if (rc != 0) {
        return rc;
    }

    if (session->symmetric.algorithm == TPM_ALG_XOR) {
        /* Response direction: nonceTPM first, nonceCaller second */
        rc = TPM2_ParamEnc_XOR(session->authHash, keyBuf, keyBufSz,
            session->nonceTPM.buffer, session->nonceTPM.size,
            session->nonceCaller.buffer, session->nonceCaller.size,
            paramData, paramSz);
    }
    else if (session->symmetric.algorithm == TPM_ALG_AES &&
             session->symmetric.mode.aes == TPM_ALG_CFB) {
        /* Response direction: nonceTPM first, nonceCaller second */
        rc = TPM2_ParamEnc_AESCFB(session->authHash,
            session->symmetric.keyBits.aes, keyBuf, keyBufSz,
            session->nonceTPM.buffer, session->nonceTPM.size,
            session->nonceCaller.buffer, session->nonceCaller.size,
            paramData, paramSz, 0);
    }
    else {
        rc = TPM_RC_FAILURE;
    }

    TPM2_ForceZero(keyBuf, sizeof(keyBuf));
    return rc;
}

#endif /* !WOLFTPM_FWTPM */


/******************************************************************************/
/* --- Hash and HMAC Functions (client-side only) -- */
/******************************************************************************/

#if !defined(WOLFTPM_FWTPM) && !defined(WOLFTPM2_NO_WOLFCRYPT) && \
    !defined(NO_HMAC)

/* Compute the command parameter hash */
/* TCG TPM 2.0 Part 1 - 18.7 Command Parameter Hash cpHash */
int TPM2_CalcCpHash(TPMI_ALG_HASH authHash, TPM_CC cmdCode,
    TPM2B_NAME* name1, TPM2B_NAME* name2, TPM2B_NAME* name3,
    BYTE* param, UINT32 paramSz, TPM2B_DIGEST* hash)
{
    int rc;
    wc_HashAlg hash_ctx;
    enum wc_HashType hashType;

    rc = TPM2_GetHashType(authHash);
    hashType = (enum wc_HashType)rc;
    rc = wc_HashGetDigestSize(hashType);
    if (rc < 0)
        return rc;
    hash->size = rc;

    rc = wc_HashInit(&hash_ctx, hashType);
    if (rc == 0) {
        UINT32 ccSwap = TPM2_Packet_SwapU32(cmdCode);
        rc = wc_HashUpdate(&hash_ctx, hashType, (byte*)&ccSwap, sizeof(ccSwap));
    #ifdef WOLFTPM_DEBUG_VERBOSE
        printf("cpHash: cmdcode size %d\n", (int)sizeof(TPM_CC));
        TPM2_PrintBin((unsigned char*)&cmdCode, sizeof(TPM_CC));
    #endif

        if (rc == 0 && name1 && name1->size > 0) {
        #ifdef WOLFTPM_DEBUG_VERBOSE
            printf("Name 0: %d\n", name1->size);
            TPM2_PrintBin(name1->name, name1->size);
        #endif
            rc = wc_HashUpdate(&hash_ctx, hashType, name1->name, name1->size);
        }
        if (rc == 0 && name2 && name2->size > 0) {
        #ifdef WOLFTPM_DEBUG_VERBOSE
            printf("Name 1: %d\n", name2->size);
            TPM2_PrintBin(name2->name, name2->size);
        #endif
            rc = wc_HashUpdate(&hash_ctx, hashType, name2->name, name2->size);
        }
        if (rc == 0 && name3 && name3->size > 0) {
        #ifdef WOLFTPM_DEBUG_VERBOSE
            printf("Name 2: %d\n", name3->size);
            TPM2_PrintBin(name3->name, name3->size);
        #endif
            rc = wc_HashUpdate(&hash_ctx, hashType, name3->name, name3->size);
        }

        if (rc == 0) {
        #ifdef WOLFTPM_DEBUG_VERBOSE
            printf("cpHash: params size %d\n", paramSz);
            TPM2_PrintBin(param, paramSz);
        #endif
            rc = wc_HashUpdate(&hash_ctx, hashType, param, paramSz);
        }

        if (rc == 0)
            rc = wc_HashFinal(&hash_ctx, hashType, hash->buffer);

        wc_HashFree(&hash_ctx, hashType);
    }

#ifdef WOLFTPM_DEBUG_VERBOSE
    printf("cpHash: cmd %x, size %d\n", (unsigned int)cmdCode, hash->size);
    TPM2_PrintBin(hash->buffer, hash->size);
#endif

    return rc;
}

/* Compute the response parameter hash */
/* TCG TPM 2.0 Part 1 - 18.8 Response Parameter Hash rpHash */
int TPM2_CalcRpHash(TPMI_ALG_HASH authHash,
    TPM_CC cmdCode, BYTE* param, UINT32 paramSz, TPM2B_DIGEST* hash)
{
    int rc;
    wc_HashAlg hash_ctx;
    enum wc_HashType hashType;

    rc = TPM2_GetHashType(authHash);
    hashType = (enum wc_HashType)rc;
    rc = wc_HashGetDigestSize(hashType);
    if (rc < 0)
        return rc;
    hash->size = rc;

    rc = wc_HashInit(&hash_ctx, hashType);
    if (rc == 0) {
        UINT32 ccSwap;

        ccSwap = 0;
        rc = wc_HashUpdate(&hash_ctx, hashType, (byte*)&ccSwap, sizeof(ccSwap));

        if (rc == 0) {
            ccSwap = TPM2_Packet_SwapU32(cmdCode);
            rc = wc_HashUpdate(&hash_ctx, hashType, (byte*)&ccSwap,
                sizeof(ccSwap));
        }

        if (rc == 0)
            rc = wc_HashUpdate(&hash_ctx, hashType, param, paramSz);

        if (rc == 0)
            rc = wc_HashFinal(&hash_ctx, hashType, hash->buffer);

        wc_HashFree(&hash_ctx, hashType);
    }

#ifdef WOLFTPM_DEBUG_VERBOSE
    printf("rpHash: cmd %x, size %d\n", (unsigned int)cmdCode, hash->size);
    TPM2_PrintBin(hash->buffer, hash->size);
#endif

    return rc;
}

/* Compute the HMAC using cpHash, nonces and session attributes */
/* TCG TPM 2.0 Part 1 - 19.6.5 - HMAC Computation */
int TPM2_CalcHmac(TPMI_ALG_HASH authHash, TPM2B_AUTH* auth,
    const TPM2B_DIGEST* hash, const TPM2B_NONCE* nonceNew,
    const TPM2B_NONCE* nonceOld, TPMA_SESSION sessionAttributes,
    TPM2B_AUTH* hmac)
{
    int rc;
    Hmac hmac_ctx;
    enum wc_HashType hashType;

    rc = TPM2_GetHashType(authHash);
    hashType = (enum wc_HashType)rc;
    hmac->size = TPM2_GetHashDigestSize(authHash);
    if (hmac->size <= 0)
        return BAD_FUNC_ARG;

    rc = wc_HmacInit(&hmac_ctx, NULL, INVALID_DEVID);
    if (rc != 0)
        return rc;

    if (auth) {
    #ifdef WOLFTPM_DEBUG_VERBOSE
        printf("HMAC Key: %d\n", auth->size);
        #ifdef WOLFTPM_DEBUG_SECRETS
            TPM2_PrintBin(auth->buffer, auth->size);
        #endif
    #endif
        rc = wc_HmacSetKey(&hmac_ctx, hashType, auth->buffer, auth->size);
    }
    else {
        rc = wc_HmacSetKey(&hmac_ctx, hashType, NULL, 0);
    }

    if (rc == 0)
        rc = wc_HmacUpdate(&hmac_ctx, hash->buffer, hash->size);
    if (rc == 0)
        rc = wc_HmacUpdate(&hmac_ctx, nonceNew->buffer, nonceNew->size);
    if (rc == 0)
        rc = wc_HmacUpdate(&hmac_ctx, nonceOld->buffer, nonceOld->size);
    if (rc == 0)
        rc = wc_HmacUpdate(&hmac_ctx, &sessionAttributes, 1);
    if (rc == 0)
        rc = wc_HmacFinal(&hmac_ctx, hmac->buffer);
    wc_HmacFree(&hmac_ctx);

#ifdef WOLFTPM_DEBUG_VERBOSE
    printf("HMAC Auth: attrib %x, size %d\n", sessionAttributes, hmac->size);
    TPM2_PrintBin(hmac->buffer, hmac->size);
#endif

    return rc;
}
#endif /* !WOLFTPM_FWTPM && !WOLFTPM2_NO_WOLFCRYPT && !NO_HMAC */
