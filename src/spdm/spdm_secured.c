/* spdm_secured.c
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

/*
 * SPDM Secured Message Format (DSP0277):
 *
 * MCTP transport:
 *   Header/AAD: SessionID(4 LE) + SeqNum(2 LE) + Length(2 LE) = 8 bytes
 *   IV XOR: Leftmost 2 bytes (bytes 0-1) with 2-byte LE sequence number (DSP0277)
 *
 * Nuvoton TCG binding (Rev 1.11):
 *   Header/AAD: SessionID(4 LE) + SeqNum(8 LE) + Length(2 LE) = 14 bytes
 *   IV XOR: Leftmost 8 bytes (bytes 0-7) with 8-byte LE sequence number (DSP0277 1.2)
 *   Plaintext: AppDataLength(2 LE) + SPDM msg + RandomData (pad to 16)
 *
 * Full message: Header || Ciphertext || Tag (16)
 */

int wolfSPDM_EncryptInternal(WOLFSPDM_CTX* ctx,
    const byte* plain, word32 plainSz,
    byte* enc, word32* encSz)
{
    Aes aes;
    byte iv[WOLFSPDM_AEAD_IV_SIZE];
    byte aad[16];  /* Up to 14 bytes for TCG format */
    byte plainBuf[WOLFSPDM_MAX_MSG_SIZE + 16];
    byte tag[WOLFSPDM_AEAD_TAG_SIZE];
    word32 plainBufSz;
    word16 recordLen;
    word32 hdrSz;
    word32 aadSz;
    int aesInit = 0;
    int rc;

    if (ctx == NULL || plain == NULL || enc == NULL || encSz == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }
    if (plainSz > WOLFSPDM_MAX_MSG_SIZE) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

#if defined(WOLFSPDM_NUVOTON) || defined(WOLFSPDM_NATIONS)
    if (ctx->mode == WOLFSPDM_MODE_NUVOTON ||
        ctx->mode == WOLFSPDM_MODE_NATIONS ||
        ctx->mode == WOLFSPDM_MODE_NATIONS_PSK) {
        /* Nuvoton TCG binding format per Rev 1.11 spec page 25:
         * Header/AAD: SessionID(4 LE) + SeqNum(8 LE) + Length(2 LE) = 14 bytes
         * IV XOR: Leftmost 8 bytes (bytes 0-7) with 8-byte LE sequence number
         */
        word16 appDataLen = (word16)plainSz;

        word16 unpadded = (word16)(2 + appDataLen);
        word16 padLen = (word16)((16 - (unpadded % 16)) % 16);
        word16 encPayloadSz = (word16)(unpadded + padLen);

        plainBufSz = encPayloadSz;
        /* Length field = ciphertext + MAC
         * (per Nuvoton spec page 25: Length=160=144+16) */
        recordLen = (word16)(encPayloadSz + WOLFSPDM_AEAD_TAG_SIZE);
        hdrSz = 14;  /* 4 + 8 + 2 (TCG binding format) */

        if (*encSz < hdrSz + plainBufSz + WOLFSPDM_AEAD_TAG_SIZE) {
            return WOLFSPDM_E_BUFFER_SMALL;
        }

        /* Build plaintext: AppDataLength(2 LE) || SPDM message || RandomData */
        SPDM_Set16LE(plainBuf, appDataLen);
        XMEMCPY(&plainBuf[2], plain, plainSz);
        /* Fill RandomData with actual random bytes per Nuvoton spec */
        if (padLen > 0) {
            rc = wolfSPDM_GetRandom(ctx, &plainBuf[unpadded], padLen);
            if (rc != WOLFSPDM_SUCCESS) {
                return rc;
            }
        }

        /* Build header/AAD: SessionID(4 LE) + SeqNum(8 LE) +
         * Length(2 LE) = 14 bytes */
        SPDM_Set32LE(&enc[0], ctx->sessionId);
        SPDM_Set64LE(&enc[4], ctx->reqSeqNum);
        SPDM_Set16LE(&enc[12], recordLen);

        aadSz = 14;
        XMEMCPY(aad, enc, aadSz);
    } else
#endif
    {
        /* MCTP format (per DSP0277):
         * Plaintext: AppDataLen(2 LE) + MCTP header(0x05) + SPDM message
         * Header: SessionID(4 LE) + SeqNum(2 LE) + Length(2 LE) = 8 bytes
         * AAD = Header
         */
        word16 appDataLen = (word16)(1 + plainSz);
        word16 encDataLen = (word16)(2 + appDataLen);

        plainBufSz = encDataLen;
        recordLen = (word16)(encDataLen + WOLFSPDM_AEAD_TAG_SIZE);
        hdrSz = 8;  /* 4 + 2 + 2 */

        if (*encSz < hdrSz + recordLen) {
            return WOLFSPDM_E_BUFFER_SMALL;
        }

        /* Build plaintext: AppDataLen(2 LE) || MCTP header(0x05) || SPDM msg */
        SPDM_Set16LE(plainBuf, appDataLen);
        plainBuf[2] = MCTP_MESSAGE_TYPE_SPDM;
        XMEMCPY(&plainBuf[3], plain, plainSz);

        /* Build header/AAD: SessionID(4 LE) + SeqNum(2 LE) + Length(2 LE) */
        SPDM_Set32LE(&enc[0], ctx->sessionId);
        SPDM_Set16LE(&enc[4], (word16)ctx->reqSeqNum);
        SPDM_Set16LE(&enc[6], recordLen);

        aadSz = 8;
        XMEMCPY(aad, enc, aadSz);
    }

    /* Build IV: BaseIV XOR sequence number (DSP0277) */
    wolfSPDM_BuildIV(iv, ctx->reqDataIv, ctx->reqSeqNum);

    /* AES-GCM encrypt — cascade with single cleanup */
    rc = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (rc == 0) {
        aesInit = 1;
        rc = wc_AesGcmSetKey(&aes, ctx->reqDataKey, WOLFSPDM_AEAD_KEY_SIZE);
    }
    if (rc == 0) {
        rc = wc_AesGcmEncrypt(&aes, &enc[hdrSz], plainBuf, plainBufSz,
            iv, WOLFSPDM_AEAD_IV_SIZE, tag, WOLFSPDM_AEAD_TAG_SIZE, aad, aadSz);
    }
    if (aesInit) {
        wc_AesFree(&aes);
    }

    if (rc == 0) {
        XMEMCPY(&enc[hdrSz + plainBufSz], tag, WOLFSPDM_AEAD_TAG_SIZE);
        *encSz = hdrSz + plainBufSz + WOLFSPDM_AEAD_TAG_SIZE;
        ctx->reqSeqNum++;
        wolfSPDM_DebugPrint(ctx, "Encrypted %u bytes -> %u bytes (seq=%llu)\n",
            plainSz, *encSz, (unsigned long long)(ctx->reqSeqNum - 1));
    }

    wc_ForceZero(plainBuf, sizeof(plainBuf));
    return (rc == 0) ? WOLFSPDM_SUCCESS : WOLFSPDM_E_CRYPTO_FAIL;
}

int wolfSPDM_DecryptInternal(WOLFSPDM_CTX* ctx,
    const byte* enc, word32 encSz,
    byte* plain, word32* plainSz)
{
    Aes aes;
    byte iv[WOLFSPDM_AEAD_IV_SIZE];
    byte aad[16];
    byte decrypted[WOLFSPDM_MAX_MSG_SIZE + 16];
    const byte* ciphertext;
    const byte* tag;
    word32 cipherLen;
    word16 appDataLen;
    word32 hdrSz;
    word32 aadSz;
    int aesInit = 0;
    int ret;
    int rc;

    if (ctx == NULL || enc == NULL || plain == NULL || plainSz == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    /* ----- Transport-specific header parsing ----- */

#if defined(WOLFSPDM_NUVOTON) || defined(WOLFSPDM_NATIONS)
    if (ctx->mode == WOLFSPDM_MODE_NUVOTON ||
        ctx->mode == WOLFSPDM_MODE_NATIONS ||
        ctx->mode == WOLFSPDM_MODE_NATIONS_PSK) {
        word64 rspSeqNum64;
        word32 rspSessionId;
        word16 rspLen;
        hdrSz = 14;
        aadSz = 14;

        if (encSz < hdrSz + WOLFSPDM_AEAD_TAG_SIZE)
            return WOLFSPDM_E_BUFFER_SMALL;

        rspSessionId = SPDM_Get32LE(&enc[0]);
        rspSeqNum64 = SPDM_Get64LE(&enc[4]);
        rspLen = SPDM_Get16LE(&enc[12]);

        if (rspSessionId != ctx->sessionId) {
            wolfSPDM_DebugPrint(ctx, "Session ID mismatch: 0x%08x != 0x%08x\n",
                rspSessionId, ctx->sessionId);
            return WOLFSPDM_E_SESSION_INVALID;
        }
        if (rspSeqNum64 != ctx->rspSeqNum) {
            wolfSPDM_DebugPrint(ctx, "Seq mismatch: %llu != %llu\n",
                (unsigned long long)rspSeqNum64,
                (unsigned long long)ctx->rspSeqNum);
            return WOLFSPDM_E_SEQUENCE;
        }
        if (rspLen < WOLFSPDM_AEAD_TAG_SIZE || encSz < hdrSz + rspLen)
            return WOLFSPDM_E_BUFFER_SMALL;

        cipherLen = (word32)(rspLen - WOLFSPDM_AEAD_TAG_SIZE);
        if (cipherLen > sizeof(decrypted))
            return WOLFSPDM_E_BUFFER_SMALL;

        ciphertext = enc + hdrSz;
        tag = enc + hdrSz + cipherLen;
        XMEMCPY(aad, enc, aadSz);
        wolfSPDM_BuildIV(iv, ctx->rspDataIv, rspSeqNum64);
    } else
#endif
    {
        word32 rspSessionId;
        word16 rspSeqNum, rspLen;
        hdrSz = 8;
        aadSz = 8;

        if (encSz < hdrSz + WOLFSPDM_AEAD_TAG_SIZE)
            return WOLFSPDM_E_BUFFER_SMALL;

        rspSessionId = SPDM_Get32LE(&enc[0]);
        rspSeqNum = SPDM_Get16LE(&enc[4]);
        rspLen = SPDM_Get16LE(&enc[6]);

        if (rspSessionId != ctx->sessionId) {
            wolfSPDM_DebugPrint(ctx, "Session ID mismatch: 0x%08x != 0x%08x\n",
                rspSessionId, ctx->sessionId);
            return WOLFSPDM_E_SESSION_INVALID;
        }
        if ((word64)rspSeqNum != ctx->rspSeqNum) {
            wolfSPDM_DebugPrint(ctx, "Seq mismatch: %u != %llu\n",
                rspSeqNum, (unsigned long long)ctx->rspSeqNum);
            return WOLFSPDM_E_SEQUENCE;
        }
        if (rspLen < WOLFSPDM_AEAD_TAG_SIZE || encSz < (word32)(hdrSz + rspLen))
            return WOLFSPDM_E_BUFFER_SMALL;

        cipherLen = (word32)(rspLen - WOLFSPDM_AEAD_TAG_SIZE);
        if (cipherLen > sizeof(decrypted))
            return WOLFSPDM_E_BUFFER_SMALL;

        ciphertext = enc + hdrSz;
        tag = enc + hdrSz + cipherLen;
        XMEMCPY(aad, enc, aadSz);
        wolfSPDM_BuildIV(iv, ctx->rspDataIv, (word64)rspSeqNum);
    }

    /* ----- AES-GCM decrypt (shared for both transports) ----- */

    ret = WOLFSPDM_E_CRYPTO_FAIL;
    rc = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (rc == 0) {
        aesInit = 1;
        rc = wc_AesGcmSetKey(&aes, ctx->rspDataKey, WOLFSPDM_AEAD_KEY_SIZE);
    }
    if (rc == 0) {
        rc = wc_AesGcmDecrypt(&aes, decrypted, ciphertext, cipherLen,
            iv, WOLFSPDM_AEAD_IV_SIZE, tag, WOLFSPDM_AEAD_TAG_SIZE,
            aad, aadSz);
        if (rc != 0) {
            wolfSPDM_DebugPrint(ctx, "AES-GCM decrypt failed: %d\n", rc);
            ret = WOLFSPDM_E_DECRYPT_FAIL;
        }
    }
    if (aesInit) {
        wc_AesFree(&aes);
    }

    /* ----- Parse decrypted payload ----- */

    if (rc == 0) {
        appDataLen = SPDM_Get16LE(decrypted);
#if defined(WOLFSPDM_NUVOTON) || defined(WOLFSPDM_NATIONS)
        if (ctx->mode == WOLFSPDM_MODE_NUVOTON ||
            ctx->mode == WOLFSPDM_MODE_NATIONS ||
            ctx->mode == WOLFSPDM_MODE_NATIONS_PSK) {
            /* TCG binding: AppDataLen(2) || SPDM msg || RandomData */
            if (cipherLen < (word32)(2 + appDataLen) ||
                *plainSz < appDataLen) {
                ret = WOLFSPDM_E_BUFFER_SMALL;
            } else {
                XMEMCPY(plain, &decrypted[2], appDataLen);
                *plainSz = appDataLen;
                ret = WOLFSPDM_SUCCESS;
            }
        } else
#endif
        {
            /* MCTP: AppDataLen(2) || MCTP(1) || SPDM msg */
            if (appDataLen < 1 || cipherLen < (word32)(2 + appDataLen) ||
                *plainSz < (word32)(appDataLen - 1)) {
                ret = WOLFSPDM_E_BUFFER_SMALL;
            } else {
                XMEMCPY(plain, &decrypted[3], appDataLen - 1);
                *plainSz = appDataLen - 1;
                ret = WOLFSPDM_SUCCESS;
            }
        }
    }

    if (ret == WOLFSPDM_SUCCESS) {
        ctx->rspSeqNum++;
        wolfSPDM_DebugPrint(ctx, "Decrypted %u bytes -> %u bytes\n",
            encSz, *plainSz);
    }

    wc_ForceZero(decrypted, sizeof(decrypted));
    return ret;
}

int wolfSPDM_SecuredExchange(WOLFSPDM_CTX* ctx,
    const byte* cmdPlain, word32 cmdSz,
    byte* rspPlain, word32* rspSz)
{
    byte encBuf[WOLFSPDM_MAX_MSG_SIZE + WOLFSPDM_AEAD_OVERHEAD];
    byte rxBuf[WOLFSPDM_MAX_MSG_SIZE + WOLFSPDM_AEAD_OVERHEAD];
    word32 encSz = sizeof(encBuf);
    word32 rxSz = sizeof(rxBuf);
    int rc;

    if (ctx == NULL || cmdPlain == NULL || rspPlain == NULL || rspSz == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    rc = wolfSPDM_EncryptInternal(ctx, cmdPlain, cmdSz, encBuf, &encSz);
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_SendReceive(ctx, encBuf, encSz, rxBuf, &rxSz);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_DecryptInternal(ctx, rxBuf, rxSz, rspPlain, rspSz);
    }

    return rc;
}
