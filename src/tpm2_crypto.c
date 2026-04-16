/* tpm2_crypto.c
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

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_crypto.h>
#include <wolftpm/tpm2_packet.h>

#ifndef WOLFTPM2_NO_WOLFCRYPT
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/hash.h>
#endif

/******************************************************************************/
/* --- KDF Functions (moved from tpm2_param_enc.c) --- */
/******************************************************************************/

/* KDFa - HMAC-based Key Derivation Function
 * Per TPM 2.0 spec Part 1 Section 11.4.10.2
 *
 * Generates key material using HMAC with:
 *   counter || label || 0x00 || contextU || contextV || sizeInBits
 *
 * Returns number of bytes generated (keySz) on success, or negative on error.
 */
int TPM2_KDFa_ex(
    TPM_ALG_ID   hashAlg,       /* IN: hash algorithm used in HMAC */
    const BYTE  *keyIn,         /* IN: HMAC key (may be NULL) */
    UINT32       keyInSz,       /* IN: HMAC key size */
    const char  *label,         /* IN: null-terminated label */
    const BYTE  *contextU,      /* IN: context U (may be NULL) */
    UINT32       contextUSz,    /* IN: context U size */
    const BYTE  *contextV,      /* IN: context V (may be NULL) */
    UINT32       contextVSz,    /* IN: context V size */
    BYTE        *key,           /* OUT: derived key buffer */
    UINT32       keySz          /* IN: desired key size in bytes */
)
{
#if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_HMAC)
    int ret;
    int hashType;
    Hmac hmac_ctx;
    word32 counter = 0;
    int hLen, copyLen, lLen = 0;
    byte uint32Buf[sizeof(UINT32)];
    UINT32 sizeInBits;
    UINT32 pos;
    byte hash[WC_MAX_DIGEST_SIZE];

    if (key == NULL || keySz > (0xFFFFFFFFUL / 8)) {
        return BAD_FUNC_ARG;
    }
    sizeInBits = keySz * 8;

    hashType = TPM2_GetHashType(hashAlg);
    if (hashType == (int)WC_HASH_TYPE_NONE) {
        return NOT_COMPILED_IN;
    }

    hLen = TPM2_GetHashDigestSize(hashAlg);
    if (hLen <= 0 || hLen > (int)sizeof(hash)) {
        return NOT_COMPILED_IN;
    }

    if (label != NULL) {
        lLen = (int)XSTRLEN(label) + 1; /* include null terminator */
    }

    ret = wc_HmacInit(&hmac_ctx, NULL, INVALID_DEVID);
    if (ret != 0) {
        return ret;
    }

    for (pos = 0; pos < keySz; pos += hLen) {
        counter++;
        copyLen = hLen;

        /* HMAC key */
        if (keyIn != NULL && keyInSz > 0) {
            ret = wc_HmacSetKey(&hmac_ctx, hashType, keyIn, keyInSz);
        }
        else {
            ret = wc_HmacSetKey(&hmac_ctx, hashType, NULL, 0);
        }
        /* counter (big-endian) */
        if (ret == 0) {
            TPM2_Packet_U32ToByteArray(counter, uint32Buf);
            ret = wc_HmacUpdate(&hmac_ctx, uint32Buf,
                (word32)sizeof(uint32Buf));
        }
        /* label (including null terminator) */
        if (ret == 0 && label != NULL) {
            ret = wc_HmacUpdate(&hmac_ctx, (const byte*)label, lLen);
        }
        /* contextU */
        if (ret == 0 && contextU != NULL && contextUSz > 0) {
            ret = wc_HmacUpdate(&hmac_ctx, contextU, contextUSz);
        }
        /* contextV */
        if (ret == 0 && contextV != NULL && contextVSz > 0) {
            ret = wc_HmacUpdate(&hmac_ctx, contextV, contextVSz);
        }
        /* sizeInBits (big-endian) */
        if (ret == 0) {
            TPM2_Packet_U32ToByteArray(sizeInBits, uint32Buf);
            ret = wc_HmacUpdate(&hmac_ctx, uint32Buf,
                (word32)sizeof(uint32Buf));
        }
        /* finalize */
        if (ret == 0) {
            ret = wc_HmacFinal(&hmac_ctx, hash);
        }
        if (ret != 0) {
            break;
        }

        if ((UINT32)hLen > keySz - pos) {
            copyLen = keySz - pos;
        }
        XMEMCPY(key + pos, hash, copyLen);
    }

    wc_HmacFree(&hmac_ctx);
    TPM2_ForceZero(hash, sizeof(hash));

    if (ret == 0) {
        ret = (int)keySz;
    }
    else {
        /* Zero partial key material on mid-loop hash error */
        TPM2_ForceZero(key, keySz);
    }
    return ret;
#else
    (void)hashAlg; (void)keyIn; (void)keyInSz; (void)label;
    (void)contextU; (void)contextUSz; (void)contextV; (void)contextVSz;
    (void)key; (void)keySz;
    return NOT_COMPILED_IN;
#endif
}

/* KDFe - Hash-based Key Derivation Function (for ECDH salt, etc.)
 * Per TPM 2.0 spec Part 1 Section 11.4.10.3
 *
 * Generates key material using Hash with:
 *   counter || Z || label || 0x00 || partyU || partyV
 *
 * Returns number of bytes generated (keySz) on success, or negative on error.
 */
int TPM2_KDFe_ex(
    TPM_ALG_ID   hashAlg,       /* IN: hash algorithm */
    const BYTE  *Z,             /* IN: shared secret (x-coordinate) */
    UINT32       ZSz,           /* IN: shared secret size */
    const char  *label,         /* IN: null-terminated label */
    const BYTE  *partyU,        /* IN: party U info (may be NULL) */
    UINT32       partyUSz,      /* IN: party U size */
    const BYTE  *partyV,        /* IN: party V info (may be NULL) */
    UINT32       partyVSz,      /* IN: party V size */
    BYTE        *key,           /* OUT: derived key buffer */
    UINT32       keySz          /* IN: desired key size in bytes */
)
{
#ifndef WOLFTPM2_NO_WOLFCRYPT
    int ret;
    int hashTypeInt;
    enum wc_HashType hashType;
    wc_HashAlg hash_ctx;
    int hashInited = 0;
    word32 counter = 0;
    int hLen, copyLen, lLen = 0;
    byte uint32Buf[sizeof(UINT32)];
    UINT32 pos;
    byte hash[WC_MAX_DIGEST_SIZE];

    if (key == NULL || Z == NULL) {
        return BAD_FUNC_ARG;
    }

    hashTypeInt = TPM2_GetHashType(hashAlg);
    if (hashTypeInt == (int)WC_HASH_TYPE_NONE) {
        return NOT_COMPILED_IN;
    }
    hashType = (enum wc_HashType)hashTypeInt;

    hLen = TPM2_GetHashDigestSize(hashAlg);
    if (hLen <= 0 || hLen > (int)sizeof(hash)) {
        return BUFFER_E;
    }

    if (label != NULL) {
        lLen = (int)XSTRLEN(label) + 1; /* include null terminator */
    }

    ret = wc_HashInit(&hash_ctx, hashType);
    if (ret != 0) {
        return ret;
    }
    hashInited = 1;

    for (pos = 0; pos < keySz; pos += hLen) {
        counter++;
        copyLen = hLen;

        /* Reinitialize hash context for each iteration so each block is
         * computed independently: H(counter || Z || label || partyU || partyV) */
        if (pos > 0) {
            wc_HashFree(&hash_ctx, hashType);
            hashInited = 0;
            ret = wc_HashInit(&hash_ctx, hashType);
            if (ret != 0) {
                break;
            }
            hashInited = 1;
        }

        /* counter (big-endian) */
        TPM2_Packet_U32ToByteArray(counter, uint32Buf);
        ret = wc_HashUpdate(&hash_ctx, hashType, uint32Buf,
            (word32)sizeof(uint32Buf));
        /* Z (shared secret) */
        if (ret == 0) {
            ret = wc_HashUpdate(&hash_ctx, hashType, Z, ZSz);
        }
        /* label (including null terminator) */
        if (ret == 0 && label != NULL) {
            ret = wc_HashUpdate(&hash_ctx, hashType, (const byte*)label, lLen);
        }
        /* partyU */
        if (ret == 0 && partyU != NULL && partyUSz > 0) {
            ret = wc_HashUpdate(&hash_ctx, hashType, partyU, partyUSz);
        }
        /* partyV */
        if (ret == 0 && partyV != NULL && partyVSz > 0) {
            ret = wc_HashUpdate(&hash_ctx, hashType, partyV, partyVSz);
        }
        /* finalize */
        if (ret == 0) {
            ret = wc_HashFinal(&hash_ctx, hashType, hash);
        }
        if (ret != 0) {
            break;
        }

        if ((UINT32)hLen > keySz - pos) {
            copyLen = keySz - pos;
        }
        XMEMCPY(key + pos, hash, copyLen);
    }

    if (hashInited) {
        wc_HashFree(&hash_ctx, hashType);
    }
    TPM2_ForceZero(hash, sizeof(hash));

    if (ret == 0) {
        ret = (int)keySz;
    }
    else {
        /* Zero partial key material on mid-loop hash error */
        TPM2_ForceZero(key, keySz);
    }
    return ret;
#else
    (void)hashAlg; (void)Z; (void)ZSz; (void)label;
    (void)partyU; (void)partyUSz; (void)partyV; (void)partyVSz;
    (void)key; (void)keySz;
    return NOT_COMPILED_IN;
#endif
}

/* Backward-compatible KDFa wrapper using TPM2B types */
int TPM2_KDFa(
    TPM_ALG_ID hashAlg, TPM2B_DATA *keyIn,
    const char *label, TPM2B_NONCE *contextU, TPM2B_NONCE *contextV,
    BYTE *key, UINT32 keySz)
{
    return TPM2_KDFa_ex(hashAlg,
        (keyIn != NULL) ? keyIn->buffer : NULL,
        (keyIn != NULL) ? keyIn->size : 0,
        label,
        (contextU != NULL) ? contextU->buffer : NULL,
        (contextU != NULL) ? contextU->size : 0,
        (contextV != NULL) ? contextV->buffer : NULL,
        (contextV != NULL) ? contextV->size : 0,
        key, keySz);
}

/* Backward-compatible KDFe wrapper using TPM2B types */
int TPM2_KDFe(
    TPM_ALG_ID hashAlg, TPM2B_DATA *Z,
    const char *label, TPM2B_NONCE *partyU, TPM2B_NONCE *partyV,
    BYTE *key, UINT32 keySz)
{
    return TPM2_KDFe_ex(hashAlg,
        (Z != NULL) ? Z->buffer : NULL,
        (Z != NULL) ? Z->size : 0,
        label,
        (partyU != NULL) ? partyU->buffer : NULL,
        (partyU != NULL) ? partyU->size : 0,
        (partyV != NULL) ? partyV->buffer : NULL,
        (partyV != NULL) ? partyV->size : 0,
        key, keySz);
}

/******************************************************************************/
/* --- Crypto Primitive Wrappers --- */
/******************************************************************************/

#ifndef WOLFTPM2_NO_WOLFCRYPT

#if !defined(NO_AES) && defined(WOLFSSL_AES_CFB)

int TPM2_AesCfbEncrypt(
    const byte* key, int keySz,
    const byte* iv,
    byte* data, word32 dataSz)
{
    int rc;
    Aes aes;
    byte zeroIV[AES_BLOCK_SIZE];

    if (key == NULL || (data == NULL && dataSz > 0)) {
        return BAD_FUNC_ARG;
    }
    if (keySz != 16 && keySz != 24 && keySz != 32) {
        return BAD_FUNC_ARG;
    }

    if (iv == NULL) {
        XMEMSET(zeroIV, 0, sizeof(zeroIV));
        iv = zeroIV;
    }

    rc = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (rc == 0) {
        rc = wc_AesSetKey(&aes, key, (word32)keySz, iv, AES_ENCRYPTION);
        if (rc == 0) {
            rc = wc_AesCfbEncrypt(&aes, data, data, dataSz);
        }
        wc_AesFree(&aes); /* the free handles zeroizing sensitive data */
    }
    return rc;
}

int TPM2_AesCfbDecrypt(
    const byte* key, int keySz,
    const byte* iv,
    byte* data, word32 dataSz)
{
    int rc;
    Aes aes;
    byte zeroIV[AES_BLOCK_SIZE];

    if (key == NULL || (data == NULL && dataSz > 0)) {
        return BAD_FUNC_ARG;
    }
    if (keySz != 16 && keySz != 24 && keySz != 32) {
        return BAD_FUNC_ARG;
    }

    if (iv == NULL) {
        XMEMSET(zeroIV, 0, sizeof(zeroIV));
        iv = zeroIV;
    }

    rc = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (rc == 0) {
        rc = wc_AesSetKey(&aes, key, (word32)keySz, iv, AES_ENCRYPTION);
        if (rc == 0) {
            rc = wc_AesCfbDecrypt(&aes, data, data, dataSz);
        }
        wc_AesFree(&aes); /* the free handles zeroizing sensitive data */
    }
    return rc;
}

#endif /* !NO_AES && WOLFSSL_AES_CFB */

#ifndef NO_HMAC

int TPM2_HmacCompute(
    TPMI_ALG_HASH hashAlg,
    const byte* key, word32 keySz,
    const byte* data, word32 dataSz,
    const byte* data2, word32 data2Sz,
    byte* digest, word32* digestSz)
{
    int rc;
    Hmac hmac;
    int hashType;
    int dSz;

    if (digest == NULL || (key == NULL && keySz > 0) ||
        (data == NULL && dataSz > 0)) {
        return BAD_FUNC_ARG;
    }

    hashType = TPM2_GetHashType(hashAlg);
    if (hashType == (int)WC_HASH_TYPE_NONE) {
        return NOT_COMPILED_IN;
    }
    dSz = TPM2_GetHashDigestSize(hashAlg);
    if (dSz <= 0) {
        return NOT_COMPILED_IN;
    }
    if (digestSz != NULL && *digestSz < (word32)dSz) {
        return BUFFER_E;
    }

    rc = wc_HmacInit(&hmac, NULL, INVALID_DEVID);
    if (rc == 0) {
        rc = wc_HmacSetKey(&hmac, hashType, key, keySz);
        if (rc == 0) {
            rc = wc_HmacUpdate(&hmac, data, dataSz);
        }
        if (rc == 0 && data2 != NULL && data2Sz > 0) {
            rc = wc_HmacUpdate(&hmac, data2, data2Sz);
        }
        if (rc == 0) {
            rc = wc_HmacFinal(&hmac, digest);
        }
        wc_HmacFree(&hmac);
        /* Wipe residual key material from the stack Hmac object. */
        TPM2_ForceZero(&hmac, sizeof(hmac));
    }
    if (rc == 0 && digestSz != NULL) {
        *digestSz = (word32)dSz;
    }
    return rc;
}

int TPM2_HmacVerify(
    TPMI_ALG_HASH hashAlg,
    const byte* key, word32 keySz,
    const byte* data, word32 dataSz,
    const byte* data2, word32 data2Sz,
    const byte* expected, word32 expectedSz)
{
    int rc;
    byte computed[WC_MAX_DIGEST_SIZE];
    word32 computedSz = (word32)sizeof(computed);

    if (expected == NULL || expectedSz == 0) {
        return BAD_FUNC_ARG;
    }

    rc = TPM2_HmacCompute(hashAlg, key, keySz,
        data, dataSz, data2, data2Sz, computed, &computedSz);
    if (rc == 0) {
        if (expectedSz != computedSz ||
            TPM2_ConstantCompare(computed, expected, computedSz) != 0) {
            rc = TPM_RC_INTEGRITY;
        }
    }
    TPM2_ForceZero(computed, sizeof(computed));
    return rc;
}

#endif /* !NO_HMAC */

int TPM2_HashCompute(
    TPMI_ALG_HASH hashAlg,
    const byte* data, word32 dataSz,
    byte* digest, word32* digestSz)
{
    int rc;
    int hashType;
    int dSz;

    if (digest == NULL || (data == NULL && dataSz > 0)) {
        return BAD_FUNC_ARG;
    }

    hashType = TPM2_GetHashType(hashAlg);
    if (hashType == (int)WC_HASH_TYPE_NONE) {
        return NOT_COMPILED_IN;
    }
    dSz = TPM2_GetHashDigestSize(hashAlg);
    if (dSz <= 0) {
        return NOT_COMPILED_IN;
    }
    if (digestSz != NULL && *digestSz < (word32)dSz) {
        return BUFFER_E;
    }

    rc = wc_Hash((enum wc_HashType)hashType, data, dataSz, digest, (word32)dSz);
    if (rc == 0 && digestSz != NULL) {
        *digestSz = (word32)dSz;
    }
    return rc;
}

#endif /* !WOLFTPM2_NO_WOLFCRYPT */
