/* tpm2_crypto.h
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

#ifndef _TPM2_CRYPTO_H_
#define _TPM2_CRYPTO_H_

#include <wolftpm/tpm2.h>

#ifdef __cplusplus
    extern "C" {
#endif

/* --- KDF Functions (moved from tpm2_param_enc.h) --- */

/*!
    \ingroup TPM2_Crypto
    \brief HMAC-based Key Derivation Function (raw pointer interface).
    Per TPM 2.0 spec Part 1 Section 11.4.10.2.

    \return keySz number of bytes generated on success
    \return BAD_FUNC_ARG if key is NULL
    \return negative on error

    \param hashAlg hash algorithm to use for HMAC (e.g. TPM_ALG_SHA256)
    \param keyIn HMAC key bytes (may be NULL for empty key)
    \param keyInSz size of keyIn in bytes
    \param label null-terminated label string
    \param contextU context U bytes (may be NULL)
    \param contextUSz size of contextU in bytes
    \param contextV context V bytes (may be NULL)
    \param contextVSz size of contextV in bytes
    \param key output buffer for derived key
    \param keySz desired number of bytes to derive

    \sa TPM2_KDFa
    \sa TPM2_KDFe_ex
*/
WOLFTPM_API int TPM2_KDFa_ex(
    TPM_ALG_ID hashAlg,
    const BYTE *keyIn, UINT32 keyInSz,
    const char *label,
    const BYTE *contextU, UINT32 contextUSz,
    const BYTE *contextV, UINT32 contextVSz,
    BYTE *key, UINT32 keySz
);

/*!
    \ingroup TPM2_Crypto
    \brief HMAC-based Key Derivation Function (TPM2B interface).
    Backward-compatible wrapper around TPM2_KDFa_ex.

    \return keySz number of bytes generated on success
    \return negative on error

    \param hashAlg hash algorithm to use for HMAC
    \param keyIn pointer to TPM2B_DATA with HMAC key (may be NULL)
    \param label null-terminated label string
    \param contextU pointer to TPM2B_NONCE for context U (may be NULL)
    \param contextV pointer to TPM2B_NONCE for context V (may be NULL)
    \param key output buffer for derived key
    \param keySz desired number of bytes to derive

    \sa TPM2_KDFa_ex
*/
WOLFTPM_API int TPM2_KDFa(
    TPM_ALG_ID hashAlg, TPM2B_DATA *keyIn,
    const char *label, TPM2B_NONCE *contextU, TPM2B_NONCE *contextV,
    BYTE *key, UINT32 keySz
);

/*!
    \ingroup TPM2_Crypto
    \brief Hash-based Key Derivation Function for ECDH (raw pointer interface).
    Per TPM 2.0 spec Part 1 Section 11.4.10.3.

    \return keySz number of bytes generated on success
    \return BAD_FUNC_ARG if key or Z is NULL
    \return negative on error

    \param hashAlg hash algorithm (e.g. TPM_ALG_SHA256)
    \param Z shared secret bytes (ECDH x-coordinate)
    \param ZSz size of Z in bytes
    \param label null-terminated label string
    \param partyU party U info bytes (may be NULL)
    \param partyUSz size of partyU in bytes
    \param partyV party V info bytes (may be NULL)
    \param partyVSz size of partyV in bytes
    \param key output buffer for derived key
    \param keySz desired number of bytes to derive

    \sa TPM2_KDFe
    \sa TPM2_KDFa_ex
*/
WOLFTPM_API int TPM2_KDFe_ex(
    TPM_ALG_ID hashAlg,
    const BYTE *Z, UINT32 ZSz,
    const char *label,
    const BYTE *partyU, UINT32 partyUSz,
    const BYTE *partyV, UINT32 partyVSz,
    BYTE *key, UINT32 keySz
);

/*!
    \ingroup TPM2_Crypto
    \brief Hash-based Key Derivation Function for ECDH (TPM2B interface).
    Backward-compatible wrapper around TPM2_KDFe_ex.

    \return keySz number of bytes generated on success
    \return negative on error

    \param hashAlg hash algorithm
    \param Z pointer to TPM2B_DATA with shared secret (may be NULL)
    \param label null-terminated label string
    \param partyU pointer to TPM2B_NONCE for party U (may be NULL)
    \param partyV pointer to TPM2B_NONCE for party V (may be NULL)
    \param key output buffer for derived key
    \param keySz desired number of bytes to derive

    \sa TPM2_KDFe_ex
*/
WOLFTPM_API int TPM2_KDFe(
    TPM_ALG_ID hashAlg, TPM2B_DATA *Z,
    const char *label, TPM2B_NONCE *partyU, TPM2B_NONCE *partyV,
    BYTE *key, UINT32 keySz
);

/* --- Crypto Primitive Wrappers --- */

#ifndef WOLFTPM2_NO_WOLFCRYPT

#if !defined(NO_AES) && defined(WOLFSSL_AES_CFB)
/*!
    \ingroup TPM2_Crypto
    \brief AES-CFB one-shot encrypt (in-place).

    \return 0 on success
    \return negative on error

    \param key AES key bytes
    \param keySz AES key size in bytes (16, 24, or 32)
    \param iv initialization vector (may be NULL for zero IV)
    \param data buffer to encrypt in-place
    \param dataSz size of data in bytes

    \sa TPM2_AesCfbDecrypt
*/
WOLFTPM_API int TPM2_AesCfbEncrypt(
    const byte* key, int keySz,
    const byte* iv,
    byte* data, word32 dataSz);

/*!
    \ingroup TPM2_Crypto
    \brief AES-CFB one-shot decrypt (in-place).

    \return 0 on success
    \return negative on error

    \param key AES key bytes
    \param keySz AES key size in bytes (16, 24, or 32)
    \param iv initialization vector (may be NULL for zero IV)
    \param data buffer to decrypt in-place
    \param dataSz size of data in bytes

    \sa TPM2_AesCfbEncrypt
*/
WOLFTPM_API int TPM2_AesCfbDecrypt(
    const byte* key, int keySz,
    const byte* iv,
    byte* data, word32 dataSz);
#endif /* !NO_AES && WOLFSSL_AES_CFB */

#ifndef NO_HMAC
/*!
    \ingroup TPM2_Crypto
    \brief HMAC one-shot compute. Supports optional second data buffer for
    computing HMAC over concatenated data.

    \return 0 on success
    \return negative on error

    \param hashAlg hash algorithm (e.g. TPM_ALG_SHA256)
    \param key HMAC key bytes
    \param keySz HMAC key size in bytes
    \param data first data buffer
    \param dataSz size of first data buffer
    \param data2 optional second data buffer (NULL to skip)
    \param data2Sz size of second data buffer (0 to skip)
    \param digest output buffer for HMAC digest
    \param digestSz on input: buffer size; on output: actual digest size
        (may be NULL if buffer is known to be large enough)

    \sa TPM2_HmacVerify
*/
WOLFTPM_API int TPM2_HmacCompute(
    TPMI_ALG_HASH hashAlg,
    const byte* key, word32 keySz,
    const byte* data, word32 dataSz,
    const byte* data2, word32 data2Sz,
    byte* digest, word32* digestSz);

/*!
    \ingroup TPM2_Crypto
    \brief HMAC verify (compute + constant-time compare).

    \return 0 on match
    \return TPM_RC_INTEGRITY on mismatch
    \return negative on error

    \param hashAlg hash algorithm (e.g. TPM_ALG_SHA256)
    \param key HMAC key bytes
    \param keySz HMAC key size in bytes
    \param data first data buffer
    \param dataSz size of first data buffer
    \param data2 optional second data buffer (NULL to skip)
    \param data2Sz size of second data buffer (0 to skip)
    \param expected expected HMAC digest to compare against
    \param expectedSz size of expected digest in bytes

    \sa TPM2_HmacCompute
*/
WOLFTPM_API int TPM2_HmacVerify(
    TPMI_ALG_HASH hashAlg,
    const byte* key, word32 keySz,
    const byte* data, word32 dataSz,
    const byte* data2, word32 data2Sz,
    const byte* expected, word32 expectedSz);
#endif /* !NO_HMAC */

/*!
    \ingroup TPM2_Crypto
    \brief Hash one-shot compute.

    \return 0 on success
    \return negative on error

    \param hashAlg hash algorithm (e.g. TPM_ALG_SHA256)
    \param data input data to hash
    \param dataSz size of input data in bytes
    \param digest output buffer for hash digest
    \param digestSz on input: buffer size; on output: actual digest size
        (may be NULL if buffer is known to be large enough)

    \sa TPM2_HmacCompute
*/
WOLFTPM_API int TPM2_HashCompute(
    TPMI_ALG_HASH hashAlg,
    const byte* data, word32 dataSz,
    byte* digest, word32* digestSz);

#endif /* !WOLFTPM2_NO_WOLFCRYPT */

#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* _TPM2_CRYPTO_H_ */
