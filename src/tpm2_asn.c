/* tpm2_asn.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfTPM.
 *
 * wolfTPM is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
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

#include <wolftpm/tpm2_wrap.h>
#include <wolftpm/tpm2_asn.h>

#ifndef WOLFTPM2_NO_WRAPPER

/*!
    \ingroup ASN
    \brief Decodes ASN.1 length with optional length checking
    \param input Buffer containing ASN.1 data
    \param inOutIdx Current position in buffer, updated to new position
    \param len Decoded length value
    \param maxIdx Maximum allowed index in buffer
    \param check Flag to enable length validation
    \return Length on success, TPM_RC_INSUFFICIENT on buffer error
*/
WOLFTPM_API int TPM2_ASN_GetLength_ex(const uint8_t* input, word32* inOutIdx, int* len,
                           word32 maxIdx, int check)
{
    int     length = 0;
    word32  idx = *inOutIdx;
    byte    b;

    *len = 0;    /* default length */

    if ((idx + 1) > maxIdx) {
        return TPM_RC_INSUFFICIENT;
    }

    b = input[idx++];
    if (b >= TPM2_ASN_LONG_LENGTH) {
        word32 bytes = b & 0x7F;
        if ((idx + bytes) > maxIdx) {
            return TPM_RC_INSUFFICIENT;
        }
        while (bytes--) {
            b = input[idx++];
            length = (length << 8) | b;
        }
    }
    else
        length = b;

    if (check && (idx + length) > maxIdx) {
        return TPM_RC_INSUFFICIENT;
    }

    *inOutIdx = idx;
    if (length > 0)
        *len = length;

    return length;
}

/*!
    \ingroup ASN
    \brief Decodes ASN.1 length with length checking enabled
    \param input Buffer containing ASN.1 data
    \param inOutIdx Current position in buffer, updated to new position
    \param len Decoded length value
    \param maxIdx Maximum allowed index in buffer
    \return Length on success, TPM_RC_INSUFFICIENT on buffer error
*/
WOLFTPM_API int TPM2_ASN_GetLength(const uint8_t* input, word32* inOutIdx, int* len,
                           word32 maxIdx)
{
    return TPM2_ASN_GetLength_ex(input, inOutIdx, len, maxIdx, 1);
}

/*!
    \ingroup ASN
    \brief Decodes ASN.1 tag and length
    \param input Buffer containing ASN.1 data
    \param tag Expected ASN.1 tag value
    \param inOutIdx Current position in buffer, updated to new position
    \param len Decoded length value
    \param maxIdx Maximum allowed index in buffer
    \return Length on success, TPM_RC_VALUE on tag mismatch, TPM_RC_INSUFFICIENT on buffer error
*/
static int TPM2_ASN_GetHeader(const uint8_t* input, byte tag, word32* inOutIdx, int* len,
                        word32 maxIdx)
{
    word32 idx = *inOutIdx;
    byte   b;
    int    length;

    if ((idx + 1) > maxIdx)
        return TPM_RC_INSUFFICIENT;

    b = input[idx++];
    if (b != tag)
        return TPM_RC_VALUE;

    if (TPM2_ASN_GetLength(input, &idx, &length, maxIdx) < 0)
        return TPM_RC_VALUE;

    *len      = length;
    *inOutIdx = idx;
    return length;
}

/*!
    \ingroup ASN
    \brief Decodes ASN.1 tag and validates length
    \param input Buffer containing ASN.1 data
    \param inputSz Size of input buffer
    \param inOutIdx Current position in buffer, updated to new position
    \param tag_len Decoded length value
    \param tag Expected ASN.1 tag value
    \return 0 on success, TPM_RC_INSUFFICIENT on buffer error, TPM_RC_VALUE on tag mismatch
*/
WOLFTPM_API int TPM2_ASN_DecodeTag(const uint8_t* input, int inputSz, 
    int* inOutIdx, int* tag_len, uint8_t tag)
{
    word32 idx = *inOutIdx;
    int rc = TPM2_ASN_GetHeader(input, tag, &idx, tag_len, inputSz);
    if (rc >= 0) {
        *inOutIdx = idx;
        rc = 0;
    }
    return rc;
}

/*!
    \ingroup ASN
    \brief Decodes RSA signature from ASN.1 format
    \param pInput Pointer to buffer containing ASN.1 encoded RSA signature
    \param inputSz Size of input buffer
    \return Size of decoded signature on success, TPM_RC_VALUE on invalid input, TPM_RC_INSUFFICIENT on buffer error
*/
WOLFTPM_API int TPM2_ASN_RsaDecodeSignature(uint8_t** pInput, int inputSz)
{
    int rc;
    uint8_t* input = *pInput;
    int idx = 0;
    int tot_len, algo_len, digest_len = 0;

    rc = TPM2_ASN_DecodeTag(input, inputSz, &idx, &tot_len,
        (TPM2_ASN_SEQUENCE | TPM2_ASN_CONSTRUCTED));
    if (rc == 0) {
        rc = TPM2_ASN_DecodeTag(input, inputSz, &idx, &algo_len,
            (TPM2_ASN_SEQUENCE | TPM2_ASN_CONSTRUCTED));
    }
    if (rc == 0) {
        idx += algo_len;
        rc = TPM2_ASN_DecodeTag(input, inputSz, &idx, &digest_len, TPM2_ASN_OCTET_STRING);
    }
    if (rc == 0) {
        *pInput = &input[idx];
        rc = digest_len;
    }
    return rc;
}

/*!
    \brief Decodes an X.509 certificate
    \param input Buffer containing ASN.1 encoded X.509 certificate
    \param inputSz Size of input buffer
    \param x509 Structure to store decoded certificate data
    \return 0 on success, TPM_RC_VALUE on invalid input, TPM_RC_INSUFFICIENT on buffer error
*/
WOLFTPM_API int TPM2_ASN_DecodeX509Cert(uint8_t* input, int inputSz,
    DecodedX509* x509)
{
    int rc;
    word32 idx = 0;
    int tot_len, cert_len = 0, len, pubkey_len = 0, sig_len = 0;

    if (input == NULL || x509 == NULL)
        return TPM_RC_VALUE;

    /* Decode outer SEQUENCE */
    rc = TPM2_ASN_GetHeader(input, TPM2_ASN_SEQUENCE | TPM2_ASN_CONSTRUCTED,
                           &idx, &tot_len, inputSz);
    if (rc < 0)
        return rc;

    /* Store certificate location */
    x509->certBegin = idx;
    x509->cert = &input[idx];

    /* Decode certificate SEQUENCE */
    rc = TPM2_ASN_GetHeader(input, TPM2_ASN_SEQUENCE | TPM2_ASN_CONSTRUCTED,
                           &idx, &cert_len, inputSz);
    if (rc < 0)
        return rc;

    x509->certSz = cert_len + (idx - x509->certBegin);

    /* Decode version */
    rc = TPM2_ASN_GetHeader(input, TPM2_ASN_CONTEXT_SPECIFIC | TPM2_ASN_CONSTRUCTED,
                           &idx, &len, inputSz);
    if (rc < 0)
        return rc;

    if (input[idx] != TPM2_ASN_INTEGER || input[idx] != 1)
        return TPM_RC_VALUE;

    idx += len;

    /* Skip serial number */
    rc = TPM2_ASN_GetHeader(input, TPM2_ASN_INTEGER, &idx, &len, inputSz);
    if (rc < 0)
        return rc;
    idx += len;

    /* Skip algorithm identifier */
    rc = TPM2_ASN_GetHeader(input, TPM2_ASN_SEQUENCE | TPM2_ASN_CONSTRUCTED,
                           &idx, &len, inputSz);
    if (rc < 0)
        return rc;
    idx += len;

    /* Skip issuer */
    rc = TPM2_ASN_GetHeader(input, TPM2_ASN_SEQUENCE | TPM2_ASN_CONSTRUCTED,
                           &idx, &len, inputSz);
    if (rc < 0)
        return rc;
    idx += len;

    /* Skip validity */
    rc = TPM2_ASN_GetHeader(input, TPM2_ASN_SEQUENCE | TPM2_ASN_CONSTRUCTED,
                           &idx, &len, inputSz);
    if (rc < 0)
        return rc;
    idx += len;

    /* Skip subject */
    rc = TPM2_ASN_GetHeader(input, TPM2_ASN_SEQUENCE | TPM2_ASN_CONSTRUCTED,
                           &idx, &len, inputSz);
    if (rc < 0)
        return rc;
    idx += len;

    /* Skip subject public key info */
    rc = TPM2_ASN_GetHeader(input, TPM2_ASN_SEQUENCE | TPM2_ASN_CONSTRUCTED,
                           &idx, &len, inputSz);
    if (rc < 0)
        return rc;
    idx += len;

    /* Get public key */
    rc = TPM2_ASN_GetHeader(input, TPM2_ASN_BIT_STRING, &idx, &pubkey_len, inputSz);
    if (rc < 0)
        return rc;

    if (input[idx] == 0x00) {
        idx++;
        pubkey_len--;
    }
    x509->publicKey = &input[idx];
    x509->pubKeySz = pubkey_len;

    /* Get signature algorithm */
    idx = x509->certBegin + x509->certSz;
    rc = TPM2_ASN_GetHeader(input, TPM2_ASN_SEQUENCE | TPM2_ASN_CONSTRUCTED,
                           &idx, &len, inputSz);
    if (rc < 0)
        return rc;

    rc = TPM2_ASN_GetHeader(input, TPM2_ASN_OBJECT_ID, &idx, &len, inputSz);
    if (rc < 0)
        return rc;
    idx += len;

    rc = TPM2_ASN_GetHeader(input, TPM2_ASN_TAG_NULL, &idx, &len, inputSz);
    if (rc < 0)
        return rc;
    idx += len;

    /* Get signature */
    rc = TPM2_ASN_GetHeader(input, TPM2_ASN_BIT_STRING, &idx, &sig_len, inputSz);
    if (rc < 0)
        return rc;

    if (input[idx] == 0x00) {
        idx++;
        sig_len--;
    }
    x509->sigSz = sig_len;
    x509->signature = &input[idx];

    return TPM_RC_SUCCESS;
}

/*!
    \ingroup ASN
    \brief Decodes RSA public key from ASN.1 format into TPM2B_PUBLIC structure
    \param input Buffer containing ASN.1 encoded RSA public key
    \param inputSz Size of input buffer
    \param pub TPM2B_PUBLIC structure to store decoded key
    \return 0 on success, TPM_RC_VALUE on invalid input, TPM_RC_INSUFFICIENT on buffer error
*/
WOLFTPM_API int TPM2_ASN_DecodeRsaPubKey(uint8_t* input, int inputSz,
    TPM2B_PUBLIC* pub)
{
    int rc;
    int idx = 0;
    int tot_len, mod_len = 0, exp_len = 0;

    rc = TPM2_ASN_DecodeTag(input, inputSz, &idx, &tot_len,
        (TPM2_ASN_SEQUENCE | TPM2_ASN_CONSTRUCTED));
    if (rc == 0) {
        rc = TPM2_ASN_DecodeTag(input, inputSz, &idx, &mod_len, TPM2_ASN_INTEGER);
    }
    if (rc == 0) {
        if (input[idx] == 0x00) {
            idx++;
            mod_len--;
        }
        if (mod_len > (int)sizeof(pub->publicArea.unique.rsa.buffer)) {
            rc = -1;
        }
    }
    if (rc == 0) {
        pub->publicArea.parameters.rsaDetail.keyBits = mod_len * 8;
        pub->publicArea.unique.rsa.size = mod_len;
        XMEMCPY(pub->publicArea.unique.rsa.buffer, &input[idx], mod_len);
    }
    if (rc == 0) {
        idx += mod_len;
        rc = TPM2_ASN_DecodeTag(input, inputSz, &idx, &exp_len, TPM2_ASN_INTEGER);
        if (input[idx] == 0x00) {
            idx++;
            exp_len--;
        }
        if (exp_len > (int)sizeof(pub->publicArea.parameters.rsaDetail.exponent)) {
            rc = -1;
        }
    }
    if (rc == 0) {
        XMEMCPY(&pub->publicArea.parameters.rsaDetail.exponent, &input[idx],
            exp_len);
    }
    return rc;
}

/*!
    \ingroup ASN
    \brief Removes PKCS#1 v1.5 padding from RSA signature
    \param pSig Pointer to buffer containing padded signature, updated to point to unpadded data
    \param sigSz Size of signature buffer, updated with unpadded size
    \return 0 on success, TPM_RC_VALUE on invalid padding
*/
WOLFTPM_API int TPM2_ASN_RsaUnpadPkcsv15(uint8_t** pSig, int* sigSz)
{
    int rc = -1;
    uint8_t* sig = *pSig;
    int idx = 0;

    if (sig[idx++] == 0x00 && sig[idx++] == 0x01) {
        while (idx < *sigSz) {
            if (sig[idx] != 0xFF)
                break;
            idx++;
        }
        if (sig[idx++] == 0x00) {
            rc = 0;
            *pSig = &sig[idx];
            *sigSz -= idx;
        }
    }
    return rc;
}

#endif /* !WOLFTPM2_NO_WRAPPER */
