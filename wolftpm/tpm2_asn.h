/* tpm2_asn.h
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

#ifndef WOLFTPM_TPM2_ASN_H
#define WOLFTPM_TPM2_ASN_H

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_types.h>

#ifndef WOLFTPM2_NO_ASN

#ifdef __cplusplus
    extern "C" {
#endif

#ifndef MAX_CERT_SZ
#define MAX_CERT_SZ 2048
#endif

/* ASN Error Codes */
#define TPM_RC_ASN_PARSE     (-201)  /* ASN parsing error */
#define TPM_RC_INSUFFICIENT  (-202)  /* ASN insufficient data */
#define TPM_RC_VALUE         (-203)  /* ASN value error (invalid tag) */
#define TPM_RC_BUFFER        (-204)  /* ASN buffer error */

/* ASN.1 Constants */
enum {
    TPM2_ASN_SEQUENCE         = 0x10,
    TPM2_ASN_CONSTRUCTED      = 0x20,
    TPM2_ASN_CONTEXT_SPECIFIC = 0x80,
    TPM2_ASN_LONG_LENGTH      = 0x80,
    TPM2_ASN_INTEGER          = 0x02,
    TPM2_ASN_BIT_STRING       = 0x03,
    TPM2_ASN_OCTET_STRING     = 0x04,
    TPM2_ASN_TAG_NULL         = 0x05,
    TPM2_ASN_OBJECT_ID        = 0x06
};

#if defined(WOLFTPM2_NO_WOLFCRYPT) || defined(NO_RSA)
#define RSA_BLOCK_TYPE_1 1
#define RSA_BLOCK_TYPE_2 2
#endif

/* ASN.1 Decoder Types */
typedef struct DecodedX509 {
    word32 certBegin;
    byte*  cert;                /* pointer to start of cert */
    word32 certSz;
    byte*  publicKey;           /* pointer to public key */
    word32 pubKeySz;
    byte*  signature;           /* pointer to signature */
    word32 sigSz;              /* length of signature */
} DecodedX509;

/* ASN.1 Decoder Functions */
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
                           word32 maxIdx);
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
                           word32 maxIdx, int check);
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
WOLFTPM_API int TPM2_ASN_DecodeTag(const uint8_t* input, int inputSz, int* inOutIdx, int* tag_len, uint8_t tag);
/*!
    \ingroup ASN
    \brief Decodes RSA signature from ASN.1 format
    \param pInput Pointer to buffer containing ASN.1 encoded RSA signature
    \param inputSz Size of input buffer
    \return Size of decoded signature on success, TPM_RC_VALUE on invalid input, TPM_RC_INSUFFICIENT on buffer error
*/
WOLFTPM_API int TPM2_ASN_RsaDecodeSignature(uint8_t** pInput, int inputSz);
/*!
    \brief Decodes an X.509 certificate
    \param input Buffer containing ASN.1 encoded X.509 certificate
    \param inputSz Size of input buffer
    \param x509 Structure to store decoded certificate data
    \return 0 on success, TPM_RC_VALUE on invalid input, TPM_RC_INSUFFICIENT on buffer error
*/
WOLFTPM_API int TPM2_ASN_DecodeX509Cert(uint8_t* input, int inputSz, DecodedX509* x509);
/*!
    \ingroup ASN
    \brief Decodes RSA public key from ASN.1 format into TPM2B_PUBLIC structure
    \param input Buffer containing ASN.1 encoded RSA public key
    \param inputSz Size of input buffer
    \param pub TPM2B_PUBLIC structure to store decoded key
    \return 0 on success, TPM_RC_VALUE on invalid input, TPM_RC_INSUFFICIENT on buffer error
*/
WOLFTPM_API int TPM2_ASN_DecodeRsaPubKey(uint8_t* input, int inputSz, TPM2B_PUBLIC* pub);
/*!
    \ingroup ASN
    \brief Removes PKCS#1 v1.5 padding from RSA signature
    \param pSig Pointer to buffer containing padded signature, updated to point to unpadded data
    \param sigSz Size of signature buffer, updated with unpadded size
    \return 0 on success, TPM_RC_VALUE on invalid padding
*/
WOLFTPM_API int TPM2_ASN_RsaUnpadPkcsv15(uint8_t** pSig, int* sigSz);

#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* !WOLFTPM2_NO_ASN */
#endif /* WOLFTPM_TPM2_ASN_H */
