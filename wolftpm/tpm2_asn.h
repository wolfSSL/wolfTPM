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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_types.h>

#ifndef WOLFTPM2_NO_WRAPPER

#ifdef __cplusplus
    extern "C" {
#endif

#ifndef MAX_CERT_SZ
#define MAX_CERT_SZ 2048
#endif

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
WOLFTPM_API int TPM2_ASN_DecodeTag(const uint8_t* input, int inputSz, int* inOutIdx, int* tag_len, uint8_t tag);
WOLFTPM_API int TPM2_ASN_RsaDecodeSignature(uint8_t** pInput, int inputSz);
WOLFTPM_API int TPM2_ASN_DecodeX509Cert(uint8_t* input, int inputSz, DecodedX509* x509);
WOLFTPM_API int TPM2_ASN_DecodeRsaPubKey(uint8_t* input, int inputSz, TPM2B_PUBLIC* pub);
WOLFTPM_API int TPM2_ASN_RsaUnpadPkcsv15(uint8_t** pSig, int* sigSz);

#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* !WOLFTPM2_NO_WRAPPER */

#endif /* WOLFTPM_TPM2_ASN_H */
