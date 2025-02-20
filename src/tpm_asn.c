/* tpm_asn.c
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
#ifdef HAVE_DO178

/* ASN.1 Constants */
#define ASN_SEQUENCE         0x10
#define ASN_CONSTRUCTED      0x20
#define ASN_CONTEXT_SPECIFIC 0x80
#define ASN_LONG_LENGTH     0x80
#define ASN_INTEGER         0x02
#define ASN_BIT_STRING      0x03
#define ASN_OCTET_STRING    0x04
#define ASN_TAG_NULL        0x05
#define ASN_OBJECT_ID       0x06

#define RSA_BLOCK_TYPE_1    0x01

/* Implementation of ASN.1 functions moved from verify_ek_cert.c */
#ifdef HAVE_DO178
WOLFTPM_API int TPM2_ASN_DecodeTag(const uint8_t* input, int inputSz, 
    int* inOutIdx, int* tag_len, uint8_t tag)
{
    int rc = -1;
    int tag_len_bytes = 1;

    *tag_len = 0;
    if (input[*inOutIdx] == tag) {
        (*inOutIdx)++;
        if (input[*inOutIdx] & ASN_LONG_LENGTH) {
            tag_len_bytes = (int)(input[*inOutIdx] & 0x7F);
            if (tag_len_bytes > 4) {
                return -1;
            }
            (*inOutIdx)++;
        }
        while (tag_len_bytes--) {
            *tag_len = (*tag_len << 8) | input[*inOutIdx];
            (*inOutIdx)++;
        }
        if (*tag_len + *inOutIdx <= inputSz) {
            rc = 0;
        }
    }
    return rc;
}
#endif /* HAVE_DO178 */

#ifdef HAVE_DO178
WOLFTPM_API int TPM2_ASN_RsaDecodeSignature(uint8_t** pInput, int inputSz)
{
    int rc = -1;
    int idx = 0;
    int len;

    if (TPM2_ASN_DecodeTag(*pInput, inputSz, &idx, &len, ASN_SEQUENCE | ASN_CONSTRUCTED) == 0) {
        *pInput += idx;
        rc = len;
    }
    return rc;
}
#endif /* HAVE_DO178 */

#ifdef HAVE_DO178
WOLFTPM_API int TPM2_ASN_DecodeX509Cert(uint8_t* input, int inputSz,
    DecodedX509* x509)
{
    int rc = -1;
    int idx = 0;
    int len;

    if (TPM2_ASN_DecodeTag(input, inputSz, &idx, &len, ASN_SEQUENCE | ASN_CONSTRUCTED) == 0) {
        x509->certBegin = idx;
        x509->cert = input;
        x509->certSz = len;

        /* Skip TBSCertificate */
        idx += len;

        /* Get signature algorithm */
        if (TPM2_ASN_DecodeTag(input, inputSz, &idx, &len, ASN_SEQUENCE | ASN_CONSTRUCTED) == 0) {
            idx += len;

            /* Get signature */
            if (TPM2_ASN_DecodeTag(input, inputSz, &idx, &len, ASN_BIT_STRING) == 0) {
                idx++; /* Skip unused bits octet */
                x509->signature = &input[idx];
                x509->sigSz = len - 1;
                rc = 0;
            }
        }
    }
    return rc;
}
#endif /* HAVE_DO178 */

#ifdef HAVE_DO178
WOLFTPM_API int TPM2_ASN_DecodeRsaPubKey(uint8_t* input, int inputSz,
    TPM2B_PUBLIC* pub)
{
    int rc = -1;
    int idx = 0;
    int len;

    if (TPM2_ASN_DecodeTag(input, inputSz, &idx, &len, ASN_SEQUENCE | ASN_CONSTRUCTED) == 0) {
        /* Skip modulus */
        idx += len;

        /* Get public exponent */
        if (TPM2_ASN_DecodeTag(input, inputSz, &idx, &len, ASN_INTEGER) == 0) {
            pub->publicArea.parameters.rsaDetail.exponent = 0;
            while (len--) {
                pub->publicArea.parameters.rsaDetail.exponent = 
                    (pub->publicArea.parameters.rsaDetail.exponent << 8) | input[idx++];
            }

            /* Get modulus */
            if (TPM2_ASN_DecodeTag(input, inputSz, &idx, &len, ASN_INTEGER) == 0) {
                if (len <= (int)sizeof(pub->publicArea.unique.rsa.buffer)) {
                    pub->publicArea.unique.rsa.size = len;
                    XMEMCPY(pub->publicArea.unique.rsa.buffer, &input[idx], len);
                    rc = 0;
                }
            }
        }
    }
    return rc;
}
#endif /* HAVE_DO178 */

#ifdef HAVE_DO178
WOLFTPM_API int TPM2_ASN_RsaUnpadPkcsv15(uint8_t** pSig, int* sigSz)
{
    int rc = -1;
    uint8_t* sig = *pSig;
    int sz = *sigSz;

    if (sig[0] == RSA_BLOCK_TYPE_1) {
        int i;
        for (i = 1; i < sz && sig[i] == 0xFF; i++);
        if (i < sz && sig[i] == 0) {
            *pSig = &sig[i + 1];
            *sigSz = sz - (i + 1);
            rc = 0;
        }
    }
    return rc;
}
#endif /* HAVE_DO178 */

#endif /* HAVE_DO178 */
#endif /* !WOLFTPM2_NO_WRAPPER */
