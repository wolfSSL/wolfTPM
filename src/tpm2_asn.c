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

WOLFTPM_API int TPM2_ASN_DecodeTag(const uint8_t* input, int inputSz, 
    int* inOutIdx, int* tag_len, uint8_t tag)
{
    int rc = -1;
    int tag_len_bytes = 1;

    *tag_len = 0;
    if (input[*inOutIdx] == tag) {
        (*inOutIdx)++;
        if (input[*inOutIdx] & TPM2_ASN_LONG_LENGTH) {
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

WOLFTPM_API int TPM2_ASN_DecodeX509Cert(uint8_t* input, int inputSz,
    DecodedX509* x509)
{
    int rc;
    int idx = 0;
    int tot_len, cert_len = 0, len, pubkey_len = 0, sig_len = 0;

    rc = TPM2_ASN_DecodeTag(input, inputSz, &idx, &tot_len,
        (TPM2_ASN_SEQUENCE | TPM2_ASN_CONSTRUCTED));
    if (rc == 0) {
        x509->certBegin = idx;
        x509->cert = &input[idx];

        rc = TPM2_ASN_DecodeTag(input, inputSz, &idx, &cert_len,
            (TPM2_ASN_SEQUENCE | TPM2_ASN_CONSTRUCTED));
    }
    if (rc == 0) {
        x509->certSz = cert_len + (idx - x509->certBegin);
        rc = TPM2_ASN_DecodeTag(input, inputSz, &idx, &len,
            (TPM2_ASN_CONTEXT_SPECIFIC | TPM2_ASN_CONSTRUCTED));
    }
    if (rc == 0) {
        if (input[idx] != TPM2_ASN_INTEGER || input[idx] != 1) {
            rc = -1;
        }
    }
    if (rc == 0) {
        idx += len;
        rc = TPM2_ASN_DecodeTag(input, inputSz, &idx, &len, TPM2_ASN_INTEGER);
    }
    if (rc == 0) {
        idx += len;
        rc = TPM2_ASN_DecodeTag(input, inputSz, &idx, &len,
            (TPM2_ASN_SEQUENCE | TPM2_ASN_CONSTRUCTED));
    }
    if (rc == 0) {
        idx += len;
        rc = TPM2_ASN_DecodeTag(input, inputSz, &idx, &len,
            (TPM2_ASN_SEQUENCE | TPM2_ASN_CONSTRUCTED));
    }
    if (rc == 0) {
        idx += len;
        rc = TPM2_ASN_DecodeTag(input, inputSz, &idx, &len,
            (TPM2_ASN_SEQUENCE | TPM2_ASN_CONSTRUCTED));
    }
    if (rc == 0) {
        idx += len;
        rc = TPM2_ASN_DecodeTag(input, inputSz, &idx, &len,
            (TPM2_ASN_SEQUENCE | TPM2_ASN_CONSTRUCTED));
    }
    if (rc == 0) {
        idx += len;
        rc = TPM2_ASN_DecodeTag(input, inputSz, &idx, &len,
            (TPM2_ASN_SEQUENCE | TPM2_ASN_CONSTRUCTED));
    }
    if (rc == 0) {
        rc = TPM2_ASN_DecodeTag(input, inputSz, &idx, &len,
            (TPM2_ASN_SEQUENCE | TPM2_ASN_CONSTRUCTED));
    }
    if (rc == 0) {
        idx += len;
        rc = TPM2_ASN_DecodeTag(input, inputSz, &idx, &pubkey_len,
            TPM2_ASN_BIT_STRING);
    }
    if (rc == 0) {
        if (input[idx] == 0x00) {
            idx++;
            pubkey_len--;
        }
        x509->publicKey = &input[idx];
        x509->pubKeySz = pubkey_len;
    }
    if (rc == 0) {
        idx = x509->certBegin + x509->certSz;
        rc = TPM2_ASN_DecodeTag(input, inputSz, &idx, &len,
            (TPM2_ASN_SEQUENCE | TPM2_ASN_CONSTRUCTED));
    }
    if (rc == 0) {
        rc = TPM2_ASN_DecodeTag(input, inputSz, &idx, &len, TPM2_ASN_OBJECT_ID);
    }
    if (rc == 0) {
        idx += len;
        rc = TPM2_ASN_DecodeTag(input, inputSz, &idx, &len, TPM2_ASN_TAG_NULL);
    }
    if (rc == 0) {
        idx += len;
        rc = TPM2_ASN_DecodeTag(input, inputSz, &idx, &sig_len,
            TPM2_ASN_BIT_STRING);
    }
    if (rc == 0) {
        if (input[idx] == 0x00) {
            idx++;
            sig_len--;
        }
        x509->sigSz = sig_len;
        x509->signature = &input[idx];
    }
    return rc;
}

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
