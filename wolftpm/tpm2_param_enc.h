/* tpm2_param_enc.h
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

#ifndef _TPM2_PARAM_ENC_H_
#define _TPM2_PARAM_ENC_H_

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_packet.h>
#include <wolftpm/tpm2_crypto.h> /* TPM2_KDFa/KDFe moved here */

#ifdef __cplusplus
    extern "C" {
#endif

/* XOR parameter encryption/decryption (raw pointer interface).
 * XOR is symmetric so encrypt and decrypt are the same operation. */
WOLFTPM_TEST_API int TPM2_ParamEnc_XOR(
    TPMI_ALG_HASH authHash,
    const BYTE *keyIn, UINT32 keyInSz,
    const BYTE *nonceA, UINT32 nonceASz,
    const BYTE *nonceB, UINT32 nonceBSz,
    BYTE *paramData, UINT32 paramSz
);

/* AES-CFB parameter encryption/decryption (raw pointer interface).
 * doEncrypt: 1 = encrypt, 0 = decrypt. */
WOLFTPM_TEST_API int TPM2_ParamEnc_AESCFB(
    TPMI_ALG_HASH authHash, UINT16 keyBits,
    const BYTE *keyIn, UINT32 keyInSz,
    const BYTE *nonceA, UINT32 nonceASz,
    const BYTE *nonceB, UINT32 nonceBSz,
    BYTE *paramData, UINT32 paramSz, int doEncrypt
);

WOLFTPM_TEST_API int TPM2_CalcHmac(TPMI_ALG_HASH authHash, TPM2B_AUTH* auth,
    const TPM2B_DIGEST* hash, const TPM2B_NONCE* nonceNew,
    const TPM2B_NONCE* nonceOld, TPMA_SESSION sessionAttributes,
    TPM2B_AUTH* hmac);
WOLFTPM_LOCAL int TPM2_CalcRpHash(TPMI_ALG_HASH authHash,
    TPM_CC cmdCode, BYTE* param, UINT32 paramSz, TPM2B_DIGEST* hash);
WOLFTPM_LOCAL int TPM2_CalcCpHash(TPMI_ALG_HASH authHash, TPM_CC cmdCode,
    TPM2B_NAME* name1, TPM2B_NAME* name2, TPM2B_NAME* name3,
    BYTE* param, UINT32 paramSz, TPM2B_DIGEST* hash);

/* Perform encryption over the first parameter of a TPM packet */
WOLFTPM_TEST_API TPM_RC TPM2_ParamEnc_CmdRequest(TPM2_AUTH_SESSION *session,
                                BYTE *paramData, UINT32 paramSz);
WOLFTPM_TEST_API TPM_RC TPM2_ParamDec_CmdResponse(TPM2_AUTH_SESSION *session,
                                BYTE *paramData, UINT32 paramSz);

#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* _TPM2_PARAM_ENC_H_ */
