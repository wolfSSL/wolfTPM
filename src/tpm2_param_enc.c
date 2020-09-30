/* tpm2_param_enc.c
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
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

#include <wolftpm/tpm2_param_enc.h>
#include <wolftpm/tpm2_packet.h>

#ifndef WOLFTPM2_NO_WOLFCRYPT
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
 */

/******************************************************************************/
/* --- Local Functions -- */
/******************************************************************************/

/* This function performs key generation according to Part 1 of the TPM spec
 * and returns the number of bytes generated, which may be zero.
 *
 * 'key' or 'authValue' are used to generate the session key.
 * - either 'key' or 'authValue' must be provided.
 *
 * 'keyStream' points to the buffer storing the generated session key
 * - 'keyStream' can not be NULL.
 *
 * 'sizeInBits' must be no larger than (2^18)-1 = 256K bits (32385 bytes).
 *
 * Note: The "once" parameter is set to allow incremental generation of a large
 * value. If this flag is TRUE, "sizeInBits" is used in the HMAC computation
 * but only one iteration of the KDF is performed. This would be used for
 * XOR obfuscation so that the mask value can be generated in digest-sized
 * chunks rather than having to be generated all at once in an arbitrarily
 * large buffer and then XORed into the result. If "once" is TRUE, then
 * "sizeInBits" must be a multiple of 8.
 *
 * Any error in the processing of this command is considered fatal.
 *
 * Return values:
 *     0    hash algorithm is not supported or is TPM_ALG_NULL
 *    >0    the number of bytes in the 'keyStream' buffer
 *
 */
static int TPM2_KDFa(
    TPM_ALG_ID  hashAlg,    /* IN: hash algorithm used in HMAC */
    TPM2B_DATA  *key,       /* IN: key, can also be used as authValue buffer */
    TPM2B_AUTH  *authValue, /* IN: authValue for unbounded, unsalted session */
    const char  *label,     /* IN: a 0-byte terminated label used in KDF */
    TPM2B_NONCE *contextU,  /* IN: context U */
    TPM2B_NONCE *contextV,  /* IN: context V */
    UINT32      sizeInBits, /* IN: size of generated key in bits */
    BYTE        *keyStream, /* OUT: key buffer */
    UINT32      *counterInc,/* IN/OUT: See Note for incremental operations */
    int         doOnce      /* IN: TRUE if only one iteration is performed */
)
{
#ifndef WOLFTPM2_NO_WOLFCRYPT
    int ret, hashType;
    Hmac hmac;
    word32 counter = 0;
    int hLen, outLen, lLen = 0;
    byte *outStream;
    byte uint32Buf[sizeof(UINT32)];

    if ((key == NULL && authValue == NULL) || keyStream == NULL)
        return BAD_FUNC_ARG;

    if (doOnce != 0 && (sizeInBits & 7) != 0)
        return BAD_FUNC_ARG;

    hashType = TPM2_GetHashType(hashAlg);
    if (hashType == WC_HASH_TYPE_NONE)
        return NOT_COMPILED_IN;

    hLen = TPM2_GetHashDigestSize(hashAlg);
    if (hLen <= 0)
        return NOT_COMPILED_IN;

    ret = wc_HmacInit(&hmac, NULL, INVALID_DEVID);
    if (ret != 0)
        return ret;

    /* setup counter */
    counter = (counterInc != NULL) ? *counterInc : 0;

    /* get label length if provided */
    if (label != NULL)
        lLen = (int)XSTRLEN(label);

    /* generate required bytes */
    outLen = doOnce ? hLen : (((int)sizeInBits + 7) / 8);
    outStream = keyStream;

    /* Do we have unbounded, unsalted session? */
    if (key == NULL) {
        /* Then, use the authValue to gen session key */
        key = (TPM2B_DATA *)authValue;
    }

    for (; outLen > 0; outLen -= hLen) {
        if (hLen > outLen)
            hLen = outLen;

        counter++;

        /* start HMAC */
        ret = wc_HmacSetKey(&hmac, hashType, &key->buffer[0], key->size);
        if (ret != 0)
            break;

        /* add counter */
        TPM2_Packet_U32ToByteArray(counter, uint32Buf);
        ret = wc_HmacUpdate(&hmac, uint32Buf, (word32)sizeof(uint32Buf));
        if (ret != 0)
            break;

        /* add label */
        if (label != NULL) {
            ret = wc_HmacUpdate(&hmac, (byte*)label, lLen);
            if (ret != 0)
                break;
        }

        /* add contextU */
        if (contextU != NULL) {
            ret = wc_HmacUpdate(&hmac, contextU->buffer, contextU->size);
            if (ret != 0)
                break;
        }

        /* add contextV */
        if (contextV != NULL) {
            ret = wc_HmacUpdate(&hmac, contextV->buffer, contextV->size);
            if (ret != 0)
                break;
        }


        /* add size in bits */
        TPM2_Packet_U32ToByteArray(sizeInBits, (byte*)&uint32Buf);
        ret = wc_HmacUpdate(&hmac, uint32Buf, (word32)sizeof(uint32Buf));
        if (ret != 0)
            break;

        /* get result */
        ret = wc_HmacFinal(&hmac, outStream);
        if (ret != 0)
            break;

        outStream = &outStream[hLen];
    }

    wc_HmacFree(&hmac);

    /* mask off bits if not a multiple of byte size */
    if ((sizeInBits % 8) != 0)
        keyStream[0] &= ((1 << (sizeInBits % 8)) - 1);

    /* return counter if provided */
    if (counterInc != NULL)
        *counterInc = counter;

    /* return length rounded up to nearest 8 multiple */
    return ((sizeInBits + 7) / 8);
#else
    (void)hashAlg;
    (void)key;
    (void)authValue;
    (void)label;
    (void)contextU;
    (void)contextV;
    (void)sizeInBits;
    (void)keyStream;
    (void)counterInc;
    (void)doOnce;

    return NOT_COMPILED_IN;
#endif
}


/* Perform XOR encryption over the first parameter of a TPM packet */
static TPM_RC TPM2_ParamEnc_XOR(TPMS_AUTH_COMMAND *session,
                                TPM2B_MAX_BUFFER *encryptedData,
                                BYTE *paramData, UINT32 paramSz)
{
    TPM_RC rc = TPM_RC_FAILURE;
    TPM2B_MAX_BUFFER mask;
    /* authValueKDF used for unbounded, unsalted session */
    TPM2B_AUTH authValueKDF;
    TPM2B_NONCE nonceNewer, nonceOlder;
    UINT32 bits = paramSz * 8;
    UINT32 i, encryptedBytes;

    if (session->auth.size <= sizeof(authValueKDF.buffer)) {
        authValueKDF.size = session->auth.size;
        XMEMCPY(authValueKDF.buffer, session->auth.buffer, authValueKDF.size);
    }
    if (session->nonce.size <= sizeof(nonceNewer.buffer)) {
        nonceNewer.size = session->nonce.size;
        XMEMCPY(nonceNewer.buffer, session->nonce.buffer, nonceNewer.size);
    }
    if (session->nonce.size <= sizeof(nonceOlder.buffer)) {
        nonceOlder.size = nonceNewer.size;
        XMEMCPY(nonceOlder.buffer, nonceNewer.buffer, nonceOlder.size);
    }

    XMEMSET(mask.buffer, 0, sizeof(mask.buffer));

    encryptedBytes = TPM2_KDFa(session->authHash, NULL, &authValueKDF, "XOR",
                               &nonceOlder, &nonceNewer, bits, mask.buffer,
                               NULL, 1);
    if (encryptedBytes == paramSz) {
        for(i = 0; i < paramSz; i++) {
            encryptedData->buffer[i] = paramData[i] ^ mask.buffer[i];
        }
        encryptedData->size = encryptedBytes;
        /* Data size matched and data encryption completed at this point */
        rc = TPM_RC_SUCCESS;
    }
#ifdef WOLFTPM_DEBUG_VERBOSE
    else {
        printf("Encrypted data differs in size = %d\n", encryptedBytes);
        printf("Parameter data original size is = %d\n", paramSz);
    }
#endif

    return rc;
}

/******************************************************************************/
/* --- Public Functions -- */
/******************************************************************************/

/* Returns MAX_SESSION_NUM if no session is found, otherwise session index */
int TPM2_ParamEnc_FindDecryptSession(TPM2_CTX *ctx)
{
    int i;

    for (i=0; i<MAX_SESSION_NUM; i++) {
        if ((ctx->authCmd[i].sessionAttributes & TPMA_SESSION_decrypt) &&
            ctx->authCmd[i].sessionHandle != TPM_RS_PW) {
            break;
        }
    }

    return i;
}

/* Returns MAX_SESSION_NUM if no session is found, otherwise session index */
int TPM2_ParamEnc_FindEncryptSession(TPM2_CTX *ctx)
{
    int i;

    for (i=0; i<MAX_SESSION_NUM; i++) {
        if ((ctx->authCmd[i].sessionAttributes & TPMA_SESSION_encrypt) &&
            ctx->authCmd[i].sessionHandle != TPM_RS_PW) {
            break;
        }
    }

    return i;
}

TPM_RC TPM2_ParamEnc_CmdRequest(TPMS_AUTH_COMMAND *session,
                                TPM2B_MAX_BUFFER *encryptedParameter,
                                BYTE *paramData, UINT32 paramSz)
{
    TPM_RC rc = TPM_RC_FAILURE;

    if (session->symmetric.algorithm == TPM_ALG_XOR) {
        rc = TPM2_ParamEnc_XOR(session, encryptedParameter, paramData, paramSz);
    }
    else {
        /* TODO: Add CFB mode
        rc = TPM2_ParamEnc_CFB_Request(sessionParamEnc, encryptedParameter,
                                       paramData, paramSz);
        */
        rc = TPM_RC_FAILURE;
    }

    return rc;
}

TPM_RC TPM2_ParamEnc_CmdResponse(TPMS_AUTH_COMMAND *session,
                                 TPM2B_MAX_BUFFER *encryptedParameter,
                                 BYTE *paramData, UINT32 paramSz)
{
    TPM_RC rc = TPM_RC_FAILURE;

    if (session->symmetric.algorithm == TPM_ALG_XOR) {
        rc = TPM2_ParamEnc_XOR(session, encryptedParameter, paramData, paramSz);
    }
    else {
        /* TODO: Handling CFB mode for response parameter differs
        rc = TPM2_ParamEnc_CFB_Response(sessionParamEnc, encryptedParameter,
                                        paramData, paramSz);
        */
        rc = TPM_RC_FAILURE;
    }

    return rc;
}
