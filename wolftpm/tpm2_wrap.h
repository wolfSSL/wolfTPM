/* tpm2_wrap.h
 *
 * Copyright (C) 2006-2018 wolfSSL Inc.
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

#ifndef __TPM2_WRAP_H__
#define __TPM2_WRAP_H__


#include <wolftpm/tpm2.h>

typedef struct WOLFTPM2_DEV {
    TPM2_CTX ctx;
    TPMS_AUTH_COMMAND session[MAX_SESSION_NUM];
} WOLFTPM2_DEV;

typedef struct WOLFTPM2_HANDLE {
    WOLFTPM2_DEV*   dev;
    TPM_HANDLE      hndl;
    TPM2B_AUTH      auth;
} WOLFTPM2_HANDLE;

typedef struct WOLFTPM2_SESSION {
    WOLFTPM2_HANDLE handle;
    TPM2B_NONCE     nonceTPM;
} WOLFTPM2_SESSION;

typedef struct WOLFTPM2_KEY {
    WOLFTPM2_HANDLE   handle;
    TPM2B_PUBLIC      pub;
    TPM2B_NAME        name;
} WOLFTPM2_KEY;


#ifndef WOLFTPM2_MAX_BUFFER
    #define WOLFTPM2_MAX_BUFFER 2048
#endif

typedef struct WOLFTPM2_BUFFER {
    int size;
    byte buffer[WOLFTPM2_MAX_BUFFER];
} WOLFTPM2_BUFFER;


/* Wrapper API's to simplify TPM use */

WOLFTPM_API int wolfTPM2_Init(WOLFTPM2_DEV* dev, TPM2HalIoCb ioCb, void* userCtx);
WOLFTPM_API int wolfTPM2_Cleanup(WOLFTPM2_DEV* dev);

WOLFTPM_API int wolfTPM2_GetTpmDevId(WOLFTPM2_DEV* dev);

WOLFTPM_API int wolfTPM2_SetAuth(WOLFTPM2_DEV* dev, int index,
    TPM_HANDLE sessionHandle, const byte* auth, int authSz);

WOLFTPM_API int wolfTPM2_StartSession(WOLFTPM2_DEV* dev,
    WOLFTPM2_SESSION* session, WOLFTPM2_KEY* tpmKey,
    WOLFTPM2_HANDLE* bind, TPM_SE sesType, int useEncrypDecrypt);

WOLFTPM_API int wolfTPM2_CreatePrimaryKey(WOLFTPM2_DEV* dev,
    WOLFTPM2_KEY* key, TPM_HANDLE primaryHandle, TPMT_PUBLIC* publicTemplate,
    const byte* auth, int authSz);
WOLFTPM_API int wolfTPM2_CreateAndLoadKey(WOLFTPM2_DEV* dev,
    WOLFTPM2_KEY* key, WOLFTPM2_HANDLE* parent, TPMT_PUBLIC* publicTemplate,
    const byte* auth, int authSz);
WOLFTPM_API int wolfTPM2_LoadPublicKey(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    const TPM2B_PUBLIC* pub);
WOLFTPM_API int wolfTPM2_LoadRsaPublicKey(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    const byte* rsaPub, word32 rsaPubSz, word32 exponent);
WOLFTPM_API int wolfTPM2_LoadEccPublicKey(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    int curveId, const byte* eccPubX, word32 eccPubXSz,
    const byte* eccPubY, word32 eccPubYSz);
WOLFTPM_API int wolfTPM2_ReadPublicKey(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    const TPM_HANDLE handle);

#ifndef WOLFTPM2_NO_WOLFCRYPT
#ifndef NO_RSA
WOLFTPM_API int wolfTPM2_RsaKey_TpmToWolf(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* tpmKey,
    RsaKey* wolfKey);
WOLFTPM_API int wolfTPM2_RsaKey_WolfToTpm(WOLFTPM2_DEV* dev, RsaKey* wolfKey,
    WOLFTPM2_KEY* tpmKey);
#endif
#ifdef HAVE_ECC
WOLFTPM_API int wolfTPM2_EccKey_TpmToWolf(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* tpmKey,
    ecc_key* wolfKey);
WOLFTPM_API int wolfTPM2_EccKey_WolfToTpm(WOLFTPM2_DEV* dev, ecc_key* wolfKey,
    WOLFTPM2_KEY* tpmKey);
#endif
#endif

WOLFTPM_API int wolfTPM2_SignHash(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    const byte* digest, int digestSz, byte* sig, int* sigSz);
WOLFTPM_API int wolfTPM2_VerifyHash(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    const byte* sig, int sigSz, const byte* digest, int digestSz);
WOLFTPM_API int wolfTPM2_ECDHGen(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* privKey,
    TPM2B_ECC_POINT* pubPoint, byte* out, int* outSz);

WOLFTPM_API int wolfTPM2_RsaEncrypt(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    TPM_ALG_ID padScheme, const byte* msg, int msgSz, byte* out, int* outSz);
WOLFTPM_API int wolfTPM2_RsaDecrypt(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    TPM_ALG_ID padScheme, const byte* in, int inSz, byte* msg, int* msgSz);

WOLFTPM_API int wolfTPM2_ReadPCR(WOLFTPM2_DEV* dev,
    int pcrIndex, int alg, byte* digest, int* p_digest_len);

WOLFTPM_API int wolfTPM2_NVCreate(WOLFTPM2_DEV* dev, TPM_HANDLE authHandle,
    word32 nvIndex, word32 nvAttributes, word32 maxSize, const byte* auth, int authSz);
WOLFTPM_API int wolfTPM2_NVWrite(WOLFTPM2_DEV* dev, TPM_HANDLE authHandle,
    word32 nvIndex, byte* dataBuf, word32 dataSz, word32 offset);
WOLFTPM_API int wolfTPM2_NVRead(WOLFTPM2_DEV* dev, TPM_HANDLE authHandle,
    word32 nvIndex, byte* dataBuf, word32* dataSz, word32 offset);
WOLFTPM_API int wolfTPM2_NVReadPublic(WOLFTPM2_DEV* dev, word32 nvIndex,
    TPMS_NV_PUBLIC* nvPublic);
WOLFTPM_API int wolfTPM2_NVDelete(WOLFTPM2_DEV* dev, TPM_HANDLE authHandle,
    word32 nvIndex);

WOLFTPM_API int wolfTPM2_NVStoreKey(WOLFTPM2_DEV* dev, TPM_HANDLE primaryHandle,
    WOLFTPM2_KEY* key, TPM_HANDLE persistentHandle);
WOLFTPM_API int wolfTPM2_NVDeleteKey(WOLFTPM2_DEV* dev, TPM_HANDLE primaryHandle,
    WOLFTPM2_KEY* key);

WOLFTPM_API struct WC_RNG* wolfTPM2_GetRng(WOLFTPM2_DEV* dev);

WOLFTPM_API int wolfTPM2_GetRandom(WOLFTPM2_DEV* dev, byte* buf, word32 len);

WOLFTPM_API int wolfTPM2_UnloadHandle(WOLFTPM2_DEV* dev, WOLFTPM2_HANDLE* handle);

WOLFTPM_API int wolfTPM2_Clear(WOLFTPM2_DEV* dev);


/* Utility functions */
WOLFTPM_API int wolfTPM2_GetKeyTemplate_RSA(TPMT_PUBLIC* publicTemplate,
    TPMA_OBJECT objectAttributes);
WOLFTPM_API int wolfTPM2_GetKeyTemplate_ECC(TPMT_PUBLIC* publicTemplate,
    TPMA_OBJECT objectAttributes, TPM_ECC_CURVE curve, TPM_ALG_ID sigScheme);
WOLFTPM_API int wolfTPM2_GetKeyTemplate_Symmetric(TPMT_PUBLIC* publicTemplate,
    int keyBits, TPM_ALG_ID algMode, int isSign, int isDecrypt);
WOLFTPM_API int wolfTPM2_GetKeyTemplate_RSA_EK(TPMT_PUBLIC* publicTemplate);
WOLFTPM_API int wolfTPM2_GetKeyTemplate_ECC_EK(TPMT_PUBLIC* publicTemplate);
WOLFTPM_API int wolfTPM2_GetNvAttributesTemplate(TPM_HANDLE auth, word32* nvAttributes);

/* moved to tpm.h native code. macros here for backwards compatibility */
#define wolfTPM2_SetupPCRSel  TPM2_SetupPCRSel
#define wolfTPM2_GetAlgName   TPM2_GetAlgName
#define wolfTPM2_GetRCString  TPM2_GetRCString
#define wolfTPM2_GetCurveSize TPM2_GetCurveSize



#ifdef WOLF_CRYPTO_DEV
typedef struct TpmCryptoDevCtx {
    WOLFTPM2_DEV* dev;
#ifndef NO_RSA
    WOLFTPM2_KEY* rsaKey;  /* RSA */
#endif
#ifdef HAVE_ECC
    WOLFTPM2_KEY* eccKey;  /* ECDSA */
    WOLFTPM2_KEY* ecdhKey; /* ECDH */
#endif
} TpmCryptoDevCtx;

WOLFTPM_API int wolfTPM2_CryptoDevCb(int devId, wc_CryptoInfo* info, void* ctx);
WOLFTPM_API int wolfTPM2_SetCryptoDevCb(WOLFTPM2_DEV* dev, CryptoDevCallbackFunc cb,
    TpmCryptoDevCtx* tpmCtx, int* pDevId);
#endif


#endif /* __TPM2_WRAP_H__ */
