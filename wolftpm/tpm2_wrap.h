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

typedef struct WOLFTPM2_HANDLE {
    TPM_HANDLE      handle;
    TPM2B_AUTH      auth;
    TPMT_SYM_DEF    symmetric; /* used for parameter encrypt/decrypt */
} WOLFTPM2_HANDLE;

typedef struct WOLFTPM2_SESSION {
    WOLFTPM2_HANDLE handle;
    TPM2B_NONCE     nonceTPM;
} WOLFTPM2_SESSION;

typedef struct WOLFTPM2_KEY {
    WOLFTPM2_HANDLE handle;
    TPM2B_PRIVATE   private;
    TPM2B_PUBLIC    public;
    TPM2B_NAME      name;
} WOLFTPM2_KEY;


/* Wrapper API's to simplify TPM use */

WOLFTPM_API int wolfTPM2_GetKeyTemplate_RSA(TPMT_PUBLIC* publicTemplate, TPMA_OBJECT objectAttributes);
WOLFTPM_API int wolfTPM2_GetKeyTemplate_ECC(TPMT_PUBLIC* publicTemplate, TPMA_OBJECT objectAttributes,
    TPM_ECC_CURVE curve);

WOLFTPM_API int wolfTPM2_StartSession(WOLFTPM2_SESSION* session, WOLFTPM2_KEY* tpmKey,
    WOLFTPM2_HANDLE* bind, TPM_SE sesType, int useEncrypDecrypt);
WOLFTPM_API int wolfTPM2_CreatePrimaryKey(WOLFTPM2_KEY* key, TPM_HANDLE primaryHandle,
    TPMT_PUBLIC* publicTemplate);
WOLFTPM_API int wolfTPM2_CreateAndLoadKey(WOLFTPM2_KEY* key, WOLFTPM2_HANDLE* parent,
    TPMT_PUBLIC* publicTemplate, const byte* auth, int authSz);

WOLFTPM_API int wolfTPM2_ReadPCR(int pcrIndex, int alg, byte* digest, int* digest_len);
WOLFTPM_API void wolfTPM2_SetupPCRSel(TPML_PCR_SELECTION* pcr, TPM_ALG_ID alg, int pcrIndex);

WOLFTPM_API int wolfTPM2_NVReadPublic(word32 nvIndex);

WOLFTPM_API const char* wolfTPM2_GetAlgName(TPM_ALG_ID alg);
WOLFTPM_API const char* wolfTPM2_GetRCString(TPM_RC rc);

WOLFTPM_API int wolfTPM2_UnloadHandle(word32* handle);


#endif /* __TPM2_WRAP_H__ */
