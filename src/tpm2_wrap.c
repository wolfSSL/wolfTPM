/* tpm2_wrap.c
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

#include <wolftpm/tpm2_wrap.h>

int wolfTPM_ReadPCR(int pcrIndex, int alg, byte* digest, int* digest_len)
{
    int rc;
    PCR_Read_In pcrReadIn;
    PCR_Read_Out pcrReadOut;

    TPM2_SetupPCRSel(&pcrReadIn.pcrSelectionIn, alg, pcrIndex);
    rc = TPM2_PCR_Read(&pcrReadIn, &pcrReadOut);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_PCR_Read failed %d: %s\n", rc, TPM2_GetRCString(rc));
        return rc;
    }

    *digest_len = (int)pcrReadOut.pcrValues.digests[0].size;
    XMEMCPY(digest, pcrReadOut.pcrValues.digests[0].buffer, *digest_len);

#ifdef DEBUG_WOLFTPM
    printf("TPM2_PCR_Read: Index %d, Digest Sz %d, Update Counter %d\n",
        pcrIndex, *digest_len, (int)pcrReadOut.pcrUpdateCounter);
    TPM2_PrintBin(digest, *digest_len);
#endif

    return rc;
}

int wolfTPM_UnloadHandle(word32* handle)
{
    int rc = TPM_RC_SUCCESS;
    FlushContext_In flushCtxIn;

    if (handle == NULL)
        return TPM_RC_FAILURE;

    if (*handle != TPM_RH_NULL) {
        flushCtxIn.flushHandle = *handle;
        rc = TPM2_FlushContext(&flushCtxIn);
        if (rc != TPM_RC_SUCCESS) {
            printf("TPM2_FlushContext failed %d: %s\n", rc, TPM2_GetRCString(rc));
            return rc;
        }

    #ifdef DEBUG_WOLFTPM
        printf("TPM2_FlushContext: Closed sessionHandle 0x%x\n", *handle);
    #endif

        *handle = TPM_RH_NULL;
    }

    return rc;
}
