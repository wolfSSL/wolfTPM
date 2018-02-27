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


/* Wrapper API's to simplify TPM use */
WOLFTPM_API int wolfTPM2_ReadPCR(int pcrIndex, int alg, byte* digest, int* digest_len);
WOLFTPM_API int wolfTPM2_UnloadHandle(word32* handle);
WOLFTPM_API int wolfTPM2_NVReadPublic(word32 nvIndex);


WOLFTPM_API int TPM2_GetHashDigestSize(TPMI_ALG_HASH hashAlg);
WOLFTPM_API const char* wolfTPM2_GetAlgName(TPM_ALG_ID alg);
WOLFTPM_API const char* wolfTPM2_GetRCString(TPM_RC rc);
WOLFTPM_API void wolfTPM2_SetupPCRSel(TPML_PCR_SELECTION* pcr, TPM_ALG_ID alg, int pcrIndex);

#ifdef DEBUG_WOLFTPM
WOLFTPM_API void wolfTPM2_PrintBin(const byte* buffer, word32 length);
#else
#define wolfTPM2_PrintBin(b, l)
#endif


#endif /* __TPM2_WRAP_H__ */
