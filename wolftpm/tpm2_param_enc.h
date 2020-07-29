/* tpm2_param_enc.h
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifndef _TPM2_PARAM_ENC_H_
#define _TPM2_PARAM_ENC_H_

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_packet.h>

#ifdef __cplusplus
    extern "C" {
#endif

WOLFTPM_LOCAL int TPM2_ParamEnc_FindDecryptSession(TPM2_CTX *ctx);
WOLFTPM_LOCAL int TPM2_ParamEnc_FindEncryptSession(TPM2_CTX *ctx);
/* Perform XOR encryption over the first parameter of a TPM packet */
TPM_RC TPM2_ParamEnc_XOR(TPMS_AUTH_COMMAND *session, TPM2B_MAX_BUFFER *encryptedData,
                         BYTE *paramData, UINT32 paramSz);
/* Perform encryption over the first parameter of a TPM packet */
TPM_RC TPM2_ParamEnc_CmdRequest(TPMS_AUTH_COMMAND *session,
                                TPM2B_MAX_BUFFER *encryptedParameter,
                                BYTE *paramData, UINT32 paramSz);
TPM_RC TPM2_ParamEnc_CmdResponse(TPMS_AUTH_COMMAND *session,
                                 TPM2B_MAX_BUFFER *encryptedParameter,
                                 BYTE *paramData, UINT32 paramSz);
#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* _TPM2_PARAM_ENC_H_ */
