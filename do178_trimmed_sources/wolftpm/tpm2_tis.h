/* tpm2_tis.h
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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

#ifndef __TPM2_TIS_H__
#define __TPM2_TIS_H__

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_packet.h>

#ifdef __cplusplus
    extern "C" {
#endif

/* The default locality to use */
#ifndef WOLFTPM_LOCALITY_DEFAULT
#define WOLFTPM_LOCALITY_DEFAULT 0
#endif

#define TPM_TIS_READ       0x80
#define TPM_TIS_WRITE      0x00

#define TPM_TIS_HEADER_SZ  4

#define TPM_TIS_READY_MASK 0x01

/* Typically only 0-2 wait states are required */
#ifndef TPM_TIS_MAX_WAIT
#define TPM_TIS_MAX_WAIT   3
#endif

WOLFTPM_LOCAL int TPM2_TIS_GetBurstCount(TPM2_CTX* ctx, word16* burstCount);
WOLFTPM_LOCAL int TPM2_TIS_SendCommand(TPM2_CTX* ctx, TPM2_Packet* packet);
WOLFTPM_LOCAL int TPM2_TIS_Ready(TPM2_CTX* ctx);
WOLFTPM_LOCAL int TPM2_TIS_WaitForStatus(TPM2_CTX* ctx, byte status, byte status_mask);
WOLFTPM_LOCAL int TPM2_TIS_Status(TPM2_CTX* ctx, byte* status);
WOLFTPM_LOCAL int TPM2_TIS_GetInfo(TPM2_CTX* ctx);
WOLFTPM_LOCAL int TPM2_TIS_RequestLocality(TPM2_CTX* ctx, int timeout);
WOLFTPM_LOCAL int TPM2_TIS_CheckLocality(TPM2_CTX* ctx, int locality, byte* access);
WOLFTPM_LOCAL int TPM2_TIS_StartupWait(TPM2_CTX* ctx, int timeout);
WOLFTPM_LOCAL int TPM2_TIS_Write(TPM2_CTX* ctx, word32 addr, const byte* value, word32 len);
WOLFTPM_LOCAL int TPM2_TIS_Read(TPM2_CTX* ctx, word32 addr, byte* result, word32 len);

#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* __TPM2_TIS_H__ */
