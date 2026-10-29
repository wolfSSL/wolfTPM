/* tpm2_optee.h
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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

#ifndef _TPM2_OPTEE_H_
#define _TPM2_OPTEE_H_

#ifdef WOLFTPM_OPTEE

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_packet.h>
#include <wolftpm/fwtpm/fwtpm_optee.h>

#ifdef __cplusplus
    extern "C" {
#endif

/* TEEC_UUID initializer for the trusted application this client opens, built
 * from the single definition in fwtpm_optee.h. See the note there before
 * overriding it: the same UUID has to appear in the trusted application and
 * in its filename too. */
#ifndef WOLFTPM_OPTEE_TA_UUID
#define WOLFTPM_OPTEE_TA_UUID       \
    { WOLFTPM_OPTEE_TA_UUID_P1,     \
      WOLFTPM_OPTEE_TA_UUID_P2,     \
      WOLFTPM_OPTEE_TA_UUID_P3,     \
      WOLFTPM_OPTEE_TA_UUID_P4 }
#endif

/* Send one whole TPM command to the trusted application and read back the
 * response. One TEEC_InvokeCommand maps onto one FWTPM_ProcessCommand, so no
 * TIS register emulation and one world switch per command rather than per
 * register access. */
WOLFTPM_LOCAL int TPM2_OPTEE_SendCommand(TPM2_CTX* ctx, TPM2_Packet* packet);

/* Release the TEE session, context and shared memory during final TPM
 * context cleanup. Idempotent. */
WOLFTPM_LOCAL void TPM2_OpteeClose(TPM2_CTX* ctx);

#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* WOLFTPM_OPTEE */

#endif /* _TPM2_OPTEE_H_ */
