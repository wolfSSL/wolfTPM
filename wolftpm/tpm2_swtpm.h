/* tpm2_swtpm.h
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

#ifndef _TPM2_SWTPM_H_
#define _TPM2_SWTPM_H_

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_packet.h>

#ifdef __cplusplus
    extern "C" {
#endif

/* copy from TpmTcpProtocol.h */
#if 0
#define TPM_SIGNAL_POWER_ON         1
#define TPM_SIGNAL_POWER_OFF        2
#define TPM_SIGNAL_NV_ON            11
#endif

#define TPM_SEND_COMMAND            8
#define TPM_SESSION_END             20
#if 0
#define TPM_STOP                    21
#endif

/* TPM2 IO for using TPM through a Socket connection */
WOLFTPM_LOCAL int TPM2_SWTPM_SendCommand(TPM2_CTX* ctx, TPM2_Packet* packet);

#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* _TPM2_SWTPM_H_ */
