/* tpm2_socket.h
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

#ifndef _TPM2_SOCKET_H_
#define _TPM2_SOCKET_H_

#include <wolftpm/tpm2.h>

#ifdef __cplusplus
    extern "C" {
#endif

/* copy from TpmTcpProtocol.h */
#define TPM_SIGNAL_POWER_ON         1
#define TPM_SIGNAL_POWER_OFF        2
#define TPM_SIGNAL_NV_ON            11

#define TPM_SEND_COMMAND            8
#define TPM_SESSION_END             20
#define TPM_STOP                    21

/* TPM2 IO for using TPM through a Socket connection */
int TPM2_SOCKET_SendCommand(TPM2_CTX* ctx, byte* cmd, word16 cmdSz);
/* int TPM2_SOCKET_PowerOn(TPM2_CTX* ctx); */

#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* _TPM2_SOCKET_H_ */
