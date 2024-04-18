/* tpm2_linux.h
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

#ifndef _TPM2_LINUX_H_
#define _TPM2_LINUX_H_

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_packet.h>

#ifdef __cplusplus
    extern "C" {
#endif

/* TPM2 IO for using TPM through the Linux kernel driver */
WOLFTPM_LOCAL int TPM2_LINUX_SendCommand(TPM2_CTX* ctx, TPM2_Packet* packet);

#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* _TPM2_LINUX_H_ */
