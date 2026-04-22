/* tpm2_linux.h
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

#ifndef _TPM2_LINUX_H_
#define _TPM2_LINUX_H_

#if defined(WOLFTPM_LINUX_DEV) || defined(WOLFTPM_LINUX_DEV_AUTODETECT)

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_packet.h>

#ifdef __cplusplus
    extern "C" {
#endif

/* TPM2 IO for using TPM through the Linux kernel driver */
WOLFTPM_LOCAL int TPM2_LINUX_SendCommand(TPM2_CTX* ctx, TPM2_Packet* packet);

#ifdef WOLFTPM_LINUX_DEV_AUTODETECT
/* Try opening /dev/tpmrm0 then /dev/tpm0. Returns TPM_RC_SUCCESS if opened,
 * sets ctx->fd. On EACCES prints permission message and returns FAILURE.
 * Returns TPM_RC_INITIALIZE if device not found (caller should try SPI). */
WOLFTPM_LOCAL int TPM2_LINUX_TryOpen(TPM2_CTX* ctx);

/* Runtime dispatch: uses /dev/tpm0 if ctx->fd >= 0, otherwise TIS/SPI */
WOLFTPM_LOCAL int TPM2_LINUX_AUTODETECT_SendCommand(TPM2_CTX* ctx,
    TPM2_Packet* packet);
#endif

#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* WOLFTPM_LINUX_DEV || WOLFTPM_LINUX_DEV_AUTODETECT */

#endif /* _TPM2_LINUX_H_ */
