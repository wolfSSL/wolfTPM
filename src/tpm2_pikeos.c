/* tpm2_pikeos.c
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2_types.h>

#ifdef WOLFTPM_PIKEOS
#include <wolftpm/tpm2_pikeos.h>

/* The PikeOS TPM driver is reached through a file provider that takes a
 * complete TPM command per vm_write and returns the complete response per
 * vm_read. The task must have called vm_init() before the first command. */
#ifndef TPM2_PIKEOS_DEV
    #define TPM2_PIKEOS_DEV "tpm0:dev0"
#endif

int TPM2_PIKEOS_SendCommand(TPM2_CTX* ctx, TPM2_Packet* packet)
{
    P4_e_t e;
    P4_size_t written = 0;
    P4_size_t readSz = 0;

    if (ctx == NULL || packet == NULL) {
        return BAD_FUNC_ARG;
    }

    if (!ctx->pikeosCtx.isOpen) {
        e = vm_open(TPM2_PIKEOS_DEV, VM_O_RD_WR, &ctx->pikeosCtx.fd);
        if (e != P4_E_OK) {
        #ifdef DEBUG_WOLFTPM
            printf("Failed to open %s: %d\n", TPM2_PIKEOS_DEV, (int)e);
        #endif
            return TPM_RC_FAILURE;
        }
        ctx->pikeosCtx.isOpen = 1;
    }

#ifdef WOLFTPM_DEBUG_VERBOSE
    printf("Command size: %d\n", packet->pos);
    TPM2_PrintBin(packet->buf, packet->pos);
#endif

    e = vm_write(&ctx->pikeosCtx.fd, packet->buf, (P4_size_t)packet->pos,
        &written);
    if (e != P4_E_OK || written != (P4_size_t)packet->pos) {
    #ifdef DEBUG_WOLFTPM
        printf("Failed write to %s: %d\n", TPM2_PIKEOS_DEV, (int)e);
    #endif
        return TPM_RC_FAILURE;
    }

    e = vm_read(&ctx->pikeosCtx.fd, packet->buf, (P4_size_t)packet->size,
        &readSz);
    /* The caller parses the TPM_Packet for correctness */
    if (e != P4_E_OK || readSz < TPM2_HEADER_SIZE) {
    #ifdef DEBUG_WOLFTPM
        printf("Failed read from %s: %d (size %d)\n", TPM2_PIKEOS_DEV,
            (int)e, (int)readSz);
    #endif
        return TPM_RC_FAILURE;
    }

#ifdef WOLFTPM_DEBUG_VERBOSE
    printf("Response size: %d\n", (int)readSz);
    TPM2_PrintBin(packet->buf, (int)readSz);
#endif

    return TPM_RC_SUCCESS;
}

int TPM2_PIKEOS_Cleanup(TPM2_CTX* ctx)
{
    int rc = TPM_RC_SUCCESS;

    if (ctx != NULL && ctx->pikeosCtx.isOpen) {
        if (vm_close(&ctx->pikeosCtx.fd) != P4_E_OK) {
            rc = TPM_RC_FAILURE;
        }
        ctx->pikeosCtx.isOpen = 0;
    }

    return rc;
}

#endif /* WOLFTPM_PIKEOS */
