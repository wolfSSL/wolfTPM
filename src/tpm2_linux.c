/* tpm2_linux.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

#ifdef WOLFTPM_LINUX_DEV
#include <wolftpm/tpm2_linux.h>
#include <wolftpm/tpm2_packet.h>

#if defined(__UBOOT__)

#include <config.h>
#include <tpm-common.h>

/* import u-boot function helper to get device */
extern int tcg2_platform_get_tpm2(struct udevice **dev);

/* Use the U-Boot TPM device and TIS layer */
int TPM2_LINUX_SendCommand(TPM2_CTX* ctx, TPM2_Packet* packet)
{
    int rc;
    struct udevice *dev;
    size_t rspSz = 0;

#ifdef WOLFTPM_DEBUG_VERBOSE
    printf("Command size: %d\n", packet->pos);
    TPM2_PrintBin(packet->buf, packet->pos);
#endif

    /* Get the TPM2 U-boot device */
    rc = tcg2_platform_get_tpm2(&dev);
    if (rc != 0 || dev == NULL) {
    #ifdef DEBUG_WOLFTPM
        printf("Failed to find TPM2 U-boot device: %d\n", rc);
    #endif
        rc = TPM_RC_FAILURE;
    }
    if (rc == 0) {
        /* Transfer the device data using tpm_xfer */
        rspSz = packet->size;
        rc = tpm_xfer(dev, packet->buf, packet->pos, packet->buf, &rspSz);
        if (rc != 0) {
        #ifdef DEBUG_WOLFTPM
            printf("tpm_xfer failed with error: %d\n", rc);
        #endif
            rc = TPM_RC_FAILURE;
        }
    }

#ifdef WOLFTPM_DEBUG_VERBOSE
    if (rspSz > 0) {
        printf("Response size: %d\n", (int)rspSz);
        TPM2_PrintBin(packet->buf, rspSz);
    }
#endif

    (void)ctx;

    return rc;
}

#else /* __linux__ */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>
#include <string.h>

/* TPM Device Path Configuration:
 * - /dev/tpm0: TPM raw device (default)
 * - /dev/tpmrm0: TPM resource manager (requires kernel 5.12+)
 *                Enabled with WOLFTPM_USE_TPMRM
 */
#ifndef TPM2_LINUX_DEV
#ifdef WOLFTPM_USE_TPMRM
    #define TPM2_LINUX_DEV "/dev/tpmrm0"
#else
    #define TPM2_LINUX_DEV "/dev/tpm0"
#endif
#endif

#ifndef TPM2_LINUX_DEV_POLL_TIMEOUT
#define TPM2_LINUX_DEV_POLL_TIMEOUT -1 /* Infinite time for poll events */
#endif

/* Linux kernels older than v4.20 (before December 2018) do not support
 * partial reads. The only way to receive a complete response is to read
 * the maximum allowed TPM response from the kernel, which is 4K. And most
 * of the ARM systems use older kernels, such as the RPI that uses v4.12
 */

/* Talk to a TPM device exposed by the Linux tpm_tis driver */
int TPM2_LINUX_SendCommand(TPM2_CTX* ctx, TPM2_Packet* packet)
{
    int rc = TPM_RC_FAILURE;
    int rc_poll, nfds = 1; /* Polling single TPM dev file */
    struct pollfd fds;
    int rspSz = 0;

#ifdef WOLFTPM_DEBUG_VERBOSE
    printf("Command size: %d\n", packet->pos);
    TPM2_PrintBin(packet->buf, packet->pos);
#endif

    if (ctx->fd < 0)
        ctx->fd = open(TPM2_LINUX_DEV, O_RDWR | O_NONBLOCK);
    if (ctx->fd >= 0) {
        /* Send the TPM command */
        if (write(ctx->fd, packet->buf, packet->pos) == packet->pos) {
            fds.fd = ctx->fd;
            fds.events = POLLIN;
            /* Wait for response to be available */
            rc_poll = poll(&fds, nfds, TPM2_LINUX_DEV_POLL_TIMEOUT);
            if (rc_poll > 0 && fds.revents == POLLIN) {
                ssize_t ret = read(ctx->fd, packet->buf, packet->size);
                /* The caller parses the TPM_Packet for correctness */
                if (ret >= TPM2_HEADER_SIZE) {
                    /* Enough bytes for a TPM response */
                    rspSz = (int)ret;
                    rc = TPM_RC_SUCCESS;
                }
                else if (rspSz == 0) {
                #ifdef DEBUG_WOLFTPM
                    printf("Received EOF(0) from %s: errno %d = %s\n",
                        TPM2_LINUX_DEV, errno, strerror(errno));
                #endif
                }
                else {
                #ifdef DEBUG_WOLFTPM
                    printf("Failed to read from %s: errno %d = %s\n",
                        TPM2_LINUX_DEV, errno, strerror(errno));
                #endif
                    rc = TPM_RC_FAILURE;
                }
            }
            else {
            #ifdef DEBUG_WOLFTPM
                printf("Failed poll on %s: errno %d = %s\n",
                    TPM2_LINUX_DEV, errno, strerror(errno));
            #endif
                rc = TPM_RC_FAILURE;
            }
        }
        else {
        #ifdef DEBUG_WOLFTPM
            printf("Failed write to %s: errno %d = %s\n",
                TPM2_LINUX_DEV, errno, strerror(errno));
        #endif
            rc = TPM_RC_FAILURE;
        }
    }
    else if (ctx->fd == -1 && errno == EACCES) {
        printf("Permission denied on %s\n"
            "Use sudo or add tss group to user.\n", TPM2_LINUX_DEV);
    }
    else {
    #ifdef DEBUG_WOLFTPM
        printf("Failed to open %s: errno %d = %s\n",
            TPM2_LINUX_DEV, errno, strerror(errno));
    #endif
    }

#ifdef WOLFTPM_DEBUG_VERBOSE
    if (rspSz > 0) {
        printf("Response size: %d\n", (int)rspSz);
        TPM2_PrintBin(packet->buf, rspSz);
    }
#endif
    return rc;
}
#endif /* __UBOOT__ __linux__ */
#endif /* WOLFTPM_LINUX_DEV */
