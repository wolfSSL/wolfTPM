/* tpm2_linux.c
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

/* supresses waring for now */
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


#ifndef TPM2_LINUX_DEV
#define TPM2_LINUX_DEV "/dev/tpm0"
#endif

#define TPM2_LINUX_DEV_POLL_TIMEOUT -1 /* Infinite time for poll events */

/* Linux kernels older than v4.20 (before December 2018) do not support
 * partial reads. The only way to receive a complete response is to read
 * the maximum allowed TPM response from the kernel, which is 4K. And most
 * of the ARM systems use older kernels, such as the RPI that uses v4.12
 */

/* Talk to a TPM device exposed by the Linux tpm_tis driver */
int TPM2_LINUX_SendCommand(TPM2_CTX* ctx, TPM2_Packet* packet)
{
    int rc = TPM_RC_FAILURE;
    int fd;
    int rc_poll, nfds = 1; /* Polling single TPM dev file */
    struct pollfd fds;
    size_t rspSz = 0;

#ifdef WOLFTPM_DEBUG_VERBOSE
    printf("Command size: %d\n", packet->pos);
    TPM2_PrintBin(packet->buf, packet->pos);
#endif

    fd = open(TPM2_LINUX_DEV, O_RDWR | O_NONBLOCK);
    if (fd >= 0) {
        /* Send the TPM command */
        if (write(fd, packet->buf, packet->pos) == packet->pos) {
            fds.fd = fd;
            fds.events = POLLIN;
            /* Wait for response to be available */
            rc_poll = poll(&fds, nfds, TPM2_LINUX_DEV_POLL_TIMEOUT);
            if (rc_poll > 0 && fds.revents == POLLIN) {
                rspSz = read(fd, packet->buf, packet->size);
                /* The caller parses the TPM_Packet for correctness */
                if (rspSz >= TPM2_HEADER_SIZE) {
                    /* Enough bytes for a TPM response */
                    rc = TPM_RC_SUCCESS;
                }
                #ifdef DEBUG_WOLFTPM
                else if (rspSz == 0) {
                    printf("Received EOF instead of TPM response.\n");
                }
                else
                {
                    printf("Failed to read from TPM device %d, got errno %d"
                        " = %s\n", fd, errno, strerror(errno));
                }
                #endif
            }
        #ifdef WOLFTPM_DEBUG_VERBOSE
            else {
                printf("Failed to get a response from fd %d, got errno %d ="
                    "%s\n", fd, errno, strerror(errno));
            }
        #endif
        }
        #ifdef WOLFTPM_DEBUG_VERBOSE
        else {
            printf("Failed to send the TPM command to fd %d, got errno %d ="
                "%s\n", fd, errno, strerror(errno));
        }
        #endif

        close(fd);
    }
#ifdef DEBUG_WOLFTPM
    else if (fd == -1 && errno == EACCES) {
        printf("Permission denied. Use sudo or change the user group.\n");
    }
    else {
        perror("Failed to open device");
    }
#endif

#ifdef WOLFTPM_DEBUG_VERBOSE
    if (rspSz > 0) {
        printf("Response size: %d\n", (int)rspSz);
        TPM2_PrintBin(packet->buf, rspSz);
    }
#endif

    (void)ctx;

    return rc;
}
#endif /* __UBOOT__ __linux__ */
#endif /* WOLFTPM_LINUX_DEV */
