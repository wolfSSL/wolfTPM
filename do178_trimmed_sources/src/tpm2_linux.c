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

#include <wolftpm/tpm2_linux.h>
#include <wolftpm/tpm2_packet.h>
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
            }
        }

        close(fd);
    }


    (void)ctx;

    return rc;
}
