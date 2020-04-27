/* tpm2_linux.c
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */


#include <wolftpm/tpm2_linux.h>
#include <wolftpm/tpm2_packet.h>
#include <wolftpm/tpm2_wrap.h> /* Needed only for WOLFTPM2_MAX_BUFFER */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>
#include <string.h>


#define TPM2_LINUX_DEV "/dev/tpm0"
#define TPM2_LINUX_DEV_POLL_TIMEOUT -1 /* Infinite time for poll events */
#define TPM2_LINUX_DEV_RSP_SIZE WOLFTPM2_MAX_BUFFER
/* Linux kernels older than v4.20 (before December 2018) do not support
 * partial reads. The only way to receive a complete response is to read
 * the maximum allowed TPM response from the kernel, which is 4K. And most
 * of the ARM systems use older kernels, such as the RPI that uses v4.12
 *
 * The caller knows what the expected outcome of the operation is. Therefore,
 * the response size is limited only by the WOLFTPM2_MAX_BUFFER used to limit
 * the WOLFTPM2_BUFFER in wolfTPM wrappers */


/* Talk to a TPM device exposed by the Linux tpm_tis driver */
int TPM2_LINUX_SendCommand(TPM2_CTX* ctx, byte* cmd, word16 cmdSz)
{
    int rc = TPM_RC_FAILURE;
    int fd, rspSz;
    int rc_poll, nfds= 1; /* Polling single TPM dev file */
    struct pollfd fds;

#ifdef DEBUG_WOLFTPM /* TODO: Change to WOLFTPM_DEBUG_VERBOSE */
    printf("Command size: %d\n", cmdSz);
    TPM2_PrintBin(cmd, cmdSz);
#endif

    fd = open(TPM2_LINUX_DEV, O_RDWR | O_NONBLOCK);
    if (fd > 0) {
        /* Send the TPM command */
        if (write(fd, cmd, cmdSz) == cmdSz) {
            fds.fd = fd;
            fds.events = POLLIN;
            /* Wait for response to be available */
            rc_poll = poll(&fds, nfds, TPM2_LINUX_DEV_POLL_TIMEOUT);
            if (rc_poll > 0 && fds.revents == POLLIN) {
                rspSz = read(fd, cmd, TPM2_LINUX_DEV_RSP_SIZE);
                if (rspSz > 0) {
                    UINT32 tmpSz;
                    XMEMCPY(&tmpSz, &cmd[2], sizeof(UINT32));
                    rspSz = TPM2_Packet_SwapU32(tmpSz);
                    /* Enough bytes for a TPM response? */
                    if (rspSz >= TPM2_HEADER_SIZE) {
                        rc = TPM_RC_SUCCESS;
                    }
                #ifdef DEBUG_WOLFTPM
                    else
                    {
                        printf("Response size is %d bytes, not enough to "
                            "hold TPM response.\n", rspSz);
                    }
                }
                else if (rspSz == 0) {
                    printf("Received EOF instead of TPM response.\n");
                }
                else {
                    printf("Failed to read from TPM device %d, got errno %d"
                        " = %s\n", fd, errno, strerror(errno));
                #endif
                }
            }
        #ifdef DEBUG_WOLFTPM /* TODO: Change to WOLFTPM_DEBUG_TIMEOUT */
            else {
                printf("Failed to get a response from fd %d, got errno %d ="
                    "%s\n", fd, errno, strerror(errno));
            }
        #endif
        }

        close(fd);
    }

#ifdef DEBUG_WOLFTPM /* TODO: Change to WOLFTPM_DEBUG_VERBOSE */
    if (rspSz > 0) {
        printf("Response size: %d\n", rspSz);
        TPM2_PrintBin(cmd, rspSz);
    }
#endif

    (void)ctx;

    return rc;
}
