/* tpm2_swtpm.c
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



/**
 * This implements a subset of TPM TCP protocol as described in
 * "TPM-Rev-2.0-Part-4-Supporting-Routines-01.38-code"
 *
 * This is intended for testing with a simulator such as
 * http://ibmswtpm.sourceforge.net/ or
 * https://github.com/stefanberger/swtpm
 *
 * See docs/SWTPM.md
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2_types.h>

#ifdef WOLFTPM_SWTPM
#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_swtpm.h>
#include <wolftpm/tpm2_packet.h>

#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#include <wolftpm/tpm2_socket.h>

#ifndef TPM2_SWTPM_HOST
#define TPM2_SWTPM_HOST         "localhost"
#endif
#ifndef TPM2_SWTPM_PORT
#define TPM2_SWTPM_PORT         "2321"
#endif

static TPM_RC SwTpmTransmit(TPM2_CTX* ctx, const void* buffer, ssize_t bufSz)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    ssize_t wrc = 0;

    if (ctx == NULL || ctx->tcpCtx.fd < 0 || buffer == NULL) {
        return BAD_FUNC_ARG;
    }

    wrc = write(ctx->tcpCtx.fd, buffer, bufSz);
    if (bufSz != wrc) {
        rc = TPM_RC_FAILURE;
    }

#ifdef WOLFTPM_DEBUG_VERBOSE
    if (wrc < 0) {
        printf("Failed to send the TPM command to fd %d, got errno %d ="
               "%s\n", ctx->tcpCtx.fd, errno, strerror(errno));
    }
#endif

    return rc;
}

static TPM_RC SwTpmReceive(TPM2_CTX* ctx, void* buffer, size_t rxSz)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    ssize_t wrc = 0;
    size_t bytes_remaining = rxSz;
    char* ptr = (char*)buffer;

    if (ctx == NULL || ctx->tcpCtx.fd < 0 || buffer == NULL) {
        return BAD_FUNC_ARG;
    }

    while (bytes_remaining > 0) {
        wrc = read(ctx->tcpCtx.fd, ptr, bytes_remaining);
        if (wrc <= 0) {
            #ifdef DEBUG_WOLFTPM
            if (wrc == 0) {
                printf("Failed to read from TPM socket: EOF\n");
            }
            else {
                printf("Failed to read from TPM socket %d, got errno %d"
                       " = %s\n", ctx->tcpCtx.fd, errno, strerror(errno));
            }
            #endif
            rc = TPM_RC_FAILURE;
            break;
        }

        bytes_remaining -= wrc;
        ptr += wrc;

        #ifdef WOLFTPM_DEBUG_VERBOSE
        printf("TPM socket received %zd waiting for %zu more\n",
               wrc, bytes_remaining);
        #endif
    }

    return rc;
}

static TPM_RC SwTpmConnect(TPM2_CTX* ctx, const char* host, const char* port)
{
    TPM_RC rc = TPM_RC_FAILURE;
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int s;
    int fd;

    if (ctx == NULL) {
        return BAD_FUNC_ARG;
    }

    XMEMSET(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    s = getaddrinfo(host, port, &hints, &result);
    if (s != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd == -1)
            continue;

        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == -1) {
            close(fd);
        }
        else {
            break;
        }
    }
    freeaddrinfo(result);

    if (rp != NULL) {
        ctx->tcpCtx.fd = fd;
        rc = TPM_RC_SUCCESS;
    }
    #ifdef DEBUG_WOLFTPM
    else {
        printf("Failed to connect to %s %s\n", host, port);
    }
    #endif

    return rc;
}

static TPM_RC SwTpmDisconnect(TPM2_CTX* ctx)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t tss_cmd;

    if (ctx == NULL || ctx->tcpCtx.fd < 0) {
        return BAD_FUNC_ARG;
    }

    /* end swtpm session */
    tss_cmd = TPM2_Packet_SwapU32(TPM_SESSION_END);
    rc = SwTpmTransmit(ctx, &tss_cmd, sizeof(uint32_t));
    #ifdef WOLFTPM_DEBUG_VERBOSE
    if (rc != TPM_RC_SUCCESS) {
        printf("Failed to transmit SESSION_END\n");
    }
    #endif

    if (0 != close(ctx->tcpCtx.fd)) {
        rc = TPM_RC_FAILURE;

        #ifdef WOLFTPM_DEBUG_VERBOSE
        printf("Failed to close fd %d, got errno %d ="
               "%s\n", ctx->tcpCtx.fd, errno, strerror(errno));
        #endif
    }

    ctx->tcpCtx.fd = -1;

    return rc;
}

/* Talk to a TPM through socket
 * return TPM_RC_SUCCESS on success,
 *        TPM_RC_FAILURE on other errors
 */
int TPM2_SWTPM_SendCommand(TPM2_CTX* ctx, TPM2_Packet* packet)
{
    int rc = TPM_RC_FAILURE;
    int rspSz = 0;
    uint32_t tss_word;

    if (ctx == NULL) {
        return BAD_FUNC_ARG;
    }

    if (ctx->tcpCtx.fd < 0) {
        rc = SwTpmConnect(ctx, TPM2_SWTPM_HOST, TPM2_SWTPM_PORT);
    }

#ifdef WOLFTPM_DEBUG_VERBOSE
    printf("Command size: %d\n", packet->pos);
    TPM2_PrintBin(packet->buf, packet->pos);
#endif

    /* send start */
    tss_word = TPM2_Packet_SwapU32(TPM_SEND_COMMAND);
    if (rc == TPM_RC_SUCCESS) {
        rc = SwTpmTransmit(ctx, &tss_word, sizeof(uint32_t));
    }

    /* locality */
    if (rc == TPM_RC_SUCCESS) {
        rc = SwTpmTransmit(ctx, &ctx->locality, sizeof(uint8_t));
    }

    /* buffer size */
    tss_word = TPM2_Packet_SwapU32(packet->pos);
    if (rc == TPM_RC_SUCCESS) {
        rc = SwTpmTransmit(ctx, &tss_word, sizeof(uint32_t));
    }

    /* Send the TPM command buffer */
    if (rc == TPM_RC_SUCCESS) {
        rc = SwTpmTransmit(ctx, packet->buf, packet->pos);
    }

    /* receive response */
    if (rc == TPM_RC_SUCCESS) {
        rc = SwTpmReceive(ctx, &tss_word, sizeof(uint32_t));
        rspSz = TPM2_Packet_SwapU32(tss_word);
        if (rspSz > packet->size) {
            #ifdef WOLFTPM_DEBUG_VERBOSE
            printf("Response size(%d) larger than command buffer(%d)\n",
                   rspSz, packet->pos);
            #endif
            rc = TPM_RC_FAILURE;
        }
    }

    /* This performs a blocking read and could hang. This means a
     * misbehaving actor on the other end of the socket
     */
    if (rc == TPM_RC_SUCCESS) {
        rc = SwTpmReceive(ctx, packet->buf, rspSz);
    }

    /* receive ack */
    if (rc == TPM_RC_SUCCESS) {
        rc = SwTpmReceive(ctx, &tss_word, sizeof(uint32_t));
        tss_word = TPM2_Packet_SwapU32(tss_word);
        #ifdef WOLFTPM_DEBUG
        if (tss_word != 0) {
            printf("SWTPM ack %d\n", tss_word);
        }
        #endif
    }


#ifdef WOLFTPM_DEBUG_VERBOSE
    if (rspSz > 0) {
        printf("Response size: %d\n", rspSz);
        TPM2_PrintBin(packet->buf, rspSz);
    }
#endif

    if (ctx->tcpCtx.fd >= 0) {
        TPM_RC rc_disconnect = SwTpmDisconnect(ctx);
        if (rc == TPM_RC_SUCCESS) {
            rc = rc_disconnect;
        }
    }

    return rc;
}
#endif /* WOLFTPM_SWTPM */
