/* tpm2_swtpm.c
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

#ifdef WOLFTPM_ZEPHYR
#include <zephyr/posix/unistd.h>
#include <zephyr/net/socket.h>
#include <zephyr/posix/sys/select.h>
#elif defined(HAVE_UNISTD_H)
#include <unistd.h>
#endif
/* select() is used for TCP socket mode, not UART mode */
#if !defined(WOLFTPM_ZEPHYR) && !defined(WOLFTPM_SWTPM_UART) && !defined(WOLFTPM_SWTPM_UARTNS550)
#include <sys/select.h>
#endif
#include <errno.h>
#include <string.h>                 /* necessary for memset */
#include <stdio.h>                  /* standard in/out procedures */
#include <stdlib.h>                 /* defines system calls */

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#if defined(WOLFTPM_SWTPM_UART)
    #define _XOPEN_SOURCE 600
    #include <sys/socket.h>         /* used for all socket calls */
    #include <netinet/in.h>         /* used for sockaddr_in6 */
    #include <arpa/inet.h>
    #include <fcntl.h>
    #include <sys/stat.h>
    #include <termios.h>
    #include <signal.h>
    #include <errno.h>

    #ifndef TPM2_SWTPM_HOST
        #ifdef __MACH__
            #define TPM2_SWTPM_HOST "/dev/cu.usbserial-0001"
        #else
            #define TPM2_SWTPM_HOST "/dev/ttyS0"
        #endif
    #endif
    #ifndef TPM2_SWTPM_PORT
    #define TPM2_SWTPM_PORT         115200
    #endif
    #ifndef TPM2_TIMEOUT_SECONDS
    #define TPM2_TIMEOUT_SECONDS    7200
    #endif
    #define WOLFTPM_WRITE write
    #define WOLFTPM_READ  read
    #define WOLFTPM_CLOSE close
#elif defined(WOLFTPM_SWTPM_UARTNS550)
    /* Xilinx 16550 UART */
    #ifndef TPM2_SWTPM_HOST
        #define TPM2_SWTPM_HOST XPAR_MB0_AXI_UART16550_2_DEVICE_ID
    #endif
    #ifndef TPM2_SWTPM_PORT
    #define TPM2_SWTPM_PORT         115200
    #endif
    #ifndef TPM2_TIMEOUT_SECONDS
    #define TPM2_TIMEOUT_SECONDS    21600
    #endif
    #define WOLFTPM_WRITE(u, b, sz) XUartNs550_Send(&(u), (b), (sz))
    #define WOLFTPM_READ(u, b, sz)  XUartNs550_Recv(&(u), (b), (sz))
    #define WOLFTPM_CLOSE(fd) 0

#else
    #include <wolftpm/tpm2_socket.h>

    #ifndef TPM2_SWTPM_HOST
    #define TPM2_SWTPM_HOST         "localhost"
    #endif
    #ifndef TPM2_SWTPM_PORT
    #define TPM2_SWTPM_PORT         "2321"
    #endif
    #ifndef TPM2_TIMEOUT_SECONDS
    #define TPM2_TIMEOUT_SECONDS    10
    #endif
    #define WOLFTPM_WRITE write
    #define WOLFTPM_READ  read
    #define WOLFTPM_CLOSE close
#endif /* WOLFTPM_SWTPM_UART */

#ifndef TPM2_SWTPM_HOST
#define TPM2_SWTPM_HOST         "localhost"
#endif
#ifndef TPM2_SWTPM_PORT
#define TPM2_SWTPM_PORT         2321
#endif

static TPM_RC SwTpmTransmit(TPM2_CTX* ctx, const void* buffer, ssize_t bufSz)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    ssize_t wrc = 0;

    if (ctx == NULL || buffer == NULL) {
        return BAD_FUNC_ARG;
    }

#if !defined(WOLFTPM_SWTPM_UARTNS550)
    if (ctx->tcpCtx.fd < 0) {
        return BAD_FUNC_ARG;
    }
#endif

#ifdef DEBUG_SWTPM_IO
    DEBUG_PRINTF("Write %zd\n\r", bufSz);
    TPM2_PrintBin(buffer, (word32)bufSz);
#endif

#if defined(WOLFTPM_SWTPM_UARTNS550)
    while (wrc < bufSz)
#endif
    {
        ssize_t tmp;

        tmp = WOLFTPM_WRITE(ctx->tcpCtx.fd, (unsigned char*)buffer + wrc,
            bufSz - wrc);
        if (tmp > 0) {
            wrc += tmp;
        }
        if (tmp < 0) {
            rc = TPM_RC_FAILURE;
        }

#if !defined(WOLFTPM_SWTPM_UARTNS550)
        if (bufSz != wrc) {
            rc = TPM_RC_FAILURE;
        }
#endif
    }

#ifdef WOLFTPM_DEBUG_VERBOSE
    if (wrc < 0) {
        DEBUG_PRINTF("Failed to send the TPM command to fd %d, got errno %d ="
               "%s\n", ctx->tcpCtx.fd, errno, strerror(errno));
    }
#endif

    return rc;
}

#if !defined(WOLFTPM_SWTPM_UARTNS550)
static int SwTpmReceive(TPM2_CTX* ctx, void* buffer, size_t rxSz)
{
    int rc;
    size_t remain;
    char* ptr = (char*)buffer;
    fd_set rfds;
    struct timeval tv = { TPM2_TIMEOUT_SECONDS, 0};

    if (ctx == NULL || ctx->tcpCtx.fd < 0 || buffer == NULL) {
        return BAD_FUNC_ARG;
    }

    FD_ZERO(&rfds);
    FD_SET(ctx->tcpCtx.fd, &rfds);
    remain   = rxSz;

    do {
        /* use select to wait for data */
        rc = select(ctx->tcpCtx.fd + 1, &rfds, NULL, NULL, &tv);
        if (rc == 0) {
            rc = TPM_RC_FAILURE; /* timeout */
            break;
        }
        rc = (int)WOLFTPM_READ(ctx->tcpCtx.fd, ptr, remain);
#ifdef DEBUG_SWTPM_IO
        DEBUG_PRINTF("Read asked %zd, got %d\n\r", remain, rc);
#endif

        if (rc == 0) {
            if (remain == 0) {
                break;
            }
            continue; /* keep trying */
        }

        if (rc <= 0) {
        #ifdef DEBUG_WOLFTPM
            if (rc == 0) {
                DEBUG_PRINTF("Failed to read from TPM socket: EOF\n");
            }
            else {
                DEBUG_PRINTF("Failed to read from TPM socket %d, got errno %d"
                       " = %s\n", ctx->tcpCtx.fd, errno, strerror(errno));
            }
        #endif
            rc = TPM_RC_FAILURE;
            break;
        }

#ifdef DEBUG_SWTPM_IO
        TPM2_PrintBin((const byte*)ptr, rc);
#endif
        remain -= rc;
        ptr += rc;

    #ifdef WOLFTPM_DEBUG_VERBOSE
        DEBUG_PRINTF("TPM socket received %d waiting for %zd more\n\r",
               rc, remain);
    #endif
    } while (remain > 0);

    if (remain <= 0) {
        rc = TPM_RC_SUCCESS;
    }

    return rc;
}
#endif

#ifdef WOLFTPM_SWTPM_UART
static int SwTpmConnect(TPM2_CTX* ctx, const char* uartDev, uint32_t baud)
{
    struct termios tty;
    int fd;

    if (ctx == NULL) {
        return BAD_FUNC_ARG;
    }

    /* Open UART file descriptor */
    fd = open(uartDev, O_RDWR | O_NOCTTY);
    if (fd < 0) {
#ifdef DEBUG_WOLFTPM
        DEBUG_PRINTF("Error opening %s: Error %i (%s)\n",
            uartDev, errno, strerror(errno));
#endif
        return TPM_RC_FAILURE;
    }
    tcgetattr(fd, &tty);
    cfsetospeed(&tty, baud);
    cfsetispeed(&tty, baud);
    tty.c_cflag = (tty.c_cflag & ~CSIZE) | (CS8);
    tty.c_iflag &= ~(IGNBRK | IXON | IXOFF | IXANY| INLCR | ICRNL);
    tty.c_oflag &= ~OPOST;
    tty.c_oflag &= ~(ONLCR|OCRNL);
    tty.c_cflag &= ~(PARENB | PARODD | CSTOPB);
    tty.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);
    tty.c_iflag &= ~ISTRIP;
    tty.c_cc[VMIN] = 0;
    tty.c_cc[VTIME] = 5;
    tcsetattr(fd, TCSANOW, &tty);

    /* Flush any data in the RX buffer */
    tcflush(fd, TCIOFLUSH);

    /* save file descriptor to context */
    ctx->tcpCtx.fd = fd;

    return TPM_RC_SUCCESS;
}

#elif defined(WOLFTPM_SWTPM_UARTNS550)

static unsigned char rxBuff[512];
static int rxBuffIdx = 0;

static int SwTpmReceive(TPM2_CTX* ctx, void* buffer, size_t rxSz)
{
    int rc;
    size_t remain, rxRemain;
    int sendAck = 0;
    int timeOut = TPM2_TIMEOUT_SECONDS;

    if (ctx == NULL || buffer == NULL) {
        return BAD_FUNC_ARG;
    }

    remain   = rxSz;
    rxRemain = rxSz;

    /* use up any leftovers before trying to pull more */
    if (rxBuffIdx > 0) {
        int minSz = (rxBuffIdx < (int)remain)? rxBuffIdx : (int)remain;

        memcpy(buffer, rxBuff, minSz);
        if (rxBuffIdx > minSz) {
            memmove(rxBuff, rxBuff + rxBuffIdx - minSz, rxBuffIdx - minSz);
        }
        rxBuffIdx -= minSz;
        remain -= minSz;
        rxRemain -= minSz;
    }

    do {
        rc = (int)WOLFTPM_READ(ctx->tcpCtx.fd, rxBuff + rxBuffIdx,
            sizeof(rxBuff) - rxBuffIdx);
    #ifdef DEBUG_SWTPM_IO
        DEBUG_PRINTF("Read asked %d, got %d\n\r", remain, rc);
    #endif

        /* send ack */
        if (rc > 0 ) {
            usleep(500);
            sendAck = 1;
            timeOut = TPM2_TIMEOUT_SECONDS; /* reset timeout */
        }

        if (rc == 0) {
            if (sendAck) {
                unsigned char tmpBuf[1] = {0x01};

                sendAck = 0;
                WOLFTPM_WRITE(ctx->tcpCtx.fd, tmpBuf, 1);
            }

            if (rxBuffIdx >= rxRemain || rxRemain == 0) {
                break;
            }

            if ((timeOut--) <= 0) {
                rxBuffIdx = 0; /* reset read state */
                rc = TPM_RC_FAILURE; /* timeout */
            #if DEBUG_WOLFTPM
                DEBUG_PRINTF("Connection timed out\r\n");
            #endif
                break;
            }
            continue; /* keep trying */
        }

        if (rc <= 0) {
        #ifdef DEBUG_WOLFTPM
            DEBUG_PRINTF("Failed to read from TPM UART\n\r");
        #endif
            rc = TPM_RC_FAILURE;
            break;
        }
        rxBuffIdx += rc;
        remain -= rc;

    #ifdef WOLFTPM_DEBUG_VERBOSE
        DEBUG_PRINTF("TPM socket received %d waiting for %d more\n\r",
               rc, remain);
    #endif
    } while (1);

    if (remain <= 0) {
        rc = TPM_RC_SUCCESS;
    }

    if (rxBuffIdx > 0 && rxRemain > 0) {
        int minSz = (rxRemain < rxBuffIdx)? rxRemain : rxBuffIdx;
        memcpy(buffer, rxBuff, minSz);
        if (rxBuffIdx > minSz) {
            memmove(rxBuff, rxBuff + minSz, rxBuffIdx - minSz);
        }
        rxBuffIdx -= minSz;
        rc = TPM_RC_SUCCESS;
    }

    return rc;
}


static int SwTpmConnect(TPM2_CTX* ctx, uint32_t baud)
{
    int ret = TPM_RC_SUCCESS;
    XUartNs550_Config *config;

    config = XUartNs550_LookupConfig(TPM2_SWTPM_HOST);
    if (config == NULL) {
        ret = TPM_RC_FAILURE;
    }

    if (ret == TPM_RC_SUCCESS) {
    #ifdef DEBUG_SWTPM_IO
        DEBUG_PRINTF("Connecting with UART base address = %X\n\r",
            config->BaseAddress);
    #endif
        if (XUartNs550_CfgInitialize(&(ctx->tcpCtx.fd), config,
            config->BaseAddress) != XST_SUCCESS) {
        #ifdef DEBUG_SWTPM_IO
            DEBUG_PRINTF("cfg initialize fail\n\r");
        #endif
            ret = TPM_RC_FAILURE;
        }
    }

    if (ret == TPM_RC_SUCCESS) {
        if (XUartNs550_SelfTest(&(ctx->tcpCtx.fd)) != XST_SUCCESS) {
        #ifdef DEBUG_SWTPM_IO
            DEBUG_PRINTF("UART tpm selftest failed\n\r");
        #endif
            ret = TPM_RC_FAILURE;
        }
    }

    if (ret == TPM_RC_SUCCESS) {
        XUartNs550_SetBaudRate( &(ctx->tcpCtx.fd), baud);
        XUartNs550_SetFifoThreshold( &(ctx->tcpCtx.fd), XUN_FIFO_TRIGGER_01);
    }

    return ret;
}
#else
static int SwTpmConnect(TPM2_CTX* ctx, const char* host, const char* port)
{
    TPM_RC rc = TPM_RC_FAILURE;
    int s;
    int fd = -1;

    /* Zephyr doesnt support getaddrinfo;
     * so we need to use Zephyr's socket API
     */
#ifdef WOLFTPM_ZEPHYR
    struct zsock_addrinfo hints;
    struct zsock_addrinfo *result, *rp;

    if (ctx == NULL) {
        return BAD_FUNC_ARG;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    s = zsock_getaddrinfo(host, port, &hints, &result);
    if (s != 0) {
        // Handle error
        return rc;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        fd = zsock_socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0)
            continue;
        if (zsock_connect(fd, rp->ai_addr, rp->ai_addrlen) < 0) {
            zsock_close(fd);
        } else {
            break;
        }
    }
    zsock_freeaddrinfo(result);

    if (rp != NULL) {
        ctx->tcpCtx.fd = fd;
        rc = TPM_RC_SUCCESS;
    }
    #ifdef DEBUG_WOLFTPM
    else {
        printf("Failed to connect to %s %s\n", host, port);
    }
    #endif
#else /* !WOLFTPM_ZEPHYR */
    struct addrinfo hints;
    struct addrinfo *result, *rp;

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
        DEBUG_PRINTF("Failed to connect to %s %s\n", host, port);
    }
    #endif
#endif /* WOLFTPM_ZEPHYR */

    return rc;
}
#endif /* WOLFTPM_SWTPM_UART */

static TPM_RC SwTpmDisconnect(TPM2_CTX* ctx)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t tss_cmd;

    if (ctx == NULL) {
        return BAD_FUNC_ARG;
    }

#if !defined(WOLFTPM_SWTPM_UARTNS550)
    if (ctx->tcpCtx.fd < 0) {
        return BAD_FUNC_ARG;
    }
#endif

    /* end software TPM session */
    tss_cmd = TPM2_Packet_SwapU32(TPM_SESSION_END);
    rc = SwTpmTransmit(ctx, &tss_cmd, sizeof(uint32_t));
#ifdef WOLFTPM_DEBUG_VERBOSE
    if (rc != TPM_RC_SUCCESS) {
        DEBUG_PRINTF("Failed to transmit SESSION_END\n");
    }
#endif

    if (WOLFTPM_CLOSE(ctx->tcpCtx.fd) != 0) {
        rc = TPM_RC_FAILURE;

    #ifdef WOLFTPM_DEBUG_VERBOSE
        DEBUG_PRINTF("Failed to close fd %d, got errno %d ="
               "%s\n", ctx->tcpCtx.fd, errno, strerror(errno));
    #endif
    }

#if !defined(WOLFTPM_SWTPM_UARTNS550)
    ctx->tcpCtx.fd = -1;
#endif

    return rc;
}

/* Talk to a TPM through socket
 * return TPM_RC_SUCCESS on success,
 *        TPM_RC_FAILURE on other errors
 */
int TPM2_SWTPM_SendCommand(TPM2_CTX* ctx, TPM2_Packet* packet)
{
    int rc = TPM_RC_SUCCESS;
    int rspSz = 0;
    uint32_t tss_word;

    if (ctx == NULL) {
        return BAD_FUNC_ARG;
    }

#if !defined(WOLFTPM_SWTPM_UARTNS550)
    if (ctx->tcpCtx.fd < 0) {
        rc = SwTpmConnect(ctx, TPM2_SWTPM_HOST, TPM2_SWTPM_PORT);
    }
#else
    if (ctx->tcpCtx.setup == 0) {
        ctx->tcpCtx.setup = 1;
        rc = SwTpmConnect(ctx, TPM2_SWTPM_PORT);
    }
#endif

#ifdef WOLFTPM_DEBUG_VERBOSE
    DEBUG_PRINTF("Command size: %d\n\r", packet->pos);
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
            DEBUG_PRINTF("Response size(%d) larger than command buffer(%d)\n",
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
            DEBUG_PRINTF("SWTPM ack %d\n", tss_word);
        }
    #endif
    }

#ifdef WOLFTPM_DEBUG_VERBOSE
    if (rspSz > 0) {
        int sz = (rspSz < packet->size) ? rspSz : packet->size;
        DEBUG_PRINTF("Response size: %d\n", rspSz);
        TPM2_PrintBin(packet->buf, sz);
        (void)sz;
    }
#endif

#if !defined(WOLFTPM_SWTPM_UARTNS550)
    if (ctx->tcpCtx.fd >= 0)
#endif
    {
        TPM_RC rc_disconnect = SwTpmDisconnect(ctx);
        if (rc == TPM_RC_SUCCESS) {
            rc = rc_disconnect;
        }
    }

    return rc;
}
#endif /* WOLFTPM_SWTPM */
