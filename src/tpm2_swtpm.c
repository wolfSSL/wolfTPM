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
#elif defined(HAVE_UNISTD_H)
#include <unistd.h>
#endif
#include <errno.h>
#include <string.h>
#include <stdio.h>
#if !defined(WOLFTPM_ZEPHYR) && !defined(_WIN32)
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif
#if !defined(NO_GETENV) || defined(WOLFTPM_SWTPM_UART)
#include <stdlib.h> /* getenv / atoi */
#endif
#ifdef WOLFTPM_SWTPM_UART
#include <fcntl.h>
#include <termios.h>
#include <sys/stat.h>
#include <time.h>
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif
/* Cumulative wall-clock timeout for SwTpmReceive. Defends against trickle
 * senders that repeatedly reset the per-read VMIN/VTIME timer. */
#ifndef WOLFTPM_SWTPM_UART_RX_TIMEOUT_SECS
#define WOLFTPM_SWTPM_UART_RX_TIMEOUT_SECS 30
#endif
#endif

#include <wolftpm/tpm2_socket.h>

#ifdef WOLFTPM_SWTPM_UART
    /* UART transport: HOST = device path, PORT = baud rate */
    #ifndef TPM2_SWTPM_HOST
        #ifdef __APPLE__
            #define TPM2_SWTPM_HOST "/dev/cu.usbmodem"
        #else
            #define TPM2_SWTPM_HOST "/dev/ttyACM0"
        #endif
    #endif
    #ifndef TPM2_SWTPM_PORT
        #define TPM2_SWTPM_PORT 115200
    #endif
#else
    /* Socket transport: HOST = hostname, PORT = TCP port */
    #ifndef TPM2_SWTPM_HOST
        #define TPM2_SWTPM_HOST "localhost"
    #endif
    #ifndef TPM2_SWTPM_PORT
        #define TPM2_SWTPM_PORT 2321
    #endif
#endif

static TPM_RC SwTpmTransmit(TPM2_CTX* ctx, const void* buffer, ssize_t bufSz)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    ssize_t wrc = 0;
    const char* ptr;
    ssize_t remaining;

    if (ctx == NULL || ctx->tcpCtx.fd < 0 || buffer == NULL || bufSz <= 0) {
        return BAD_FUNC_ARG;
    }

    ptr = (const char*)buffer;
    remaining = bufSz;
    while (remaining > 0) {
        wrc = write(ctx->tcpCtx.fd, ptr, remaining);
        if (wrc < 0) {
            /* Retry on EINTR (signal). EAGAIN/EWOULDBLOCK shouldn't normally
             * happen on the default blocking fd, but treat them as transient. */
            if (errno == EINTR
                #ifdef EAGAIN
                    || errno == EAGAIN
                #endif
                #if defined(EWOULDBLOCK) && (!defined(EAGAIN) || EWOULDBLOCK != EAGAIN)
                    || errno == EWOULDBLOCK
                #endif
            ) {
                continue;
            }
        #ifdef WOLFTPM_DEBUG_VERBOSE
            printf("Failed to send the TPM command to fd %d, got errno %d ="
                   "%s\n", ctx->tcpCtx.fd, errno, strerror(errno));
        #endif
            rc = TPM_RC_FAILURE;
            break;
        }
        if (wrc == 0) {
            /* Defensive: write() returning 0 on a regular fd is unspecified —
             * treat as failure rather than spinning. */
            rc = TPM_RC_FAILURE;
            break;
        }
        remaining -= wrc;
        ptr += wrc;
    }

    return rc;
}

static TPM_RC SwTpmReceive(TPM2_CTX* ctx, void* buffer, size_t rxSz)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    ssize_t wrc = 0;
    size_t bytes_remaining = rxSz;
    char* ptr = (char*)buffer;
#if defined(WOLFTPM_SWTPM_UART) && defined(CLOCK_MONOTONIC)
    struct timespec start, now;
    int haveStart = 0;
    if (clock_gettime(CLOCK_MONOTONIC, &start) == 0) {
        haveStart = 1;
    }
#endif

    if (ctx == NULL || ctx->tcpCtx.fd < 0 || buffer == NULL) {
        return BAD_FUNC_ARG;
    }

    while (bytes_remaining > 0) {
        wrc = read(ctx->tcpCtx.fd, ptr, bytes_remaining);
        if (wrc < 0) {
            /* Retry on EINTR; treat EAGAIN/EWOULDBLOCK as transient too. */
            if (errno == EINTR
                #ifdef EAGAIN
                    || errno == EAGAIN
                #endif
                #if defined(EWOULDBLOCK) && (!defined(EAGAIN) || EWOULDBLOCK != EAGAIN)
                    || errno == EWOULDBLOCK
                #endif
            ) {
                continue;
            }
            #ifdef DEBUG_WOLFTPM
            printf("Failed to read from TPM socket %d, got errno %d"
                   " = %s\n", ctx->tcpCtx.fd, errno, strerror(errno));
            #endif
            rc = TPM_RC_FAILURE;
            break;
        }
        if (wrc == 0) {
            #ifdef DEBUG_WOLFTPM
            printf("Failed to read from TPM socket: EOF\n");
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

#if defined(WOLFTPM_SWTPM_UART) && defined(CLOCK_MONOTONIC)
        /* Enforce cumulative timeout so a trickle sender cannot reset
         * VMIN/VTIME indefinitely. */
        if (haveStart && bytes_remaining > 0 &&
                clock_gettime(CLOCK_MONOTONIC, &now) == 0 &&
                (now.tv_sec - start.tv_sec) >
                    WOLFTPM_SWTPM_UART_RX_TIMEOUT_SECS) {
        #ifdef DEBUG_WOLFTPM
            printf("SwTpmReceive: cumulative UART timeout after %lds "
                   "(%zu bytes remaining)\n",
                   (long)(now.tv_sec - start.tv_sec), bytes_remaining);
        #endif
            rc = TPM_RC_FAILURE;
            break;
        }
#endif
    }

    return rc;
}

static TPM_RC SwTpmConnect(TPM2_CTX* ctx, const char* host, const char* port)
{
    TPM_RC rc = TPM_RC_FAILURE;
    int fd = -1;

#ifdef WOLFTPM_SWTPM_UART
    /* UART transport: open serial device with termios */
    struct termios tty;
    speed_t baud;
    int baudInt;
    struct stat devStat;

    if (ctx == NULL) {
        return BAD_FUNC_ARG;
    }
    /* Note: TPM2_SWTPM_HOST env var is checked by caller
     * (TPM2_SWTPM_SendCommand) before invoking SwTpmConnect */

    fd = open(host, O_RDWR | O_NOCTTY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
    #ifdef DEBUG_WOLFTPM
        printf("Failed to open UART device %s: %s\n", host, strerror(errno));
    #endif
        return TPM_RC_FAILURE;
    }
    /* If O_CLOEXEC wasn't available at compile time, set FD_CLOEXEC now. */
    if (O_CLOEXEC == 0) {
        int flags = fcntl(fd, F_GETFD);
        if (flags != -1) {
            (void)fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
        }
    }
    /* Verify the opened path is a character device */
    if (fstat(fd, &devStat) != 0 || !S_ISCHR(devStat.st_mode)) {
        close(fd);
        return TPM_RC_FAILURE;
    }

    /* Configure serial port: 8N1, raw mode, no flow control */
    XMEMSET(&tty, 0, sizeof(tty));
    if (tcgetattr(fd, &tty) != 0) {
        close(fd);
        return TPM_RC_FAILURE;
    }

    /* Baud rate from port string or default */
    baudInt = (port != NULL) ? atoi(port) : 0;
    if (baudInt <= 0) {
        baudInt = TPM2_SWTPM_PORT;
    }
    switch (baudInt) {
        case 9600:   baud = B9600; break;
        case 19200:  baud = B19200; break;
        case 38400:  baud = B38400; break;
        case 57600:  baud = B57600; break;
        case 115200: baud = B115200; break;
    #ifdef B230400
        case 230400: baud = B230400; break;
    #endif
    #ifdef B460800
        case 460800: baud = B460800; break;
    #endif
    #ifdef B921600
        case 921600: baud = B921600; break;
    #endif
        default:     baud = B115200; break;
    }
    if (cfsetospeed(&tty, baud) != 0 || cfsetispeed(&tty, baud) != 0) {
    #ifdef DEBUG_WOLFTPM
        printf("Failed to set UART baud rate %d: %s\n",
            baudInt, strerror(errno));
    #endif
        close(fd);
        return TPM_RC_FAILURE;
    }

    /* 8N1: 8 data bits, no parity, 1 stop bit */
    tty.c_cflag = (tty.c_cflag & ~CSIZE) | CS8;
    tty.c_cflag &= ~(PARENB | PARODD | CSTOPB);
#ifdef CRTSCTS
    tty.c_cflag &= ~CRTSCTS;
#endif
    tty.c_cflag |= (CLOCAL | CREAD);

    /* Raw mode: no special input/output processing */
    tty.c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP |
                      INLCR | IGNCR | ICRNL | IXON | IXOFF | IXANY);
    tty.c_oflag &= ~OPOST;
    tty.c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);

    /* Read with overall timeout.
     * RSA key generation on embedded targets can take 10+ seconds,
     * so use a generous timeout. With VMIN=0 and VTIME>0, read()
     * returns after the timeout even if no byte is received. */
    tty.c_cc[VMIN] = 0;    /* allow timeout without requiring first byte */
    tty.c_cc[VTIME] = 200; /* 20 second timeout (tenths of seconds) */

    if (tcsetattr(fd, TCSANOW, &tty) != 0) {
        close(fd);
        return TPM_RC_FAILURE;
    }

    /* Flush any stale data */
    tcflush(fd, TCIOFLUSH);

    ctx->tcpCtx.fd = fd;
    rc = TPM_RC_SUCCESS;

#ifdef DEBUG_WOLFTPM
    printf("UART connected: %s @ %d baud\n", host, baudInt);
#endif

#elif defined(WOLFTPM_ZEPHYR)
    /* Zephyr doesn't support getaddrinfo;
     * so we need to use Zephyr's socket API
     */
    int s;
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
    int s;
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
        return rc;
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
#endif /* WOLFTPM_ZEPHYR */

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

#ifdef WOLFTPM_SWTPM_UART
    /* UART: on success, keep the port open for the next command.
     * The SESSION_END tells the server the command sequence is done.
     * Final cleanup of the UART FD is handled in TPM2_SwtpmCloseUART.
     * On SESSION_END write failure, close and reset the fd so the next
     * command reconnects instead of reusing a broken connection. */
    if (rc != TPM_RC_SUCCESS) {
        close(ctx->tcpCtx.fd);
        ctx->tcpCtx.fd = -1;
    }
#else
    if (0 != close(ctx->tcpCtx.fd)) {
        rc = TPM_RC_FAILURE;

        #ifdef WOLFTPM_DEBUG_VERBOSE
        printf("Failed to close fd %d, got errno %d ="
               "%s\n", ctx->tcpCtx.fd, errno, strerror(errno));
        #endif
    }

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
    const char* swtpmHost = TPM2_SWTPM_HOST;
    const char* swtpmPort = XSTRINGIFY(TPM2_SWTPM_PORT);
#ifndef NO_GETENV
    const char* envVal;
#endif

    if (ctx == NULL) {
        return BAD_FUNC_ARG;
    }

    if (ctx->tcpCtx.fd < 0) {
    #ifndef NO_GETENV
        envVal = getenv("TPM2_SWTPM_HOST");
        if (envVal != NULL && envVal[0] != '\0')
            swtpmHost = envVal;
        envVal = getenv("TPM2_SWTPM_PORT");
        if (envVal != NULL && envVal[0] != '\0')
            swtpmPort = envVal;
    #endif
        rc = SwTpmConnect(ctx, swtpmHost, swtpmPort);
    }
    else {
        rc = TPM_RC_SUCCESS; /* already connected (e.g. UART persistent fd) */
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

#ifdef WOLFTPM_SWTPM_UART
/* Close the persistent UART FD during final TPM context cleanup */
void TPM2_SwtpmCloseUART(TPM2_CTX* ctx)
{
    if (ctx != NULL && ctx->tcpCtx.fd >= 0) {
        close(ctx->tcpCtx.fd);
        ctx->tcpCtx.fd = -1;
    }
}
#endif
#endif /* WOLFTPM_SWTPM */
