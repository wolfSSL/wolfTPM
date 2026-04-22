/* fwtpm_io.c
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

/* fwTPM Socket Transport Server
 * Implements the server side of the SWTPM TCP protocol so that
 * wolfTPM clients built with --enable-swtpm can connect directly.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2_types.h>

#ifdef WOLFTPM_FWTPM

#include <wolftpm/tpm2_packet.h>
#include <wolftpm/fwtpm/fwtpm.h>
#include <wolftpm/fwtpm/fwtpm_io.h>
#include <wolftpm/fwtpm/fwtpm_command.h>
#ifdef WOLFTPM_FWTPM_TIS
#include <wolftpm/fwtpm/fwtpm_tis.h>
#endif

#include <stdio.h>
#include <string.h>
#include <errno.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#include <wolftpm/tpm2_socket.h>

#include <signal.h> /* sig_atomic_t */
#ifndef _WIN32
#include <sys/select.h>
#include <arpa/inet.h>
#endif

/* Async-signal-safe stop flag. Set by FWTPM_IO_RequestStop() (callable from
 * a signal handler) and polled by the server loop. Using sig_atomic_t guarantees
 * POSIX-conformant atomic read/write from inside a signal handler. */
static volatile sig_atomic_t g_stopRequested = 0;

void FWTPM_IO_RequestStop(void)
{
    g_stopRequested = 1;
}

int FWTPM_IO_IsStopRequested(void)
{
    return g_stopRequested != 0;
}

/* Use TPM2_Packet_SwapU32 from tpm2_packet.c (compiled directly) */
#define FwTpmSwapU32 TPM2_Packet_SwapU32

#ifndef WOLFTPM_FWTPM_TIS
/* --- Low-level socket helpers --- */

static int SocketSend(SOCKET_T fd, const void* buf, int sz)
{
    const char* ptr = (const char*)buf;
    int remaining = sz;
    while (remaining > 0) {
    #ifdef _WIN32
        int sent = send(fd, ptr, remaining, 0);
    #else
        int sent = (int)write(fd, ptr, remaining);
    #endif
        if (sent <= 0) {
        #ifdef _WIN32
            if (WSAGetLastError() == WSAEINTR) continue;
        #else
            if (errno == EINTR) continue;
        #endif
        #ifdef DEBUG_WOLFTPM
            printf("fwTPM: send error %d\n",
            #ifdef _WIN32
                WSAGetLastError()
            #else
                errno
            #endif
            );
        #endif
            return TPM_RC_FAILURE;
        }
        remaining -= sent;
        ptr += sent;
    }
    return TPM_RC_SUCCESS;
}

static int SocketRecv(SOCKET_T fd, void* buf, int sz)
{
    char* ptr = (char*)buf;
    int remaining = sz;
    while (remaining > 0) {
    #ifdef _WIN32
        int got = recv(fd, ptr, remaining, 0);
    #else
        int got = (int)read(fd, ptr, remaining);
    #endif
        if (got <= 0) {
        #ifdef _WIN32
            if (got < 0 && WSAGetLastError() == WSAEINTR) continue;
        #else
            if (got < 0 && errno == EINTR) continue;
        #endif
        #ifdef DEBUG_WOLFTPM
            if (got == 0) {
                printf("fwTPM: recv EOF\n");
            }
            else {
                printf("fwTPM: recv error %d\n",
                #ifdef _WIN32
                    WSAGetLastError()
                #else
                    errno
                #endif
                );
            }
        #endif
            return TPM_RC_FAILURE;
        }
        remaining -= got;
        ptr += got;
    }
    return TPM_RC_SUCCESS;
}

static SOCKET_T CreateListenSocket(int port)
{
    SOCKET_T fd;
    int optval = 1;
    struct sockaddr_in addr;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == FWTPM_INVALID_FD) {
    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: socket() failed\n");
    #endif
        return FWTPM_INVALID_FD;
    }

    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
        (const char*)&optval, sizeof(optval));

    XMEMSET(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((unsigned short)port);

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: bind(%d) failed\n", port);
    #endif
        CloseSocket(fd);
        return FWTPM_INVALID_FD;
    }

    if (listen(fd, 1) != 0) {
    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: listen(%d) failed\n", port);
    #endif
        CloseSocket(fd);
        return FWTPM_INVALID_FD;
    }

    return fd;
}

/* Build a minimal TPM error response using TPM2_Packet API */
static int BuildErrorResponse(byte* rspBuf, UINT16 tag, TPM_RC rc)
{
    TPM2_Packet pkt;
    int totalSz;
    pkt.buf = rspBuf;
    pkt.pos = TPM2_HEADER_SIZE;
    pkt.size = FWTPM_MAX_COMMAND_SIZE;
    totalSz = pkt.pos;
    pkt.pos = 0;
    TPM2_Packet_AppendU16(&pkt, tag);
    TPM2_Packet_AppendU32(&pkt, (UINT32)totalSz);
    TPM2_Packet_AppendU32(&pkt, rc);
    return totalSz;
}

/* --- Platform port handler --- */
static int HandlePlatformCommand(FWTPM_CTX* ctx, int clientFd)
{
    int rc;
    UINT32 cmd;
    UINT32 ack = 0;

    rc = SocketRecv(clientFd, &cmd, 4);
    if (rc != TPM_RC_SUCCESS) {
        return rc;
    }

    cmd = FwTpmSwapU32(cmd);

    switch (cmd) {
        case FWTPM_TCP_SIGNAL_POWER_ON:
            ctx->powerOn = 1;
        #ifdef DEBUG_WOLFTPM
            printf("fwTPM: Platform POWER_ON\n");
        #endif
            break;

        case FWTPM_TCP_SIGNAL_POWER_OFF:
            ctx->powerOn = 0;
            ctx->wasStarted = 0;
        #ifdef DEBUG_WOLFTPM
            printf("fwTPM: Platform POWER_OFF\n");
        #endif
            break;

        case FWTPM_TCP_SIGNAL_NV_ON:
        #ifdef DEBUG_WOLFTPM
            printf("fwTPM: Platform NV_ON\n");
        #endif
            break;

        case FWTPM_TCP_SIGNAL_RESET:
            ctx->wasStarted = 0;
        #ifdef DEBUG_WOLFTPM
            printf("fwTPM: Platform RESET\n");
        #endif
            break;

        case FWTPM_TCP_SIGNAL_PHYS_PRES_ON:
        case FWTPM_TCP_SIGNAL_PHYS_PRES_OFF:
        case FWTPM_TCP_SIGNAL_CANCEL_ON:
        case FWTPM_TCP_SIGNAL_CANCEL_OFF:
        case FWTPM_TCP_SIGNAL_HASH_START:
        case FWTPM_TCP_SIGNAL_HASH_END:
        #ifdef DEBUG_WOLFTPM
            printf("fwTPM: Platform signal %d (ignored)\n", cmd);
        #endif
            break;

        case FWTPM_TCP_SESSION_END:
        #ifdef DEBUG_WOLFTPM
            printf("fwTPM: Platform SESSION_END\n");
        #endif
            return TPM_RC_SUCCESS; /* no ack for session end */

        case FWTPM_TCP_STOP:
        #ifdef DEBUG_WOLFTPM
            printf("fwTPM: Platform STOP\n");
        #endif
            ctx->running = 0;
            break;

        default:
        #ifdef DEBUG_WOLFTPM
            printf("fwTPM: Platform unknown command %d\n", cmd);
        #endif
            break;
    }

    /* Send ack (0 = success) */
    ack = FwTpmSwapU32(0);
    rc = SocketSend(clientFd, &ack, 4);

    return rc;
}

/* --- Handle mssim signal on command port --- */
static int HandleMssimSignal(FWTPM_CTX* ctx, int clientFd, UINT32 tssCmd)
{
    UINT32 netVal;
    if (tssCmd == FWTPM_TCP_SIGNAL_POWER_ON)
        ctx->powerOn = 1;
    else if (tssCmd == FWTPM_TCP_SIGNAL_POWER_OFF) {
        ctx->powerOn = 0;
        ctx->wasStarted = 0;
    }
    else if (tssCmd == FWTPM_TCP_SIGNAL_RESET)
        ctx->wasStarted = 0;
#ifdef DEBUG_WOLFTPM
    printf("fwTPM: Cmd-port signal %u (ack)\n", tssCmd);
#endif
    netVal = FwTpmSwapU32(0);
    return SocketSend(clientFd, &netVal, 4);
}

/* --- Process and send TPM command response --- */
static int DispatchAndRespond(FWTPM_CTX* ctx, UINT32 cmdSize, int locality,
    int clientFd, int isSwtpm)
{
    int rc;
    int rspSize = 0;
    int procRc;
    UINT32 netVal;

    procRc = FWTPM_ProcessCommand(ctx, ctx->cmdBuf, (int)cmdSize,
        ctx->rspBuf, &rspSize, locality);
    if (procRc != TPM_RC_SUCCESS || rspSize == 0) {
        rspSize = BuildErrorResponse(ctx->rspBuf, TPM_ST_NO_SESSIONS,
            TPM_RC_FAILURE);
    }

    if (isSwtpm) {
        /* swtpm protocol: raw TPM response only (no framing) */
        rc = SocketSend(clientFd, ctx->rspBuf, rspSize);
    }
    else {
        /* mssim protocol: size(4) + response + ack(4) */
        netVal = FwTpmSwapU32((UINT32)rspSize);
        rc = SocketSend(clientFd, &netVal, 4);
        if (rc == TPM_RC_SUCCESS) {
            rc = SocketSend(clientFd, ctx->rspBuf, rspSize);
        }
        if (rc == TPM_RC_SUCCESS) {
            netVal = FwTpmSwapU32(0); /* ack = 0 (success) */
            rc = SocketSend(clientFd, &netVal, 4);
        }
    }

    return rc;
}

/* --- Check if mssim protocol signal (not SEND_COMMAND or SESSION_END) --- */
static int IsMssimSignal(UINT32 cmd)
{
    switch (cmd) {
        case FWTPM_TCP_SIGNAL_POWER_ON:
        case FWTPM_TCP_SIGNAL_POWER_OFF:
        case FWTPM_TCP_SIGNAL_PHYS_PRES_ON:
        case FWTPM_TCP_SIGNAL_PHYS_PRES_OFF:
        case FWTPM_TCP_SIGNAL_HASH_START:
        case FWTPM_TCP_SIGNAL_HASH_DATA:
        case FWTPM_TCP_SIGNAL_HASH_END:
        case FWTPM_TCP_SIGNAL_NV_ON:
        case FWTPM_TCP_SIGNAL_CANCEL_ON:
        case FWTPM_TCP_SIGNAL_CANCEL_OFF:
        case FWTPM_TCP_SIGNAL_RESET:
        case FWTPM_TCP_STOP:
            return 1;
        default:
            return 0;
    }
}

/* --- Command port handler (auto-detects mssim vs swtpm protocol) ---
 * mssim: first 4 bytes are a small protocol command (1-21)
 * swtpm: first 4 bytes are raw TPM header (tag 0x8001/0x8002 + size) */
static int HandleCommandConnection(FWTPM_CTX* ctx, int clientFd)
{
    int rc;
    UINT32 firstWord;
    UINT16 tag;
    UINT32 tssCmd;
    UINT8 locality;
    UINT32 cmdSize;
    UINT32 remaining;
    UINT32 netVal;

    /* Read first 4 bytes to determine protocol */
    rc = SocketRecv(clientFd, &firstWord, 4);
    if (rc != TPM_RC_SUCCESS) {
        return rc;
    }

    /* Check if this looks like a raw TPM command (swtpm protocol).
     * TPM commands start with tag 0x8001 or 0x8002 in big-endian. */
    tag = FwLoadU16BE((byte*)&firstWord);
    if (tag == TPM_ST_NO_SESSIONS || tag == TPM_ST_SESSIONS) {
        /* swtpm protocol: firstWord is the beginning of a raw TPM command.
         * Parse size from TPM header (bytes 2-5), read remaining bytes. */

        /* We already have 4 bytes (tag + start of size). Read 6 more to
         * complete the 10-byte TPM header (tag(2) + size(4) + cc(4)). */
        XMEMCPY(ctx->cmdBuf, &firstWord, 4);
        rc = SocketRecv(clientFd, ctx->cmdBuf + 4, 6);
        if (rc != TPM_RC_SUCCESS) {
            return rc;
        }
        cmdSize = FwLoadU32BE(ctx->cmdBuf + 2);

        if (cmdSize < TPM2_HEADER_SIZE || cmdSize > FWTPM_MAX_COMMAND_SIZE) {
        #ifdef DEBUG_WOLFTPM
            printf("fwTPM: swtpm command size invalid: %u\n", cmdSize);
        #endif
            return TPM_RC_COMMAND_SIZE;
        }

        /* Read remaining command bytes */
        remaining = cmdSize - TPM2_HEADER_SIZE;
        if (remaining > 0) {
            rc = SocketRecv(clientFd, ctx->cmdBuf + TPM2_HEADER_SIZE,
                (int)remaining);
            if (rc != TPM_RC_SUCCESS) {
                return rc;
            }
        }

    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: swtpm raw command (size=%u)\n", cmdSize);
    #endif

        return DispatchAndRespond(ctx, cmdSize, 0, clientFd, 1);
    }

    /* mssim protocol: firstWord is a protocol command code */
    tssCmd = FwTpmSwapU32(firstWord);

    if (tssCmd == FWTPM_TCP_SESSION_END) {
    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: Command SESSION_END\n");
    #endif
        return TPM_RC_SUCCESS;
    }

    /* Handle platform signals on command port */
    if (IsMssimSignal(tssCmd)) {
        return HandleMssimSignal(ctx, clientFd, tssCmd);
    }

    if (tssCmd != FWTPM_TCP_SEND_COMMAND) {
    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: Unknown command code %u\n", tssCmd);
    #endif
        return TPM_RC_FAILURE;
    }

    /* mssim SEND_COMMAND: locality(1) + size(4) + command */
    rc = SocketRecv(clientFd, &locality, 1);
    if (rc != TPM_RC_SUCCESS) {
        return rc;
    }

    rc = SocketRecv(clientFd, &netVal, 4);
    if (rc != TPM_RC_SUCCESS) {
        return rc;
    }
    cmdSize = FwTpmSwapU32(netVal);

    if (cmdSize < TPM2_HEADER_SIZE || cmdSize > FWTPM_MAX_COMMAND_SIZE) {
    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: Command size invalid: %u\n", cmdSize);
    #endif
        return TPM_RC_COMMAND_SIZE;
    }

    rc = SocketRecv(clientFd, ctx->cmdBuf, (int)cmdSize);
    if (rc != TPM_RC_SUCCESS) {
        return rc;
    }

    return DispatchAndRespond(ctx, cmdSize, (int)locality, clientFd, 0);
}

#endif /* !WOLFTPM_FWTPM_TIS */

/* --- Public API --- */

#ifndef WOLFTPM_FWTPM_TIS
int FWTPM_IO_SetHAL(FWTPM_CTX* ctx, FWTPM_IO_HAL* hal)
{
    if (ctx == NULL || hal == NULL) {
        return BAD_FUNC_ARG;
    }
    XMEMCPY(&ctx->ioHal, hal, sizeof(FWTPM_IO_HAL));
    return TPM_RC_SUCCESS;
}
#endif

int FWTPM_IO_Init(FWTPM_CTX* ctx)
{
    if (ctx == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLFTPM_FWTPM_TIS
    return FWTPM_TIS_Init(ctx);
#else
#ifdef _WIN32
    {
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            fprintf(stderr, "fwTPM: WSAStartup failed\n");
            return TPM_RC_FAILURE;
        }
    }
#endif
    XMEMSET(&ctx->io, 0, sizeof(ctx->io));
    ctx->io.listenFd = FWTPM_INVALID_FD;
    ctx->io.platListenFd = FWTPM_INVALID_FD;
    ctx->io.clientFd = FWTPM_INVALID_FD;
    ctx->io.platClientFd = FWTPM_INVALID_FD;

    /* Create command port listener */
    ctx->io.listenFd = CreateListenSocket(ctx->cmdPort);
    if (ctx->io.listenFd == FWTPM_INVALID_FD) {
        fprintf(stderr, "fwTPM: Failed to listen on command port %d\n",
            ctx->cmdPort);
    #ifdef _WIN32
        WSACleanup();
    #endif
        return TPM_RC_FAILURE;
    }

    /* Create platform port listener */
    ctx->io.platListenFd = CreateListenSocket(ctx->platPort);
    if (ctx->io.platListenFd == FWTPM_INVALID_FD) {
        fprintf(stderr, "fwTPM: Failed to listen on platform port %d\n",
            ctx->platPort);
        CloseSocket(ctx->io.listenFd);
        ctx->io.listenFd = FWTPM_INVALID_FD;
    #ifdef _WIN32
        WSACleanup();
    #endif
        return TPM_RC_FAILURE;
    }

    printf("fwTPM: Listening on command port %d, platform port %d\n",
        ctx->cmdPort, ctx->platPort);

    return TPM_RC_SUCCESS;
#endif /* !WOLFTPM_FWTPM_TIS */
}

void FWTPM_IO_Cleanup(FWTPM_CTX* ctx)
{
    if (ctx == NULL) {
        return;
    }

#ifdef WOLFTPM_FWTPM_TIS
    FWTPM_TIS_Cleanup(ctx);
#else
    if (ctx->io.clientFd != FWTPM_INVALID_FD) {
        CloseSocket(ctx->io.clientFd);
        ctx->io.clientFd = FWTPM_INVALID_FD;
    }
    if (ctx->io.platClientFd != FWTPM_INVALID_FD) {
        CloseSocket(ctx->io.platClientFd);
        ctx->io.platClientFd = FWTPM_INVALID_FD;
    }
    if (ctx->io.listenFd != FWTPM_INVALID_FD) {
        CloseSocket(ctx->io.listenFd);
        ctx->io.listenFd = FWTPM_INVALID_FD;
    }
    if (ctx->io.platListenFd != FWTPM_INVALID_FD) {
        CloseSocket(ctx->io.platListenFd);
        ctx->io.platListenFd = FWTPM_INVALID_FD;
    }
#ifdef _WIN32
    WSACleanup();
#endif
#endif /* !WOLFTPM_FWTPM_TIS */
}

int FWTPM_IO_ServerLoop(FWTPM_CTX* ctx)
{
#ifndef WOLFTPM_FWTPM_TIS
    int rc = TPM_RC_SUCCESS;
    fd_set readFds;
    int maxFd;
    SOCKET_T cmdFd = FWTPM_INVALID_FD;   /* active command client fd */
    SOCKET_T platFd = FWTPM_INVALID_FD;  /* active platform client fd */
    struct timeval tv;
    int selRc;
#ifndef _WIN32
    struct sigaction sa;
#endif
#endif

    if (ctx == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLFTPM_FWTPM_TIS
    return FWTPM_TIS_ServerLoop(ctx);
#else
    ctx->running = 1;

#ifndef _WIN32
    /* Ignore SIGPIPE so write to closed socket returns error instead
     * of killing the process */
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGPIPE, &sa, NULL);
#endif

    /* Multiplexed select loop: handles listen sockets AND active client fds
     * simultaneously.  This is required because the mssim TCTI opens both
     * port 2321 (command) and port 2322 (platform) concurrently and keeps
     * the command connection open while sending POWER_ON on the platform port.
     * A sequential accept/handle loop would deadlock here. */
    while (ctx->running) {
        /* Propagate async stop request into ctx state from normal
         * control flow (signal handler only sets the volatile flag). */
        if (g_stopRequested) {
            ctx->running = 0;
            break;
        }
        FD_ZERO(&readFds);
        FD_SET(ctx->io.listenFd, &readFds);
        FD_SET(ctx->io.platListenFd, &readFds);
        maxFd = ctx->io.listenFd;
        if (ctx->io.platListenFd > maxFd)
            maxFd = ctx->io.platListenFd;

        /* Watch active client connections for incoming data */
        if (cmdFd != FWTPM_INVALID_FD) {
            FD_SET(cmdFd, &readFds);
            if (cmdFd > maxFd) maxFd = cmdFd;
        }
        if (platFd != FWTPM_INVALID_FD) {
            FD_SET(platFd, &readFds);
            if (platFd > maxFd) maxFd = platFd;
        }

        tv.tv_sec = 30;
        tv.tv_usec = 0;
        selRc = select(maxFd + 1, &readFds, NULL, NULL, &tv);
        if (selRc < 0) {
        #ifdef _WIN32
            if (WSAGetLastError() == WSAEINTR) continue;
        #else
            if (errno == EINTR) continue;
        #endif
        #ifdef DEBUG_WOLFTPM
            printf("fwTPM: select error\n");
        #endif
            rc = TPM_RC_FAILURE;
            break;
        }
        if (selRc == 0) {
            continue; /* timeout — recheck ctx->running */
        }

        /* Accept new platform connection */
        if (FD_ISSET(ctx->io.platListenFd, &readFds)) {
            SOCKET_T newFd = accept(ctx->io.platListenFd, NULL, NULL);
            if (newFd != FWTPM_INVALID_FD) {
                if (platFd != FWTPM_INVALID_FD) {
                #ifdef DEBUG_WOLFTPM
                    printf("fwTPM: platform connection replaced\n");
                #endif
                    CloseSocket(platFd);
                }
                platFd = newFd;
            }
        }

        /* Accept new command connection */
        if (FD_ISSET(ctx->io.listenFd, &readFds)) {
            SOCKET_T newFd = accept(ctx->io.listenFd, NULL, NULL);
            if (newFd != FWTPM_INVALID_FD) {
                if (cmdFd != FWTPM_INVALID_FD) {
                #ifdef DEBUG_WOLFTPM
                    printf("fwTPM: command connection replaced\n");
                #endif
                    CloseSocket(cmdFd);
                }
                cmdFd = newFd;
            }
        }

        /* Handle one message from active platform client */
        if (platFd != FWTPM_INVALID_FD && FD_ISSET(platFd, &readFds)) {
            if (HandlePlatformCommand(ctx, platFd) != TPM_RC_SUCCESS) {
                CloseSocket(platFd);
                platFd = FWTPM_INVALID_FD;
            }
        }

        /* Handle one message from active command client */
        if (cmdFd != FWTPM_INVALID_FD && FD_ISSET(cmdFd, &readFds)) {
            if (HandleCommandConnection(ctx, cmdFd) != TPM_RC_SUCCESS) {
                CloseSocket(cmdFd);
                cmdFd = FWTPM_INVALID_FD;
            }
        }
    }

    if (cmdFd != FWTPM_INVALID_FD)  CloseSocket(cmdFd);
    if (platFd != FWTPM_INVALID_FD) CloseSocket(platFd);

    return rc;
#endif /* !WOLFTPM_FWTPM_TIS */
}

#endif /* WOLFTPM_FWTPM */
