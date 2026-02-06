/* spdm_demo.c
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

/* SPDM Secure Session Demo
 *
 * Demonstrates establishing an SPDM secure session with a TPM
 * and running TPM commands over the encrypted channel.
 *
 * Targets: Nuvoton NPCT75x (Fw 7.2+) connected via SPI
 *
 * Usage:
 *   ./spdm_demo --enable       Enable SPDM on TPM (requires reset)
 *   ./spdm_demo --status       Query SPDM status
 *   ./spdm_demo --connect      Establish SPDM session and run test command
 *   ./spdm_demo --lock         Lock SPDM-only mode
 *   ./spdm_demo --unlock       Unlock SPDM-only mode
 *   ./spdm_demo --all          Run full demo sequence
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_wrap.h>

#ifndef WOLFTPM2_NO_WOLFCRYPT
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/kdf.h>
#include <wolfssl/wolfcrypt/aes.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Socket includes for TCP transport to libspdm emulator */
#ifdef __linux__
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <netinet/tcp.h>  /* TCP_NODELAY */
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <errno.h>
    #define SPDM_EMU_SOCKET_SUPPORT
    #define SPDM_EMU_DEFAULT_PORT 2323  /* DEFAULT_SPDM_PLATFORM_PORT (MCTP) */
    #define SPDM_EMU_DEFAULT_HOST "127.0.0.1"
    /* Transport types for libspdm emulator socket protocol */
    #ifndef SOCKET_TRANSPORT_TYPE_MCTP
        #define SOCKET_TRANSPORT_TYPE_MCTP 0x00000001
    #endif
    #ifndef SOCKET_TRANSPORT_TYPE_TCP
        #define SOCKET_TRANSPORT_TYPE_TCP  0x00000003
    #endif
#endif

#ifndef WOLFTPM2_NO_WRAPPER

#include <hal/tpm_io.h>
#include <examples/tpm_test.h>

#ifdef WOLFTPM_SPDM

#include <wolftpm/tpm2_spdm.h>

#include <wolfspdm/spdm.h>

#ifndef WOLFTPM2_NO_WOLFCRYPT
    #include <wolfssl/wolfcrypt/ecc.h>
    #include <wolfssl/wolfcrypt/random.h>
#endif

/* -------------------------------------------------------------------------- */
/* Unified SPDM I/O Layer
 *
 * Single I/O callback that handles both:
 * - TCP transport to libspdm emulator (--emu mode)
 * - TPM TIS transport to Nuvoton hardware (--connect mode)
 *
 * The callback gates internally based on the transport mode set in context.
 * -------------------------------------------------------------------------- */

/* Transport modes for unified I/O callback */
typedef enum {
    SPDM_IO_MODE_NONE = 0,  /* Not configured */
    SPDM_IO_MODE_TCP  = 1,  /* TCP socket to libspdm emulator */
    SPDM_IO_MODE_TPM  = 2   /* TPM TIS (SPI) to Nuvoton hardware */
} SPDM_IO_MODE;

/* Unified I/O context - passed as userCtx to wolfSPDM */
typedef struct {
    SPDM_IO_MODE mode;
    /* TCP fields (for emulator) */
    int sockFd;
    int isSecured;
    /* TPM fields (for Nuvoton hardware) */
    WOLFTPM2_DEV* tpmDev;
} SPDM_IO_CTX;

/* Global unified I/O context */
static SPDM_IO_CTX g_ioCtx;

/******************************************************************************/
/* --- SPDM Demo --- */
/******************************************************************************/

/* Forward declarations */
int TPM2_SPDM_Demo(void* userCtx, int argc, char *argv[]);

static void usage(void)
{
    printf("SPDM Secure Session Demo\n");
    printf("Demonstrates SPDM secure communication with Nuvoton NPCT75x\n");
    printf("\n");
    printf("Usage: spdm_demo [options]\n");
    printf("Options:\n");
    printf("  --enable       Enable SPDM on TPM via NTC2_PreConfig\n");
    printf("  --status       Query SPDM status from TPM\n");
    printf("  --get-pubkey   Get TPM's SPDM-Identity public key\n");
    printf("  --connect      Establish SPDM session and run test command\n");
    printf("  --lock         Lock SPDM-only mode\n");
    printf("  --unlock       Unlock SPDM-only mode\n");
    printf("  --all          Run full demo sequence\n");
#ifdef SPDM_EMU_SOCKET_SUPPORT
    printf("  --emu          Test SPDM with libspdm emulator (TCP)\n");
    printf("  --host <addr>  Emulator IP address (default: 127.0.0.1)\n");
    printf("  --port <num>   Emulator port (default: 2323)\n");
#endif
    printf("  -h, --help     Show this help message\n");
    printf("\n");
    printf("Nuvoton Hardware Mode (--enable, --connect, etc.):\n");
    printf("  - Requires Nuvoton NPCT75x TPM with Fw 7.2+ via SPI\n");
    printf("  - Built with: ./configure --enable-spdm --enable-nuvoton\n");
#ifdef SPDM_EMU_SOCKET_SUPPORT
    printf("\n");
    printf("Emulator Mode (--emu):\n");
    printf("  - Tests SPDM 1.2 protocol with libspdm responder emulator\n");
    printf("  - Built with: ./configure --enable-spdm --with-wolfspdm=PATH\n");
    printf("  - Start emulator: ./spdm_responder_emu\n");
    printf("  - Run test: ./spdm_demo --emu\n");
#endif
}

/* -------------------------------------------------------------------------- */
/* Unified I/O Callback Implementation
 * -------------------------------------------------------------------------- */

/* MCTP transport constants */
#define SOCKET_SPDM_COMMAND_NORMAL    0x00000001
#define MCTP_MESSAGE_TYPE_SPDM        0x05
#define MCTP_MESSAGE_TYPE_SECURED     0x06

/* Initialize I/O context for TCP mode (emulator) */
static int spdm_io_init_tcp(SPDM_IO_CTX* ioCtx, const char* host, int port)
{
    int sockFd;
    struct sockaddr_in addr;
    int optVal = 1;

    XMEMSET(ioCtx, 0, sizeof(*ioCtx));
    ioCtx->mode = SPDM_IO_MODE_NONE;
    ioCtx->sockFd = -1;

    printf("TCP: Creating socket...\n");
    fflush(stdout);
    sockFd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockFd < 0) {
        printf("TCP: Failed to create socket (%d)\n", errno);
        return -1;
    }
    printf("TCP: Socket created (fd=%d)\n", sockFd);
    fflush(stdout);

    /* Disable Nagle's algorithm for immediate send */
    setsockopt(sockFd, IPPROTO_TCP, TCP_NODELAY, &optVal, sizeof(optVal));

    XMEMSET(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        printf("TCP: Invalid address %s\n", host);
        close(sockFd);
        return -1;
    }

    printf("TCP: Calling connect()...\n");
    fflush(stdout);
    if (connect(sockFd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        printf("TCP: Failed to connect to %s:%d (%d)\n", host, port, errno);
        close(sockFd);
        return -1;
    }

    printf("TCP: Connected to %s:%d\n", host, port);
    fflush(stdout);

    ioCtx->mode = SPDM_IO_MODE_TCP;
    ioCtx->sockFd = sockFd;
    return 0;
}

#ifdef WOLFTPM_NUVOTON
/* Initialize I/O context for TPM mode (Nuvoton hardware) */
static void spdm_io_init_tpm(SPDM_IO_CTX* ioCtx, WOLFTPM2_DEV* dev)
{
    XMEMSET(ioCtx, 0, sizeof(*ioCtx));
    ioCtx->mode = SPDM_IO_MODE_TPM;
    ioCtx->sockFd = -1;
    ioCtx->tpmDev = dev;
}
#endif /* WOLFTPM_NUVOTON */

/* Cleanup I/O context */
static void spdm_io_cleanup(SPDM_IO_CTX* ioCtx)
{
    if (ioCtx->mode == SPDM_IO_MODE_TCP && ioCtx->sockFd >= 0) {
        close(ioCtx->sockFd);
        ioCtx->sockFd = -1;
    }
    ioCtx->mode = SPDM_IO_MODE_NONE;
    ioCtx->tpmDev = NULL;
}

/* Internal: TCP send/receive for emulator */
static int spdm_io_tcp_exchange(SPDM_IO_CTX* ioCtx,
    const byte* txBuf, word32 txSz,
    byte* rxBuf, word32* rxSz)
{
    byte sendBuf[512];
    byte recvHdr[12];
    ssize_t sent, recvd;
    word32 respSize;
    word32 payloadSz;
    int isSecured = 0;

    if (ioCtx->sockFd < 0) {
        return -1;
    }

    /* Detect secured messages: SPDM messages start with version (0x10-0x1F),
     * secured messages start with SessionID (typically 0xFF...). */
    if (txSz >= 8 && (txBuf[0] < 0x10 || txBuf[0] > 0x1F)) {
        isSecured = 1;
    }

    /* Payload = MCTP header (1 byte) + SPDM message */
    payloadSz = 1 + txSz;
    if (12 + payloadSz > sizeof(sendBuf)) {
        return -1;
    }

    /* Build socket header: command(4,BE) + transport_type(4,BE) + size(4,BE) */
    sendBuf[0] = 0x00; sendBuf[1] = 0x00; sendBuf[2] = 0x00; sendBuf[3] = 0x01;
    sendBuf[4] = 0x00; sendBuf[5] = 0x00; sendBuf[6] = 0x00; sendBuf[7] = 0x01;
    sendBuf[8] = (byte)(payloadSz >> 24);
    sendBuf[9] = (byte)(payloadSz >> 16);
    sendBuf[10] = (byte)(payloadSz >> 8);
    sendBuf[11] = (byte)(payloadSz & 0xFF);

    /* MCTP header: 0x05 for SPDM, 0x06 for secured SPDM */
    sendBuf[12] = isSecured ? MCTP_MESSAGE_TYPE_SECURED : MCTP_MESSAGE_TYPE_SPDM;

    if (txSz > 0) {
        XMEMCPY(sendBuf + 13, txBuf, txSz);
    }

    sent = send(ioCtx->sockFd, sendBuf, 12 + payloadSz, 0);
    if (sent != (ssize_t)(12 + payloadSz)) {
        return -1;
    }

    recvd = recv(ioCtx->sockFd, recvHdr, 12, MSG_WAITALL);
    if (recvd != 12) {
        return -1;
    }

    respSize = ((word32)recvHdr[8] << 24) | ((word32)recvHdr[9] << 16) |
               ((word32)recvHdr[10] << 8) | (word32)recvHdr[11];

    if (respSize < 1 || respSize - 1 > *rxSz) {
        return -1;
    }

    /* Skip MCTP header */
    {
        byte mctpHdr;
        recvd = recv(ioCtx->sockFd, &mctpHdr, 1, MSG_WAITALL);
        if (recvd != 1) return -1;
    }

    *rxSz = respSize - 1;
    if (*rxSz > 0) {
        recvd = recv(ioCtx->sockFd, rxBuf, *rxSz, MSG_WAITALL);
        if (recvd != (ssize_t)*rxSz) return -1;
    }

    return 0;
}

/* TCG SPDM Binding tags */
#define TCG_SPDM_TAG_CLEAR   0x8101
#define TCG_SPDM_TAG_SECURED 0x8201

#ifdef WOLFTPM_NUVOTON
/* Internal: TPM TIS send/receive for Nuvoton hardware
 *
 * wolfSPDM may send either:
 * - Raw SPDM messages (standard commands like GET_VERSION)
 * - Already TCG-framed messages (vendor-defined commands like GET_PUBK)
 * - Encrypted SPDM records (session messages like FINISH)
 *
 * This function detects which format and handles accordingly:
 * - If already TCG-framed (starts with 0x8101 or 0x8201): send as-is
 * - If encrypted record (starts with session ID): wrap in TCG secured format
 * - If raw SPDM: wrap in TCG clear message format first
 */
static int spdm_io_tpm_exchange(SPDM_IO_CTX* ioCtx, WOLFSPDM_CTX* spdmCtx,
    const byte* txBuf, word32 txSz,
    byte* rxBuf, word32* rxSz)
{
    WOLFTPM2_DEV* dev = ioCtx->tpmDev;
    byte tcgTxBuf[512];  /* TCG-framed message to send */
    byte tcgRxBuf[512];  /* TCG-framed response */
    const byte* sendBuf;
    word32 sendSz;
    word32 tcgRxSz;
    int alreadyFramed = 0;
    int isEncrypted = 0;
    word32 i;
    int rc;

    if (dev == NULL) {
        printf("SPDM I/O ERROR: dev is NULL\n");
        return -1;
    }

    if (spdmCtx == NULL) {
        printf("SPDM I/O ERROR: spdmCtx is NULL\n");
        return -1;
    }

    /* Check if message is already TCG-framed (starts with tag 0x8101 or 0x8201) */
    if (txSz >= 2) {
        word16 tag = (word16)((txBuf[0] << 8) | txBuf[1]);
        if (tag == TCG_SPDM_TAG_CLEAR || tag == TCG_SPDM_TAG_SECURED) {
            alreadyFramed = 1;
        }
    }

    /* Check if message is encrypted (not a clear SPDM message)
     * Clear SPDM messages start with version byte (0x10-0x1F)
     * Encrypted messages start with session ID (first byte is low byte of reqSessionId) */
    if (!alreadyFramed && txSz >= 8) {
        /* SPDM version bytes are 0x10 (1.0), 0x11 (1.1), 0x12 (1.2), 0x13 (1.3) */
        if (txBuf[0] < 0x10 || txBuf[0] > 0x1F) {
            isEncrypted = 1;
        }
    }

    /* Print incoming message */
    printf("SPDM I/O TX (%u bytes, %s): ", txSz,
           alreadyFramed ? "TCG-framed" :
           (isEncrypted ? "encrypted" : "raw SPDM"));
    for (i = 0; i < txSz && i < 20; i++) {
        printf("%02x ", txBuf[i]);
    }
    if (txSz > 20) printf("...");
    printf("\n");

    if (alreadyFramed) {
        /* Already TCG-framed, send as-is */
        sendBuf = txBuf;
        sendSz = txSz;
        printf("  -> Already TCG-framed, sending as-is\n");
    }
    else if (isEncrypted) {
        /* Wrap TCG-format encrypted message in TCG binding header (16 bytes)
         *
         * wolfSPDM (Nuvoton mode) outputs TCG format:
         *   SessionID(4 LE) + SeqNum(8 LE) + Length(2 LE) + encrypted + tag = 14 + data
         *
         * We just add the TCG binding header (16 bytes with tag 0x8201):
         *   Tag(2 BE) + Size(4 BE) + ConnHandle(4 BE) + FIPS(2 BE) + Reserved(4)
         */
        word32 totalSz = 16 + txSz;
        word32 connHandle = 0;
        word16 fipsInd = 0;

        if (totalSz > sizeof(tcgTxBuf)) {
            printf("SPDM I/O: Encrypted message too large\n");
            return -1;
        }

        /* Get ConnectionHandle from SPDM context.
         * FipsIndicator for requests is D/C (Don't Care) per Nuvoton spec,
         * but spec example shows 0x0000 for requests. */
        if (spdmCtx != NULL) {
            connHandle = wolfSPDM_GetConnectionHandle(spdmCtx);
        }
        /* fipsInd stays 0 for requests (D/C per spec) */

        /* TCG binding header (16 bytes, all BE) */
        tcgTxBuf[0] = (byte)(TCG_SPDM_TAG_SECURED >> 8);
        tcgTxBuf[1] = (byte)(TCG_SPDM_TAG_SECURED & 0xFF);
        tcgTxBuf[2] = (byte)(totalSz >> 24);
        tcgTxBuf[3] = (byte)(totalSz >> 16);
        tcgTxBuf[4] = (byte)(totalSz >> 8);
        tcgTxBuf[5] = (byte)(totalSz & 0xFF);
        tcgTxBuf[6] = (byte)(connHandle >> 24);  /* ConnectionHandle (BE) */
        tcgTxBuf[7] = (byte)(connHandle >> 16);
        tcgTxBuf[8] = (byte)(connHandle >> 8);
        tcgTxBuf[9] = (byte)(connHandle & 0xFF);
        tcgTxBuf[10] = (byte)(fipsInd >> 8);     /* FipsIndicator (BE) */
        tcgTxBuf[11] = (byte)(fipsInd & 0xFF);
        tcgTxBuf[12] = 0; tcgTxBuf[13] = 0;      /* Reserved */
        tcgTxBuf[14] = 0; tcgTxBuf[15] = 0;

        /* Copy TCG-format encrypted SPDM record (already has 14-byte header) */
        XMEMCPY(tcgTxBuf + 16, txBuf, txSz);

        sendBuf = tcgTxBuf;
        sendSz = totalSz;

        printf("  -> Wrapped in TCG secured (%u bytes, connHandle=0x%x): ", sendSz, connHandle);
        for (i = 0; i < sendSz && i < 24; i++) {
            printf("%02x ", sendBuf[i]);
        }
        if (sendSz > 24) printf("...");
        printf("\n");

        /* Parse and display TCG header details */
        printf("  TCG Header breakdown:\n");
        printf("    Tag: 0x%02x%02x (expect 0x8201 for secured)\n", sendBuf[0], sendBuf[1]);
        printf("    Size: 0x%02x%02x%02x%02x = %u bytes\n", sendBuf[2], sendBuf[3], sendBuf[4], sendBuf[5],
            ((word32)sendBuf[2] << 24) | ((word32)sendBuf[3] << 16) |
            ((word32)sendBuf[4] << 8) | sendBuf[5]);
        printf("    ConnHandle: 0x%02x%02x%02x%02x\n", sendBuf[6], sendBuf[7], sendBuf[8], sendBuf[9]);
        printf("    FIPS: 0x%02x%02x\n", sendBuf[10], sendBuf[11]);
        printf("    Reserved: 0x%02x%02x%02x%02x\n", sendBuf[12], sendBuf[13], sendBuf[14], sendBuf[15]);
        printf("  SPDM Record (after TCG header):\n");
        printf("    SessionID: 0x%02x%02x%02x%02x (LE: req=%04x rsp=%04x)\n",
            sendBuf[16], sendBuf[17], sendBuf[18], sendBuf[19],
            sendBuf[16] | (sendBuf[17] << 8), sendBuf[18] | (sendBuf[19] << 8));
        printf("    SeqNum: 0x%02x%02x%02x%02x%02x%02x%02x%02x (LE: %llu)\n",
            sendBuf[20], sendBuf[21], sendBuf[22], sendBuf[23],
            sendBuf[24], sendBuf[25], sendBuf[26], sendBuf[27],
            (unsigned long long)((word64)sendBuf[20] | ((word64)sendBuf[21] << 8) |
            ((word64)sendBuf[22] << 16) | ((word64)sendBuf[23] << 24)));
        printf("    Length: 0x%02x%02x (LE: %u = encrypted + 16 tag)\n",
            sendBuf[28], sendBuf[29], sendBuf[28] | (sendBuf[29] << 8));
    }
    else {
        /* Wrap raw SPDM message in TCG clear message format (16-byte header) */
        int tcgTxSz = wolfSPDM_BuildTcgClearMessage(spdmCtx, txBuf, txSz,
                                                 tcgTxBuf, sizeof(tcgTxBuf));
        if (tcgTxSz < 0) {
            printf("SPDM I/O: BuildTcgClearMessage failed: %d\n", tcgTxSz);
            return tcgTxSz;
        }
        sendBuf = tcgTxBuf;
        sendSz = (word32)tcgTxSz;

        /* Print wrapped message */
        printf("  -> Wrapped in TCG (%u bytes): ", sendSz);
        for (i = 0; i < sendSz && i < 24; i++) {
            printf("%02x ", sendBuf[i]);
        }
        if (sendSz > 24) printf("...");
        printf("\n");
    }

    printf("SPDM I/O: Calling TPM2_SendRawBytes...\n");
    fflush(stdout);

    /* Send via TPM2_SendRawBytes */
    tcgRxSz = sizeof(tcgRxBuf);
    rc = TPM2_SendRawBytes(&dev->ctx, sendBuf, sendSz, tcgRxBuf, &tcgRxSz);

    printf("SPDM I/O: TPM2_SendRawBytes returned %d (0x%x)\n", rc, rc);
    fflush(stdout);

    if (rc != TPM_RC_SUCCESS) {
        printf("SPDM I/O: SendRawBytes failed: %s\n", TPM2_GetRCString(rc));
        return rc;
    }

    /* Print response */
    printf("SPDM I/O RX (%u bytes): ", tcgRxSz);
    for (i = 0; i < tcgRxSz && i < 24; i++) {
        printf("%02x ", tcgRxBuf[i]);
    }
    if (tcgRxSz > 24) printf("...");
    printf("\n");

    if (alreadyFramed) {
        /* wolfSPDM already did TCG framing, so it will parse the response.
         * Return the raw TCG response as-is. */
        if (tcgRxSz > *rxSz) {
            printf("SPDM I/O: Response too large: %u > %u\n", tcgRxSz, *rxSz);
            return -1;
        }
        XMEMCPY(rxBuf, tcgRxBuf, tcgRxSz);
        *rxSz = tcgRxSz;
        printf("  -> Returning TCG response as-is (wolfSPDM will parse)\n");
    }
    else if (isEncrypted) {
        /* For encrypted requests, response can be:
         * - SECURED (0x8201): successful response, return encrypted record for decryption
         * - CLEAR (0x8101): error response, return SPDM payload directly */
        word16 rspTag = 0;
        if (tcgRxSz >= 2) {
            rspTag = (word16)((tcgRxBuf[0] << 8) | tcgRxBuf[1]);
        }

        if (rspTag == TCG_SPDM_TAG_SECURED) {
            /* Secured response - strip TCG header, return encrypted record */
            if (tcgRxSz < 16) {
                printf("SPDM I/O: Secured response too small\n");
                return -1;
            }
            if (tcgRxSz - 16 > *rxSz) {
                printf("SPDM I/O: Secured response too large: %u > %u\n",
                       tcgRxSz - 16, *rxSz);
                return -1;
            }
            XMEMCPY(rxBuf, tcgRxBuf + 16, tcgRxSz - 16);
            *rxSz = tcgRxSz - 16;
            printf("  -> Stripped TCG header, returning encrypted record (%u bytes)\n", *rxSz);
        }
        else if (rspTag == TCG_SPDM_TAG_CLEAR) {
            /* Clear response - likely an error, extract SPDM payload */
            rc = wolfSPDM_ParseTcgClearMessage(tcgRxBuf, tcgRxSz, rxBuf, rxSz, NULL);
            if (rc < 0) {
                printf("SPDM I/O: ParseTcgClearMessage failed: %d\n", rc);
                return rc;
            }
            /* Check if it's an SPDM ERROR response */
            if (*rxSz >= 2 && rxBuf[1] == 0x7F) {  /* SPDM_ERROR */
                printf("  -> TPM returned SPDM ERROR: code=0x%02x data=0x%02x\n",
                       (*rxSz >= 3) ? rxBuf[2] : 0,
                       (*rxSz >= 4) ? rxBuf[3] : 0);
            }
            printf("  -> Extracted clear SPDM response (%u bytes)\n", *rxSz);
        }
        else {
            printf("SPDM I/O: Unknown response tag 0x%04x\n", rspTag);
            return -1;
        }
    }
    else {
        /* For clear requests, response should be CLEAR */
        rc = wolfSPDM_ParseTcgClearMessage(tcgRxBuf, tcgRxSz, rxBuf, rxSz, NULL);
        if (rc < 0) {
            printf("SPDM I/O: ParseTcgClearMessage failed: %d\n", rc);
            return rc;
        }
        printf("  -> Extracted SPDM (%u bytes): ", *rxSz);
        for (i = 0; i < *rxSz && i < 16; i++) {
            printf("%02x ", rxBuf[i]);
        }
        if (*rxSz > 16) printf("...");
        printf("\n");
    }

    return 0;
}
#endif /* WOLFTPM_NUVOTON */

/* Unified I/O callback for wolfSPDM
 * Handles both TCP (emulator) and TPM TIS (Nuvoton hardware) transports.
 * The mode is determined by ioCtx->mode set during initialization.
 *
 * For TCP (emulator): adds MCTP framing and sends over socket
 * For TPM (Nuvoton): adds TCG binding framing and sends via TIS */
static int wolfspdm_io_callback(
    WOLFSPDM_CTX* ctx,
    const byte* txBuf, word32 txSz,
    byte* rxBuf, word32* rxSz,
    void* userCtx)
{
    SPDM_IO_CTX* ioCtx = (SPDM_IO_CTX*)userCtx;

    if (ioCtx == NULL || txBuf == NULL || rxBuf == NULL || rxSz == NULL) {
        return -1;
    }

    switch (ioCtx->mode) {
        case SPDM_IO_MODE_TCP:
            /* TCP path for emulator - uses MCTP framing */
            (void)ctx; /* Not needed for TCP */
            return spdm_io_tcp_exchange(ioCtx, txBuf, txSz, rxBuf, rxSz);

        case SPDM_IO_MODE_TPM:
#ifdef WOLFTPM_NUVOTON
            /* TPM TIS path for Nuvoton - uses TCG binding framing */
            return spdm_io_tpm_exchange(ioCtx, ctx, txBuf, txSz, rxBuf, rxSz);
#else
            printf("SPDM I/O: TPM mode requires --enable-nuvoton\n");
            (void)ctx;
            return -1;
#endif /* WOLFTPM_NUVOTON */

        case SPDM_IO_MODE_NONE:
        default:
            printf("SPDM I/O: Invalid mode %d\n", ioCtx->mode);
            return -1;
    }
}

/* -------------------------------------------------------------------------- */
/* Nuvoton-Specific Demo Functions
 * -------------------------------------------------------------------------- */

#ifdef WOLFSPDM_NUVOTON
static int demo_enable(WOLFTPM2_DEV* dev)
{
    int rc;

    printf("\n=== Enable SPDM on TPM ===\n");
    printf("Sending NTC2_PreConfig to enable SPDM (CFG_H bit 1 = 0)...\n");

    rc = wolfTPM2_SpdmEnable(dev);
    if (rc == 0) {
        printf("  SUCCESS: SPDM is enabled on this TPM (was already enabled "
               "or just configured).\n");
        printf("  If newly enabled, TPM must be reset to take effect.\n");
    } else if (rc == (int)TPM_RC_DISABLED) {
        printf("  SPDM-only mode is active - TPM commands are blocked.\n");
        printf("  SPDM is already enabled (this is not an error).\n");
        rc = 0; /* Not an error - SPDM is already active */
    } else if (rc == TPM_RC_COMMAND_CODE) {
        printf("  NOTE: NTC2_PreConfig not supported on this TPM.\n");
        printf("  SPDM may already be enabled, or use vendor tools to enable.\n");
        rc = 0; /* Not a fatal error for demo */
    } else {
        printf("  FAILED: 0x%x: %s\n", rc, TPM2_GetRCString(rc));
    }
    return rc;
}
#endif /* WOLFSPDM_NUVOTON */

#ifdef WOLFSPDM_NUVOTON
static int demo_raw_test(WOLFTPM2_DEV* dev)
{
    int rc;
    WOLFTPM2_SPDM_CTX* spdmCtx = dev->spdmCtx;
    byte txBuf[64];
    byte rxBuf[256];
    word32 rxSz;
    int txSz;
    word32 i;

    printf("\n=== Raw SPDM GET_VERSION Test ===\n");

    if (spdmCtx == NULL || spdmCtx->spdmCtx == NULL) {
        printf("  ERROR: SPDM not initialized\n");
        return -1;
    }

    /* Build GET_VERSION SPDM request:
     * SPDMVersion=0x10 (v1.0 for initial GET_VERSION per SPDM spec),
     * Code=0x84, Param1=0, Param2=0 */
    {
        byte spdmReq[4];
        spdmReq[0] = 0x10; /* SPDM version 1.0 for GET_VERSION */
        spdmReq[1] = 0x84; /* GET_VERSION */
        spdmReq[2] = 0x00;
        spdmReq[3] = 0x00;

        /* Wrap in TCG clear message (16-byte header per Nuvoton spec) */
        txSz = wolfSPDM_BuildTcgClearMessage(spdmCtx->spdmCtx, spdmReq, 4,
            txBuf, sizeof(txBuf));
        if (txSz < 0) {
            printf("  ERROR: BuildClearMessage failed: %d\n", txSz);
            return txSz;
        }
    }

    printf("  Sending GET_VERSION (%d bytes):\n  ", txSz);
    for (i = 0; i < (word32)txSz; i++) printf("%02x ", txBuf[i]);
    printf("\n");

    /* Use wolfSPDM_GetVersion which handles the I/O internally */
    printf("  Note: Raw I/O test skipped - use wolfSPDM_GetVersion() instead\n");
    rc = wolfSPDM_GetVersion(spdmCtx->spdmCtx);
    if (rc == WOLFSPDM_SUCCESS) {
        printf("  -> VERSION response received!\n");
        rxSz = 0; /* Indicate we got a response via wolfSPDM */
    } else {
        printf("  ERROR: wolfSPDM_GetVersion failed: %d\n", rc);
        return rc;
    }

    (void)rxBuf;
    (void)rxSz;
    return 0;
}
#endif /* WOLFSPDM_NUVOTON */

#ifdef WOLFSPDM_NUVOTON
static int demo_status(WOLFTPM2_DEV* dev)
{
    int rc;
    WOLFSPDM_NUVOTON_STATUS status;

    printf("\n=== SPDM Status (GET_STS_ vendor command) ===\n");

    /* Initialize I/O context for TPM mode */
    spdm_io_init_tpm(&g_ioCtx, dev);

    /* Set I/O callback for wolfSPDM */
    rc = wolfSPDM_SetIO(dev->spdmCtx->spdmCtx, wolfspdm_io_callback, &g_ioCtx);
    if (rc != 0) {
        printf("  ERROR: Failed to set I/O callback: %d\n", rc);
        return rc;
    }

    /* Enable debug for verbose output */
    wolfSPDM_SetDebug(dev->spdmCtx->spdmCtx, 1);

    XMEMSET(&status, 0, sizeof(status));
    rc = wolfTPM2_SpdmGetStatus(dev, &status);
    if (rc == 0) {
        printf("  SPDM Enabled:      %s\n", status.spdmEnabled ? "Yes" : "No");
        printf("  SPDM Spec Version: %u.%u", status.specVersionMajor,
               status.specVersionMinor);
        if (status.specVersionMajor == 0 && status.specVersionMinor == 1) {
            printf(" (SPDM 1.1)\n");
        } else if (status.specVersionMajor == 0 && status.specVersionMinor == 3) {
            printf(" (SPDM 1.3)\n");
        } else if (status.specVersionMajor == 1 && status.specVersionMinor == 3) {
            printf(" (SPDM 1.3 alt format)\n");
        } else {
            printf("\n");
        }
        printf("  SPDM-Only Locked:  %s\n", status.spdmOnlyLocked ? "YES (TPM commands blocked)" : "No");
        printf("  Session Active:    %s\n", status.sessionActive ? "Yes" : "Unknown");

        if (status.spdmOnlyLocked) {
            printf("\n  NOTE: TPM is in SPDM-only mode. Standard TPM commands will\n");
            printf("        return TPM_RC_DISABLED until SPDM session is established\n");
            printf("        and --unlock is called.\n");
        }
    } else {
        printf("  FAILED to get status: 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        printf("  Note: GET_STS requires SPDM to be enabled on the TPM\n");
    }
    return rc;
}
#endif /* WOLFSPDM_NUVOTON */

#ifdef WOLFSPDM_NUVOTON
static int demo_get_pubkey(WOLFTPM2_DEV* dev)
{
    int rc;
    byte pubKey[128];
    word32 pubKeySz = sizeof(pubKey);
    word32 i;

    printf("\n=== Get TPM SPDM-Identity Public Key ===\n");

    /* Initialize I/O context for TPM mode */
    spdm_io_init_tpm(&g_ioCtx, dev);

    /* Set I/O callback for wolfSPDM */
    rc = wolfSPDM_SetIO(dev->spdmCtx->spdmCtx, wolfspdm_io_callback, &g_ioCtx);
    if (rc != 0) {
        printf("  ERROR: Failed to set I/O callback: %d\n", rc);
        return rc;
    }

    /* Enable debug for verbose output */
    wolfSPDM_SetDebug(dev->spdmCtx->spdmCtx, 1);

    rc = wolfTPM2_SpdmGetPubKey(dev, pubKey, &pubKeySz);
    if (rc == 0) {
        printf("  SUCCESS: Got TPM public key (%d bytes)\n", (int)pubKeySz);
        printf("  Key (hex): ");
        for (i = 0; i < pubKeySz && i < 32; i++) {
            printf("%02x", pubKey[i]);
        }
        if (pubKeySz > 32) {
            printf("...");
        }
        printf("\n");
    } else {
        printf("  FAILED: 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        printf("  Note: GET_PUB_KEY requires SPDM to be enabled\n");
    }
    return rc;
}

static int demo_connect(WOLFTPM2_DEV* dev)
{
    int rc;
#ifndef WOLFTPM2_NO_WOLFCRYPT
    /* Generate test ECDSA P-384 keypair for mutual authentication */
    ecc_key hostKey;
    WC_RNG rng;
    byte hostPrivKey[48];  /* Raw 48-byte scalar */
    word32 hostPrivKeySz = sizeof(hostPrivKey);
    byte hostPubKeyX[48], hostPubKeyY[48];
    word32 xSz = sizeof(hostPubKeyX), ySz = sizeof(hostPubKeyY);
    /* TPMT_PUBLIC structure for host's public key (120 bytes) */
    byte hostPubKeyTPMT[120];
    word32 hostPubKeyTPMTSz = 0;
#endif

    printf("\n=== SPDM Connect (Full Handshake) ===\n");
    printf("Establishing SPDM secure session...\n");
    printf("  Steps: GET_VERSION -> GET_PUB_KEY -> KEY_EXCHANGE -> "
           "GIVE_PUB_KEY -> FINISH\n\n");

#ifndef WOLFTPM2_NO_WOLFCRYPT
    /* Generate test keypair for SPDM mutual authentication */
    printf("Generating host ECDSA P-384 keypair for mutual auth...\n");

    rc = wc_InitRng(&rng);
    if (rc != 0) {
        printf("  ERROR: wc_InitRng failed: %d\n", rc);
        return rc;
    }

    rc = wc_ecc_init(&hostKey);
    if (rc != 0) {
        wc_FreeRng(&rng);
        printf("  ERROR: wc_ecc_init failed: %d\n", rc);
        return rc;
    }

    rc = wc_ecc_make_key_ex(&rng, 48, &hostKey, ECC_SECP384R1);
    if (rc != 0) {
        wc_ecc_free(&hostKey);
        wc_FreeRng(&rng);
        printf("  ERROR: wc_ecc_make_key failed: %d\n", rc);
        return rc;
    }

    /* Export private key (raw scalar) */
    rc = wc_ecc_export_private_only(&hostKey, hostPrivKey, &hostPrivKeySz);
    if (rc != 0) {
        wc_ecc_free(&hostKey);
        wc_FreeRng(&rng);
        printf("  ERROR: export private key failed: %d\n", rc);
        return rc;
    }

    /* Export public key X,Y */
    rc = wc_ecc_export_public_raw(&hostKey, hostPubKeyX, &xSz,
                                   hostPubKeyY, &ySz);
    wc_ecc_free(&hostKey);
    wc_FreeRng(&rng);
    if (rc != 0) {
        printf("  ERROR: export public key failed: %d\n", rc);
        return rc;
    }

    /* Build TPMT_PUBLIC structure matching Nuvoton spec page 24:
     * type(2) + nameAlg(2) + objectAttr(4) + authPolicy(2+0) +
     * symmetric(2) + scheme(2+2) + curveID(2) + kdf(2) + unique(2+48+2+48) = 120 bytes
     * Note: objectAttributes must be 0x00040000 per Nuvoton spec */
    {
        byte* p = hostPubKeyTPMT;
        /* type = TPM_ALG_ECC (0x0023) */
        *p++ = 0x00; *p++ = 0x23;
        /* nameAlg = TPM_ALG_SHA384 (0x000C) */
        *p++ = 0x00; *p++ = 0x0C;
        /* objectAttributes = 0x00040000 (sign only, per Nuvoton spec page 24) */
        *p++ = 0x00; *p++ = 0x04; *p++ = 0x00; *p++ = 0x00;
        /* authPolicy size = 0 */
        *p++ = 0x00; *p++ = 0x00;
        /* parameters.eccDetail.symmetric = TPM_ALG_NULL (0x0010) */
        *p++ = 0x00; *p++ = 0x10;
        /* parameters.eccDetail.scheme = TPM_ALG_ECDSA (0x0018) */
        *p++ = 0x00; *p++ = 0x18;
        /* parameters.eccDetail.scheme.hashAlg = SHA384 (0x000C) */
        *p++ = 0x00; *p++ = 0x0C;
        /* parameters.eccDetail.curveID = TPM_ECC_NIST_P384 (0x0004) */
        *p++ = 0x00; *p++ = 0x04;
        /* parameters.eccDetail.kdf = TPM_ALG_NULL (0x0010) */
        *p++ = 0x00; *p++ = 0x10;
        /* unique.x size = 48 */
        *p++ = 0x00; *p++ = 0x30;
        /* unique.x data */
        XMEMCPY(p, hostPubKeyX, 48); p += 48;
        /* unique.y size = 48 */
        *p++ = 0x00; *p++ = 0x30;
        /* unique.y data */
        XMEMCPY(p, hostPubKeyY, 48); p += 48;
        hostPubKeyTPMTSz = (word32)(p - hostPubKeyTPMT);
    }

    printf("  Generated host key (TPMT_PUBLIC: %u bytes, private: %u bytes)\n",
           hostPubKeyTPMTSz, hostPrivKeySz);

    /* Initialize unified I/O context for TPM mode */
    spdm_io_init_tpm(&g_ioCtx, dev);

    /* Set unified I/O callback (handles both TCP emulator and TPM TIS modes) */
    rc = wolfSPDM_SetIO(dev->spdmCtx->spdmCtx, wolfspdm_io_callback, &g_ioCtx);
    if (rc != 0) {
        printf("  ERROR: Failed to set I/O callback: %d\n", rc);
        return rc;
    }

    /* Enable debug output for TH1/ResponderVerifyData comparison */
    wolfSPDM_SetDebug(dev->spdmCtx->spdmCtx, 1);

    rc = wolfTPM2_SpdmConnectNuvoton(dev, hostPubKeyTPMT, hostPubKeyTPMTSz,
                                      hostPrivKey, hostPrivKeySz);
#else
    /* No wolfCrypt - skip mutual authentication */
    /* Initialize unified I/O context for TPM mode */
    spdm_io_init_tpm(&g_ioCtx, dev);

    /* Set unified I/O callback (handles both TCP emulator and TPM TIS modes) */
    rc = wolfSPDM_SetIO(dev->spdmCtx->spdmCtx, wolfspdm_io_callback, &g_ioCtx);
    if (rc != 0) {
        printf("  ERROR: Failed to set I/O callback: %d\n", rc);
        return rc;
    }

    /* Enable debug output for TH1/ResponderVerifyData comparison */
    wolfSPDM_SetDebug(dev->spdmCtx->spdmCtx, 1);

    rc = wolfTPM2_SpdmConnectNuvoton(dev, NULL, 0, NULL, 0);
#endif
    if (rc == 0) {
        printf("  SUCCESS: SPDM session established!\n");
        printf("  All TPM commands now encrypted with AES-256-GCM\n");

        /* Run a test command over the secure channel */
        printf("\n  Running TPM2_SelfTest over SPDM secure channel...\n");
        {
            SelfTest_In selfTestIn;
            selfTestIn.fullTest = YES;
            rc = TPM2_SelfTest(&selfTestIn);
            if (rc == TPM_RC_SUCCESS) {
                printf("  SUCCESS: TPM2_SelfTest passed over SPDM!\n");
            } else {
                printf("  SelfTest result: 0x%x: %s\n", rc,
                    TPM2_GetRCString(rc));
            }
        }

        /* Check connection status */
        if (wolfTPM2_SpdmIsConnected(dev)) {
            printf("  SPDM session is active\n");
        }
    } else {
        printf("  FAILED: 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        printf("  Note: Ensure SPDM is enabled and backend is configured\n");
    }
    return rc;
}

static int demo_lock(WOLFTPM2_DEV* dev, int lock)
{
    int rc;

    printf("\n=== SPDM-Only Mode: %s ===\n", lock ? "LOCK" : "UNLOCK");

    rc = wolfTPM2_SpdmSetOnlyMode(dev, lock);
    if (rc == 0) {
        printf("  SUCCESS: SPDM-only mode %s\n",
            lock ? "LOCKED" : "UNLOCKED");
        if (lock) {
            printf("  WARNING: TPM will only accept commands over SPDM!\n");
        }
    } else {
        printf("  FAILED: 0x%x: %s\n", rc, TPM2_GetRCString(rc));
    }
    return rc;
}

static int demo_all(WOLFTPM2_DEV* dev)
{
    int rc;
    int failures = 0;

    printf("\n========================================\n");
    printf("SPDM Secure Session Full Demo\n");
    printf("========================================\n");
    printf("Target: Nuvoton NPCT75x via SPI\n");
    printf("Algorithm Set B: ECDSA P-384, SHA-384, ECDHE P-384, AES-256-GCM\n");
    printf("========================================\n");

    /* Step 1: Check/Enable SPDM */
    rc = demo_enable(dev);
    if (rc != 0) failures++;

    /* Step 2: Query Status */
    rc = demo_status(dev);
    if (rc != 0) failures++;

    /* Step 3: Get TPM public key */
    rc = demo_get_pubkey(dev);
    if (rc != 0) failures++;

    /* Step 4: Connect (full handshake) */
    rc = demo_connect(dev);
    if (rc != 0) failures++;

    /* Step 5: Disconnect */
    if (wolfTPM2_SpdmIsConnected(dev)) {
        rc = wolfTPM2_SpdmDisconnect(dev);
        if (rc == 0) {
            printf("\n  SPDM session disconnected\n");
        } else {
            printf("\n  Disconnect failed: 0x%x\n", rc);
            failures++;
        }
    }

    printf("\n========================================\n");
    printf("Demo Summary\n");
    printf("========================================\n");
    if (failures == 0) {
        printf("ALL STEPS COMPLETED SUCCESSFULLY\n");
    } else {
        printf("%d STEP(S) FAILED\n", failures);
    }
    printf("========================================\n");

    return (failures == 0) ? 0 : 1;
}
#endif /* WOLFSPDM_NUVOTON */

/* -------------------------------------------------------------------------- */
/* Standard SPDM over TCP (for libspdm emulator testing) */
/* -------------------------------------------------------------------------- */

#ifdef SPDM_EMU_SOCKET_SUPPORT

/* SPDM emulator test using wolfSPDM library
 * Connects to libspdm responder emulator via TCP and performs full SPDM 1.2 handshake
 * Uses the unified I/O callback (same as Nuvoton hardware mode) */
static int demo_emulator(const char* host, int port)
{
    WOLFSPDM_CTX* ctx;
    int rc;

    printf("\n=== SPDM Emulator Test (wolfSPDM -> libspdm) ===\n");
    printf("Connecting to %s:%d...\n", host, port);

    /* Initialize unified I/O context for TCP mode (emulator) */
    rc = spdm_io_init_tcp(&g_ioCtx, host, port);
    if (rc < 0) {
        printf("Failed to connect to emulator\n");
        printf("Make sure spdm_responder_emu is running:\n");
        printf("  ./spdm_responder_emu --trans TCP\n");
        return rc;
    }

    /* Create wolfSPDM context */
    ctx = wolfSPDM_New();
    if (ctx == NULL) {
        printf("ERROR: wolfSPDM_New() failed\n");
        spdm_io_cleanup(&g_ioCtx);
        return -1;
    }

    /* Initialize wolfSPDM */
    rc = wolfSPDM_Init(ctx);
    if (rc != WOLFSPDM_SUCCESS) {
        printf("ERROR: wolfSPDM_Init() failed: %s\n", wolfSPDM_GetErrorString(rc));
        wolfSPDM_Free(ctx);
        spdm_io_cleanup(&g_ioCtx);
        return rc;
    }

    /* Set unified I/O callback (handles both TCP emulator and TPM TIS modes) */
    wolfSPDM_SetIO(ctx, wolfspdm_io_callback, &g_ioCtx);
    wolfSPDM_SetDebug(ctx, 1);

    /* Full SPDM handshake - this single call replaces ~1000 lines of code!
     * Performs: GET_VERSION -> GET_CAPABILITIES -> NEGOTIATE_ALGORITHMS ->
     *           GET_DIGESTS -> GET_CERTIFICATE -> KEY_EXCHANGE -> FINISH */
    printf("\nEstablishing SPDM session...\n");
    rc = wolfSPDM_Connect(ctx);

    if (rc == WOLFSPDM_SUCCESS) {
        printf("\n=============================================\n");
        printf(" SUCCESS: SPDM Session Established!\n");
        printf(" Session ID: 0x%08x\n", wolfSPDM_GetSessionId(ctx));
        printf(" SPDM Version: 0x%02x\n", wolfSPDM_GetVersion_Negotiated(ctx));
        printf("=============================================\n");
    } else {
        printf("\nERROR: wolfSPDM_Connect() failed: %s (%d)\n",
               wolfSPDM_GetErrorString(rc), rc);
    }

    /* Cleanup */
    wolfSPDM_Free(ctx);
    spdm_io_cleanup(&g_ioCtx);

    return (rc == WOLFSPDM_SUCCESS) ? 0 : rc;
}


#endif /* SPDM_EMU_SOCKET_SUPPORT */

int TPM2_SPDM_Demo(void* userCtx, int argc, char *argv[])
{
    int rc;
    WOLFTPM2_DEV dev;
    int i;
#ifdef SPDM_EMU_SOCKET_SUPPORT
    const char* emuHost = SPDM_EMU_DEFAULT_HOST;
    int emuPort = SPDM_EMU_DEFAULT_PORT;
    int useEmulator = 0;
#endif

    if (argc <= 1) {
        usage();
        return 0;
    }

    for (i = 1; i < argc; i++) {
        if (XSTRCMP(argv[i], "-h") == 0 ||
            XSTRCMP(argv[i], "--help") == 0) {
            usage();
            return 0;
        }
#ifdef SPDM_EMU_SOCKET_SUPPORT
        else if (XSTRCMP(argv[i], "--emu") == 0) {
            useEmulator = 1;
        }
        else if (XSTRCMP(argv[i], "--host") == 0 && i + 1 < argc) {
            emuHost = argv[++i];
        }
        else if (XSTRCMP(argv[i], "--port") == 0 && i + 1 < argc) {
            emuPort = atoi(argv[++i]);
        }
#endif
    }

#ifdef SPDM_EMU_SOCKET_SUPPORT
    /* Handle --emu mode (TCP to emulator, no TPM needed) */
    if (useEmulator) {
        printf("Entering emulator mode...\n");
        fflush(stdout);
        return demo_emulator(emuHost, emuPort);
    }
#endif

    /* Init the TPM2 device.
     * When SPDM is enabled on Nuvoton TPMs, TPM2_Startup may return
     * TPM_RC_DISABLED because the TPM expects SPDM-only communication.
     * wolfTPM2_Init tolerates this when built with WOLFTPM_SPDM -
     * SPDM commands work over raw SPI regardless of TPM startup state. */
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != 0) {
        printf("wolfTPM2_Init failed: 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        return rc;
    }

    /* Initialize SPDM support */
    rc = wolfTPM2_SpdmInit(&dev);
    if (rc != 0) {
        printf("wolfTPM2_SpdmInit failed: 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        printf("Ensure wolfTPM is built with --enable-spdm and a backend\n");
        printf("(e.g., --with-libspdm=PATH)\n");
        wolfTPM2_Cleanup(&dev);
        return rc;
    }

    /* Process command-line options */
    for (i = 1; i < argc; i++) {
#ifdef WOLFSPDM_NUVOTON
        if (XSTRCMP(argv[i], "--all") == 0) {
            rc = demo_all(&dev);
            break;
        }
        else if (XSTRCMP(argv[i], "--enable") == 0) {
            rc = demo_enable(&dev);
            if (rc != 0) break;
        }
        else if (XSTRCMP(argv[i], "--status") == 0) {
            rc = demo_status(&dev);
            if (rc != 0) break;
        }
        else if (XSTRCMP(argv[i], "--get-pubkey") == 0) {
            rc = demo_get_pubkey(&dev);
            if (rc != 0) break;
        }
        else if (XSTRCMP(argv[i], "--connect") == 0) {
            rc = demo_connect(&dev);
            if (rc != 0) break;
        }
        else if (XSTRCMP(argv[i], "--lock") == 0) {
            rc = demo_lock(&dev, 1);
            if (rc != 0) break;
        }
        else if (XSTRCMP(argv[i], "--unlock") == 0) {
            rc = demo_lock(&dev, 0);
            if (rc != 0) break;
        }
        else if (XSTRCMP(argv[i], "--raw-test") == 0) {
            rc = demo_raw_test(&dev);
            if (rc != 0) break;
        }
        else
#endif /* WOLFSPDM_NUVOTON */
        {
            printf("Unknown option: %s\n", argv[i]);
            usage();
            rc = BAD_FUNC_ARG;
            break;
        }
    }

    /* Cleanup SPDM */
    wolfTPM2_SpdmCleanup(&dev);

    wolfTPM2_Cleanup(&dev);
    return rc;
}

/******************************************************************************/
/* --- END SPDM Demo --- */
/******************************************************************************/

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = -1;

#ifndef WOLFTPM2_NO_WRAPPER
    rc = TPM2_SPDM_Demo(NULL, argc, argv);
#else
    printf("Wrapper code not compiled in\n");
    (void)argc;
    (void)argv;
#endif

    return (rc == 0) ? 0 : 1;
}
#endif /* !NO_MAIN_DRIVER */

#endif /* WOLFTPM_SPDM */
#endif /* !WOLFTPM2_NO_WRAPPER */