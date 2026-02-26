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
 *   ./spdm_demo --disable      Disable SPDM on TPM (requires reset)
 *   ./spdm_demo --status       Query SPDM status
 *   ./spdm_demo --connect      Establish SPDM session and run test command
 *   ./spdm_demo --lock         Lock SPDM-only mode
 *   ./spdm_demo --unlock       Unlock SPDM-only mode
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_wrap.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Socket includes for TCP transport to libspdm emulator */
#ifdef WOLFTPM_SWTPM
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <netinet/tcp.h>  /* TCP_NODELAY */
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <errno.h>
    #define SPDM_EMU_DEFAULT_PORT 2323  /* DEFAULT_SPDM_PLATFORM_PORT (MCTP) */
    #define SPDM_EMU_DEFAULT_HOST "127.0.0.1"
#endif

#ifndef WOLFTPM2_NO_WRAPPER

#include <hal/tpm_io.h>
#include <examples/tpm_test.h>

#ifdef WOLFTPM_SPDM

#include <wolftpm/tpm2_spdm.h>

#include <wolfspdm/spdm.h>

/* -------------------------------------------------------------------------- */
/* Unified SPDM I/O Layer
 *
 * Single I/O callback that handles both:
 * - TCP transport to libspdm emulator (--emu mode)
 * - TPM TIS transport to Nuvoton hardware (--connect mode)
 *
 * The callback gates internally based on the transport mode set in context.
 * -------------------------------------------------------------------------- */

#ifdef WOLFTPM_SWTPM
/* Transport modes for I/O callback */
typedef enum {
    SPDM_IO_MODE_NONE = 0,  /* Not configured */
    SPDM_IO_MODE_TCP  = 1   /* TCP socket to libspdm emulator */
} SPDM_IO_MODE;

/* I/O context for TCP emulator mode */
typedef struct {
    SPDM_IO_MODE mode;
    int sockFd;
    int isSecured;
} SPDM_IO_CTX;

/* Global I/O context for emulator */
static SPDM_IO_CTX g_ioCtx;
#endif /* WOLFTPM_SWTPM */

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
    printf("  --disable      Disable SPDM on TPM via NTC2_PreConfig\n");
    printf("  --status       Query SPDM status from TPM\n");
    printf("  --get-pubkey   Get TPM's SPDM-Identity public key\n");
    printf("  --connect      Establish SPDM session and run test command\n");
    printf("  --lock         Lock SPDM-only mode\n");
    printf("  --unlock       Unlock SPDM-only mode\n");
#ifdef WOLFTPM_SWTPM
    printf("  --emu          Test SPDM with libspdm emulator (TCP)\n");
    printf("  --meas         Retrieve and verify device measurements (--emu)\n");
    printf("  --no-sig       Skip signature verification (use with --meas)\n");
    printf("  --challenge    Challenge authentication (sessionless, --emu)\n");
    printf("  --heartbeat    Session heartbeat keep-alive (--emu)\n");
    printf("  --key-update   Session key rotation (--emu)\n");
    printf("  --host <addr>  Emulator IP address (default: 127.0.0.1)\n");
    printf("  --port <num>   Emulator port (default: 2323)\n");
#endif
    printf("  -h, --help     Show this help message\n");
    printf("\n");
    printf("Nuvoton Hardware Mode (--enable, --connect, etc.):\n");
    printf("  - Requires Nuvoton NPCT75x TPM with Fw 7.2+ via SPI\n");
    printf("  - Built with: ./configure --enable-spdm --enable-nuvoton\n");
#ifdef WOLFTPM_SWTPM
    printf("\n");
    printf("Emulator Mode (--emu):\n");
    printf("  - Tests SPDM 1.2 protocol with libspdm responder emulator\n");
    printf("  - Built with: ./configure --enable-spdm --enable-swtpm\n");
    printf("  - Start emulator: ./spdm_responder_emu\n");
    printf("  - Run test: ./spdm_demo --emu\n");
#endif
}

/* -------------------------------------------------------------------------- */
/* Unified I/O Callback Implementation
 * -------------------------------------------------------------------------- */

#ifdef WOLFTPM_SWTPM
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

    sockFd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockFd < 0) {
        printf("TCP: Failed to create socket (%d)\n", errno);
        return -1;
    }

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

    if (connect(sockFd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        printf("TCP: Failed to connect to %s:%d (%d)\n", host, port, errno);
        close(sockFd);
        return -1;
    }

    ioCtx->mode = SPDM_IO_MODE_TCP;
    ioCtx->sockFd = sockFd;
    return 0;
}

/* Cleanup TCP I/O context */
static void spdm_io_cleanup(SPDM_IO_CTX* ioCtx)
{
    if (ioCtx->sockFd >= 0) {
        close(ioCtx->sockFd);
        ioCtx->sockFd = -1;
    }
    ioCtx->mode = SPDM_IO_MODE_NONE;
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
#endif /* WOLFTPM_SWTPM */

#ifdef WOLFTPM_SWTPM
/* I/O callback for TCP mode (emulator only).
 * Nuvoton TPM mode uses the built-in library callback via
 * wolfTPM2_SpdmSetNuvotonIo(). */
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

    (void)ctx;

    if (ioCtx->mode == SPDM_IO_MODE_TCP) {
        return spdm_io_tcp_exchange(ioCtx, txBuf, txSz, rxBuf, rxSz);
    }

    return -1;
}
#endif /* WOLFTPM_SWTPM */

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

static int demo_disable(WOLFTPM2_DEV* dev)
{
    int rc;

    printf("\n=== Disable SPDM on TPM ===\n");
    printf("Sending NTC2_PreConfig to disable SPDM (CFG_H bit 1 = 1)...\n");

    rc = wolfTPM2_SpdmDisable(dev);
    if (rc == 0) {
        printf("  SUCCESS: SPDM is disabled on this TPM.\n");
        printf("  TPM must be reset for changes to take effect.\n");
    } else if (rc == (int)TPM_RC_DISABLED) {
        printf("  SPDM-only mode is active - cannot disable via cleartext.\n");
        printf("  Unlock SPDM-only mode first, then reset and disable.\n");
    } else if (rc == TPM_RC_COMMAND_CODE) {
        printf("  NOTE: NTC2_PreConfig not supported on this TPM.\n");
        rc = 0;
    } else {
        printf("  FAILED: 0x%x: %s\n", rc, TPM2_GetRCString(rc));
    }
    return rc;
}
#endif /* WOLFSPDM_NUVOTON */

#ifdef WOLFSPDM_NUVOTON
static int demo_status(WOLFTPM2_DEV* dev)
{
    int rc;
    WOLFSPDM_NUVOTON_STATUS status;

    printf("\n=== SPDM Status (GET_STS_ vendor command) ===\n");

    XMEMSET(&status, 0, sizeof(status));
    rc = wolfTPM2_SpdmGetStatus(dev, &status);
    if (rc == 0) {
        int isConnected = wolfTPM2_SpdmIsConnected(dev);
        byte negVer = wolfSPDM_GetNegotiatedVersion(dev->spdmCtx->spdmCtx);

        printf("  SPDM Enabled:      %s\n", status.spdmEnabled ? "Yes" : "No");
        printf("  SPDM-Only Locked:  %s\n",
            status.spdmOnlyLocked ? "YES (TPM commands blocked)" : "No");
        printf("  Session Active:    %s\n", isConnected ? "Yes" : "No");
        if (isConnected) {
            printf("  Negotiated Ver:    SPDM %u.%u (0x%02x)\n",
                (negVer >> 4) & 0xF, negVer & 0xF, negVer);
            printf("  Session ID:        0x%08x\n",
                wolfTPM2_SpdmGetSessionId(dev));
        }
        printf("  Nuvoton Status:    v%u.%u\n",
            status.specVersionMajor, status.specVersionMinor);

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

    printf("\n=== SPDM Connect (Full Handshake) ===\n");

    /* If auto-SPDM already established a session (SPDM-only mode), skip */
    if (wolfTPM2_SpdmIsConnected(dev)) {
        printf("  SPDM session already active (auto-established)\n");
        printf("  Session ID: 0x%08x\n", wolfTPM2_SpdmGetSessionId(dev));
        return 0;
    }

    printf("Establishing SPDM secure session...\n");
    printf("  Steps: GET_VERSION -> GET_PUB_KEY -> KEY_EXCHANGE -> "
           "GIVE_PUB_KEY -> FINISH\n\n");

    /* wolfTPM2_SpdmConnectNuvoton handles everything:
     * - Auto-sets TIS I/O callback for SPI/I2C transport
     * - Auto-generates ephemeral P-384 key pair (when NULL keys passed)
     * - Sets Nuvoton mode and performs full SPDM handshake */
    rc = wolfTPM2_SpdmConnectNuvoton(dev, NULL, 0, NULL, 0);
    if (rc == 0) {
        printf("  SUCCESS: SPDM session established!\n");
        printf("  All TPM commands now encrypted with AES-256-GCM\n");

        if (wolfTPM2_SpdmIsConnected(dev)) {
            printf("  Session ID: 0x%08x\n", wolfTPM2_SpdmGetSessionId(dev));
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

#endif /* WOLFSPDM_NUVOTON */

/* -------------------------------------------------------------------------- */
/* Standard SPDM over TCP (for libspdm emulator testing) */
/* -------------------------------------------------------------------------- */

#ifdef WOLFTPM_SWTPM

#ifndef NO_WOLFSPDM_MEAS
/* Retrieve and display device measurements from an established SPDM session.
 * Calls wolfSPDM measurement APIs directly. */
static int demo_measurements(WOLFSPDM_CTX* ctx, int requestSignature)
{
    int rc, count, i;

    printf("\n=== SPDM GET_MEASUREMENTS ===\n");

    rc = wolfSPDM_GetMeasurements(ctx, SPDM_MEAS_OPERATION_ALL,
                                  requestSignature);
    if (rc == WOLFSPDM_SUCCESS) {
        printf("Measurements retrieved and signature VERIFIED\n");
    }
    else if (rc == WOLFSPDM_E_MEAS_NOT_VERIFIED) {
        printf("Measurements retrieved (not signature-verified)\n");
    }
    else if (rc == WOLFSPDM_E_MEAS_SIG_FAIL) {
        printf("WARNING: Measurement signature INVALID\n");
        return rc;
    }
    else {
        printf("ERROR: %s (%d)\n", wolfSPDM_GetErrorString(rc), rc);
        return rc;
    }

    count = wolfSPDM_GetMeasurementCount(ctx);
    printf("Measurement blocks: %d\n", count);

    for (i = 0; i < count; i++) {
        byte idx = 0, mtype = 0;
        byte val[WOLFSPDM_MAX_MEAS_VALUE_SIZE];
        word32 valSz = sizeof(val);
        int j;

        rc = wolfSPDM_GetMeasurementBlock(ctx, i, &idx, &mtype, val, &valSz);
        if (rc != WOLFSPDM_SUCCESS)
            continue;

        printf("  [%u] type=0x%02x size=%u: ", idx, mtype, valSz);
        for (j = 0; j < (int)valSz && j < 48; j++)
            printf("%02x", val[j]);
        if (valSz > 48)
            printf("...");
        printf("\n");
    }

    return 0;
}
#endif /* !NO_WOLFSPDM_MEAS */

#ifndef NO_WOLFSPDM_CHALLENGE

/* Execute an SPDM step with error reporting */
#define DEMO_STEP(name, call) do { \
    printf("  " name "...\n"); \
    rc = (call); \
    if (rc != WOLFSPDM_SUCCESS) { \
        printf("  ERROR: " name " failed: %s (%d)\n", \
               wolfSPDM_GetErrorString(rc), rc); \
        return rc; \
    } \
} while(0)

/* Perform CHALLENGE authentication (sessionless attestation).
 * Uses individual handshake steps instead of wolfSPDM_Connect() to avoid
 * establishing a full session (KEY_EXCHANGE/FINISH). */
static int demo_challenge(WOLFSPDM_CTX* ctx)
{
    int rc;

    printf("\n=== SPDM CHALLENGE (Sessionless Attestation) ===\n");

    DEMO_STEP("GET_VERSION", wolfSPDM_GetVersion(ctx));
    DEMO_STEP("GET_CAPABILITIES", wolfSPDM_GetCapabilities(ctx));
    DEMO_STEP("NEGOTIATE_ALGORITHMS", wolfSPDM_NegotiateAlgorithms(ctx));
    DEMO_STEP("GET_DIGESTS", wolfSPDM_GetDigests(ctx));
    DEMO_STEP("GET_CERTIFICATE", wolfSPDM_GetCertificate(ctx, 0));

    /* Step 6: CHALLENGE */
    printf("  CHALLENGE (slot=0, no measurement summary)...\n");
    rc = wolfSPDM_Challenge(ctx, 0, SPDM_MEAS_SUMMARY_HASH_NONE);
    if (rc == WOLFSPDM_SUCCESS) {
        printf("\n  CHALLENGE authentication PASSED\n");
    }
    else {
        printf("\n  CHALLENGE authentication FAILED: %s (%d)\n",
               wolfSPDM_GetErrorString(rc), rc);
    }

    return rc;
}
#endif /* !NO_WOLFSPDM_CHALLENGE */

/* Send HEARTBEAT over an established SPDM session */
static int demo_heartbeat(WOLFSPDM_CTX* ctx)
{
    int rc;

    printf("\n=== SPDM HEARTBEAT ===\n");

    rc = wolfSPDM_Heartbeat(ctx);
    if (rc == WOLFSPDM_SUCCESS) {
        printf("  HEARTBEAT_ACK received — session alive\n");
    }
    else {
        printf("  HEARTBEAT failed: %s (%d)\n",
               wolfSPDM_GetErrorString(rc), rc);
    }

    return rc;
}

/* Perform KEY_UPDATE to rotate session encryption keys */
static int demo_key_update(WOLFSPDM_CTX* ctx)
{
    int rc;

    printf("\n=== SPDM KEY_UPDATE ===\n");

    rc = wolfSPDM_KeyUpdate(ctx, 1); /* updateAll = 1: rotate both keys */
    if (rc == WOLFSPDM_SUCCESS) {
        printf("  KEY_UPDATE completed — new keys active\n");
    }
    else {
        printf("  KEY_UPDATE failed: %s (%d)\n",
               wolfSPDM_GetErrorString(rc), rc);
    }

    return rc;
}

/* SPDM emulator test using wolfSPDM library
 * Connects to libspdm responder emulator via TCP and performs full SPDM 1.2 handshake
 * Uses the unified I/O callback (same as Nuvoton hardware mode) */
static int demo_emulator(const char* host, int port, int doMeas,
                         int requestSignature, int doChallenge,
                         int doHeartbeat, int doKeyUpdate)
{
    WOLFSPDM_CTX* ctx;
    int rc;
#ifndef WOLFSPDM_DYNAMIC_MEMORY
    byte spdmBuf[WOLFSPDM_CTX_STATIC_SIZE];
#endif

    printf("\n=== wolfSPDM spdm-emu Test ===\n");
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
#ifdef WOLFSPDM_DYNAMIC_MEMORY
    ctx = wolfSPDM_New();
    if (ctx == NULL) {
        printf("ERROR: wolfSPDM_New() failed\n");
        spdm_io_cleanup(&g_ioCtx);
        return -1;
    }
#else
    ctx = (WOLFSPDM_CTX*)spdmBuf;
    rc = wolfSPDM_InitStatic(ctx, (int)sizeof(spdmBuf));
    if (rc != WOLFSPDM_SUCCESS) {
        printf("ERROR: wolfSPDM_InitStatic() failed: %s\n",
               wolfSPDM_GetErrorString(rc));
        spdm_io_cleanup(&g_ioCtx);
        return rc;
    }
#endif

    /* Set unified I/O callback (handles both TCP emulator and TPM TIS modes) */
    wolfSPDM_SetIO(ctx, wolfspdm_io_callback, &g_ioCtx);
#ifdef DEBUG_WOLFTPM
    wolfSPDM_SetDebug(ctx, 1);
#endif

#ifndef NO_WOLFSPDM_CHALLENGE
    /* Challenge mode: sessionless attestation (no KEY_EXCHANGE/FINISH) */
    if (doChallenge) {
        rc = demo_challenge(ctx);

        /* Cleanup */
        wolfSPDM_Free(ctx);
        spdm_io_cleanup(&g_ioCtx);
        return (rc == WOLFSPDM_SUCCESS) ? 0 : rc;
    }
#else
    (void)doChallenge;
#endif

    /* Full SPDM handshake - this single call replaces ~1000 lines of code!
     * Performs: GET_VERSION -> GET_CAPABILITIES -> NEGOTIATE_ALGORITHMS ->
     *           GET_DIGESTS -> GET_CERTIFICATE -> KEY_EXCHANGE -> FINISH */
    printf("\nEstablishing SPDM session...\n");
    rc = wolfSPDM_Connect(ctx);

    if (rc == WOLFSPDM_SUCCESS) {
        printf("\n=============================================\n");
        printf(" SUCCESS: SPDM Session Established!\n");
        printf(" Session ID: 0x%08x\n", wolfSPDM_GetSessionId(ctx));
        printf(" SPDM Version: 0x%02x\n", wolfSPDM_GetNegotiatedVersion(ctx));
        printf("=============================================\n");

        /* Heartbeat: send keep-alive over encrypted channel */
        if (doHeartbeat) {
            rc = demo_heartbeat(ctx);
            if (rc != WOLFSPDM_SUCCESS) goto cleanup;
        }

        /* Key update: rotate session keys */
        if (doKeyUpdate) {
            rc = demo_key_update(ctx);
            if (rc != WOLFSPDM_SUCCESS) goto cleanup;
        }

#ifndef NO_WOLFSPDM_MEAS
        /* Retrieve measurements if requested */
        if (doMeas) {
            rc = demo_measurements(ctx, requestSignature);
        }
#else
        (void)doMeas;
        (void)requestSignature;
#endif
    } else {
        printf("\nERROR: wolfSPDM_Connect() failed: %s (%d)\n",
               wolfSPDM_GetErrorString(rc), rc);
    }

cleanup:
    /* Cleanup */
    wolfSPDM_Free(ctx);
    spdm_io_cleanup(&g_ioCtx);

    return (rc == WOLFSPDM_SUCCESS) ? 0 : rc;
}


#endif /* WOLFTPM_SWTPM */

int TPM2_SPDM_Demo(void* userCtx, int argc, char *argv[])
{
    int rc;
    WOLFTPM2_DEV dev;
    int i;
#ifdef WOLFTPM_SWTPM
    const char* emuHost = SPDM_EMU_DEFAULT_HOST;
    int emuPort = SPDM_EMU_DEFAULT_PORT;
    int useEmulator = 0;
    int doMeas = 0;
    int requestSignature = 1;
    int doChallenge = 0;
    int doHeartbeat = 0;
    int doKeyUpdate = 0;
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
#ifdef WOLFTPM_SWTPM
        else if (XSTRCMP(argv[i], "--emu") == 0) {
            useEmulator = 1;
        }
        else if (XSTRCMP(argv[i], "--host") == 0 && i + 1 < argc) {
            emuHost = argv[++i];
        }
        else if (XSTRCMP(argv[i], "--port") == 0 && i + 1 < argc) {
            emuPort = atoi(argv[++i]);
        }
        else if (XSTRCMP(argv[i], "--meas") == 0) {
            doMeas = 1;
            useEmulator = 1;
        }
        else if (XSTRCMP(argv[i], "--no-sig") == 0) {
            requestSignature = 0;
        }
        else if (XSTRCMP(argv[i], "--challenge") == 0) {
            doChallenge = 1;
            useEmulator = 1;
        }
        else if (XSTRCMP(argv[i], "--heartbeat") == 0) {
            doHeartbeat = 1;
            useEmulator = 1;
        }
        else if (XSTRCMP(argv[i], "--key-update") == 0) {
            doKeyUpdate = 1;
            useEmulator = 1;
        }
#endif
    }

#ifdef WOLFTPM_SWTPM
    /* Handle --emu mode (TCP to emulator, no TPM needed) */
    if (useEmulator) {
        printf("Entering emulator mode...\n");
        fflush(stdout);
        return demo_emulator(emuHost, emuPort, doMeas, requestSignature,
                             doChallenge, doHeartbeat, doKeyUpdate);
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
        printf("Ensure wolfTPM is built with --enable-spdm\n");
        wolfTPM2_Cleanup(&dev);
        return rc;
    }

#ifdef WOLFSPDM_NUVOTON
    /* Set Nuvoton mode + TIS I/O for all Nuvoton commands */
    wolfTPM2_SpdmSetNuvotonMode(&dev);
    wolfTPM2_SPDM_SetTisIO(dev.spdmCtx);
#endif

    /* Process command-line options */
    for (i = 1; i < argc; i++) {
#ifdef WOLFSPDM_NUVOTON
        if (XSTRCMP(argv[i], "--enable") == 0) {
            rc = demo_enable(&dev);
            if (rc != 0) break;
        }
        else if (XSTRCMP(argv[i], "--disable") == 0) {
            rc = demo_disable(&dev);
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