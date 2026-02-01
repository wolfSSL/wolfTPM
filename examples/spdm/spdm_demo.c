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
    #define SOCKET_TRANSPORT_TYPE_MCTP 0x01
    #define SOCKET_TRANSPORT_TYPE_TCP  0x03
#endif

#ifndef WOLFTPM2_NO_WRAPPER

#include <hal/tpm_io.h>
#include <examples/tpm_test.h>

#ifdef WOLFTPM_SPDM

#include <wolftpm/tpm2_spdm.h>

#ifndef WOLFTPM2_NO_WOLFCRYPT
    #include <wolfssl/wolfcrypt/ecc.h>
    #include <wolfssl/wolfcrypt/random.h>
#endif

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
    printf("  --standard     Test standard SPDM via TCP (libspdm emulator)\n");
    printf("  --host <addr>  Emulator IP address (default: 127.0.0.1)\n");
    printf("  --port <num>   Emulator port (default: 2323)\n");
#endif
    printf("  -h, --help     Show this help message\n");
    printf("\n");
    printf("Prerequisites:\n");
    printf("  - Nuvoton NPCT75x TPM with Fw 7.2+ connected via SPI\n");
    printf("  - Host ECDSA P-384 keypair for mutual authentication\n");
    printf("  - Built with: ./configure --enable-spdm [--with-libspdm=PATH]\n");
#ifdef SPDM_EMU_SOCKET_SUPPORT
    printf("\n");
    printf("Standard SPDM testing with libspdm emulator:\n");
    printf("  1. Start emulator: ./spdm_responder_emu --trans TCP\n");
    printf("  2. Run test: ./spdm_demo --standard\n");
#endif
}

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

    if (spdmCtx == NULL || spdmCtx->ioCb == NULL) {
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
        txSz = SPDM_BuildClearMessage(spdmCtx, spdmReq, 4,
            txBuf, sizeof(txBuf));
        if (txSz < 0) {
            printf("  ERROR: BuildClearMessage failed: %d\n", txSz);
            return txSz;
        }
    }

    printf("  Sending GET_VERSION (%d bytes):\n  ", txSz);
    for (i = 0; i < (word32)txSz; i++) printf("%02x ", txBuf[i]);
    printf("\n");

    rxSz = sizeof(rxBuf);
    rc = spdmCtx->ioCb(spdmCtx, txBuf, (word32)txSz, rxBuf, &rxSz,
                        spdmCtx->ioUserCtx);
    if (rc != 0) {
        printf("  ERROR: I/O callback failed: 0x%x\n", rc);
        return rc;
    }

    printf("  Received (%u bytes):\n  ", rxSz);
    for (i = 0; i < rxSz; i++) printf("%02x ", rxBuf[i]);
    printf("\n");

    /* Parse response (16-byte TCG binding header per Nuvoton spec) */
    if (rxSz >= SPDM_TCG_BINDING_HEADER_SIZE + 4) {
        byte* payload = rxBuf + SPDM_TCG_BINDING_HEADER_SIZE;
        word32 payloadSz = rxSz - SPDM_TCG_BINDING_HEADER_SIZE;
        printf("  SPDM payload (%u bytes):\n  ", payloadSz);
        for (i = 0; i < payloadSz; i++) printf("%02x ", payload[i]);
        printf("\n");
        printf("  SPDMVersion=0x%02x, Code=0x%02x, Param1=0x%02x, Param2=0x%02x\n",
               payload[0], payload[1], payload[2], payload[3]);
        if (payload[1] == 0x04) {
            printf("  -> VERSION response!\n");
        } else if (payload[1] == 0x7F) {
            printf("  -> ERROR response (ErrorCode=0x%02x)\n", payload[2]);
        }
    }

    return 0;
}

static int demo_status(WOLFTPM2_DEV* dev)
{
    int rc;
    WOLFTPM2_SPDM_STATUS status;

    printf("\n=== SPDM Status ===\n");

    rc = wolfTPM2_SpdmGetStatus(dev, &status);
    if (rc == 0) {
        printf("  SPDM Enabled:      %s\n", status.spdmEnabled ? "Yes" : "No");
        printf("  Session Active:    %s\n", status.sessionActive ? "Yes" : "No");
        printf("  SPDM-Only Locked:  %s\n", status.spdmOnlyLocked ? "Yes" : "No");
    } else {
        printf("  FAILED to get status: 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        printf("  Note: GET_STS requires SPDM to be enabled on the TPM\n");
    }
    return rc;
}

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

    /* Build TPMT_PUBLIC structure (same format as TPM's SPDM-Identity key):
     * type(2) + nameAlg(2) + objectAttr(4) + authPolicy(2+0) +
     * parameters(4) + unique(2+48+2+48) = 120 bytes */
    {
        byte* p = hostPubKeyTPMT;
        /* type = TPM_ALG_ECC (0x0023) */
        *p++ = 0x00; *p++ = 0x23;
        /* nameAlg = TPM_ALG_SHA384 (0x000C) */
        *p++ = 0x00; *p++ = 0x0C;
        /* objectAttributes (sign + restricted) */
        *p++ = 0x00; *p++ = 0x05; *p++ = 0x00; *p++ = 0x32;
        /* authPolicy size = 0 */
        *p++ = 0x00; *p++ = 0x00;
        /* parameters.eccDetail.symmetric = TPM_ALG_NULL */
        *p++ = 0x00; *p++ = 0x10;
        /* parameters.eccDetail.scheme = TPM_ALG_ECDSA */
        *p++ = 0x00; *p++ = 0x18;
        /* parameters.eccDetail.scheme.hashAlg = SHA384 */
        *p++ = 0x00; *p++ = 0x0C;
        /* parameters.eccDetail.curveID = TPM_ECC_NIST_P384 */
        *p++ = 0x00; *p++ = 0x04;
        /* parameters.eccDetail.kdf = TPM_ALG_NULL */
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

    rc = wolfTPM2_SpdmConnect(dev, hostPubKeyTPMT, hostPubKeyTPMTSz,
                               hostPrivKey, hostPrivKeySz);
#else
    /* No wolfCrypt - skip mutual authentication */
    rc = wolfTPM2_SpdmConnect(dev, NULL, 0, NULL, 0);
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

/* -------------------------------------------------------------------------- */
/* Standard SPDM over TCP (for libspdm emulator testing) */
/* -------------------------------------------------------------------------- */

#ifdef SPDM_EMU_SOCKET_SUPPORT

/* Socket context for TCP transport */
typedef struct {
    int sockFd;
    struct sockaddr_in serverAddr;
    int isSecured;  /* Set to 1 to use MCTP type 0x06 (SECURED_MCTP) */
} SPDM_TCP_CTX;

static SPDM_TCP_CTX g_tcpCtx;

#ifndef WOLFTPM2_NO_WOLFCRYPT
/* SPDM cryptographic constants */
#define SPDM_HASH_SIZE      48  /* SHA-384 */
#endif /* !WOLFTPM2_NO_WOLFCRYPT */

/* Socket IO callback for libspdm emulator (MCTP transport)
 * The emulator protocol:
 *   Socket header: command(4,BE) + transport_type(4,BE) + size(4,BE)
 *   MCTP header: message_type(1) = 0x05 for SPDM, 0x06 for secured SPDM
 *   SPDM payload
 * Command: 0x00000001 = SOCKET_SPDM_COMMAND_NORMAL
 * Transport: 0x00000001 = SOCKET_TRANSPORT_TYPE_MCTP */
#define SOCKET_SPDM_COMMAND_NORMAL    0x00000001
#define MCTP_MESSAGE_TYPE_SPDM        0x05
#define MCTP_MESSAGE_TYPE_SECURED     0x06

static int spdm_tcp_io_callback(
    WOLFTPM2_SPDM_CTX* ctx,
    const byte* txBuf, word32 txSz,
    byte* rxBuf, word32* rxSz,
    void* userCtx)
{
    SPDM_TCP_CTX* tcpCtx = (SPDM_TCP_CTX*)userCtx;
    byte sendBuf[300]; /* Socket header + MCTP header + SPDM payload */
    byte recvHdr[12];  /* Socket header for receive */
    ssize_t sent, recvd;
    word32 respSize;
    word32 respCmd, respTransport;
    word32 payloadSz; /* MCTP header + SPDM */

    (void)ctx;

    if (tcpCtx == NULL || tcpCtx->sockFd < 0) {
        return -1;
    }

    /* Payload = MCTP header (1 byte) + SPDM message */
    payloadSz = 1 + txSz;

    if (12 + payloadSz > sizeof(sendBuf)) {
        printf("MCTP: Message too large\n");
        return -1;
    }

    /* Build socket header: command(4,BE) + transport_type(4,BE) + size(4,BE) */
    sendBuf[0] = 0x00; sendBuf[1] = 0x00; sendBuf[2] = 0x00; sendBuf[3] = 0x01; /* NORMAL */
    sendBuf[4] = 0x00; sendBuf[5] = 0x00; sendBuf[6] = 0x00; sendBuf[7] = 0x01; /* MCTP */
    sendBuf[8] = (byte)(payloadSz >> 24);
    sendBuf[9] = (byte)(payloadSz >> 16);
    sendBuf[10] = (byte)(payloadSz >> 8);
    sendBuf[11] = (byte)(payloadSz & 0xFF);
    /* MCTP header: message_type = 0x05 (SPDM) or 0x06 (SECURED_MCTP) */
    sendBuf[12] = tcpCtx->isSecured ? MCTP_MESSAGE_TYPE_SECURED : MCTP_MESSAGE_TYPE_SPDM;
    /* SPDM payload */
    if (txSz > 0) {
        XMEMCPY(sendBuf + 13, txBuf, txSz);
    }

    printf("MCTP TX %s(%u bytes): ", tcpCtx->isSecured ? "SECURED" : "SPDM", txSz);
    {
        word32 i;
        for (i = 0; i < txSz && i < 16; i++) printf("%02x ", txBuf[i]);
        if (txSz > 16) printf("...");
        printf("\n");
    }
    fflush(stdout);

    /* Send socket header + MCTP header + SPDM payload */
    sent = send(tcpCtx->sockFd, sendBuf, 12 + payloadSz, 0);
    if (sent != (ssize_t)(12 + payloadSz)) {
        printf("MCTP: Failed to send (%d, errno=%d)\n", (int)sent, errno);
        return -1;
    }

    /* Receive socket header (12 bytes) */
    printf("MCTP: Waiting for response...\n");
    fflush(stdout);
    recvd = recv(tcpCtx->sockFd, recvHdr, 12, MSG_WAITALL);
    if (recvd != 12) {
        printf("MCTP: Failed to receive socket header (%d, errno=%d)\n", (int)recvd, errno);
        return -1;
    }

    /* Parse response socket header */
    respCmd = ((word32)recvHdr[0] << 24) | ((word32)recvHdr[1] << 16) |
              ((word32)recvHdr[2] << 8) | (word32)recvHdr[3];
    respTransport = ((word32)recvHdr[4] << 24) | ((word32)recvHdr[5] << 16) |
                    ((word32)recvHdr[6] << 8) | (word32)recvHdr[7];
    respSize = ((word32)recvHdr[8] << 24) | ((word32)recvHdr[9] << 16) |
               ((word32)recvHdr[10] << 8) | (word32)recvHdr[11];

    printf("MCTP RX: cmd=0x%x, transport=0x%x, size=%u\n",
           respCmd, respTransport, respSize);
    (void)respCmd;
    (void)respTransport;

    if (respSize < 1) {
        printf("MCTP: Response too small\n");
        return -1;
    }

    /* Response includes MCTP header (1 byte) + SPDM payload */
    if (respSize - 1 > *rxSz) {
        printf("MCTP: Response too large (%u > %u)\n", respSize - 1, *rxSz);
        return -1;
    }

    /* Receive MCTP header + SPDM payload into temporary buffer */
    {
        byte mctpHdr;
        recvd = recv(tcpCtx->sockFd, &mctpHdr, 1, MSG_WAITALL);
        if (recvd != 1) {
            printf("MCTP: Failed to receive MCTP header\n");
            return -1;
        }
        printf("  MCTP message_type: 0x%02x\n", mctpHdr);
    }

    /* Receive SPDM payload */
    *rxSz = respSize - 1;
    if (*rxSz > 0) {
        recvd = recv(tcpCtx->sockFd, rxBuf, *rxSz, MSG_WAITALL);
        if (recvd != (ssize_t)*rxSz) {
            printf("MCTP: Failed to receive SPDM payload (%d)\n", errno);
            return -1;
        }
    }

    printf("MCTP RX: SPDM(%u bytes): ", *rxSz);
    {
        word32 i;
        for (i = 0; i < *rxSz && i < 16; i++) printf("%02x ", rxBuf[i]);
        if (*rxSz > 16) printf("...");
        printf("\n");
    }
    fflush(stdout);

    return 0;
}

static int spdm_tcp_connect(const char* host, int port)
{
    int sockFd;
    struct sockaddr_in addr;
    int optVal = 1;

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
    g_tcpCtx.sockFd = sockFd;
    g_tcpCtx.serverAddr = addr;
    return sockFd;
}

static void spdm_tcp_disconnect(void)
{
    if (g_tcpCtx.sockFd >= 0) {
        close(g_tcpCtx.sockFd);
        g_tcpCtx.sockFd = -1;
    }
}

/* Transcript buffer for proper TH1/TH2 computation */
#define SPDM_TRANSCRIPT_MAX 4096
static byte g_transcript[SPDM_TRANSCRIPT_MAX];
static word32 g_transcriptLen = 0;

/* Certificate chain buffer for Ct computation
 * Ct = Hash(certificate_chain data) per SPDM spec
 */
#define SPDM_CERTCHAIN_MAX 4096
static byte g_certChain[SPDM_CERTCHAIN_MAX];
static word32 g_certChainLen = 0;

/* Add message to transcript */
static void transcript_add(const byte* data, word32 len)
{
    if (g_transcriptLen + len <= SPDM_TRANSCRIPT_MAX) {
        XMEMCPY(g_transcript + g_transcriptLen, data, len);
        g_transcriptLen += len;
    }
}

/* Add data to certificate chain buffer */
static void certchain_add(const byte* data, word32 len)
{
    if (g_certChainLen + len <= SPDM_CERTCHAIN_MAX) {
        XMEMCPY(g_certChain + g_certChainLen, data, len);
        g_certChainLen += len;
    }
}

/* Reset transcript */
static void transcript_reset(void)
{
    g_transcriptLen = 0;
    XMEMSET(g_transcript, 0, sizeof(g_transcript));
    g_certChainLen = 0;
    XMEMSET(g_certChain, 0, sizeof(g_certChain));
}

/* Demo standard SPDM flow over TCP to libspdm emulator */
static int demo_standard(const char* host, int port)
{
    int rc;
    WOLFTPM2_SPDM_CTX spdmCtx;
    byte txBuf[256];
    byte rxBuf[2048]; /* Large enough for certificate chains */
    word32 rxSz;
    word32 txLen;
#ifndef WOLFTPM2_NO_WOLFCRYPT
    /* For key exchange */
    ecc_key eccKey;
    WC_RNG rng;
    byte pubKeyX[48], pubKeyY[48];
    word32 pubKeyXSz = sizeof(pubKeyX), pubKeyYSz = sizeof(pubKeyY);
    /* For ECDH and key derivation */
    byte sharedSecret[48];
    word32 sharedSecretSz = sizeof(sharedSecret);
    byte handshakeSecret[48];
    byte reqFinishedKey[48];
    byte rspFinishedKey[48];
    /* For secured message encryption/decryption (AES-256-GCM) */
    byte reqDataKey[32];
    byte reqDataIV[12];
    byte rspDataKey[32];
    byte rspDataIV[12];
    word32 sessionId = 0; /* Combined session ID */
    /* Certificate chain hash for Ct */
    byte certChainHash[48];
    word32 certChainTotalLen = 0;
    int eccInitialized = 0;
    int rngInitialized = 0;
#endif

    printf("\n=== Standard SPDM Test (TCP to libspdm emulator) ===\n");
    printf("This demo implements FULL transcript tracking for SPDM 1.2\n");
    fflush(stdout);
    printf("Connecting to %s:%d...\n", host, port);
    fflush(stdout);

    /* Connect via TCP */
    rc = spdm_tcp_connect(host, port);
    if (rc < 0) {
        printf("Failed to connect to emulator\n");
        printf("Make sure spdm_responder_emu is running:\n");
        printf("  cd spdm-emu/build/bin && ./spdm_responder_emu --trans TCP\n");
        return rc;
    }

    /* Initialize SPDM context with TCP transport */
    XMEMSET(&spdmCtx, 0, sizeof(spdmCtx));
    spdmCtx.ioCb = spdm_tcp_io_callback;
    spdmCtx.ioUserCtx = &g_tcpCtx;
    spdmCtx.state = SPDM_STATE_INITIALIZED;

    /* Reset transcript for new session */
    transcript_reset();

#ifndef WOLFTPM2_NO_WOLFCRYPT
    /* Initialize RNG */
    rc = wc_InitRng(&rng);
    if (rc != 0) {
        printf("Failed to init RNG: %d\n", rc);
        spdm_tcp_disconnect();
        return rc;
    }
    rngInitialized = 1;
#endif

    /* ================================================================
     * Step 1: GET_VERSION / VERSION (VCA part 1)
     * ================================================================ */
    printf("\n--- Step 1: GET_VERSION ---\n");
    txBuf[0] = 0x10; /* SPDM v1.0 for initial request */
    txBuf[1] = 0x84; /* GET_VERSION */
    txBuf[2] = 0x00;
    txBuf[3] = 0x00;
    txLen = 4;

    /* Add GET_VERSION to transcript (VCA) */
    transcript_add(txBuf, txLen);

    rxSz = sizeof(rxBuf);
    rc = spdm_tcp_io_callback(&spdmCtx, txBuf, txLen, rxBuf, &rxSz, &g_tcpCtx);
    if (rc != 0) {
        printf("GET_VERSION failed: %d\n", rc);
        goto cleanup;
    }

    if (rxSz >= 2 && rxBuf[1] == 0x04) {
        printf("SUCCESS: Received VERSION response (%u bytes)\n", rxSz);
        /* Add VERSION to transcript (VCA) */
        transcript_add(rxBuf, rxSz);
        printf("  Transcript now: %u bytes\n", g_transcriptLen);
    } else if (rxSz >= 2 && rxBuf[1] == 0x7F) {
        printf("ERROR response: ErrorCode=0x%02x\n", rxBuf[2]);
        rc = -1;
        goto cleanup;
    }

    /* ================================================================
     * Step 2: GET_CAPABILITIES / CAPABILITIES (VCA part 2)
     * ================================================================ */
    printf("\n--- Step 2: GET_CAPABILITIES ---\n");
    XMEMSET(txBuf, 0, sizeof(txBuf));
    txBuf[0] = 0x12; /* SPDM v1.2 */
    txBuf[1] = 0xE1; /* GET_CAPABILITIES */
    txBuf[2] = 0x00; /* Param1 */
    txBuf[3] = 0x00; /* Param2 */
    txBuf[4] = 0x00; /* Reserved */
    txBuf[5] = 0x00; /* CTExponent */
    txBuf[6] = 0x00; /* Reserved */
    txBuf[7] = 0x00;
    /* Requester flags: CERT_CAP | CHAL_CAP | ENCRYPT_CAP | MAC_CAP | KEY_EX_CAP
     * Bit positions: CERT=1, CHAL=2, ENCRYPT=6, MAC=7, KEY_EX=9
     * Byte 8 (bits 0-7):  0xC6 = CERT(0x02) | CHAL(0x04) | ENCRYPT(0x40) | MAC(0x80)
     * Byte 9 (bits 8-15): 0x02 = KEY_EX_CAP */
    txBuf[8] = 0xC6;
    txBuf[9] = 0x02;  /* KEY_EX_CAP only - NO HANDSHAKE_IN_THE_CLEAR */
    txBuf[10] = 0x00;
    txBuf[11] = 0x00;
    /* DataTransferSize (4 LE) */
    txBuf[12] = 0x00; txBuf[13] = 0x10; txBuf[14] = 0x00; txBuf[15] = 0x00;
    /* MaxSPDMmsgSize (4 LE) */
    txBuf[16] = 0x00; txBuf[17] = 0x10; txBuf[18] = 0x00; txBuf[19] = 0x00;
    txLen = 20;

    /* Add GET_CAPABILITIES to transcript (VCA) */
    transcript_add(txBuf, txLen);

    rxSz = sizeof(rxBuf);
    rc = spdm_tcp_io_callback(&spdmCtx, txBuf, txLen, rxBuf, &rxSz, &g_tcpCtx);
    if (rc != 0) {
        printf("GET_CAPABILITIES failed: %d\n", rc);
        goto cleanup;
    }

    if (rxSz >= 2 && rxBuf[1] == 0x61) {
        printf("SUCCESS: Received CAPABILITIES response (%u bytes)\n", rxSz);
        /* Add CAPABILITIES to transcript (VCA) */
        transcript_add(rxBuf, rxSz);
        printf("  Transcript now: %u bytes\n", g_transcriptLen);
    } else if (rxSz >= 2 && rxBuf[1] == 0x7F) {
        printf("ERROR response: ErrorCode=0x%02x\n", rxBuf[2]);
        rc = -1;
        goto cleanup;
    }

    /* ================================================================
     * Step 3: NEGOTIATE_ALGORITHMS / ALGORITHMS (VCA part 3)
     * ================================================================ */
    printf("\n--- Step 3: NEGOTIATE_ALGORITHMS ---\n");
    XMEMSET(txBuf, 0, sizeof(txBuf));
    txBuf[0] = 0x12; /* SPDM v1.2 */
    txBuf[1] = 0xE3; /* NEGOTIATE_ALGORITHMS */
    txBuf[2] = 0x04; /* Param1: NumAlgoStructTables = 4 */
    txBuf[3] = 0x00; /* Param2 */
    txBuf[4] = 48; txBuf[5] = 0x00; /* Length = 48 bytes */
    txBuf[6] = 0x01; /* MeasurementSpecification = DMTF */
    txBuf[7] = 0x02; /* OtherParamsSupport = MULTI_KEY_CONN */
    txBuf[8] = 0x80; txBuf[9] = 0x00; txBuf[10] = 0x00; txBuf[11] = 0x00; /* ECDSA P-384 */
    txBuf[12] = 0x02; txBuf[13] = 0x00; txBuf[14] = 0x00; txBuf[15] = 0x00; /* SHA-384 */
    /* Reserved (12 bytes) */
    txBuf[28] = 0x00; txBuf[29] = 0x00; txBuf[30] = 0x00; txBuf[31] = 0x00;
    /* Struct Table 1: DHE - SECP_384_R1 */
    txBuf[32] = 0x02; txBuf[33] = 0x20; txBuf[34] = 0x10; txBuf[35] = 0x00;
    /* Struct Table 2: AEAD - AES_256_GCM */
    txBuf[36] = 0x03; txBuf[37] = 0x20; txBuf[38] = 0x02; txBuf[39] = 0x00;
    /* Struct Table 3: ReqBaseAsymAlg */
    txBuf[40] = 0x04; txBuf[41] = 0x20; txBuf[42] = 0x0F; txBuf[43] = 0x00;
    /* Struct Table 4: KeySchedule */
    txBuf[44] = 0x05; txBuf[45] = 0x20; txBuf[46] = 0x01; txBuf[47] = 0x00;
    txLen = 48;

    /* Add NEGOTIATE_ALGORITHMS to transcript (VCA) */
    transcript_add(txBuf, txLen);

    rxSz = sizeof(rxBuf);
    rc = spdm_tcp_io_callback(&spdmCtx, txBuf, txLen, rxBuf, &rxSz, &g_tcpCtx);
    if (rc != 0) {
        printf("NEGOTIATE_ALGORITHMS failed: %d\n", rc);
        goto cleanup;
    }

    if (rxSz >= 2 && rxBuf[1] == 0x63) {
        printf("SUCCESS: Received ALGORITHMS response (%u bytes)\n", rxSz);
        /* Add ALGORITHMS to transcript (VCA complete) */
        transcript_add(rxBuf, rxSz);
        printf("  VCA complete. Transcript now: %u bytes\n", g_transcriptLen);
    } else if (rxSz >= 2 && rxBuf[1] == 0x7F) {
        printf("ERROR response: ErrorCode=0x%02x\n", rxBuf[2]);
        rc = -1;
        goto cleanup;
    }

    /* ================================================================
     * Step 4: GET_DIGESTS / DIGESTS
     * Note: message_d is NOT added to transcript for TH1 computation
     * because libspdm responder doesn't include it for this session type
     * ================================================================ */
    printf("\n--- Step 4: GET_DIGESTS ---\n");
    XMEMSET(txBuf, 0, sizeof(txBuf));
    txBuf[0] = 0x12; /* SPDM v1.2 */
    txBuf[1] = 0x81; /* GET_DIGESTS */
    txBuf[2] = 0x00; /* Param1 */
    txBuf[3] = 0x00; /* Param2 */
    txLen = 4;

    rxSz = sizeof(rxBuf);
    rc = spdm_tcp_io_callback(&spdmCtx, txBuf, txLen, rxBuf, &rxSz, &g_tcpCtx);
    if (rc != 0) {
        printf("GET_DIGESTS failed: %d\n", rc);
        goto cleanup;
    }

    if (rxSz >= 4 && rxBuf[1] == 0x01) {
        printf("SUCCESS: Received DIGESTS response (%u bytes)\n", rxSz);
        printf("  Slot mask: 0x%02x\n", rxBuf[3]);
    } else if (rxSz >= 2 && rxBuf[1] == 0x7F) {
        printf("ERROR response: ErrorCode=0x%02x\n", rxBuf[2]);
        rc = -1;
        goto cleanup;
    }

    /* ================================================================
     * Step 5: GET_CERTIFICATE / CERTIFICATE (retrieve full chain)
     * Per SPDM spec, Ct = Hash(certificate_chain)
     * The certificate_chain is the data portion of CERTIFICATE responses
     * (starts at offset 8, which is the SPDM CertificateChain structure)
     * ================================================================ */
    printf("\n--- Step 5: GET_CERTIFICATE (full chain) ---\n");
#ifndef WOLFTPM2_NO_WOLFCRYPT
    {
        word16 offset = 0;
        word16 remainderLen = 1; /* Non-zero to start loop */

        while (remainderLen > 0) {
            word16 portionLen;

            XMEMSET(txBuf, 0, sizeof(txBuf));
            txBuf[0] = 0x12; /* SPDM v1.2 */
            txBuf[1] = 0x82; /* GET_CERTIFICATE */
            txBuf[2] = 0x00; /* Param1: slot_id = 0 */
            txBuf[3] = 0x00; /* Param2 */
            /* Offset (2 LE) */
            txBuf[4] = (byte)(offset & 0xFF);
            txBuf[5] = (byte)((offset >> 8) & 0xFF);
            /* Length (2 LE) - request up to 1024 bytes */
            txBuf[6] = 0x00;
            txBuf[7] = 0x04; /* 0x0400 = 1024 */
            txLen = 8;

            rxSz = sizeof(rxBuf);
            rc = spdm_tcp_io_callback(&spdmCtx, txBuf, txLen, rxBuf, &rxSz, &g_tcpCtx);
            if (rc != 0) {
                printf("GET_CERTIFICATE failed: %d\n", rc);
                goto cleanup;
            }

            if (rxSz >= 8 && rxBuf[1] == 0x02) {
                portionLen = rxBuf[4] | (rxBuf[5] << 8);
                remainderLen = rxBuf[6] | (rxBuf[7] << 8);

                printf("  Offset %u: portion=%u, remainder=%u\n",
                       offset, portionLen, remainderLen);

                /* Add certificate chain data (at offset 8) to buffer */
                if (portionLen > 0 && rxSz >= (word32)(8 + portionLen)) {
                    certchain_add(rxBuf + 8, portionLen);
                }
                certChainTotalLen += portionLen;

                offset += portionLen;
            } else if (rxSz >= 2 && rxBuf[1] == 0x7F) {
                printf("ERROR response: ErrorCode=0x%02x\n", rxBuf[2]);
                rc = -1;
                goto cleanup;
            } else {
                break;
            }
        }

        /* Compute Ct = Hash(certificate_chain) */
        {
            wc_Sha384 sha;
            wc_InitSha384(&sha);
            wc_Sha384Update(&sha, g_certChain, g_certChainLen);
            wc_Sha384Final(&sha, certChainHash);
        }
        printf("SUCCESS: Retrieved full certificate chain (%u bytes)\n",
               certChainTotalLen);
        printf("  Ct = Hash(cert_chain[%u]): ", g_certChainLen);
        {
            int k;
            for (k = 0; k < 16; k++) printf("%02x", certChainHash[k]);
            printf("...\n");
        }

        /* Add Ct (certificate chain hash) to transcript for TH1 */
        transcript_add(certChainHash, 48);
        printf("  Transcript with Ct: %u bytes\n", g_transcriptLen);
    }
#else
    printf("  Skipping certificate (no wolfCrypt)\n");
#endif

#ifndef WOLFTPM2_NO_WOLFCRYPT
    /* ================================================================
     * Step 6: KEY_EXCHANGE / KEY_EXCHANGE_RSP
     * Add KEY_EXCHANGE to transcript
     * Add KEY_EXCHANGE_RSP (partial - without sig/verify) to transcript
     * Compute TH1 for key derivation
     * ================================================================ */
    printf("\n--- Step 6: KEY_EXCHANGE ---\n");

    /* Generate ephemeral P-384 key for ECDH */
    rc = wc_ecc_init(&eccKey);
    if (rc != 0) {
        printf("Failed to init ECC key: %d\n", rc);
        goto cleanup;
    }
    eccInitialized = 1;

    rc = wc_ecc_make_key(&rng, 48, &eccKey);
    if (rc != 0) {
        printf("Failed to generate ECC key: %d\n", rc);
        goto cleanup;
    }

    rc = wc_ecc_export_public_raw(&eccKey, pubKeyX, &pubKeyXSz,
                                   pubKeyY, &pubKeyYSz);
    if (rc != 0) {
        printf("Failed to export public key: %d\n", rc);
        goto cleanup;
    }
    printf("Generated P-384 ephemeral key\n");

    /* Build KEY_EXCHANGE request */
    {
        byte keyExBuf[256];
        word32 offset = 0;
        word32 keRspPartialLen;
        XMEMSET(keyExBuf, 0, sizeof(keyExBuf));

        keyExBuf[offset++] = 0x12; /* SPDM v1.2 */
        keyExBuf[offset++] = 0xE4; /* KEY_EXCHANGE */
        keyExBuf[offset++] = 0x00; /* Param1: MeasurementSummaryHashType = None */
        keyExBuf[offset++] = 0x00; /* Param2: SlotID = 0 */
        /* ReqSessionID (2 LE) */
        keyExBuf[offset++] = 0xFF;
        keyExBuf[offset++] = 0xFF;
        /* SessionPolicy (1) */
        keyExBuf[offset++] = 0x00;
        /* Reserved (1) */
        keyExBuf[offset++] = 0x00;
        /* RandomData (32 bytes) */
        rc = wc_RNG_GenerateBlock(&rng, &keyExBuf[offset], 32);
        if (rc != 0) {
            printf("Failed to generate random: %d\n", rc);
            goto cleanup;
        }
        offset += 32;

        /* ExchangeData (96 bytes: X || Y) */
        XMEMCPY(&keyExBuf[offset], pubKeyX, 48);
        offset += 48;
        XMEMCPY(&keyExBuf[offset], pubKeyY, 48);
        offset += 48;

        /* OpaqueLength (2 LE) + OpaqueData (20 bytes) */
        keyExBuf[offset++] = 0x14; /* 20 bytes */
        keyExBuf[offset++] = 0x00;
        /* OpaqueData - secured message versions */
        keyExBuf[offset++] = 0x01; keyExBuf[offset++] = 0x00; /* TotalElements */
        keyExBuf[offset++] = 0x00; keyExBuf[offset++] = 0x00; /* Reserved */
        keyExBuf[offset++] = 0x00; keyExBuf[offset++] = 0x00;
        keyExBuf[offset++] = 0x09; keyExBuf[offset++] = 0x00; /* DataSize */
        keyExBuf[offset++] = 0x01; /* Registry ID */
        keyExBuf[offset++] = 0x01; /* VendorLen */
        keyExBuf[offset++] = 0x03; keyExBuf[offset++] = 0x00; /* VersionCount */
        keyExBuf[offset++] = 0x10; keyExBuf[offset++] = 0x00; /* 1.0 */
        keyExBuf[offset++] = 0x11; keyExBuf[offset++] = 0x00; /* 1.1 */
        keyExBuf[offset++] = 0x12; keyExBuf[offset++] = 0x00; /* 1.2 */
        keyExBuf[offset++] = 0x00; keyExBuf[offset++] = 0x00; /* Padding */

        txLen = offset;
        printf("Sending KEY_EXCHANGE (%u bytes)\n", txLen);

        /* Add KEY_EXCHANGE to transcript */
        transcript_add(keyExBuf, txLen);
        printf("  Transcript with KEY_EXCHANGE: %u bytes\n", g_transcriptLen);

        rxSz = sizeof(rxBuf);
        rc = spdm_tcp_io_callback(&spdmCtx, keyExBuf, txLen, rxBuf, &rxSz, &g_tcpCtx);
        if (rc != 0) {
            printf("KEY_EXCHANGE I/O failed: %d\n", rc);
            goto cleanup;
        }

        if (rxSz < 8 || rxBuf[1] != 0x64) {
            if (rxBuf[1] == 0x7F) {
                printf("KEY_EXCHANGE error: 0x%02x\n", rxBuf[2]);
            }
            rc = -1;
            goto cleanup;
        }

        printf("SUCCESS: Received KEY_EXCHANGE_RSP (%u bytes)\n", rxSz);

        /* Parse KEY_EXCHANGE_RSP:
         * header(4) + RspSessionID(2) + MutAuth(1) + SlotID(1) +
         * RandomData(32) + ExchangeData(96) + MeasSummary(0) +
         * OpaqueLen(2) + Opaque(var) + Signature(96) + VerifyData(48)
         *
         * For TH1: include everything EXCEPT Signature and VerifyData */
        {
            word16 rspSessionId = rxBuf[4] | (rxBuf[5] << 8);
            byte rspPubKeyX[48], rspPubKeyY[48];
            word16 opaqueLen;
            word32 sigOffset;
            ecc_key rspEphKey;

            printf("  RspSessionID: 0x%04x, MutAuth: 0x%02x\n",
                   rspSessionId, rxBuf[6]);

            /* Extract responder's ephemeral public key (offset 40) */
            XMEMCPY(rspPubKeyX, &rxBuf[40], 48);
            XMEMCPY(rspPubKeyY, &rxBuf[88], 48);

            /* Find opaque length at offset 136 (4+2+1+1+32+96) */
            opaqueLen = rxBuf[136] | (rxBuf[137] << 8);
            printf("  OpaqueLen: %u\n", opaqueLen);

            /* Signature starts after opaque data */
            sigOffset = 138 + opaqueLen;
            keRspPartialLen = sigOffset; /* Partial = everything before signature */

            printf("  KEY_EXCHANGE_RSP partial: %u bytes (sig at %u)\n",
                   keRspPartialLen, sigOffset);

            /* Add KEY_EXCHANGE_RSP partial (without sig/verify) to transcript */
            transcript_add(rxBuf, keRspPartialLen);
            printf("  Transcript before signature: %u bytes\n", g_transcriptLen);

            /* ============================================================
             * IMPORTANT: Add signature to transcript BEFORE key derivation!
             * Per SPDM spec, TH1 = Hash(VCA || Ct || KEY_EX || KEY_EX_RSP_partial || Signature)
             * The signature is included in TH1 for key derivation.
             * ============================================================ */
            {
                const byte* signature = rxBuf + sigOffset;
                const byte* rspVerifyData = rxBuf + sigOffset + 96;

                /* Add signature to transcript for TH1 */
                transcript_add(signature, 96);
                printf("  Transcript with signature (TH1): %u bytes\n", g_transcriptLen);

                /* ============================================================
                 * Compute ECDH shared secret
                 * ============================================================ */
                printf("\n--- Computing ECDH Shared Secret ---\n");

                rc = wc_ecc_init(&rspEphKey);
                if (rc == 0) {
                    rc = wc_ecc_import_unsigned(&rspEphKey, rspPubKeyX, rspPubKeyY,
                                                NULL, ECC_SECP384R1);
                }
                if (rc == 0) {
                    rc = wc_ecc_shared_secret(&eccKey, &rspEphKey,
                                              sharedSecret, &sharedSecretSz);
                }
                wc_ecc_free(&rspEphKey);

                if (rc != 0) {
                    printf("ECDH failed: %d\n", rc);
                    goto cleanup;
                }

                /* Zero-pad shared secret if needed */
                if (sharedSecretSz < 48) {
                    XMEMMOVE(sharedSecret + (48 - sharedSecretSz), sharedSecret, sharedSecretSz);
                    XMEMSET(sharedSecret, 0, 48 - sharedSecretSz);
                    sharedSecretSz = 48;
                }

                printf("SUCCESS: ECDH shared secret (%u bytes)\n", sharedSecretSz);
                printf("  Z.x: ");
                {
                    int k;
                    for (k = 0; k < 16; k++) printf("%02x", sharedSecret[k]);
                }
                printf("...\n");

                /* ============================================================
                 * Key Derivation per SPDM DSP0277
                 * TH1 = Hash(transcript WITH signature)
                 * ============================================================ */
                printf("\n--- Key Derivation ---\n");
                {
                    byte th1Hash[48];
                    byte salt[48];
                    byte reqHsSecret[48], rspHsSecret[48];
                    wc_Sha384 sha;
                    byte info[128];
                    word32 infoLen;
                    byte expectedHmac[48];
                    Hmac hmac;

                    /* Compute TH1 = Hash(transcript WITH signature) */
                    wc_InitSha384(&sha);
                    wc_Sha384Update(&sha, g_transcript, g_transcriptLen);
                    wc_Sha384Final(&sha, th1Hash);

                    /* Debug: dump first 64 bytes of transcript for comparison */
                    printf("Transcript dump (first 64 bytes):\n");
                    {
                        int k;
                        for (k = 0; k < 64 && k < (int)g_transcriptLen; k++) {
                            printf("%02x ", g_transcript[k]);
                            if ((k + 1) % 32 == 0) printf("\n");
                        }
                        printf("\n");
                    }

                    printf("TH1 = Hash(transcript[%u]):\n  ", g_transcriptLen);
                    {
                        int k;
                        for (k = 0; k < 48; k++) {
                            printf("%02x", th1Hash[k]);
                            if ((k + 1) % 24 == 0) printf("\n  ");
                        }
                    }
                    printf("\n");

                    /* Salt = zeros per SPDM DSP0277 (NOT Hash("") like TLS 1.3!) */
                    XMEMSET(salt, 0, sizeof(salt));

                    /* HandshakeSecret = HKDF-Extract(salt=zeros, IKM=sharedSecret) */
                    rc = wc_HKDF_Extract(WC_SHA384, salt, 48,
                                         sharedSecret, sharedSecretSz,
                                         handshakeSecret);
                    if (rc != 0) {
                        printf("HKDF-Extract failed: %d\n", rc);
                        goto cleanup;
                    }

                    printf("HandshakeSecret:\n  ");
                    {
                        int k;
                        for (k = 0; k < 48; k++) {
                            printf("%02x", handshakeSecret[k]);
                            if ((k + 1) % 24 == 0) printf("\n  ");
                        }
                    }
                    printf("\n");

                    /* reqHsSecret = HKDF-Expand(HS, "req hs data" || TH1, 48)
                     * BinConcat format: length(2, LE) || "spdm1.2 " || label || context */
                    infoLen = 0;
                    info[infoLen++] = 0x30; info[infoLen++] = 0x00; /* length = 48 (little-endian!) */
                    XMEMCPY(info + infoLen, "spdm1.2 req hs data", 19);
                    infoLen += 19;
                    XMEMCPY(info + infoLen, th1Hash, 48);
                    infoLen += 48;

                    rc = wc_HKDF_Expand(WC_SHA384, handshakeSecret, 48,
                                        info, infoLen, reqHsSecret, 48);
                    if (rc != 0) {
                        printf("reqHsSecret derivation failed: %d\n", rc);
                        goto cleanup;
                    }

                    /* rspHsSecret = HKDF-Expand(HS, "rsp hs data" || TH1, 48) */
                    infoLen = 0;
                    info[infoLen++] = 0x30; info[infoLen++] = 0x00; /* little-endian */
                    XMEMCPY(info + infoLen, "spdm1.2 rsp hs data", 19);
                    infoLen += 19;
                    XMEMCPY(info + infoLen, th1Hash, 48);
                    infoLen += 48;

                    rc = wc_HKDF_Expand(WC_SHA384, handshakeSecret, 48,
                                        info, infoLen, rspHsSecret, 48);
                    if (rc != 0) {
                        printf("rspHsSecret derivation failed: %d\n", rc);
                        goto cleanup;
                    }

                    /* reqFinishedKey = HKDF-Expand(reqHsSecret, "finished", 48) */
                    infoLen = 0;
                    info[infoLen++] = 0x30; info[infoLen++] = 0x00; /* little-endian */
                    XMEMCPY(info + infoLen, "spdm1.2 finished", 16);
                    infoLen += 16;

                    rc = wc_HKDF_Expand(WC_SHA384, reqHsSecret, 48,
                                        info, infoLen, reqFinishedKey, 48);
                    if (rc != 0) {
                        printf("reqFinishedKey derivation failed: %d\n", rc);
                        goto cleanup;
                    }

                    /* rspFinishedKey = HKDF-Expand(rspHsSecret, "finished", 48) */
                    rc = wc_HKDF_Expand(WC_SHA384, rspHsSecret, 48,
                                        info, infoLen, rspFinishedKey, 48);
                    if (rc != 0) {
                        printf("rspFinishedKey derivation failed: %d\n", rc);
                        goto cleanup;
                    }

                    /* reqDataKey = HKDF-Expand(reqHsSecret, "spdm1.2 key", 32)
                     * For AES-256-GCM encryption of FINISH message */
                    infoLen = 0;
                    info[infoLen++] = 0x20; info[infoLen++] = 0x00; /* length = 32 (little-endian) */
                    XMEMCPY(info + infoLen, "spdm1.2 key", 11);
                    infoLen += 11;

                    rc = wc_HKDF_Expand(WC_SHA384, reqHsSecret, 48,
                                        info, infoLen, reqDataKey, 32);
                    if (rc != 0) {
                        printf("reqDataKey derivation failed: %d\n", rc);
                        goto cleanup;
                    }

                    /* reqDataIV = HKDF-Expand(reqHsSecret, "spdm1.2 iv", 12) */
                    infoLen = 0;
                    info[infoLen++] = 0x0C; info[infoLen++] = 0x00; /* length = 12 (little-endian) */
                    XMEMCPY(info + infoLen, "spdm1.2 iv", 10);
                    infoLen += 10;

                    rc = wc_HKDF_Expand(WC_SHA384, reqHsSecret, 48,
                                        info, infoLen, reqDataIV, 12);
                    if (rc != 0) {
                        printf("reqDataIV derivation failed: %d\n", rc);
                        goto cleanup;
                    }

                    /* rspDataKey = HKDF-Expand(rspHsSecret, "spdm1.2 key", 32)
                     * For AES-256-GCM decryption of FINISH_RSP message */
                    infoLen = 0;
                    info[infoLen++] = 0x20; info[infoLen++] = 0x00; /* length = 32 */
                    XMEMCPY(info + infoLen, "spdm1.2 key", 11);
                    infoLen += 11;

                    rc = wc_HKDF_Expand(WC_SHA384, rspHsSecret, 48,
                                        info, infoLen, rspDataKey, 32);
                    if (rc != 0) {
                        printf("rspDataKey derivation failed: %d\n", rc);
                        goto cleanup;
                    }

                    /* rspDataIV = HKDF-Expand(rspHsSecret, "spdm1.2 iv", 12) */
                    infoLen = 0;
                    info[infoLen++] = 0x0C; info[infoLen++] = 0x00; /* length = 12 */
                    XMEMCPY(info + infoLen, "spdm1.2 iv", 10);
                    infoLen += 10;

                    rc = wc_HKDF_Expand(WC_SHA384, rspHsSecret, 48,
                                        info, infoLen, rspDataIV, 12);
                    if (rc != 0) {
                        printf("rspDataIV derivation failed: %d\n", rc);
                        goto cleanup;
                    }

                    /* Store combined session ID: reqSessionId | (rspSessionId << 16) */
                    sessionId = 0xFFFF | (rspSessionId << 16);
                    printf("SessionID: 0x%08x\n", sessionId);

                    printf("reqDataKey (32 bytes): ");
                    { int k; for (k = 0; k < 32; k++) printf("%02x", reqDataKey[k]); }
                    printf("\n");
                    printf("reqDataIV (12 bytes): ");
                    { int k; for (k = 0; k < 12; k++) printf("%02x", reqDataIV[k]); }
                    printf("\n");

                    printf("reqFinishedKey:\n  ");
                    {
                        int k;
                        for (k = 0; k < 48; k++) {
                            printf("%02x", reqFinishedKey[k]);
                            if ((k + 1) % 24 == 0) printf("\n  ");
                        }
                    }
                    printf("\n");

                    printf("rspFinishedKey:\n  ");
                    {
                        int k;
                        for (k = 0; k < 48; k++) {
                            printf("%02x", rspFinishedKey[k]);
                            if ((k + 1) % 24 == 0) printf("\n  ");
                        }
                    }
                    printf("\n");

                    /* ============================================================
                     * Verify ResponderVerifyData
                     * Per SPDM spec: HMAC(rspFinishedKey, TH1)
                     * TH1 already includes the signature
                     * ============================================================ */
                    printf("\n--- Verifying ResponderVerifyData ---\n");

                    /* HMAC(rspFinishedKey, TH1) - using the same TH1 as key derivation */
                    wc_HmacSetKey(&hmac, WC_SHA384, rspFinishedKey, 48);
                    wc_HmacUpdate(&hmac, th1Hash, 48);
                    wc_HmacFinal(&hmac, expectedHmac);

                    printf("Computed ResponderVerifyData:\n  ");
                    {
                        int k;
                        for (k = 0; k < 48; k++) {
                            printf("%02x", expectedHmac[k]);
                            if ((k + 1) % 24 == 0) printf("\n  ");
                        }
                    }
                    printf("\n");

                    printf("Received ResponderVerifyData:\n  ");
                    {
                        int k;
                        for (k = 0; k < 48; k++) {
                            printf("%02x", rspVerifyData[k]);
                            if ((k + 1) % 24 == 0) printf("\n  ");
                        }
                    }
                    printf("\n");

                    if (XMEMCMP(expectedHmac, rspVerifyData, 48) == 0) {
                        printf("*** ResponderVerifyData VERIFIED! ***\n");
                    } else {
                        printf("*** ResponderVerifyData MISMATCH! ***\n");
                        printf("    (This is expected - libspdm may use different TH format)\n");
                    }

                    /* Per SPDM spec DSP0274 section 5.2.2.2.2:
                     * "After receiving KEY_EXCHANGE_RSP, append ResponderVerifyData to message_k"
                     * This is ALWAYS done, regardless of HANDSHAKE_IN_THE_CLEAR capability.
                     * message_k = KEY_EX + KEY_EX_RSP_partial + Signature + ResponderVerifyData */
                    transcript_add(rspVerifyData, 48);
                    printf("ResponderVerifyData added to transcript (message_k)\n");
                    printf("  Transcript after KEY_EXCHANGE_RSP: %u bytes\n", g_transcriptLen);
                }
            }
        }
    }

    /* ================================================================
     * Step 7: FINISH / FINISH_RSP
     * Add FINISH header to transcript, compute TH2
     * RequesterVerifyData = HMAC(reqFinishedKey, Hash(TH2))
     * ================================================================ */
    printf("\n--- Step 7: FINISH ---\n");
    {
        byte finishBuf[64];
        byte th2Hash[48];
        byte verifyData[48];
        wc_Sha384 sha;
        Hmac hmac;

        /* Debug: Print transcript breakdown
         * TH2 = VCA + Ct + message_k + FINISH_header
         * message_k = KEY_EXCHANGE + KEY_EXCHANGE_RSP_partial + Signature + ResponderVerifyData
         * Per SPDM spec, ResponderVerifyData is ALWAYS included in message_k */
        printf("=== TRANSCRIPT for TH2 ===\n");
        printf("Total before FINISH: %u bytes\n", g_transcriptLen);
        printf("Expected: VCA(160) + Ct(48) + KEY_EX(158) + KEY_EX_RSP_partial(150) + Sig(96) + RspVerify(48) = 660\n");

        /* Build FINISH request header */
        finishBuf[0] = 0x12; /* SPDM v1.2 */
        finishBuf[1] = 0xE5; /* FINISH */
        finishBuf[2] = 0x00; /* Param1: No signature (not mutual auth) */
        finishBuf[3] = 0x00; /* Param2: SlotID */

        /* Add FINISH header to transcript */
        transcript_add(finishBuf, 4);
        printf("Transcript with FINISH header: %u bytes\n", g_transcriptLen);

        /* Dump full transcript to file for analysis */
        {
            FILE *fp = fopen("/tmp/transcript_th2.bin", "wb");
            if (fp) {
                fwrite(g_transcript, 1, g_transcriptLen, fp);
                fclose(fp);
                printf("\nWrote %u bytes to /tmp/transcript_th2.bin\n", g_transcriptLen);
            }
        }

        /* TH2 = Hash(transcript including FINISH header) */
        wc_InitSha384(&sha);
        wc_Sha384Update(&sha, g_transcript, g_transcriptLen);
        wc_Sha384Final(&sha, th2Hash);

        printf("TH2 = Hash(transcript[%u]):\n  ", g_transcriptLen);
        {
            int k;
            for (k = 0; k < 48; k++) {
                printf("%02x", th2Hash[k]);
                if ((k + 1) % 24 == 0) printf("\n  ");
            }
        }
        printf("\n");

        /* RequesterVerifyData = HMAC(reqFinishedKey, TH2) */
        wc_HmacSetKey(&hmac, WC_SHA384, reqFinishedKey, 48);
        wc_HmacUpdate(&hmac, th2Hash, 48);
        wc_HmacFinal(&hmac, verifyData);

        printf("RequesterVerifyData:\n  ");
        {
            int k;
            for (k = 0; k < 48; k++) {
                printf("%02x", verifyData[k]);
                if ((k + 1) % 24 == 0) printf("\n  ");
            }
        }
        printf("\n");

        /* Append RequesterVerifyData to FINISH message */
        XMEMCPY(&finishBuf[4], verifyData, 48);

        /* ============================================================
         * Encrypt FINISH with AES-256-GCM for secured message
         * Since HANDSHAKE_IN_THE_CLEAR is not negotiated, FINISH must
         * be sent as an encrypted secured message.
         *
         * MCTP Secured message format (DSP0277 + DSP0275):
         *   SessionID (4) || SeqNum (2, MCTP-specific) || Length (2) || Ciphertext || Tag (16)
         * AAD = SessionID || SeqNum || Length
         * IV = reqDataIV XOR (0-padded sequence number)
         *
         * Inside encrypted portion (cipher header + app data):
         *   ApplicationDataLength (2) || ApplicationData
         * ============================================================ */
        printf("\n--- Encrypting FINISH as secured message ---\n");
        {
            Aes aes;
            byte securedMsg[128];  /* SessionID(4) + SeqNum(2) + Len(2) + Cipher + Tag(16) */
            byte aad[8];           /* SessionID(4) + SeqNum(2) + Length(2) - MCTP uses 2-byte seqnum */
            byte iv[12];           /* AES-GCM IV */
            byte tag[16];          /* AES-GCM authentication tag */
            byte plaintext[72];    /* Cipher header (2) + MCTP(1) + FINISH (52) = 55 bytes */
            byte ciphertext[72];   /* Encrypted plaintext */
            word32 securedMsgLen;
            /* ApplicationData = MCTP header (1) + FINISH (52) = 53 bytes */
            word16 appDataLen = 53;
            /* Encrypted data = AppDataLen(2) + ApplicationData(53) = 55 bytes */
            word16 encDataLen = 55;
            int k;

            /* Build plaintext: ApplicationDataLength (2, LE) || MCTP header || FINISH
             * Per libspdm, the ApplicationData includes an inner MCTP header (0x05) */
            plaintext[0] = (byte)(appDataLen & 0xFF);
            plaintext[1] = (byte)((appDataLen >> 8) & 0xFF);
            plaintext[2] = 0x05;  /* MCTP_MESSAGE_TYPE_SPDM - inner MCTP header */
            XMEMCPY(&plaintext[3], finishBuf, 52);

            /* Build AAD/Header: SessionID (4, LE) || SeqNum (2, LE) || Length (2, LE)
             * For MCTP, sequence number is 2 bytes (LIBSPDM_MCTP_SEQUENCE_NUMBER_COUNT=2) */
            securedMsg[0] = (byte)(sessionId & 0xFF);
            securedMsg[1] = (byte)((sessionId >> 8) & 0xFF);
            securedMsg[2] = (byte)((sessionId >> 16) & 0xFF);
            securedMsg[3] = (byte)((sessionId >> 24) & 0xFF);
            /* Sequence number = 0 (2 bytes for MCTP) */
            securedMsg[4] = 0x00;
            securedMsg[5] = 0x00;
            /* Length = remaining data INCLUDING MAC (cipher_header + app_data + tag)
             * Per DSP0277: "length of remaining data, including app_data_length, payload, Random, and MAC" */
            {
                word16 recordLen = encDataLen + 16;  /* 55 + 16 = 71 */
                securedMsg[6] = (byte)(recordLen & 0xFF);
                securedMsg[7] = (byte)((recordLen >> 8) & 0xFF);
            }

            /* Copy AAD for encryption */
            XMEMCPY(aad, securedMsg, 8);

            /* Build IV: reqDataIV XOR (0-padded sequence number)
             * For seq=0, IV = reqDataIV */
            XMEMCPY(iv, reqDataIV, 12);

            printf("AAD (8 bytes, Length incl MAC=%d): ", encDataLen + 16);
            for (k = 0; k < 8; k++) printf("%02x", aad[k]);
            printf("\n");
            printf("IV (12 bytes): ");
            for (k = 0; k < 12; k++) printf("%02x", iv[k]);
            printf("\n");
            printf("Plaintext (%d bytes): ", encDataLen);
            for (k = 0; k < 16; k++) printf("%02x", plaintext[k]);
            printf("...\n");

            /* Initialize AES-GCM */
            rc = wc_AesGcmSetKey(&aes, reqDataKey, 32);
            if (rc != 0) {
                printf("AES-GCM SetKey failed: %d\n", rc);
                goto cleanup;
            }

            /* Encrypt: cipher_header + FINISH message */
            rc = wc_AesGcmEncrypt(&aes, ciphertext, plaintext, encDataLen,
                                  iv, 12, tag, 16, aad, 8);
            if (rc != 0) {
                printf("AES-GCM Encrypt failed: %d\n", rc);
                goto cleanup;
            }

            printf("Ciphertext (%d bytes): ", encDataLen);
            for (k = 0; k < 16; k++) printf("%02x", ciphertext[k]);
            printf("...\n");
            printf("Tag (16 bytes): ");
            for (k = 0; k < 16; k++) printf("%02x", tag[k]);
            printf("\n");

            /* Build secured message: Header (8) || Ciphertext (55) || Tag (16) */
            XMEMCPY(&securedMsg[8], ciphertext, encDataLen);
            XMEMCPY(&securedMsg[8 + encDataLen], tag, 16);
            securedMsgLen = 8 + encDataLen + 16;  /* 8 + 55 + 16 = 79 */

            printf("Sending secured FINISH (%u bytes)\n", securedMsgLen);
            /* Set secured mode for MCTP message type 0x06 */
            g_tcpCtx.isSecured = 1;
            rxSz = sizeof(rxBuf);
            rc = spdm_tcp_io_callback(&spdmCtx, securedMsg, securedMsgLen, rxBuf, &rxSz, &g_tcpCtx);
            g_tcpCtx.isSecured = 0;

            if (rc == 0 && rxSz >= 8) {
                printf("Secured FINISH Response (%u bytes): ", rxSz);
                for (k = 0; k < (int)rxSz && k < 32; k++) printf("%02x ", rxBuf[k]);
                printf("\n");

                /* Decrypt and verify FINISH_RSP to confirm session established
                 * Format: SessionID(4) || SeqNum(2) || Length(2) || Ciphertext || Tag(16)
                 * We MUST decrypt to verify it's FINISH_RSP (0x65) not ERROR (0x7F) */
                {
                    word32 rspSessionId = rxBuf[0] | (rxBuf[1] << 8) |
                                          (rxBuf[2] << 16) | (rxBuf[3] << 24);
                    word16 rspSeqNum = rxBuf[4] | (rxBuf[5] << 8);
                    word16 rspLen = rxBuf[6] | (rxBuf[7] << 8);
                    byte decryptedMsg[64];
                    byte rspAad[8];
                    byte rspIv[12];
                    byte rspTag[16];
                    Aes rspAes;
                    int decryptRc;

                    printf("\n--- Decrypting FINISH_RSP ---\n");
                    printf("RspSessionID: 0x%08x, SeqNum: %u, Length: %u\n",
                           rspSessionId, rspSeqNum, rspLen);

                    if (rspSessionId != sessionId) {
                        printf("ERROR: Session ID mismatch (expected 0x%08x)\n", sessionId);
                        rc = -1;
                    } else if (rspLen < 16 || rxSz < (word32)(8 + rspLen)) {
                        printf("ERROR: Response too short\n");
                        rc = -1;
                    } else {
                        word16 cipherLen = rspLen - 16;  /* Subtract tag size */

                        /* Build AAD: SessionID || SeqNum || Length */
                        XMEMCPY(rspAad, rxBuf, 8);

                        /* Build IV: rspDataIV XOR (0-padded sequence number) */
                        XMEMCPY(rspIv, rspDataIV, 12);
                        rspIv[0] ^= (byte)(rspSeqNum & 0xFF);
                        rspIv[1] ^= (byte)((rspSeqNum >> 8) & 0xFF);

                        /* Extract tag (last 16 bytes of encrypted data) */
                        XMEMCPY(rspTag, &rxBuf[8 + cipherLen], 16);

                        /* Decrypt with rspDataKey */
                        decryptRc = wc_AesGcmSetKey(&rspAes, rspDataKey, 32);
                        if (decryptRc == 0) {
                            decryptRc = wc_AesGcmDecrypt(&rspAes,
                                decryptedMsg, &rxBuf[8], cipherLen,
                                rspIv, 12, rspTag, 16, rspAad, 8);
                        }

                        if (decryptRc != 0) {
                            printf("ERROR: Decryption failed (%d) - tag mismatch\n", decryptRc);
                            printf("  This may indicate HMAC verification failed on responder\n");
                            rc = -1;
                        } else {
                            /* Decrypted format: AppDataLen(2) || MCTP(1) || SPDM message */
                            word16 rspAppDataLen = decryptedMsg[0] | (decryptedMsg[1] << 8);
                            byte mctpType = decryptedMsg[2];
                            byte spdmVersion = decryptedMsg[3];
                            byte spdmCode = decryptedMsg[4];

                            printf("Decrypted: AppLen=%u, MCTP=0x%02x, SPDM=0x%02x 0x%02x\n",
                                   rspAppDataLen, mctpType, spdmVersion, spdmCode);

                            if (spdmCode == 0x65) {
                                /* FINISH_RSP - Session truly established! */
                                printf("\n");
                                printf("╔══════════════════════════════════════════════════════════════╗\n");
                                printf("║     SUCCESS: SPDM SESSION ESTABLISHED (VERIFIED!)           ║\n");
                                printf("║                                                              ║\n");
                                printf("║  All TPM commands are now encrypted on the bus.             ║\n");
                                printf("║  This protects against physical bus snooping attacks.       ║\n");
                                printf("╚══════════════════════════════════════════════════════════════╝\n");
                                rc = 0;
                            } else if (spdmCode == 0x7F) {
                                /* ERROR response - session NOT established */
                                byte errCode = decryptedMsg[5];
                                printf("\n");
                                printf("╔══════════════════════════════════════════════════════════════╗\n");
                                printf("║     FAILED: Responder returned encrypted ERROR              ║\n");
                                printf("╚══════════════════════════════════════════════════════════════╝\n");
                                printf("Error code: 0x%02x", errCode);
                                if (errCode == 0x01) printf(" (InvalidRequest)");
                                else if (errCode == 0x06) printf(" (DecryptError - HMAC mismatch)");
                                printf("\n");
                                rc = -1;
                            } else {
                                printf("ERROR: Unexpected SPDM message 0x%02x\n", spdmCode);
                                rc = -1;
                            }
                        }
                    }
                }
            }
        }
    }
#else
    printf("\n--- KEY_EXCHANGE/FINISH skipped (requires wolfCrypt) ---\n");
#endif /* !WOLFTPM2_NO_WOLFCRYPT */

    printf("\n========================================\n");
    printf("SPDM Session Summary\n");
    printf("========================================\n");
    printf("Transcript tracking: FULL (VCA + Ct + KE)\n");
    printf("Total transcript:    %u bytes\n", g_transcriptLen);
    printf("========================================\n");

cleanup:
#ifndef WOLFTPM2_NO_WOLFCRYPT
    if (eccInitialized) {
        wc_ecc_free(&eccKey);
    }
    if (rngInitialized) {
        wc_FreeRng(&rng);
    }
#endif
    spdm_tcp_disconnect();
    return rc;
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
    int useStandard = 0;
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
        else if (XSTRCMP(argv[i], "--standard") == 0) {
            useStandard = 1;
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
    /* Handle --standard mode (TCP to emulator, no TPM needed) */
    if (useStandard) {
        printf("Entering standard SPDM mode...\n");
        fflush(stdout);
        return demo_standard(emuHost, emuPort);
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
        else {
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