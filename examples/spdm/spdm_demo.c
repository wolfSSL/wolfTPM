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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef WOLFTPM2_NO_WRAPPER

#include <hal/tpm_io.h>
#include <examples/tpm_test.h>

#ifdef WOLFTPM_SPDM

#include <wolftpm/tpm2_spdm.h>

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
    printf("  -h, --help     Show this help message\n");
    printf("\n");
    printf("Prerequisites:\n");
    printf("  - Nuvoton NPCT75x TPM with Fw 7.2+ connected via SPI\n");
    printf("  - Host ECDSA P-384 keypair for mutual authentication\n");
    printf("  - Built with: ./configure --enable-spdm [--with-libspdm=PATH]\n");
}

static int demo_enable(WOLFTPM2_DEV* dev)
{
    int rc;

    printf("\n=== Enable SPDM on TPM ===\n");
    printf("Sending NTC2_PreConfig to enable SPDM (CFG_H bit 1 = 0)...\n");

    rc = wolfTPM2_SpdmEnable(dev);
    if (rc == 0) {
        printf("  SUCCESS: SPDM enabled. TPM must be reset to take effect.\n");
    } else if (rc == TPM_RC_COMMAND_CODE) {
        printf("  NOTE: NTC2_PreConfig SPDM enable not yet implemented.\n");
        printf("  Use Nuvoton tools to enable SPDM, or implement NTC2_PreConfig.\n");
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

    printf("\n=== SPDM Connect (Full Handshake) ===\n");
    printf("Establishing SPDM secure session...\n");
    printf("  Steps: GET_VERSION -> GET_PUB_KEY -> KEY_EXCHANGE -> "
           "GIVE_PUB_KEY -> FINISH\n\n");

    /* TODO: Load host's ECDSA P-384 keypair from file or NV.
     * For now, pass NULL to skip mutual auth key provisioning.
     * In production, you must provide the host's key pair. */
    rc = wolfTPM2_SpdmConnect(dev, NULL, 0, NULL, 0);
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

int TPM2_SPDM_Demo(void* userCtx, int argc, char *argv[])
{
    int rc;
    WOLFTPM2_DEV dev;
    int i;

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
    }

    /* Init the TPM2 device.
     * When SPDM is enabled on Nuvoton TPMs, TPM2_Startup may return
     * TPM_RC_DISABLED because the TPM expects SPDM-only communication.
     * We tolerate this for SPDM operations since the TIS layer is
     * already initialized and SPDM messages bypass TPM2_Startup. */
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc == (int)TPM_RC_DISABLED) {
        printf("Note: TPM2_Startup returned TPM_RC_DISABLED "
               "(SPDM-only mode may be active)\n");
        rc = 0; /* Continue - SPDM commands work over raw SPI */
    }
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
