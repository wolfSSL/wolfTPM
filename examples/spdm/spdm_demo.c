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
#include <wolfspdm/spdm.h>

int TPM2_SPDM_Demo(void* userCtx, int argc, char *argv[]);

static void usage(void)
{
    printf("SPDM Demo - Nuvoton NPCT75x secure session\n\n"
           "Usage: spdm_demo [options]\n"
           "  --enable       Enable SPDM via NTC2_PreConfig\n"
           "  --disable      Disable SPDM via NTC2_PreConfig\n"
           "  --status       Query SPDM status\n"
           "  --get-pubkey   Get TPM's SPDM-Identity public key\n"
           "  --connect      Establish SPDM session\n"
           "  --lock         Lock SPDM-only mode\n"
           "  --unlock       Unlock SPDM-only mode\n"
           "  -h, --help     Show this help\n\n"
           "Build: ./configure --enable-spdm --enable-nuvoton\n");
}

#ifdef WOLFSPDM_NUVOTON
static int demo_enable(WOLFTPM2_DEV* dev)
{
    int rc;
    printf("\n=== Enable SPDM ===\n");
    rc = wolfTPM2_SpdmEnable(dev);
    if (rc == 0) {
        printf("  SPDM enabled (reset TPM if newly configured)\n");
    } else if (rc == (int)TPM_RC_DISABLED) {
        printf("  SPDM-only active (already enabled)\n");
        rc = 0;
    } else if (rc == TPM_RC_COMMAND_CODE) {
        printf("  NTC2_PreConfig not supported (may already be enabled)\n");
        rc = 0;
    } else {
        printf("  FAILED: 0x%x: %s\n", rc, TPM2_GetRCString(rc));
    }
    return rc;
}

static int demo_disable(WOLFTPM2_DEV* dev)
{
    int rc;
    printf("\n=== Disable SPDM ===\n");
    rc = wolfTPM2_SpdmDisable(dev);
    if (rc == 0) {
        printf("  SPDM disabled (reset TPM for effect)\n");
    } else if (rc == (int)TPM_RC_DISABLED) {
        printf("  SPDM-only active - unlock first, then reset and disable\n");
    } else if (rc == TPM_RC_COMMAND_CODE) {
        printf("  NTC2_PreConfig not supported\n");
        rc = 0;
    } else {
        printf("  FAILED: 0x%x: %s\n", rc, TPM2_GetRCString(rc));
    }
    return rc;
}

static int demo_status(WOLFTPM2_DEV* dev)
{
    int rc;
    WOLFSPDM_NUVOTON_STATUS status;

    printf("\n=== SPDM Status ===\n");
    XMEMSET(&status, 0, sizeof(status));
    rc = wolfTPM2_SpdmGetStatus(dev, &status);
    if (rc == 0) {
        int isConn = wolfTPM2_SpdmIsConnected(dev);
        printf("  Enabled: %s  Locked: %s  Session: %s\n",
            status.spdmEnabled ? "Yes" : "No",
            status.spdmOnlyLocked ? "YES" : "No",
            isConn ? "Yes" : "No");
        if (isConn) {
            byte negVer = wolfSPDM_GetNegotiatedVersion(dev->spdmCtx->spdmCtx);
            printf("  Version: SPDM %u.%u  SessionID: 0x%08x\n",
                (negVer >> 4) & 0xF, negVer & 0xF,
                wolfTPM2_SpdmGetSessionId(dev));
        }
        printf("  Nuvoton: v%u.%u\n", status.specVersionMajor,
            status.specVersionMinor);
        if (status.spdmOnlyLocked)
            printf("  NOTE: SPDM-only mode, use --unlock to restore\n");
    } else {
        printf("  FAILED: 0x%x: %s\n", rc, TPM2_GetRCString(rc));
    }
    return rc;
}

static int demo_get_pubkey(WOLFTPM2_DEV* dev)
{
    int rc;
    byte pubKey[128];
    word32 pubKeySz = sizeof(pubKey);
    word32 i;

    printf("\n=== Get SPDM-Identity Public Key ===\n");
    rc = wolfTPM2_SpdmGetPubKey(dev, pubKey, &pubKeySz);
    if (rc == 0) {
        printf("  Got %d bytes: ", (int)pubKeySz);
        for (i = 0; i < pubKeySz && i < 32; i++) printf("%02x", pubKey[i]);
        if (pubKeySz > 32) printf("...");
        printf("\n");
    } else {
        printf("  FAILED: 0x%x: %s\n", rc, TPM2_GetRCString(rc));
    }
    return rc;
}

static int demo_connect(WOLFTPM2_DEV* dev)
{
    int rc;

    printf("\n=== SPDM Connect ===\n");
    if (wolfTPM2_SpdmIsConnected(dev)) {
        printf("  Already connected (SessionID: 0x%08x)\n",
            wolfTPM2_SpdmGetSessionId(dev));
        return 0;
    }

    printf("  Handshake: VERSION -> GET_PUBK -> KEY_EXCHANGE -> "
           "GIVE_PUB -> FINISH\n");
    rc = wolfTPM2_SpdmConnectNuvoton(dev, NULL, 0, NULL, 0);
    if (rc == 0) {
        printf("  Session established (AES-256-GCM, SessionID: 0x%08x)\n",
            wolfTPM2_SpdmGetSessionId(dev));
    } else {
        printf("  FAILED: 0x%x: %s\n", rc, TPM2_GetRCString(rc));
    }
    return rc;
}

static int demo_lock(WOLFTPM2_DEV* dev, int lock)
{
    int rc;
    printf("\n=== SPDM-Only: %s ===\n", lock ? "LOCK" : "UNLOCK");
    rc = wolfTPM2_SpdmSetOnlyMode(dev, lock);
    if (rc == 0)
        printf("  %s\n", lock ? "LOCKED (TPM requires SPDM)" : "UNLOCKED");
    else
        printf("  FAILED: 0x%x: %s\n", rc, TPM2_GetRCString(rc));
    return rc;
}
#endif /* WOLFSPDM_NUVOTON */

int TPM2_SPDM_Demo(void* userCtx, int argc, char *argv[])
{
    int rc, i;
    WOLFTPM2_DEV dev;

    if (argc <= 1) { usage(); return 0; }
    for (i = 1; i < argc; i++) {
        if (XSTRCMP(argv[i], "-h") == 0 || XSTRCMP(argv[i], "--help") == 0) {
            usage(); return 0;
        }
    }

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != 0) {
        printf("wolfTPM2_Init failed: 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        return rc;
    }

    rc = wolfTPM2_SpdmInit(&dev);
    if (rc != 0) {
        printf("wolfTPM2_SpdmInit failed: %s\n", TPM2_GetRCString(rc));
        wolfTPM2_Cleanup(&dev);
        return rc;
    }

#ifdef WOLFSPDM_NUVOTON
    wolfTPM2_SpdmSetNuvotonMode(&dev);
    wolfTPM2_SPDM_SetTisIO(dev.spdmCtx);
#endif

    for (i = 1; i < argc; i++) {
#ifdef WOLFSPDM_NUVOTON
        if (XSTRCMP(argv[i], "--enable") == 0)
            rc = demo_enable(&dev);
        else if (XSTRCMP(argv[i], "--disable") == 0)
            rc = demo_disable(&dev);
        else if (XSTRCMP(argv[i], "--status") == 0)
            rc = demo_status(&dev);
        else if (XSTRCMP(argv[i], "--get-pubkey") == 0)
            rc = demo_get_pubkey(&dev);
        else if (XSTRCMP(argv[i], "--connect") == 0)
            rc = demo_connect(&dev);
        else if (XSTRCMP(argv[i], "--lock") == 0)
            rc = demo_lock(&dev, 1);
        else if (XSTRCMP(argv[i], "--unlock") == 0)
            rc = demo_lock(&dev, 0);
        else
#endif
        { printf("Unknown option: %s\n", argv[i]); usage(); rc = BAD_FUNC_ARG; }
        if (rc != 0) break;
    }

    wolfTPM2_SpdmCleanup(&dev);
    wolfTPM2_Cleanup(&dev);
    return rc;
}

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = -1;
#ifndef WOLFTPM2_NO_WRAPPER
    rc = TPM2_SPDM_Demo(NULL, argc, argv);
#else
    printf("Wrapper code not compiled in\n");
    (void)argc; (void)argv;
#endif
    return (rc == 0) ? 0 : 1;
}
#endif

#endif /* WOLFTPM_SPDM */
#endif /* !WOLFTPM2_NO_WRAPPER */
