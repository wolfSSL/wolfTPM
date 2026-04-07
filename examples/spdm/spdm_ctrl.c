/* spdm_ctrl.c
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
#include <wolftpm/spdm/spdm.h>

int TPM2_SPDM_Ctrl(void* userCtx, int argc, char *argv[]);

static void usage(void)
{
    printf("SPDM Demo - TPM secure session\n\n"
           "Usage: spdm_ctrl [options]\n"
#ifdef WOLFSPDM_NUVOTON
           "  --enable       Enable SPDM via NTC2_PreConfig\n"
           "  --disable      Disable SPDM via NTC2_PreConfig\n"
           "  --status       Query SPDM status\n"
           "  --lock         Lock SPDM-only mode\n"
           "  --unlock       Unlock SPDM-only mode\n"
#endif
#ifdef WOLFSPDM_NATIONS
           "  --identity-key-set    Provision SPDM identity key\n"
           "  --identity-key-unset  Un-provision SPDM identity key\n"
           "  --psk <hex>           PSK mode connect (64-byte PSK)\n"
           "  --psk-set <psk> <clearauth>  Provision PSK (64-byte PSK, 32-byte ClearAuth)\n"
           "  --psk-clear <clearauth>   Clear PSK (32-byte ClearAuth from psk-set)\n"
           "  --lock                Lock SPDM-only mode (PSK mode, use with --psk)\n"
           "  --unlock              Unlock SPDM-only mode (PSK mode, use with --psk)\n"
           "  --status              Query SPDM status (PSK mode)\n"
#endif
           "  --get-pubkey   Get TPM's SPDM-Identity public key\n"
           "  --connect      Establish SPDM session\n"
           "  --caps         Get TPM capabilities (use with --connect)\n"
           "  -h, --help     Show this help\n\n"
#ifdef WOLFSPDM_NUVOTON
           "Build: ./configure --enable-spdm --enable-nuvoton\n"
#elif defined(WOLFSPDM_NATIONS)
           "Build: ./configure --enable-spdm --enable-nations\n"
#endif
           );
}

#ifdef WOLFSPDM_NUVOTON
static int ctrl_enable(WOLFTPM2_DEV* dev)
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

static int ctrl_disable(WOLFTPM2_DEV* dev)
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

static int ctrl_status(WOLFTPM2_DEV* dev)
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

static int ctrl_get_pubkey(WOLFTPM2_DEV* dev)
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

static int ctrl_connect(WOLFTPM2_DEV* dev)
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

static int ctrl_lock(WOLFTPM2_DEV* dev, int lock)
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

#ifdef WOLFSPDM_NATIONS
static int hex2bin(const char* hex, byte* bin, word32* binSz)
{
    word32 hexLen = (word32)XSTRLEN(hex);
    word32 i;
    if (hexLen % 2 != 0 || hexLen / 2 > *binSz) return -1;
    for (i = 0; i < hexLen; i += 2) {
        byte hi, lo;
        hi = (byte)((hex[i] >= '0' && hex[i] <= '9') ? hex[i] - '0' :
             (hex[i] >= 'a' && hex[i] <= 'f') ? hex[i] - 'a' + 10 :
             (hex[i] >= 'A' && hex[i] <= 'F') ? hex[i] - 'A' + 10 : 0xFF);
        lo = (byte)((hex[i+1] >= '0' && hex[i+1] <= '9') ? hex[i+1] - '0' :
             (hex[i+1] >= 'a' && hex[i+1] <= 'f') ? hex[i+1] - 'a' + 10 :
             (hex[i+1] >= 'A' && hex[i+1] <= 'F') ? hex[i+1] - 'A' + 10 : 0xFF);
        if (hi == 0xFF || lo == 0xFF) return -1;
        bin[i / 2] = (byte)((hi << 4) | lo);
    }
    *binSz = hexLen / 2;
    return 0;
}

static int ctrl_nations_status(WOLFTPM2_DEV* dev)
{
    int rc;
    int isConn;
    int stsRc;
    GetCapability_In capIn;
    GetCapability_Out capOut;
    WOLFSPDM_NATIONS_STATUS status;

    printf("\n=== Nations SPDM Status ===\n");

    /* 1. Check identity key provisioning via GetCapability (always works) */
    XMEMSET(&capIn, 0, sizeof(capIn));
    capIn.capability = TPM_CAP_VENDOR_PROPERTY;
    capIn.property = 12; /* TPM_PT_VENDOR + 12: identity key status */
    capIn.propertyCount = 1;
    XMEMSET(&capOut, 0, sizeof(capOut));
    rc = TPM2_GetCapability(&capIn, &capOut);
    if (rc == 0) {
        byte* raw = (byte*)&capOut.capabilityData.data.tpmProperties;
        int identityKey = (raw[3] != 0); /* value at prop 12 */
        printf("  Identity Key: %s\n",
            identityKey ? "provisioned" : "not provisioned");
    } else {
        printf("  Identity Key: unknown (GetCap failed: 0x%x)\n", rc);
    }

    /* 2. Try GET_STS_ vendor command (PSK mode only — may fail) */
    stsRc = wolfSPDM_GetVersion(dev->spdmCtx->spdmCtx);
    if (stsRc == 0) {
        XMEMSET(&status, 0, sizeof(status));
        stsRc = wolfTPM2_SpdmNationsGetStatus(dev, &status);
        if (stsRc == 0) {
            printf("  PSK: %s  SPDM-Only: %s\n",
                status.pskProvisioned ? "provisioned" : "not provisioned",
                !status.spdmOnlyLocked ? "disabled" :
                status.spdmOnlyPending ? "PENDING_DISABLE" : "ENABLED");
        } else {
            printf("  PSK Status: unknown (GET_STS failed)\n");
        }
    } else {
        printf("  PSK Status: GET_VERSION failed\n");
    }

    /* 3. Local session state */
    isConn = wolfTPM2_SpdmIsConnected(dev);
    printf("  Session: %s\n", isConn ? "active" : "none");
    if (isConn) {
        printf("  SessionID: 0x%08x\n", wolfTPM2_SpdmGetSessionId(dev));
    }

    return 0; /* status is informational, don't fail */
}

static int ctrl_nations_psk_connect(WOLFTPM2_DEV* dev, const char* pskHex)
{
    int rc;
    byte psk[128];
    word32 pskSz = sizeof(psk);

    printf("\n=== Nations PSK Connect ===\n");
    rc = hex2bin(pskHex, psk, &pskSz);
    if (rc != 0) {
        printf("  Invalid PSK hex string\n");
        return BAD_FUNC_ARG;
    }

    rc = wolfTPM2_SpdmConnectNationsPsk(dev, psk, pskSz, NULL, 0);
    XMEMSET(psk, 0, sizeof(psk));
    if (rc == 0) {
        printf("  PSK session established (SessionID: 0x%08x)\n",
            wolfTPM2_SpdmGetSessionId(dev));
    } else {
        printf("  FAILED: 0x%x: %s\n", rc, TPM2_GetRCString(rc));
    }
    return rc;
}

static int ctrl_nations_psk_set(WOLFTPM2_DEV* dev,
    const char* pskHex, const char* clearAuthHex)
{
    int rc;
    byte psk[64];
    word32 pskSz = sizeof(psk);
    byte clearAuth[256];
    word32 clearAuthSz = sizeof(clearAuth);
    byte payload[112]; /* PSK(64) + SHA-384(ClearAuth)(48) */
    wc_Sha384 sha;

    printf("\n=== Nations PSK Set ===\n");
    rc = hex2bin(pskHex, psk, &pskSz);
    if (rc != 0 || pskSz != 64) {
        printf("  Error: PSK must be exactly 64 bytes, got %u\n", pskSz);
        return BAD_FUNC_ARG;
    }
    rc = hex2bin(clearAuthHex, clearAuth, &clearAuthSz);
    if (rc != 0 || clearAuthSz != 32) {
        printf("  Error: ClearAuth must be exactly 32 bytes, got %u\n",
            clearAuthSz);
        return BAD_FUNC_ARG;
    }

    /* Build payload: PSK(64) + SHA-384(ClearAuth)(48) */
    XMEMCPY(payload, psk, 64);
    rc = wc_InitSha384(&sha);
    if (rc == 0) rc = wc_Sha384Update(&sha, clearAuth, clearAuthSz);
    if (rc == 0) rc = wc_Sha384Final(&sha, payload + 64);
    wc_Sha384Free(&sha);
    XMEMSET(psk, 0, sizeof(psk));
    if (rc != 0) {
        printf("  SHA-384 failed: %d\n", rc);
        XMEMSET(payload, 0, sizeof(payload));
        return rc;
    }

    printf("  ClearAuthDigest = SHA-384(%u bytes ClearAuth)\n", clearAuthSz);

    /* PSK_SET is a vendor-defined SPDM command — needs GET_VERSION first */
    rc = wolfSPDM_GetVersion(dev->spdmCtx->spdmCtx);
    if (rc != 0) {
        printf("  GET_VERSION failed: %d\n", rc);
        XMEMSET(payload, 0, sizeof(payload));
        return rc;
    }

    rc = wolfTPM2_SpdmNationsPskSet(dev, payload, sizeof(payload));
    XMEMSET(payload, 0, sizeof(payload));
    if (rc == 0)
        printf("  PSK provisioned (64-byte PSK + 48-byte digest)\n");
    else
        printf("  FAILED: 0x%x: %s\n", rc, TPM2_GetRCString(rc));
    return rc;
}

static int ctrl_nations_psk_clear(WOLFTPM2_DEV* dev, const char* authHex)
{
    int rc;
    byte clearAuth[256];
    word32 clearAuthSz = sizeof(clearAuth);

    printf("\n=== Nations PSK Clear ===\n");

    if (authHex == NULL) {
        printf("  Error: --psk-clear requires ClearAuth hex argument\n");
        return BAD_FUNC_ARG;
    }
    rc = hex2bin(authHex, clearAuth, &clearAuthSz);
    if (rc != 0 || clearAuthSz != 32) {
        printf("  Error: ClearAuth must be exactly 32 bytes, got %u\n",
            clearAuthSz);
        return BAD_FUNC_ARG;
    }
    /* PSK_CLEAR: sends raw 32-byte ClearAuth. TPM computes SHA-384
     * internally and compares against stored ClearAuthDigest. */
    rc = wolfSPDM_Nations_PskClearWithVCA(dev->spdmCtx->spdmCtx,
        clearAuth, clearAuthSz);
    XMEMSET(clearAuth, 0, sizeof(clearAuth));
    if (rc == 0)
        printf("  PSK cleared\n");
    else
        printf("  FAILED: 0x%x: %s\n", rc, TPM2_GetRCString(rc));
    return rc;
}

static int ctrl_nations_identity_key_set(WOLFTPM2_DEV* dev, int set)
{
    int rc;
    printf("\n=== Nations Identity Key %s ===\n", set ? "Set" : "Unset");
    rc = wolfTPM2_SpdmNationsIdentityKeySet(dev, set);
    if (rc == 0) {
        printf("  Identity key %s\n", set ? "provisioned" : "un-provisioned");
    } else {
        printf("  FAILED: 0x%x: %s\n", rc, TPM2_GetRCString(rc));
    }
    return rc;
}

static int ctrl_nations_get_pubkey(WOLFTPM2_DEV* dev)
{
    int rc;
    byte pubKey[128];
    word32 pubKeySz = sizeof(pubKey);
    word32 i;

    printf("\n=== Get SPDM-Identity Public Key ===\n");

    /* GET_PUBK is a vendor SPDM command — needs GET_VERSION first */
    rc = wolfSPDM_GetVersion(dev->spdmCtx->spdmCtx);
    if (rc != 0) {
        printf("  GET_VERSION failed: %d\n", rc);
        return rc;
    }

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

static int ctrl_nations_caps184(WOLFTPM2_DEV* dev)
{
    int rc;
    GetCapability_In capIn;
    GetCapability_Out capOut;
    word32 i;
    (void)dev;

    printf("\n=== Nations TPM 184 Capabilities ===\n");

    /* 1. Vendor properties (identity key status, FIPS mode, etc.) */
    printf("  Vendor Properties (TPM_CAP_VENDOR_PROPERTY):\n");
    XMEMSET(&capIn, 0, sizeof(capIn));
    capIn.capability = TPM_CAP_VENDOR_PROPERTY;
    capIn.property = 11; /* FIPS_SL2_MODE */
    capIn.propertyCount = 2; /* Read props 11 and 12 */
    XMEMSET(&capOut, 0, sizeof(capOut));
    rc = TPM2_GetCapability(&capIn, &capOut);
    if (rc == 0) {
        /* Vendor props are raw UINT32 values, not tagged pairs.
         * With count=2 starting at prop 11, we get props 11 and 12 */
        byte* raw = (byte*)&capOut.capabilityData.data.tpmProperties;
        printf("    Raw response: ");
        for (i = 0; i < 16 && i < sizeof(capOut.capabilityData); i++)
            printf("%02x", raw[i]);
        printf("\n");
    } else {
        printf("    Failed: 0x%x: %s\n", rc, TPM2_GetRCString(rc));
    }

    /* 2. TPM_CAP_PUB_KEYS (TPM 184: SPDM identity keys) */
    printf("  SPDM Public Keys (TPM_CAP_PUB_KEYS):\n");
    XMEMSET(&capIn, 0, sizeof(capIn));
    capIn.capability = TPM_CAP_PUB_KEYS;
    capIn.property = 0;
    capIn.propertyCount = 1;
    XMEMSET(&capOut, 0, sizeof(capOut));
    rc = TPM2_GetCapability(&capIn, &capOut);
    if (rc == 0) {
        byte* raw = (byte*)&capOut.capabilityData;
        word32 rawSz = sizeof(capOut.capabilityData);
        printf("    Response (%u bytes): ", rawSz);
        for (i = 0; i < rawSz && i < 64; i++)
            printf("%02x", raw[i]);
        if (rawSz > 64) printf("...");
        printf("\n");
    } else if (rc == TPM_RC_VALUE) {
        printf("    Not supported (TPM_RC_VALUE)\n");
    } else {
        printf("    Failed: 0x%x: %s\n", rc, TPM2_GetRCString(rc));
    }

    /* 3. TPM_CAP_SPDM_SESSION_INFO (TPM 184: SPDM session state) */
    printf("  SPDM Session Info (TPM_CAP_SPDM_SESSION_INFO):\n");
    XMEMSET(&capIn, 0, sizeof(capIn));
    capIn.capability = TPM_CAP_SPDM_SESSION_INFO;
    capIn.property = 0;
    capIn.propertyCount = 1;
    XMEMSET(&capOut, 0, sizeof(capOut));
    rc = TPM2_GetCapability(&capIn, &capOut);
    if (rc == 0) {
        byte* raw = (byte*)&capOut.capabilityData;
        word32 rawSz = sizeof(capOut.capabilityData);
        printf("    Response (%u bytes): ", rawSz);
        for (i = 0; i < rawSz && i < 64; i++)
            printf("%02x", raw[i]);
        if (rawSz > 64) printf("...");
        printf("\n");
    } else if (rc == TPM_RC_VALUE) {
        printf("    Not supported (TPM_RC_VALUE)\n");
    } else {
        printf("    Failed: 0x%x: %s\n", rc, TPM2_GetRCString(rc));
    }

    return 0;
}

static int ctrl_nations_connect(WOLFTPM2_DEV* dev)
{
    int rc;

    printf("\n=== SPDM Connect (Nations) ===\n");
    if (wolfTPM2_SpdmIsConnected(dev)) {
        printf("  Already connected (SessionID: 0x%08x)\n",
            wolfTPM2_SpdmGetSessionId(dev));
        return 0;
    }

    printf("  Handshake: VERSION -> GET_PUBK -> KEY_EXCHANGE -> "
           "GIVE_PUB -> FINISH\n");
    rc = wolfTPM2_SpdmConnectNations(dev, NULL, 0, NULL, 0);
    if (rc == 0) {
        printf("  Session established (AES-256-GCM, SessionID: 0x%08x)\n",
            wolfTPM2_SpdmGetSessionId(dev));
    } else {
        printf("  FAILED: 0x%x: %s\n", rc, TPM2_GetRCString(rc));
    }
    return rc;
}
#endif /* WOLFSPDM_NATIONS */

int TPM2_SPDM_Ctrl(void* userCtx, int argc, char *argv[])
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
#elif defined(WOLFSPDM_NATIONS)
    wolfTPM2_SpdmSetNationsMode(&dev);
    wolfTPM2_SPDM_SetTisIO(dev.spdmCtx);
#ifdef DEBUG_WOLFTPM
    wolfSPDM_SetDebug(dev.spdmCtx->spdmCtx, 1);
#endif
#endif

    for (i = 1; i < argc; i++) {
#ifdef WOLFSPDM_NUVOTON
        if (XSTRCMP(argv[i], "--enable") == 0)
            rc = ctrl_enable(&dev);
        else if (XSTRCMP(argv[i], "--disable") == 0)
            rc = ctrl_disable(&dev);
        else if (XSTRCMP(argv[i], "--status") == 0)
            rc = ctrl_status(&dev);
        else if (XSTRCMP(argv[i], "--get-pubkey") == 0)
            rc = ctrl_get_pubkey(&dev);
        else if (XSTRCMP(argv[i], "--connect") == 0)
            rc = ctrl_connect(&dev);
        else if (XSTRCMP(argv[i], "--lock") == 0)
            rc = ctrl_lock(&dev, 1);
        else if (XSTRCMP(argv[i], "--unlock") == 0)
            rc = ctrl_lock(&dev, 0);
        else
#endif
#ifdef WOLFSPDM_NATIONS
        if (XSTRCMP(argv[i], "--identity-key-set") == 0)
            rc = ctrl_nations_identity_key_set(&dev, 1);
        else if (XSTRCMP(argv[i], "--identity-key-unset") == 0)
            rc = ctrl_nations_identity_key_set(&dev, 0);
        else if (XSTRCMP(argv[i], "--get-pubkey") == 0)
            rc = ctrl_nations_get_pubkey(&dev);
        else if (XSTRCMP(argv[i], "--connect") == 0)
            rc = ctrl_nations_connect(&dev);
        else if (XSTRCMP(argv[i], "--status") == 0)
            rc = ctrl_nations_status(&dev);
        else if (XSTRCMP(argv[i], "--psk") == 0 && i + 1 < argc)
            rc = ctrl_nations_psk_connect(&dev, argv[++i]);
        else if (XSTRCMP(argv[i], "--psk-set") == 0 && i + 2 < argc)
        {
            const char* pskArg = argv[++i];
            const char* authArg = argv[++i];
            rc = ctrl_nations_psk_set(&dev, pskArg, authArg);
        }
        else if (XSTRCMP(argv[i], "--psk-clear") == 0 && i + 1 < argc)
            rc = ctrl_nations_psk_clear(&dev, argv[++i]);
        else if (XSTRCMP(argv[i], "--lock") == 0)
            rc = wolfTPM2_SpdmNationsSetOnlyMode(&dev, 1);
        else if (XSTRCMP(argv[i], "--unlock") == 0)
            rc = wolfTPM2_SpdmNationsSetOnlyMode(&dev, 0);
        else if (XSTRCMP(argv[i], "--tpm-clear") == 0) {
            printf("\n=== TPM2_Clear ===\n");
            rc = wolfTPM2_Clear(&dev);
            printf("  %s (rc=0x%x)\n", rc == 0 ? "Success" : "FAILED", rc);
        }
        else if (XSTRCMP(argv[i], "--caps184") == 0)
            rc = ctrl_nations_caps184(&dev);
        else
#endif
        { printf("Unknown option: %s\n", argv[i]); usage(); rc = BAD_FUNC_ARG; }
        if (rc != 0) break;
    }

    wolfTPM2_Cleanup(&dev);  /* TPM2_Shutdown + END_SESSION via SPDM, then free */
    wolfTPM2_SpdmCleanup(&dev);  /* no-op safety net (already freed by Cleanup) */
    return rc;
}

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = -1;
#ifndef WOLFTPM2_NO_WRAPPER
    rc = TPM2_SPDM_Ctrl(NULL, argc, argv);
#else
    printf("Wrapper code not compiled in\n");
    (void)argc; (void)argv;
#endif
    return (rc == 0) ? 0 : 1;
}
#endif

#endif /* WOLFTPM_SPDM */
#endif /* !WOLFTPM2_NO_WRAPPER */
