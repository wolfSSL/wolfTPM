/* nv_bind.c
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

/* Bind an NV index to an SPDM session with TPM2_PolicyTransportSPDM so it can
 * only be accessed over the SPDM secure channel: a secret in NV that a normal
 * (plaintext) bus request cannot reach.
 *
 * The demo runs against a firmware TPM started in SPDM-PSK mode:
 *   ./src/fwtpm/fwtpm_server --spdm-psk --spdm-psk-hex <psk> --clear &
 *   ./examples/spdm/nv_bind --psk <psk>
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

int TPM2_SPDM_NVBind_Example(void* userCtx, int argc, char *argv[]);

#if defined(WOLFTPM_SPDM) && defined(WOLFTPM_SPDM_PSK)

#define NV_BIND_INDEX  TPM2_DEMO_NVRAM_STORE_INDEX

static int nv_bind_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int nv_bind_hex(const char* hex, byte* out, word32 outSz, word32* usedSz)
{
    word32 len = (word32)XSTRLEN(hex);
    word32 i;
    int hi, lo;

    if ((len & 1U) != 0U || (len / 2U) > outSz) {
        return BAD_FUNC_ARG;
    }
    for (i = 0; i < len; i += 2) {
        hi = nv_bind_nibble(hex[i]);
        lo = nv_bind_nibble(hex[i + 1]);
        if (hi < 0 || lo < 0) {
            return BAD_FUNC_ARG;
        }
        out[i / 2] = (byte)((hi << 4) | lo);
    }
    *usedSz = len / 2U;
    return TPM_RC_SUCCESS;
}

/* Read the SPDM-bound NV index through a fresh policy session that asserts
 * PolicyTransportSPDM. Returns the TPM_RC so the caller can tell an
 * off-channel denial (TPM_RC_CHANNEL) from a real error. */
static int nv_bind_policy_read(WOLFTPM2_DEV* dev, WOLFTPM2_NV* nv,
    byte* buf, word32* bufSz)
{
    int rc;
    WOLFTPM2_SESSION session;

    XMEMSET(&session, 0, sizeof(session));
    /* Writing flips TPMA_NV_WRITTEN and changes the Name, so refresh it. */
    rc = wolfTPM2_NVOpen(dev, nv, NV_BIND_INDEX, NULL, 0);
    if (rc == 0) {
        rc = wolfTPM2_StartSession(dev, &session, NULL, NULL, TPM_SE_POLICY,
            TPM_ALG_NULL);
    }
    if (rc == 0) {
        rc = wolfTPM2_SetAuthSession(dev, 0, &session,
            TPMA_SESSION_continueSession);
    }
    if (rc == 0) {
        rc = wolfTPM2_PolicyTransportSPDM(dev, session.handle.hndl, NULL, NULL);
    }
    if (rc == 0) {
        rc = wolfTPM2_NVReadAuth(dev, nv, NV_BIND_INDEX, buf, bufSz, 0);
    }
    if (session.handle.hndl != 0) {
        wolfTPM2_UnsetAuth(dev, 0);
        wolfTPM2_UnloadHandle(dev, &session.handle);
    }
    return rc;
}

/* Create the NV index and write the secret to it over SPDM. */
static int nv_bind_provision(WOLFTPM2_DEV* dev, const byte* secret,
    word32 secretSz, const byte* policyDigest, word32 policyDigestSz)
{
    int rc;
    word32 nvAttributes;
    WOLFTPM2_HANDLE parent;
    WOLFTPM2_SESSION session;
    WOLFTPM2_NV nv;
    int nvAttempted = 0;

    XMEMSET(&parent, 0, sizeof(parent));
    XMEMSET(&session, 0, sizeof(session));
    XMEMSET(&nv, 0, sizeof(nv));
    parent.hndl = TPM_RH_OWNER;

    rc = wolfTPM2_GetNvAttributesTemplate(parent.hndl, &nvAttributes);
    if (rc == 0) {
        /* Policy-only: clear owner and auth access so the SPDM policy is the
         * only way in (an owner-authorized read would otherwise bypass it). */
        nvAttributes &= ~(TPMA_NV_AUTHREAD | TPMA_NV_AUTHWRITE |
            TPMA_NV_OWNERREAD | TPMA_NV_OWNERWRITE);
        nvAttributes |= (TPMA_NV_POLICYREAD | TPMA_NV_POLICYWRITE);
        nvAttempted = 1;
        rc = wolfTPM2_NVCreateAuthPolicy(dev, &parent, &nv, NV_BIND_INDEX,
            nvAttributes, secretSz, NULL, 0, policyDigest, (int)policyDigestSz);
        if (rc == TPM_RC_NV_DEFINED) {
            rc = wolfTPM2_NVDeleteAuth(dev, &parent, NV_BIND_INDEX);
            if (rc == 0) {
                rc = wolfTPM2_NVCreateAuthPolicy(dev, &parent, &nv,
                    NV_BIND_INDEX, nvAttributes, secretSz, NULL, 0,
                    policyDigest, (int)policyDigestSz);
            }
        }
    }
    if (rc == 0) {
        rc = wolfTPM2_StartSession(dev, &session, NULL, NULL, TPM_SE_POLICY,
            TPM_ALG_NULL);
    }
    if (rc == 0) {
        rc = wolfTPM2_SetAuthSession(dev, 0, &session,
            TPMA_SESSION_continueSession);
    }
    if (rc == 0) {
        rc = wolfTPM2_PolicyTransportSPDM(dev, session.handle.hndl, NULL, NULL);
    }
    if (rc == 0) {
        rc = wolfTPM2_NVWriteAuth(dev, &nv, NV_BIND_INDEX, (byte*)secret,
            secretSz, 0);
    }
    if (session.handle.hndl != 0) {
        wolfTPM2_UnsetAuth(dev, 0);
        wolfTPM2_UnloadHandle(dev, &session.handle);
    }
    /* The wrapper defines the index before it opens it, so clean up on any
     * failure after the attempt, not only after a reported success. */
    if (rc != 0 && nvAttempted) {
        (void)wolfTPM2_NVDeleteAuth(dev, &parent, NV_BIND_INDEX);
    }
    return rc;
}

int TPM2_SPDM_NVBind_Example(void* userCtx, int argc, char *argv[])
{
    int rc;
    int i;
    const char* pskHex = NULL;
    byte psk[128];
    word32 pskSz = 0;
    byte secret[] = "SPDM-only NV secret";
    byte readBuf[sizeof(secret)];
    word32 readSz;
    byte policyDigest[TPM_MAX_DIGEST_SIZE];
    word32 policyDigestSz;
    WOLFTPM2_DEV dev;
    WOLFTPM2_NV nv;
    WOLFTPM2_HANDLE parent;
    int nvProvisioned = 0;

    for (i = 1; i < argc; i++) {
        if (XSTRCMP(argv[i], "--psk") == 0 && i + 1 < argc) {
            pskHex = argv[++i];
        }
        else if (XSTRCMP(argv[i], "-h") == 0 ||
                 XSTRCMP(argv[i], "--help") == 0) {
            printf("Usage: nv_bind --psk <hex-psk>\n");
            printf("Binds NV index 0x%x to an SPDM session.\n", NV_BIND_INDEX);
            return 0;
        }
    }
#ifndef NO_GETENV
    if (pskHex == NULL) {
        pskHex = getenv("WOLFTPM_TEST_SPDM_PSK");
    }
#endif
    if (pskHex == NULL || pskHex[0] == '\0') {
        printf("No PSK provided (use --psk <hex> or WOLFTPM_TEST_SPDM_PSK)\n");
        return 0;
    }
    XMEMSET(&nv, 0, sizeof(nv));
    XMEMSET(&parent, 0, sizeof(parent));
    XMEMSET(readBuf, 0, sizeof(readBuf));
    parent.hndl = TPM_RH_OWNER;

    /* The policy binds to any SPDM session (no key names). */
    XMEMSET(policyDigest, 0, sizeof(policyDigest));
    policyDigestSz = (word32)sizeof(policyDigest);
    rc = wolfTPM2_PolicyTransportSPDMMake(WOLFTPM2_WRAP_DIGEST, NULL, NULL,
        policyDigest, &policyDigestSz);
    if (rc != 0) {
        printf("PolicyTransportSPDMMake failed 0x%x: %s\n",
            rc, TPM2_GetRCString(rc));
        return rc;
    }

    printf("=== Bind an NV index to an SPDM session ===\n");
    printf("NV index 0x%x, authPolicy = PolicyTransportSPDM: ", NV_BIND_INDEX);
    TPM2_PrintBin(policyDigest, policyDigestSz);

    /* Decode the PSK just before use; every path from here zeroizes it. */
    rc = nv_bind_hex(pskHex, psk, (word32)sizeof(psk), &pskSz);
    if (rc != 0) {
        wc_ForceZero(psk, sizeof(psk));
        printf("Invalid PSK hex string\n");
        return rc;
    }

    /* Step 1: over SPDM, create the index and store the secret. */
    printf("\n[1] Over the SPDM channel: provision and store the secret\n");
    XMEMSET(&dev, 0, sizeof(dev));
    rc = wolfTPM2_InitWithSpdmPsk(&dev, TPM2_IoCb, userCtx, psk, pskSz,
        NULL, 0);
    wc_ForceZero(psk, sizeof(psk));
    if (rc != 0) {
        printf("  SPDM init failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        return rc;
    }
    if (!wolfTPM2_SpdmIsConnected(&dev)) {
        printf("  SPDM session not established\n");
        wolfTPM2_Cleanup(&dev);
        return WOLFSPDM_E_BAD_STATE;
    }
    printf("  SPDM session established (0x%08x)\n",
        wolfTPM2_SpdmGetSessionId(&dev));
    rc = nv_bind_provision(&dev, secret, (word32)sizeof(secret),
        policyDigest, policyDigestSz);
    if (rc == 0) {
        nvProvisioned = 1;
        readSz = (word32)sizeof(readBuf);
        rc = nv_bind_policy_read(&dev, &nv, readBuf, &readSz);
    }
    if (rc == 0 && (readSz != (word32)sizeof(secret) ||
            XMEMCMP(readBuf, secret, readSz) != 0)) {
        printf("  Read-back mismatch over SPDM\n");
        rc = TPM_RC_FAILURE;
    }
    if (rc == 0) {
        printf("  Wrote and read back over SPDM: \"%s\"\n", (char*)readBuf);
    }
    else {
        printf("  FAILED over SPDM 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        /* Remove the index before leaving so nothing persists on failure. */
        if (nvProvisioned)
            (void)wolfTPM2_NVDeleteAuth(&dev, &parent, NV_BIND_INDEX);
    }
    wolfTPM2_Cleanup(&dev);
    if (rc != 0) {
        return rc;
    }

    /* Step 2: off the channel (plaintext bus), the same read is refused. */
    printf("\n[2] Off the SPDM channel: the same read is refused\n");
    XMEMSET(&dev, 0, sizeof(dev));
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != 0) {
        printf("  Plaintext init failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        if (nvProvisioned) {
            printf("  NV index 0x%x remains; remove it with NV_UndefineSpace\n",
                NV_BIND_INDEX);
        }
        return rc;
    }
    XMEMSET(&nv, 0, sizeof(nv));
    readSz = (word32)sizeof(readBuf);
    rc = nv_bind_policy_read(&dev, &nv, readBuf, &readSz);
    /* Format-one codes may carry an auth-session selector in the upper bits. */
    if ((rc & RC_MAX_FMT1) == TPM_RC_CHANNEL) {
        printf("  Correctly denied with TPM_RC_CHANNEL: "
               "no SPDM channel, no access\n");
        rc = TPM_RC_SUCCESS;
    }
    else if (rc == TPM_RC_SUCCESS) {
        printf("  UNEXPECTED: plaintext read succeeded\n");
        rc = TPM_RC_FAILURE;
    }
    else {
        printf("  UNEXPECTED 0x%x: %s\n", rc, TPM2_GetRCString(rc));
    }

    /* Clean up the NV index (owner authorization, not the NV policy). */
    (void)wolfTPM2_NVDeleteAuth(&dev, &parent, NV_BIND_INDEX);
    wolfTPM2_Cleanup(&dev);

    printf("\n%s\n", rc == TPM_RC_SUCCESS ?
        "PASS: the NV index is reachable only over SPDM" :
        "FAIL");
    return rc;
}

#else /* !WOLFTPM_SPDM || !WOLFTPM_SPDM_PSK */
int TPM2_SPDM_NVBind_Example(void* userCtx, int argc, char *argv[])
{
    (void)userCtx; (void)argc; (void)argv;
    printf("Example requires --enable-spdm --enable-psk\n");
    return 0;
}
#endif

#endif /* !WOLFTPM2_NO_WRAPPER */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = -1;
#ifndef WOLFTPM2_NO_WRAPPER
    rc = TPM2_SPDM_NVBind_Example(NULL, argc, argv);
#else
    printf("Wrapper code not compiled in\n");
    (void)argc; (void)argv;
#endif
    return rc == 0 ? 0 : 1;
}
#endif
