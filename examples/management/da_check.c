/* da_check.c
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

/* Exercises Dictionary Attack (DA) vs noDA behavior end to end: signing with a
 * DA-protected (non-noDA) key rides through the TPM_RC_RETRY the TPM returns
 * while it persists the daUsed flag on first auth use, and a noDA key never
 * trips lockout. With -lockout it also drives the lockout/recovery path. */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2_wrap.h>
#include <examples/management/management.h>
#include <hal/tpm_io.h>
#include <examples/tpm_test.h>

#include <stdio.h>

#if !defined(WOLFTPM2_NO_WRAPPER) && defined(HAVE_ECC)

/* Sign a digest, resubmitting on TPM_RC_RETRY. A real TPM (and fwTPM built
 * with FWTPM_DA_USED_RETRY) returns RETRY once while it persists daUsed on the
 * first DA-protected auth use. The wolfTPM client does not auto-resubmit, so
 * callers must resend the identical command, as this loop does. */
static int DaSignWithRetry(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    const byte* digest, int digestSz, byte* sig, int sigCap)
{
    int rc;
    int sigSz;
    int retries = 0;

    do {
        sigSz = sigCap;
        rc = wolfTPM2_SignHash(dev, key, digest, digestSz, sig, &sigSz);
        if (rc == TPM_RC_RETRY) {
            printf("  TPM_RC_RETRY (daUsed persist) - resubmitting\n");
        }
    } while (rc == TPM_RC_RETRY && ++retries < 10);

    return rc;
}


int TPM2_DA_Check_Example(void* userCtx, int argc, char *argv[])
{
    int rc;
    int i;
    int sigSz;
    int locked = 0;
    int doLockout = 0;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY srk;
    WOLFTPM2_KEY daKey;     /* DA-protected: noDA clear */
    WOLFTPM2_KEY noDaKey;   /* noDA set */
    TPMT_PUBLIC publicTemplate;
    byte digest[TPM_SHA256_DIGEST_SIZE];
    byte sig[256];
    const byte keyAuth[] = { 'd', 'a', '-', 'a', 'u', 't', 'h' };

    for (i = 1; i < argc; i++) {
        if (XSTRCMP(argv[i], "-lockout") == 0) {
            doLockout = 1;
        }
    }

    XMEMSET(&dev, 0, sizeof(dev));
    XMEMSET(&srk, 0, sizeof(srk));
    XMEMSET(&daKey, 0, sizeof(daKey));
    XMEMSET(&noDaKey, 0, sizeof(noDaKey));
    XMEMSET(digest, 0x11, sizeof(digest));

    printf("TPM2 Dictionary Attack (DA / noDA) check\n");

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_Init failed 0x%x: %s\n", rc, wolfTPM2_GetRCString(rc));
        return rc;
    }

    rc = wolfTPM2_CreateSRK(&dev, &srk, TPM_ALG_ECC, NULL, 0);
    if (rc != 0) goto exit;

    /* DA-protected ECC signing key (noDA deliberately omitted). */
    rc = wolfTPM2_GetKeyTemplate_ECC(&publicTemplate,
        TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent |
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_sign,
        TPM_ECC_NIST_P256, TPM_ALG_ECDSA);
    if (rc != 0) goto exit;
    publicTemplate.nameAlg = TPM_ALG_SHA256;
    rc = wolfTPM2_CreateAndLoadKey(&dev, &daKey, &srk.handle, &publicTemplate,
        keyAuth, (int)sizeof(keyAuth));
    if (rc != 0) goto exit;
    printf("Created DA-protected ECC signing key (noDA clear)\n");

    /* First auth use of a DA-protected key may return TPM_RC_RETRY. */
    rc = DaSignWithRetry(&dev, &daKey, digest, (int)sizeof(digest),
        sig, (int)sizeof(sig));
    if (rc != 0) goto exit;
    printf("Signed with DA-protected key (rode through any RC_RETRY)\n");

    if (doLockout) {
        wolfTPM2_SetAuthPassword(&dev, 0, NULL);
        rc = wolfTPM2_DictionaryAttackParameters(&dev, 3, 0, 0);
        if (rc != 0) goto exit;

        /* Bad auth until lockout. */
        daKey.handle.auth.buffer[0] ^= 0xFF;
        for (i = 0; i < 8 && !locked; i++) {
            sigSz = (int)sizeof(sig);
            rc = wolfTPM2_SignHash(&dev, &daKey, digest, (int)sizeof(digest),
                sig, &sigSz);
            if (rc == TPM_RC_LOCKOUT) {
                locked = 1;
            }
        }
        daKey.handle.auth.buffer[0] ^= 0xFF;
        if (!locked) {
            printf("Expected lockout was not reached\n");
            rc = TPM_RC_FAILURE;
            goto exit;
        }
        printf("Entered lockout after repeated bad auth\n");

        wolfTPM2_SetAuthPassword(&dev, 0, NULL);
        rc = wolfTPM2_DictionaryAttackLockReset(&dev);
        if (rc != 0) goto exit;
        rc = DaSignWithRetry(&dev, &daKey, digest, (int)sizeof(digest),
            sig, (int)sizeof(sig));
        if (rc != 0) goto exit;
        printf("Recovered via DictionaryAttackLockReset; signing works\n");
    }

    /* noDA contrast key. */
    rc = wolfTPM2_GetKeyTemplate_ECC(&publicTemplate,
        TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent |
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_sign | TPMA_OBJECT_noDA,
        TPM_ECC_NIST_P256, TPM_ALG_ECDSA);
    if (rc != 0) goto exit;
    publicTemplate.nameAlg = TPM_ALG_SHA256;
    rc = wolfTPM2_CreateAndLoadKey(&dev, &noDaKey, &srk.handle, &publicTemplate,
        keyAuth, (int)sizeof(keyAuth));
    if (rc != 0) goto exit;

    /* Repeated bad auth on a noDA key must never reach lockout. */
    noDaKey.handle.auth.buffer[0] ^= 0xFF;
    for (i = 0; i < 8; i++) {
        sigSz = (int)sizeof(sig);
        rc = wolfTPM2_SignHash(&dev, &noDaKey, digest, (int)sizeof(digest),
            sig, &sigSz);
        if (rc == TPM_RC_LOCKOUT) {
            printf("noDA key unexpectedly hit lockout\n");
            noDaKey.handle.auth.buffer[0] ^= 0xFF;
            rc = TPM_RC_FAILURE;
            goto exit;
        }
    }
    noDaKey.handle.auth.buffer[0] ^= 0xFF;

    /* A correct-auth noDA sign never returns RC_RETRY. */
    sigSz = (int)sizeof(sig);
    rc = wolfTPM2_SignHash(&dev, &noDaKey, digest, (int)sizeof(digest),
        sig, &sigSz);
    if (rc == TPM_RC_RETRY) {
        printf("noDA key unexpectedly returned RC_RETRY\n");
        rc = TPM_RC_FAILURE;
        goto exit;
    }
    if (rc != 0) goto exit;
    printf("noDA key: no lockout, no RC_RETRY (DA bypassed as expected)\n");

    printf("DA check example complete\n");

exit:
    if (rc != 0) {
        printf("Failure 0x%x: %s\n", rc, wolfTPM2_GetRCString(rc));
    }

    /* Best-effort: do not leave the TPM locked for subsequent examples. */
    wolfTPM2_SetAuthPassword(&dev, 0, NULL);
    (void)wolfTPM2_DictionaryAttackLockReset(&dev);

    wolfTPM2_UnloadHandle(&dev, &noDaKey.handle);
    wolfTPM2_UnloadHandle(&dev, &daKey.handle);
    wolfTPM2_UnloadHandle(&dev, &srk.handle);
    wolfTPM2_Cleanup(&dev);
    return rc;
}
#endif /* !WOLFTPM2_NO_WRAPPER && HAVE_ECC */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = NOT_COMPILED_IN;

#if !defined(WOLFTPM2_NO_WRAPPER) && defined(HAVE_ECC)
    rc = TPM2_DA_Check_Example(NULL, argc, argv);
#else
    printf("DA check tool requires the wrapper and ECC\n");
    (void)argc;
    (void)argv;
#endif

    return rc;
}
#endif
