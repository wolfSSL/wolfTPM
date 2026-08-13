/* firmware_policy.c
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <examples/firmware/firmware_policy.h>

/* These helpers are built on the wolfTPM2 wrapper API and use wolfCrypt hashing */
#if defined(WOLFTPM_FIRMWARE_UPGRADE) && !defined(WOLFTPM2_NO_WRAPPER) && \
    !defined(WOLFTPM2_NO_WOLFCRYPT)

#include <stdio.h>

/* Print a digest as hex. Unlike TPM2_PrintBin (a no-op unless DEBUG_WOLFTPM),
 * this is always available so the self-test failure report is usable in a
 * stock build. */
static void firmware_print_hex(const byte* buf, word32 len)
{
    word32 j;
    for (j = 0; j < len; j++) {
        printf("%02x", buf[j]);
    }
    printf("\n");
}

/* Report whether the LOCAL wolfCrypt build implements this hash.
 * wolfTPM2_IsAlgSupported only reports what the TPM implements, and
 * TPM2_GetHashDigestSize is a static table lookup that answers 64 for SHA2-512
 * regardless of build flags. Without this check a TPM that implements a hash
 * wolfCrypt was not built with would take the offline digest path and fail in
 * wc_HashInit, turning a build-configuration mismatch into a self-test
 * failure. wc_HashGetDigestSize returns negative for an unavailable hash. */
static int firmware_hash_local_supported(TPMI_ALG_HASH hashAlg)
{
    enum wc_HashType hashType;
    int rc;

    rc = TPM2_GetHashType(hashAlg);
    if (rc <= 0) {
        return 0;
    }
    hashType = (enum wc_HashType)rc;
    return (wc_HashGetDigestSize(hashType) > 0) ? 1 : 0;
}

/* Exercise wolfTPM2_PolicyOR at the requested hash and verify the TPM's
 * running policy digest matches an offline computation. Non-destructive.
 * The skip decision is reported through *skipped rather than a magic return
 * value, so the return code namespace holds only real errors and cannot
 * collide with a TPM rc. Returns 0 on match (or when skipped), TPM_RC_POLICY
 * on digest mismatch, or a TPM rc / BAD_FUNC_ARG on other errors. */
static int firmware_policy_selftest(WOLFTPM2_DEV* dev, TPMI_ALG_HASH hashAlg,
    const char* name, int* skipped)
{
    int rc;
    int isSupported = 0;
    WOLFTPM2_SESSION sess;
    TPML_DIGEST orList;
    word32 hsz = (word32)TPM2_GetHashDigestSize(hashAlg);
    byte branchA[TPM_MAX_DIGEST_SIZE];
    byte branchB[TPM_MAX_DIGEST_SIZE];
    byte concat[2 * TPM_MAX_DIGEST_SIZE];
    byte expected[TPM_MAX_DIGEST_SIZE];
    byte got[TPM_MAX_DIGEST_SIZE];
    word32 aSz = 0, bSz = 0, expSz = 0, gotSz = 0;

    XMEMSET(&sess, 0, sizeof(sess));
    XMEMSET(&orList, 0, sizeof(orList));

    if (skipped == NULL) {
        return BAD_FUNC_ARG;
    }
    *skipped = 0;
    if (hsz == 0 || hsz > TPM_MAX_DIGEST_SIZE) {
        return BAD_FUNC_ARG;
    }

    /* Skip cleanly if the local wolfCrypt build cannot hash with this
     * algorithm - the offline digest below needs it, and a build mismatch is
     * not a self-test failure. */
    if (!firmware_hash_local_supported(hashAlg)) {
        printf("  %s: skipped (not built into this wolfCrypt)\n", name);
        *skipped = 1;
        return 0;
    }

    /* Skip cleanly if the TPM does not implement this hash. A query failure is
     * reported and returned, distinct from "not implemented". */
    rc = wolfTPM2_IsAlgSupported(dev, hashAlg, &isSupported);
    if (rc != TPM_RC_SUCCESS) {
        printf("  %s: capability query failed 0x%x: %s\n",
            name, rc, TPM2_GetRCString(rc));
        return rc;
    }
    if (!isSupported) {
        printf("  %s: skipped (not implemented by this TPM)\n", name);
        *skipped = 1;
        return 0;
    }

    /* Offline: two distinct PolicyCommandCode branch digests. aSz/bSz are
     * in/out - supply the buffer capacity, get back the digest size. */
    aSz = (word32)sizeof(branchA);
    rc = wolfTPM2_PolicyCommandCodeMake(hashAlg, branchA, &aSz, TPM_CC_NV_Read);
    if (rc == 0) {
        bSz = (word32)sizeof(branchB);
        rc = wolfTPM2_PolicyCommandCodeMake(hashAlg, branchB, &bSz,
            TPM_CC_Unseal);
    }
    /* Offline PolicyOR digest = H(zeros || TPM_CC_PolicyOR || A || B) */
    if (rc == 0) {
        XMEMCPY(concat, branchA, aSz);
        XMEMCPY(&concat[aSz], branchB, bSz);
        XMEMSET(expected, 0, sizeof(expected));
        expSz = hsz;
        rc = wolfTPM2_PolicyHash(hashAlg, expected, &expSz,
            TPM_CC_PolicyOR, concat, aSz + bSz);
    }

    /* On-TPM: start a policy session using the requested hash algorithm */
    if (rc == 0) {
        rc = wolfTPM2_StartSession_ex(dev, &sess, NULL, NULL,
            TPM_SE_POLICY, TPM_ALG_NULL, hashAlg);
        if (rc != 0) {
            printf("  %s: StartSession failed 0x%x: %s\n",
                name, rc, TPM2_GetRCString(rc));
            return rc;
        }
    }
    /* Satisfy branch A, then OR against {A,B} with the new wrapper */
    if (rc == 0) {
        rc = wolfTPM2_PolicyCommandCode(dev, &sess, TPM_CC_NV_Read);
    }
    if (rc == 0) {
        orList.count = 2;
        orList.digests[0].size = (UINT16)aSz;
        XMEMCPY(orList.digests[0].buffer, branchA, aSz);
        orList.digests[1].size = (UINT16)bSz;
        XMEMCPY(orList.digests[1].buffer, branchB, bSz);
        rc = wolfTPM2_PolicyOR(dev, &sess, &orList);
    }
    if (rc == 0) {
        gotSz = (word32)sizeof(got);
        rc = wolfTPM2_GetPolicyDigest(dev, sess.handle.hndl, got, &gotSz);
    }

    if (rc == 0) {
        if (gotSz == expSz && XMEMCMP(got, expected, expSz) == 0) {
            printf("  %s PolicyOR: PASS (%u byte digest matches)\n",
                name, expSz);
        }
        else {
            printf("  %s PolicyOR: FAIL (digest mismatch)\n", name);
            printf("    expected: ");
            firmware_print_hex(expected, expSz);
            printf("    got:      ");
            firmware_print_hex(got, gotSz);
            /* a defined rc, so the caller can propagate it meaningfully */
            rc = TPM_RC_POLICY;
        }
    }
    else {
        printf("  %s PolicyOR: ERROR 0x%x: %s\n",
            name, rc, TPM2_GetRCString(rc));
    }

    if (sess.handle.hndl != 0) {
        wolfTPM2_UnloadHandle(dev, &sess.handle);
    }
    return rc;
}

int firmware_policy_selftest_all(WOLFTPM2_DEV* dev)
{
    int i, rc, skipped;
    int firstFail = 0;
    struct { TPMI_ALG_HASH alg; const char* name; } hashes[3];

    hashes[0].alg = TPM_ALG_SHA256; hashes[0].name = "SHA2-256";
    hashes[1].alg = TPM_ALG_SHA384; hashes[1].name = "SHA2-384";
    hashes[2].alg = TPM_ALG_SHA512; hashes[2].name = "SHA2-512";

    printf("Firmware policy authorization self-test "
           "(no firmware changes):\n");
    for (i = 0; i < 3; i++) {
        skipped = 0;
        rc = firmware_policy_selftest(dev, hashes[i].alg, hashes[i].name,
            &skipped);
        /* Keep the first real failure rc so the caller (and the process exit
         * status) can report why, rather than a generic -1. A skip is not a
         * failure. */
        if (rc != 0 && !skipped && firstFail == 0) {
            firstFail = rc;
        }
    }
    return firstFail;
}

/* Build the PolicyOR branch list this example provisions. Branch A authorizes
 * the vendor firmware start; branch B authorizes TPM2_SetPrimaryPolicy so the
 * policy can be rolled back under itself. */
static void firmware_policy_or_list(const FirmwarePolicyCtx* ctx,
    TPML_DIGEST* orList)
{
    XMEMSET(orList, 0, sizeof(*orList));
    orList->count = 2;
    orList->digests[0].size = (UINT16)ctx->branchSz;
    XMEMCPY(orList->digests[0].buffer, ctx->branchFu, ctx->branchSz);
    orList->digests[1].size = (UINT16)ctx->branchSz;
    XMEMCPY(orList->digests[1].buffer, ctx->branchSpp, ctx->branchSz);
}

/* Clear the platform authPolicy under a policy session that satisfies the
 * SetPrimaryPolicy branch. Only usable when a PolicyOR was provisioned. */
static int firmware_policy_clear_by_policy(WOLFTPM2_DEV* dev,
    FirmwarePolicyCtx* ctx)
{
    int rc;
    int restoreAuth = 0;
    WOLFTPM2_SESSION sess;
    TPML_DIGEST orList;

    XMEMSET(&sess, 0, sizeof(sess));

    rc = wolfTPM2_StartSession_ex(dev, &sess, NULL, NULL,
        TPM_SE_POLICY, TPM_ALG_NULL, ctx->hashAlg);
    if (rc == 0) {
        rc = wolfTPM2_PolicyCommandCode(dev, &sess, TPM_CC_SetPrimaryPolicy);
    }
    if (rc == 0) {
        firmware_policy_or_list(ctx, &orList);
        rc = wolfTPM2_PolicyOR(dev, &sess, &orList);
    }
    if (rc == 0) {
        /* route the next command's authorization through this policy session */
        rc = wolfTPM2_SetAuthSession(dev, 0, &sess, 0);
        if (rc == 0) {
            restoreAuth = 1;
        }
    }
    if (rc == 0) {
        rc = wolfTPM2_SetPrimaryPolicy(dev, TPM_RH_PLATFORM, TPM_ALG_NULL,
            NULL, 0);
        if (rc == TPM_RC_SUCCESS) {
            /* The session was set up with continueSession CLEAR, so the TPM
             * flushed it when the command completed. Mark it released (as the
             * library does for a consumed firmware-start session) so the
             * cleanup below does not send a FlushContext the TPM will
             * reject. */
            sess.handle.hndl = TPM_RH_NULL;
        }
    }

    /* restore the default password authorization on session slot 0 */
    if (restoreAuth) {
        wolfTPM2_SetAuthPassword(dev, 0, NULL);
    }
    if (sess.handle.hndl != 0) {
        wolfTPM2_UnloadHandle(dev, &sess.handle);
    }
    return rc;
}

int firmware_policy_clear(WOLFTPM2_DEV* dev, FirmwarePolicyCtx* ctx)
{
    int rc;

    if (dev == NULL || ctx == NULL) {
        return BAD_FUNC_ARG;
    }
    /* Never touch a policy this example did not install. Without this an early
     * failure (a bad firmware file, for example) would clear a platform policy
     * the deployment provisioned itself. */
    if (!ctx->provisioned) {
        return 0;
    }

    /* Default path: platform password authorization. Installing an authPolicy
     * does not disable the authValue path (TPM 2.0 Part 1 Sec.19.7), so this
     * succeeds whenever platformAuth is still the default empty password. */
    rc = wolfTPM2_SetPrimaryPolicy(dev, TPM_RH_PLATFORM, TPM_ALG_NULL, NULL, 0);

    /* Fallback: authorize the clear with the provisioned SetPrimaryPolicy
     * branch, for a deployment that set a non-default platformAuth. */
    if (rc != TPM_RC_SUCCESS && ctx->useOr) {
        printf("Clearing platform policy with default auth failed 0x%x: %s\n",
            rc, TPM2_GetRCString(rc));
        printf("  retrying under the SetPrimaryPolicy branch\n");
        rc = firmware_policy_clear_by_policy(dev, ctx);
    }

    if (rc == TPM_RC_SUCCESS) {
        ctx->provisioned = 0;
        printf("Cleared platform policy (restored default auth)\n");
    }
    else {
        printf("ERROR: could not clear the platform policy 0x%x: %s\n",
            rc, TPM2_GetRCString(rc));
        printf("  The platform hierarchy still requires the provisioned "
               "policy.\n");
        printf("  Reset or power cycle the TPM to restore default "
               "authorization.\n");
    }
    return rc;
}

int firmware_policy_session_setup(WOLFTPM2_DEV* dev, FirmwarePolicyCtx* ctx,
    TPMI_ALG_HASH hashAlg, int useOr, TPM_CC fuStartCC,
    WOLFTPM2_SESSION* session)
{
    int rc;
    int isSupported = 0;
    TPML_DIGEST orList;
    word32 hsz = (word32)TPM2_GetHashDigestSize(hashAlg);
    byte concat[2 * TPM_MAX_DIGEST_SIZE];
    byte platformPolicy[TPM_MAX_DIGEST_SIZE];
    word32 aSz, bSz = 0, polSz = 0;

    if (dev == NULL || ctx == NULL || session == NULL) {
        return BAD_FUNC_ARG;
    }
    if (hsz == 0 || hsz > TPM_MAX_DIGEST_SIZE) {
        return BAD_FUNC_ARG;
    }
    XMEMSET(ctx, 0, sizeof(*ctx));
    XMEMSET(session, 0, sizeof(*session));
    XMEMSET(&orList, 0, sizeof(orList));
    ctx->hashAlg = hashAlg;
    ctx->useOr = useOr;

    /* Fail early (before provisioning) if this policy hash is unusable, either
     * because the local wolfCrypt build lacks it or the TPM does not implement
     * it. Unlike the self-test these are hard errors: the caller explicitly
     * asked for this hash. */
    if (!firmware_hash_local_supported(hashAlg)) {
        printf("Policy hash %s not built into this wolfCrypt\n",
            TPM2_GetAlgName(hashAlg));
        return BAD_FUNC_ARG;
    }
    rc = wolfTPM2_IsAlgSupported(dev, hashAlg, &isSupported);
    if (rc != TPM_RC_SUCCESS) {
        printf("Capability query failed 0x%x: %s\n",
            rc, TPM2_GetRCString(rc));
        return rc;
    }
    if (!isSupported) {
        printf("Policy hash %s not implemented by this TPM\n",
            TPM2_GetAlgName(hashAlg));
        return BAD_FUNC_ARG;
    }

    printf("Provisioning platform policy (%s, %s)\n",
        useOr ? "PolicyOR" : "PolicyCommandCode",
        TPM2_GetAlgName(hashAlg));
    /* TPM 2.0 provides no way to read a hierarchy's authPolicy back (there is
     * no read command, and TPMA_PERMANENT only reports authValue state), so
     * this cannot detect or preserve an existing one. Say so plainly. */
    printf("  WARNING: this REPLACES any authPolicy already installed\n");
    printf("  platform hierarchy. An existing policy cannot be read back or\n");
    printf("  restored - cleanup REMOVES the policy rather than restoring\n");
    printf("  the previous digest. Do not use on a system whose platform\n");
    printf("  hierarchy is gated by a policy you need to keep.\n");

    /* Branch A: PolicyCommandCode(FieldUpgradeStart) - required to start FU */
    aSz = (word32)sizeof(ctx->branchFu);
    rc = wolfTPM2_PolicyCommandCodeMake(hashAlg, ctx->branchFu, &aSz,
        fuStartCC);

    /* Compute the platform authPolicy digest */
    if (rc == 0) {
        ctx->branchSz = aSz;
        if (useOr) {
            /* Branch B: PolicyCommandCode(SetPrimaryPolicy). This is the
             * rollback branch - it lets the provisioned policy authorize its
             * own removal, so cleanup works even if platformAuth is not the
             * default empty password. */
            bSz = (word32)sizeof(ctx->branchSpp);
            rc = wolfTPM2_PolicyCommandCodeMake(hashAlg, ctx->branchSpp, &bSz,
                TPM_CC_SetPrimaryPolicy);
            if (rc == 0) {
                XMEMCPY(concat, ctx->branchFu, aSz);
                XMEMCPY(&concat[aSz], ctx->branchSpp, bSz);
                XMEMSET(platformPolicy, 0, sizeof(platformPolicy));
                polSz = hsz;
                rc = wolfTPM2_PolicyHash(hashAlg, platformPolicy, &polSz,
                    TPM_CC_PolicyOR, concat, aSz + bSz);
            }
        }
        else {
            XMEMCPY(platformPolicy, ctx->branchFu, aSz);
            polSz = aSz;
        }
    }

    /* Provision the platform primary policy (empty platformAuth) */
    if (rc == 0) {
        rc = wolfTPM2_SetPrimaryPolicy(dev, TPM_RH_PLATFORM, hashAlg,
            platformPolicy, polSz);
        if (rc != 0) {
            printf("  SetPrimaryPolicy failed 0x%x: %s\n",
                rc, TPM2_GetRCString(rc));
        }
        else {
            ctx->provisioned = 1;
        }
    }

    /* Start a policy session and satisfy the platform policy */
    if (rc == 0) {
        rc = wolfTPM2_StartSession_ex(dev, session, NULL, NULL,
            TPM_SE_POLICY, TPM_ALG_NULL, hashAlg);
        if (rc != 0) {
            printf("  StartSession failed 0x%x: %s\n",
                rc, TPM2_GetRCString(rc));
        }
    }
    if (rc == 0) {
        rc = wolfTPM2_PolicyCommandCode(dev, session, fuStartCC);
    }
    if (rc == 0 && useOr) {
        firmware_policy_or_list(ctx, &orList);
        rc = wolfTPM2_PolicyOR(dev, session, &orList);
    }

    if (rc != 0) {
        if (session->handle.hndl != 0) {
            wolfTPM2_UnloadHandle(dev, &session->handle);
        }
        /* Restore default platform auth so a later run is not locked out (the
         * platform policy is otherwise cleared only on TPM reset). */
        (void)firmware_policy_clear(dev, ctx);
    }
    return rc;
}

#endif /* WOLFTPM_FIRMWARE_UPGRADE && !NO_WRAPPER && !NO_WOLFCRYPT */
