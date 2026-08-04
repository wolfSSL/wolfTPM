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

/* Exercise wolfTPM2_PolicyOR at the requested hash and verify the TPM's
 * running policy digest matches an offline computation. Non-destructive.
 * Returns 0 on match, 1 if the hash is not implemented (intentional skip),
 * -1 on digest mismatch, or a TPM rc / BAD_FUNC_ARG on other errors. */
static int firmware_policy_selftest(WOLFTPM2_DEV* dev, TPMI_ALG_HASH hashAlg,
    const char* name)
{
    int rc;
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

    if (hsz == 0 || hsz > TPM_MAX_DIGEST_SIZE) {
        return BAD_FUNC_ARG;
    }

    /* Skip cleanly if the TPM does not implement this hash; a negative rc is a
     * query failure (reported), distinct from "not implemented" (0). */
    rc = wolfTPM2_IsAlgSupported(dev, hashAlg);
    if (rc == 0) {
        printf("  %s: skipped (not implemented by this TPM)\n", name);
        return 1; /* intentional skip, not a failure */
    }
    if (rc != 1) {
        printf("  %s: capability query failed 0x%x: %s\n",
            name, rc, TPM2_GetRCString(rc));
        return rc;
    }

    /* Offline: two distinct PolicyCommandCode branch digests */
    aSz = hsz;
    rc = wolfTPM2_PolicyCommandCodeMake(hashAlg, branchA, &aSz, TPM_CC_NV_Read);
    if (rc == 0) {
        bSz = hsz;
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
            rc = -1;
        }
    }
    else {
        printf("  %s PolicyOR: ERROR 0x%x: %s\n",
            name, rc, TPM2_GetRCString(rc));
    }

    wolfTPM2_UnloadHandle(dev, &sess.handle);
    return rc;
}

int firmware_policy_selftest_all(WOLFTPM2_DEV* dev)
{
    int i, rc, hardFail = 0;
    struct { TPMI_ALG_HASH alg; const char* name; } hashes[3];

    hashes[0].alg = TPM_ALG_SHA256; hashes[0].name = "SHA2-256";
    hashes[1].alg = TPM_ALG_SHA384; hashes[1].name = "SHA2-384";
    hashes[2].alg = TPM_ALG_SHA512; hashes[2].name = "SHA2-512";

    printf("Firmware policy authorization self-test "
           "(no firmware changes):\n");
    for (i = 0; i < 3; i++) {
        rc = firmware_policy_selftest(dev, hashes[i].alg, hashes[i].name);
        /* rc == 1 is an intentional "hash not implemented" skip. Any other
         * non-zero (digest mismatch, bad arg, or a TPM rc) is a failure. */
        if (rc != 0 && rc != 1) {
            hardFail = 1;
        }
    }
    return hardFail ? -1 : 0;
}

void firmware_policy_clear(WOLFTPM2_DEV* dev)
{
    if (wolfTPM2_SetPrimaryPolicy(dev, TPM_RH_PLATFORM, TPM_ALG_NULL,
            NULL, 0) == TPM_RC_SUCCESS) {
        printf("Cleared platform policy (restored default auth)\n");
    }
}

int firmware_policy_session_setup(WOLFTPM2_DEV* dev,
    TPMI_ALG_HASH hashAlg, int useOr, TPM_CC fuStartCC,
    WOLFTPM2_SESSION* session)
{
    int rc;
    int provisioned = 0;
    TPML_DIGEST orList;
    word32 hsz = (word32)TPM2_GetHashDigestSize(hashAlg);
    byte branchA[TPM_MAX_DIGEST_SIZE];
    byte branchB[TPM_MAX_DIGEST_SIZE];
    byte concat[2 * TPM_MAX_DIGEST_SIZE];
    byte platformPolicy[TPM_MAX_DIGEST_SIZE];
    word32 aSz, bSz = 0, polSz = 0;

    if (hsz == 0 || hsz > TPM_MAX_DIGEST_SIZE) {
        return BAD_FUNC_ARG;
    }
    XMEMSET(session, 0, sizeof(*session));
    XMEMSET(&orList, 0, sizeof(orList));

    /* Fail early (before provisioning) if the TPM can't use this policy hash.
     * rc==0 means not implemented; a negative rc is a query failure. */
    rc = wolfTPM2_IsAlgSupported(dev, hashAlg);
    if (rc == 0) {
        printf("Policy hash %s not implemented by this TPM\n",
            TPM2_GetAlgName(hashAlg));
        return BAD_FUNC_ARG;
    }
    if (rc != 1) {
        printf("Capability query failed 0x%x: %s\n",
            rc, TPM2_GetRCString(rc));
        return rc;
    }

    printf("Provisioning platform policy (%s, %s)\n",
        useOr ? "PolicyOR" : "PolicyCommandCode",
        TPM2_GetAlgName(hashAlg));

    /* Branch A: PolicyCommandCode(FieldUpgradeStart) - required to start FU */
    aSz = hsz;
    rc = wolfTPM2_PolicyCommandCodeMake(hashAlg, branchA, &aSz, fuStartCC);

    /* Compute the platform authPolicy digest */
    if (rc == 0) {
        if (useOr) {
            /* Branch B: a second, distinct policy branch */
            bSz = hsz;
            rc = wolfTPM2_PolicyCommandCodeMake(hashAlg, branchB, &bSz,
                TPM_CC_NV_Read);
            if (rc == 0) {
                XMEMCPY(concat, branchA, aSz);
                XMEMCPY(&concat[aSz], branchB, bSz);
                XMEMSET(platformPolicy, 0, sizeof(platformPolicy));
                polSz = hsz;
                rc = wolfTPM2_PolicyHash(hashAlg, platformPolicy, &polSz,
                    TPM_CC_PolicyOR, concat, aSz + bSz);
            }
        }
        else {
            XMEMCPY(platformPolicy, branchA, aSz);
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
            provisioned = 1;
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
        orList.count = 2;
        orList.digests[0].size = (UINT16)aSz;
        XMEMCPY(orList.digests[0].buffer, branchA, aSz);
        orList.digests[1].size = (UINT16)bSz;
        XMEMCPY(orList.digests[1].buffer, branchB, bSz);
        rc = wolfTPM2_PolicyOR(dev, session, &orList);
    }

    if (rc != 0) {
        if (session->handle.hndl != 0) {
            wolfTPM2_UnloadHandle(dev, &session->handle);
        }
        /* Restore default platform auth so a later run is not locked out (the
         * platform policy is otherwise cleared only on TPM reset). */
        if (provisioned) {
            firmware_policy_clear(dev);
        }
    }
    return rc;
}

#endif /* WOLFTPM_FIRMWARE_UPGRADE && !NO_WRAPPER && !NO_WOLFCRYPT */
