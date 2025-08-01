/* extend.c
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

/* Example for showing NV extend usage for bus protection:
* See "TCG_-CPU_-TPM_Bus_Protection_Guidance_Active_Attack_Mitigations-V1-R30_PUB-1.pdf" */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2_wrap.h>
#include <wolftpm/tpm2_packet.h>
#include <stdio.h>

#if !defined(WOLFTPM2_NO_WRAPPER) && !defined(WOLFTPM2_NO_WOLFCRYPT)

#include <examples/nvram/nvram.h>
#include <hal/tpm_io.h>
#include <examples/tpm_test.h>
#include <examples/tpm_test_keys.h>


/******************************************************************************/
/* --- BEGIN TPM NVRAM Extend Example -- */
/******************************************************************************/
static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/nvram/extend [-nvindex=handle] [-aes/-xor]\n");
    printf("* -nvindex=[handle] (default 0x%x)\n",
        TPM2_DEMO_NVRAM_EXTEND_INDEX);
    printf("* -aes/xor: Use Parameter Encryption\n");;
}

static int BuildPolicyCommandCode(TPMI_ALG_HASH hashAlg,
    byte* digest, word32* digestSz, TPM_CC cc)
{
    word32 val = cpu_to_be32(cc);
    return wolfTPM2_PolicyHash(hashAlg, digest, digestSz,
        TPM_CC_PolicyCommandCode, (byte*)&val, sizeof(val));
}

static int PolicyOrApply(WOLFTPM2_DEV* dev, WOLFTPM2_SESSION* policySession,
    byte** hashList, word32 hashListSz, word32 digestSz)
{
    word32 i;
    PolicyOR_In policyOR;
    XMEMSET(&policyOR, 0, sizeof(policyOR));
    policyOR.policySession = policySession->handle.hndl;
    policyOR.pHashList.count = hashListSz;
    for (i=0; i<hashListSz; i++) {
        policyOR.pHashList.digests[i].size = digestSz;
        XMEMCPY(policyOR.pHashList.digests[i].buffer, hashList[i], digestSz);
    }
    (void)dev;
    return TPM2_PolicyOR(&policyOR);
}

int TPM2_NVRAM_Extend_Example(void* userCtx, int argc, char *argv[])
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY endorse;
    WOLFTPM2_SESSION tpmSession;
    WOLFTPM2_HANDLE nvAuth;
    WOLFTPM2_HANDLE bind;
    WOLFTPM2_NV nv;
    word32 nvAttributes;
    int paramEncAlg = TPM_ALG_CFB;
    TPMI_RH_NV_AUTH authHandle = TPM_RH_PLATFORM;
    word32 nvIndex = TPM2_DEMO_NVRAM_EXTEND_INDEX;
    byte*  auth = (byte*)"cpusecret";
    word32 authSz = (word32)XSTRLEN((const char*)auth);
    TPMI_ALG_HASH hashAlg = WOLFTPM2_WRAP_DIGEST;
    word32 nvSize = TPM2_GetHashDigestSize(hashAlg);
    byte   nvDigest[TPM_MAX_DIGEST_SIZE]; /* buffer for nv read */
    byte   policyDigest[3*TPM_MAX_DIGEST_SIZE]; /* Policy A/B/C */
    word32 policyDigestSz = 0;
    byte*  policy[3]; /* pointers to policy A/B/C */
    byte   policyOr[TPM_MAX_DIGEST_SIZE];

    if (argc >= 2) {
        if (XSTRCMP(argv[1], "-?") == 0 ||
            XSTRCMP(argv[1], "-h") == 0 ||
            XSTRCMP(argv[1], "--help") == 0) {
            usage();
            return 0;
        }
    }
    while (argc > 1) {
        if (XSTRNCMP(argv[argc-1], "-nvindex=", XSTRLEN("-nvindex=")) == 0) {
            const char* nvIndexStr = argv[argc-1] + XSTRLEN("-nvindex=");
            nvIndex = (word32)XSTRTOUL(nvIndexStr, NULL, 0);
            if (nvIndex >= TPM_20_PLATFORM_MFG_NV_SPACE &&
                nvIndex <  TPM_20_OWNER_NV_SPACE) {
                authHandle = TPM_RH_PLATFORM;
            }
            else if (nvIndex >= TPM_20_OWNER_NV_SPACE &&
                     nvIndex <  TPM_20_TCG_NV_SPACE) {
                authHandle = TPM_RH_OWNER;
            }
            else {
                fprintf(stderr, "Invalid NV Index %s\n", nvIndexStr);
                fprintf(stderr, "\tPlatform Range: 0x%x -> 0x%x\n",
                    TPM_20_PLATFORM_MFG_NV_SPACE, TPM_20_OWNER_NV_SPACE);
                fprintf(stderr, "\tOwner Range: 0x%x -> 0x%x\n",
                    TPM_20_OWNER_NV_SPACE, TPM_20_TCG_NV_SPACE);
                usage();
                return -1;
            }
        }
        else if (XSTRCMP(argv[argc-1], "-aes") == 0) {
            paramEncAlg = TPM_ALG_CFB;
        }
        else if (XSTRCMP(argv[argc-1], "-xor") == 0) {
            paramEncAlg = TPM_ALG_XOR;
        }
        else {
            printf("Warning: Unrecognized option: %s\n", argv[argc-1]);
        }
        argc--;
    };

    printf("NVRAM Extend (bus protection example)\n");
    printf("Parameter Encryption: %s\n",
        (paramEncAlg == TPM_ALG_CFB) ? "AES CFB" : "XOR");

    XMEMSET(&tpmSession, 0, sizeof(tpmSession));
    XMEMSET(&endorse, 0, sizeof(endorse));
    XMEMSET(&bind, 0, sizeof(bind));
    XMEMSET(&nv, 0, sizeof(nv));
    XMEMSET(&nvAuth, 0, sizeof(nvAuth));
    XMEMSET(nvDigest, 0, sizeof(nvDigest));
    XMEMSET(policyDigest, 0, sizeof(policyDigest));

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_Init failed\n");
        goto exit;
    }

    /* Build Policies A/B/C */
    /* Policy A: TPM2_PolicyCommandCode -> TPM_CC_NV_Read */
    /* 47ce3032d8bad1f3089cb0c09088de43501491d460402b90cd1b7fc0b68ca92f */
    policy[0] = &policyDigest[policyDigestSz];
    BuildPolicyCommandCode(hashAlg, policy[0], &nvSize, TPM_CC_NV_Read);
    printf("PolicyA: %d\n", nvSize);
    TPM2_PrintBin(policy[0], nvSize);
    policyDigestSz += nvSize;

    /* Policy B: TPM2_PolicyCommandCode -> TPM_CC_NV_Extend */
    /* b6a2e7142ee56fd978047488483daa5b42b8dc4cc7ddcceddfb91793cf1ff1b7 */
    policy[1] = &policyDigest[policyDigestSz];
    BuildPolicyCommandCode(hashAlg, policy[1], &nvSize, TPM_CC_NV_Extend);
    printf("PolicyB: %d\n", nvSize);
    TPM2_PrintBin(policy[1], nvSize);
    policyDigestSz += nvSize;

    /* Policy C: TPM2_PolicyCommandCode -> TPM_CC_PolicyNV */
    /* 203e4bd5d0448c9615cc13fa18e8d39222441cc40204d99a77262068dbd55a43 */
    policy[2] = &policyDigest[policyDigestSz];
    BuildPolicyCommandCode(hashAlg, policy[2], &nvSize, TPM_CC_PolicyNV);
    printf("PolicyC: %d\n", nvSize);
    TPM2_PrintBin(policy[2], nvSize);
    policyDigestSz += nvSize;

    /* Policy OR A/B/C */
    /* 7f17937e206279a3f755fb60f40cf126b70e5b1d9bf202866d527613874a64ac */
    XMEMSET(policyOr, 0, sizeof(policyOr));
    rc = wolfTPM2_PolicyHash(hashAlg, policyOr, &nvSize,
        TPM_CC_PolicyOR, policyDigest, policyDigestSz);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_PolicyHash failed!\n");
        goto exit;
    }
    printf("PolicyOR A/B/C: %d\n", nvSize);
    TPM2_PrintBin(policyOr, nvSize);

    /* 1: Create EK (RSA or ECC) */
    rc = wolfTPM2_CreateEK(&dev, &endorse,
    #ifndef NO_RSA
        TPM_ALG_RSA
    #else
        TPM_ALG_ECC
    #endif
    );
    if (rc != 0) {
        printf("Create EK RSA failed!\n");
        goto exit;
    }
    endorse.handle.policyAuth = 1; /* EK requires policy auth */
    printf("EK Handle: 0x%x\n", (word32)endorse.handle.hndl);

    /* 2: Create a salted session with the TPM using the EK */
    rc = wolfTPM2_StartSession(&dev, &tpmSession, &endorse, NULL,
        TPM_SE_HMAC, paramEncAlg);
    if (rc == 0) {
        rc = wolfTPM2_SetAuthSession(&dev, 0, &tpmSession,
            (TPMA_SESSION_decrypt | TPMA_SESSION_encrypt |
             TPMA_SESSION_continueSession));
    }
    if (rc != 0) {
        printf("Start HMAC session failed!\n");
        goto exit;
    }
    printf("Encrypted HMAC Session Handle 0x%x\n",
        (word32)tpmSession.handle.hndl);

    /* 3. Create the NV Index with extend attribute.
     * Use "host secret" as password so it is used with the bind session later */

    /* See TPM_Bus_Protection_Guidance_Active_Attack_Mitigations:
     * Section 3.4 Provisioning the NV Index */
    nvAttributes = (
            (TPMA_NV_TPM_NT & (TPM_NT_EXTEND << 4)) |
            TPMA_NV_ORDERLY |
            TPMA_NV_CLEAR_STCLEAR |
            TPMA_NV_PLATFORMCREATE |
            TPMA_NV_POLICYWRITE |
            TPMA_NV_POLICYREAD |
            TPMA_NV_NO_DA);
    nvSize = TPM2_GetHashDigestSize(WOLFTPM2_WRAP_DIGEST);

    /* Try and open existing NV */
    rc = wolfTPM2_NVOpen(&dev, &nv, nvIndex, auth, authSz);
    if (rc != 0) {
        nvAuth.hndl = authHandle;

        rc = wolfTPM2_NVCreateAuthPolicy(&dev, &nvAuth, &nv, nvIndex,
            nvAttributes, /* needs TPM_NT_EXTEND set */
            nvSize, /* must match nameAlg digest size */
            auth, authSz, /* the password to bind session with */
            policyOr, nvSize
        );
    }
    if (rc != 0) {
        printf("NV Create failed!\n");
        goto exit;
    }

    /* Close session and unload endorsement */
    wolfTPM2_UnsetAuth(&dev, 0);
    wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);
    wolfTPM2_UnloadHandle(&dev, &endorse.handle);


    /* 4. Start a policy session and bind to NV handle */
    rc = wolfTPM2_StartSession(&dev, &tpmSession, NULL, &nv.handle,
        TPM_SE_POLICY, TPM_ALG_CFB);
    if (rc == 0) {
        rc = wolfTPM2_SetAuthSession(&dev, 0, &tpmSession,
            (TPMA_SESSION_decrypt | TPMA_SESSION_encrypt |
             TPMA_SESSION_continueSession));
    }
    if (rc != 0) {
        printf("Start Policy session failed!\n");
        goto exit;
    }
    printf("Encrypted Policy Session Handle 0x%x\n",
        (word32)tpmSession.handle.hndl);

    /* 5. Satisfy policy for NV Extend (policy B) */
    rc = wolfTPM2_PolicyCommandCode(&dev, &tpmSession, TPM_CC_NV_Extend);
    if (rc == 0) {
        rc = PolicyOrApply(&dev, &tpmSession, policy, 3, nvSize);
    }
    if (rc != 0) {
        printf("Failed to apply policy B\n");
        goto exit;
    }

    /* 6. Perform NV extend */
    rc = wolfTPM2_NVExtend(&dev, &nv, nvIndex, auth, (word32)authSz);
    if (rc != 0) {
        printf("NV Extend failed!\n");
        goto exit;
    }
    printf("NV 0x%08x extended\n", (word32)nvIndex);

    /* 7. Restart session policy */
    rc = wolfTPM2_PolicyRestart(&dev, tpmSession.handle.hndl);
    if (rc != 0) {
        printf("Policy restart failed!\n");
        goto exit;
    }

    /* 8. Satisfy policy for NV Read (policy A) */
    rc = wolfTPM2_PolicyCommandCode(&dev, &tpmSession, TPM_CC_NV_Read);
    if (rc == 0) {
        rc = PolicyOrApply(&dev, &tpmSession, policy, 3, nvSize);
    }
    if (rc != 0) {
        printf("Failed to apply policy A\n");
        goto exit;
    }

    /* 9. Read NV extend digest */
    rc = wolfTPM2_NVRead(&dev, authHandle, nv.handle.hndl,
        nvDigest, &nvSize, 0);
    if (rc == 0) {
        printf("NV Digest: %d\n", nvSize);
        TPM2_PrintBin(nvDigest, nvSize);

        /* Should be:
         * 0ad80f8e4450587760d9137df41c9374f657bafa621fe37d4d5c8cecf0bcce5e */
    }

exit:

    if (rc != 0) {
        printf("\nFailure 0x%x: %s\n\n", rc, wolfTPM2_GetRCString(rc));
    }

    wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);
    wolfTPM2_Cleanup(&dev);

    return rc;
}

/******************************************************************************/
/* --- END TPM NVRAM Extend Example -- */
/******************************************************************************/
#endif /* !WOLFTPM2_NO_WRAPPER && !WOLFTPM2_NO_WOLFCRYPT */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = NOT_COMPILED_IN;

#if !defined(WOLFTPM2_NO_WRAPPER) && !defined(WOLFTPM2_NO_WOLFCRYPT)
    rc = TPM2_NVRAM_Extend_Example(NULL, argc, argv);
#else
    printf("NVRAM extend code not compiled in\n");
    (void)argc;
    (void)argv;
#endif

    return rc;
}
#endif
