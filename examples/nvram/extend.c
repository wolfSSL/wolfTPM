/* extend.c
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
 *
 * This file is part of wolfTPM.
 *
 * wolfTPM is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
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
#include <stdio.h>

#ifndef WOLFTPM2_NO_WRAPPER

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

/* Policy A: TPM2_PolicyCommandCode -> TPM_CC_NV_Read */
static const byte policyA[] = {
    0x47, 0xCE, 0x30, 0x32, 0xD8, 0xBA, 0xD1, 0xF3,
    0x08, 0x9C, 0xB0, 0xC0, 0x90, 0x88, 0xDE, 0x43,
    0x50, 0x14, 0x91, 0xD4, 0x60, 0x40, 0x2B, 0x90,
    0xCD, 0x1B, 0x7F, 0xC0, 0xB6, 0x8C, 0xA9, 0x2F
};
/* Policy B: TPM2_PolicyCommandCode -> TPM_CC_NV_Extend */
static const byte policyB[] = {
    0xB6, 0xA2, 0xE7, 0x14, 0x2E, 0xE5, 0x6F, 0xD9,
    0x78, 0x04, 0x74, 0x88, 0x48, 0x3D, 0xAA, 0x5B,
    0x42, 0xB8, 0xDC, 0x4C, 0xC7, 0xDD, 0xCC, 0xED,
    0xDF, 0xB9, 0x17, 0x93, 0xCF, 0x1F, 0xF1, 0xB7
};
/* Policy C: TPM2_PolicyCommandCode -> TPM_CC_PolicyNV */
static const byte policyC[] = {
    0x20, 0x3E, 0x4B, 0xD5, 0xD0, 0x44, 0x8C, 0x96,
    0x15, 0xCC, 0x13, 0xFA, 0x18, 0xE8, 0xD3, 0x92,
    0x22, 0x44, 0x1C, 0xC4, 0x02, 0x04, 0xD9, 0x9A,
    0x77, 0x26, 0x20, 0x68, 0xDB, 0xD5, 0x5A, 0x43
};

/* pre-computed policy:
 * NV Read (A), NV Extend (B), PolicyNV (C), then policy OR (A/B/C) */
static const byte policyNv[] = {
    0x7F, 0x17, 0x93, 0x7E, 0x20, 0x62, 0x79, 0xA3,
    0xF7, 0x55, 0xFB, 0x60, 0xF4, 0x0C, 0xF1, 0x26,
    0xB7, 0x0E, 0x5B, 0x1D, 0x9B, 0xF2, 0x02, 0x86,
    0x6D, 0x52, 0x76, 0x13, 0x87, 0x4A, 0x64, 0xAC
};


static int PolicyOrApply(WOLFTPM2_DEV* dev, WOLFTPM2_SESSION* policySession)
{
    PolicyOR_In policyOR;
    XMEMSET(&policyOR, 0, sizeof(policyOR));
    policyOR.policySession = policySession->handle.hndl;
    policyOR.pHashList.count = 3;
    policyOR.pHashList.digests[0].size = sizeof(policyA);
    XMEMCPY(policyOR.pHashList.digests[0].buffer, policyA, sizeof(policyA));
    policyOR.pHashList.digests[1].size = sizeof(policyB);
    XMEMCPY(policyOR.pHashList.digests[1].buffer, policyB, sizeof(policyB));
    policyOR.pHashList.digests[2].size = sizeof(policyC);
    XMEMCPY(policyOR.pHashList.digests[2].buffer, policyC, sizeof(policyC));
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
    word32 nvSize; /* 32 for SHA2-256 */
    byte*  auth = (byte*)"cpusecret";
    word32 authSz = (word32)XSTRLEN((const char*)auth);
    byte   nvDigest[32];
    word32 nvDigestSz = (word32)sizeof(nvDigest);

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

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_Init failed\n");
        goto exit;
    }

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
            policyNv, (word32)sizeof(policyNv)
        );
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
        rc = PolicyOrApply(&dev, &tpmSession);
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
        rc = PolicyOrApply(&dev, &tpmSession);
    }
    if (rc != 0) {
        printf("Failed to apply policy A\n");
        goto exit;
    }

    /* 9. Read NV extend digest */
    rc = wolfTPM2_NVRead(&dev, authHandle, nv.handle.hndl,
        nvDigest, &nvDigestSz, 0);
    if (rc == 0) {
        printf("NV Digest: %d\n", nvDigestSz);
        TPM2_PrintBin(nvDigest, nvDigestSz);

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
#endif /* !WOLFTPM2_NO_WRAPPER */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = NOT_COMPILED_IN;

#ifndef WOLFTPM2_NO_WRAPPER
    rc = TPM2_NVRAM_Extend_Example(NULL, argc, argv);
#else
    printf("NVRAM code not compiled in\n");
    (void)argc;
    (void)argv;
#endif

    return rc;
}
#endif
