/* seal_nv.c
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

/* NV storage with PCR policy.
 *
 * Stores a secret in TPM NV memory protected by PCR policy.
 * Only readable when PCR values match.
 *
 * Sealing method: NV + PCR policy
 *   Complexity:   Medium
 *   Flexibility:  High
 *   Use case:     Storing small metadata (keys/passwords) directly in TPM
 *                 silicon instead of disk
 */

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
/* --- BEGIN TPM2.0 NV Seal Example -- */
/******************************************************************************/

#define TPM2_DEMO_NV_SEAL_INDEX 0x01800203

static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/nvram/seal_nv [-pcr=N] [-nvindex=0xNNNNNNNN]\n");
    printf("\t[-store/-read/-delete] [-ownerauth=str] [-secretstr=str]\n");
    printf("\t[-aes/-xor]\n");
    printf("* -pcr=N: PCR index to use (default %d)\n", TPM2_DEMO_PCR_INDEX);
    printf("* -nvindex=handle: NV index (default 0x%x)\n",
        TPM2_DEMO_NV_SEAL_INDEX);
    printf("* -store: Store secret to NV\n");
    printf("* -read: Read secret from NV\n");
    printf("* -delete: Delete NV index (cleanup)\n");
    printf("* -ownerauth=str: Owner authorization password (default empty)\n");
    printf("* -secretstr=str: Secret to store (default TestNVSeal)\n");
    printf("* -aes/xor: Use Parameter Encryption\n");
}

int TPM2_NVRAM_SealNV_Example(void* userCtx, int argc, char *argv[])
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_SESSION tpmSession;
    WOLFTPM2_SESSION paramEncSession;
    WOLFTPM2_HANDLE parent;
    WOLFTPM2_NV nv;
    TPM_ALG_ID paramEncAlg = TPM_ALG_NULL;
    TPM_ALG_ID pcrAlg = TPM_ALG_SHA256;
    byte pcrIndex = TPM2_DEMO_PCR_INDEX;
    byte pcrArray[1];
    word32 pcrArraySz;
    word32 nvIndex = TPM2_DEMO_NV_SEAL_INDEX;
    const char* ownerAuth = "";
    const char* secretStr = "TestNVSeal";
    int doStore = 0;
    int doRead = 0;
    int doDelete = 0;
    byte pcrDigest[TPM_SHA256_DIGEST_SIZE];
    int pcrDigestSz;
    byte policyDigest[TPM_SHA256_DIGEST_SIZE];
    word32 policyDigestSz;

    XMEMSET(&dev, 0, sizeof(dev));
    XMEMSET(&tpmSession, 0, sizeof(tpmSession));
    XMEMSET(&paramEncSession, 0, sizeof(paramEncSession));
    XMEMSET(&parent, 0, sizeof(parent));
    XMEMSET(&nv, 0, sizeof(nv));

    if (argc >= 2) {
        if (XSTRCMP(argv[1], "-?") == 0 ||
            XSTRCMP(argv[1], "-h") == 0 ||
            XSTRCMP(argv[1], "--help") == 0) {
            usage();
            return 0;
        }
    }
    while (argc > 1) {
        if (XSTRNCMP(argv[argc-1], "-pcr=", XSTRLEN("-pcr=")) == 0) {
            pcrIndex = (byte)XATOI(argv[argc-1] + XSTRLEN("-pcr="));
            if (pcrIndex > PCR_LAST) {
                printf("PCR index out of range (0-23)\n");
                usage();
                return BAD_FUNC_ARG;
            }
        }
        else if (XSTRNCMP(argv[argc-1], "-nvindex=",
                XSTRLEN("-nvindex=")) == 0) {
            nvIndex = (word32)XSTRTOUL(argv[argc-1] + XSTRLEN("-nvindex="),
                NULL, 0);
        }
        else if (XSTRCMP(argv[argc-1], "-store") == 0) {
            doStore = 1;
        }
        else if (XSTRCMP(argv[argc-1], "-read") == 0) {
            doRead = 1;
        }
        else if (XSTRCMP(argv[argc-1], "-delete") == 0) {
            doDelete = 1;
        }
        else if (XSTRNCMP(argv[argc-1], "-ownerauth=",
                XSTRLEN("-ownerauth=")) == 0) {
            ownerAuth = argv[argc-1] + XSTRLEN("-ownerauth=");
        }
        else if (XSTRNCMP(argv[argc-1], "-secretstr=",
                XSTRLEN("-secretstr=")) == 0) {
            secretStr = argv[argc-1] + XSTRLEN("-secretstr=");
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
    }

    /* Default to store if nothing specified */
    if (!doStore && !doRead && !doDelete) {
        doStore = 1;
    }

    pcrArray[0] = pcrIndex;
    pcrArraySz = 1;

    printf("TPM2.0 NV Seal Example\n");
    printf("\tPCR Index: %d\n", pcrIndex);
    printf("\tNV Index: 0x%x\n", nvIndex);
    printf("\tUse Parameter Encryption: %s\n", TPM2_GetAlgName(paramEncAlg));

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_Init failed\n");
        goto exit;
    }

    if (paramEncAlg != TPM_ALG_NULL) {
        /* Start TPM session for parameter encryption */
        rc = wolfTPM2_StartSession(&dev, &paramEncSession, NULL, NULL,
            TPM_SE_HMAC, paramEncAlg);
        if (rc != 0) goto exit;
        printf("TPM2_StartAuthSession: sessionHandle 0x%x\n",
            (word32)paramEncSession.handle.hndl);
        /* Set TPM session attributes for parameter encryption.
         * Use index 2 to avoid conflict with NV handle auth on index 1 */
        rc = wolfTPM2_SetAuthSession(&dev, 2, &paramEncSession,
            (TPMA_SESSION_decrypt | TPMA_SESSION_encrypt |
             TPMA_SESSION_continueSession));
        if (rc != 0) goto exit;
    }

    /* Validate that the PCR bank is available */
    pcrDigestSz = (int)sizeof(pcrDigest);
    rc = wolfTPM2_ReadPCR(&dev, pcrIndex, pcrAlg, pcrDigest, &pcrDigestSz);
    if (rc != TPM_RC_SUCCESS) {
        printf("PCR %d with %s is not available (bank may not be active)\n",
            pcrIndex, TPM2_GetAlgName(pcrAlg));
        goto exit;
    }

    /* Set owner auth */
    parent.hndl = TPM_RH_OWNER;
    if (XSTRLEN(ownerAuth) > 0) {
        parent.auth.size = (int)XSTRLEN(ownerAuth);
        XMEMCPY(parent.auth.buffer, ownerAuth, parent.auth.size);
    }

    /* ---- DELETE ---- */
    if (doDelete) {
        printf("\nDeleting NV index 0x%x\n", nvIndex);
        rc = wolfTPM2_NVDeleteAuth(&dev, &parent, nvIndex);
        if (rc != TPM_RC_SUCCESS) {
            printf("wolfTPM2_NVDeleteAuth failed 0x%x: %s\n",
                rc, wolfTPM2_GetRCString(rc));
        }
        else {
            printf("NV index 0x%x deleted\n", nvIndex);
        }
        goto exit;
    }

    /* ---- STORE ---- */
    if (doStore) {
        WOLFTPM2_SESSION trialSession;
        word32 nvAttributes;
        word32 secretSz = (word32)XSTRLEN(secretStr);

        XMEMSET(&trialSession, 0, sizeof(trialSession));

        printf("\nStoring secret (%d bytes) to NV index 0x%x\n",
            secretSz, nvIndex);

        /* Step 1: Trial session to compute PCR policy digest */
        rc = wolfTPM2_StartSession(&dev, &trialSession, NULL, NULL,
            TPM_SE_TRIAL, TPM_ALG_NULL);
        if (rc != 0) goto exit;

        rc = wolfTPM2_PolicyPCR(&dev, trialSession.handle.hndl,
            pcrAlg, pcrArray, pcrArraySz);
        if (rc != 0) {
            wolfTPM2_UnloadHandle(&dev, &trialSession.handle);
            goto exit;
        }

        policyDigestSz = (word32)sizeof(policyDigest);
        rc = wolfTPM2_GetPolicyDigest(&dev, trialSession.handle.hndl,
            policyDigest, &policyDigestSz);
        wolfTPM2_UnloadHandle(&dev, &trialSession.handle);
        if (rc != 0) goto exit;

        printf("PCR Policy Digest (%d bytes)\n", policyDigestSz);

        /* Step 2: Create NV index with PCR policy for read and write */
        rc = wolfTPM2_GetNvAttributesTemplate(parent.hndl, &nvAttributes);
        if (rc != 0) goto exit;
        /* Clear auth read/write, set policy read/write */
        nvAttributes &= ~(TPMA_NV_AUTHREAD | TPMA_NV_AUTHWRITE);
        nvAttributes |= (TPMA_NV_POLICYREAD | TPMA_NV_POLICYWRITE);

        rc = wolfTPM2_NVCreateAuthPolicy(&dev, &parent, &nv, nvIndex,
            nvAttributes, secretSz, NULL, 0,
            policyDigest, policyDigestSz);
        if (rc == TPM_RC_NV_DEFINED) {
            /* Delete existing and recreate with correct policy */
            printf("NV index exists, deleting and recreating\n");
            rc = wolfTPM2_NVDeleteAuth(&dev, &parent, nvIndex);
            if (rc != 0) {
                printf("wolfTPM2_NVDeleteAuth failed\n");
                goto exit;
            }
            rc = wolfTPM2_NVCreateAuthPolicy(&dev, &parent, &nv, nvIndex,
                nvAttributes, secretSz, NULL, 0,
                policyDigest, policyDigestSz);
        }
        if (rc != 0) {
            printf("wolfTPM2_NVCreateAuthPolicy failed\n");
            goto exit;
        }
        printf("Created NV index 0x%x (%d bytes)\n", nvIndex, secretSz);

        /* Step 3: Start policy session for write */
        rc = wolfTPM2_StartSession(&dev, &tpmSession, NULL, NULL,
            TPM_SE_POLICY, TPM_ALG_NULL);
        if (rc != 0) goto exit;

        /* Set auth session to populate authHash for HMAC calculation.
         * NVWriteAuthPolicy internally uses SetSessionHandle (partial update)
         * which requires authHash to already be set in dev->session. */
        rc = wolfTPM2_SetAuthSession(&dev, 0, &tpmSession,
            TPMA_SESSION_continueSession);
        if (rc != 0) {
            wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);
            goto exit;
        }

        /* Write using policy session (internally calls PolicyPCR) */
        rc = wolfTPM2_NVWriteAuthPolicy(&dev, &tpmSession, pcrAlg,
            pcrArray, pcrArraySz, &nv, nvIndex,
            (byte*)secretStr, secretSz, 0);
        wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);
        if (rc != TPM_RC_SUCCESS) {
            printf("wolfTPM2_NVWriteAuthPolicy failed\n");
            goto exit;
        }
        printf("Wrote %d bytes to NV index 0x%x\n", secretSz, nvIndex);
    }

    /* ---- READ ---- */
    if (doRead) {
        byte readBuf[MAX_SYM_DATA];
        word32 readSz;
        TPMS_NV_PUBLIC nvPublic;

        printf("\nReading from NV index 0x%x\n", nvIndex);

        /* Get NV index size from public data */
        rc = wolfTPM2_NVReadPublic(&dev, nvIndex, &nvPublic);
        if (rc != 0) {
            printf("wolfTPM2_NVReadPublic failed\n");
            goto exit;
        }
        readSz = nvPublic.dataSize;
        if (readSz > (word32)sizeof(readBuf)) {
            readSz = (word32)sizeof(readBuf);
        }

        /* Start policy session for read */
        rc = wolfTPM2_StartSession(&dev, &tpmSession, NULL, NULL,
            TPM_SE_POLICY, TPM_ALG_NULL);
        if (rc != 0) goto exit;

        /* Set auth session to populate authHash for HMAC calculation */
        rc = wolfTPM2_SetAuthSession(&dev, 0, &tpmSession,
            TPMA_SESSION_continueSession);
        if (rc != 0) {
            wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);
            goto exit;
        }

        /* Read using policy session (internally calls PolicyPCR) */
        rc = wolfTPM2_NVReadAuthPolicy(&dev, &tpmSession, pcrAlg,
            pcrArray, pcrArraySz, &nv, nvIndex,
            readBuf, &readSz, 0);
        wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);
        if (rc != TPM_RC_SUCCESS) {
            printf("wolfTPM2_NVReadAuthPolicy failed\n");
            goto exit;
        }

        printf("Read %d bytes from NV index 0x%x: %.*s\n",
            readSz, nvIndex, readSz, readBuf);
    }

exit:
    if (rc != 0) {
        printf("\nFailure 0x%x: %s\n\n", rc, wolfTPM2_GetRCString(rc));
    }

    wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);
    wolfTPM2_UnloadHandle(&dev, &paramEncSession.handle);

    wolfTPM2_Cleanup(&dev);

    return rc;
}

/******************************************************************************/
/* --- END TPM2.0 NV Seal Example -- */
/******************************************************************************/
#endif /* !WOLFTPM2_NO_WRAPPER */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = NOT_COMPILED_IN;

#ifndef WOLFTPM2_NO_WRAPPER
    rc = TPM2_NVRAM_SealNV_Example(NULL, argc, argv);
#else
    printf("Wrapper code not compiled in\n");
    (void)argc;
    (void)argv;
#endif

    return rc;
}
#endif
