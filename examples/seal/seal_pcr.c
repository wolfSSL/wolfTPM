/* seal_pcr.c
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

/* Example for TPM 2.0 PCR policy seal/unseal.
 *
 * Seals a secret that can only be unsealed when specific PCR values match.
 * No password, no signing key - simplest "measured boot" scenario.
 *
 * Sealing method: PCR-only policy
 *   Complexity:   Low
 *   Flexibility:  Low (PCR values are hard-coded at seal time)
 *   Use case:     Static Root of Trust - bind secrets to a specific boot state
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2_wrap.h>

#include <stdio.h>

#ifndef WOLFTPM2_NO_WRAPPER

#include <examples/seal/seal.h>
#include <hal/tpm_io.h>
#include <examples/tpm_test.h>
#include <examples/tpm_test_keys.h>

/******************************************************************************/
/* --- BEGIN TPM2.0 PCR Seal Example -- */
/******************************************************************************/

static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/seal/seal_pcr [-pcr=N] [-seal/-unseal/-both]\n");
    printf("\t[-sealblob=file] [-secretstr=str] [-aes/-xor]\n");
    printf("* -pcr=N: PCR index to use (default %d)\n", TPM2_DEMO_PCR_INDEX);
    printf("* -seal: Seal only\n");
    printf("* -unseal: Unseal only\n");
    printf("* -both: Seal then unseal (default)\n");
    printf("* -sealblob=file: Sealed blob filename (default sealblob.bin)\n");
    printf("* -secretstr=str: Secret string to seal (default TestSealPCR)\n");
    printf("* -aes/xor: Use Parameter Encryption\n");
}

int TPM2_Seal_PCR_Example(void* userCtx, int argc, char *argv[])
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY storage;
    WOLFTPM2_KEYBLOB sealBlob;
    WOLFTPM2_SESSION tpmSession;
    TPMT_PUBLIC sealTemplate;
    TPM_ALG_ID paramEncAlg = TPM_ALG_NULL;
    TPM_ALG_ID pcrAlg = TPM_ALG_SHA256;
    byte pcrIndex = TPM2_DEMO_PCR_INDEX;
    byte pcrArray[1];
    word32 pcrArraySz;
    const char* sealFile = "sealblob.bin";
    const char* secretStr = "TestSealPCR";
    int doSeal = 0;
    int doUnseal = 0;
    byte policyDigest[TPM_SHA256_DIGEST_SIZE];
    word32 policyDigestSz;
    byte pcrDigest[TPM_SHA256_DIGEST_SIZE];
    int pcrDigestSz;
    Unseal_In unsealIn;
    Unseal_Out unsealOut;

    XMEMSET(&dev, 0, sizeof(dev));
    XMEMSET(&storage, 0, sizeof(storage));
    XMEMSET(&sealBlob, 0, sizeof(sealBlob));
    XMEMSET(&tpmSession, 0, sizeof(tpmSession));
    XMEMSET(&unsealIn, 0, sizeof(unsealIn));
    XMEMSET(&unsealOut, 0, sizeof(unsealOut));

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
        else if (XSTRCMP(argv[argc-1], "-seal") == 0) {
            doSeal = 1;
        }
        else if (XSTRCMP(argv[argc-1], "-unseal") == 0) {
            doUnseal = 1;
        }
        else if (XSTRCMP(argv[argc-1], "-both") == 0) {
            doSeal = 1;
            doUnseal = 1;
        }
        else if (XSTRNCMP(argv[argc-1], "-sealblob=",
                XSTRLEN("-sealblob=")) == 0) {
            sealFile = argv[argc-1] + XSTRLEN("-sealblob=");
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

    /* Default to both seal and unseal */
    if (!doSeal && !doUnseal) {
        doSeal = 1;
        doUnseal = 1;
    }

    pcrArray[0] = pcrIndex;
    pcrArraySz = 1;

    printf("TPM2.0 PCR Seal Example\n");
    printf("\tPCR Index: %d\n", pcrIndex);
    printf("\tSeal Blob: %s\n", sealFile);
    printf("\tUse Parameter Encryption: %s\n", TPM2_GetAlgName(paramEncAlg));

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_Init failed\n");
        goto exit;
    }

    /* Validate that the PCR bank is available */
    pcrDigestSz = (int)sizeof(pcrDigest);
    rc = wolfTPM2_ReadPCR(&dev, pcrIndex, pcrAlg, pcrDigest, &pcrDigestSz);
    if (rc != TPM_RC_SUCCESS) {
        printf("PCR %d with %s is not available (bank may not be active)\n",
            pcrIndex, TPM2_GetAlgName(pcrAlg));
        goto exit;
    }

    /* Get SRK */
    rc = getPrimaryStoragekey(&dev, &storage, TPM_ALG_RSA);
    if (rc != 0) goto exit;

    if (paramEncAlg != TPM_ALG_NULL) {
        /* Start an authenticated session (salted / unbound) with param enc */
        rc = wolfTPM2_StartSession(&dev, &tpmSession, &storage, NULL,
            TPM_SE_HMAC, paramEncAlg);
        if (rc != 0) goto exit;
        printf("TPM2_StartAuthSession: sessionHandle 0x%x\n",
            (word32)tpmSession.handle.hndl);
        rc = wolfTPM2_SetAuthSession(&dev, 1, &tpmSession,
            (TPMA_SESSION_decrypt | TPMA_SESSION_encrypt |
             TPMA_SESSION_continueSession));
        if (rc != 0) goto exit;
    }

    /* ---- SEAL ---- */
    if (doSeal) {
        WOLFTPM2_SESSION trialSession;
        XMEMSET(&trialSession, 0, sizeof(trialSession));

        printf("\nSealing secret: %s\n", secretStr);

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

        printf("Policy Digest (%d bytes)\n", policyDigestSz);

        /* Step 2: Create seal template with PCR policy */
        wolfTPM2_GetKeyTemplate_KeySeal(&sealTemplate, pcrAlg);
        /* Do NOT set TPMA_OBJECT_userWithAuth - policy-only access */
        sealTemplate.authPolicy.size = policyDigestSz;
        XMEMCPY(sealTemplate.authPolicy.buffer, policyDigest, policyDigestSz);

        /* Step 3: Create sealed blob */
        rc = wolfTPM2_CreateKeySeal_ex(&dev, &sealBlob, &storage.handle,
            &sealTemplate, NULL, 0, pcrAlg, pcrArray, pcrArraySz,
            (const byte*)secretStr, (int)XSTRLEN(secretStr));
        if (rc != TPM_RC_SUCCESS) {
            printf("wolfTPM2_CreateKeySeal_ex failed\n");
            goto exit;
        }
        printf("Created sealed blob (pub %d, priv %d bytes)\n",
            sealBlob.pub.size, sealBlob.priv.size);

    #if !defined(NO_FILESYSTEM) && !defined(NO_WRITE_TEMP_FILES)
        rc = writeKeyBlob(sealFile, &sealBlob);
        if (rc != 0) goto exit;
        printf("Sealed blob written to: %s\n", sealFile);
    #else
        printf("Filesystem support not available for saving sealed blob\n");
        (void)sealFile;
    #endif
    }

    /* ---- UNSEAL ---- */
    if (doUnseal) {
        WOLFTPM2_SESSION policySession;
        XMEMSET(&policySession, 0, sizeof(policySession));

        printf("\nUnsealing secret...\n");

        /* Clear param enc session from seal phase */
        if (paramEncAlg != TPM_ALG_NULL) {
            wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);
            wolfTPM2_UnsetAuth(&dev, 1);
        }

        /* Step 1: Load sealed blob from disk */
        if (!doSeal) {
            /* If we didn't just seal, load from file */
        #if !defined(NO_FILESYSTEM)
            rc = readKeyBlob(sealFile, &sealBlob);
            if (rc != 0) goto exit;
        #else
            printf("Filesystem support not available for loading sealed blob\n");
            rc = NOT_COMPILED_IN;
            goto exit;
        #endif
        }

        /* Step 2: Load sealed blob into TPM */
        rc = wolfTPM2_LoadKey(&dev, &sealBlob, &storage.handle);
        if (rc != TPM_RC_SUCCESS) {
            printf("wolfTPM2_LoadKey failed\n");
            goto exit;
        }
        printf("Loaded sealed blob to 0x%x\n", (word32)sealBlob.handle.hndl);

        /* Step 3: Start policy session and satisfy PCR policy.
         * If param enc is requested, create a salted policy session that
         * handles both authorization and parameter encryption. */
        rc = wolfTPM2_StartSession(&dev, &policySession,
            (paramEncAlg != TPM_ALG_NULL) ? &storage : NULL, NULL,
            TPM_SE_POLICY, paramEncAlg);
        if (rc != 0) {
            wolfTPM2_UnloadHandle(&dev, &sealBlob.handle);
            goto exit;
        }

        rc = wolfTPM2_PolicyPCR(&dev, policySession.handle.hndl,
            pcrAlg, pcrArray, pcrArraySz);
        if (rc != 0) {
            wolfTPM2_UnloadHandle(&dev, &policySession.handle);
            wolfTPM2_UnloadHandle(&dev, &sealBlob.handle);
            goto exit;
        }

        /* Step 4: Use policy session for unseal (with param enc if set) */
        {
            word32 sessionAttrs = TPMA_SESSION_continueSession;
            if (paramEncAlg != TPM_ALG_NULL) {
                sessionAttrs |= (TPMA_SESSION_decrypt |
                                 TPMA_SESSION_encrypt);
            }
            rc = wolfTPM2_SetAuthSession(&dev, 0, &policySession,
                sessionAttrs);
        }
        if (rc != 0) {
            wolfTPM2_UnloadHandle(&dev, &policySession.handle);
            wolfTPM2_UnloadHandle(&dev, &sealBlob.handle);
            goto exit;
        }
        wolfTPM2_SetAuthHandleName(&dev, 0, &sealBlob.handle);

        unsealIn.itemHandle = sealBlob.handle.hndl;
        rc = TPM2_Unseal(&unsealIn, &unsealOut);
        wolfTPM2_UnloadHandle(&dev, &policySession.handle);
        wolfTPM2_UnloadHandle(&dev, &sealBlob.handle);

        if (rc != TPM_RC_SUCCESS) {
            printf("TPM2_Unseal failed 0x%x: %s\n", rc,
                TPM2_GetRCString(rc));
            goto exit;
        }

        printf("Unsealed secret (%d bytes): %.*s\n",
            unsealOut.outData.size,
            unsealOut.outData.size, unsealOut.outData.buffer);
    }

exit:
    if (rc != 0) {
        printf("\nFailure 0x%x: %s\n\n", rc, wolfTPM2_GetRCString(rc));
    }

    wolfTPM2_UnloadHandle(&dev, &storage.handle);
    wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);

    wolfTPM2_Cleanup(&dev);

    return rc;
}

/******************************************************************************/
/* --- END TPM2.0 PCR Seal Example -- */
/******************************************************************************/
#endif /* !WOLFTPM2_NO_WRAPPER */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = NOT_COMPILED_IN;

#ifndef WOLFTPM2_NO_WRAPPER
    rc = TPM2_Seal_PCR_Example(NULL, argc, argv);
#else
    printf("Wrapper code not compiled in\n");
    (void)argc;
    (void)argv;
#endif

    return rc;
}
#endif
