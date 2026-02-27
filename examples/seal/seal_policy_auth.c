/* seal_policy_auth.c
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

/* Self-contained PolicyAuthorize seal/unseal example.
 *
 * Creates a TPM-internal signing key, seals a secret with PolicyAuthorize
 * + PCR policy, then unseals using the same key. No pre-existing signing
 * key is required — the TPM generates one internally. However, the key
 * blob file (authkey.bin) must be retained for subsequent unseal operations.
 *
 * Sealing method: PolicyAuthorize (with PCR policy)
 *   Complexity:   High
 *   Flexibility:  High (authorized updates - e.g., OS updates that change
 *                 PCRs but are signed by a trusted key)
 *   Use case:     Flexible measured boot with authorized policy updates
 *
 * IMPORTANT: The signing key blob (authkey.bin) MUST be kept alongside
 * the sealed blob (sealblob.bin). If the signing key is regenerated
 * (even with the same template), the TPM Name changes and the sealed
 * blob becomes un-unsealable.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_wrap.h>

#include <stdio.h>

#if !defined(WOLFTPM2_NO_WRAPPER) && !defined(WOLFTPM2_NO_WOLFCRYPT)

#include <examples/seal/seal.h>
#include <hal/tpm_io.h>
#include <examples/tpm_test.h>
#include <examples/tpm_test_keys.h>

/******************************************************************************/
/* --- BEGIN TPM2.0 PolicyAuthorize Seal Example -- */
/******************************************************************************/

static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/seal/seal_policy_auth [-ecc/-rsa] [-pcr=N]\n");
    printf("\t[-seal/-unseal/-both] [-sealblob=file] [-authkey=file]\n");
    printf("\t[-secretstr=str] [-aes/-xor]\n");
    printf("* -ecc/-rsa: Signing key type (default ECC)\n");
    printf("* -pcr=N: PCR index to use (default %d)\n", TPM2_DEMO_PCR_INDEX);
    printf("* -seal: Seal only\n");
    printf("* -unseal: Unseal only\n");
    printf("* -both: Seal then unseal (default)\n");
    printf("* -sealblob=file: Sealed blob filename (default sealblob.bin)\n");
    printf("* -authkey=file: Auth key blob filename (default authkey.bin)\n");
    printf("* -secretstr=str: Secret string to seal (default TestPolicyAuth)\n");
    printf("* -aes/xor: Use Parameter Encryption\n");
    printf("\nNOTE: authkey.bin and sealblob.bin must be kept together.\n");
}

int TPM2_Seal_PolicyAuth_Example(void* userCtx, int argc, char *argv[])
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY storage;
    WOLFTPM2_KEYBLOB authKeyBlob;
    WOLFTPM2_KEYBLOB sealBlob;
    WOLFTPM2_SESSION tpmSession;
    TPMT_PUBLIC sealTemplate;
    TPM_ALG_ID paramEncAlg = TPM_ALG_NULL;
    TPM_ALG_ID alg = TPM_ALG_ECC;
    TPM_ALG_ID pcrAlg = TPM_ALG_SHA256;
    byte pcrIndex = TPM2_DEMO_PCR_INDEX;
    byte pcrArray[1];
    word32 pcrArraySz;
    const char* sealFile = "sealblob.bin";
    const char* authKeyFile = "authkey.bin";
    const char* secretStr = "TestPolicyAuth";
    int doSeal = 0;
    int doUnseal = 0;
    byte policyDigest[TPM_SHA256_DIGEST_SIZE];
    word32 policyDigestSz;
    Unseal_In unsealIn;
    Unseal_Out unsealOut;

    XMEMSET(&dev, 0, sizeof(dev));
    XMEMSET(&storage, 0, sizeof(storage));
    XMEMSET(&authKeyBlob, 0, sizeof(authKeyBlob));
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
        if (XSTRCMP(argv[argc-1], "-ecc") == 0) {
            alg = TPM_ALG_ECC;
        }
        else if (XSTRCMP(argv[argc-1], "-rsa") == 0) {
            alg = TPM_ALG_RSA;
        }
        else if (XSTRNCMP(argv[argc-1], "-pcr=", XSTRLEN("-pcr=")) == 0) {
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
        else if (XSTRNCMP(argv[argc-1], "-authkey=",
                XSTRLEN("-authkey=")) == 0) {
            authKeyFile = argv[argc-1] + XSTRLEN("-authkey=");
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

    printf("TPM2.0 PolicyAuthorize Seal Example\n");
    printf("\tKey Type: %s\n", TPM2_GetAlgName(alg));
    printf("\tPCR Index: %d\n", pcrIndex);
    printf("\tSeal Blob: %s\n", sealFile);
    printf("\tAuth Key: %s\n", authKeyFile);
    printf("\tUse Parameter Encryption: %s\n", TPM2_GetAlgName(paramEncAlg));

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_Init failed\n");
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
        TPMT_PUBLIC keyTemplate;

        printf("\nSealing secret: %s\n", secretStr);

        /* Step 1: Create signing key under SRK */
        if (alg == TPM_ALG_ECC) {
            rc = wolfTPM2_GetKeyTemplate_ECC(&keyTemplate,
                TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
                TPMA_OBJECT_sign | TPMA_OBJECT_noDA,
                TPM_ECC_NIST_P256, TPM_ALG_ECDSA);
        }
        else {
            rc = wolfTPM2_GetKeyTemplate_RSA(&keyTemplate,
                TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
                TPMA_OBJECT_sign | TPMA_OBJECT_noDA);
            keyTemplate.parameters.rsaDetail.scheme.scheme = TPM_ALG_RSASSA;
            keyTemplate.parameters.rsaDetail.scheme.details.rsassa.hashAlg =
                TPM_ALG_SHA256;
        }
        if (rc != 0) goto exit;

        rc = wolfTPM2_CreateKey(&dev, &authKeyBlob, &storage.handle,
            &keyTemplate, (const byte*)gKeyAuth,
            (int)sizeof(gKeyAuth) - 1);
        if (rc != 0) {
            printf("wolfTPM2_CreateKey (auth key) failed\n");
            goto exit;
        }
        /* Set auth on handle after create (CreateKey zeroes the keyBlob) */
        authKeyBlob.handle.auth.size = (int)sizeof(gKeyAuth) - 1;
        XMEMCPY(authKeyBlob.handle.auth.buffer, gKeyAuth,
            authKeyBlob.handle.auth.size);
        printf("Created %s signing key (pub %d, priv %d bytes)\n",
            TPM2_GetAlgName(alg), authKeyBlob.pub.size, authKeyBlob.priv.size);

    #if !defined(NO_FILESYSTEM) && !defined(NO_WRITE_TEMP_FILES)
        /* Save key blob to disk - MUST keep alongside sealed blob */
        rc = writeKeyBlob(authKeyFile, &authKeyBlob);
        if (rc != 0) goto exit;
        printf("Auth key blob written to: %s\n", authKeyFile);
    #else
        printf("Filesystem support not available for saving auth key\n");
        (void)authKeyFile;
    #endif

        /* Step 2: Compute PolicyAuthorize digest from key's public area */
        policyDigestSz = TPM2_GetHashDigestSize(pcrAlg);
        XMEMSET(policyDigest, 0, sizeof(policyDigest));
        rc = wolfTPM2_PolicyAuthorizeMake(pcrAlg, &authKeyBlob.pub,
            policyDigest, &policyDigestSz, NULL, 0);
        if (rc != 0) {
            printf("wolfTPM2_PolicyAuthorizeMake failed\n");
            goto exit;
        }
        printf("PolicyAuthorize Digest (%d bytes)\n", policyDigestSz);

        /* Step 3: Create seal template with PolicyAuthorize digest */
        wolfTPM2_GetKeyTemplate_KeySeal(&sealTemplate, pcrAlg);
        /* Do NOT set TPMA_OBJECT_userWithAuth - policy-only access */
        sealTemplate.authPolicy.size = policyDigestSz;
        XMEMCPY(sealTemplate.authPolicy.buffer, policyDigest, policyDigestSz);

        /* Step 4: Create sealed blob */
        rc = wolfTPM2_CreateKeySeal_ex(&dev, &sealBlob, &storage.handle,
            &sealTemplate, NULL, 0, pcrAlg, NULL, 0,
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
        byte pcrDigest[TPM_SHA256_DIGEST_SIZE];
        word32 pcrDigestSz;
        byte sig[512]; /* up to 4096-bit key */
        int sigSz;
        TPMT_TK_VERIFIED checkTicket;
        TPMI_ALG_SIG_SCHEME sigAlg;
        byte* policyRef = NULL;
        word32 policyRefSz = 0;

        XMEMSET(&policySession, 0, sizeof(policySession));
        XMEMSET(&checkTicket, 0, sizeof(checkTicket));

        printf("\nUnsealing secret...\n");

        /* Clear param enc session from seal phase (nonces are stale).
         * A fresh session will be started before unseal if needed. */
        if (paramEncAlg != TPM_ALG_NULL) {
            wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);
            wolfTPM2_UnsetAuth(&dev, 1);
        }

        /* Step 1: Load auth key blob */
        if (!doSeal) {
            /* If we didn't just seal, load from file */
        #if !defined(NO_FILESYSTEM)
            rc = readKeyBlob(authKeyFile, &authKeyBlob);
            if (rc != 0) {
                printf("Error loading auth key blob from: %s\n", authKeyFile);
                goto exit;
            }
        #else
            printf("Filesystem support not available\n");
            rc = NOT_COMPILED_IN;
            goto exit;
        #endif
        }

        /* Set auth for the key */
        authKeyBlob.handle.auth.size = (int)sizeof(gKeyAuth) - 1;
        XMEMCPY(authKeyBlob.handle.auth.buffer, gKeyAuth,
            authKeyBlob.handle.auth.size);

        /* Load auth key into TPM */
        rc = wolfTPM2_LoadKey(&dev, &authKeyBlob, &storage.handle);
        if (rc != TPM_RC_SUCCESS) {
            printf("wolfTPM2_LoadKey (auth key) failed\n");
            goto exit;
        }
        printf("Loaded auth key to 0x%x\n", (word32)authKeyBlob.handle.hndl);

        /* Step 2: Load sealed blob */
        if (!doSeal) {
        #if !defined(NO_FILESYSTEM)
            rc = readKeyBlob(sealFile, &sealBlob);
            if (rc != 0) {
                printf("Error loading sealed blob from: %s\n", sealFile);
                wolfTPM2_UnloadHandle(&dev, &authKeyBlob.handle);
                goto exit;
            }
        #else
            rc = NOT_COMPILED_IN;
            wolfTPM2_UnloadHandle(&dev, &authKeyBlob.handle);
            goto exit;
        #endif
        }

        rc = wolfTPM2_LoadKey(&dev, &sealBlob, &storage.handle);
        if (rc != TPM_RC_SUCCESS) {
            printf("wolfTPM2_LoadKey (seal blob) failed\n");
            wolfTPM2_UnloadHandle(&dev, &authKeyBlob.handle);
            goto exit;
        }
        printf("Loaded sealed blob to 0x%x\n", (word32)sealBlob.handle.hndl);

        /* Step 3: Start policy session and apply PCR policy.
         * If param enc is requested, create a salted policy session that
         * handles both authorization and parameter encryption. */
        rc = wolfTPM2_StartSession(&dev, &policySession,
            (paramEncAlg != TPM_ALG_NULL) ? &storage : NULL, NULL,
            TPM_SE_POLICY, paramEncAlg);
        if (rc != 0) {
            wolfTPM2_UnloadHandle(&dev, &authKeyBlob.handle);
            wolfTPM2_UnloadHandle(&dev, &sealBlob.handle);
            goto exit;
        }

        rc = wolfTPM2_PolicyPCR(&dev, policySession.handle.hndl,
            pcrAlg, pcrArray, pcrArraySz);
        if (rc != 0) {
            printf("wolfTPM2_PolicyPCR failed\n");
            wolfTPM2_UnloadHandle(&dev, &policySession.handle);
            wolfTPM2_UnloadHandle(&dev, &authKeyBlob.handle);
            wolfTPM2_UnloadHandle(&dev, &sealBlob.handle);
            goto exit;
        }

        /* Step 4: Get policy digest from session */
        pcrDigestSz = (word32)sizeof(pcrDigest);
        rc = wolfTPM2_GetPolicyDigest(&dev, policySession.handle.hndl,
            pcrDigest, &pcrDigestSz);
        if (rc != 0) {
            printf("wolfTPM2_GetPolicyDigest failed\n");
            wolfTPM2_UnloadHandle(&dev, &policySession.handle);
            wolfTPM2_UnloadHandle(&dev, &authKeyBlob.handle);
            wolfTPM2_UnloadHandle(&dev, &sealBlob.handle);
            goto exit;
        }
        printf("PCR Policy Digest (%d bytes)\n", pcrDigestSz);

        /* Step 5: Hash digest with policyRef (empty) */
        policyDigestSz = pcrDigestSz;
        XMEMCPY(policyDigest, pcrDigest, pcrDigestSz);
        rc = wolfTPM2_PolicyRefMake(pcrAlg, policyDigest, &policyDigestSz,
            policyRef, policyRefSz);
        if (rc != 0) {
            printf("wolfTPM2_PolicyRefMake failed\n");
            wolfTPM2_UnloadHandle(&dev, &policySession.handle);
            wolfTPM2_UnloadHandle(&dev, &authKeyBlob.handle);
            wolfTPM2_UnloadHandle(&dev, &sealBlob.handle);
            goto exit;
        }

        /* Step 6: Sign the policy digest with the TPM auth key */
        wolfTPM2_SetAuthHandle(&dev, 0, &authKeyBlob.handle);
        sigSz = (int)sizeof(sig);
        rc = wolfTPM2_SignHash(&dev, (WOLFTPM2_KEY*)&authKeyBlob,
            policyDigest, policyDigestSz, sig, &sigSz);
        if (rc != 0) {
            printf("wolfTPM2_SignHash failed\n");
            wolfTPM2_UnloadHandle(&dev, &policySession.handle);
            wolfTPM2_UnloadHandle(&dev, &authKeyBlob.handle);
            wolfTPM2_UnloadHandle(&dev, &sealBlob.handle);
            goto exit;
        }
        printf("Signed policy digest (%d bytes)\n", sigSz);

        /* Step 7: Verify the signature and get a ticket from the TPM */
        sigAlg = (alg == TPM_ALG_RSA) ? TPM_ALG_RSASSA : TPM_ALG_ECDSA;
        rc = wolfTPM2_VerifyHashTicket(&dev, (WOLFTPM2_KEY*)&authKeyBlob,
            sig, sigSz, policyDigest, policyDigestSz, sigAlg, pcrAlg,
            &checkTicket);
        if (rc != 0) {
            printf("wolfTPM2_VerifyHashTicket failed\n");
            wolfTPM2_UnloadHandle(&dev, &policySession.handle);
            wolfTPM2_UnloadHandle(&dev, &authKeyBlob.handle);
            wolfTPM2_UnloadHandle(&dev, &sealBlob.handle);
            goto exit;
        }
        printf("Verify ticket: tag 0x%x, hi 0x%x\n",
            checkTicket.tag, checkTicket.hierarchy);

        /* Step 8: PolicyAuthorize with the ticket */
        rc = wolfTPM2_PolicyAuthorize(&dev, policySession.handle.hndl,
            &authKeyBlob.pub, &checkTicket, pcrDigest, pcrDigestSz,
            policyRef, policyRefSz);
        if (rc != 0) {
            printf("wolfTPM2_PolicyAuthorize failed\n");
            wolfTPM2_UnloadHandle(&dev, &policySession.handle);
            wolfTPM2_UnloadHandle(&dev, &authKeyBlob.handle);
            wolfTPM2_UnloadHandle(&dev, &sealBlob.handle);
            goto exit;
        }

        /* Done with auth key */
        wolfTPM2_UnloadHandle(&dev, &authKeyBlob.handle);

        /* Step 9: Unseal using the policy session (with param enc if set) */
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

    wolfTPM2_UnloadHandle(&dev, &authKeyBlob.handle);
    wolfTPM2_UnloadHandle(&dev, &sealBlob.handle);
    wolfTPM2_UnloadHandle(&dev, &storage.handle);
    wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);

    wolfTPM2_Cleanup(&dev);

    return rc;
}

/******************************************************************************/
/* --- END TPM2.0 PolicyAuthorize Seal Example -- */
/******************************************************************************/
#endif /* !WOLFTPM2_NO_WRAPPER && !WOLFTPM2_NO_WOLFCRYPT */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = NOT_COMPILED_IN;

#if !defined(WOLFTPM2_NO_WRAPPER) && !defined(WOLFTPM2_NO_WOLFCRYPT)
    rc = TPM2_Seal_PolicyAuth_Example(NULL, argc, argv);
#else
    printf("Example not compiled in! Requires Wrapper and wolfCrypt\n");
    (void)argc;
    (void)argv;
#endif

    return rc;
}
#endif
