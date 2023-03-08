/* seal_policy_auth.c
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* This is a helper tool for setting policies on a TPM 2.0 PCR */

#include <wolftpm/tpm2_wrap.h>

#ifndef WOLFTPM2_NO_WRAPPER

#ifndef WOLFTPM2_NO_WOLFCRYPT
#include <wolfssl/wolfcrypt/hash.h>
#endif

#include <hal/tpm_io.h>
#include <examples/seal/seal.h>
//#include <examples/tpm_test.h>

#include <stdio.h>

/******************************************************************************/
/* --- BEGIN TPM2.0 PCR Policy example tool  -- */
/******************************************************************************/

static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/pcr/policy [-aes/xor] [-digest=HEXSTR] [pcr]\n");
    printf("* pcr: PCR index between 0-23 (default %d)\n", 16);
    printf("* -aes/xor: Use Parameter Encryption\n");
    //printf("* -digest=[HEXSTR]: SHA-1 or SHA2-256 hash of expected PCR's\n");
}

//static const char gKeyAuth[] =        "ThisIsMyKeyAuth";
//static const char gStorageKeyAuth[] = "ThisIsMyStorageKeyAuth";

int TPM2_PCR_Seal_With_Policy_Auth_Test(void* userCtx, int argc, char *argv[])
{
    int rc = -1;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY storage;
    WOLFTPM2_SESSION tpmSession;
    WOLFTPM2_KEYBLOB authKey;
    WOLFTPM2_KEYBLOB sealBlob;
    TPMT_PUBLIC publicTemplate;
    TPM2B_AUTH auth;
    TPM_ALG_ID paramEncAlg = TPM_ALG_NULL;
    int pcrIndex = 16;
    byte policyDigest[32];
    int policyDigestSz = sizeof(policyDigest);
    byte policyDigestSig[32];
    int policyDigestSigSz = sizeof(policyDigestSig);
    int pcrArray[] = {16};
    byte secret[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    byte secretOut[16];
    int secretOutSz;
    TPM_ALG_ID alg = TPM_ALG_RSA;

    XMEMSET(&dev, 0, sizeof(WOLFTPM2_DEV));
    XMEMSET(&storage, 0, sizeof(WOLFTPM2_KEY));
    XMEMSET(&tpmSession, 0, sizeof(WOLFTPM2_SESSION));
    XMEMSET(&authKey, 0, sizeof(WOLFTPM2_KEYBLOB));
    XMEMSET(&sealBlob, 0, sizeof(WOLFTPM2_KEYBLOB));
    XMEMSET(&publicTemplate, 0, sizeof(TPMT_PUBLIC));
    XMEMSET(&auth, 0, sizeof(TPM2B_AUTH));

    if (argc >= 2) {
        if (XSTRCMP(argv[1], "-?") == 0 ||
            XSTRCMP(argv[1], "-h") == 0 ||
            XSTRCMP(argv[1], "--help") == 0) {
            usage();
            return 0;
        }
    }
    while (argc > 1) {
        if (XSTRCMP(argv[argc-1], "-aes") == 0) {
            paramEncAlg = TPM_ALG_CFB;
        }
        else if (XSTRCMP(argv[argc-1], "-xor") == 0) {
            paramEncAlg = TPM_ALG_XOR;
        }
        else if (XSTRCMP(argv[argc-1], "-rsa") == 0) {
            alg = TPM_ALG_RSA;
        }
        else if (XSTRCMP(argv[argc-1], "-ecc") == 0) {
            alg = TPM_ALG_ECC;
        }
        else if (argv[argc-1][0] != '-') {
            /* TODO: Allow selection of multiple PCR's SHA-1 or SHA2-256 */
            pcrIndex = XATOI(argv[argc-1]);
            if (pcrIndex < (int)PCR_FIRST || pcrIndex > (int)PCR_LAST) {
                printf("PCR index is out of range (0-23)\n");
                usage();
                return 0;
            }
        }
        else {
            printf("Warning: Unrecognized option: %s\n", argv[argc-1]);
        }
        argc--;
    }

    printf("Example for setting PCR policies\n");
    printf("\tPCR Index: %d\n", pcrIndex);
    printf("\tUse Parameter Encryption: %s\n", TPM2_GetAlgName(paramEncAlg));

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_Init failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    printf("wolfTPM2_Init: success\n");

    /* session is required for pcr authorization */
    /* Start an authenticated policy session (salted / unbound) */
    rc = wolfTPM2_StartSession(&dev, &tpmSession, NULL, NULL,
        TPM_SE_POLICY, paramEncAlg);
    if (rc != 0) goto exit;
    printf("TPM2_StartAuthSession: sessionHandle 0x%x\n",
        (word32)tpmSession.handle.hndl);

    /* set session for authorization of the storage key */
    rc = wolfTPM2_SetAuthSession(&dev, 0, &tpmSession,
        (TPMA_SESSION_decrypt | TPMA_SESSION_encrypt | TPMA_SESSION_continueSession));
    if (rc != 0) goto exit;

    /* Create primary storage key */
    rc = wolfTPM2_CreateSRK(&dev, &storage, TPM_ALG_ECC,
        NULL, 0);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_CreateSRK failed\n");
        goto exit;
    }

    /* create the template */
    if (alg == TPM_ALG_RSA) {
        printf("RSA template\n");
        rc = wolfTPM2_GetKeyTemplate_RSA(&publicTemplate,
                 TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
                 TPMA_OBJECT_decrypt | TPMA_OBJECT_sign | TPMA_OBJECT_noDA);
    }
    else if (alg == TPM_ALG_ECC) {
        printf("ECC template\n");
        rc = wolfTPM2_GetKeyTemplate_ECC(&publicTemplate,
                 TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
                 TPMA_OBJECT_sign | TPMA_OBJECT_noDA,
                 TPM_ECC_NIST_P256, TPM_ALG_ECDSA);
    }

    /* set the auth */
    /*
    auth.size = (int)sizeof(gKeyAuth)-1;
    XMEMCPY(auth.buffer, gKeyAuth, auth.size);
    */

    /* generate the authorized key */
    rc = wolfTPM2_CreateKey(&dev, &authKey, &storage.handle,
                            &publicTemplate, NULL, 0);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_CreateKey failed\n");
        goto exit;
    }

    rc = wolfTPM2_LoadKey(&dev, &authKey, &storage.handle);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_LoadKey failed\n");
        goto exit;
    }

    /* seal the secret */
    rc = wolfTPM2_SealWithAuthKey(&dev, &auth, &authKey, &storage.handle,
        &publicTemplate, &sealBlob, tpmSession.handle.hndl, TPM_ALG_SHA256,
        pcrArray, sizeof(pcrArray), secret, sizeof(secret), policyDigest,
        &policyDigestSz);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_SealWithAuthorizedKey failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }

    /* sign the digest */
    rc = wolfTPM2_SignHash(&dev, (WOLFTPM2_KEY*)&authKey, policyDigest, policyDigestSz,
        policyDigestSig, &policyDigestSigSz);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_SignHash failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }

    /* unseal the secret */
    rc = wolfTPM2_UnsealWithAuthSig(&dev, &auth, &authKey,
        tpmSession.handle.hndl, sealBlob.handle.hndl, TPM_ALG_SHA256,
        pcrArray, sizeof(pcrArray), policyDigest, policyDigestSz, policyDigestSig,
        policyDigestSigSz, secretOut, &secretOutSz);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_UnsealWithAuthorizedKey failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }

    if (memcmp(secret, secretOut, sizeof(secret)) != 0) {
        printf("Usealed secret does not match\n");
        goto exit;
    }
    else {
        printf("Usealed secret matches!\n");
    }

exit:

    if (rc != 0) {
        printf("Failure 0x%x: %s\n", rc, wolfTPM2_GetRCString(rc));
    }

    wolfTPM2_UnloadHandle(&dev, &authKey.handle);
    wolfTPM2_UnloadHandle(&dev, &sealBlob.handle);
    wolfTPM2_UnloadHandle(&dev, &storage.handle);
    wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);

    wolfTPM2_Cleanup(&dev);

    return rc;
}

/******************************************************************************/
/* --- END TPM2.0 PCR Policy example tool -- */
/******************************************************************************/

#endif /* !WOLFTPM2_NO_WRAPPER */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = -1;

#ifndef WOLFTPM2_NO_WRAPPER
    rc = TPM2_PCR_Seal_With_Policy_Auth_Test(NULL, argc, argv);
#else
    printf("Wrapper code not compiled in\n");
    (void)argc;
    (void)argv;
#endif /* !WOLFTPM2_NO_WRAPPER */

    return rc;
}
#endif
