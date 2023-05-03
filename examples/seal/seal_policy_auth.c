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

#include <stdio.h>

#ifndef WOLFTPM2_NO_WRAPPER

#ifndef WOLFTPM2_NO_WOLFCRYPT
#include <wolfssl/wolfcrypt/hash.h>
#endif

#include <examples/seal/seal.h>
#include <hal/tpm_io.h>
#include <examples/tpm_test.h>
#include <examples/tpm_test_keys.h>

/******************************************************************************/
/* --- BEGIN TPM2.0 PCR Policy example tool  -- */
/******************************************************************************/

static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/seal/seal_policy_auth [-aes/xor] [-rsa/ecc] [pcr]\n");
    printf("* -aes/xor: Use Parameter Encryption\n");
    printf("* -rsa/ecc: Pick sealing key type, (default rsa)\n");
    printf("* pcr: PCR index between 0-23 (default %d)\n", TPM2_DEMO_PCR_INDEX);
}

int TPM2_PCR_Seal_With_Policy_Auth_Test(void* userCtx, int argc, char *argv[])
{
    int i;
    int rc = -1;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY storage;
    WOLFTPM2_SESSION tpmSession;
    WOLFTPM2_KEYBLOB authKey;
    WOLFTPM2_KEYBLOB sealBlob;
    TPMT_PUBLIC authTemplate;
    TPMT_PUBLIC sealTemplate;
    /* default to aes since parm encryption is required */
    TPM_ALG_ID paramEncAlg = TPM_ALG_CFB;
    TPM_ALG_ID alg = TPM_ALG_RSA;
    word32 pcrIndex = TPM2_DEMO_PCR_INDEX;
    byte policyDigest[TPM_MAX_DIGEST_SIZE];
    word32 policyDigestSz = (word32)sizeof(policyDigest);
    byte policyDigestSig[MAX_RSA_KEY_BYTES];
    word32 policyDigestSigSz = (word32)sizeof(policyDigestSig);
    byte badDigest[TPM_MAX_DIGEST_SIZE] = {0};
    byte badSig[TPM_MAX_DIGEST_SIZE] = {0};
    word32 badSigSz = (word32)TPM_MAX_DIGEST_SIZE;
    word32 pcrArray[48];
    word32 pcrArraySz = 0;
    byte nonce[16];
    byte secret[16];
    byte secretOut[16];
    word32 secretOutSz = (word32)sizeof(secretOut);
    Unseal_In unsealIn[1];
    Unseal_Out unsealOut[1];

    XMEMSET(&dev, 0, sizeof(WOLFTPM2_DEV));
    XMEMSET(&storage, 0, sizeof(WOLFTPM2_KEY));
    XMEMSET(&tpmSession, 0, sizeof(WOLFTPM2_SESSION));
    XMEMSET(&authKey, 0, sizeof(WOLFTPM2_KEYBLOB));
    XMEMSET(&sealBlob, 0, sizeof(WOLFTPM2_KEYBLOB));
    XMEMSET(&authTemplate, 0, sizeof(TPMT_PUBLIC));
    XMEMSET(&sealTemplate, 0, sizeof(TPMT_PUBLIC));
    XMEMSET(unsealIn, 0, sizeof(Unseal_In));
    XMEMSET(unsealOut, 0, sizeof(Unseal_Out));

    /* set nonce and secret */
    for (i = 0; i < (int)sizeof(nonce); i++) {
        nonce[i] = sizeof(nonce) - 1 - i;
        secret[i] = i;
    }

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
            if (pcrIndex > PCR_LAST) {
                printf("PCR index is out of range (0-23)\n");
                usage();
                return 0;
            }
            pcrArray[pcrArraySz] = pcrIndex;
            pcrArraySz++;
        }
        else {
            printf("Warning: Unrecognized option: %s\n", argv[argc-1]);
        }
        argc--;
    }

    if (pcrArraySz == 0) {
        pcrArray[pcrArraySz] = pcrIndex;
        pcrArraySz++;
    }

    printf("Example for sealing data to the TPM with policy authorization\n");
    printf("\tPCR Indicies:");

    for (i = 0; i < (int)pcrArraySz; i++) {
        printf("%d ", pcrArray[i]);
    }

    printf("\n");
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
        (TPMA_SESSION_decrypt | TPMA_SESSION_encrypt |
        TPMA_SESSION_continueSession));
    if (rc != 0) goto exit;

    /* get SRK */
    rc = getPrimaryStoragekey(&dev, &storage, TPM_ALG_RSA);
    if (rc != 0) goto exit;

    /* create the auth key template */
    if (alg == TPM_ALG_RSA) {
        printf("RSA template\n");
        rc = wolfTPM2_GetKeyTemplate_RSA(&authTemplate,
                 TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
                 TPMA_OBJECT_decrypt | TPMA_OBJECT_sign | TPMA_OBJECT_noDA);
    }
    else if (alg == TPM_ALG_ECC) {
        printf("ECC template\n");
        rc = wolfTPM2_GetKeyTemplate_ECC(&authTemplate,
                 TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
                 TPMA_OBJECT_sign | TPMA_OBJECT_noDA,
                 TPM_ECC_NIST_P256, TPM_ALG_ECDSA);
    }

    if (rc != TPM_RC_SUCCESS) {
        printf("key template generation failed\n");
        goto exit;
    }

    /* generate the authorized key, this auth key can also generated and */
    /* loaded externally */
    rc = wolfTPM2_CreateKey(&dev, &authKey, &storage.handle,
                            &authTemplate, NULL, 0);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_CreateKey failed\n");
        goto exit;
    }

    rc = wolfTPM2_LoadKey(&dev, &authKey, &storage.handle);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_LoadKey failed\n");
        goto exit;
    }

    /* create the template */
    wolfTPM2_GetKeyTemplate_KeySeal(&sealTemplate, TPM_ALG_SHA256);

    /* seal the secret */
    rc = wolfTPM2_SealWithAuthKey(&dev, &authKey, &storage.handle,
        &sealTemplate, &sealBlob, tpmSession.handle.hndl,
        TPM_ALG_SHA256, pcrArray, pcrArraySz,
        secret, sizeof(secret), nonce, sizeof(nonce), policyDigest,
        &policyDigestSz, policyDigestSig, &policyDigestSigSz);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_SealWithAuthKey failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }

    /* load the seal blob */
    rc = wolfTPM2_LoadKey(&dev, &sealBlob, &storage.handle);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_LoadKey failed\n");
        goto exit;
    }
    printf("Loaded sealBlob to 0x%x\n",
        (word32)sealBlob.handle.hndl);

    /* reset our session */
    wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);

    rc = wolfTPM2_StartSession(&dev, &tpmSession, NULL, NULL,
        TPM_SE_POLICY, paramEncAlg);
    if (rc != 0) goto exit;
    printf("TPM2_StartAuthSession: sessionHandle 0x%x\n",
        (word32)tpmSession.handle.hndl);

    /* set session for authorization of the storage key */
    rc = wolfTPM2_SetAuthSession(&dev, 0, &tpmSession,
        (TPMA_SESSION_decrypt | TPMA_SESSION_encrypt |
        TPMA_SESSION_continueSession));
    if (rc != 0) goto exit;

    /* try to unseal with the regular command, should fail */
    unsealIn->itemHandle = sealBlob.handle.hndl;

    rc = TPM2_Unseal(unsealIn, unsealOut);

    if (rc == TPM_RC_SUCCESS) {
        printf("TPM2_Unseal failed, should not have allowed unauthorized"
            "unseal 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }

    /* unseal the secret */
    rc = wolfTPM2_UnsealWithAuthSig(&dev, &authKey,
        tpmSession.handle.hndl, sealBlob.handle.hndl, TPM_ALG_SHA256,
        pcrArray, pcrArraySz, policyDigest,
        policyDigestSz, nonce, sizeof(nonce), policyDigestSig,
        policyDigestSigSz, secretOut, &secretOutSz);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_UnsealWithAuthSig failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }

    if (XMEMCMP(secret, secretOut, sizeof(secret)) != 0) {
        printf("Usealed secret does not match\n");
        goto exit;
    }
    else {
        printf("Usealed secret matches!\n");
    }

    /* try to unseal with a bad signature, should fail */
    rc = wolfTPM2_UnsealWithAuthSig(&dev, &authKey,
        tpmSession.handle.hndl, sealBlob.handle.hndl, TPM_ALG_SHA256,
        pcrArray, pcrArraySz, policyDigest,
        policyDigestSz, nonce, sizeof(nonce), badSig, policyDigestSigSz,
        secretOut, &secretOutSz);
    if (rc == TPM_RC_SUCCESS) {
        printf("wolfTPM2_UnsealWithAuthorizedKey failed, should not have"
            "allowed bad signature 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }

    /* sign the bad digest, this is done for testing */
    rc = wolfTPM2_SignHash(&dev, (WOLFTPM2_KEY*)&authKey, badDigest, policyDigestSz,
        badSig, (int*)&badSigSz);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_SignHash failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }

    /* try to unseal with a bad digest, but good signature, should fail */
    rc = wolfTPM2_UnsealWithAuthSig(&dev, &authKey,
        tpmSession.handle.hndl, sealBlob.handle.hndl, TPM_ALG_SHA256,
        pcrArray, pcrArraySz, badDigest,
        policyDigestSz, nonce, sizeof(nonce), badSig, badSigSz, secretOut,
        &secretOutSz);
    if (rc == TPM_RC_SUCCESS) {
        printf("wolfTPM2_UnsealWithAuthorizedKey failed, should not have"
            "allowed bad digest 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    else {
        rc = 0;
    }

exit:
    if (rc != 0) {
        printf("Failure 0x%x: %s\n", rc, wolfTPM2_GetRCString(rc));
    }

    wolfTPM2_SetAuthPassword(&dev, 0, NULL);

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
