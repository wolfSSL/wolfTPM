/* keygen.c
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
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

/* Tool and example for creating, storing and loading keys using TPM2.0 */

#include <wolftpm/tpm2_wrap.h>

#include <examples/keygen/keygen.h>
#include <examples/tpm_io.h>
#include <examples/tpm_test.h>
#include <examples/tpm_test_keys.h>

#include <stdio.h>

#ifndef WOLFTPM2_NO_WRAPPER

/******************************************************************************/
/* --- BEGIN TPM Keygen Example -- */
/******************************************************************************/
static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/keygen/keygen [keyblob.bin] [-ecc/-rsa] [-t] [-aes/xor]\n");
    printf("* -ecc: Use RSA or ECC for keys\n");
    printf("* -t: Use default template (otherwise AIK)\n");
    printf("* -aes/xor: Use Parameter Encryption\n");
}

int TPM2_Keygen_Example(void* userCtx, int argc, char *argv[])
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY storage; /* SRK */
    WOLFTPM2_KEYBLOB newKey;
    TPMT_PUBLIC publicTemplate;
    TPMI_ALG_PUBLIC alg = TPM_ALG_RSA; /* TPM_ALG_ECC */
    TPM_ALG_ID paramEncAlg = TPM_ALG_NULL;
    WOLFTPM2_SESSION tpmSession;
    TPM2B_AUTH auth;
    int bAIK = 1;
    const char* outputFile = "keyblob.bin";

    if (argc >= 2) {
        if (XSTRNCMP(argv[1], "-?", 2) == 0 ||
            XSTRNCMP(argv[1], "-h", 2) == 0 ||
            XSTRNCMP(argv[1], "--help", 6) == 0) {
            usage();
            return 0;
        }
        if (argv[1][0] != '-')
            outputFile = argv[1];
    }
    while (argc > 1) {
        if (XSTRNCMP(argv[argc-1], "-ecc", 4) == 0) {
            alg = TPM_ALG_ECC;
        }
        if (XSTRNCMP(argv[argc-1], "-t", 2) == 0) {
            bAIK = 0;
        }
        if (XSTRNCMP(argv[argc-1], "-aes", 4) == 0) {
            paramEncAlg = TPM_ALG_CFB;
        }
        if (XSTRNCMP(argv[argc-1], "-xor", 4) == 0) {
            paramEncAlg = TPM_ALG_XOR;
        }
        argc--;
    }

    XMEMSET(&storage, 0, sizeof(storage));
    XMEMSET(&newKey, 0, sizeof(newKey));
    XMEMSET(&tpmSession, 0, sizeof(tpmSession));
    XMEMSET(&auth, 0, sizeof(auth));

    printf("TPM2.0 Key generation example\n");
    printf("\tKey Blob: %s\n", outputFile);
    printf("\tAlgorithm: %s\n", TPM2_GetAlgName(alg));
    printf("\tTemplate: %s\n", bAIK ? "AIK" : "Default");
    printf("\tUse Parameter Encryption: %s\n", TPM2_GetAlgName(paramEncAlg));

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("\nwolfTPM2_Init failed\n");
        goto exit;
    }

    /* get SRK */
    rc = getPrimaryStoragekey(&dev, &storage, TPM_ALG_RSA);
    if (rc != 0) goto exit;

    if (paramEncAlg != TPM_ALG_NULL) {
        /* Start an authenticated session (salted / unbound) with parameter encryption */
        rc = wolfTPM2_StartSession(&dev, &tpmSession, &storage, NULL,
            TPM_SE_HMAC, paramEncAlg);
        if (rc != 0) goto exit;
        printf("TPM2_StartAuthSession: sessionHandle 0x%x\n",
            (word32)tpmSession.handle.hndl);

        /* set session for authorization of the storage key */
        rc = wolfTPM2_SetAuthSession(&dev, 1, &tpmSession,
            (TPMA_SESSION_decrypt | TPMA_SESSION_encrypt | TPMA_SESSION_continueSession));
        if (rc != 0) goto exit;
    }

    /* Create new key */
    if (bAIK) {
        if (alg == TPM_ALG_RSA) {
            printf("RSA AIK template\n");
            rc = wolfTPM2_GetKeyTemplate_RSA_AIK(&publicTemplate);
        }
        else if (alg == TPM_ALG_ECC) {
            printf("ECC AIK template\n");
            rc = wolfTPM2_GetKeyTemplate_ECC_AIK(&publicTemplate);
        }
        else {
            rc = BAD_FUNC_ARG;
        }

        /* set session for authorization key */
        auth.size = (int)sizeof(gAiKeyAuth)-1;
        XMEMCPY(auth.buffer, gAiKeyAuth, auth.size);

    }
    else {
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
        else {
            rc = BAD_FUNC_ARG;
        }

        /* set session for authorization key */
        auth.size = (int)sizeof(gKeyAuth)-1;
        XMEMCPY(auth.buffer, gKeyAuth, auth.size);
    }
    if (rc != 0) goto exit;

    printf("Creating new %s key...\n", TPM2_GetAlgName(alg));
    rc = wolfTPM2_CreateKey(&dev, &newKey, &storage.handle,
                            &publicTemplate, auth.buffer, auth.size);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_CreateKey failed\n");
        goto exit;
    }
    printf("Created new key (pub %d, priv %d bytes)\n",
        newKey.pub.size, newKey.priv.size);

    /* Save key as encrypted blob to the disk */
#if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_FILESYSTEM)
    rc = writeKeyBlob(outputFile, &newKey);
#else
    printf("Key Public Blob %d\n", newKey.pub.size);
    TPM2_PrintBin((const byte*)&newKey.pub.publicArea, newKey.pub.size);
    printf("Key Private Blob %d\n", newKey.priv.size);
    TPM2_PrintBin(newKey.priv.buffer, newKey.priv.size);
#endif

exit:

    if (rc != 0) {
        printf("\nFailure 0x%x: %s\n\n", rc, wolfTPM2_GetRCString(rc));
    }

    /* Close handles */
    wolfTPM2_UnloadHandle(&dev, &storage.handle);
    wolfTPM2_UnloadHandle(&dev, &newKey.handle);
    wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);

    wolfTPM2_Cleanup(&dev);
    return rc;
}

/******************************************************************************/
/* --- END TPM Keygen Example -- */
/******************************************************************************/
#endif /* !WOLFTPM2_NO_WRAPPER */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = NOT_COMPILED_IN;

#ifndef WOLFTPM2_NO_WRAPPER
    rc = TPM2_Keygen_Example(NULL, argc, argv);
#else
    printf("KeyGen code not compiled in\n");
    (void)argc;
    (void)argv;
#endif

    return rc;
}
#endif
