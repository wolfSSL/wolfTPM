/* seal.c
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

/* Example for TPM 2.0 sealing a user secret using TPM key */

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
/* --- BEGIN TPM2.0 Seal Example -- */
/******************************************************************************/
static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/seal/seal [filename] [userdata]\n");
    printf("* -aes/xor: Use Parameter Encryption\n");
    printf("* filename: Name of the file where the TPM key will be stored (default: keyblob.bin)\n");
    printf("* userdata: Arbitrary data to seal inside the TPM key (no whitespaces) (default: My1Pass2Phrase3)\n");
}

int TPM2_Seal_Example(void* userCtx, int argc, char *argv[])
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY storage; /* SRK */
    WOLFTPM2_KEYBLOB newKey;
    TPMT_PUBLIC publicTemplate;
    TPM_ALG_ID paramEncAlg = TPM_ALG_NULL;
    WOLFTPM2_SESSION tpmSession;
    TPM2B_AUTH auth;
    const char* outputFile = "keyblob.bin";
    char defaultData[] = "My1Pass2Phrase3";
    char *userData = defaultData;

    if (argc >= 2) {
        if (XSTRCMP(argv[1], "-?") == 0 ||
            XSTRCMP(argv[1], "-h") == 0 ||
            XSTRCMP(argv[1], "--help") == 0) {
            usage();
            return 0;
        }
        if (argv[1][0] != '-') {
            outputFile = argv[1];
        }
    }
    if (argc >= 3) {
        if (argv[2][0] != '-') {
            userData = argv[2];
        }
    }
    while (argc > 1) {
        if (XSTRCMP(argv[argc-1], "-aes") == 0) {
            paramEncAlg = TPM_ALG_CFB;
        }
        else if (XSTRCMP(argv[argc-1], "-xor") == 0) {
            paramEncAlg = TPM_ALG_XOR;
        }
        else if (argv[argc-1][0] == '-') {
            printf("Warning: Unrecognized option: %s\n", argv[argc-1]);
        }
        argc--;
    }

    XMEMSET(&storage, 0, sizeof(storage));
    XMEMSET(&newKey, 0, sizeof(newKey));
    XMEMSET(&tpmSession, 0, sizeof(tpmSession));
    XMEMSET(&auth, 0, sizeof(auth));

    printf("TPM2.0 Simple Seal example\n");
    printf("\tKey Blob: %s\n", outputFile);
    printf("\tUser Data: %s\n", userData);
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

    wolfTPM2_GetKeyTemplate_KeySeal(&publicTemplate, TPM_ALG_SHA256);
    /* Allow password based unsealing */
    publicTemplate.objectAttributes |= TPMA_OBJECT_userWithAuth;

    /* set session for authorization key */
    auth.size = (int)sizeof(gKeyAuth)-1;
    XMEMCPY(auth.buffer, gKeyAuth, auth.size);

    printf("Sealing the user secret into a new TPM key\n");
    rc = wolfTPM2_CreateKeySeal(&dev, &newKey, &storage.handle,
                                &publicTemplate, auth.buffer, auth.size,
                                (BYTE*)userData, (int)strlen(userData));
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_CreateKey failed\n");
        goto exit;
    }
    printf("Created new TPM seal key (pub %d, priv %d bytes)\n",
        newKey.pub.size, newKey.priv.size);

    /* Save key as encrypted blob to the disk */
#if !defined(NO_FILESYSTEM) && !defined(NO_WRITE_TEMP_FILES)
    rc = writeKeyBlob(outputFile, &newKey);
#else
    printf("Storing key seal to file is not supported.\n");
#endif

#ifdef DEBUG_WOLFTPM
    printf("Key Seal, Public Blob %d\n", newKey.pub.size);
    TPM2_PrintBin((const byte*)&newKey.pub.publicArea, newKey.pub.size);
    printf("Key Seal, Private Blob %d\n", newKey.priv.size);
    TPM2_PrintBin(newKey.priv.buffer, newKey.priv.size);
#endif

exit:

    if (rc != 0) {
        printf("\nFailure 0x%x: %s\n\n", rc, wolfTPM2_GetRCString(rc));
    }

    /* Remove the auth for loaded TPM seal object */
    wolfTPM2_UnsetAuth(&dev, 0);

    /* Close handles */
    wolfTPM2_UnloadHandle(&dev, &storage.handle);
    wolfTPM2_UnloadHandle(&dev, &newKey.handle);
    wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);

    wolfTPM2_Cleanup(&dev);
    return rc;
}

/******************************************************************************/
/* --- END TPM2.0 Seal Example -- */
/******************************************************************************/
#endif /* !WOLFTPM2_NO_WRAPPER */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = NOT_COMPILED_IN;

#ifndef WOLFTPM2_NO_WRAPPER
    rc = TPM2_Seal_Example(NULL, argc, argv);
#else
    printf("KeyGen code not compiled in\n");
    (void)argc;
    (void)argv;
#endif

    return rc;
}
#endif
