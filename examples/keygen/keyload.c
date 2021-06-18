/* keyload.c
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
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


/* use ANSI stdio for support of format strings, must be set before
 * including stdio.h
 */
#if defined(__MINGW32__) || defined(__MINGW64__)
#define __USE_MINGW_ANSI_STDIO 1
#endif

#include <wolftpm/tpm2_wrap.h>

#include <examples/keygen/keygen.h>
#include <examples/tpm_io.h>
#include <examples/tpm_test.h>
#include <examples/tpm_test_keys.h>

#include <stdio.h>


#ifndef WOLFTPM2_NO_WRAPPER
/******************************************************************************/
/* --- BEGIN TPM Key Load Example -- */
/******************************************************************************/

static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/keygen/keyload [keyblob.bin] [-aes/xor] [-persistent] [-eh]\n");
    printf("* -eh: Key is from the Endorsement Hierarchy, requires EK\n");
    printf("* -aes/xor: Use Parameter Encryption\n");
    printf("* -persistent: Load the TPM key as persistent\n");
}

int TPM2_Keyload_Example(void* userCtx, int argc, char *argv[])
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY endorse; /* EK */
    WOLFTPM2_KEY storage; /* SRK */
    WOLFTPM2_KEY *primary = NULL;
    WOLFTPM2_KEYBLOB newKey;
    WOLFTPM2_KEY persistKey;
    TPM_ALG_ID paramEncAlg = TPM_ALG_NULL;
    WOLFTPM2_SESSION tpmSession;
    const char* inputFile = "keyblob.bin";
    int persistent = 0;
    int endorseKey = 0;

    if (argc >= 2) {
        if (XSTRNCMP(argv[1], "-?", 2) == 0 ||
            XSTRNCMP(argv[1], "-h", 2) == 0 ||
            XSTRNCMP(argv[1], "--help", 6) == 0) {
            usage();
            return 0;
        }

        if (argv[1][0] != '-') {
            inputFile = argv[1];
        }
        if (XSTRNCMP(argv[1], "-eh", 3) == 0) {
            endorseKey = 1;
        }
    }
    while (argc > 1) {
        if (XSTRNCMP(argv[argc-1], "-aes", 4) == 0) {
            paramEncAlg = TPM_ALG_CFB;
        }
        if (XSTRNCMP(argv[argc-1], "-xor", 4) == 0) {
            paramEncAlg = TPM_ALG_XOR;
        }
        if (XSTRNCMP(argv[argc-1], "-persistent", 11) == 0) {
            persistent = 1;
        }
        argc--;
    }

    XMEMSET(&endorse, 0, sizeof(endorse));
    XMEMSET(&storage, 0, sizeof(storage));
    XMEMSET(&newKey, 0, sizeof(newKey));
    XMEMSET(&persistKey, 0, sizeof(persistKey));
    XMEMSET(&tpmSession, 0, sizeof(tpmSession));

    printf("TPM2.0 Key load example\n");
    printf("\tKey Blob: %s\n", inputFile);
    printf("\tUse Parameter Encryption: %s\n", TPM2_GetAlgName(paramEncAlg));

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("\nwolfTPM2_Init failed\n");
        goto exit;
    }

    if (endorseKey) {
        rc = wolfTPM2_CreateEK(&dev, &endorse, TPM_ALG_RSA);
        if (rc != 0) goto exit;
        endorse.handle.policyAuth = 1;
        primary = &endorse;
    }
    else { /* SRK */
        rc = getPrimaryStoragekey(&dev, primary, TPM_ALG_RSA);
        if (rc != 0) goto exit;
        primary = &storage;
    }

    if (endorseKey) {
        /* Fresh policy session for EK auth */
        rc = wolfTPM2_CreateAuthSession_EkPolicy(&dev, &tpmSession);
        if (rc != 0) goto exit;
        /* Set the created Policy Session for use in next operation */
        rc = wolfTPM2_SetAuthSession(&dev, 0, &tpmSession, 0);
        if (rc != 0) goto exit;
    }

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

    /* Load encrypted key from the disk */
#if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_FILESYSTEM)
    rc = readKeyBlob(inputFile, &newKey);
    if (rc != 0) goto exit;
#else
    /* TODO: Option to load hex blob */
    printf("Loading blob from disk not supported. Enable wolfcrypt support.\n");
    goto exit;
#endif

    rc = wolfTPM2_LoadKey(&dev, &newKey, &primary->handle);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_LoadKey failed\n");
        goto exit;
    }
    printf("Loaded key to 0x%x\n",
        (word32)newKey.handle.hndl);

    /* Make the TPM key persistent, so it remains loaded after example exit */
    if (persistent) {
        /* Prepare key in the format expected by the wolfTPM wrapper */
        persistKey.handle.hndl = newKey.handle.hndl;
        XMEMCPY((BYTE*)&persistKey.pub, (BYTE*)&newKey.pub, sizeof(persistKey.pub));
        /* Make key persistent */
        rc = wolfTPM2_NVStoreKey(&dev, TPM_RH_OWNER, &persistKey,
                                    TPM2_DEMO_PERSISTENT_KEY_HANDLE);
        if (rc != TPM_RC_SUCCESS) {
            printf("wolfTPM2_NVStoreKey failed\n");
            goto exit;
        }
        printf("Key was made persistent at 0x%X\n", persistKey.handle.hndl);
    }

exit:

    if (rc != 0) {
        printf("\nFailure 0x%x: %s\n\n", rc, wolfTPM2_GetRCString(rc));
    }

    /* Close key handles */
    wolfTPM2_UnloadHandle(&dev, &primary->handle);
    /* newKey.handle is already flushed by wolfTPM2_NVStoreKey */
    if (!persistent) {
        wolfTPM2_UnloadHandle(&dev, &newKey.handle);
    }
    /* EK policy is destroyed after use, flush parameter encryption session */
    if (!endorseKey) {
        wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);
    }

    wolfTPM2_Cleanup(&dev);
    return rc;
}

/******************************************************************************/
/* --- END TPM Key Load Example -- */
/******************************************************************************/
#endif /* !WOLFTPM2_NO_WRAPPER */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = NOT_COMPILED_IN;

#ifndef WOLFTPM2_NO_WRAPPER
    rc = TPM2_Keyload_Example(NULL, argc, argv);
#else
    printf("KeyImport code not compiled in\n");
    (void)argc;
    (void)argv;
#endif

    return rc;
}
#endif
