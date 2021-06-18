/* activate_credential.c
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

/* This example shows how to decrypt a credential for Remote Attestation
 * and extract the secret for challenge response to an attestation server
 */

#include <wolftpm/tpm2_wrap.h>

#ifndef WOLFTPM2_NO_WRAPPER

#include <examples/attestation/credential.h>
#include <examples/tpm_io.h>
#include <examples/tpm_test.h>
#include <examples/tpm_test_keys.h>

#include <stdio.h>


/******************************************************************************/
/* --- BEGIN TPM2.0 Activate Credential example tool  -- */
/******************************************************************************/

static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/attestation/activate_credential [cred.blob] [-eh]\n");
    printf("* cred.blob is a input file holding the generated credential.\n");
    printf("Demo usage without parameters, uses \"cred.blob\" filename.\n");
}

int TPM2_ActivateCredential_Example(void* userCtx, int argc, char *argv[])
{
    int rc = -1;
    int endorseKey = 0;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY endorse;
    WOLFTPM2_KEY storage;
    WOLFTPM2_KEY *primary = NULL;
    WOLFTPM2_KEYBLOB akKey;
    WOLFTPM2_SESSION tpmSession;
#if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_FILESYSTEM)
    FILE *fp;
    int dataSize = 0;
#endif
    const char *input = "cred.blob";
    const char *keyblob = "keyblob.bin";

    union {
        ActivateCredential_In activCred;
        byte maxInput[MAX_COMMAND_SIZE];
    } cmdIn;
    union {
        ActivateCredential_Out activCred;
        byte maxOutput[MAX_RESPONSE_SIZE];
    } cmdOut;

    if (argc == 1) {
        printf("Using default values\n");
    }
    else if (argc == 2) {
        if (XSTRNCMP(argv[1], "-?", 2) == 0 ||
            XSTRNCMP(argv[1], "-h", 2) == 0 ||
            XSTRNCMP(argv[1], "--help", 6) == 0) {
            usage();
            return 0;
        }
        if (argv[1][0] != '-') {
            input = argv[1];
        }
        if (XSTRNCMP(argv[1], "-eh", 3) == 0) {
            printf("Use Endorsement Key\n");
            endorseKey = 1;
        }
    }
    else {
        printf("Incorrect arguments\n");
        usage();
        goto exit_badargs;
    }

    XMEMSET(&endorse, 0, sizeof(endorse));
    XMEMSET(&storage, 0, sizeof(storage));
    XMEMSET(&akKey, 0, sizeof(akKey));

    printf("Demo how to create a credential blob for remote attestation\n");
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_Init failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    printf("wolfTPM2_Init: success\n");

    printf("Credential will be read from %s\n", input);

    /* Load key, required to unwrap credential */
    if (endorseKey) {
        rc = wolfTPM2_CreateEK(&dev, &endorse, TPM_ALG_RSA);
        if (rc != 0) goto exit;
        printf("EK loaded\n");
        /* Endorsement Key requires authorization with Policy */
        endorse.handle.policyAuth = 1;
        rc = wolfTPM2_CreateAuthSession_EkPolicy(&dev, &tpmSession);
        if (rc != 0) goto exit;
        /* Set the created Policy Session for use in next operation */
        rc = wolfTPM2_SetAuthSession(&dev, 0, &tpmSession, 0);
        if (rc != 0) goto exit;

        primary = &endorse;
    }
    else {
        rc = getPrimaryStoragekey(&dev, &storage, TPM_ALG_RSA);
        if (rc != 0) goto exit;
        printf("SRK loaded\n");
        wolfTPM2_SetAuthHandle(&dev, 0, &storage.handle);

        primary = &storage;
    }

    /* Load AK, required to verify the Key Attributes in the credential */
    rc = readKeyBlob(keyblob, &akKey);
    if (rc != TPM_RC_SUCCESS) {
        printf("Failure to read keyblob.\n");
    }
    rc = wolfTPM2_LoadKey(&dev, &akKey, &primary->handle);
    if (rc != TPM_RC_SUCCESS) {
        printf("Failure to load the AK and read its Name.\n");
        goto exit;
    }
    printf("AK loaded at 0x%x\n", (word32)akKey.handle.hndl);

    rc = wolfTPM2_UnsetAuth(&dev, 0);

    if (endorseKey) {
        /* Fresh policy session for EK auth */
        rc = wolfTPM2_CreateAuthSession_EkPolicy(&dev, &tpmSession);
        if (rc != 0) goto exit;
        /* Set the created Policy Session for use in next operation */
        rc = wolfTPM2_SetAuthSession(&dev, 1, &tpmSession, 0);
        if (rc != 0) goto exit;
    }
    else {
        wolfTPM2_SetAuthHandle(&dev, 1, &storage.handle);
    }

    /* Prepare the auth password for the Attestation Key */
    akKey.handle.auth.size = sizeof(gAiKeyAuth)-1;
    XMEMCPY(akKey.handle.auth.buffer, gAiKeyAuth,
            akKey.handle.auth.size);
    wolfTPM2_SetAuthHandle(&dev, 0, &akKey.handle);

    /* Prepare the Activate Credential command */
    XMEMSET(&cmdIn.activCred, 0, sizeof(cmdIn.activCred));
    XMEMSET(&cmdOut.activCred, 0, sizeof(cmdOut.activCred));
    cmdIn.activCred.activateHandle = akKey.handle.hndl;
    cmdIn.activCred.keyHandle = primary->handle.hndl;
    /* Read credential from the user file */
#if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_FILESYSTEM)
    fp = XFOPEN(input, "rb");
    if (fp != XBADFILE) {
        dataSize = (int)XFREAD((BYTE*)&cmdIn.activCred.credentialBlob, 1,
                                sizeof(cmdIn.activCred.credentialBlob), fp);
        dataSize = (int)XFREAD((BYTE*)&cmdIn.activCred.secret, 1,
                                sizeof(cmdIn.activCred.secret), fp);
        XFCLOSE(fp);
    }
    printf("Read credential blob and secret from %s, %d bytes\n", input, dataSize);
#else
    printf("Can not load credential. File support not enabled\n");
    goto exit;
#endif
    /* All required data to verify the credential is prepared */
    rc = TPM2_ActivateCredential(&cmdIn.activCred, &cmdOut.activCred);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_ActivateCredentials failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_ActivateCredential success\n");

exit:

    wolfTPM2_UnloadHandle(&dev, &primary->handle);
    wolfTPM2_UnloadHandle(&dev, &akKey.handle);
    wolfTPM2_Cleanup(&dev);

exit_badargs:

    return rc;
}

/******************************************************************************/
/* --- END TPM2.0 Activate Credential example tool -- */
/******************************************************************************/
#endif /* !WOLFTPM2_NO_WRAPPER */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = -1;

#ifndef WOLFTPM2_NO_WRAPPER
    rc = TPM2_ActivateCredential_Example(NULL, argc, argv);
#else
    printf("Wrapper code not compiled in\n");
    (void)argc;
    (void)argv;
#endif /* !WOLFTPM2_NO_WRAPPER */

    return rc;
}
#endif
