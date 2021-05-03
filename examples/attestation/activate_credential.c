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
    printf("./examples/attestation/activate_credential [cred.blob]\n");
    printf("* cred.blob is a input file holding the generated credential.\n");
    printf("Demo usage without parameters, uses \"cred.blob\" filename.\n");
}

int TPM2_ActivateCredential_Example(void* userCtx, int argc, char *argv[])
{
    int rc = -1;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY storage;
    WOLFTPM2_KEYBLOB akKey;
    WOLFTPM2_SESSION tpmSession;
    FILE *fp;
    const char *input = "cred.blob";
    const char *keyblob = "keyblob.bin";
    int dataSize = 0;

    union {
        ActivateCredential_In activCred;
        PolicyCommandCode_In policyCommandCode;
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
    }
    else {
        printf("Incorrect arguments\n");
        usage();
        goto exit_badargs;
    }

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

    /* Load SRK, required to unwrap credential */
    rc = getPrimaryStoragekey(&dev, &storage, TPM_ALG_RSA);
    if (rc != 0) goto exit;
    printf("SRK loaded\n");
    /* Prepare the auth password for the Storage Key */
    storage.handle.auth.size = sizeof(gStorageKeyAuth)-1;
    XMEMCPY(storage.handle.auth.buffer, gStorageKeyAuth,
            storage.handle.auth.size);
    wolfTPM2_SetAuthHandle(&dev, 0, &storage.handle);

    /* Load AK, required to verify the Key Attributes in the credential */
    rc = readKeyBlob(keyblob, &akKey);
    if (rc != TPM_RC_SUCCESS) {
        printf("Failure to read keyblob.\n");
    }
    storage.handle.hndl = TPM2_DEMO_STORAGE_KEY_HANDLE;
    rc = wolfTPM2_LoadKey(&dev, &akKey, &storage.handle);
    if (rc != TPM_RC_SUCCESS) {
        printf("Failure to load the AK and read its Name.\n");
        goto exit;
    }
    printf("AK loaded at 0x%x\n", (word32)akKey.handle.hndl);
    /* Prepare the auth password for the Attestation Key */
    akKey.handle.auth.size = sizeof(gAiKeyAuth)-1;
    XMEMCPY(akKey.handle.auth.buffer, gAiKeyAuth,
            akKey.handle.auth.size);
    wolfTPM2_SetAuthHandle(&dev, 0, &akKey.handle);

    /* Start an authenticated session (salted / unbound) */
    rc = wolfTPM2_StartSession(&dev, &tpmSession, NULL, NULL,
        TPM_SE_POLICY, TPM_ALG_NULL);
    if (rc != 0) goto exit;
    printf("TPM2_StartAuthSession: sessionHandle 0x%x\n",
        (word32)tpmSession.handle.hndl);

    /* ADMIN role required for Activate Credential command */
    XMEMSET(&cmdIn.policyCommandCode, 0, sizeof(cmdIn.policyCommandCode));
    cmdIn.policyCommandCode.policySession = tpmSession.handle.hndl;
    cmdIn.policyCommandCode.code = TPM_CC_ActivateCredential;
    rc = TPM2_PolicyCommandCode(&cmdIn.policyCommandCode);
    if (rc != TPM_RC_SUCCESS) {
        printf("policyCommandCode failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_policyCommandCode success\n"); /* No command response payload */

    /* Prepare Key Auths in correct order for ActivateCredential */
    wolfTPM2_SetAuthHandle(&dev, 0, &akKey.handle);
    wolfTPM2_SetAuthHandle(&dev, 1, &storage.handle);

    /* Prepare the Activate Credential command */
    XMEMSET(&cmdIn.activCred, 0, sizeof(cmdIn.activCred));
    XMEMSET(&cmdOut.activCred, 0, sizeof(cmdOut.activCred));
    cmdIn.activCred.activateHandle = akKey.handle.hndl;
    cmdIn.activCred.keyHandle = TPM2_DEMO_STORAGE_KEY_HANDLE;
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

    wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);
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
