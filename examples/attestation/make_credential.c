/* make_credential.c
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

/* This example shows how to create a challenge for Remote Attestation */

#include <wolftpm/tpm2_wrap.h>

#ifndef WOLFTPM2_NO_WRAPPER

#include <examples/attestation/credential.h>
#include <examples/tpm_io.h>
#include <examples/tpm_test.h>
#include <examples/tpm_test_keys.h>

#include <stdio.h>


/******************************************************************************/
/* --- BEGIN TPM2.0 Make Credential example tool  -- */
/******************************************************************************/

static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/attestation/make_credential [cred.blob]\n");
    printf("* cred.blob is a output file holding the generated credential.\n");
    printf("Demo usage without parameters, uses \"cred.blob\" filename.\n");
}

int TPM2_MakeCredential_Example(void* userCtx, int argc, char *argv[])
{
    int rc = -1;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY storage;
    WOLFTPM2_KEYBLOB akKey;
    FILE *fp;
    const char *output = "cred.blob";
    const char *keyblob = "keyblob.bin";
    int dataSize = 0;

    union {
        MakeCredential_In makeCred;
        byte maxInput[MAX_COMMAND_SIZE];
    } cmdIn;
    union {
        MakeCredential_Out makeCred;
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
            output = argv[1];
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

    printf("Credential will be stored in %s\n", output);

    /* Prepare the auth password for the storage key */
    storage.handle.auth.size = sizeof(gStorageKeyAuth)-1;
    XMEMCPY(storage.handle.auth.buffer, gStorageKeyAuth,
            storage.handle.auth.size);
    wolfTPM2_SetAuthPassword(&dev, 0, &storage.handle.auth);

    /* Prepare the Make Credential command */
    XMEMSET(&cmdIn.makeCred, 0, sizeof(cmdIn.makeCred));
    XMEMSET(&cmdOut.makeCred, 0, sizeof(cmdOut.makeCred));
    cmdIn.makeCred.handle = TPM2_DEMO_STORAGE_KEY_HANDLE;
    /* Create secret for the attestation server - a symmetric key seed */
    cmdIn.makeCred.credential.size = CRED_SECRET_SIZE;
    wolfTPM2_GetRandom(&dev, cmdIn.makeCred.credential.buffer,
                        cmdIn.makeCred.credential.size);
    /* Acquire the Name of the Attestation Key */
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
    /* Copy the AK name into the command request */
    cmdIn.makeCred.objectName.size = akKey.handle.name.size;
    XMEMCPY(cmdIn.makeCred.objectName.name, akKey.handle.name.name,
                cmdIn.makeCred.objectName.size);
    /* All required data for a credential is prepared */
    rc = TPM2_MakeCredential(&cmdIn.makeCred, &cmdOut.makeCred);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_MakeCredentials failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_MakeCredential success\n");

#if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_FILESYSTEM)
    fp = XFOPEN(output, "wb");
    if (fp != XBADFILE) {
        dataSize = (int)XFWRITE((BYTE*)&cmdOut.makeCred.credentialBlob, 1,
                                sizeof(cmdOut.makeCred.credentialBlob), fp);
        dataSize = (int)XFWRITE((BYTE*)&cmdOut.makeCred.secret, 1,
                                sizeof(cmdOut.makeCred.secret), fp);
        XFCLOSE(fp);
    }
    printf("Wrote credential blob and secret to %s, %d bytes\n", output, dataSize);
#else
    printf("Can not store credential. File support not enabled\n");
#endif

exit:

    wolfTPM2_UnloadHandle(&dev, &akKey.handle);
    wolfTPM2_Cleanup(&dev);

exit_badargs:

    return rc;
}

/******************************************************************************/
/* --- END TPM2.0 Make Credential example tool -- */
/******************************************************************************/
#endif /* !WOLFTPM2_NO_WRAPPER */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = -1;

#ifndef WOLFTPM2_NO_WRAPPER
    rc = TPM2_MakeCredential_Example(NULL, argc, argv);
#else
    printf("Wrapper code not compiled in\n");
    (void)argc;
    (void)argv;
#endif /* !WOLFTPM2_NO_WRAPPER */

    return rc;
}
#endif
