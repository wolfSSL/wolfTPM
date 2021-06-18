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
    printf("./examples/attestation/make_credential [-eh]\n");
    printf("* -eh: Use the EK public key to encrypt the challenge\n");
    printf("Notes:\n");
    printf("\tName digest is loaded from \"ak.name\" file\n");
    printf("\tPublic key is loaded from a file containing TPM2B_PUBLIC\n");
    printf("\t\"tek.pub\" for EK pub");
    printf("\t\"tsrk.pub\" for SRK pub");
    printf("\tOutput is stored in \"cred.blob\"\n");
    printf("Demo usage without parameters, uses SRK pub\n");
}

int TPM2_MakeCredential_Example(void* userCtx, int argc, char *argv[])
{
    int rc = -1;
    int endorseKey = 0;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEYBLOB primary;
    WOLFTPM2_HANDLE handle;
    TPM2B_NAME name;
#if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_FILESYSTEM)
    FILE *fp;
    int dataSize = 0;
#endif
    const char *output = "cred.blob";
    const char *ekPubFile = "ek.pub";
    const char *srkPubFile = "srk.pub";
    const char *pubFilename = NULL;

    union {
        MakeCredential_In makeCred;
        LoadExternal_In  loadExtIn;
        byte maxInput[MAX_COMMAND_SIZE];
    } cmdIn;
    union {
        MakeCredential_Out makeCred;
        LoadExternal_Out loadExtOut;
        byte maxOutput[MAX_RESPONSE_SIZE];
    } cmdOut;

    if (argc == 1) {
        printf("Using public key from SRK to create the challenge\n");
    }
    else if (argc == 2) {
        if (XSTRNCMP(argv[1], "-?", 2) == 0 ||
            XSTRNCMP(argv[1], "-h", 2) == 0 ||
            XSTRNCMP(argv[1], "--help", 6) == 0) {
            usage();
            return 0;
        }
        if (XSTRNCMP(argv[1], "-eh", 3) == 0) {
            printf("Using keys under the Endorsement Hierarchy\n");
            endorseKey = 1;
        }
    }
    else {
        printf("Incorrect arguments\n");
        usage();
        goto exit_badargs;
    }

    XMEMSET(&name, 0, sizeof(name));
    XMEMSET(&cmdIn.makeCred, 0, sizeof(cmdIn.makeCred));
    XMEMSET(&cmdOut.makeCred, 0, sizeof(cmdOut.makeCred));
    XMEMSET(&cmdIn.loadExtIn, 0, sizeof(cmdIn.loadExtIn));
    XMEMSET(&cmdOut.loadExtOut, 0, sizeof(cmdOut.loadExtOut));

    printf("Demo how to create a credential challenge for remote attestation\n");
    printf("Credential will be stored in %s\n", output);

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
         printf("wolfTPM2_Init failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    printf("wolfTPM2_Init: success\n");

    /* Load encrypting public key from disk */
    if (endorseKey) {
        pubFilename = ekPubFile;
    }
    else {
        pubFilename = srkPubFile;
    }
    rc = readKeyBlob(pubFilename, &primary);
    if (rc != 0) {
        printf("Failure to load %s\n", pubFilename);
        goto exit;
    }
    /* Prepare the key for use by the TPM */
    XMEMCPY(&cmdIn.loadExtIn.inPublic, &primary.pub, sizeof(cmdIn.loadExtIn.inPublic));
    cmdIn.loadExtIn.hierarchy = TPM_RH_NULL;
    rc = TPM2_LoadExternal(&cmdIn.loadExtIn, &cmdOut.loadExtOut);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_LoadExternal: failed %d: %s\n", rc,
            wolfTPM2_GetRCString(rc));
        return rc;
    }
    printf("Public key for encryption loaded\n");
    handle.hndl = cmdOut.loadExtOut.objectHandle;

    /* Load AK Name digest */
    fp = XFOPEN("ak.name", "rb");
    if (fp != XBADFILE) {
        XFREAD((BYTE*)&name, 1, sizeof(name), fp);
        printf("Read AK Name digest\n");
        XFCLOSE(fp);
    }

    /* Create secret for the attestation server */
    cmdIn.makeCred.credential.size = CRED_SECRET_SIZE;
    wolfTPM2_GetRandom(&dev, cmdIn.makeCred.credential.buffer,
                        cmdIn.makeCred.credential.size);
    /* Prepare the AK name */
    cmdIn.makeCred.objectName.size = name.size;
    XMEMCPY(cmdIn.makeCred.objectName.name, name.name,
                cmdIn.makeCred.objectName.size);
    /* Set TPM key and execute */
    cmdIn.makeCred.handle = handle.hndl;
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

    wolfTPM2_UnloadHandle(&dev, &handle);
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
