/* make_credential.c
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/* This example shows how to create a challenge for Remote Attestation */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2_wrap.h>

#ifndef WOLFTPM2_NO_WRAPPER

#include <examples/attestation/credential.h>
#include <hal/tpm_io.h>
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
#if !defined(NO_FILESYSTEM) && !defined(NO_WRITE_TEMP_FILES)
    FILE *fp;
    int dataSize = 0;
#endif
    const char *output = "cred.blob";
    const char *ekPubFile = "ek.pub";
    const char *srkPubFile = "srk.pub";
    const char *pubFilename = NULL;

    MakeCredential_In  makeCredIn;
    MakeCredential_Out makeCredOut;
    LoadExternal_In  loadExtIn;
    LoadExternal_Out loadExtOut;

    if (argc == 1) {
        printf("Using public key from SRK to create the challenge\n");
    }
    else if (argc == 2) {
        if (XSTRCMP(argv[1], "-?") == 0 ||
            XSTRCMP(argv[1], "-h") == 0 ||
            XSTRCMP(argv[1], "--help") == 0) {
            usage();
            return 0;
        }
        if (XSTRCMP(argv[1], "-eh") == 0) {
            printf("Using keys under the Endorsement Hierarchy\n");
            endorseKey = 1;
        }
    }
    else {
        printf("Incorrect arguments\n");
        usage();
        goto exit_badargs;
    }

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
        printf("Failure to read %s\n", pubFilename);
        goto exit;
    }

    /* Prepare the key for use by the TPM */
    XMEMSET(&loadExtIn, 0, sizeof(loadExtIn));
    XMEMSET(&loadExtOut, 0, sizeof(loadExtOut));
    XMEMCPY(&loadExtIn.inPublic, &primary.pub, sizeof(loadExtIn.inPublic));
    loadExtIn.hierarchy = TPM_RH_NULL;
    rc = TPM2_LoadExternal(&loadExtIn, &loadExtOut);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_LoadExternal: failed %d: %s\n", rc,
            wolfTPM2_GetRCString(rc));
        return rc;
    }
    printf("Public key for encryption loaded\n");
    handle.hndl = loadExtOut.objectHandle;
#if !defined(NO_FILESYSTEM) && !defined(NO_WRITE_TEMP_FILES)
    /* Load AK Name digest */
    XMEMSET(&name, 0, sizeof(name));
    fp = XFOPEN("ak.name", "rb");
    if (fp != XBADFILE) {
        size_t nameReadSz = XFREAD((BYTE*)&name, 1, sizeof(name), fp);
        printf("Read AK Name digest %s\n",
            nameReadSz == sizeof(name) ? "success" : "failed");
        XFCLOSE(fp);
    }
#endif

    /* Create secret for the attestation server */
    XMEMSET(&makeCredIn, 0, sizeof(makeCredIn));
    XMEMSET(&makeCredOut, 0, sizeof(makeCredOut));
    makeCredIn.credential.size = CRED_SECRET_SIZE;
    wolfTPM2_GetRandom(&dev, makeCredIn.credential.buffer,
                             makeCredIn.credential.size);
    /* Set the object name */
    makeCredIn.objectName.size = name.size;
    XMEMCPY(makeCredIn.objectName.name, name.name,
            makeCredIn.objectName.size);
    /* Set TPM key and execute */
    makeCredIn.handle = handle.hndl;
    rc = TPM2_MakeCredential(&makeCredIn, &makeCredOut);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_MakeCredential failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_MakeCredential success\n");

    printf("Secret: %d\n", makeCredIn.credential.size);
    TPM2_PrintBin(makeCredIn.credential.buffer,
                  makeCredIn.credential.size);

#if !defined(NO_FILESYSTEM) && !defined(NO_WRITE_TEMP_FILES)
    fp = XFOPEN(output, "wb");
    if (fp != XBADFILE) {
        dataSize = (int)XFWRITE((BYTE*)&makeCredOut.credentialBlob, 1,
                                 sizeof(makeCredOut.credentialBlob), fp);
        if (dataSize > 0) {
            dataSize += (int)XFWRITE((BYTE*)&makeCredOut.secret, 1,
                                      sizeof(makeCredOut.secret), fp);
        }
        XFCLOSE(fp);
    }
    printf("Wrote credential blob and secret to %s, %d bytes\n",
        output, dataSize);
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
