/* activate_credential.c
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

/* This example shows how to decrypt a credential for Remote Attestation
 * and extract the secret for challenge response to an attestation server
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2_wrap.h>

#include <stdio.h>

#ifndef WOLFTPM2_NO_WRAPPER

#include <examples/attestation/attestation.h>
#include <hal/tpm_io.h>
#include <examples/tpm_test.h>
#include <examples/tpm_test_keys.h>


/******************************************************************************/
/* --- BEGIN TPM2.0 Activate Credential example tool  -- */
/******************************************************************************/

static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/attestation/activate_credential [cred.blob] [-eh]\n");
    printf("* cred.blob is a input file holding the generated credential.\n");
    printf("* -eh: Use the EK public key to encrypt the challenge\n");
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
#if !defined(NO_FILESYSTEM) && !defined(NO_WRITE_TEMP_FILES)
    FILE *fp;
    int dataSize = 0;
#endif
    const char *input = "cred.blob";
    const char *keyblob = "keyblob.bin";

    ActivateCredential_In  activCredIn;
    ActivateCredential_Out activCredOut;

    if (argc == 1) {
        printf("Using default values\n");
    }
    else if (argc == 2) {
        if (XSTRCMP(argv[1], "-?") == 0 ||
            XSTRCMP(argv[1], "-h") == 0 ||
            XSTRCMP(argv[1], "--help") == 0) {
            usage();
            return 0;
        }
        if (argv[1][0] != '-') {
            input = argv[1];
        }
        if (XSTRCMP(argv[1], "-eh") == 0) {
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
        rc = wolfTPM2_GetEK(&dev, &tpmSession, &endorse, TPM_ALG_RSA);
        if (rc != TPM_RC_SUCCESS) {
            printf("wolfTPM2_GetEK failed 0x%x: %s\n", rc,
                TPM2_GetRCString(rc));
            goto exit;
        }
        printf("EK loaded\n");

        primary = &endorse;
    }
    else {
        rc = getPrimaryStoragekey(&dev, &storage, TPM_ALG_RSA);
        if (rc != TPM_RC_SUCCESS) goto exit;
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
    if (rc != TPM_RC_SUCCESS) goto exit;

    if (endorseKey) {
        /* Fresh policy session for EK auth */
        rc = wolfTPM2_CreateAuthSession_EkPolicy(&dev, &tpmSession);
        if (rc != TPM_RC_SUCCESS) goto exit;
        /* Set the created Policy Session for use in next operation */
        rc = wolfTPM2_SetAuthSession(&dev, 1, &tpmSession, 0);
        if (rc != TPM_RC_SUCCESS) goto exit;
        /* Set the name for the endorsement handle */
        rc = wolfTPM2_SetAuthHandleName(&dev, 1, &endorse.handle);
        if (rc != TPM_RC_SUCCESS) goto exit;
    }
    else {
        rc = wolfTPM2_SetAuthHandle(&dev, 1, &storage.handle);
        if (rc != TPM_RC_SUCCESS) goto exit;
    }

    /* Prepare the auth password for the Attestation Key */
    akKey.handle.auth.size = sizeof(gAiKeyAuth)-1;
    XMEMCPY(akKey.handle.auth.buffer, gAiKeyAuth,
            akKey.handle.auth.size);
    wolfTPM2_SetAuthHandle(&dev, 0, &akKey.handle);

    /* Prepare the Activate Credential command */
    XMEMSET(&activCredIn, 0, sizeof(activCredIn));
    XMEMSET(&activCredOut, 0, sizeof(activCredOut));
    activCredIn.activateHandle = akKey.handle.hndl;
    activCredIn.keyHandle = primary->handle.hndl;
    /* Read credential from the user file */
#if !defined(NO_FILESYSTEM) && !defined(NO_WRITE_TEMP_FILES)
    fp = XFOPEN(input, "rb");
    if (fp != XBADFILE) {
        dataSize = (int)XFREAD((BYTE*)&activCredIn.credentialBlob, 1,
                                sizeof(activCredIn.credentialBlob), fp);
        if (dataSize > 0) {
            dataSize += (int)XFREAD((BYTE*)&activCredIn.secret, 1,
                                     sizeof(activCredIn.secret), fp);
        }
        XFCLOSE(fp);
    }
    printf("Read credential blob and secret from %s, %d bytes\n",
        input, dataSize);
#else
    printf("Can not load credential. File support not enabled\n");
    goto exit;
#endif
    /* All required data to verify the credential is prepared */
    rc = TPM2_ActivateCredential(&activCredIn, &activCredOut);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_ActivateCredential failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_ActivateCredential success\n");
    if (endorseKey) {
        /* The policy session is closed after use.
         * Reset handle, so we don't try and free it */
        tpmSession.handle.hndl = TPM_RH_NULL;
    }

    printf("Secret: %d\n", activCredOut.certInfo.size);
    TPM2_PrintBin(activCredOut.certInfo.buffer,
                  activCredOut.certInfo.size);

exit:

    wolfTPM2_UnloadHandle(&dev, &primary->handle);
    wolfTPM2_UnloadHandle(&dev, &akKey.handle);
    wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);
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
