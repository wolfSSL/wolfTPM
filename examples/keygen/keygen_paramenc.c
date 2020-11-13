/* keygen_paramenc.c
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

#include <stdio.h>


/******************************************************************************/
/* --- BEGIN TPM Keygen w/Parameter Encryption Example -- */
/******************************************************************************/

static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/pcr/keygen_paramenc [outputFile]\n");
    printf("* outputFile - points to file(data) to measure\n");
    printf("Demo usage without parameters, generates a new key" \
           "and makes it persistent.\n");
}

int TPM2_Keygen_ParamEnc_Example(void* userCtx, int argc, char *argv[])
{
    int rc = -1;
    int storeKey = 0;
    const char *outputFile = NULL;
    XFILE keyFile;
    int fileSz = 0;
    /* TPM ops related variables */
    WOLFTPM2_DEV dev;
    TPMS_AUTH_COMMAND session[MAX_SESSION_NUM];
    WOLFTPM2_KEY storage; /* SRK */
    WOLFTPM2_KEYBLOB rsaKey; /* AIK */
    WOLFTPM2_SESSION tpmSession;
    WOLFTPM2_HANDLE bind;
    TPMT_PUBLIC publicTemplate;
    TPM_ALG_ID alg = TPM_ALG_RSA;

    XMEMSET(session, 0, sizeof(session));
    XMEMSET(&storage, 0, sizeof(storage));
    XMEMSET(&rsaKey, 0, sizeof(rsaKey));
    XMEMSET(&tpmSession, 0, sizeof(tpmSession));
    XMEMSET(&bind, 0, sizeof(bind));

    if (argc >= 2) {
        outputFile = argv[1];
        storeKey=1;
        if (argc >= 3) {
            /* ECC vs RSA */
            if (XSTRNCMP(argv[2], "ECC", 3) == 0) {
                alg = TPM_ALG_ECC;
            }
        }
    }
    else if (argc == 1) {
        printf("Will create a new TPM key and make it persistent\n" \
               "Will not store the new key to disk\n");
    }
    else {
        printf("Incorrect arguments\n");
        usage();
        goto exit_badargs;
    }

    printf("TPM2.0 Key generation example with parameter encryption\n");
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("\nwolfTPM2_Init failed\n");
        goto exit;
    }
    printf("wolfTPM2_Init: success\n\n");


    /* Define the default session auth that has NULL password */
    session[0].sessionHandle = TPM_RS_PW;
    session[0].auth.size = 0;
    TPM2_SetSessionAuth(session);


    /* See if SRK already exists */
    rc = wolfTPM2_ReadPublicKey(&dev, &storage, TPM2_DEMO_STORAGE_KEY_HANDLE);
    if (rc != 0) {
        printf("Loading SRK: Storage failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    printf("Loading SRK: Storage 0x%x (%d bytes)\n",
        (word32)storage.handle.hndl, storage.pub.size);

    bind.hndl = TPM_RH_NULL;
    rc = wolfTPM2_StartSession(&dev, &tpmSession, &storage, &bind,
        TPM_SE_POLICY, TPM_ALG_CFB);
    if (rc != 0) {
        goto exit;
    }
    printf("TPM2_StartAuthSession: sessionHandle 0x%x\n",
        (word32)tpmSession.handle.hndl);


    /* set session for authorization of the storage key */
    session[0].auth.size = sizeof(gStorageKeyAuth)-1;
    XMEMCPY(session[0].auth.buffer, gStorageKeyAuth, session[0].auth.size);

    /* set session for XOR parameter encryption of the TPM Command */
    session[1].sessionHandle = tpmSession.handle.hndl;
    session[1].sessionAttributes = TPMA_SESSION_decrypt | TPMA_SESSION_continueSession;
#if 1
    session[1].symmetric.algorithm = TPM_ALG_XOR;
    session[1].symmetric.keyBits.xorr = TPM_ALG_SHA256;
#else
    session[1].symmetric.algorithm = TPM_ALG_CFB;
    session[1].symmetric.keyBits.aes = 128;
#endif
    session[1].authHash = TPM_ALG_SHA256;
    session[1].nonceCaller.size = TPM_SHA256_DIGEST_SIZE;
    rc = TPM2_GetNonce(session[1].nonceCaller.buffer,
                       session[1].nonceCaller.size);
    if (rc < 0) {
        printf("TPM2_GetNonce failed\n");
        goto exit;
    }
    session[1].nonceTPM.size = session[1].nonceCaller.size;
    XMEMCPY(session[1].nonceTPM.buffer, tpmSession.nonceTPM.buffer,
            session[1].nonceTPM.size);

    /* Create new key */
    if (alg == TPM_ALG_RSA) {
        rc = wolfTPM2_GetKeyTemplate_RSA_AIK(&publicTemplate);
    }
    else if (alg == TPM_ALG_ECC) {
        rc = wolfTPM2_GetKeyTemplate_ECC_AIK(&publicTemplate);
    }
    else {
        rc = BAD_FUNC_ARG;
        goto exit;
    }

    /* Create an Attestation Key */
    printf("Creating new %s key...\n", TPM2_GetAlgName(alg));
    rc = wolfTPM2_CreateKey(&dev, &rsaKey, &storage.handle,
        &publicTemplate, (const byte*)gAiKeyAuth, sizeof(gAiKeyAuth)-1);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_CreateKey failed\n");
       goto exit;
    }
    printf("Created new key (pub %d, priv %d bytes)\n",
           (word32)rsaKey.handle.hndl, rsaKey.pub.size);

    /* Store to disk or make persistent */
    if(storeKey) {
 #if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_FILESYSTEM)
        printf("Storing key as file = %s\n", outputFile);
        keyFile = XFOPEN(outputFile, "wb");
        if (keyFile != XBADFILE) {
            rsaKey.pub.size = sizeof(rsaKey.pub);
            fileSz += XFWRITE(&rsaKey.pub, 1, sizeof(rsaKey.pub), keyFile);
            fileSz += XFWRITE(&rsaKey.priv, 1, sizeof(UINT16) + rsaKey.priv.size, keyFile);
            XFCLOSE(keyFile);
        }
        printf("Wrote %d bytes to %s\n", (int)fileSz, outputFile);
#else
        printf("Lack of support for wolfCrypt and Filesystem\n");
#endif
    }
    else {
        printf("Making the key from transient TPM object to persistent\n");
        /* wolfTPM2_NVStoreKey */
        rc = wolfTPM2_NVStoreKey(&dev, TPM_RH_OWNER, &storage,
                             TPM2_DEMO_STORAGE_KEY_HANDLE);
        if (rc != 0) {
            wolfTPM2_UnloadHandle(&dev, &storage.handle);
            goto exit;
        }
    }

exit:

    if (rc != 0) {
        printf("\nFailure 0x%x: %s\n\n", rc, wolfTPM2_GetRCString(rc));
    }

    /* Close session */
    if (tpmSession.handle.hndl != TPM_RH_NULL) {
        wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);
    }

    /* Close key handles */
    wolfTPM2_UnloadHandle(&dev, &rsaKey.handle);
    wolfTPM2_Cleanup(&dev);

exit_badargs:

    return rc;
}

/******************************************************************************/
/* --- END TPM Timestamp Test -- */
/******************************************************************************/


#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc;

    rc = TPM2_Keygen_ParamEnc_Example(NULL, argc, argv);

    return rc;
}
#endif
