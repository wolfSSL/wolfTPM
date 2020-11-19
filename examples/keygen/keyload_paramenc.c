/* keyload_paramenc.c
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
/* --- BEGIN TPM Key Load Example -- */
/******************************************************************************/

int TPM2_Keyload_ParamEnc_Example(void* userCtx, int argc, char *argv[])
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY storage; /* SRK */
    WOLFTPM2_KEYBLOB newKey;
    TPMS_AUTH_COMMAND session[MAX_SESSION_NUM];
    WOLFTPM2_SESSION tpmSession;
    WOLFTPM2_HANDLE bind;
#if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_FILESYSTEM)
    XFILE f;
    const char* inputFile = "keyblob.bin";

    if (argc >= 2) {
        inputFile = argv[1];
    }
#else
    (void)argc;
    (void)argv;
#endif

    XMEMSET(session, 0, sizeof(session));
    XMEMSET(&storage, 0, sizeof(storage));
    XMEMSET(&newKey, 0, sizeof(newKey));

    printf("TPM2.0 Key load example\n");
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

    /* Start salted TPM session */
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
    session[1].nonce.size = TPM_SHA256_DIGEST_SIZE;
    /* Fresh nonce creation is handled by the wolfTPM stack */

    /* Load encrypted key from the disk */
#if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_FILESYSTEM)
    f = XFOPEN(inputFile, "rb");
    if (f != XBADFILE) {
        size_t fileSz;
        XFSEEK(f, 0, XSEEK_END);
        fileSz = XFTELL(f);
        XREWIND(f);
        if (fileSz > sizeof(newKey.priv) + sizeof(newKey.pub)) {
            printf("File size check failed\n");
            rc = BUFFER_E; goto exit;
        }
        printf("Reading %d bytes from %s\n", (int)fileSz, inputFile);

        XFREAD(&newKey.pub, 1, sizeof(newKey.pub), f);
        if (fileSz > sizeof(newKey.pub)) {
            fileSz -= sizeof(newKey.pub);
            XFREAD(&newKey.priv, 1, fileSz, f);
        }
        XFCLOSE(f);

        /* sanity check the sizes */
        if (newKey.pub.size != sizeof(newKey.pub) || newKey.priv.size > sizeof(newKey.priv.buffer)) {
            printf("Struct size check failed (pub %d, priv %d)\n", newKey.pub.size, newKey.priv.size);
            rc = BUFFER_E; goto exit;
        }
    }
    else {
        rc = BUFFER_E;
        printf("File %s not found!\n", inputFile);
        goto exit;
    }
#else
    /* TODO: Option to load hex blob */
    printf("Loading blob from disk not supported\n");
#endif

    rc = wolfTPM2_LoadKey(&dev, &newKey, &storage.handle);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_LoadKey failed\n");
        goto exit;
    }
    printf("Loaded key to 0x%x\n",
        (word32)newKey.handle.hndl);

exit:

    if (rc != 0) {
        printf("\nFailure 0x%x: %s\n\n", rc, wolfTPM2_GetRCString(rc));
    }

    /* Close session */
    if (tpmSession.handle.hndl != TPM_RH_NULL) {
        wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);
    }

    /* Close key handles */
    wolfTPM2_UnloadHandle(&dev, &newKey.handle);
    wolfTPM2_UnloadHandle(&dev, &storage.handle);

    wolfTPM2_Cleanup(&dev);
    return rc;
}

/******************************************************************************/
/* --- END TPM Timestamp Test -- */
/******************************************************************************/


#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc;

    rc = TPM2_Keyload_ParamEnc_Example(NULL, argc, argv);

    return rc;
}
#endif
