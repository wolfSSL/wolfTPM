/* keygen.c
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
/* --- BEGIN TPM Keygen Example -- */
/******************************************************************************/
static void usage(void)
{
    printf("Expected usage:\n");
    printf("keygen [keyblob.bin] [ECC/RSA]\n");
}

int TPM2_Keygen_Example(void* userCtx, int argc, char *argv[])
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY storage; /* SRK */
    WOLFTPM2_KEYBLOB newKey;
    TPMT_PUBLIC publicTemplate;
    TPMS_AUTH_COMMAND session[MAX_SESSION_NUM];
    TPMI_ALG_PUBLIC alg = TPM_ALG_RSA; /* TPM_ALG_ECC */
#if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_FILESYSTEM)
    XFILE f;
    size_t fileSz = 0;
#endif
    const char* outputFile = "keyblob.bin";

    if (argc >= 2) {
        if (XSTRNCMP(argv[1], "-?", 2) == 0 ||
            XSTRNCMP(argv[1], "-h", 2) == 0 ||
            XSTRNCMP(argv[1], "--help", 6) == 0) {
            usage();
            return 0;
        }
        outputFile = argv[1];
        if (argc >= 3) {
            /* ECC vs RSA */
            if (XSTRNCMP(argv[2], "ECC", 3) == 0) {
                alg = TPM_ALG_ECC;
            }
        }
    }

    XMEMSET(session, 0, sizeof(session));
    XMEMSET(&storage, 0, sizeof(storage));
    XMEMSET(&newKey, 0, sizeof(newKey));

    printf("TPM2.0 Key generation example\n");
    printf("\tKey: %s\n", outputFile);
    printf("\tAlgorithm: %s\n", TPM2_GetAlgName(alg));

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("\nwolfTPM2_Init failed\n");
        goto exit;
    }

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

    /* set session for authorization of the storage key */
    session[0].auth.size = sizeof(gStorageKeyAuth)-1;
    XMEMCPY(session[0].auth.buffer, gStorageKeyAuth, session[0].auth.size);

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
    printf("Creating new %s key...\n", TPM2_GetAlgName(alg));
    rc = wolfTPM2_CreateKey(&dev, &newKey, &storage.handle,
        &publicTemplate, (const byte*)gAiKeyAuth, sizeof(gAiKeyAuth)-1);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_CreateKey failed\n");
        goto exit;
    }
    printf("Created new key (pub %d, priv %d bytes)\n",
        newKey.pub.size, newKey.priv.size);

    /* Save key as encrypted blob to the disk */
#if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_FILESYSTEM)
    f = XFOPEN(outputFile, "wb");
    if (f != XBADFILE) {
        newKey.pub.size = sizeof(newKey.pub);
        fileSz += XFWRITE(&newKey.pub, 1, sizeof(newKey.pub), f);
        fileSz += XFWRITE(&newKey.priv, 1, sizeof(UINT16) + newKey.priv.size, f);
        XFCLOSE(f);
    }
    printf("Wrote %d bytes to %s\n", (int)fileSz, outputFile);
#else
    printf("Key Public Blob %d\n", newKey.pub.size);
    TPM2_PrintBin((const byte*)&newKey.pub.publicArea, newKey.pub.size);
    printf("Key Private Blob %d\n", newKey.priv.size);
    TPM2_PrintBin(newKey.priv.buffer, newKey.priv.size);
#endif

exit:

    if (rc != 0) {
        printf("\nFailure 0x%x: %s\n\n", rc, wolfTPM2_GetRCString(rc));
    }

    /* Close key handles */
    wolfTPM2_UnloadHandle(&dev, &newKey.handle);

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

    rc = TPM2_Keygen_Example(NULL, argc, argv);

    return rc;
}
#endif
