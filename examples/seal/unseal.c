/* unseal.c
 *
 * Copyright (C) 2006-2022 wolfSSL Inc.
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

/* This example demonstrates how to extract the data from a TPM seal object */

#include <wolftpm/tpm2_wrap.h>

#include <stdio.h>

#if !defined(WOLFTPM2_NO_WRAPPER) && !defined(NO_FILESYSTEM)

#include <examples/seal/seal.h>
#include <hal/tpm_io.h>
#include <examples/tpm_test.h>
#include <examples/tpm_test_keys.h>


/******************************************************************************/
/* --- BEGIN TPM2.0 Unseal example --- */
/******************************************************************************/

static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/seal/unseal [filename] [inkey_filename]\n");
    printf("* filename - File contaning a TPM seal key\n");
    printf("Demo usage, without arguments, uses keyblob.bin file input.\n");
}

int TPM2_Unseal_Example(void* userCtx, int argc, char *argv[])
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY key;
    TPM2B_AUTH auth;
    const char *filename = "unseal.bin";
    const char *inkeyfilename = "keyblob.bin";
#if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_FILESYSTEM)
    XFILE fp = NULL;
    size_t len;
#endif
    Unseal_In cmdIn_unseal;
    Unseal_Out cmdOut_unseal;

    WOLFTPM2_KEYBLOB newKey;
    WOLFTPM2_KEY storage; /* SRK */


    XMEMSET(&cmdIn_unseal, 0, sizeof(cmdIn_unseal));
    XMEMSET(&cmdOut_unseal, 0, sizeof(cmdOut_unseal));
    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(&auth, 0, sizeof(auth));

    if (argc >= 2) {
        if (XSTRCMP(argv[1], "-?") == 0 ||
            XSTRCMP(argv[1], "-h") == 0 ||
            XSTRCMP(argv[1], "--help") == 0) {
            usage();
            return 0;
        }

        if (argv[1][0] != '-') {
            filename = argv[1];
        }

        if (argc >= 3 && argv[2][0] != '-') {
           inkeyfilename = argv[2];
        }
    }

    printf("Example how to unseal data using TPM2.0\n");
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_Init failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    printf("wolfTPM2_Init: success\n");

    rc = getPrimaryStoragekey(&dev, &storage, TPM_ALG_RSA);
    if (rc != 0) goto exit;

    rc = readKeyBlob(inkeyfilename, &newKey);
    if (rc != 0) goto exit;

    rc = wolfTPM2_LoadKey(&dev, &newKey, &storage.handle);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_LoadKey failed\n");
        goto exit;
    }
    printf("Loaded key to 0x%x\n",
        (word32)newKey.handle.hndl);

    /* Set authorization for using the seal key */
    auth.size = (int)sizeof(gKeyAuth) - 1;
    XMEMCPY(auth.buffer, gKeyAuth, auth.size);
    wolfTPM2_SetAuthPassword(&dev, 0, &auth);

    cmdIn_unseal.itemHandle = newKey.handle.hndl;

    rc = TPM2_Unseal(&cmdIn_unseal, &cmdOut_unseal);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_Unseal failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    printf("Unsealing succeeded\n");

#ifdef DEBUG_WOLFTPM
    printf("Unsealed data:\n");
    TPM2_PrintBin(cmdOut_unseal.outData.buffer, cmdOut_unseal.outData.size);
#endif

#if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_FILESYSTEM)
    /* Output the unsealed data to a file */
    if (filename) {
        fp = XFOPEN(filename, "wb");
        if (fp) {
            len = XFWRITE(cmdOut_unseal.outData.buffer, 1, cmdOut_unseal.outData.size, fp);
            if (len != cmdOut_unseal.outData.size) {
                printf("Error while writing the unsealed data to a file.\n");
                goto exit;
            }
        }
        printf("Stored unsealed data to file = %s\n", filename);
        XFCLOSE(fp);
    }
#else
    printf("Unable to store unsealed data to a file. Enable wolfcrypt support.\n");
    (void)filename;
#endif

    /* Remove the loaded TPM seal object */
    wolfTPM2_SetAuthPassword(&dev, 0, NULL);

exit:
    wolfTPM2_UnloadHandle(&dev, &storage.handle);
    wolfTPM2_UnloadHandle(&dev, &newKey.handle);

    wolfTPM2_Cleanup(&dev);
    return rc;
}

/******************************************************************************/
/* --- END TPM2.0 Unseal example --- */
/******************************************************************************/

#endif /* !WOLFTPM2_NO_WRAPPER */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = -1;

#if !defined(WOLFTPM2_NO_WRAPPER) && !defined(NO_FILESYSTEM)
    rc = TPM2_Unseal_Example(NULL, argc, argv);
#else
    printf("Wrapper code not compiled in\n");
    (void)argc;
    (void)argv;
#endif /* !WOLFTPM2_NO_WRAPPER */

    return rc;
}
#endif
