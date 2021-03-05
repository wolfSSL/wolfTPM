/* read.c
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

/* Tool and example for extracting a TPM key from the TPM's NVRAM
 *
 * NB: This example uses Parameter Encryption to protect
 *     the Password Authorization of the TPM NVRAM Index
 *
 **/

#include <wolftpm/tpm2_wrap.h>

#include <examples/nvram/store.h>
#include <examples/tpm_io.h>
#include <examples/tpm_test.h>
#include <examples/tpm_test_keys.h>

#include <stdio.h>
#include <stdlib.h>

#ifndef WOLFTPM2_NO_WRAPPER

#define ARGC_PUB_SIZE  1
#define ARGC_PRIV_SIZE 2
#define ARGC_PARAM_ENC 3

/******************************************************************************/
/* --- BEGIN TPM Keygen Example -- */
/******************************************************************************/
static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/nvram/read priv pub [-aes/-xor]\n");
    printf("* priv: size in bytes of the private part of the key in NV\n");
    printf("* pub: size in bytes of the public part of the key in NV\n");
    printf("* -aes/xor: Use Parameter Encryption\n");
}

int TPM2_NVRAM_Read_Example(void* userCtx, int argc, char *argv[])
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY storage;
    WOLFTPM2_KEYBLOB keyBlob;
    WOLFTPM2_SESSION tpmSession;
    WOLFTPM2_HANDLE parent;
    WOLFTPM2_NV nv;
    TPM2B_AUTH auth;
    word32 readSize;
    int paramEncAlg = TPM_ALG_NULL;

    if (argc > 2) {
        XMEMSET(&keyBlob, 0, sizeof(keyBlob));
        keyBlob.pub.size = atoi(argv[ARGC_PUB_SIZE]);
        keyBlob.priv.size = atoi(argv[ARGC_PRIV_SIZE]);

        if (argc == 4) {
            if (XSTRNCMP(argv[ARGC_PARAM_ENC], "-aes", 4) == 0) {
                paramEncAlg = TPM_ALG_CFB;
            }
            if (XSTRNCMP(argv[ARGC_PARAM_ENC], "-xor", 4) == 0) {
                paramEncAlg = TPM_ALG_XOR;
            }
            argc--;
        }
    }
    else {
        usage();
        return 0;
    }

    if (keyBlob.priv.size == 0 || keyBlob.pub.size == 0) {
        printf("Specify size of private and public part of the key\n");
        usage();
        return 0;
    }

    XMEMSET(&tpmSession, 0, sizeof(tpmSession));
    XMEMSET(&parent, 0, sizeof(parent));
    XMEMSET(&auth, 0, sizeof(auth));
    XMEMSET(&storage, 0, sizeof(storage));

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("\nwolfTPM2_Init failed\n");
        goto exit;
    }

    if (paramEncAlg != TPM_ALG_NULL) {
        /* Start TPM session for parameter encryption */
        rc = wolfTPM2_StartSession(&dev, &tpmSession, NULL, NULL,
                TPM_SE_HMAC, TPM_ALG_CFB);
        if (rc != 0) goto exit;
        printf("TPM2_StartAuthSession: sessionHandle 0x%x\n",
            (word32)tpmSession.handle.hndl);
        /* Set TPM session attributes for parameter encryption */
        rc = wolfTPM2_SetAuthSession(&dev, 1, &tpmSession,
            (TPMA_SESSION_decrypt | TPMA_SESSION_encrypt | TPMA_SESSION_continueSession));
        if (rc != 0) goto exit;
    }

    auth.size = sizeof(gNvAuth)-1;
    XMEMCPY(auth.buffer, gNvAuth, auth.size);

    /* Prepare auth for NV Index */
    XMEMSET(&nv, 0, sizeof(nv));
    nv.handle.hndl = TPM2_DEMO_NVRAM_STORE_INDEX;
    nv.handle.auth.size = auth.size;
    XMEMCPY(nv.handle.auth.buffer, auth.buffer, auth.size);

    readSize = keyBlob.pub.size;
    printf("Trying to read %d bytes of public key part from NV\n", readSize);
    rc = wolfTPM2_NVReadAuth(&dev, &nv, TPM2_DEMO_NVRAM_STORE_INDEX,
        (byte*)&keyBlob.pub.publicArea, &readSize, 0);
    if (rc != 0) goto exit;

    readSize = keyBlob.priv.size;
    printf("Trying to read %d bytes of private key part from NV\n", readSize);
    rc = wolfTPM2_NVReadAuth(&dev, &nv, TPM2_DEMO_NVRAM_STORE_INDEX,
        (byte*)&keyBlob.priv.buffer, &readSize, keyBlob.pub.size);
    if (rc != 0) goto exit;

    parent.hndl = TPM_RH_OWNER;
    rc = wolfTPM2_NVDeleteAuth(&dev, &parent, TPM2_DEMO_NVRAM_STORE_INDEX);
    if (rc != 0) goto exit;

    printf("Extraction of key from NVRAM at index 0x%x succeeded\n" ,
        TPM2_DEMO_NVRAM_STORE_INDEX);

#if 1
    /* get SRK */
    rc = getPrimaryStoragekey(&dev, &storage, TPM_ALG_RSA);
    if (rc != 0) goto exit;

    printf("Trying to load the key extracted from NVRAM\n");
    rc = wolfTPM2_LoadKey(&dev, &keyBlob, &storage.handle);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_LoadKey failed\n");
        goto exit;
    }
    printf("Loaded key to 0x%x\n",
        (word32)keyBlob.handle.hndl);
#endif

exit:

    if (rc != 0) {
        printf("\nFailure 0x%x: %s\n\n", rc, wolfTPM2_GetRCString(rc));
    }

    wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);
    wolfTPM2_Cleanup(&dev);

    return rc;
}

/******************************************************************************/
/* --- END TPM NVRAM Store Example -- */
/******************************************************************************/
#endif /* !WOLFTPM2_NO_WRAPPER */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = NOT_COMPILED_IN;

#ifndef WOLFTPM2_NO_WRAPPER
    rc = TPM2_NVRAM_Read_Example(NULL, argc, argv);
#else
    printf("NVRAM code not compiled in\n");
    (void)argc;
    (void)argv;
#endif

    return rc;
}
#endif
