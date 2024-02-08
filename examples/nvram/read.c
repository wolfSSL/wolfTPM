/* read.c
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

/* Tool and example for extracting a TPM key from the TPM's NVRAM
 *
 * NB: This example uses Parameter Encryption to protect
 *     the Password Authorization of the TPM NVRAM Index
 *
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2_wrap.h>

#include <stdio.h>

#ifndef WOLFTPM2_NO_WRAPPER

#include <examples/nvram/nvram.h>
#include <hal/tpm_io.h>
#include <examples/tpm_test.h>
#include <examples/tpm_test_keys.h>

#define PRIVATE_PART_ONLY   0x01
#define PUBLIC_PART_ONLY    0x02

/******************************************************************************/
/* --- BEGIN TPM NVRAM Read Example -- */
/******************************************************************************/
static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/nvram/read [-nvindex] [-priv] [-pub] [-aes/-xor]\n");
    printf("* -nvindex=[handle] (default 0x%x)\n", TPM2_DEMO_NVRAM_STORE_INDEX);
    printf("* -priv: Read ony the private part\n");
    printf("* -pub: Read only the public part\n");
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
    TPMI_RH_NV_AUTH authHandle = TPM_RH_OWNER; /* or TPM_RH_PLATFORM */
    int paramEncAlg = TPM_ALG_NULL;
    int partialRead = 0;
    int offset = 0;
    /* Needed for TPM2_ParsePublic */
    byte pubAreaBuffer[sizeof(TPM2B_PUBLIC)];
    int pubAreaSize;
    word32 nvIndex = TPM2_DEMO_NVRAM_STORE_INDEX;

    if (argc >= 2) {
        if (XSTRCMP(argv[1], "-?") == 0 ||
            XSTRCMP(argv[1], "-h") == 0 ||
            XSTRCMP(argv[1], "--help") == 0) {
            usage();
            return 0;
        }
    }
    while (argc > 1) {
        if (XSTRNCMP(argv[argc-1], "-nvindex=", XSTRLEN("-nvindex=")) == 0) {
            const char* nvIndexStr = argv[argc-1] + XSTRLEN("-nvindex=");
            nvIndex = (word32)XSTRTOL(nvIndexStr, NULL, 0);
            if (!(authHandle == TPM_RH_PLATFORM && (
                    nvIndex > TPM_20_PLATFORM_MFG_NV_SPACE &&
                    nvIndex < TPM_20_OWNER_NV_SPACE)) &&
                !(authHandle == TPM_RH_OWNER && (
                    nvIndex > TPM_20_OWNER_NV_SPACE &&
                    nvIndex < TPM_20_TCG_NV_SPACE)))
            {
                fprintf(stderr, "Invalid NV Index %s\n", nvIndexStr);
                fprintf(stderr, "\tPlatform Range: 0x%x -> 0x%x\n",
                    TPM_20_PLATFORM_MFG_NV_SPACE, TPM_20_OWNER_NV_SPACE);
                fprintf(stderr, "\tOwner Range: 0x%x -> 0x%x\n",
                    TPM_20_OWNER_NV_SPACE, TPM_20_TCG_NV_SPACE);
                usage();
                return -1;
            }
        }
        else if (XSTRCMP(argv[argc-1], "-aes") == 0) {
            paramEncAlg = TPM_ALG_CFB;
        }
        else if (XSTRCMP(argv[argc-1], "-xor") == 0) {
            paramEncAlg = TPM_ALG_XOR;
        }
        else if (XSTRCMP(argv[argc-1], "-priv") == 0) {
            partialRead = PRIVATE_PART_ONLY;
        }
        else if (XSTRCMP(argv[argc-1], "-pub") == 0) {
            partialRead = PUBLIC_PART_ONLY;
        }
        else {
            printf("Warning: Unrecognized option: %s\n", argv[argc-1]);
        }
        argc--;
    }

    if (paramEncAlg == TPM_ALG_CFB) {
        printf("Parameter Encryption: Enabled. (AES CFB)\n\n");
    }
    else if (paramEncAlg == TPM_ALG_XOR) {
        printf("Parameter Encryption: Enabled. (XOR)\n\n");
    }
    else {
        printf("Parameter Encryption: Not enabled (try -aes or -xor).\n\n");
    }

    XMEMSET(&keyBlob, 0, sizeof(keyBlob));
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
                TPM_SE_HMAC, paramEncAlg);
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
    nv.handle.hndl = nvIndex;
    nv.handle.auth.size = auth.size;
    XMEMCPY(nv.handle.auth.buffer, auth.buffer, auth.size);

    if (partialRead != PRIVATE_PART_ONLY) {
        readSize = sizeof(keyBlob.pub.size);
        printf("Trying to read %d bytes of public key size marker\n", readSize);
        rc = wolfTPM2_NVReadAuth(&dev, &nv, nvIndex,
            (byte*)&keyBlob.pub.size, &readSize, 0);
        if (rc != 0) {
            printf("Was a public key part written? (see nvram/store)\n");
            goto exit;
        }
        printf("Successfully read public key part from NV\n\n");
        offset += readSize;

        readSize = sizeof(UINT16) + keyBlob.pub.size; /* account for TPM2B size marker */
        printf("Trying to read %d bytes of public key part from NV\n", keyBlob.pub.size);
        rc = wolfTPM2_NVReadAuth(&dev, &nv, nvIndex,
            pubAreaBuffer, &readSize, offset);
        if (rc != 0) goto exit;
        printf("Successfully read public key part from NV\n\n");
        offset += readSize;

        /* Necessary for storing the publicArea with the correct encoding */
        rc = TPM2_ParsePublic(&keyBlob.pub, pubAreaBuffer,
            (word32)sizeof(pubAreaBuffer), &pubAreaSize);
        if (rc != TPM_RC_SUCCESS) {
            printf("Decoding of PublicArea failed. Unable to extract correctly.\n");
            goto exit;
        }

#ifdef WOLFTPM_DEBUG_VERBOSE
        TPM2_PrintPublicArea(&keyBlob.pub);
#endif
    }

    if (partialRead != PUBLIC_PART_ONLY) {
        printf("Trying to read size marker of the private key part from NV\n");
        readSize = sizeof(keyBlob.priv.size);
        rc = wolfTPM2_NVReadAuth(&dev, &nv, nvIndex,
            (byte*)&keyBlob.priv.size, &readSize, offset);
        if (rc != 0) {
            printf("Was a private key part written? (see nvram/store)\n");
            goto exit;
        }
        printf("Successfully read size marker from NV\n\n");
        offset += readSize;

        readSize = keyBlob.priv.size;
        printf("Trying to read %d bytes of private key part from NV\n", readSize);
        rc = wolfTPM2_NVReadAuth(&dev, &nv, nvIndex,
            (byte*)&keyBlob.priv.buffer, &readSize, offset);
        if (rc != 0) goto exit;
        printf("Successfully read private key part from NV\n\n");
    }

    /* auth 0 is owner, no auth */
    wolfTPM2_SetAuthPassword(&dev, 0, NULL);
    wolfTPM2_UnsetAuth(&dev, 1);

    parent.hndl = authHandle;
    rc = wolfTPM2_NVDeleteAuth(&dev, &parent, nvIndex);
    if (rc != 0) goto exit;

    printf("Extraction of key from NVRAM at index 0x%x succeeded\n",
        nvIndex);

    if (!partialRead) {
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
    }

exit:

    if (rc != 0) {
        printf("\nFailure 0x%x: %s\n\n", rc, wolfTPM2_GetRCString(rc));
    }

    wolfTPM2_UnloadHandle(&dev, &keyBlob.handle);
    wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);
    wolfTPM2_Cleanup(&dev);

    return rc;
}

/******************************************************************************/
/* --- END TPM NVRAM Read Example -- */
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
