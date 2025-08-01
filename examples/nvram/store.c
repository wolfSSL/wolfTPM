/* store.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfTPM.
 *
 * wolfTPM is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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

/* Tool and example for storing a TPM key into the TPM's NVRAM
 *
 * NB: This example uses Parameter Encryption to protect the password of the
 *     TPM NVRAM Index, where the private and public parts of a TPM key is stored
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
/* --- BEGIN TPM NVRAM Store Example -- */
/******************************************************************************/
static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/nvram/store [filename] [-nvindex] [-priv] [-pub] [-aes/-xor]\n");
    printf("* filename: point to a file containing a TPM key (default keyblob.bin\n");
    printf("\tDefault filename is \"keyblob.bin\"\n");
    printf("* -nvindex=[handle] (default 0x%x)\n", TPM2_DEMO_NVRAM_STORE_INDEX);
    printf("* -priv: Store only the private part of the key\n");
    printf("* -pub: Store only the public part of the key\n");
    printf("* -aes/xor: Use Parameter Encryption\n");
}

int TPM2_NVRAM_Store_Example(void* userCtx, int argc, char *argv[])
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEYBLOB keyBlob;
    WOLFTPM2_SESSION tpmSession;
    WOLFTPM2_HANDLE parent;
    WOLFTPM2_NV nv;
    word32 nvAttributes;
    TPMI_RH_NV_AUTH authHandle = TPM_RH_OWNER; /* or TPM_RH_PLATFORM */
    const char* filename = "keyblob.bin";
    int paramEncAlg = TPM_ALG_NULL;
    int partialStore = 0;
    int offset = 0;
    /* Needed for TPM2_AppendPublic */
    byte pubAreaBuffer[sizeof(TPM2B_PUBLIC)];
    int pubAreaSize;
    word32 nvIndex = TPM2_DEMO_NVRAM_STORE_INDEX;
    byte* auth = (byte*)gNvAuth;
    word32 authSz = (word32)sizeof(gNvAuth)-1;
    word32 nvSize;

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
            nvIndex = (word32)XSTRTOUL(nvIndexStr, NULL, 0);
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
            partialStore = PRIVATE_PART_ONLY;
        }
        else if (XSTRCMP(argv[argc-1], "-pub") == 0) {
            partialStore = PUBLIC_PART_ONLY;
        }
        else if (argv[argc-1][0] != '-') {
            filename = argv[argc-1];
        }
        else {
            printf("Warning: Unrecognized option: %s\n", argv[argc-1]);
        }
        argc--;
    };

    if (paramEncAlg == TPM_ALG_CFB) {
        printf("Parameter Encryption: Enabled. (AES CFB)\n\n");
    }
    else if (paramEncAlg == TPM_ALG_XOR) {
        printf("Parameter Encryption: Enabled. (XOR)\n\n");
    }
    else {
        printf("Parameter Encryption: Not enabled (try -aes or -xor).\n\n");
    }

    XMEMSET(&nv, 0, sizeof(nv));
    XMEMSET(&keyBlob, 0, sizeof(keyBlob));
    XMEMSET(&tpmSession, 0, sizeof(tpmSession));
    XMEMSET(&parent, 0, sizeof(parent));

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

    /* Prepare NV_AUTHWRITE and NV_AUTHREAD attributes necessary for password */
    parent.hndl = authHandle;
    rc = wolfTPM2_GetNvAttributesTemplate(parent.hndl, &nvAttributes);
    if (rc != 0) goto exit;

    rc = readKeyBlob(filename, &keyBlob);
    if (rc != 0) goto exit;

    /* Get maximum size of NV */
    nvSize =
        keyBlob.pub.size + sizeof(keyBlob.pub.size) + sizeof(UINT16) +
        keyBlob.priv.size + sizeof(keyBlob.priv.size) + sizeof(UINT16);

    /* Try and open existing NV */
    rc = wolfTPM2_NVOpen(&dev, &nv, nvIndex, auth, authSz);
    if (rc != 0) {
        /* In not found try create using wolfTPM2 wrapper for NV_Define */
        rc = wolfTPM2_NVCreateAuth(&dev, &parent, &nv, nvIndex,
            nvAttributes, nvSize, auth, authSz);

        if (rc != 0 && rc != TPM_RC_NV_DEFINED) goto exit;
    }
    /* The set auth is done already in NVOpen and NVCreateAuth, but shown here
     * as example for how to set the authentication on a handle */
    wolfTPM2_SetAuthHandle(&dev, 0, &nv.handle);

    printf("Storing key at TPM NV index 0x%x with password protection\n\n",
            nvIndex);

    if (partialStore != PRIVATE_PART_ONLY) {
        printf("Public part = %hu bytes\n", keyBlob.pub.size);
        rc = wolfTPM2_NVWriteAuth(&dev, &nv, nvIndex,
            (byte*)&keyBlob.pub.size, sizeof(keyBlob.pub.size), 0);
        if (rc != 0) goto exit;
        printf("Stored 2-byte size marker before the private part\n");
        offset += sizeof(keyBlob.pub.size);

        /* Necessary for storing the publicArea with the correct byte encoding */
        rc = TPM2_AppendPublic(pubAreaBuffer, (word32)sizeof(pubAreaBuffer),
            &pubAreaSize, &keyBlob.pub);
        /* Note:
        * Public Area is the only part of a TPM key that can be stored encoded
        * Private Area is stored as-is, because TPM2B_PRIVATE is byte buffer
        * and UINT16 size field, while Public Area is a complex TCG structure.
        */
        if (rc != TPM_RC_SUCCESS) {
            printf("Encoding of the publicArea failed. Unable to store.\n");
            goto exit;
        }

        /* The buffer holds pub.publicArea and also pub.size(UINT16) */
        rc = wolfTPM2_NVWriteAuth(&dev, &nv, nvIndex,
            pubAreaBuffer, sizeof(UINT16) + keyBlob.pub.size, offset);
        if (rc != 0) goto exit;
        printf("NV write of public part succeeded\n\n");
        offset += sizeof(UINT16) + keyBlob.pub.size;

#ifdef WOLFTPM_DEBUG_VERBOSE
        TPM2_PrintPublicArea(&keyBlob.pub);
#endif
    }
    if (partialStore != PUBLIC_PART_ONLY) {
        printf("Private part = %d bytes\n", keyBlob.priv.size);
        rc = wolfTPM2_NVWriteAuth(&dev, &nv, nvIndex,
            (byte*)&keyBlob.priv.size, sizeof(keyBlob.priv.size), offset);
        if (rc != 0) goto exit;
        printf("Stored 2-byte size marker before the private part\n");
        offset += sizeof(keyBlob.priv.size);

        rc = wolfTPM2_NVWriteAuth(&dev, &nv, nvIndex,
            keyBlob.priv.buffer, keyBlob.priv.size, offset);
        if (rc != 0) goto exit;
        printf("NV write of private part succeeded\n\n");
    }

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
    rc = TPM2_NVRAM_Store_Example(NULL, argc, argv);
#else
    printf("NVRAM code not compiled in\n");
    (void)argc;
    (void)argv;
#endif

    return rc;
}
#endif
