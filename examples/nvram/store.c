/* store.c
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

/* Tool and example for storing a TPM key into the TPM's NVRAM
 *
 * NB: This example uses Parameter Encryption to protect the password of the
 *     TPM NVRAM Index, where the private and public parts of a TPM key is stored
 *
 **/

#include <wolftpm/tpm2_wrap.h>

#include <examples/nvram/store.h>
#include <examples/tpm_io.h>
#include <examples/tpm_test.h>
#include <examples/tpm_test_keys.h>

#include <stdio.h>

#ifndef WOLFTPM2_NO_WRAPPER

/******************************************************************************/
/* --- BEGIN TPM Keygen Example -- */
/******************************************************************************/
static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/nvram/store [filename] [-aes/-xor]\n");
    printf("* filename: point to a file containing a TPM key\n");
    printf("\tIf not supplied, default filename is \"keyblob.bin\"\n");
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
    TPM2B_AUTH auth;
    word32 nvAttributes;
    const char* filename = "keyblob.bin";
    int paramEncAlg = TPM_ALG_NULL;

    if (argc >= 2) {
        if (XSTRNCMP(argv[1], "-?", 2) == 0 ||
            XSTRNCMP(argv[1], "-h", 2) == 0 ||
            XSTRNCMP(argv[1], "--help", 6) == 0) {
            usage();
            return 0;
        }
        if (argv[1][0] != '-') {
            filename = argv[1];
        }
    }
    while (argc > 1) {
        if (XSTRNCMP(argv[argc-1], "-aes", 4) == 0) {
            paramEncAlg = TPM_ALG_CFB;
        }
        if (XSTRNCMP(argv[argc-1], "-xor", 4) == 0) {
            paramEncAlg = TPM_ALG_XOR;
        }
        argc--;
    };

    XMEMSET(&keyBlob, 0, sizeof(keyBlob));
    XMEMSET(&tpmSession, 0, sizeof(tpmSession));
    XMEMSET(&parent, 0, sizeof(parent));
    XMEMSET(&auth, 0, sizeof(auth));

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

    rc = readKeyBlob(filename, &keyBlob);
    if (rc != 0) goto exit;

    /*  Prepare NV_AUTHWRITE and NV_AUTHREAD attributes necessary for password */
    parent.hndl = TPM_RH_OWNER;
    rc = wolfTPM2_GetNvAttributesTemplate(parent.hndl, &nvAttributes);
    if (rc != 0) goto exit;

    /* Our wolfTPM2 wrapper for NV_Define */
    rc = wolfTPM2_NVCreateAuth(&dev, &parent, &nv, TPM2_DEMO_NVRAM_STORE_PRIV_INDEX,
        nvAttributes, TPM2_DEMO_NV_TEST_SIZE, (byte*)gNvAuth, sizeof(gNvAuth)-1);
    if (rc != 0 && rc != TPM_RC_NV_DEFINED) goto exit;

    printf("Storing key at TPM NV index 0x%x with password protection\n",
             TPM2_DEMO_NVRAM_STORE_PRIV_INDEX);

    printf("Public part = %d bytes\n", keyBlob.pub.size);
    rc = wolfTPM2_NVWriteAuth(&dev, &nv, TPM2_DEMO_NVRAM_STORE_PRIV_INDEX,
        (byte*)&keyBlob.pub.publicArea, keyBlob.pub.size, 0);
    if (rc != 0) goto exit;

    printf("Private part = %d bytes\n", keyBlob.priv.size);
    rc = wolfTPM2_NVWriteAuth(&dev, &nv, TPM2_DEMO_NVRAM_STORE_PRIV_INDEX,
        keyBlob.priv.buffer, keyBlob.priv.size, keyBlob.pub.size);
    if (rc != 0) goto exit;

    printf("NV write succeeded\n");

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
