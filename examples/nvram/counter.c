/* counter.c
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

/* Example for incrementing an NV counter.
 *
 * NB: This example uses Parameter Encryption to protect
 *     the Password Authorization of the TPM NVRAM Index
 *
 **/

#include <wolftpm/tpm2_wrap.h>

#include <stdio.h>

#ifndef WOLFTPM2_NO_WRAPPER

#include <examples/nvram/nvram.h>
#include <hal/tpm_io.h>
#include <examples/tpm_test.h>
#include <examples/tpm_test_keys.h>

/******************************************************************************/
/* --- BEGIN TPM NV Counter Example -- */
/******************************************************************************/
static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/nvram/counter [-nvindex=0x0] [-aes/-xor]\n");
    printf("* -nvindex=[handle] (default 0x%x)\n", TPM2_DEMO_NV_COUNTER_INDEX);
    printf("* -aes/xor: Use Parameter Encryption\n");
}

int TPM2_NVRAM_Counter_Example(void* userCtx, int argc, char *argv[])
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY storage;
    WOLFTPM2_SESSION tpmSession;
    WOLFTPM2_HANDLE parent;
    WOLFTPM2_NV nv;
    TPMS_NV_PUBLIC nvPublic;
    int paramEncAlg = TPM_ALG_NULL;
    word32 nvIndex = TPM2_DEMO_NV_COUNTER_INDEX;

    XMEMSET(&tpmSession, 0, sizeof(tpmSession));
    XMEMSET(&parent, 0, sizeof(parent));
    XMEMSET(&nv, 0, sizeof(nv));
    XMEMSET(&storage, 0, sizeof(storage));

    if (argc >= 2) {
        if (XSTRCMP(argv[1], "-?") == 0 ||
            XSTRCMP(argv[1], "-h") == 0 ||
            XSTRCMP(argv[1], "--help") == 0) {
            usage();
            return 0;
        }
    }
    while (argc) {
        if (XSTRCMP(argv[argc-1], "-aes") == 0) {
            paramEncAlg = TPM_ALG_CFB;
        }
        else if (XSTRCMP(argv[argc-1], "-xor") == 0) {
            paramEncAlg = TPM_ALG_XOR;
        }
        else if (XSTRCMP(argv[argc-1], "-nvindex=") == 0) {
            nvIndex = (word32)XSTRTOL(argv[argc-1] + XSTRLEN("-nvindex="),
                NULL, 0);
            if (nvIndex > TPM_20_OWNER_NV_SPACE &&
                                                nvIndex < TPM_20_TCG_NV_SPACE) {
                printf("Invalid NV Index %s\n", argv[argc-1] + 8);
                nvIndex = 0;
            }
        }
        else {
            printf("Warning: Unrecognized option: %s\n", argv[argc-1]);
        }

        argc--;
    }

    printf("NV Counter: NV Index 0x%x\n", nvIndex);
    if (paramEncAlg == TPM_ALG_CFB) {
        printf("Parameter Encryption: Enabled. (AES CFB)\n\n");
    }
    else if (paramEncAlg == TPM_ALG_XOR) {
        printf("Parameter Encryption: Enabled. (XOR)\n\n");
    }
    else {
        printf("Parameter Encryption: Not enabled (try -aes or -xor).\n\n");
    }


    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_Init failed\n");
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
            (TPMA_SESSION_decrypt | TPMA_SESSION_encrypt |
             TPMA_SESSION_continueSession));
        if (rc != 0) goto exit;
    }

    rc = wolfTPM2_NVReadPublic(&dev, nvIndex, &nvPublic);
    if (rc == (RC_VER1 | TPM_RC_HANDLE)) {
        word32 nvAttributes;

        /* create new NV counter under owner hierarchy */
        parent.hndl = TPM_RH_OWNER;
        rc = wolfTPM2_GetNvAttributesTemplate(parent.hndl, &nvAttributes);
        if (rc != 0) goto exit;

        /* Specify an NV counter */
        nvAttributes |= (TPMA_NV_TPM_NT & (TPM_NT_COUNTER << 4));

        /* Our wolfTPM2 wrapper for NV_Define */
        rc = wolfTPM2_NVCreateAuth(&dev, &parent, &nv, nvIndex,
            nvAttributes, 8, (byte*)gNvAuth, sizeof(gNvAuth)-1);
        if (rc != 0) goto exit;

        rc = wolfTPM2_NVReadPublic(&dev, nvIndex, &nvPublic);
    }
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM NV Read public failed\n");
        goto exit;
    }

    printf("NV Info: attributes 0x%x, data size %d\n",
        nvPublic.attributes, nvPublic.dataSize);

    rc = wolfTPM2_NVOpen(&dev, &nv, nvIndex, (byte*)gNvAuth, sizeof(gNvAuth)-1);
    if (rc != TPM_RC_SUCCESS) {
        printf("NV Open failed\n");
        goto exit;
    }

    rc = wolfTPM2_NVIncrement(&dev, &nv);
    if (rc != TPM_RC_SUCCESS) {
        printf("NV Increment failed\n");
        goto exit;
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
/* --- END TPM NVRAM Counter Example -- */
/******************************************************************************/
#endif /* !WOLFTPM2_NO_WRAPPER */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = NOT_COMPILED_IN;

#ifndef WOLFTPM2_NO_WRAPPER
    rc = TPM2_NVRAM_Counter_Example(NULL, argc, argv);
#else
    printf("NVRAM code not compiled in\n");
    (void)argc;
    (void)argv;
#endif

    return rc;
}
#endif
