/* nvauth.c
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

/* Tool and example for NVRAM operations with authentication
 *
 * This example demonstrates creating, writing, reading, and deleting
 * NV indices with owner authentication. It shows how to use
 * owner authentication for write/delete operations while allowing
 * unauthenticated reads.
 *
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2_wrap.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef WOLFTPM2_NO_WRAPPER

#include <examples/nvram/nvram.h>
#include <hal/tpm_io.h>
#include <examples/tpm_test.h>
#include <examples/tpm_test_keys.h>

/******************************************************************************/
/* --- BEGIN TPM NVRAM Auth Example -- */
/******************************************************************************/
static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/nvram/nvauth\n");
    printf("* -all       Run all operations in order (create, write, read, delete)\n");
    printf("* -ownerauth[=<auth>] Auth for owner (optional)\n");
    printf("* -setownerauth Set owner auth\n");
    printf("* -create[=auth] Create NV index (optional: set nvIndex auth)\n");
    printf("* -write[=<val>] Write value to NV index (optional: specify value, default: test)\n");
    printf("* -delete    Delete NV index\n");
    printf("* -aes/xor:  Enable Parameter Encryption\n");
}

int TPM2_NVRAM_Auth_Example(void* userCtx, int argc, char *argv[])
{
    int rc = 0;
    int i;
    WOLFTPM2_DEV dev;
    WOLFTPM2_SESSION session;
    WOLFTPM2_NV nv;
    word32 nvIndex = TPM2_DEMO_NVRAM_OWNER_INDEX;
    byte buf[64];
    word32 bufLen = sizeof(buf);
    int paramEncAlg = TPM_ALG_NULL;
    const char* ownerAuthStr = NULL;
    const char* nvIndexAuthStr = NULL;
    WOLFTPM2_HANDLE owner;
    WOLFTPM2_HANDLE nvIndexAuth;

    /* Command line flags */
    int do_create = 0;
    int do_write = 0;
    int do_read = 0;
    int do_delete = 0;
    const char* write_value = "test";
    int set_owner_auth = 0;

    if (argc >= 2) {
        if (XSTRCMP(argv[1], "-?") == 0 ||
            XSTRCMP(argv[1], "-h") == 0 ||
            XSTRCMP(argv[1], "--help") == 0) {
            usage();
            return 0;
        }
    }

    /* Parse command line arguments */
    for (i = 1; i < argc; i++) {
        /* Handle -ownerauth[=<auth>] */
        if (XSTRNCMP(argv[i], "-ownerauth=", XSTRLEN("-ownerauth=")) == 0) {
            ownerAuthStr = argv[i] + XSTRLEN("-ownerauth=");
        }
        else if (XSTRCMP(argv[i], "-setownerauth") == 0) {
            set_owner_auth = 1;
        }
        /* Handle -create[=auth] */
        else if (XSTRNCMP(argv[i], "-create=", XSTRLEN("-create=")) == 0) {
            do_create = 1;
            nvIndexAuthStr = argv[i] + XSTRLEN("-create=");
        }
        else if (XSTRCMP(argv[i], "-create") == 0) {
            do_create = 1;
        }
        /* Handle -write[=<val>] */
        else if (XSTRNCMP(argv[i], "-write=", XSTRLEN("-write=")) == 0) {
            do_write = 1;
            write_value = argv[i] + XSTRLEN("-write=");
        }
        else if (XSTRCMP(argv[i], "-write") == 0) {
            do_write = 1;
        }
        else if (XSTRCMP(argv[i], "-read") == 0) {
            do_read = 1;
        }
        else if (XSTRCMP(argv[i], "-delete") == 0) {
            do_delete = 1;
        }
        else if (XSTRCMP(argv[i], "-all") == 0) {
            do_create = 1;
            do_write = 1;
            do_read = 1;
            do_delete = 1;
        }
        else if (XSTRCMP(argv[i], "-aes") == 0) {
            paramEncAlg = TPM_ALG_CFB;
        }
        else if (XSTRCMP(argv[i], "-xor") == 0) {
            paramEncAlg = TPM_ALG_XOR;
        }
        else {
            printf("Warning: Unrecognized option: %s\n", argv[i]);
        }
    }

    printf("Example for NVRAM operations with authentication\n");
    printf("NV Index: 0x%x\n", nvIndex);
    if (paramEncAlg == TPM_ALG_CFB) {
        printf("Parameter Encryption: Enabled. (AES CFB)\n\n");
    }
    else if (paramEncAlg == TPM_ALG_XOR) {
        printf("Parameter Encryption: Enabled. (XOR)\n\n");
    }

    /* setup the owner authentication for NV write/delete */
    XMEMSET(&owner, 0, sizeof(owner));
    owner.hndl = TPM_RH_OWNER;
    if (ownerAuthStr != NULL) {
        owner.auth.size = (word16)XSTRLEN(ownerAuthStr);
        XMEMCPY(owner.auth.buffer, ownerAuthStr, owner.auth.size);
    }

    /* setup the nvIndex authentication */
    XMEMSET(&nvIndexAuth, 0, sizeof(nvIndexAuth));
    nvIndexAuth.hndl = nvIndex;
    if (nvIndexAuthStr != NULL) {
        nvIndexAuth.auth.size = (word16)XSTRLEN(nvIndexAuthStr);
        XMEMCPY(nvIndexAuth.auth.buffer, nvIndexAuthStr, nvIndexAuth.auth.size);
    }

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("Failed to initialize TPM: 0x%x\n", rc);
        goto cleanup;
    }

    if (paramEncAlg != TPM_ALG_NULL) {
        rc = wolfTPM2_StartSession(&dev, &session, NULL, NULL, TPM_SE_HMAC,
                                   paramEncAlg);
        if (rc != TPM_RC_SUCCESS) {
            printf("Failed to start session: 0x%x\n", rc);
            goto cleanup;
        }

        rc = wolfTPM2_SetAuthSession(&dev, 1, &session,
            (TPMA_SESSION_decrypt | TPMA_SESSION_encrypt |
             TPMA_SESSION_continueSession));
        if (rc != TPM_RC_SUCCESS) {
            printf("Failed to set auth session: 0x%x\n", rc);
            goto cleanup;
        }
    }

    if (set_owner_auth) {
        /* Example for setting the owner authentication */
        HierarchyChangeAuth_In in;
        XMEMSET(&in, 0, sizeof(in));
        in.authHandle = owner.hndl;
        in.newAuth.size = owner.auth.size;
        XMEMCPY(in.newAuth.buffer, owner.auth.buffer, in.newAuth.size);
        rc = TPM2_HierarchyChangeAuth(&in);
        if (rc != TPM_RC_SUCCESS) {
            printf("Failed to set owner auth: 0x%x (%s), allowing error and "
                "continuing as it might already be set\n",
                rc, wolfTPM2_GetRCString(rc));
            rc = TPM_RC_SUCCESS;
        }
        printf("Owner hierarchy auth set\n");
    }

    if (do_create) {
        /* Try to open an existing */
        rc = wolfTPM2_NVOpen(&dev, &nv, nvIndex,
            nvIndexAuth.auth.buffer, nvIndexAuth.auth.size);
        if (rc != TPM_RC_SUCCESS) {
            /* Require owner password to write/delete and no password to read */
            word32 nvAttributes =
                (TPMA_NV_AUTHREAD | TPMA_NV_OWNERWRITE | TPM_NT_ORDINARY);
            /* Can also switch to using AUTHWRITE or OWNERREAD to flip permissions */

            /* By default the nv auth handle is the nvIndex handle,
             * but it can also be a hierarchy handle */
            nv.handle.hndl = owner.hndl;
            /* Set auth for the owner hierarchy */
            wolfTPM2_SetAuthHandle(&dev, 0, &owner);

            /* if the NV is not found then create it */
            rc = wolfTPM2_NVCreateAuth(&dev, &owner, &nv, nvIndex,
                nvAttributes, sizeof(buf),
                nvIndexAuth.auth.buffer, nvIndexAuth.auth.size);
            if (rc != TPM_RC_SUCCESS) {
                printf("Failed to create NV index: 0x%x\n", rc);
                goto cleanup;
            }
            printf("Created NV index 0x%x\n", nvIndex);
        }
        else {
            printf("NV index 0x%x already exists\n", nvIndex);
        }
    }

    if (do_write) {
        rc = wolfTPM2_NVOpen(&dev, &nv, nvIndex,
            nvIndexAuth.auth.buffer, nvIndexAuth.auth.size);
        if (rc != TPM_RC_SUCCESS) {
            printf("Failed to open NV index for write: 0x%x\n", rc);
            goto cleanup;
        }

        /* By default the nv auth handle is the nvIndex handle,
         * but it can also be a hierarchy handle */
        nv.handle.hndl = owner.hndl;
        wolfTPM2_SetAuthHandle(&dev, 0, &owner);
        wolfTPM2_SetAuthHandle(&dev, 1, &nvIndexAuth);

        bufLen = (word32)XSTRLEN(write_value)+1;
        rc = wolfTPM2_NVWriteData(&dev,
            (paramEncAlg != TPM_ALG_NULL) ? &session : NULL,
            TPM_ALG_NULL, NULL, 0, &nv, nvIndex, (byte*)write_value,
            bufLen, 0, NW_WRITE_FLAG_AUTH_CUSTOM);
        if (rc != TPM_RC_SUCCESS) {
            printf("Failed to write to NV index: 0x%x\n", rc);
            goto cleanup;
        }
        printf("Wrote %u bytes to NV index 0x%x\n", bufLen, nvIndex);
    }

    if (do_read) {
        TPMS_NV_PUBLIC nvPublic;

        /* Prepare auth for NV Index */
        XMEMSET(&nv, 0, sizeof(nv));

        /* Clear all auth. Not required here, since wolfTPM2_NVReadAuth does it,
         * but demonstrating that the auth is not required for a read because
         * AUTHREAD is not set */
        wolfTPM2_SetAuthPassword(&dev, 0, NULL);
        wolfTPM2_SetAuthPassword(&dev, 1, NULL);

        rc = wolfTPM2_NVOpen(&dev, &nv, nvIndex,
            nvIndexAuth.auth.buffer, nvIndexAuth.auth.size);
        if (rc != TPM_RC_SUCCESS) {
            printf("Failed to open NV index for read: 0x%x\n", rc);
            goto cleanup;
        }

        rc = wolfTPM2_NVReadPublic(&dev, nvIndex, &nvPublic);
        if (rc != TPM_RC_SUCCESS) {
            printf("Failed to read public from NV index: 0x%x\n", rc);
            goto cleanup;
        }
        bufLen = nvPublic.dataSize;

        rc = wolfTPM2_NVReadAuth(&dev, &nv, nvIndex, buf, &bufLen, 0);
        if (rc != TPM_RC_SUCCESS) {
            printf("Failed to read from NV index: 0x%x\n", rc);
            goto cleanup;
        }

        printf("Read %u bytes from NV index:\n", bufLen);
        printf("Data: %s\n", buf);
    }

    if (do_delete) {
        wolfTPM2_SetAuthHandle(&dev, 0, &owner);
        wolfTPM2_SetAuthHandle(&dev, 1, &nvIndexAuth);

        rc = wolfTPM2_NVDeleteAuth(&dev, &owner, nvIndex);
        if (rc != TPM_RC_SUCCESS) {
            printf("Failed to delete NV index: 0x%x\n", rc);
            goto cleanup;
        }
        printf("Deleted NV index 0x%x\n", nvIndex);
    }

cleanup:

    if (rc != 0) {
        printf("\nFailure 0x%x: %s\n\n", rc, wolfTPM2_GetRCString(rc));
    }

    wolfTPM2_UnsetAuth(&dev, 0);
    if (paramEncAlg != TPM_ALG_NULL) {
        wolfTPM2_UnloadHandle(&dev, &session.handle);
    }
    wolfTPM2_Cleanup(&dev);

    return rc;
}

/******************************************************************************/
/* --- END TPM NVRAM Auth Example -- */
/******************************************************************************/
#endif /* !WOLFTPM2_NO_WRAPPER */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = NOT_COMPILED_IN;

#ifndef WOLFTPM2_NO_WRAPPER
    rc = TPM2_NVRAM_Auth_Example(NULL, argc, argv);
#else
    printf("NVRAM code not compiled in\n");
    (void)argc;
    (void)argv;
#endif

    return rc;
}
#endif

