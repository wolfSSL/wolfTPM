/* create_primary.c
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

/* Tool and example for creating and storing primary keys using TPM2.0 */

#include <wolftpm/tpm2_wrap.h>

#include <stdio.h>

#ifndef WOLFTPM2_NO_WRAPPER

#include <examples/keygen/keygen.h>
#include <hal/tpm_io.h>
#include <examples/tpm_test.h>
#include <examples/tpm_test_keys.h>

/******************************************************************************/
/* --- BEGIN TPM Create Primary Key Example -- */
/******************************************************************************/
static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/keygen/create_primary [-ecc/-rsa] [-oh/-eh/-ph] "
                                  "[-unique=] [-auth=] [-aes/-xor] [-store=]\n");
    printf("Primary Key Type:\n");
    printf("\t-rsa: Use RSA for asymmetric key generation (DEFAULT)\n");
    printf("\t-ecc: Use ECC for asymmetric key generation \n");
    printf("Hierarchy:\n");
    printf("\t-oh: Create keys under the Owner Hierarchy (DEFAULT)\n");
    printf("\t-eh: Create keys under the Endorsement Hierarchy\n");
    printf("\t-ph: Create keys under the Platform Hierarchy\n");
    printf("Unique Template:\n");
    printf("\t-unique=[value]\n");
    printf("\t\tOptional unique value for the KDF of the create\n");
    printf("Authentication:\n");
    printf("\t-auth=[value]\n");
    printf("\t\tOptional authentication string for primary\n");
    printf("Parameter Encryption:\n");
    printf("\t-aes: Use AES CFB parameter encryption\n");
    printf("\t-xor: Use XOR parameter obfuscation\n");
    printf("NV Storage:\n");
    printf("\t-store=[handle]\n");
    printf("\t\tPersistent primary key handle range: 0x81000000 - 0x810FFFF\n");
    printf("\t\tUse leading 0x for hex\n");

    printf("Example usage:\n");
    printf("\t* Create SRK used by wolfTPM:\n");
    printf("\t\tcreate_primary -rsa -oh -auth=ThisIsMyStorageKeyAuth "
                                       "-store=0x81000200\n");
}

int TPM2_CreatePrimaryKey_Example(void* userCtx, int argc, char *argv[])
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY primary;
    TPMT_PUBLIC publicTemplate;
    TPMI_ALG_PUBLIC alg = TPM_ALG_RSA;
    TPM_ALG_ID paramEncAlg = TPM_ALG_NULL;
    TPM_RH hierarchy = TPM_RH_OWNER;
    WOLFTPM2_SESSION tpmSession;
    const char* uniqueStr = NULL;
    const char* authStr = NULL;
    word32 persistHandle = 0;

    if (argc >= 2) {
        if (XSTRCMP(argv[1], "-?") == 0 ||
            XSTRCMP(argv[1], "-h") == 0 ||
            XSTRCMP(argv[1], "--help") == 0) {
            usage();
            return 0;
        }
    }
    while (argc > 1) {
        if (XSTRCMP(argv[argc-1], "-rsa") == 0) {
            alg = TPM_ALG_RSA;
        }
        else if (XSTRCMP(argv[argc-1], "-ecc") == 0) {
            alg = TPM_ALG_ECC;
        }
        else if (XSTRCMP(argv[argc-1], "-aes") == 0) {
            paramEncAlg = TPM_ALG_CFB;
        }
        else if (XSTRCMP(argv[argc-1], "-xor") == 0) {
            paramEncAlg = TPM_ALG_XOR;
        }
        else if (XSTRCMP(argv[argc-1], "-eh") == 0) {
            hierarchy = TPM_RH_ENDORSEMENT;
        }
        else if (XSTRCMP(argv[argc-1], "-ph") == 0) {
            hierarchy = TPM_RH_PLATFORM;
        }
        else if (XSTRCMP(argv[argc-1], "-oh") == 0) {
            hierarchy = TPM_RH_OWNER;
        }
        else if (XSTRCMP(argv[argc-1], "-unique=") == 0) {
            uniqueStr = argv[argc-1] + 8;
        }
        else if (XSTRCMP(argv[argc-1], "-auth=") == 0) {
            authStr = argv[argc-1] + 6;
        }
        else if (XSTRNCMP(argv[argc-1], "-store=", XSTRLEN("-store=")) == 0) {
            persistHandle = (word32)XSTRTOL(argv[argc-1] + XSTRLEN("-store="),
                NULL, 0);
            if (persistHandle < 0x81000000 && persistHandle > 0x810FFFF) {
                printf("Invalid storage handle %s\n", argv[argc-1] + 7);
                persistHandle = 0;
            }
        }
        else {
            printf("Warning: Unrecognized option: %s\n", argv[argc-1]);
        }

        argc--;
    }

    XMEMSET(&primary, 0, sizeof(primary));
    XMEMSET(&tpmSession, 0, sizeof(tpmSession));

    printf("TPM2.0 Primary Key generation example\n");
    printf("\tAlgorithm: %s\n", TPM2_GetAlgName(alg));
    if (uniqueStr != NULL) {
        printf("\tUnique: %s\n", uniqueStr);
    }
    if (authStr != NULL) {
        printf("\tAuth: %s\n", authStr);
    }
    printf("\tStore Handle: 0x%08x\n", persistHandle);
    printf("\tUse Parameter Encryption: %s\n", TPM2_GetAlgName(paramEncAlg));

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("\nwolfTPM2_Init failed\n");
        goto exit;
    }

    /* See if handle already exists */
    if (persistHandle > 0) {
        if (wolfTPM2_ReadPublicKey(&dev, &primary, persistHandle) == 0) {
            printf("Primary Handle 0x%08x already exists\n", persistHandle);
            goto exit;
        }
    }

    /* Supported algorithms for primary key are only RSA 2048-bit & ECC P256 */
    if (alg == TPM_ALG_RSA) {
        rc = wolfTPM2_GetKeyTemplate_RSA_SRK(&publicTemplate);
    }
    else if (alg == TPM_ALG_ECC) {
        rc = wolfTPM2_GetKeyTemplate_ECC_SRK(&publicTemplate);
    }
    else {
        rc = BAD_FUNC_ARG;
    }
    if (rc != TPM_RC_SUCCESS) goto exit;

    if (paramEncAlg != TPM_ALG_NULL) {
        /* Start an authenticated session (salted / unbound) with parameter encryption */
        rc = wolfTPM2_StartSession(&dev, &tpmSession, NULL, NULL,
            TPM_SE_HMAC, paramEncAlg);
        if (rc != TPM_RC_SUCCESS) goto exit;
        printf("TPM2_StartAuthSession: sessionHandle 0x%x\n",
            (word32)tpmSession.handle.hndl);

        /* set session for authorization of the primary key */
        rc = wolfTPM2_SetAuthSession(&dev, 0, &tpmSession,
            (TPMA_SESSION_decrypt | TPMA_SESSION_encrypt | TPMA_SESSION_continueSession));
        if (rc != TPM_RC_SUCCESS) goto exit;
    }

    /* optionally set a unique field */
    if (uniqueStr != NULL) {
        rc = wolfTPM2_SetKeyTemplate_Unique(&publicTemplate,
            (const byte*)uniqueStr, (int)XSTRLEN(uniqueStr));
        if (rc != TPM_RC_SUCCESS) goto exit;
    }

    printf("Creating new %s primary key...\n", TPM2_GetAlgName(alg));

    rc = wolfTPM2_CreatePrimaryKey(&dev, &primary, hierarchy, &publicTemplate,
        (const byte*)authStr, authStr ? (int)XSTRLEN(authStr) : 0);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_CreatePrimaryKey failed\n");
        goto exit;
    }

#ifdef DEBUG_WOLFTPM
    printf("Primary Key Public (%d bytes)\n", primary.pub.size);
    TPM2_PrintBin((const byte*)&primary.pub.publicArea, primary.pub.size);
#endif

    if (persistHandle > 0) {
    #ifndef WOLFTPM_WINAPI
        /* Move storage key into persistent NV */
        printf("Storing Primary key to handle 0x%08x\n", persistHandle);
        rc = wolfTPM2_NVStoreKey(&dev, hierarchy, &primary,
            persistHandle);
        if (rc != TPM_RC_SUCCESS) goto exit;
    #else
        printf("Windows TBS does not allow persisting handles to "
               "Non-Volatile (NV) Memory\n");
    #endif
    }

exit:

    if (rc != 0) {
        printf("\nFailure 0x%x: %s\n\n", rc, wolfTPM2_GetRCString(rc));
    }

    /* Close handles */
    wolfTPM2_UnloadHandle(&dev, &primary.handle);
    if (paramEncAlg != TPM_ALG_NULL) {
        wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);
    }

    wolfTPM2_Cleanup(&dev);
    return rc;
}

/******************************************************************************/
/* --- END TPM Create Primary Key Example -- */
/******************************************************************************/
#endif /* !WOLFTPM2_NO_WRAPPER */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = NOT_COMPILED_IN;

#ifndef WOLFTPM2_NO_WRAPPER
    rc = TPM2_CreatePrimaryKey_Example(NULL, argc, argv);
#else
    printf("Create Primary key code not compiled in\n");
    (void)argc;
    (void)argv;
#endif

    return rc;
}
#endif
