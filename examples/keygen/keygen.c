/* keygen.c
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

/* Tool and example for creating, storing and loading keys using TPM2.0 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2_wrap.h>

#include <stdio.h>

#ifndef WOLFTPM2_NO_WRAPPER

#include <examples/keygen/keygen.h>
#include <hal/tpm_io.h>
#include <examples/tpm_test.h>
#include <examples/tpm_test_keys.h>

/* Output file path defines with defaults */
#ifndef OUTPUT_FILE
    #define OUTPUT_FILE "keyblob.bin"
#endif
#ifndef EK_PUB_FILE
    #define EK_PUB_FILE "ek.pub"
#endif
#ifndef SRK_PUB_FILE
    #define SRK_PUB_FILE "srk.pub"
#endif

#if !defined(NO_FILESYSTEM) && !defined(NO_WRITE_TEMP_FILES)
    #ifndef AK_NAME_FILE
        #define AK_NAME_FILE "ak.name"
    #endif
    #if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_ASN)
        /* PEM_FILE is NULL by default, but can be overridden */
        #ifndef PEM_FILE
            #define PEM_FILE NULL
        #endif
    #endif
#endif

/******************************************************************************/
/* --- BEGIN TPM Keygen Example -- */
/******************************************************************************/
static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/keygen/keygen [keyblob.bin] [-ecc/-rsa/-sym] [-t] [-aes/xor] [-eh] [-pem] [-auth=pass]\n");
    printf("* -pem: Store the primary and child public keys as PEM formatted files\n");
    printf("\t child public key filename: ak.pem or key.pem\n");
    printf("\t primary public key filename: ek.pem or srk.pem\n");
    printf("* -eh: Create keys under the Endorsement Hierarchy (EK)\n");
    printf("* -rsa: Use RSA for asymmetric key generation (DEFAULT)\n");
    printf("* -ecc: Use ECC for asymmetric key generation \n");
    printf("* -sym: Use Symmetric Cipher for key generation\n");
    printf("\tDefault Symmetric Cipher is AES CTR with 256 bits\n");
    printf("* -keyedhash: Use Keyed Hash for key generation\n");
    printf("* -t: Use default template (otherwise AIK)\n");
    printf("* -aes/xor: Use Parameter Encryption\n");
    printf("* -unique=[value]\n");
    printf("\t* Used for the KDF of the create\n");
    printf("* -auth=pass: Use custom password for key authentication\n");
    printf("\t* If not specified, default key auth is used\n");

    printf("Example usage:\n");
    printf("\t* RSA, default template\n");
    printf("\t\t keygen -t\n");
    printf("\t* ECC, Attestation Key template "\
           "with AES CFB parameter encryption\n");
    printf("\t\t keygen -ecc -aes\n");
    printf("\t* Symmetric key, AES, CTR mode, 128 bits\n");
    printf("\t\t keygen -sym=aesctr128\n");
    printf("\t* Symmetric key, AES, CFB mode, 256 bits\n");
    printf("\t\t keygen -sym=aescfb256\n");
    printf("\t* Symmetric key, AES, CBC mode, 128 bits, "\
           "with XOR parameter encryption\n");
    printf("\t\t keygen -sym=aescbc256 -xor\n");
}

static int symChoice(const char* symMode, TPM_ALG_ID* algSym, int* keyBits)
{
    if (XSTRNCMP(symMode, "aescfb", 6) == 0) {
        *algSym = TPM_ALG_CFB;
    }
    else if (XSTRNCMP(symMode, "aesctr", 6) == 0) {
        *algSym = TPM_ALG_CTR;
    }
    else if (XSTRNCMP(symMode, "aescbc", 6) == 0) {
        *algSym = TPM_ALG_CBC;
    }
    else {
        return TPM_RC_FAILURE;
    }

    *keyBits = XATOI(&symMode[6]);
    if (*keyBits != 128 && *keyBits != 192 && *keyBits != 256) {
        return TPM_RC_FAILURE;
    }

    return TPM_RC_SUCCESS;
}

int TPM2_Keygen_Example(void* userCtx, int argc, char *argv[])
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY endorse; /* EK */
    WOLFTPM2_KEY storage; /* SRK */
    WOLFTPM2_KEY *primary = NULL;
    WOLFTPM2_KEY aesKey; /* Symmetric key */
    WOLFTPM2_KEYBLOB newKeyBlob; /* newKey as WOLFTPM2_KEYBLOB */
    WOLFTPM2_KEYBLOB primaryBlob; /* Primary key as WOLFTPM2_KEYBLOB */
    TPMT_PUBLIC publicTemplate;
    TPMI_ALG_PUBLIC alg = TPM_ALG_RSA; /* default, see usage() for options */
    TPMI_ALG_PUBLIC srkAlg = TPM_ALG_ECC; /* prefer ECC, but allow RSA */
    TPM_ALG_ID algSym = TPM_ALG_CTR; /* default Symmetric Cipher, see usage */
    TPM_ALG_ID paramEncAlg = TPM_ALG_NULL;
    WOLFTPM2_SESSION tpmSession;
    TPM2B_AUTH auth;
    int endorseKey = 0;
    int pemFiles = 0;
    int bAIK = 1;
    int keyBits = 256;
    const char* uniqueStr = NULL;
    const char* authStr = NULL;
    const char *outputFile = OUTPUT_FILE;
    const char *ekPubFile = EK_PUB_FILE;
    const char *srkPubFile = SRK_PUB_FILE;
    const char *pubFilename = NULL;
#if !defined(NO_FILESYSTEM) && !defined(NO_WRITE_TEMP_FILES)
    const char *nameFile = AK_NAME_FILE; /* Name Digest for attestation purposes */
    #if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_ASN)
    const char *pemFilename = PEM_FILE;
    #endif
#endif
    const char* symMode = "aesctr";

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
        else if (XSTRNCMP(argv[argc-1], "-sym=", XSTRLEN("-sym=")) == 0) {
            symMode = argv[argc-1] + XSTRLEN("-sym=");
            alg = TPM_ALG_SYMCIPHER;
            bAIK = 0;
        }
        else if (XSTRCMP(argv[argc-1], "-sym") == 0) {
            alg = TPM_ALG_SYMCIPHER;
            bAIK = 0;
        }
        else if (XSTRCMP(argv[argc-1], "-keyedhash") == 0) {
            alg = TPM_ALG_KEYEDHASH;
            bAIK = 0;
        }
        else if (XSTRCMP(argv[argc-1], "-t") == 0) {
            bAIK = 0;
        }
        else if (XSTRCMP(argv[argc-1], "-eh") == 0) {
            endorseKey = 1;
        }
        else if (XSTRCMP(argv[argc-1], "-pem") == 0) {
            pemFiles = 1;
        }
        else if (XSTRCMP(argv[argc-1], "-aes") == 0) {
            paramEncAlg = TPM_ALG_CFB;
        }
        else if (XSTRCMP(argv[argc-1], "-xor") == 0) {
            paramEncAlg = TPM_ALG_XOR;
        }
        else if (XSTRNCMP(argv[argc-1], "-unique=", XSTRLEN("-unique=")) == 0) {
            uniqueStr = argv[argc-1] + XSTRLEN("-unique=");
        }
        else if (XSTRNCMP(argv[argc-1], "-auth=", XSTRLEN("-auth=")) == 0) {
            authStr = argv[argc-1] + XSTRLEN("-auth=");
        }
        else if (argv[argc-1][0] != '-') {
            outputFile = argv[argc-1];
        }
        else {
            printf("Warning: Unrecognized option: %s\n", argv[argc-1]);
        }

        argc--;
    }

    XMEMSET(&endorse, 0, sizeof(endorse));
    XMEMSET(&storage, 0, sizeof(storage));
    XMEMSET(&aesKey, 0, sizeof(aesKey));
    XMEMSET(&newKeyBlob, 0, sizeof(newKeyBlob));
    XMEMSET(&primaryBlob, 0, sizeof(primaryBlob));
    XMEMSET(&tpmSession, 0, sizeof(tpmSession));
    XMEMSET(&auth, 0, sizeof(auth));

    if (alg == TPM_ALG_RSA)
        srkAlg = TPM_ALG_RSA;
    if (alg == TPM_ALG_SYMCIPHER) {
        rc = symChoice(symMode, &algSym, &keyBits);
        if (rc != TPM_RC_SUCCESS) {
            usage();
            return 0;
        }
    }

    printf("TPM2.0 Key generation example\n");
    printf("\tKey Blob: %s\n", outputFile);
    printf("\tAlgorithm: %s\n", TPM2_GetAlgName(alg));
    if (alg == TPM_ALG_SYMCIPHER) {
        printf("\t\t %s mode, %d keybits\n", symMode, keyBits);
    }
    printf("\tTemplate: %s\n", bAIK ? "AIK" : "Default");
    printf("\tSRK: %s\n", TPM2_GetAlgName(srkAlg));
    printf("\tUse Parameter Encryption: %s\n", TPM2_GetAlgName(paramEncAlg));

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("\nwolfTPM2_Init failed\n");
        goto exit;
    }

    if (endorseKey) {
        /* endorsement key (EK) */
        rc = wolfTPM2_CreateEK(&dev, &endorse, srkAlg);
        endorse.handle.policyAuth = 1; /* EK requires Policy auth, not Password */
        pubFilename = ekPubFile;
        primary = &endorse;
    }
    else {
        /* storage root key (SRK) */
        rc = getPrimaryStoragekey(&dev, &storage, srkAlg);
        pubFilename = srkPubFile;
        primary = &storage;
    }
    if (rc != 0) goto exit;

    if (paramEncAlg != TPM_ALG_NULL) {
        WOLFTPM2_KEY* bindKey = primary;
    #ifndef HAVE_ECC
        if (srkAlg == TPM_ALG_ECC)
            bindKey = NULL; /* cannot bind to key without ECC enabled */
    #endif
    #ifdef NO_RSA
        if (srkAlg == TPM_ALG_RSA)
            bindKey = NULL; /* cannot bind to key without RSA enabled */
    #endif
        /* Start an authenticated session (salted / unbound) with parameter encryption */
        rc = wolfTPM2_StartSession(&dev, &tpmSession, bindKey, NULL,
            TPM_SE_HMAC, paramEncAlg);
        if (rc != 0) goto exit;
        printf("HMAC Session: Handle 0x%x\n",
            (word32)tpmSession.handle.hndl);

        /* set session for authorization of the primary key */
        rc = wolfTPM2_SetAuthSession(&dev, 1, &tpmSession,
            (TPMA_SESSION_decrypt | TPMA_SESSION_encrypt |
             TPMA_SESSION_continueSession));
        if (rc != 0) goto exit;
    }

    if (endorseKey) {
        /* Endorsement Key requires authorization with Policy */
        rc = wolfTPM2_CreateAuthSession_EkPolicy(&dev, &tpmSession);
        if (rc != 0) goto exit;
        printf("EK Policy Session: Handle 0x%x\n",
            (word32)tpmSession.handle.hndl);

        /* Set the created Policy Session for use in next operation */
        rc = wolfTPM2_SetAuthSession(&dev, 0, &tpmSession, 0);
        if (rc != 0) goto exit;
    }

    /* Create new key */
    if (bAIK) {
        if (alg == TPM_ALG_RSA) {
            printf("RSA AIK template\n");
            rc = wolfTPM2_GetKeyTemplate_RSA_AIK(&publicTemplate);
        }
        else if (alg == TPM_ALG_ECC) {
            printf("ECC AIK template\n");
            rc = wolfTPM2_GetKeyTemplate_ECC_AIK(&publicTemplate);
        }
        else if (alg == TPM_ALG_SYMCIPHER || alg == TPM_ALG_KEYEDHASH) {
            printf("AIK are expected to be RSA or ECC only, "
                "not symmetric or keyedhash keys.\n");
            rc = BAD_FUNC_ARG;
        }
        else {
            rc = BAD_FUNC_ARG;
        }
        if (rc != 0) goto exit;

        /* set session for authorization key */
        if (authStr != NULL) {
            /* Use provided custom auth */
            auth.size = (int)XSTRLEN(authStr);
            XMEMCPY(auth.buffer, authStr, auth.size);
        }
        else {
            auth.size = (int)sizeof(gAiKeyAuth)-1;
            XMEMCPY(auth.buffer, gAiKeyAuth, auth.size);
        }
    }
    else {
        if (alg == TPM_ALG_RSA) {
            printf("RSA template\n");
            rc = wolfTPM2_GetKeyTemplate_RSA(&publicTemplate,
                     TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
                     TPMA_OBJECT_decrypt | TPMA_OBJECT_sign | TPMA_OBJECT_noDA);
        }
        else if (alg == TPM_ALG_ECC) {
            printf("ECC template\n");
            rc = wolfTPM2_GetKeyTemplate_ECC(&publicTemplate,
                     TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
                     TPMA_OBJECT_sign | TPMA_OBJECT_noDA,
                     TPM_ECC_NIST_P256, TPM_ALG_ECDSA);
        }
        else if (alg == TPM_ALG_SYMCIPHER) {
            printf("Symmetric template\n");
            rc = wolfTPM2_GetKeyTemplate_Symmetric(&publicTemplate, keyBits,
                    algSym, YES, YES);
        }
        else if (alg == TPM_ALG_KEYEDHASH) {
            printf("Keyed Hash template\n");
            rc = wolfTPM2_GetKeyTemplate_KeyedHash(&publicTemplate,
                TPM_ALG_SHA256, YES, NO);
            publicTemplate.objectAttributes |= TPMA_OBJECT_sensitiveDataOrigin;
        }
        else {
            rc = BAD_FUNC_ARG;
        }

        /* set session for authorization key */
        if (authStr != NULL) {
            /* Use provided custom auth key */
            auth.size = (int)XSTRLEN(authStr);
            XMEMCPY(auth.buffer, authStr, auth.size);
        }
        else {
            auth.size = (int)sizeof(gKeyAuth)-1;
            XMEMCPY(auth.buffer, gKeyAuth, auth.size);
        }
    }
    if (rc != 0) goto exit;

    /* optionally set a unique field */
    if (uniqueStr != NULL) {
        rc = wolfTPM2_SetKeyTemplate_Unique(&publicTemplate, (byte*)uniqueStr,
            (int)XSTRLEN(uniqueStr));
        if (rc != 0) goto exit;
    }

    printf("Creating new %s key...\n", TPM2_GetAlgName(alg));

    rc = wolfTPM2_CreateKey(&dev, &newKeyBlob, &primary->handle,
                            &publicTemplate, auth.buffer, auth.size);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_CreateKey failed\n");
        goto exit;
    }
    if (endorseKey) {
        /* Endorsement policy session is closed after use, so start another */
        rc = wolfTPM2_CreateAuthSession_EkPolicy(&dev, &tpmSession);
        if (rc == 0) {
            rc = wolfTPM2_SetAuthSession(&dev, 0, &tpmSession, 0);
        }
        if (rc != 0) goto exit;
    }
    rc = wolfTPM2_LoadKey(&dev, &newKeyBlob, &primary->handle);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_LoadKey failed\n");
        goto exit;
    }
    if (endorseKey) {
        /* The policy session is closed after use.
         * Reset handle, so we don't try and free it */
        tpmSession.handle.hndl = TPM_RH_NULL;
    }

    printf("New key created and loaded (pub %d, priv %d bytes)\n",
        newKeyBlob.pub.size, newKeyBlob.priv.size);

    /* Save key as encrypted blob to the disk */
#if !defined(NO_FILESYSTEM) && !defined(NO_WRITE_TEMP_FILES)
    rc = writeKeyBlob(outputFile, &newKeyBlob);
    /* Generate key artifacts needed for remote attestation */
    if (bAIK) {
        /* Store primary public key */
        XMEMCPY(&primaryBlob.pub, &primary->pub, sizeof(primaryBlob.pub));
        rc |= writeKeyBlob(pubFilename, &primaryBlob);

        /* Write AK's Name digest */
        rc |= writeBin(nameFile, (byte*)&newKeyBlob.handle.name,
            sizeof(newKeyBlob.handle.name));
        printf("Wrote AK Name digest\n");
    }
    if (rc != TPM_RC_SUCCESS) goto exit;
#else
    if (alg == TPM_ALG_SYMCIPHER) {
        printf("The Public Part of a symmetric key contains only meta data\n");
    }
    printf("Key Public Blob %d\n", newKeyBlob.pub.size);
    TPM2_PrintBin((const byte*)&newKeyBlob.pub.publicArea, newKeyBlob.pub.size);
    printf("Key Private Blob %d\n", newKeyBlob.priv.size);
    TPM2_PrintBin(newKeyBlob.priv.buffer, newKeyBlob.priv.size);
#endif

    /* Save EK public key as PEM format file to the disk */
#if !defined(NO_FILESYSTEM) && !defined(NO_WRITE_TEMP_FILES) && \
    !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_ASN)
    if (pemFiles) {
        byte pem[MAX_RSA_KEY_BYTES];
        word32 pemSz;

        pemFilename = (endorseKey) ? pemFileEk : pemFileSrk;
        pemSz = (word32)sizeof(pem);
        rc = wolfTPM2_ExportPublicKeyBuffer(&dev, primary,
            ENCODING_TYPE_PEM, pem, &pemSz);
        if (rc == 0) {
            rc = writeBin(pemFilename, pem, pemSz);
        }
        if (rc != 0) goto exit;

        pemFilename = (bAIK) ? pemFileAk : pemFileKey;
        pemSz = (word32)sizeof(pem);
        rc = wolfTPM2_ExportPublicKeyBuffer(&dev, (WOLFTPM2_KEY*)&newKeyBlob,
            ENCODING_TYPE_PEM, pem, &pemSz);
        if (rc == 0) {
            rc = writeBin(pemFilename, pem, pemSz);
        }
        wolfTPM2_UnloadHandle(&dev, &newKeyBlob.handle);

    #if 0
        /* example for loading public pem to TPM */
        rc = wolfTPM2_RsaKey_PubPemToTpm(&dev, (WOLFTPM2_KEY*)&newKeyBlob, pem, pemSz);
        printf("wolfTPM2_RsaKey_PubPemToTpm rc=%d\n", rc);
        rc = 0;
    #endif
    }
#else
    (void)pemFiles;
    (void)pubFilename;
    printf("Unable to store EK pub as PEM file. Lack of file support\n");
#endif

exit:

    if (rc != 0) {
        printf("\nFailure 0x%x: %s\n\n", rc, wolfTPM2_GetRCString(rc));
    }

    /* Close handles */
    wolfTPM2_UnloadHandle(&dev, &primary->handle);
    wolfTPM2_UnloadHandle(&dev, &newKeyBlob.handle);
    wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);

    wolfTPM2_Cleanup(&dev);
    return rc;
}

/******************************************************************************/
/* --- END TPM Keygen Example -- */
/******************************************************************************/
#endif /* !WOLFTPM2_NO_WRAPPER */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = NOT_COMPILED_IN;

#ifndef WOLFTPM2_NO_WRAPPER
    rc = TPM2_Keygen_Example(NULL, argc, argv);
#else
    printf("KeyGen code not compiled in\n");
    (void)argc;
    (void)argv;
#endif

    return rc;
}
#endif
