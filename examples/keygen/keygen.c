/* keygen.c
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

/* Tool and example for creating, storing and loading keys using TPM2.0 */

#include <wolftpm/tpm2_wrap.h>

#include <examples/keygen/keygen.h>
#include <examples/tpm_io.h>
#include <examples/tpm_test.h>
#include <examples/tpm_test_keys.h>

#include <stdio.h>
#include <stdlib.h> /* atoi */

#ifndef WOLFTPM2_NO_WRAPPER

#define SYM_EXTRA_OPTS_LEN 14 /* 5 chars for "-sym=" and 9 for extra options */
#define SYM_EXTRA_OPTS_POS 4  /* Array pos of the equal sign for extra opts */
#define SYM_EXTRA_OPTS_AES_MODE_POS 8
#define SYM_EXTRA_OPTS_KEY_BITS_POS 11



/******************************************************************************/
/* --- BEGIN TPM Keygen Example -- */
/******************************************************************************/
static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/keygen/keygen [keyblob.bin] [-ecc/-rsa/-sym] [-t] [-aes/xor] [-eh] [-pem]\n");
    printf("* -pem: Store the primary and child public keys as PEM formated files\n");
    printf("\t child public key filename: ak.pem or key.pem\n");
    printf("\t primary public key filename: ek.pem or srk.pem\n");
    printf("* -eh: Create keys under the Endorsement Hierarchy (EK)\n");
    printf("* -rsa: Use RSA for asymmetric key generation (DEFAULT)\n");
    printf("* -ecc: Use ECC for asymmetric key generation \n");
    printf("* -sym: Use Symmetric Cypher for key generation\n");
    printf("\tDefault Symmetric Cypher is AES CTR with 256 bits\n");
    printf("* -t: Use default template (otherwise AIK)\n");
    printf("* -aes/xor: Use Parameter Encryption\n");
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

static int symChoice(const char* arg, TPM_ALG_ID* algSym, int* keyBits,
                     char* symMode)
{
    size_t len = XSTRLEN(arg);

    if (len != SYM_EXTRA_OPTS_LEN) {
        return TPM_RC_FAILURE;
    }
    if (XSTRNCMP(&arg[SYM_EXTRA_OPTS_POS+1], "aes", 3)) {
        return TPM_RC_FAILURE;
    }

    /* Copy string for user information later */
    XMEMCPY(symMode, &arg[SYM_EXTRA_OPTS_POS+1], 6);

    if (XSTRNCMP(&arg[SYM_EXTRA_OPTS_AES_MODE_POS], "cfb", 3) == 0) {
        *algSym = TPM_ALG_CFB;
    }
    else if (XSTRNCMP(&arg[SYM_EXTRA_OPTS_AES_MODE_POS], "ctr", 3) == 0) {
        *algSym = TPM_ALG_CTR;
    }
    else if (XSTRNCMP(&arg[SYM_EXTRA_OPTS_AES_MODE_POS], "cbc", 3) == 0) {
        *algSym = TPM_ALG_CBC;
    }
    else {
        return TPM_RC_FAILURE;
    }

    *keyBits = atoi(&arg[SYM_EXTRA_OPTS_KEY_BITS_POS]);
    if(*keyBits != 128 && *keyBits != 192 && *keyBits != 256) {
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
    WOLFTPM2_KEY newKey; /* child or attestation key */
    WOLFTPM2_KEYBLOB newKeyBlob; /* newKey as WOLFTPM2_KEYBLOB */
    WOLFTPM2_KEYBLOB primaryBlob; /* Primary key as WOLFTPM2_KEYBLOB */
    TPMT_PUBLIC publicTemplate;
    TPMI_ALG_PUBLIC alg = TPM_ALG_RSA; /* default, see usage() for options */
    TPM_ALG_ID algSym = TPM_ALG_CTR; /* default Symmetric Cypher, see usage */
    TPM_ALG_ID paramEncAlg = TPM_ALG_NULL;
    WOLFTPM2_SESSION tpmSession;
    TPM2B_AUTH auth;
    int endorseKey = 0;
    int pemFiles = 0;
    int bAIK = 1;
    int keyBits = 256;
    const char *outputFile = "keyblob.bin";
    const char *nameFile = "ak.name"; /* Name Digest for attestation purposes */
    const char *ekPubFile = "ek.pub";
    const char *srkPubFile = "srk.pub";
    const char *pubFilename = NULL;
    const char *pemFilename = NULL;
    size_t len = 0;
    char symMode[] = "aesctr";
    FILE *fp;

    if (argc >= 2) {
        if (XSTRNCMP(argv[1], "-?", 2) == 0 ||
            XSTRNCMP(argv[1], "-h", 2) == 0 ||
            XSTRNCMP(argv[1], "--help", 6) == 0) {
            usage();
            return 0;
        }
        if (argv[1][0] != '-')
            outputFile = argv[1];
    }
    while (argc > 1) {
        if (XSTRNCMP(argv[argc-1], "-rsa", 4) == 0) {
            alg = TPM_ALG_RSA;
        }
        if (XSTRNCMP(argv[argc-1], "-ecc", 4) == 0) {
            alg = TPM_ALG_ECC;
        }
        if (XSTRNCMP(argv[argc-1], "-sym", 4) == 0) {
            len = XSTRLEN(argv[argc-1]);
            if (len >= SYM_EXTRA_OPTS_LEN) {
                /* Did the user provide specific options? */
                if (argv[argc-1][SYM_EXTRA_OPTS_POS] == '=') {
                    rc = symChoice(argv[argc-1], &algSym, &keyBits, symMode);
                    /* In case of incorrect extra options, abort execution */
                    if (rc != TPM_RC_SUCCESS) {
                        usage();
                        return 0;
                    }
                }
                /* Otherwise, defaults are used: AES CTR, 256 key bits */
            }
            alg = TPM_ALG_SYMCIPHER;
            bAIK = 0;
        }
        if (XSTRNCMP(argv[argc-1], "-t", 2) == 0) {
            bAIK = 0;
        }
        if (XSTRNCMP(argv[argc-1], "-eh", 3) == 0) {
            endorseKey = 1;
        }
        if (XSTRNCMP(argv[argc-1], "-pem", 4) == 0) {
            pemFiles = 1;
        }
        if (XSTRNCMP(argv[argc-1], "-aes", 4) == 0) {
            paramEncAlg = TPM_ALG_CFB;
        }
        if (XSTRNCMP(argv[argc-1], "-xor", 4) == 0) {
            paramEncAlg = TPM_ALG_XOR;
        }
        argc--;
    }

    XMEMSET(&endorse, 0, sizeof(endorse));
    XMEMSET(&storage, 0, sizeof(storage));
    XMEMSET(&aesKey, 0, sizeof(aesKey));
    XMEMSET(&newKey, 0, sizeof(newKey));
    XMEMSET(&newKeyBlob, 0, sizeof(newKeyBlob));
    XMEMSET(&primaryBlob, 0, sizeof(primaryBlob));
    XMEMSET(&tpmSession, 0, sizeof(tpmSession));
    XMEMSET(&auth, 0, sizeof(auth));

    printf("TPM2.0 Key generation example\n");
    printf("\tKey Blob: %s\n", outputFile);
    printf("\tAlgorithm: %s\n", TPM2_GetAlgName(alg));
    if(alg == TPM_ALG_SYMCIPHER) {
        printf("\t\t %s mode, %d keybits\n", symMode, keyBits);
    }
    printf("\tTemplate: %s\n", bAIK ? "AIK" : "Default");
    printf("\tUse Parameter Encryption: %s\n", TPM2_GetAlgName(paramEncAlg));

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("\nwolfTPM2_Init failed\n");
        goto exit;
    }

    if(endorseKey) {
        rc = wolfTPM2_CreateEK(&dev, &endorse, TPM_ALG_RSA);
        endorse.handle.policyAuth = 1; /* EK requires Policy auth, not Password */
        pubFilename = ekPubFile;
        primary = &endorse;
    }
    else {
        /* get SRK */
        rc = getPrimaryStoragekey(&dev, &storage, TPM_ALG_RSA);
        pubFilename = srkPubFile;
        primary = &storage;
    }
    if (rc != 0) goto exit;

    if (paramEncAlg != TPM_ALG_NULL) {
        /* Start an authenticated session (salted / unbound) with parameter encryption */
        rc = wolfTPM2_StartSession(&dev, &tpmSession, primary, NULL,
            TPM_SE_HMAC, paramEncAlg);
        if (rc != 0) goto exit;
        printf("TPM2_StartAuthSession: sessionHandle 0x%x\n",
            (word32)tpmSession.handle.hndl);

        /* set session for authorization of the primary key */
        rc = wolfTPM2_SetAuthSession(&dev, 1, &tpmSession,
            (TPMA_SESSION_decrypt | TPMA_SESSION_encrypt | TPMA_SESSION_continueSession));
        if (rc != 0) goto exit;
    }

    if (endorseKey) {
        /* Endorsement Key requires authorization with Policy */
        wolfTPM2_CreateAuthSession_EkPolicy(&dev, &tpmSession);
        /* Set the created Policy Session for use in next operation */
        wolfTPM2_SetAuthSession(&dev, 0, &tpmSession, 0);
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
        else if (alg == TPM_ALG_SYMCIPHER) {
            printf("AIK are expected to be RSA or ECC, not symmetric keys.\n");
            rc = BAD_FUNC_ARG;
        }
        else {
            rc = BAD_FUNC_ARG;
        }

        /* set session for authorization key */
        auth.size = (int)sizeof(gAiKeyAuth)-1;
        XMEMCPY(auth.buffer, gAiKeyAuth, auth.size);

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
        else {
            rc = BAD_FUNC_ARG;
        }

        /* set session for authorization key */
        auth.size = (int)sizeof(gKeyAuth)-1;
        XMEMCPY(auth.buffer, gKeyAuth, auth.size);
    }
    if (rc != 0) goto exit;

    printf("Creating new %s key...\n", TPM2_GetAlgName(alg));
    rc = wolfTPM2_CreateLoadedKey(&dev, &newKeyBlob, &primary->handle,
                            &publicTemplate, auth.buffer, auth.size);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_CreateLoadedKey failed\n");
        goto exit;
    }
    printf("New key created and loaded (pub %d, priv %d bytes)\n",
        newKeyBlob.pub.size, newKeyBlob.priv.size);

    /* Save key as encrypted blob to the disk */
#if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_FILESYSTEM)
    rc = writeKeyBlob(outputFile, &newKeyBlob);
    /* Generate key artifacts needed for remote attestation */
    if (bAIK) {
        /* Store primary public key */
        XMEMCPY(&primaryBlob.pub, &primary->pub, sizeof(primaryBlob.pub));
        rc |= writeKeyBlob(pubFilename, &primaryBlob);
        /* Write AK's Name digest */
        fp = XFOPEN(nameFile, "wb");
        if (fp != XBADFILE) {
            XFWRITE((BYTE*)&newKeyBlob.name, 1, sizeof(newKeyBlob.name), fp);
            printf("Wrote AK Name digest\n");
            XFCLOSE(fp);
        }
    }
#else
    if(alg == TPM_ALG_SYMCIPHER) {
        printf("The Public Part of a symmetric key contains only meta data\n");
    }
    printf("Key Public Blob %d\n", newKeyBlob.pub.size);
    TPM2_PrintBin((const byte*)&newKeyBlob.pub.publicArea, newKeyBlob.pub.size);
    printf("Key Private Blob %d\n", newKeyBlob.priv.size);
    TPM2_PrintBin(newKeyBlob.priv.buffer, newKeyBlob.priv.size);
#endif

    /* Save EK public key as PEM format file to the disk */
#if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_FILESYSTEM)
    if (pemFiles) {
        byte pem[MAX_RSA_KEY_BYTES], tempBuf[MAX_RSA_KEY_BYTES];
        int pemSz, tempSz = sizeof(tempBuf);

        if (endorseKey) {
            pemFilename = pemFileEk;
        }
        else {
            pemFilename = pemFileSrk;
        }

        rc = wolfTPM2_RsaKey_TpmToPem(&dev, primary, pem, &pemSz, tempBuf, tempSz);
        if (rc == 0) {
            rc = writeKeyPubPem(pemFilename, pem, (word32)pemSz);
        }

        if (bAIK) {
            pemFilename = pemFileAk;
        }
        else {
            pemFilename = pemFileKey;
        }

        rc = wolfTPM2_RsaKey_TpmToPem(&dev, &newKey, pem, &pemSz, tempBuf, tempSz);
        if (rc == 0) {
            rc = writeKeyPubPem(pemFilename, pem, (word32)pemSz);
        }
    }
#else
    printf("Unable to store EK pub as PEM file. Lack of file support\n");
#endif

exit:

    if (rc != 0) {
        printf("\nFailure 0x%x: %s\n\n", rc, wolfTPM2_GetRCString(rc));
    }

    /* Close handles */
    wolfTPM2_UnloadHandle(&dev, &primary->handle);
    wolfTPM2_UnloadHandle(&dev, &newKeyBlob.handle);
    /* EK policy is destroyed after use, flush parameter encryption session */
    if(!endorseKey) {
        wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);
    }

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
