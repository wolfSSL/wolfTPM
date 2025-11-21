/* keyimport.c
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

#if !defined(WOLFTPM2_NO_WRAPPER) && !defined(WOLFTPM2_NO_WOLFCRYPT)

#include <examples/keygen/keygen.h>
#include <hal/tpm_io.h>
#include <examples/tpm_test.h>
#include <examples/tpm_test_keys.h>

/******************************************************************************/
/* --- BEGIN TPM Key Import / Blob Example -- */
/******************************************************************************/

static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/keygen/keyimport [keyblob.bin] [-ecc/-rsa] [-key=] "
           "[-aes/xor] [-password] [-public]\n");
    printf("* -aes/xor: Use Parameter Encryption\n");
    printf("* -rsa/-ecc: Use RSA or ECC key\n");
    printf("* -public: Input file is public key only\n");
    printf("* -password=[password]: Optional password for private key\n");
    printf("* -key=[keyfile]: PEM (Base64 Encoded) or DER (ASN.1) binary key file\n");
    printf("Examples:\n");
    printf("\t./examples/keygen/keyimport -ecc\n");
    printf("\t./examples/keygen/keyimport -rsa\n");
    printf("\t./examples/keygen/keyimport -ecc -key=./certs/example-ecc256-key.pem -aes\n");
    printf("\t./examples/keygen/keyimport -rsa -key=./certs/example-rsa2048-key.pem -aes\n");
    printf("\t./examples/keygen/keyimport -ecc -key=./certs/example-ecc256-key.der -aes\n");
    printf("\t./examples/keygen/keyimport -rsa -key=./certs/example-rsa2048-key.der -aes\n");
    printf("\t./examples/keygen/keyimport -ecc -key=../wolfssl/certs/ecc-keyPkcs8Enc.pem -password=yassl123 -aes\n");
    printf("\t./examples/keygen/keyimport -rsa -key=../wolfssl/certs/server-keyPkcs8Enc.pem -password=yassl123 -aes\n");
    printf("\t./examples/keygen/keyimport -ecc -key=./certs/example-ecc256-key-pub.der -public\n");
    printf("\t./examples/keygen/keyimport -rsa -key=./certs/example-rsa2048-key-pub.der -public\n");
}

int TPM2_Keyimport_Example(void* userCtx, int argc, char *argv[])
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY storage; /* SRK */
    WOLFTPM2_KEYBLOB impKey;
    TPMI_ALG_PUBLIC alg = TPM_ALG_RSA;
    TPMI_ALG_PUBLIC srkAlg = TPM_ALG_ECC; /* prefer ECC, but allow RSA */
    TPM_ALG_ID paramEncAlg = TPM_ALG_NULL;
    WOLFTPM2_SESSION tpmSession;
    const char* outputFile = "keyblob.bin";
    const char* impFile = NULL;
    int encType = ENCODING_TYPE_ASN1;
    const char* password = NULL;
    TPMA_OBJECT attributes;
    byte* buf = NULL;
    size_t bufSz = 0;
    int isPublicKey = 0;
    const char* impFileEnd;

    if (argc >= 2) {
        if (XSTRCMP(argv[1], "-?") == 0 ||
            XSTRCMP(argv[1], "-h") == 0 ||
            XSTRCMP(argv[1], "--help") == 0) {
            usage();
            return 0;
        }

        if (argv[1][0] != '-') {
            outputFile = argv[1];
        }
    }
    while (argc > 1) {
        if (XSTRCMP(argv[argc-1], "-ecc") == 0) {
            alg = TPM_ALG_ECC;
        }
        else if (XSTRCMP(argv[argc-1], "-rsa") == 0) {
            alg = TPM_ALG_RSA;
        }
        else if (XSTRCMP(argv[argc-1], "-aes") == 0) {
            paramEncAlg = TPM_ALG_CFB;
        }
        else if (XSTRCMP(argv[argc-1], "-xor") == 0) {
            paramEncAlg = TPM_ALG_XOR;
        }
        else if (XSTRCMP(argv[argc-1], "-public") == 0) {
            isPublicKey = 1;
        }
        else if (XSTRNCMP(argv[argc-1], "-password=",
                XSTRLEN("-password=")) == 0) {
            password = (const char*)(argv[argc-1] + XSTRLEN("-password="));
        }
        else if (XSTRNCMP(argv[argc-1], "-key=", XSTRLEN("-key=")) == 0) {
            impFile = (const char*)(argv[argc-1] + XSTRLEN("-key="));
        }
        else if (argv[argc-1][0] == '-') {
            printf("Warning: Unrecognized option: %s\n", argv[argc-1]);
        }

        argc--;
    }

    /* setup default import file */
    if (impFile == NULL) {
        if (alg == TPM_ALG_RSA)
            impFile = "./certs/example-rsa2048-key.der";
        else if (alg == TPM_ALG_ECC)
            impFile = "./certs/example-ecc256-key.der";
    }
    impFileEnd = XSTRSTR(impFile, ".pem");
    if (impFileEnd != NULL && impFileEnd[XSTRLEN(".pem")] == '\0') {
        encType = ENCODING_TYPE_PEM;
    }

    XMEMSET(&storage, 0, sizeof(storage));
    XMEMSET(&impKey, 0, sizeof(impKey));
    XMEMSET(&tpmSession, 0, sizeof(tpmSession));

    if (alg == TPM_ALG_RSA)
        srkAlg = TPM_ALG_RSA;

    printf("TPM2.0 Key Import example\n");
    printf("\tKey Blob: %s\n", outputFile);
    printf("\tAlgorithm: %s\n", TPM2_GetAlgName(alg));
    printf("\tSRK: %s\n", TPM2_GetAlgName(srkAlg));
    printf("\tUse Parameter Encryption: %s\n", TPM2_GetAlgName(paramEncAlg));
    if (password != NULL) {
        printf("\tpassword: %s\n", password);
    }

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("\nwolfTPM2_Init failed\n");
        goto exit;
    }

    /* get SRK */
    rc = getPrimaryStoragekey(&dev, &storage, srkAlg);
    if (rc != 0) goto exit;

    if (paramEncAlg != TPM_ALG_NULL) {
        WOLFTPM2_KEY* bindKey = &storage;
    #ifndef HAVE_ECC
        if (srkAlg == TPM_ALG_ECC)
            bindKey = NULL; /* cannot bind to key without ECC enabled */
    #endif
    #ifdef NO_RSA
        if (srkAlg == TPM_ALG_RSA)
            bindKey = NULL; /* cannot bind to key without RSA enabled */
    #endif

        /* Start an authenticated session (salted / unbound) with parameter
         * encryption */
        rc = wolfTPM2_StartSession(&dev, &tpmSession, bindKey, NULL,
            TPM_SE_HMAC, paramEncAlg);
        if (rc != 0) goto exit;
        printf("TPM2_StartAuthSession: sessionHandle 0x%x\n",
            (word32)tpmSession.handle.hndl);

        /* set session for authorization of the storage key */
        rc = wolfTPM2_SetAuthSession(&dev, 1, &tpmSession,
            (TPMA_SESSION_decrypt | TPMA_SESSION_encrypt |
             TPMA_SESSION_continueSession));
        if (rc != 0) goto exit;
    }

    /* setup an auth value */
    if (password != NULL) {
        impKey.handle.auth.size = (int)XSTRLEN(password);
        XMEMCPY(impKey.handle.auth.buffer, password, impKey.handle.auth.size);
    }

    attributes = (TPMA_OBJECT_restricted |
             TPMA_OBJECT_sensitiveDataOrigin |
             TPMA_OBJECT_decrypt |
             TPMA_OBJECT_userWithAuth |
             TPMA_OBJECT_noDA);

#if !defined(NO_FILESYSTEM) && !defined(NO_WRITE_TEMP_FILES) && !defined(NO_ASN)
    if (impFile != NULL) {
        printf("Loading %s%s key file: %s\n",
            encType == ENCODING_TYPE_PEM ? "PEM" : "DER",
            isPublicKey ? " public" : "",
            impFile);
        rc = loadFile(impFile, &buf, &bufSz);
        if (rc == 0) {
            if (isPublicKey) {
                rc = wolfTPM2_ImportPublicKeyBuffer(&dev,
                    alg,
                    (WOLFTPM2_KEY*)&impKey,
                    encType,
                    (const char*)buf, (word32)bufSz,
                    attributes
                );
            }
            else { /* private key */
                rc = wolfTPM2_ImportPrivateKeyBuffer(&dev, &storage,
                    alg,
                    &impKey,
                    encType,
                    (const char*)buf, (word32)bufSz,
                    password,
                    attributes, NULL, 0
                );
            }
        }
    #if defined(NO_RSA) || !defined(HAVE_ECC)
        if (rc == NOT_COMPILED_IN) {
            printf("Feature not compiled in! Skipping test\n");
            rc = 0; /* allowing error */
        }
    #endif
    }
    else
#else
    (void)encType;
    (void)attributes;
    (void)bufSz;
    (void)isPublicKey;
#endif
    if (alg == TPM_ALG_RSA) {
        printf("Loading example RSA key (see kRsaKeyPrivQ)\n");

        /* Import raw RSA private key into TPM */
        rc = wolfTPM2_ImportRsaPrivateKey(&dev, &storage, &impKey,
            kRsaKeyPubModulus, (word32)sizeof(kRsaKeyPubModulus),
            kRsaKeyPubExponent,
            kRsaKeyPrivQ,      (word32)sizeof(kRsaKeyPrivQ),
            TPM_ALG_NULL, TPM_ALG_NULL);
    }
    else if (alg == TPM_ALG_ECC) {
        printf("Loading example ECC key (see kEccKeyPrivD)\n");

        /* Import raw ECC private key into TPM */
        rc = wolfTPM2_ImportEccPrivateKey(&dev, &storage, &impKey,
            TPM_ECC_NIST_P256,
            kEccKeyPubXRaw, (word32)sizeof(kEccKeyPubXRaw),
            kEccKeyPubYRaw, (word32)sizeof(kEccKeyPubYRaw),
            kEccKeyPrivD,   (word32)sizeof(kEccKeyPrivD));
    }
    if (rc != 0) goto exit;

    printf("Imported %s key (pub %d, priv %d bytes)\n",
        TPM2_GetAlgName(alg), impKey.pub.size, impKey.priv.size);

    /* Save key as encrypted blob to the disk */
#if !defined(NO_FILESYSTEM) && !defined(NO_WRITE_TEMP_FILES) && \
    !defined(NO_WRITE_TEMP_FILES)
    rc = writeKeyBlob(outputFile, &impKey);
#else
    printf("Key Public Blob %d\n", impKey.pub.size);
    TPM2_PrintBin((const byte*)&impKey.pub.publicArea, impKey.pub.size);
    printf("Key Private Blob %d\n", impKey.priv.size);
    TPM2_PrintBin(impKey.priv.buffer, impKey.priv.size);
#endif

exit:

    if (rc != 0) {
        printf("\nFailure 0x%x: %s\n\n", rc, wolfTPM2_GetRCString(rc));
    }

    XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    /* Close key handles */
    wolfTPM2_UnloadHandle(&dev, &storage.handle);
    wolfTPM2_UnloadHandle(&dev, &impKey.handle);
    wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);

    wolfTPM2_Cleanup(&dev);
    return rc;
}

/******************************************************************************/
/* --- END TPM Key Import / Blob Example -- */
/******************************************************************************/
#endif /* !WOLFTPM2_NO_WRAPPER && !WOLFTPM2_NO_WOLFCRYPT */


#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = NOT_COMPILED_IN;

#if !defined(WOLFTPM2_NO_WRAPPER) && !defined(WOLFTPM2_NO_WOLFCRYPT)
    rc = TPM2_Keyimport_Example(NULL, argc, argv);
#else
    printf("KeyImport code not compiled in\n");
    (void)argc;
    (void)argv;
#endif

    return rc;
}
#endif
