/* secret_seal.c
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

/* Example for using TPM to seal a secret using an external key based on PCR(s)
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_wrap.h>

#include <stdio.h>

#if !defined(WOLFTPM2_NO_WRAPPER) && !defined(WOLFTPM2_NO_WOLFCRYPT)

#include <hal/tpm_io.h>
#include <examples/tpm_test.h>
#include <examples/tpm_test_keys.h>
#include <examples/boot/boot.h>

#include <wolfssl/wolfcrypt/hash.h>

/******************************************************************************/
/* --- BEGIN TPM Secure Boot Secret Seal Example -- */
/******************************************************************************/

#define USE_SECRET_SZ 32
#define USE_PCR_ALG   TPM_ALG_SHA256 /* always SHA2-256 */

static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/boot/secret_seal [-secretstr=/-secrethex] [-policy=] [-out=]\n");
    printf("./examples/boot/secret_seal [-secretstr=/-secrethex] [-ecc/-rsa] [-publickey=] [-out=]\n");
    printf("* -secretstr=string/-secrethex=hex: Secret to seal (default=random)\n");
    printf("* -policy=file: Policy authorization digest for the public key used to sign the policy (default policyauth.bin)\n");
    printf("* -ecc/-rsa: Public key is RSA or ECC (default is RSA)\n");
    printf("* -publickey=file: Public key file (PEM or DER) for the policy signing key used\n");
    printf("* -out=binfile: Sealed secret blob (default sealblob.bin)\n");
    printf("Examples:\n");
    printf("./examples/boot/secret_seal -policy=policyauth.bin -out=sealblob.bin\n");
    printf("./examples/boot/secret_seal -rsa -publickey=./certs/example-rsa2048-key-pub.der -out=sealblob.bin\n");
    printf("./examples/boot/secret_seal -ecc -publickey=./certs/example-ecc256-key-pub.der -out=sealblob.bin\n");
}

/* Load Key Public Info */
#if !defined(NO_FILESYSTEM) && !defined(NO_ASN)
static int LoadAuthKeyInfo(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* authKey,
    TPM_ALG_ID alg, const char* file)
{
    int rc;
    int encType = ENCODING_TYPE_ASN1;
    byte* buf = NULL;
    size_t bufSz = 0;
    const char* fileEnd;

    fileEnd = XSTRSTR(file, ".pem");
    if (fileEnd != NULL && fileEnd[XSTRLEN(".pem")] == '\0') {
        encType = ENCODING_TYPE_PEM;
    }

    printf("Loading %s public key file: %s\n",
        encType == ENCODING_TYPE_PEM ? "PEM" : "DER",
        file);

    rc = loadFile(file, &buf, &bufSz);
    if (rc == 0) {
        rc = wolfTPM2_ImportPublicKeyBuffer(dev,
            alg,
            authKey,
            encType,
            (const char*)buf, (word32)bufSz,
            0
        );
        XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (rc != 0) {
        printf("Load policy authorization key failed %d\n", rc);
    }
    return rc;
}
#endif /* !NO_FILESYSTEM && !NO_ASN */

int TPM2_Boot_SecretSeal_Example(void* userCtx, int argc, char *argv[])
{
    int rc = 0;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY storage;
    WOLFTPM2_SESSION tpmSession;
    WOLFTPM2_KEYBLOB sealBlob;
    TPM_ALG_ID paramEncAlg = TPM_ALG_CFB;
    TPM_ALG_ID alg = TPM_ALG_RSA, srkAlg;
    TPM_ALG_ID pcrAlg = USE_PCR_ALG;
    TPMT_PUBLIC sealTemplate;
    byte secret[MAX_SYM_DATA+1]; /* for NULL term */
    word32 secretSz = 0;
    const char* publicKeyFile = NULL;
    const char* outFile = "sealblob.bin";
    const char* policyFile = "policyauth.bin";
    byte policyDigest[WC_MAX_DIGEST_SIZE];
    word32 policyDigestSz = 0;

    XMEMSET(&dev, 0, sizeof(WOLFTPM2_DEV));
    XMEMSET(&storage, 0, sizeof(WOLFTPM2_KEY));
    XMEMSET(&tpmSession, 0, sizeof(WOLFTPM2_SESSION));
    XMEMSET(&sealBlob, 0, sizeof(sealBlob));
    XMEMSET(secret, 0, sizeof(secret));

    if (argc >= 2) {
        if (XSTRCMP(argv[1], "-?") == 0 ||
            XSTRCMP(argv[1], "-h") == 0 ||
            XSTRCMP(argv[1], "--help") == 0) {
            usage();
            return 0;
        }
    }
    while (argc > 1) {
        if (XSTRCMP(argv[argc-1], "-ecc") == 0) {
            alg = TPM_ALG_ECC;
        }
        else if (XSTRCMP(argv[argc-1], "-rsa") == 0) {
            alg = TPM_ALG_RSA;
        }
        else if (XSTRNCMP(argv[argc-1], "-secretstr=", XSTRLEN("-secretstr=")) == 0) {
            const char* secretStr = argv[argc-1] + XSTRLEN("-secretstr=");
            secretSz = (int)XSTRLEN(secretStr);
            if (secretSz > (word32)sizeof(secret)-1)
                secretSz = (word32)sizeof(secret)-1;
            XMEMCPY(secret, secretStr, secretSz);
        }
        else if (XSTRNCMP(argv[argc-1], "-secrethex=", XSTRLEN("-secrethex=")) == 0) {
            const char* secretStr = argv[argc-1] + XSTRLEN("-secrethex=");
            word32 secretStrSz = (word32)XSTRLEN(secretStr);
            if (secretStrSz > (word32)(sizeof(secret)*2-1))
                secretStrSz = (word32)(sizeof(secret)*2-1);
            secretSz = hexToByte(secretStr, secret, secretStrSz);
        }
        else if (XSTRNCMP(argv[argc-1], "-policy=",
                XSTRLEN("-policy=")) == 0) {
            policyFile = argv[argc-1] + XSTRLEN("-policy=");
        }
        else if (XSTRNCMP(argv[argc-1], "-publickey=",
                XSTRLEN("-publickey=")) == 0) {
            publicKeyFile = argv[argc-1] + XSTRLEN("-publickey=");
        }
        else if (XSTRNCMP(argv[argc-1], "-out=",
                XSTRLEN("-out=")) == 0) {
            outFile = argv[argc-1] + XSTRLEN("-out=");
        }
        else {
            printf("Warning: Unrecognized option: %s\n", argv[argc-1]);
        }
        argc--;
    }

    printf("Secret Seal example with authorized policy\n");

    /* Secret - Generate if none provided */
    if (secretSz == 0) {
        WC_RNG rng;
        rc = wc_InitRng(&rng);
        if (rc == 0) {
            secretSz = USE_SECRET_SZ;
            rc = wc_RNG_GenerateBlock(&rng, secret, secretSz);
            wc_FreeRng(&rng);
        }
    }
    if (rc != 0 || secretSz == 0) {
        printf("Error getting secret\n");
        goto exit;
    }
    printf("Secret (%d bytes): %s\n", secretSz, secret);
    printHexString(secret, secretSz, 32);

    /* Storage Root and Parameter Encryption */
    srkAlg = alg;
#if defined(HAVE_ECC) && !defined(WOLFSSL_PUBLIC_MP)
    if (srkAlg == TPM_ALG_ECC && paramEncAlg != TPM_ALG_NULL) {
        /* ECC encrypt requires mp_ API's */
        printf("Parameter encryption with ECC SRK support not available, "
               "using RSA SRK\n");
        srkAlg = TPM_ALG_RSA;
    }
#endif

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_Init failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    printf("wolfTPM2_Init: success\n");

    /* get SRK */
    rc = getPrimaryStoragekey(&dev, &storage, srkAlg);
    if (rc != 0) goto exit;

    /* Start an authenticated session (salted / unbound) */
    rc = wolfTPM2_StartSession(&dev, &tpmSession, &storage, NULL,
        TPM_SE_POLICY, paramEncAlg);
    if (rc != 0) goto exit;
    printf("Session Handle 0x%x\n", (word32)tpmSession.handle.hndl);
    printf("Parameter Encryption: %s\n", TPM2_GetAlgName(paramEncAlg));

    rc = wolfTPM2_SetAuthSession(&dev, 1, &tpmSession,
        (TPMA_SESSION_decrypt | TPMA_SESSION_encrypt |
        TPMA_SESSION_continueSession));
    if (rc != 0) goto exit;

    if (policyFile == NULL && publicKeyFile == NULL) {
        if (alg == TPM_ALG_RSA)
            publicKeyFile = "./certs/example-rsa2048-key-pub.der";
        else if (alg == TPM_ALG_ECC)
            publicKeyFile = "./certs/example-ecc256-key-pub.der";
    }
#if !defined(NO_FILESYSTEM) && !defined(NO_ASN)
    /* Policy Authorization */
    if (policyFile) {
        policyDigestSz = (word32)sizeof(policyDigest);
        rc = readBin(policyFile, policyDigest, &policyDigestSz);
    }
    /* Load signing authority public key */
    else if (publicKeyFile != NULL) {
        WOLFTPM2_KEY authKey;
        XMEMSET(&authKey, 0, sizeof(WOLFTPM2_KEY));
        /* Build Policy Authorization from public key */
        rc = LoadAuthKeyInfo(&dev, &authKey, alg, publicKeyFile);
        if (rc == 0) {
            /* Policy Digest used for creation of a keyed hash */
            XMEMSET(policyDigest, 0, sizeof(policyDigest));
            policyDigestSz = TPM2_GetHashDigestSize(pcrAlg);
            rc = wolfTPM2_PolicyAuthorizeMake(pcrAlg, &authKey.pub,
                policyDigest, &policyDigestSz, NULL, 0);
        }
        wolfTPM2_UnloadHandle(&dev, &authKey.handle);
    }
    else {
        printf("Error: Must provide -policy= or -publickey=\n");
        usage();
        rc = BAD_FUNC_ARG;
    }
#else
    printf("File system support not compiled in!\n");
    rc = NOT_COMPILED_IN;
#endif
    if (rc != 0) goto exit;
    printf("Policy Authorize Digest (%d bytes):\n", policyDigestSz);
    printHexString(policyDigest, policyDigestSz, policyDigestSz);

    /* Create a new key for sealing using signing auth for external key */
    wolfTPM2_GetKeyTemplate_KeySeal(&sealTemplate, pcrAlg);
    sealTemplate.authPolicy.size = policyDigestSz;
    XMEMCPY(sealTemplate.authPolicy.buffer, policyDigest, policyDigestSz);
    rc = wolfTPM2_CreateKeySeal_ex(&dev, &sealBlob, &storage.handle,
        &sealTemplate, NULL, 0, pcrAlg, NULL, 0, secret, secretSz);
    if (rc != 0) goto exit;
    printf("Sealed keyed hash (pub %d, priv %d bytes):\n",
        sealBlob.pub.size, sealBlob.priv.size);
#if !defined(NO_FILESYSTEM)
    rc = writeKeyBlob(outFile, &sealBlob);
#else
    printf("Sealed keyed hash pub %d\n", sealBlob.pub.size);
    printHexString((const byte*)&sealBlob.pub.publicArea, sealBlob.pub.size, 32);
    printf("Sealed keyed hash priv %d\n", sealBlob.priv.size);
    printHexString(sealBlob.priv.buffer, sealBlob.priv.size, 32);
    (void)outFile;
#endif

exit:
    if (rc != 0) {
        printf("Failure 0x%x: %s\n", rc, wolfTPM2_GetRCString(rc));
    }

    wolfTPM2_UnloadHandle(&dev, &storage.handle);
    wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);

    wolfTPM2_Cleanup(&dev);

    return rc;
}
#endif /* !WOLFTPM2_NO_WRAPPER && !WOLFTPM2_NO_WOLFCRYPT */

/******************************************************************************/
/* --- END TPM Secure Boot Secret Seal Example -- */
/******************************************************************************/

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = NOT_COMPILED_IN;

#if !defined(WOLFTPM2_NO_WRAPPER) && !defined(WOLFTPM2_NO_WOLFCRYPT)
    rc = TPM2_Boot_SecretSeal_Example(NULL, argc, argv);
#else
    printf("Example not compiled in! Requires Wrapper and wolfCrypt\n");
    (void)argc;
    (void)argv;
#endif

    return rc;
}
#endif /* NO_MAIN_DRIVER */
