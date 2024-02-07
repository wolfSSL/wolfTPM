/* secret_unseal.c
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
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
/* --- BEGIN TPM Secure Boot Secret Unseal Example -- */
/******************************************************************************/

#define MAX_SECRET_SZ 32
#define USE_PCR_ALG   TPM_ALG_SHA256 /* always SHA2-256 */

static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/boot/secret_unseal [-seal=] [-pcrsig=] [-rsa/-ecc] [-publickey]\n");
    printf("* -seal=file: The sealed blob file (default sealblob.bin)\n");
    printf("* -pcr=index: SHA2-256 PCR index < 24 (multiple can be supplied) (default %d)\n", TPM2_DEMO_PCR_INDEX);
    printf("* -pcrsig=file: The signed PCR policy (default pcrsig.bin)\n");
    printf("* -ecc/-rsa: Public key is RSA or ECC (default is RSA)\n");
    printf("* -publickey=file: Public key file (PEM or DER) for the policy signing key used\n");
    printf("Examples:\n");
    printf("./examples/boot/secret_seal -policy=policyauth.bin -out=sealblob.bin\n");

}

/* Load Key Public Info */
#if !defined(NO_FILESYSTEM)
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
        if (rc == 0) {
            /* Load public key and get handle */
            rc = wolfTPM2_LoadPublicKey_ex(dev, authKey, &authKey->pub,
                TPM_RH_PLATFORM);
        }
    }

    if (rc != 0) {
        printf("Load policy authorization key failed %d\n", rc);
    }
    return rc;
}
#endif /* !NO_FILESYSTEM */

int TPM2_Boot_SecretUnseal_Example(void* userCtx, int argc, char *argv[])
{
    int rc = 0;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY storage;
    WOLFTPM2_SESSION tpmSession;
    WOLFTPM2_KEYBLOB sealBlob;
    WOLFTPM2_KEY authKey;
    TPM_ALG_ID paramEncAlg = TPM_ALG_CFB;
    TPM_ALG_ID alg = TPM_ALG_RSA, srkAlg, sigAlg;
    TPM_ALG_ID pcrAlg = USE_PCR_ALG;
    byte pcrArray[PCR_SELECT_MAX*2];
    word32 pcrArraySz = 0;
    const char* sealFile = "sealblob.bin";
    const char* publicKeyFile = NULL;
    const char* pcrSigFile = "pcrsig.bin";
    byte pcrDigest[WC_MAX_DIGEST_SIZE];
    word32 pcrDigestSz = 0;
    byte policyDigest[WC_MAX_DIGEST_SIZE];
    word32 policyDigestSz = 0;
    byte sig[512]; /* up to 4096-bit key */
    word32 sigSz = 0;
    TPMT_TK_VERIFIED checkTicket;
    Unseal_In unsealIn;
    Unseal_Out unsealOut;
    byte* policyRef = NULL; /* optional nonce */
    word32 policyRefSz = 0;
    byte secret[MAX_SYM_DATA+1]; /* room for NULL term */
    word32 secretSz = 0;

    XMEMSET(&dev, 0, sizeof(WOLFTPM2_DEV));
    XMEMSET(&storage, 0, sizeof(WOLFTPM2_KEY));
    XMEMSET(&tpmSession, 0, sizeof(WOLFTPM2_SESSION));
    XMEMSET(&sealBlob, 0, sizeof(WOLFTPM2_KEYBLOB));
    XMEMSET(&authKey, 0, sizeof(WOLFTPM2_KEY));
    XMEMSET(&checkTicket, 0, sizeof(TPMT_TK_VERIFIED));
    XMEMSET(&unsealIn, 0, sizeof(Unseal_In));
    XMEMSET(&unsealOut, 0, sizeof(Unseal_Out));

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
        else if (XSTRNCMP(argv[argc-1], "-pcr=", XSTRLEN("-pcr=")) == 0) {
            const char* pcrStr = argv[argc-1] + XSTRLEN("-pcr=");
            byte pcrIndex = (byte)XATOI(pcrStr);
            if (pcrIndex > PCR_LAST) {
                printf("PCR index is out of range (0-23)\n");
                usage();
                return 0;
            }
            pcrArray[pcrArraySz] = pcrIndex;
            pcrArraySz++;
        }
        else if (XSTRNCMP(argv[argc-1], "-seal=",
                XSTRLEN("-seal=")) == 0) {
            sealFile = argv[argc-1] + XSTRLEN("-seal=");
        }
        else if (XSTRNCMP(argv[argc-1], "-pcrsig=",
                XSTRLEN("-pcrsig=")) == 0) {
            pcrSigFile = argv[argc-1] + XSTRLEN("-pcrsig=");
        }
        else if (XSTRNCMP(argv[argc-1], "-publickey=",
                XSTRLEN("-publickey=")) == 0) {
            publicKeyFile = argv[argc-1] + XSTRLEN("-publickey=");
        }
        else {
            printf("Warning: Unrecognized option: %s\n", argv[argc-1]);
        }
        argc--;
    }

    printf("Secret Unseal example with authorized policy\n");

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

    /* Start an authenticated policy session (salted / unbound) */
    rc = wolfTPM2_StartSession(&dev, &tpmSession, &storage, NULL,
        TPM_SE_POLICY, paramEncAlg);
    if (rc != 0) goto exit;
    printf("Policy Session Handle 0x%x\n", (word32)tpmSession.handle.hndl);
    printf("Parameter Encryption: %s\n", TPM2_GetAlgName(paramEncAlg));

    /* enable parameter encryption for unseal */
    rc = wolfTPM2_SetAuthSession(&dev, 1, &tpmSession,
        (TPMA_SESSION_decrypt | TPMA_SESSION_encrypt |
        TPMA_SESSION_continueSession));
    if (rc != 0) goto exit;

    /* Get PCR policy digest */
    if (pcrArraySz == 0) {
        pcrArray[pcrArraySz++] = TPM2_DEMO_PCR_INDEX;
    }
    rc = wolfTPM2_PolicyPCR(&dev, tpmSession.handle.hndl, pcrAlg, pcrArray, pcrArraySz);
    if (rc == 0) {
        pcrDigestSz = (word32)sizeof(pcrDigest);
        rc = wolfTPM2_GetPolicyDigest(&dev, tpmSession.handle.hndl, pcrDigest,
            &pcrDigestSz);
    }
    if (rc != TPM_RC_SUCCESS) {
        printf("Error getting PCR policy digest!\n");
        goto exit;
    }
    printf("PCR Policy Digest (%d bytes):\n", pcrDigestSz);
    printHexString(pcrDigest, pcrDigestSz, pcrDigestSz);

    /* Add policyRef (if blank just re-hash) */
    policyDigestSz = pcrDigestSz;
    XMEMCPY(policyDigest, pcrDigest, pcrDigestSz);
    rc = wolfTPM2_PolicyRefMake(pcrAlg, policyDigest, &policyDigestSz,
        policyRef, policyRefSz);
    if (rc != 0) goto exit;
    printf("PCR Policy Digest (w/PolicyRef) (%d bytes):\n", policyDigestSz);
    printHexString(policyDigest, policyDigestSz, policyDigestSz);

    /* Load external public key and signature */
#if !defined(NO_FILESYSTEM)
    /* Policy Authorization Signature */
    if (pcrSigFile) {
        sigSz = (word32)sizeof(sig);
        rc = readBin(pcrSigFile, sig, &sigSz);
    }
    if (rc != TPM_RC_SUCCESS) {
        printf("Reading PCR signature failed!\n");
        goto exit;
    }
    printf("PCR Policy Signature (%d bytes):\n", sigSz);
    printHexString(sig, sigSz, 32);

    if (publicKeyFile == NULL) {
        if (alg == TPM_ALG_RSA)
            publicKeyFile = "./certs/example-rsa2048-key-pub.der";
        else if (alg == TPM_ALG_ECC)
            publicKeyFile = "./certs/example-ecc256-key-pub.der";
    }
    if (publicKeyFile != NULL) {
        /* Build Policy Authorization from public key */
        rc = LoadAuthKeyInfo(&dev, &authKey, alg, publicKeyFile);
    }
    else {
        printf("Error, missing -publickey= argument!\n");
        usage();
        rc = BAD_FUNC_ARG;
    }
#else
    printf("File system support not compiled in!\n");
    rc = NOT_COMPILED_IN;
#endif
    if (rc != TPM_RC_SUCCESS) {
        printf("Error loading authorization public key and signature\n");
        goto exit;
    }

    sigAlg = alg == TPM_ALG_RSA ? TPM_ALG_RSASSA : TPM_ALG_ECDSA;
    rc = wolfTPM2_VerifyHashTicket(&dev, &authKey,
        sig, sigSz, policyDigest, policyDigestSz,
        sigAlg, pcrAlg, &checkTicket);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_VerifyHashTicket failed!\n");
        goto exit;
    }
    printf("Verify ticket: tag 0x%x, hi 0x%x, digest %d\n",
        checkTicket.tag, checkTicket.hierarchy, checkTicket.digest.size);
    printHexString(checkTicket.digest.buffer, checkTicket.digest.size, 32);

    rc = wolfTPM2_PolicyAuthorize(&dev, tpmSession.handle.hndl, &authKey.pub,
        &checkTicket, pcrDigest, pcrDigestSz, policyRef, policyRefSz);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_PolicyAuthorize failed!\n");
        goto exit;
    }

    /* done with authorization public key */
    wolfTPM2_UnloadHandle(&dev, &authKey.handle);

    /* load seal blob file */
#ifndef NO_FILESYSTEM
    rc = readKeyBlob(sealFile, &sealBlob);
#else
    rc = NOT_COMPILED_IN;
#endif
    if (rc != TPM_RC_SUCCESS) {
        printf("Error loading seal blob file!\n");
        goto exit;
    }

    /* load the seal blob */
    rc = wolfTPM2_LoadKey(&dev, &sealBlob, &storage.handle);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_LoadKey failed\n");
        goto exit;
    }
    printf("Loaded sealBlob to 0x%x\n", (word32)sealBlob.handle.hndl);

    /* use the policy session for unseal */
    rc = wolfTPM2_SetAuthSession(&dev, 0, &tpmSession,
        (TPMA_SESSION_decrypt | TPMA_SESSION_encrypt |
        TPMA_SESSION_continueSession));
    if (rc != 0) goto exit;
    /* set the sealed object name 0 (required) */
    wolfTPM2_SetAuthHandleName(&dev, 0, &sealBlob.handle);

    /* unseal */
    unsealIn.itemHandle = sealBlob.handle.hndl;
    rc = TPM2_Unseal(&unsealIn, &unsealOut);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_Unseal failed\n");
        goto exit;
    }

    secretSz = unsealOut.outData.size;
    XMEMSET(secret, 0, sizeof(secret));
    XMEMCPY(secret, unsealOut.outData.buffer, secretSz);
    printf("Secret (%d bytes): %s\n", secretSz, secret);
    printHexString(secret, secretSz, 32);

exit:
    if (rc != 0) {
        printf("Failure 0x%x: %s\n", rc, wolfTPM2_GetRCString(rc));
    }

    wolfTPM2_UnloadHandle(&dev, &authKey.handle);
    wolfTPM2_UnloadHandle(&dev, &sealBlob.handle);
    wolfTPM2_UnloadHandle(&dev, &storage.handle);
    wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);

    wolfTPM2_Cleanup(&dev);

    return rc;
}
#endif /* !WOLFTPM2_NO_WRAPPER && !WOLFTPM2_NO_WOLFCRYPT */

/******************************************************************************/
/* --- END TPM Secure Boot Secret Unseal Example -- */
/******************************************************************************/

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = NOT_COMPILED_IN;

#if !defined(WOLFTPM2_NO_WRAPPER) && !defined(WOLFTPM2_NO_WOLFCRYPT)
    rc = TPM2_Boot_SecretUnseal_Example(NULL, argc, argv);
#else
    printf("Example not compiled in! Requires Wrapper and wolfCrypt\n");
    (void)argc;
    (void)argv;
#endif

    return rc;
}
#endif /* NO_MAIN_DRIVER */
