/* keyimport.c
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

/* Tool and example for creating, storing and loading keys using TPM2.0 */

#include <wolftpm/tpm2_wrap.h>

#include <examples/keygen/keygen.h>
#include <examples/tpm_io.h>
#include <examples/tpm_test.h>
#include <examples/tpm_test_keys.h>

#include <stdio.h>


#ifndef WOLFTPM2_NO_WRAPPER

static const char* kRsaKeyPrivPem =
"-----BEGIN PRIVATE KEY-----"
"MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCePbYR1SIZAL/2"
"8FYbgpxynENgvHACM9LczZnsgVkZYxx3O9DTba2VTxhMN21i/aocJCzZB35qvz+R"
"ickyvWBqPDXauJEn9icPXgSknqxzw0ZATzL0wbq/Tk5T+oITFFCGJ8/baFoktOKu"
"iP5H50Dx6X2W1qNHiLkbGq7NbXHA8YG2wzK9kwikowSXQVB7pZ5bgjW2q73vIGSs"
"eW802f7I/30wbf4oR1vfk4OQursT9sl2CFLNt5bJSw6lFTm4BOgC7Q3bpHPzC/YK"
"uFYWKGeQL9GCsEZVWHCM6vzek6SNwQ0eoQ0i9IuF0os/0nJDwdXEZX9OoBhFT717"
"svlxDXpFAgMBAAECggEABYIV6Jx/5ZloVTbr9GSxP+8PDFq61mTJ6fwxJ7Gf8ZmI"
"1+Cp5fYrJOeeK6cBRIEabwTWV86iOKKEGrOOYJkFdmU2pbCngtnXZbpK1JUeYSAy"
"vZHULv9gWgDmipdNeE8Md4MCwfspqh3uxw8HNOcIlHMhd0Ls55RLhzVAUO/GliXz"
"5HIDhohyQAUvPvkwz1yrPNn5BQwMlJBARc2OKSKf+pJrlFw1KJWR9TKzGvRzMbI4"
"gwrq9BZ5LCX5y6C7BpuzXdySHXofwihPNmi1KU/88cWhas2E0Xz+p+N/ifmkquTN"
"3EqzqKBW+xobryM6X9JfQ6has211eUaZKNuU2/idKQKBgQC5rymu0UKHuAkr4uPS"
"NLGmaWb4p+kDNxbVyzS2ENjtoJ6JyEo/pZQrTG4S/kCWFgGsuztCbx+1Kgk0Pgwi"
"znaGvcfrjiP9XE1oVfMifA2JmH+drjASyjPqNfsf0BKQtlk0nZXwUO/C1FQ5vUU4"
"lpmpx4EhTnucQ9E7r0+uXnQHTQKBgQDaKh4bBV7dLBF4ZxwCdydMMSZkBgckBiH7"
"83BvyLW6I0GKXcFTa7KKLgTj41pXeWh6bmM9365+Cr8fxTZop28EfGRYFBMp08/g"
"wHpmS3NZ4moSgirJ+PhZsH+nBq89W75INR7BqV4SAc3n4lcwv9eBL9q0Q/YJZ1ph"
"NCKvz79y2QKBgFyDFPVwdQFBg/BFntRARLJwmUkR/1oGvG3QTHbZdfsOp25mR/fl"
"+yiHb+AupOciF7uDnUbALsAILYXF1C4TR6JiM5T8wJmev0JYcEaiH+yJ+isJehIi"
"hDMQqglzlYxcDZ3VVbrh2FLtjvklf7Nt9SlNqNx7ScLVVw2xjrWFgbGRAoGBAMjo"
"Wnsl0fu6Noh74/Z9RmpLJQCd8HuDTk6ZHCVFX91/1D6ZIo0xM+U+hfBbkfnWa5m8"
"CJaVZDrcqK+YTQfJkVo/N6VJL3Coh9qBRvbnat4OvQI4bzE6n3LxME1fwYeu8ifL"
"C3zq/R92G+n8rbDOKqbkq/KwV2bHkBrOCVeA6NzZAoGACztyZbS5jCuSlPqk/xoN"
"EzX9Cev/GipF5tZMeOcQlty+anPg3TC70O06yZ1SIJKLzOOyoPCUDNrM2M5TCaau"
"vT0vW1GeNAryc+q9aOmFT3AlZ93Tfst+90Q+NJecEEhkO43tU5S1ZK2iVf9XAOV6"
"ovHegJU35IUeaoyg23HjFWU="
"-----END PRIVATE KEY-----";

/******************************************************************************/
/* --- BEGIN TPM Key Import / Blob Example -- */
/******************************************************************************/

static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/keygen/keyimport [keyblob.bin] [-ecc/-rsa] [-pem/-der] [-aes/xor]\n");
    printf("* -ecc: Use RSA or ECC for keys\n");
    printf("* -aes/xor: Use Parameter Encryption\n");
    printf("* -pem/der: Key encoding type, none for binary\n");
}

int TPM2_Keyimport_Example(void* userCtx, int argc, char *argv[])
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY storage; /* SRK */
    WOLFTPM2_KEYBLOB impKey;
    TPMI_ALG_PUBLIC alg = TPM_ALG_RSA; /* TPM_ALG_ECC */
    TPM_ALG_ID paramEncAlg = TPM_ALG_NULL;
    WOLFTPM2_SESSION tpmSession;
    const char* outputFile = "keyblob.bin";
    uint8_t derEncode = 0;
    uint8_t pemEncode = 0;

    if (argc >= 2) {
        if (XSTRCMP(argv[1], "-?") == 0 ||
            XSTRCMP(argv[1], "-h") == 0 ||
            XSTRCMP(argv[1], "--help") == 0) {
            usage();
            return 0;
        }

        if (argv[1][0] != '-')
            outputFile = argv[1];
    }
    while (argc > 1) {
        if (XSTRCMP(argv[argc-1], "-ecc") == 0) {
            alg = TPM_ALG_ECC;
        }
        else if (XSTRCMP(argv[argc-1], "-aes") == 0) {
            paramEncAlg = TPM_ALG_CFB;
        }
        else if (XSTRCMP(argv[argc-1], "-xor") == 0) {
            paramEncAlg = TPM_ALG_XOR;
        }
        else if (XSTRCMP(argv[argc-1], "-pem") == 0) {
            paramEncAlg = TPM_ALG_XOR;
        }
        else if (XSTRCMP(argv[argc-1], "-der") == 0) {
            derEncode = 1;
        }
        else if (XSTRCMP(argv[argc-1], "-pem") == 0) {
            pemEncode = 1;
        }
        else {
            printf("Warning: Unrecognized option: %s\n", argv[argc-1]);
        }
        argc--;
    }

    XMEMSET(&storage, 0, sizeof(storage));
    XMEMSET(&impKey, 0, sizeof(impKey));
    XMEMSET(&tpmSession, 0, sizeof(tpmSession));

    printf("TPM2.0 Key Import example\n");
    printf("\tKey Blob: %s\n", outputFile);
    printf("\tAlgorithm: %s\n", TPM2_GetAlgName(alg));
    printf("\tUse Parameter Encryption: %s\n", TPM2_GetAlgName(paramEncAlg));

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("\nwolfTPM2_Init failed\n");
        goto exit;
    }

    /* get SRK */
    rc = getPrimaryStoragekey(&dev, &storage, TPM_ALG_RSA);
    if (rc != 0) goto exit;

    if (paramEncAlg != TPM_ALG_NULL) {
        /* Start an authenticated session (salted / unbound) with parameter encryption */
        rc = wolfTPM2_StartSession(&dev, &tpmSession, &storage, NULL,
            TPM_SE_HMAC, paramEncAlg);
        if (rc != 0) goto exit;
        printf("TPM2_StartAuthSession: sessionHandle 0x%x\n",
            (word32)tpmSession.handle.hndl);

        /* set session for authorization of the storage key */
        rc = wolfTPM2_SetAuthSession(&dev, 1, &tpmSession,
            (TPMA_SESSION_decrypt | TPMA_SESSION_encrypt | TPMA_SESSION_continueSession));
        if (rc != 0) goto exit;
    }

    /* setup an auth value */
    impKey.handle.auth.size = (int)sizeof(gKeyAuth)-1;
    XMEMCPY(impKey.handle.auth.buffer, gKeyAuth, impKey.handle.auth.size);

    if (alg == TPM_ALG_RSA) {
        if (derEncode == 1) {
            rc = wolfTPM2_RsaPrivateKeyImportDer(&dev, &storage, &impKey,
                kRsaKeyPrivDer, sizeof(kRsaKeyPrivDer), TPM_ALG_NULL,
                TPM_ALG_NULL);
        }
        else if (pemEncode == 1) {
            rc = wolfTPM2_RsaPrivateKeyImportPem(&dev, &storage, &impKey,
                kRsaKeyPrivPem, strlen(kRsaKeyPrivPem), NULL,
                TPM_ALG_NULL, TPM_ALG_NULL);
        }
        else {
            /* Import raw RSA private key into TPM */
            rc = wolfTPM2_ImportRsaPrivateKey(&dev, &storage, &impKey,
                kRsaKeyPubModulus, (word32)sizeof(kRsaKeyPubModulus),
                kRsaKeyPubExponent,
                kRsaKeyPrivQ,      (word32)sizeof(kRsaKeyPrivQ),
                TPM_ALG_NULL, TPM_ALG_NULL);
        }
    }
    else if (alg == TPM_ALG_ECC) {
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
#if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_FILESYSTEM)
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
#endif /* !WOLFTPM2_NO_WRAPPER */


#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = NOT_COMPILED_IN;

#ifndef WOLFTPM2_NO_WRAPPER
    rc = TPM2_Keyimport_Example(NULL, argc, argv);
#else
    printf("KeyImport code not compiled in\n");
    (void)argc;
    (void)argv;
#endif

    return rc;
}
#endif
