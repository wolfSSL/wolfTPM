/* external_import.c
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

/* Example for importing an external RSA key with seed and creating a
 * child key under it. */

#include <wolftpm/tpm2_wrap.h>

#include <stdio.h>

#if !defined(WOLFTPM2_NO_WRAPPER) && !defined(WOLFTPM2_NO_WOLFCRYPT)

#include <examples/keygen/keygen.h>
#include <examples/tpm_test_keys.h>
#include <hal/tpm_io.h>

/* For testing */
#define USE_TEST_SEED /* use fixed seed, not random */

/* from certs/example-rsa-key.pem */
const char* extRSAPrivatePem =
"-----BEGIN PRIVATE KEY-----\n"
"MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCePbYR1SIZAL/2\n"
"8FYbgpxynENgvHACM9LczZnsgVkZYxx3O9DTba2VTxhMN21i/aocJCzZB35qvz+R\n"
"ickyvWBqPDXauJEn9icPXgSknqxzw0ZATzL0wbq/Tk5T+oITFFCGJ8/baFoktOKu\n"
"iP5H50Dx6X2W1qNHiLkbGq7NbXHA8YG2wzK9kwikowSXQVB7pZ5bgjW2q73vIGSs\n"
"eW802f7I/30wbf4oR1vfk4OQursT9sl2CFLNt5bJSw6lFTm4BOgC7Q3bpHPzC/YK\n"
"uFYWKGeQL9GCsEZVWHCM6vzek6SNwQ0eoQ0i9IuF0os/0nJDwdXEZX9OoBhFT717\n"
"svlxDXpFAgMBAAECggEABYIV6Jx/5ZloVTbr9GSxP+8PDFq61mTJ6fwxJ7Gf8ZmI\n"
"1+Cp5fYrJOeeK6cBRIEabwTWV86iOKKEGrOOYJkFdmU2pbCngtnXZbpK1JUeYSAy\n"
"vZHULv9gWgDmipdNeE8Md4MCwfspqh3uxw8HNOcIlHMhd0Ls55RLhzVAUO/GliXz\n"
"5HIDhohyQAUvPvkwz1yrPNn5BQwMlJBARc2OKSKf+pJrlFw1KJWR9TKzGvRzMbI4\n"
"gwrq9BZ5LCX5y6C7BpuzXdySHXofwihPNmi1KU/88cWhas2E0Xz+p+N/ifmkquTN\n"
"3EqzqKBW+xobryM6X9JfQ6has211eUaZKNuU2/idKQKBgQC5rymu0UKHuAkr4uPS\n"
"NLGmaWb4p+kDNxbVyzS2ENjtoJ6JyEo/pZQrTG4S/kCWFgGsuztCbx+1Kgk0Pgwi\n"
"znaGvcfrjiP9XE1oVfMifA2JmH+drjASyjPqNfsf0BKQtlk0nZXwUO/C1FQ5vUU4\n"
"lpmpx4EhTnucQ9E7r0+uXnQHTQKBgQDaKh4bBV7dLBF4ZxwCdydMMSZkBgckBiH7\n"
"83BvyLW6I0GKXcFTa7KKLgTj41pXeWh6bmM9365+Cr8fxTZop28EfGRYFBMp08/g\n"
"wHpmS3NZ4moSgirJ+PhZsH+nBq89W75INR7BqV4SAc3n4lcwv9eBL9q0Q/YJZ1ph\n"
"NCKvz79y2QKBgFyDFPVwdQFBg/BFntRARLJwmUkR/1oGvG3QTHbZdfsOp25mR/fl\n"
"+yiHb+AupOciF7uDnUbALsAILYXF1C4TR6JiM5T8wJmev0JYcEaiH+yJ+isJehIi\n"
"hDMQqglzlYxcDZ3VVbrh2FLtjvklf7Nt9SlNqNx7ScLVVw2xjrWFgbGRAoGBAMjo\n"
"Wnsl0fu6Noh74/Z9RmpLJQCd8HuDTk6ZHCVFX91/1D6ZIo0xM+U+hfBbkfnWa5m8\n"
"CJaVZDrcqK+YTQfJkVo/N6VJL3Coh9qBRvbnat4OvQI4bzE6n3LxME1fwYeu8ifL\n"
"C3zq/R92G+n8rbDOKqbkq/KwV2bHkBrOCVeA6NzZAoGACztyZbS5jCuSlPqk/xoN\n"
"EzX9Cev/GipF5tZMeOcQlty+anPg3TC70O06yZ1SIJKLzOOyoPCUDNrM2M5TCaau\n"
"vT0vW1GeNAryc+q9aOmFT3AlZ93Tfst+90Q+NJecEEhkO43tU5S1ZK2iVf9XAOV6\n"
"ovHegJU35IUeaoyg23HjFWU=\n"
"-----END PRIVATE KEY-----";

static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/keygen/external_import [-ecc/-rsa]\n");
    printf("Primary Key Type:\n");
    printf("\t-rsa: Use RSA SRK (DEFAULT)\n");
    printf("\t-ecc: Use ECC SRK\n");
    printf("\t-load: Load the keyblob.bin to 3rd level key "
        "(otherwise create and save)\n");
}

int TPM2_ExternalImport_Example(void* userCtx, int argc, char *argv[])
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY storage; /* SRK */
    WOLFTPM2_KEY *primary;
    WOLFTPM2_KEYBLOB* key2;
    WOLFTPM2_KEYBLOB* rsaKey3;
    TPM2B_DIGEST seedValue;
    TPMT_PUBLIC publicTemplate3;
    TPMA_OBJECT attributes;
    TPMI_ALG_PUBLIC alg = TPM_ALG_RSA;
#if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_FILESYSTEM)
    const char* keyblobFile = "keyblob.bin";
#endif
    int loadKeyBlob = 0;

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
        else if (XSTRCMP(argv[argc-1], "-load") == 0) {
            loadKeyBlob = 1;
        }
        else {
            printf("Warning: Unrecognized option: %s\n", argv[argc-1]);
        }

        argc--;
    }

    key2 = wolfTPM2_NewKeyBlob();
    rsaKey3 = wolfTPM2_NewKeyBlob();
    primary = &storage;

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, NULL);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_Init failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }

    /* RSA or ECC (faster) SRK */
    rc = wolfTPM2_CreateSRK(&dev, &storage, alg, NULL, 0);
    if (rc != 0) {
        printf("Failed to wolfTPM2_CreateSRK\n");
        goto exit;
    }

    /* Second level key */
    attributes = (TPMA_OBJECT_restricted |
             TPMA_OBJECT_sensitiveDataOrigin |
             TPMA_OBJECT_decrypt |
             TPMA_OBJECT_userWithAuth |
             TPMA_OBJECT_noDA);

    /* Generate random seed */
    XMEMSET(&seedValue, 0, sizeof(seedValue));
    seedValue.size = TPM2_GetHashDigestSize(TPM_ALG_SHA256);
#ifndef USE_TEST_SEED
    TPM2_GetNonce(seedValue.buffer, seedValue.size);
#else
    {
        const byte custSeed[] = {
            0x00, 0x01, 0x02, 0x03,  0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B,  0x0C, 0x0D, 0x0E, 0x0F,
            0x00, 0x01, 0x02, 0x03,  0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B,  0x0C, 0x0D, 0x0E, 0x0F,
        };
        XMEMCPY(seedValue.buffer, custSeed, seedValue.size);
    }
#endif
    printf("Import RSA Seed %d\n", seedValue.size);
    TPM2_PrintBin(seedValue.buffer, seedValue.size);

    rc = wolfTPM2_ImportPrivateKeyBuffer(&dev, &storage, TPM_ALG_RSA, key2,
        ENCODING_TYPE_PEM, extRSAPrivatePem, (word32)strlen(extRSAPrivatePem),
        NULL, attributes, seedValue.buffer, seedValue.size);
    if (rc != 0) {
        printf("Failed to wolfTPM2_RsaPrivateKeyImportPem\n");
        goto exit;
    }

    rc = wolfTPM2_LoadKey(&dev, key2, &primary->handle);
    if (rc != 0) {
       printf("Failed to wolfTPM2_LoadKey\n");
       goto exit;
    }

    /* The 3rd level RSA key */
    if (loadKeyBlob) {
        rc = readKeyBlob(keyblobFile, rsaKey3);
        if (rc != TPM_RC_SUCCESS) {
            printf("Error reading keyblob.bin: %d\n", rc);
        }
    }
    else { /* create key and save as keyblob.bin */
        rc = wolfTPM2_GetKeyTemplate_RSA(&publicTemplate3,
            TPMA_OBJECT_sensitiveDataOrigin |
            TPMA_OBJECT_userWithAuth |
            TPMA_OBJECT_sign |
            TPMA_OBJECT_noDA);
        if (rc != 0) {
            printf("Failed to wolfTPM2_GetKeyTemplate_RSA\n");
            goto exit;
        }
        rc = wolfTPM2_CreateKey(&dev, rsaKey3, &key2->handle,
            &publicTemplate3, NULL, 0);
        if (rc != TPM_RC_SUCCESS) {
            printf("wolfTPM2_CreateKey failed for the 3rd level key: %d\n", rc);
            goto exit;
        }

        printf("Key Public Blob %d\n", rsaKey3->pub.size);
        TPM2_PrintBin((const byte*)&rsaKey3->pub.publicArea, rsaKey3->pub.size);
        printf("Key Private Blob %d\n", rsaKey3->priv.size);
        TPM2_PrintBin(rsaKey3->priv.buffer, rsaKey3->priv.size);

        /* Save key as encrypted blob to the disk */
    #if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_FILESYSTEM)
        rc = writeKeyBlob(keyblobFile, rsaKey3);
        if (rc != TPM_RC_SUCCESS) {
            printf("Error saving keyblob.bin: %d\n", rc);
        }
    #endif
    }

    /* load the rsa key */
    rc = wolfTPM2_LoadKey(&dev, rsaKey3, &key2->handle);
    if (rc != 0) {
        printf("Failed to wolfTPM2_LoadKey %d\n", rc);
        goto exit;
    }

exit:
    wolfTPM2_UnloadHandle(&dev, &rsaKey3->handle);
    wolfTPM2_UnloadHandle(&dev, &key2->handle);
    wolfTPM2_UnloadHandle(&dev, &primary->handle);

    wolfTPM2_FreeKeyBlob(key2);
    wolfTPM2_FreeKeyBlob(rsaKey3);

    wolfTPM2_Cleanup(&dev);

    (void)userCtx;
    (void)argc;


    return rc;
}
#endif /* !WOLFTPM2_NO_WRAPPER && !WOLFTPM2_NO_WOLFCRYPT */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = NOT_COMPILED_IN;

#if !defined(WOLFTPM2_NO_WRAPPER) && !defined(WOLFTPM2_NO_WOLFCRYPT)
    rc = TPM2_ExternalImport_Example(NULL, argc, argv);
#else
    printf("Example for external import and child key creation (not compiled in)\n");
    (void)argc;
    (void)argv;
#endif

    return rc;
}
#endif
