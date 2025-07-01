/* hmac.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

/* This example shows using the TPM2 wrapper API's for HMAC
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_wrap.h>

#include <stdio.h>

#ifndef WOLFTPM2_NO_WRAPPER

#include <hal/tpm_io.h>
#include <examples/tpm_test.h>
#include <examples/tpm_test_keys.h>
#include <examples/wrap/wrap_test.h>

static void usage(void)
{
    printf("Expected Usage:\n");
    printf("./examples/wrap/hmac [-aes/xor] [-rsa/ecc]\n");
    printf("* -aes/xor: Use Parameter Encryption\n");
    printf("* -rsa/ecc: Use RSA or ECC for SRK (default ECC)\n");
    printf("* -keep: Keep the HMAC key in persistent storage\n");
    printf("\nThis example demonstrates:\n");
    printf("1. Creating an SRK (Storage Root Key)\n");
    printf("2. Loading an HMAC key using the SRK as parent\n");
    printf("3. Storing the HMAC key persistently at handle 0x%x\n",
        TPM2_DEMO_HMAC_KEY_HANDLE);
    printf("4. Using the persistent HMAC key for HMAC operations\n");
    printf("5. Reusing the persistent key for multiple operations\n\n");
}

int TPM2_Wrapper_Hmac(void* userCtx)
{
    return TPM2_Wrapper_HmacArgs(userCtx, 0, NULL);
}
int TPM2_Wrapper_HmacArgs(void* userCtx, int argc, char *argv[])
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY storage; /* SRK */
    WOLFTPM2_HMAC hmac;
    WOLFTPM2_SESSION tpmSession;
    TPMI_ALG_PUBLIC srkAlg = TPM_ALG_ECC; /* prefer ECC, but allow RSA */
    TPM_ALG_ID paramEncAlg = TPM_ALG_NULL;
    WOLFTPM2_BUFFER cipher;
    int keepKey = 0;

    const char* hmacTestKey =
        "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
        "\x0b\x0b\x0b\x0b";
    const char* hmacTestData = "Hi There";
    const char* hmacTestDig =
        "\xb0\x34\x4c\x61\xd8\xdb\x38\x53\x5c\xa8\xaf\xce\xaf\x0b\xf1\x2b"
        "\x88\x1d\xc2\x00\xc9\x83\x3d\xa7\x26\xe9\x37\x6c\x2e\x32\xcf\xf7";

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
            srkAlg = TPM_ALG_RSA;
        }
        else if (XSTRCMP(argv[argc-1], "-ecc") == 0) {
            srkAlg = TPM_ALG_ECC;
        }
        else if (XSTRCMP(argv[argc-1], "-aes") == 0) {
            paramEncAlg = TPM_ALG_CFB;
        }
        else if (XSTRCMP(argv[argc-1], "-xor") == 0) {
            paramEncAlg = TPM_ALG_XOR;
        }
        else if (XSTRCMP(argv[argc-1], "-keep") == 0) {
            keepKey = 1;
        }
        else {
            printf("Warning: Unrecognized option: %s\n", argv[argc-1]);
        }

        argc--;
    }

    XMEMSET(&hmac, 0, sizeof(hmac));
    XMEMSET(&tpmSession, 0, sizeof(tpmSession));

    printf("TPM2.0 HMAC example\n");
    printf("\tUse Parameter Encryption: %s\n", TPM2_GetAlgName(paramEncAlg));
    printf("\tSRK: %s\n", TPM2_GetAlgName(srkAlg));

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != 0) goto exit;

    /* storage root key (SRK) */
    rc = getPrimaryStoragekey(&dev, &storage, srkAlg);
    if (rc != 0) goto exit;

    /* Start an authenticated session (salted / unbound) with parameter encryption */
    if (paramEncAlg != TPM_ALG_NULL) {
        WOLFTPM2_KEY* bindKey = &storage;
    #ifdef NO_RSA
        if (srkAlg == TPM_ALG_RSA)
            bindKey = NULL; /* cannot bind to key without RSA enabled */
    #endif
    #ifndef HAVE_ECC
        if (srkAlg == TPM_ALG_ECC)
            bindKey = NULL; /* cannot bind to key without ECC enabled */
    #endif
        rc = wolfTPM2_StartSession(&dev, &tpmSession, bindKey, NULL,
            TPM_SE_HMAC, paramEncAlg);
        if (rc != 0) goto exit;
        printf("TPM2_StartAuthSession: sessionHandle 0x%x\n",
            (word32)tpmSession.handle.hndl);

        /* set session for authorization of the storage key */
        rc = wolfTPM2_SetAuthSession(&dev, 0, &tpmSession,
            (TPMA_SESSION_decrypt | TPMA_SESSION_encrypt | TPMA_SESSION_continueSession));
        if (rc != 0) goto exit;
    }

    /* Try to load existing persistent HMAC key first */
    rc = wolfTPM2_ReadPublicKey(&dev, &hmac.key, TPM2_DEMO_HMAC_KEY_HANDLE);
    if (rc != 0) {
        printf("Persistent HMAC key not found, creating new one...\n");

        /* Load Keyed Hash Key */
        rc = wolfTPM2_LoadKeyedHashKey(&dev, &hmac.key, &storage.handle,
            TPM_ALG_SHA256,
            (const byte*)hmacTestKey, (word32)XSTRLEN(hmacTestKey),
            (const byte*)gUsageAuth, sizeof(gUsageAuth)-1);
        if (rc != 0) goto exit;

        printf("Storing HMAC key to persistent handle 0x%x\n", TPM2_DEMO_HMAC_KEY_HANDLE);
        /* Store the HMAC key to persistent storage */
        rc = wolfTPM2_NVStoreKey(&dev, TPM_RH_OWNER, &hmac.key,
            TPM2_DEMO_HMAC_KEY_HANDLE);
        if (rc != 0) {
            printf("wolfTPM2_NVStoreKey failed 0x%x: %s\n", rc,
                wolfTPM2_GetRCString(rc));
            goto exit;
        }
        printf("HMAC key stored persistently at handle 0x%x\n",
            TPM2_DEMO_HMAC_KEY_HANDLE);
    }
    else {
        printf("Using existing persistent HMAC key at handle 0x%x\n",
            TPM2_DEMO_HMAC_KEY_HANDLE);

        /* Set auth for persistent key */
        hmac.key.handle.auth.size = sizeof(gUsageAuth)-1;
        XMEMCPY(hmac.key.handle.auth.buffer, gUsageAuth,
            hmac.key.handle.auth.size);
    }

    /* Test HMAC operations using the persistent key */
    printf("\nTesting HMAC operations with persistent key...\n");

    hmac.hmacKeyKeep = 1; /* don't unload key on finish */
    rc = wolfTPM2_HmacStart(&dev, &hmac, &storage.handle, TPM_ALG_SHA256,
        NULL, 0, (const byte*)gUsageAuth, sizeof(gUsageAuth)-1);
    if (rc != 0) goto exit;

    rc = wolfTPM2_HmacUpdate(&dev, &hmac, (byte*)hmacTestData,
        (word32)XSTRLEN(hmacTestData));
    if (rc != 0) goto exit;

    cipher.size = TPM_SHA256_DIGEST_SIZE;
    rc = wolfTPM2_HmacFinish(&dev, &hmac, cipher.buffer, (word32*)&cipher.size);
    if (rc != 0) goto exit;

    if (cipher.size != TPM_SHA256_DIGEST_SIZE ||
        XMEMCMP(cipher.buffer, hmacTestDig, cipher.size) != 0) {
        printf("HMAC SHA256 test failed, result not as expected!\n");
        goto exit;
    }
    printf("HMAC SHA256 test with persistent key: PASSED\n");

    if (!keepKey) {
        /* remove the key from persistent storage */
        wolfTPM2_SetAuthPassword(&dev, 0, NULL);
        wolfTPM2_NVDeleteKey(&dev, TPM_RH_OWNER, &hmac.key);
    }

exit:
    if (rc != 0) {
        printf("\nFailure 0x%x: %s\n\n", rc, wolfTPM2_GetRCString(rc));
    }

    /* Clean up session */
    wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);
    wolfTPM2_UnloadHandle(&dev, &hmac.key.handle);

    wolfTPM2_Cleanup(&dev);
    return rc;
}

#endif /* !WOLFTPM2_NO_WRAPPER */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = -1;

#ifndef WOLFTPM2_NO_WRAPPER
    rc = TPM2_Wrapper_HmacArgs(NULL, argc, argv);
#else
    (void)argc;
    (void)argv;
    printf("Wrapper code not compiled in\n");
#endif

    return rc;
}
#endif /* !NO_MAIN_DRIVER */
