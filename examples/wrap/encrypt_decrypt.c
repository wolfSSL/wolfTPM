/* encrypt_decrypt.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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

/* Example for symmetric encrypt/decrypt using a TPM generated AES key */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2_wrap.h>

#ifndef WOLFTPM2_NO_WRAPPER

#include <hal/tpm_io.h>
#include <examples/tpm_test.h>
#include <examples/tpm_test_keys.h>
#include <examples/wrap/wrap_test.h>

#include <stdio.h>

/* Number of message bytes to encrypt/decrypt */
#define ENCDEC_MSG_SIZE 32

/******************************************************************************/
/* --- BEGIN TPM2 Encrypt/Decrypt example -- */
/******************************************************************************/

static void usage(void)
{
    printf("Expected Usage:\n");
    printf("./examples/wrap/encrypt_decrypt [-aesctr] [-aescbc] [-aescfb]\n");
    printf("* AES mode defaults to CTR; use -aescbc or -aescfb to override\n");
    printf("* NOTE: many TPM's disable TPM2_EncryptDecrypt entirely due to\n");
    printf("        export controls (see examples/tpm_test.h); when enabled\n");
    printf("        the supported mode varies by TPM\n");
}

int TPM2_EncryptDecrypt_Example(void* userCtx, int argc, char* argv[])
{
    int rc;
    int i;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY storage; /* SRK */
    WOLFTPM2_KEY aesKey;
    TPMT_PUBLIC publicTemplate;
    /* TPM2_EncryptDecrypt is frequently disabled entirely due to export
     * controls (see comments in examples/tpm_test.h); when enabled the
     * supported mode varies by TPM. Default to CTR; -aescbc / -aescfb
     * override. A fully disabled command is handled gracefully below. */
    TPM_ALG_ID mode = TPM_ALG_CTR;
    const char* modeName = "AES-CTR";
    byte message[ENCDEC_MSG_SIZE];
    byte cipher[ENCDEC_MSG_SIZE];
    byte plain[ENCDEC_MSG_SIZE];
    byte iv[MAX_AES_BLOCK_SIZE_BYTES];

    if (argc > 1) {
        if (XSTRCMP(argv[1], "-?") == 0 ||
            XSTRCMP(argv[1], "-h") == 0 ||
            XSTRCMP(argv[1], "--help") == 0) {
            usage();
            return 0;
        }
    }

    for (i = 1; i < argc; i++) {
        if (XSTRCMP(argv[i], "-aesctr") == 0) {
            mode = TPM_ALG_CTR;
            modeName = "AES-CTR";
        }
        else if (XSTRCMP(argv[i], "-aescbc") == 0) {
            mode = TPM_ALG_CBC;
            modeName = "AES-CBC";
        }
        else if (XSTRCMP(argv[i], "-aescfb") == 0) {
            mode = TPM_ALG_CFB;
            modeName = "AES-CFB";
        }
    }

    printf("TPM2 Encrypt/Decrypt Example (%s)\n", modeName);

    XMEMSET(&storage, 0, sizeof(storage));
    XMEMSET(&aesKey, 0, sizeof(aesKey));
    XMEMSET(&publicTemplate, 0, sizeof(publicTemplate));

    /* Test data */
    for (i = 0; i < (int)sizeof(message); i++) {
        message[i] = (byte)(i & 0xff);
    }
    XMEMSET(cipher, 0, sizeof(cipher));
    XMEMSET(plain, 0, sizeof(plain));

    /* Init the TPM2 device */
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != 0) {
        printf("wolfTPM2_Init failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        return rc;
    }

    /* Create or load the Storage Root Key (SRK) */
    rc = getPrimaryStoragekey(&dev, &storage, TPM_ALG_RSA);
    if (rc != 0) {
        printf("getPrimaryStoragekey failed 0x%x: %s\n", rc,
            wolfTPM2_GetRCString(rc));
        goto exit;
    }

    /* Create and load a 128-bit symmetric key under the SRK
     * (isSign=NO, isDecrypt=YES) */
    rc = wolfTPM2_GetKeyTemplate_Symmetric(&publicTemplate, 128, mode, NO, YES);
    if (rc != 0) {
        printf("wolfTPM2_GetKeyTemplate_Symmetric failed 0x%x: %s\n", rc,
            wolfTPM2_GetRCString(rc));
        goto exit;
    }
    rc = wolfTPM2_CreateAndLoadKey(&dev, &aesKey, &storage.handle,
        &publicTemplate, (const byte*)gUsageAuth, sizeof(gUsageAuth)-1);
    if (rc != 0) {
        printf("wolfTPM2_CreateAndLoadKey failed 0x%x: %s\n", rc,
            wolfTPM2_GetRCString(rc));
        goto exit;
    }

    /* Encrypt */
    XMEMSET(iv, 0, sizeof(iv));
    rc = wolfTPM2_EncryptDecrypt(&dev, &aesKey, message, cipher,
        (word32)sizeof(message), iv, (word32)sizeof(iv), WOLFTPM2_ENCRYPT);
    if (rc != 0 && !WOLFTPM_IS_COMMAND_UNAVAILABLE(rc)) {
        printf("wolfTPM2_EncryptDecrypt (encrypt) failed 0x%x: %s\n", rc,
            wolfTPM2_GetRCString(rc));
        goto exit;
    }

    if (WOLFTPM_IS_COMMAND_UNAVAILABLE(rc)) {
        printf("Encrypt/Decrypt: not supported (export controls)\n");
        rc = 0; /* not an error condition */
        goto exit;
    }

    /* Decrypt */
    XMEMSET(iv, 0, sizeof(iv));
    rc = wolfTPM2_EncryptDecrypt(&dev, &aesKey, cipher, plain,
        (word32)sizeof(cipher), iv, (word32)sizeof(iv), WOLFTPM2_DECRYPT);
    if (rc != 0 && !WOLFTPM_IS_COMMAND_UNAVAILABLE(rc)) {
        printf("wolfTPM2_EncryptDecrypt (decrypt) failed 0x%x: %s\n", rc,
            wolfTPM2_GetRCString(rc));
        goto exit;
    }

    if (WOLFTPM_IS_COMMAND_UNAVAILABLE(rc)) {
        printf("Encrypt/Decrypt: not supported (export controls)\n");
        rc = 0; /* not an error condition */
        goto exit;
    }

    if (XMEMCMP(message, plain, sizeof(message)) != 0) {
        printf("Encrypt/Decrypt test failed, result not as expected!\n");
        rc = TPM_RC_TESTING;
        goto exit;
    }
    printf("Encrypt/Decrypt test success\n");

exit:

    wolfTPM2_UnloadHandle(&dev, &aesKey.handle);
    wolfTPM2_UnloadHandle(&dev, &storage.handle);

    wolfTPM2_Cleanup(&dev);

    return rc;
}

/******************************************************************************/
/* --- END TPM2 Encrypt/Decrypt example -- */
/******************************************************************************/

#endif /* !WOLFTPM2_NO_WRAPPER */

#ifndef NO_MAIN_DRIVER
int main(int argc, char* argv[])
{
    int rc = -1;

#ifndef WOLFTPM2_NO_WRAPPER
    rc = TPM2_EncryptDecrypt_Example(NULL, argc, argv);
#else
    (void)argc;
    (void)argv;
    printf("Wrapper code not compiled in\n");
#endif

    return rc;
}
#endif /* !NO_MAIN_DRIVER */
