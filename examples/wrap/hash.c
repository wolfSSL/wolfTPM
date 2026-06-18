/* hash.c
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

/* Example for computing a hash digest using the TPM hash sequence */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2_wrap.h>

#ifndef WOLFTPM2_NO_WRAPPER

#include <hal/tpm_io.h>
#include <examples/tpm_test.h>
#include <examples/wrap/wrap_test.h>

#include <stdio.h>

/******************************************************************************/
/* --- BEGIN TPM2 Hash example -- */
/******************************************************************************/

static void usage(void)
{
    printf("Expected Usage:\n");
    printf("./examples/wrap/hash [message] [-sha256] [-sha384] [-sha512]\n");
    printf("* message is the string to hash (default is a test vector)\n");
    printf("* hash algorithm defaults to SHA-256\n");
}

int TPM2_Hash_Example(void* userCtx, int argc, char* argv[])
{
    int rc;
    int i;
    WOLFTPM2_DEV dev;
    WOLFTPM2_HASH hash;
    TPMI_ALG_HASH hashAlg = TPM_ALG_SHA256;
    const char* hashAlgName = "SHA-256";
    byte digest[TPM_MAX_DIGEST_SIZE];
    word32 digestSz = (word32)sizeof(digest);
    /* NIST SHA test vector message */
    const char* message =
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

    if (argc > 1) {
        if (XSTRCMP(argv[1], "-?") == 0 ||
            XSTRCMP(argv[1], "-h") == 0 ||
            XSTRCMP(argv[1], "--help") == 0) {
            usage();
            return 0;
        }
    }

    for (i = 1; i < argc; i++) {
        if (XSTRCMP(argv[i], "-sha256") == 0) {
            hashAlg = TPM_ALG_SHA256;
            hashAlgName = "SHA-256";
        }
        else if (XSTRCMP(argv[i], "-sha384") == 0) {
        #ifdef WOLFSSL_SHA384
            hashAlg = TPM_ALG_SHA384;
            hashAlgName = "SHA-384";
        #else
            printf("SHA-384 not enabled in this build\n");
            return 0;
        #endif
        }
        else if (XSTRCMP(argv[i], "-sha512") == 0) {
        #ifdef WOLFSSL_SHA512
            hashAlg = TPM_ALG_SHA512;
            hashAlgName = "SHA-512";
        #else
            printf("SHA-512 not enabled in this build\n");
            return 0;
        #endif
        }
        else if (argv[i][0] != '-') {
            message = argv[i];
        }
        else {
            printf("Unknown option: %s\n", argv[i]);
            usage();
            return -1;
        }
    }

    printf("TPM2 Hash Example (%s)\n", hashAlgName);
    printf("Message: %s\n", message);

    XMEMSET(&hash, 0, sizeof(hash));
    XMEMSET(digest, 0, sizeof(digest));

    /* Init the TPM2 device */
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != 0) {
        printf("wolfTPM2_Init failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        return rc;
    }

    rc = wolfTPM2_HashStart(&dev, &hash, hashAlg, NULL, 0);
    if (rc != 0) {
        printf("wolfTPM2_HashStart failed 0x%x: %s\n", rc,
            wolfTPM2_GetRCString(rc));
        goto exit;
    }

    rc = wolfTPM2_HashUpdate(&dev, &hash, (const byte*)message,
        (word32)XSTRLEN(message));
    if (rc != 0) {
        printf("wolfTPM2_HashUpdate failed 0x%x: %s\n", rc,
            wolfTPM2_GetRCString(rc));
        goto exit;
    }

    rc = wolfTPM2_HashFinish(&dev, &hash, digest, &digestSz);
    if (rc != 0) {
        printf("wolfTPM2_HashFinish failed 0x%x: %s\n", rc,
            wolfTPM2_GetRCString(rc));
        goto exit;
    }

    printf("Digest (%u bytes):\n", digestSz);
    for (i = 0; i < (int)digestSz; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");

exit:

    wolfTPM2_Cleanup(&dev);

    return rc;
}

/******************************************************************************/
/* --- END TPM2 Hash example -- */
/******************************************************************************/

#endif /* !WOLFTPM2_NO_WRAPPER */

#ifndef NO_MAIN_DRIVER
int main(int argc, char* argv[])
{
    int rc = -1;

#ifndef WOLFTPM2_NO_WRAPPER
    rc = TPM2_Hash_Example(NULL, argc, argv);
#else
    (void)argc;
    (void)argv;
    printf("Wrapper code not compiled in\n");
#endif

    return rc;
}
#endif /* !NO_MAIN_DRIVER */
