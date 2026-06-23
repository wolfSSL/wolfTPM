/* ecdh.c
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

/* Example for ECDH key agreement (shared secret) using the TPM */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2_wrap.h>

#ifndef WOLFTPM2_NO_WRAPPER

#include <hal/tpm_io.h>
#include <examples/tpm_test.h>
#include <examples/tpm_test_keys.h>
#include <examples/keygen/keygen.h>

#include <stdio.h>

/******************************************************************************/
/* --- BEGIN TPM2 ECDH example -- */
/******************************************************************************/

#ifdef HAVE_ECC
static void usage(void)
{
    printf("Expected Usage:\n");
    printf("./examples/keygen/ecdh\n");
    printf("* Demonstrates ECDH key agreement using NIST P-256\n");
}
#endif

int TPM2_ECDH_Example(void* userCtx, int argc, char* argv[])
{
    int rc;
#ifdef HAVE_ECC
    int i;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY storage; /* SRK */
    WOLFTPM2_KEY eccKey;
    TPMT_PUBLIC publicTemplate;
    TPM2B_ECC_POINT pubPoint; /* ephemeral public point from the TPM */
    byte secret[MAX_ECC_BYTES];
    int secretSz = (int)sizeof(secret);

    if (argc > 1) {
        if (XSTRCMP(argv[1], "-?") == 0 ||
            XSTRCMP(argv[1], "-h") == 0 ||
            XSTRCMP(argv[1], "--help") == 0) {
            usage();
            return 0;
        }
    }

    printf("TPM2 ECDH Example\n");

    XMEMSET(&storage, 0, sizeof(storage));
    XMEMSET(&eccKey, 0, sizeof(eccKey));
    XMEMSET(&publicTemplate, 0, sizeof(publicTemplate));
    XMEMSET(&pubPoint, 0, sizeof(pubPoint));
    XMEMSET(secret, 0, sizeof(secret));

    /* Init the TPM2 device */
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != 0) {
        printf("wolfTPM2_Init failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        return rc;
    }

    /* Create or load the Storage Root Key (SRK) */
    rc = getPrimaryStoragekey(&dev, &storage, TPM_ALG_ECC);
    if (rc != 0) {
        printf("getPrimaryStoragekey failed 0x%x: %s\n", rc,
            wolfTPM2_GetRCString(rc));
        goto exit;
    }

    /* Create and load an ECC key for key-agreement (ECDH) under the SRK */
    rc = wolfTPM2_GetKeyTemplate_ECC(&publicTemplate,
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_decrypt | TPMA_OBJECT_noDA,
        TPM_ECC_NIST_P256, TPM_ALG_ECDH);
    if (rc != 0) {
        printf("wolfTPM2_GetKeyTemplate_ECC failed 0x%x: %s\n", rc,
            wolfTPM2_GetRCString(rc));
        goto exit;
    }
    publicTemplate.nameAlg = TPM_ALG_SHA256; /* make sure its SHA256 */

    rc = wolfTPM2_CreateAndLoadKey(&dev, &eccKey, &storage.handle,
        &publicTemplate, (const byte*)gKeyAuth, sizeof(gKeyAuth)-1);
    if (rc != 0) {
        printf("wolfTPM2_CreateAndLoadKey failed 0x%x: %s\n", rc,
            wolfTPM2_GetRCString(rc));
        goto exit;
    }

    /* Generate an ephemeral point and compute the shared secret Z.
     * The TPM returns the ephemeral public point (pubPoint) that the peer
     * would use to compute the same secret. */
    rc = wolfTPM2_ECDHGen(&dev, &eccKey, &pubPoint, secret, &secretSz);
    if (rc != 0) {
        printf("wolfTPM2_ECDHGen failed 0x%x: %s\n", rc,
            wolfTPM2_GetRCString(rc));
        goto exit;
    }

    printf("ECDH key agreement success\n");
    printf("Ephemeral point: X size %u, Y size %u\n",
        pubPoint.point.x.size, pubPoint.point.y.size);
    printf("Shared secret Z (%d bytes):\n", secretSz);
    for (i = 0; i < secretSz; i++) {
        printf("%02x", secret[i]);
    }
    printf("\n");

exit:

    wolfTPM2_UnloadHandle(&dev, &eccKey.handle);
    wolfTPM2_UnloadHandle(&dev, &storage.handle);

    wolfTPM2_Cleanup(&dev);

#else
    (void)userCtx;
    (void)argc;
    (void)argv;
    printf("ECDH example: not supported (HAVE_ECC not defined)\n");
    rc = 0;
#endif /* HAVE_ECC */

    return rc;
}

/******************************************************************************/
/* --- END TPM2 ECDH example -- */
/******************************************************************************/

#endif /* !WOLFTPM2_NO_WRAPPER */

#ifndef NO_MAIN_DRIVER
int main(int argc, char* argv[])
{
    int rc = -1;

#ifndef WOLFTPM2_NO_WRAPPER
    rc = TPM2_ECDH_Example(NULL, argc, argv);
#else
    (void)argc;
    (void)argv;
    printf("Wrapper code not compiled in\n");
#endif

    return rc;
}
#endif /* !NO_MAIN_DRIVER */
