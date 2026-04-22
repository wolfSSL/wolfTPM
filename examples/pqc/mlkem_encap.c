/* mlkem_encap.c
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

/* Example: ML-KEM Encapsulate / Decapsulate round-trip using wolfTPM2
 * wrappers. Per TCG TPM 2.0 v1.85 Part 3 §14.10 / §14.11. */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2_wrap.h>
#include <hal/tpm_io.h>
#include <examples/tpm_test.h>

#include <stdio.h>
#include <string.h>

#if !defined(WOLFTPM2_NO_WRAPPER) && defined(WOLFTPM_V185)

static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/pqc/mlkem_encap [-mlkem=512|768|1024]\n");
    printf("* -mlkem=N: Parameter set (default 768)\n");
}

static int parseParamSet(const char* arg, TPMI_MLKEM_PARAMETER_SET* ps)
{
    int n = XATOI(arg);
    switch (n) {
        case 0:
        case 768:  *ps = TPM_MLKEM_768;  return 0;
        case 512:  *ps = TPM_MLKEM_512;  return 0;
        case 1024: *ps = TPM_MLKEM_1024; return 0;
        default:   return BAD_FUNC_ARG;
    }
}

static int mlkem_encap_run(int argc, char *argv[])
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY mlkemKey;
    TPMT_PUBLIC pubTemplate;
    TPMI_MLKEM_PARAMETER_SET paramSet = TPM_MLKEM_768;
    byte ciphertext[1600];
    int ciphertextSz = (int)sizeof(ciphertext);
    byte sharedSecret1[64];
    int sharedSecret1Sz = (int)sizeof(sharedSecret1);
    byte sharedSecret2[64];
    int sharedSecret2Sz = (int)sizeof(sharedSecret2);

    if (argc >= 2) {
        if (XSTRCMP(argv[1], "-?") == 0 ||
            XSTRCMP(argv[1], "-h") == 0 ||
            XSTRCMP(argv[1], "--help") == 0) {
            usage();
            return 0;
        }
    }
    while (argc > 1) {
        if (XSTRCMP(argv[argc-1], "-mlkem") == 0 ||
                XSTRNCMP(argv[argc-1], "-mlkem=",
                    XSTRLEN("-mlkem=")) == 0) {
            const char* val = (argv[argc-1][6] == '=') ?
                argv[argc-1] + 7 : "";
            if (parseParamSet(val, &paramSet) != 0) {
                usage();
                return BAD_FUNC_ARG;
            }
        }
        else {
            printf("Warning: Unrecognized option: %s\n", argv[argc-1]);
        }
        argc--;
    }

    XMEMSET(&dev, 0, sizeof(dev));
    XMEMSET(&mlkemKey, 0, sizeof(mlkemKey));
    XMEMSET(&pubTemplate, 0, sizeof(pubTemplate));
    XMEMSET(ciphertext, 0, sizeof(ciphertext));
    XMEMSET(sharedSecret1, 0, sizeof(sharedSecret1));
    XMEMSET(sharedSecret2, 0, sizeof(sharedSecret2));

    printf("TPM2.0 ML-KEM Encapsulation Example\n");
    printf("\tParameter Set: ML-KEM-%s\n",
        paramSet == TPM_MLKEM_512  ? "512"  :
        paramSet == TPM_MLKEM_1024 ? "1024" : "768");

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, NULL);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_Init failed 0x%x: %s\n",
            rc, wolfTPM2_GetRCString(rc));
        return rc;
    }

    rc = wolfTPM2_GetKeyTemplate_MLKEM(&pubTemplate,
        TPMA_OBJECT_decrypt | TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent |
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_noDA, paramSet);
    if (rc != TPM_RC_SUCCESS) goto exit;

    rc = wolfTPM2_CreatePrimaryKey(&dev, &mlkemKey, TPM_RH_OWNER,
        &pubTemplate, NULL, 0);
    if (rc != TPM_RC_SUCCESS) {
        printf("CreatePrimary failed 0x%x: %s\n",
            rc, wolfTPM2_GetRCString(rc));
        goto exit;
    }
    printf("Created ML-KEM primary: handle 0x%08x, pubkey %u bytes\n",
        (unsigned)mlkemKey.handle.hndl,
        (unsigned)mlkemKey.pub.publicArea.unique.mlkem.size);

    rc = wolfTPM2_Encapsulate(&dev, &mlkemKey, ciphertext, &ciphertextSz,
        sharedSecret1, &sharedSecret1Sz);
    if (rc != TPM_RC_SUCCESS) {
        printf("Encapsulate failed 0x%x: %s\n",
            rc, wolfTPM2_GetRCString(rc));
        goto exit;
    }
    printf("Encapsulate: ciphertext %d bytes, shared secret %d bytes\n",
        ciphertextSz, sharedSecret1Sz);

    rc = wolfTPM2_Decapsulate(&dev, &mlkemKey, ciphertext, ciphertextSz,
        sharedSecret2, &sharedSecret2Sz);
    if (rc != TPM_RC_SUCCESS) {
        printf("Decapsulate failed 0x%x: %s\n",
            rc, wolfTPM2_GetRCString(rc));
        goto exit;
    }
    printf("Decapsulate: shared secret %d bytes\n", sharedSecret2Sz);

    if (sharedSecret1Sz != sharedSecret2Sz ||
            XMEMCMP(sharedSecret1, sharedSecret2, sharedSecret1Sz) != 0) {
        printf("ERROR: shared secrets do not match\n");
        rc = TPM_RC_FAILURE;
        goto exit;
    }
    printf("Round-trip OK: encapsulated secret matches decapsulated secret\n");

exit:
    wc_ForceZero(sharedSecret1, sizeof(sharedSecret1));
    wc_ForceZero(sharedSecret2, sizeof(sharedSecret2));
    wolfTPM2_UnloadHandle(&dev, &mlkemKey.handle);
    wolfTPM2_Cleanup(&dev);
    return rc;
}

#endif /* !WOLFTPM2_NO_WRAPPER && WOLFTPM_V185 */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
#if !defined(WOLFTPM2_NO_WRAPPER) && defined(WOLFTPM_V185)
    int rc = mlkem_encap_run(argc, argv);
    return (rc == 0) ? 0 : 1;
#else
    (void)argc;
    (void)argv;
    printf("Example requires --enable-v185\n");
    return 0;
#endif
}
#endif /* NO_MAIN_DRIVER */
