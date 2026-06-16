/* mlkem_decap_neg.c
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

/* Example: ML-KEM negative decapsulation. Confirms a genuine ciphertext
 * reproduces the encapsulated shared secret while a tampered ciphertext
 * yields a different secret (FIPS 203 implicit rejection), per TCG v1.85
 * Part 3 Sec.14.10/14.11. */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2_wrap.h>
#include <hal/tpm_io.h>
#include <examples/tpm_test.h>

#include <stdio.h>
#include <string.h>

#if !defined(WOLFTPM2_NO_WRAPPER) && \
    defined(WOLFTPM_MLKEM_ENCAP) && defined(WOLFTPM_MLKEM_DECAP)

static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/pqc/mlkem_decap_neg [-mlkem=512|768|1024]\n");
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
        default: return BAD_FUNC_ARG;
    }
}

static int mlkem_decap_neg_run(int argc, char *argv[])
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY mlkemKey;
    TPMT_PUBLIC pubTemplate;
    TPMI_MLKEM_PARAMETER_SET paramSet = TPM_MLKEM_768;
    byte ciphertext[1600];
    int ciphertextSz = (int)sizeof(ciphertext);
    byte secretEncap[64];
    int secretEncapSz = (int)sizeof(secretEncap);
    byte secretGood[64];
    int secretGoodSz = (int)sizeof(secretGood);
    byte secretBad[64];
    int secretBadSz = (int)sizeof(secretBad);
    int correct = 0; /* count of cases that behaved as required */

    XMEMSET(&dev, 0, sizeof(dev));
    XMEMSET(&mlkemKey, 0, sizeof(mlkemKey));
    XMEMSET(&pubTemplate, 0, sizeof(pubTemplate));
    XMEMSET(ciphertext, 0, sizeof(ciphertext));
    XMEMSET(secretEncap, 0, sizeof(secretEncap));
    XMEMSET(secretGood, 0, sizeof(secretGood));
    XMEMSET(secretBad, 0, sizeof(secretBad));

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
                XSTRNCMP(argv[argc-1], "-mlkem=", XSTRLEN("-mlkem=")) == 0) {
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

    printf("TPM2.0 ML-KEM Negative Decapsulation Example\n");
    printf("\tParameter Set: ML-KEM-%s\n",
        paramSet == TPM_MLKEM_512 ? "512" :
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

    /* Encapsulate to obtain a genuine ciphertext and its shared secret. */
    rc = wolfTPM2_Encapsulate(&dev, &mlkemKey, ciphertext, &ciphertextSz,
        secretEncap, &secretEncapSz);
    if (rc != TPM_RC_SUCCESS) {
        printf("Encapsulate failed 0x%x: %s\n", rc, wolfTPM2_GetRCString(rc));
        goto exit;
    }
    printf("Encapsulated: ciphertext %d bytes, shared secret %d bytes\n",
        ciphertextSz, secretEncapSz);

    /* Case 1: genuine ciphertext MUST decapsulate to the same secret. */
    rc = wolfTPM2_Decapsulate(&dev, &mlkemKey, ciphertext, ciphertextSz,
        secretGood, &secretGoodSz);
    if (rc == TPM_RC_SUCCESS && secretGoodSz == secretEncapSz &&
            XMEMCMP(secretGood, secretEncap, secretEncapSz) == 0) {
        printf("[1] genuine ciphertext    -> secret MATCHES   (expected)\n");
        correct++;
    }
    else {
        printf("[1] genuine ciphertext    -> secret MISMATCH 0x%x (UNEXPECTED)\n",
            rc);
    }

    /* Case 2: flip one bit in the ciphertext. Implicit rejection returns a
     * different secret, so it MUST NOT match the encapsulated one. */
    ciphertext[ciphertextSz / 2] ^= 0x01;
    secretBadSz = (int)sizeof(secretBad);
    rc = wolfTPM2_Decapsulate(&dev, &mlkemKey, ciphertext, ciphertextSz,
        secretBad, &secretBadSz);
    if (rc == TPM_RC_SUCCESS &&
            (secretBadSz != secretEncapSz ||
             XMEMCMP(secretBad, secretEncap, secretEncapSz) != 0)) {
        printf("[2] tampered ciphertext   -> secret DIFFERS    (expected)\n");
        correct++;
    }
    else if (rc != TPM_RC_SUCCESS) {
        /* A TPM that rejects the bad ciphertext outright is also acceptable. */
        printf("[2] tampered ciphertext   -> REJECTED 0x%x: %s (expected)\n",
            rc, wolfTPM2_GetRCString(rc));
        correct++;
    }
    else {
        printf("[2] tampered ciphertext   -> secret MATCHES    (BUG!)\n");
    }
    ciphertext[ciphertextSz / 2] ^= 0x01; /* restore */

    if (correct == 2) {
        printf("Negative-decap OK: genuine ciphertext reproduced the secret "
            "and a tampered ciphertext did not\n");
        rc = TPM_RC_SUCCESS;
    }
    else {
        printf("Negative-decap FAILED: %d/2 cases behaved correctly\n",
            correct);
        rc = TPM_RC_FAILURE;
    }

exit:
    wolfTPM2_UnloadHandle(&dev, &mlkemKey.handle);
    wolfTPM2_Cleanup(&dev);
    return rc;
}

#endif /* !WOLFTPM2_NO_WRAPPER && PQC ops */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
#if !defined(WOLFTPM2_NO_WRAPPER) && \
    defined(WOLFTPM_MLKEM_ENCAP) && defined(WOLFTPM_MLKEM_DECAP)
    int rc = mlkem_decap_neg_run(argc, argv);
    return (rc == 0) ? 0 : 1;
#else
    (void)argc;
    (void)argv;
    printf("Example requires --enable-v185\n");
    return 0;
#endif
}
#endif /* NO_MAIN_DRIVER */
