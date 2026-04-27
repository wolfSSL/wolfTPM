/* mldsa_sign.c
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

/* Example: Pure ML-DSA sign/verify round-trip using wolfTPM2 wrappers.
 * Per TCG TPM 2.0 v1.85 Part 3 Sec.17.5 (SignSequenceStart), Sec.20.6
 * (SignSequenceComplete), Sec.17.6 (VerifySequenceStart), Sec.20.3
 * (VerifySequenceComplete).
 *
 * Pure ML-DSA is one-shot on the sign path: SequenceUpdate is rejected
 * with TPM_RC_ONE_SHOT_SIGNATURE, the full message must arrive via the
 * SignSequenceComplete buffer. Verify sequences do accept Update per
 * Sec.20.3 and this example uses that path to exercise both idioms. */

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
    printf("./examples/pqc/mldsa_sign [-mldsa=44|65|87]\n");
    printf("* -mldsa=N: Parameter set (default 65)\n");
}

static int parseParamSet(const char* arg, TPMI_MLDSA_PARAMETER_SET* ps)
{
    int n = XATOI(arg);
    switch (n) {
        case 0:
        case 65: *ps = TPM_MLDSA_65; return 0;
        case 44: *ps = TPM_MLDSA_44; return 0;
        case 87: *ps = TPM_MLDSA_87; return 0;
        default: return BAD_FUNC_ARG;
    }
}

static int mldsa_sign_run(int argc, char *argv[])
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY mldsaKey;
    TPMT_PUBLIC pubTemplate;
    TPMI_MLDSA_PARAMETER_SET paramSet = TPM_MLDSA_65;
    TPM_HANDLE seqHandle = 0;
    TPMT_TK_VERIFIED validation;
    byte message[] = "wolfTPM PQC example: Pure ML-DSA sign/verify";
    int messageSz = (int)sizeof(message) - 1;
    byte sig[5000]; /* ML-DSA-87 sig = 4627 bytes; slack included */
    int sigSz = (int)sizeof(sig);

    if (argc >= 2) {
        if (XSTRCMP(argv[1], "-?") == 0 ||
            XSTRCMP(argv[1], "-h") == 0 ||
            XSTRCMP(argv[1], "--help") == 0) {
            usage();
            return 0;
        }
    }
    while (argc > 1) {
        if (XSTRCMP(argv[argc-1], "-mldsa") == 0 ||
                XSTRNCMP(argv[argc-1], "-mldsa=",
                    XSTRLEN("-mldsa=")) == 0) {
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
    XMEMSET(&mldsaKey, 0, sizeof(mldsaKey));
    XMEMSET(&pubTemplate, 0, sizeof(pubTemplate));
    XMEMSET(&validation, 0, sizeof(validation));

    printf("TPM2.0 ML-DSA Sign/Verify Example\n");
    printf("\tParameter Set: ML-DSA-%s\n",
        paramSet == TPM_MLDSA_44 ? "44" :
        paramSet == TPM_MLDSA_87 ? "87" : "65");

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, NULL);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_Init failed 0x%x: %s\n",
            rc, wolfTPM2_GetRCString(rc));
        return rc;
    }

    rc = wolfTPM2_GetKeyTemplate_MLDSA(&pubTemplate,
        TPMA_OBJECT_sign | TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent |
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_noDA, paramSet, 0 /* allowExternalMu */);
    if (rc != TPM_RC_SUCCESS) goto exit;

    rc = wolfTPM2_CreatePrimaryKey(&dev, &mldsaKey, TPM_RH_OWNER,
        &pubTemplate, NULL, 0);
    if (rc != TPM_RC_SUCCESS) {
        printf("CreatePrimary failed 0x%x: %s\n",
            rc, wolfTPM2_GetRCString(rc));
        goto exit;
    }
    printf("Created ML-DSA primary: handle 0x%08x, pubkey %u bytes\n",
        (unsigned)mldsaKey.handle.hndl,
        (unsigned)mldsaKey.pub.publicArea.unique.mldsa.size);

    /* Sign: Pure ML-DSA is one-shot per Sec.17.5. Message goes via
     * SignSequenceComplete's buffer parameter, not via SequenceUpdate
     * (which returns TPM_RC_ONE_SHOT_SIGNATURE for Pure MLDSA keys). */
    rc = wolfTPM2_SignSequenceStart(&dev, &mldsaKey, NULL, 0, &seqHandle);
    if (rc != TPM_RC_SUCCESS) {
        printf("SignSequenceStart failed 0x%x: %s\n",
            rc, wolfTPM2_GetRCString(rc));
        goto exit;
    }
    rc = wolfTPM2_SignSequenceComplete(&dev, seqHandle, &mldsaKey,
        message, messageSz, sig, &sigSz);
    if (rc != TPM_RC_SUCCESS) {
        printf("SignSequenceComplete failed 0x%x: %s\n",
            rc, wolfTPM2_GetRCString(rc));
        goto exit;
    }
    printf("Sign: signature %d bytes\n", sigSz);

    /* Verify: SequenceUpdate is allowed per Sec.20.3, so exercise it by
     * streaming the message through Update before Complete. */
    rc = wolfTPM2_VerifySequenceStart(&dev, &mldsaKey, NULL, 0, &seqHandle);
    if (rc != TPM_RC_SUCCESS) {
        printf("VerifySequenceStart failed 0x%x: %s\n",
            rc, wolfTPM2_GetRCString(rc));
        goto exit;
    }
    rc = wolfTPM2_VerifySequenceUpdate(&dev, seqHandle, message, messageSz);
    if (rc != TPM_RC_SUCCESS) {
        printf("VerifySequenceUpdate failed 0x%x: %s\n",
            rc, wolfTPM2_GetRCString(rc));
        goto exit;
    }
    rc = wolfTPM2_VerifySequenceComplete(&dev, seqHandle, &mldsaKey,
        NULL, 0, sig, sigSz, &validation);
    if (rc != TPM_RC_SUCCESS) {
        printf("VerifySequenceComplete failed 0x%x: %s\n",
            rc, wolfTPM2_GetRCString(rc));
        goto exit;
    }

    if (validation.tag != TPM_ST_MESSAGE_VERIFIED) {
        printf("ERROR: validation tag 0x%x, expected TPM_ST_MESSAGE_VERIFIED\n",
            validation.tag);
        rc = TPM_RC_FAILURE;
        goto exit;
    }
    printf("Verify: TPM_ST_MESSAGE_VERIFIED ticket returned\n");
    printf("Round-trip OK: Pure ML-DSA sign + verify sequence\n");

exit:
    wolfTPM2_UnloadHandle(&dev, &mldsaKey.handle);
    wolfTPM2_Cleanup(&dev);
    return rc;
}

#endif /* !WOLFTPM2_NO_WRAPPER && WOLFTPM_V185 */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
#if !defined(WOLFTPM2_NO_WRAPPER) && defined(WOLFTPM_V185)
    int rc = mldsa_sign_run(argc, argv);
    return (rc == 0) ? 0 : 1;
#else
    (void)argc;
    (void)argv;
    printf("Example requires --enable-v185\n");
    return 0;
#endif
}
#endif /* NO_MAIN_DRIVER */
