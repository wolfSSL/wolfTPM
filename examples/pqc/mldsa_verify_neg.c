/* mldsa_verify_neg.c
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

/* Example: Pure ML-DSA negative verification. Confirms the TPM accepts a
 * valid signature (TPM_ST_MESSAGE_VERIFIED) but rejects a bit-flipped
 * signature and a wrong message (TPM_RC_SIGNATURE), per TCG v1.85 Part 3. */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2_wrap.h>
#include <hal/tpm_io.h>
#include <examples/tpm_test.h>

#include <stdio.h>
#include <string.h>

#if !defined(WOLFTPM2_NO_WRAPPER) && \
    defined(WOLFTPM_MLDSA_SIGN) && defined(WOLFTPM_MLDSA_VERIFY)

static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/pqc/mldsa_verify_neg [-mldsa=44|65|87]\n");
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

/* Run one VerifySequence over msg/sig. Returns the TPM RC and, on success,
 * the validation ticket via val. */
static int verifySeq(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    const byte* msg, word32 msgSz, const byte* sig, int sigSz,
    TPMT_TK_VERIFIED* val)
{
    int rc;
    TPM_HANDLE seqHandle = 0;
    WOLFTPM2_HANDLE seqObj;

    XMEMSET(val, 0, sizeof(*val));

    rc = wolfTPM2_VerifySequenceStart(dev, key, NULL, 0, &seqHandle);
    if (rc != TPM_RC_SUCCESS)
        return rc;
    rc = wolfTPM2_VerifySequenceUpdate(dev, seqHandle, msg, msgSz);
    if (rc != TPM_RC_SUCCESS) {
        /* Update failed after Start created the sequence object; flush it so
         * the transient slot is not left allocated. Complete flushes itself
         * on its own error path. */
        XMEMSET(&seqObj, 0, sizeof(seqObj));
        seqObj.hndl = seqHandle;
        wolfTPM2_UnloadHandle(dev, &seqObj);
        return rc;
    }
    return wolfTPM2_VerifySequenceComplete(dev, seqHandle, key, NULL, 0,
        sig, sigSz, val);
}

static int mldsa_verify_neg_run(int argc, char *argv[])
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY mldsaKey;
    TPMT_PUBLIC pubTemplate;
    TPMT_TK_VERIFIED validation;
    TPM_HANDLE seqHandle = 0;
    WOLFTPM2_HANDLE seqObj;
    TPMI_MLDSA_PARAMETER_SET paramSet = TPM_MLDSA_65;
    byte message[32];
    byte altMessage[32];
    byte* sig = NULL;
    int sigSz = MAX_MLDSA_SIG_SIZE;
    int correct = 0; /* count of cases that behaved as required */

    XMEMSET(&dev, 0, sizeof(dev));
    XMEMSET(&mldsaKey, 0, sizeof(mldsaKey));
    XMEMSET(&pubTemplate, 0, sizeof(pubTemplate));
    XMEMSET(message, 0xAB, sizeof(message));
    XMEMSET(altMessage, 0xAB, sizeof(altMessage));
    altMessage[0] = 0xAC; /* differs from message in one byte */

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
                XSTRNCMP(argv[argc-1], "-mldsa=", XSTRLEN("-mldsa=")) == 0) {
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

    printf("TPM2.0 ML-DSA Negative Verify Example\n");
    printf("\tParameter Set: ML-DSA-%s\n",
        paramSet == TPM_MLDSA_44 ? "44" :
        paramSet == TPM_MLDSA_87 ? "87" : "65");

    sig = (byte*)XMALLOC(MAX_MLDSA_SIG_SIZE, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (sig == NULL)
        return MEMORY_E;

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, NULL);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_Init failed 0x%x: %s\n",
            rc, wolfTPM2_GetRCString(rc));
        XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
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

    /* Sign the message via Complete's buffer (Pure ML-DSA is streamable). */
    rc = wolfTPM2_SignSequenceStart(&dev, &mldsaKey, NULL, 0, &seqHandle);
    if (rc == TPM_RC_SUCCESS) {
        rc = wolfTPM2_SignSequenceComplete(&dev, seqHandle, &mldsaKey,
            message, (word32)sizeof(message), sig, &sigSz);
        if (rc != TPM_RC_SUCCESS) {
            /* Start succeeded but Complete failed; the TPM did not consume
             * the sequence object, so flush it. */
            XMEMSET(&seqObj, 0, sizeof(seqObj));
            seqObj.hndl = seqHandle;
            wolfTPM2_UnloadHandle(&dev, &seqObj);
        }
    }
    if (rc != TPM_RC_SUCCESS) {
        printf("Sign failed 0x%x: %s\n", rc, wolfTPM2_GetRCString(rc));
        goto exit;
    }
    printf("Signed %u-byte message into %d-byte signature\n",
        (unsigned)sizeof(message), sigSz);

    /* Case 1: correct signature over correct message MUST be accepted. */
    rc = verifySeq(&dev, &mldsaKey, message, (word32)sizeof(message),
        sig, sigSz, &validation);
    if (rc == TPM_RC_SUCCESS && validation.tag == TPM_ST_MESSAGE_VERIFIED) {
        printf("[1] valid signature       -> ACCEPTED   (expected)\n");
        correct++;
    }
    else {
        printf("[1] valid signature       -> REJECTED 0x%x: %s (UNEXPECTED)\n",
            rc, wolfTPM2_GetRCString(rc));
    }

    /* Case 2: flip one bit in the signature body, MUST be rejected. */
    sig[sigSz / 2] ^= 0x01;
    rc = verifySeq(&dev, &mldsaKey, message, (word32)sizeof(message),
        sig, sigSz, &validation);
    if (rc != TPM_RC_SUCCESS || validation.tag != TPM_ST_MESSAGE_VERIFIED) {
        printf("[2] bit-flipped signature -> REJECTED 0x%x: %s (expected)\n",
            rc, wolfTPM2_GetRCString(rc));
        correct++;
    }
    else {
        printf("[2] bit-flipped signature -> ACCEPTED   (rubber-stamp BUG!)\n");
    }
    sig[sigSz / 2] ^= 0x01; /* restore the valid signature */

    /* Case 3: correct signature over a DIFFERENT message MUST be rejected. */
    rc = verifySeq(&dev, &mldsaKey, altMessage, (word32)sizeof(altMessage),
        sig, sigSz, &validation);
    if (rc != TPM_RC_SUCCESS || validation.tag != TPM_ST_MESSAGE_VERIFIED) {
        printf("[3] wrong message         -> REJECTED 0x%x: %s (expected)\n",
            rc, wolfTPM2_GetRCString(rc));
        correct++;
    }
    else {
        printf("[3] wrong message         -> ACCEPTED   (rubber-stamp BUG!)\n");
    }

    if (correct == 3) {
        printf("Negative-verify OK: TPM accepted the valid signature and "
            "rejected both tampered cases\n");
        rc = TPM_RC_SUCCESS;
    }
    else {
        printf("Negative-verify FAILED: %d/3 cases behaved correctly\n",
            correct);
        rc = TPM_RC_FAILURE;
    }

exit:
    wolfTPM2_UnloadHandle(&dev, &mldsaKey.handle);
    wolfTPM2_Cleanup(&dev);
    XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return rc;
}

#endif /* !WOLFTPM2_NO_WRAPPER && PQC ops */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
#if !defined(WOLFTPM2_NO_WRAPPER) && \
    defined(WOLFTPM_MLDSA_SIGN) && defined(WOLFTPM_MLDSA_VERIFY)
    int rc = mldsa_verify_neg_run(argc, argv);
    return (rc == 0) ? 0 : 1;
#else
    (void)argc;
    (void)argv;
    printf("Example requires --enable-v185\n");
    return 0;
#endif
}
#endif /* NO_MAIN_DRIVER */
