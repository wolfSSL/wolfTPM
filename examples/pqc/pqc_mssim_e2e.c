/* pqc_mssim_e2e.c
 *
 * End-to-end test of wolfTPM2_* v1.85 post-quantum wrappers against a
 * running fwTPM server over the mssim (SWTPM) socket transport.
 *
 * Two round-trips in one binary:
 *   1. CreatePrimary MLKEM-768 + Encapsulate + Decapsulate.
 *      Asserts ciphertext is 1088 bytes and the two shared secrets match.
 *   2. CreatePrimary HashMLDSA-65 (SHA-256) + SignDigest + VerifyDigestSignature.
 *      Asserts the signature is 3309 bytes and the validation ticket
 *      returns TPM_ST_DIGEST_VERIFIED.
 *
 * Proves client marshaling + mssim framing + fwtpm_server unmarshaling +
 * PQC handler dispatch all agree end-to-end, without the convenience
 * of a shared-address-space in-process test.
 *
 * Run standalone (fwtpm_server must be listening on 127.0.0.1:2321):
 *   ./src/fwtpm/fwtpm_server &
 *   ./examples/pqc/pqc_mssim_e2e
 *
 * Or use tests/pqc_mssim_e2e.sh which spawns and stops the server.
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 * wolfTPM is free software distributed under GPLv3; see COPYING.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2_wrap.h>
#include <hal/tpm_io.h>

#include <stdio.h>
#include <string.h>

#if !defined(WOLFTPM2_NO_WRAPPER) && defined(WOLFTPM_V185)

/* Guard against the CopyPubT-class bug where the server-side key exists
 * and the handle works, but the client-side TPM2B buffer is zero-filled
 * (Part 2 Table 225 unique arm never copied). */
static int check_pub_populated(const char* label, const byte* buf,
    UINT16 gotSize, UINT16 wantSize)
{
    int i;
    if (gotSize != wantSize) {
        printf("%s.size = %u (expected %u)\n", label, gotSize, wantSize);
        return -1;
    }
    for (i = 0; i < wantSize; i++) {
        if (buf[i] != 0) return 0;
    }
    printf("%s.buffer is all zero (client-side unique-arm copy dropped)\n",
        label);
    return -1;
}

static int test_mlkem_roundtrip(WOLFTPM2_DEV* dev)
{
    WOLFTPM2_KEY mlkem;
    TPMT_PUBLIC tpl;
    int rc;
    byte ss1[32], ss2[32];
    int ss1Sz = sizeof(ss1), ss2Sz = sizeof(ss2);
    byte ct[MAX_MLKEM_CT_SIZE];
    int ctSz = sizeof(ct);

    XMEMSET(&mlkem, 0, sizeof(mlkem));
    XMEMSET(&tpl, 0, sizeof(tpl));

    rc = wolfTPM2_GetKeyTemplate_MLKEM(&tpl,
        TPMA_OBJECT_decrypt | TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent |
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth,
        TPM_MLKEM_768);
    if (rc != 0) {
        printf("GetKeyTemplate_MLKEM rc=%d\n", rc);
        return rc;
    }

    rc = wolfTPM2_CreatePrimaryKey(dev, &mlkem, TPM_RH_OWNER, &tpl, NULL, 0);
    if (rc != 0) {
        printf("CreatePrimary(MLKEM-768) rc=%d\n", rc);
        return rc;
    }

    rc = check_pub_populated("mlkem.unique",
        mlkem.pub.publicArea.unique.mlkem.buffer,
        mlkem.pub.publicArea.unique.mlkem.size, 1184);
    if (rc != 0) goto cleanup;

    rc = wolfTPM2_Encapsulate(dev, &mlkem, ct, &ctSz, ss1, &ss1Sz);
    if (rc != 0) {
        printf("Encapsulate rc=%d\n", rc);
        goto cleanup;
    }
    if (ctSz != 1088 || ss1Sz != 32) {
        printf("MLKEM-768 size mismatch: ct=%d (expected 1088) "
               "ss=%d (expected 32)\n", ctSz, ss1Sz);
        rc = -1;
        goto cleanup;
    }

    rc = wolfTPM2_Decapsulate(dev, &mlkem, ct, ctSz, ss2, &ss2Sz);
    if (rc != 0) {
        printf("Decapsulate rc=%d\n", rc);
        goto cleanup;
    }

    if (ss2Sz != 32 || XMEMCMP(ss1, ss2, 32) != 0) {
        printf("Shared-secret mismatch — mssim wire path broken\n");
        rc = -1;
        goto cleanup;
    }

    printf("[E2E] MLKEM-768 Encap/Decap over mssim: "
           "ct=%d bytes, shared secrets match\n", ctSz);

cleanup:
    /* Wipe MLKEM shared secrets — these are session-key material and
     * mlkem_encap.c uses the same pattern (wc_ForceZero in exit). */
    wc_ForceZero(ss1, sizeof(ss1));
    wc_ForceZero(ss2, sizeof(ss2));
    wolfTPM2_UnloadHandle(dev, &mlkem.handle);
    return rc;
}

static int test_hash_mldsa_digest_roundtrip(WOLFTPM2_DEV* dev)
{
    WOLFTPM2_KEY mldsa;
    TPMT_PUBLIC tpl;
    int rc;
    byte digest[32];
    byte sig[MAX_MLDSA_SIG_SIZE];
    int sigSz = sizeof(sig);
    TPMT_TK_VERIFIED validation;

    XMEMSET(&mldsa, 0, sizeof(mldsa));
    XMEMSET(&tpl, 0, sizeof(tpl));
    XMEMSET(&validation, 0, sizeof(validation));
    XMEMSET(digest, 0xAA, sizeof(digest));

    rc = wolfTPM2_GetKeyTemplate_HASH_MLDSA(&tpl,
        TPMA_OBJECT_sign | TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent |
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth,
        TPM_MLDSA_65, TPM_ALG_SHA256);
    if (rc != 0) {
        printf("GetKeyTemplate_HASH_MLDSA rc=%d\n", rc);
        return rc;
    }

    rc = wolfTPM2_CreatePrimaryKey(dev, &mldsa, TPM_RH_OWNER, &tpl, NULL, 0);
    if (rc != 0) {
        printf("CreatePrimary(HashMLDSA-65) rc=%d\n", rc);
        return rc;
    }

    /* HashMLDSA shares the mldsa arm of TPMU_PUBLIC_ID. */
    rc = check_pub_populated("mldsa.unique",
        mldsa.pub.publicArea.unique.mldsa.buffer,
        mldsa.pub.publicArea.unique.mldsa.size, 1952);
    if (rc != 0) goto cleanup;

    rc = wolfTPM2_SignDigest(dev, &mldsa,
        digest, sizeof(digest),
        NULL, 0,
        sig, &sigSz);
    if (rc != 0) {
        printf("SignDigest rc=%d\n", rc);
        goto cleanup;
    }
    if (sigSz != 3309) {
        printf("HashMLDSA-65 sig size=%d (expected 3309)\n", sigSz);
        rc = -1;
        goto cleanup;
    }

    rc = wolfTPM2_VerifyDigestSignature(dev, &mldsa,
        digest, sizeof(digest),
        sig, sigSz,
        NULL, 0,
        &validation);
    if (rc != 0) {
        printf("VerifyDigestSignature rc=%d\n", rc);
        goto cleanup;
    }

    if (validation.tag != TPM_ST_DIGEST_VERIFIED) {
        printf("Ticket tag=0x%x (expected 0x%x DIGEST_VERIFIED)\n",
            validation.tag, TPM_ST_DIGEST_VERIFIED);
        rc = -1;
        goto cleanup;
    }

    printf("[E2E] HashMLDSA-65 SignDigest/Verify over mssim: "
           "sig=%d bytes, ticket=DIGEST_VERIFIED\n", sigSz);

cleanup:
    wolfTPM2_UnloadHandle(dev, &mldsa.handle);
    return rc;
}

int main(int argc, char** argv)
{
    WOLFTPM2_DEV dev;
    int rc;

    (void)argc; (void)argv;

    XMEMSET(&dev, 0, sizeof(dev));
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, NULL);
    if (rc != 0) {
        printf("wolfTPM2_Init failed: %d (is fwtpm_server running on "
               "127.0.0.1:2321?)\n", rc);
        return 1;
    }

    rc = test_mlkem_roundtrip(&dev);
    if (rc != 0) goto done;

    rc = test_hash_mldsa_digest_roundtrip(&dev);

done:
    wolfTPM2_Cleanup(&dev);

    if (rc == 0) {
        printf("[E2E] All PQC mssim round-trips passed\n");
        return 0;
    }
    return 1;
}

#else /* !WOLFTPM_V185 || WOLFTPM2_NO_WRAPPER */

int main(void)
{
    printf("pqc_mssim_e2e: WOLFTPM_V185 + wrapper API required; skipping.\n");
    return 77; /* autoconf convention for SKIP */
}

#endif
