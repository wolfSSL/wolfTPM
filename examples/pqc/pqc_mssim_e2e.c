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

#if !defined(WOLFTPM2_NO_WRAPPER) && \
    defined(WOLFTPM_MLDSA_SIGN) && defined(WOLFTPM_MLDSA_VERIFY) && \
    defined(WOLFTPM_MLKEM_ENCAP) && defined(WOLFTPM_MLKEM_DECAP) && \
    defined(WOLFTPM_HASH_MLDSA)

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
    /* MLKEM ciphertext can be up to 1568 bytes — heap-alloc. */
    byte* ct = NULL;
    int ctBufSz = MAX_MLKEM_CT_SIZE;
    int ctSz = ctBufSz;

    XMEMSET(&mlkem, 0, sizeof(mlkem));
    XMEMSET(&tpl, 0, sizeof(tpl));

    ct = (byte*)XMALLOC(ctBufSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (ct == NULL) return MEMORY_E;

    rc = wolfTPM2_GetKeyTemplate_MLKEM(&tpl,
        TPMA_OBJECT_decrypt | TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent |
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth,
        TPM_MLKEM_768);
    if (rc != 0) {
        printf("GetKeyTemplate_MLKEM rc=%d\n", rc);
        XFREE(ct, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return rc;
    }

    rc = wolfTPM2_CreatePrimaryKey(dev, &mlkem, TPM_RH_OWNER, &tpl, NULL, 0);
    if (rc != 0) {
        printf("CreatePrimary(MLKEM-768) rc=%d\n", rc);
        XFREE(ct, NULL, DYNAMIC_TYPE_TMP_BUFFER);
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
    XFREE(ct, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return rc;
}

static int test_hash_mldsa_digest_roundtrip(WOLFTPM2_DEV* dev)
{
    WOLFTPM2_KEY mldsa;
    TPMT_PUBLIC tpl;
    int rc;
    byte digest[32];
    /* MLDSA-87 sig = 4627 bytes — heap-alloc to keep stack small. */
    byte* sig = NULL;
    int sigBufSz = MAX_MLDSA_SIG_SIZE;
    int sigSz = sigBufSz;
    TPMT_TK_VERIFIED validation;

    XMEMSET(&mldsa, 0, sizeof(mldsa));
    XMEMSET(&tpl, 0, sizeof(tpl));
    XMEMSET(&validation, 0, sizeof(validation));
    XMEMSET(digest, 0xAA, sizeof(digest));

    sig = (byte*)XMALLOC(sigBufSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (sig == NULL) return MEMORY_E;

    rc = wolfTPM2_GetKeyTemplate_HASH_MLDSA(&tpl,
        TPMA_OBJECT_sign | TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent |
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth,
        TPM_MLDSA_65, TPM_ALG_SHA256);
    if (rc != 0) {
        printf("GetKeyTemplate_HASH_MLDSA rc=%d\n", rc);
        XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return rc;
    }

    rc = wolfTPM2_CreatePrimaryKey(dev, &mldsa, TPM_RH_OWNER, &tpl, NULL, 0);
    if (rc != 0) {
        printf("CreatePrimary(HashMLDSA-65) rc=%d\n", rc);
        XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
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
    XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return rc;
}

/* MakeCredential -> ActivateCredential with an ML-KEM EK, through the client
 * library. Proves the client marshals both credential commands and that the
 * fwTPM unwraps the ML-KEM-encapsulated seed end-to-end (recovered secret
 * matches). The EK is also the activate object, so no second key is needed. */
static int test_mlkem_credential_roundtrip(WOLFTPM2_DEV* dev)
{
    WOLFTPM2_KEY ek;
    TPMT_PUBLIC tpl;
    MakeCredential_In makeCredIn;
    MakeCredential_Out makeCredOut;
    ActivateCredential_In activCredIn;
    ActivateCredential_Out activCredOut;
    byte secret[16];
    int rc;

    XMEMSET(&ek, 0, sizeof(ek));
    XMEMSET(&tpl, 0, sizeof(tpl));
    XMEMSET(&makeCredIn, 0, sizeof(makeCredIn));
    XMEMSET(&makeCredOut, 0, sizeof(makeCredOut));
    XMEMSET(&activCredIn, 0, sizeof(activCredIn));
    XMEMSET(&activCredOut, 0, sizeof(activCredOut));
    XMEMSET(secret, 0xC7, sizeof(secret));

    /* Credential key must be a restricted decryption (Storage) key per Part 3
     * Sec.24; the template adds an AES symmetric for restricted. */
    rc = wolfTPM2_GetKeyTemplate_MLKEM(&tpl,
        TPMA_OBJECT_decrypt | TPMA_OBJECT_restricted | TPMA_OBJECT_fixedTPM |
        TPMA_OBJECT_fixedParent | TPMA_OBJECT_sensitiveDataOrigin |
        TPMA_OBJECT_userWithAuth,
        TPM_MLKEM_768);
    if (rc != 0) {
        printf("GetKeyTemplate_MLKEM rc=%d\n", rc);
        return rc;
    }

    rc = wolfTPM2_CreatePrimaryKey(dev, &ek, TPM_RH_OWNER, &tpl, NULL, 0);
    if (rc != 0) {
        printf("CreatePrimary(MLKEM-768) rc=%d\n", rc);
        return rc;
    }

    /* MakeCredential (no auth): encrypt the secret to the EK, bound to the
     * EK's own Name. */
    makeCredIn.handle = ek.handle.hndl;
    makeCredIn.credential.size = sizeof(secret);
    XMEMCPY(makeCredIn.credential.buffer, secret, sizeof(secret));
    makeCredIn.objectName.size = ek.handle.name.size;
    XMEMCPY(makeCredIn.objectName.name, ek.handle.name.name,
        ek.handle.name.size);
    rc = TPM2_MakeCredential(&makeCredIn, &makeCredOut);
    if (rc != 0) {
        printf("TPM2_MakeCredential rc=0x%x\n", rc);
        goto cleanup;
    }

    /* ActivateCredential: EK decrypts the seed (ML-KEM decap) and unwraps.
     * Two auth slots: activateHandle then keyHandle, both the EK. */
    wolfTPM2_SetAuthHandle(dev, 0, &ek.handle);
    wolfTPM2_SetAuthHandle(dev, 1, &ek.handle);
    activCredIn.activateHandle = ek.handle.hndl;
    activCredIn.keyHandle = ek.handle.hndl;
    activCredIn.credentialBlob = makeCredOut.credentialBlob;
    activCredIn.secret = makeCredOut.secret;
    rc = TPM2_ActivateCredential(&activCredIn, &activCredOut);
    if (rc != 0) {
        printf("TPM2_ActivateCredential rc=0x%x\n", rc);
        goto cleanup;
    }

    if (activCredOut.certInfo.size != sizeof(secret) ||
            XMEMCMP(activCredOut.certInfo.buffer, secret,
                sizeof(secret)) != 0) {
        printf("Recovered credential mismatch: MLKEM activate path broken\n");
        rc = -1;
        goto cleanup;
    }

    printf("[E2E] MLKEM-768 MakeCredential/ActivateCredential over mssim: "
           "recovered %u-byte secret matches\n", activCredOut.certInfo.size);

cleanup:
    wolfTPM2_UnloadHandle(dev, &ek.handle);
    return rc;
}

/* TPM2_Quote with a restricted Pure ML-DSA signing key, through the client
 * library. Proves the client marshals the quote and parses the Pure ML-DSA
 * signature off the wire (sigAlg + expected size). */
static int test_mldsa_quote(WOLFTPM2_DEV* dev)
{
    WOLFTPM2_KEY ak;
    TPMT_PUBLIC tpl;
    Quote_In quoteIn;
    Quote_Out quoteOut;
    int rc;

    XMEMSET(&ak, 0, sizeof(ak));
    XMEMSET(&tpl, 0, sizeof(tpl));
    XMEMSET(&quoteIn, 0, sizeof(quoteIn));
    XMEMSET(&quoteOut, 0, sizeof(quoteOut));

    rc = wolfTPM2_GetKeyTemplate_MLDSA(&tpl,
        TPMA_OBJECT_sign | TPMA_OBJECT_restricted | TPMA_OBJECT_fixedTPM |
        TPMA_OBJECT_fixedParent | TPMA_OBJECT_sensitiveDataOrigin |
        TPMA_OBJECT_userWithAuth,
        TPM_MLDSA_65, NO);
    if (rc != 0) {
        printf("GetKeyTemplate_MLDSA rc=%d\n", rc);
        return rc;
    }

    rc = wolfTPM2_CreatePrimaryKey(dev, &ak, TPM_RH_OWNER, &tpl, NULL, 0);
    if (rc != 0) {
        printf("CreatePrimary(MLDSA-65) rc=%d\n", rc);
        return rc;
    }

    /* Quote PCR0 (SHA-256) with the key's own scheme (inScheme NULL). */
    wolfTPM2_SetAuthHandle(dev, 0, &ak.handle);
    quoteIn.signHandle = ak.handle.hndl;
    quoteIn.inScheme.scheme = TPM_ALG_NULL;
    TPM2_SetupPCRSel(&quoteIn.PCRselect, TPM_ALG_SHA256, 0);

    rc = TPM2_Quote(&quoteIn, &quoteOut);
    if (rc != 0) {
        printf("TPM2_Quote rc=0x%x\n", rc);
        goto cleanup;
    }

    if (quoteOut.signature.sigAlg != TPM_ALG_MLDSA) {
        printf("Quote sigAlg=0x%x (expected MLDSA 0x%x)\n",
            quoteOut.signature.sigAlg, TPM_ALG_MLDSA);
        rc = -1;
        goto cleanup;
    }
    if (quoteOut.signature.signature.mldsa.size != 3309) {
        printf("MLDSA-65 quote sig size=%u (expected 3309)\n",
            quoteOut.signature.signature.mldsa.size);
        rc = -1;
        goto cleanup;
    }

    printf("[E2E] MLDSA-65 Quote over mssim: attest=%u bytes, "
           "sig=%u bytes (sigAlg=MLDSA)\n",
           quoteOut.quoted.size, quoteOut.signature.signature.mldsa.size);

cleanup:
    wolfTPM2_UnloadHandle(dev, &ak.handle);
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
    if (rc != 0) goto done;

    rc = test_mlkem_credential_roundtrip(&dev);
    if (rc != 0) goto done;

    rc = test_mldsa_quote(&dev);

done:
    wolfTPM2_Cleanup(&dev);

    if (rc == 0) {
        printf("[E2E] All PQC mssim round-trips passed\n");
        return 0;
    }
    return 1;
}

#else /* PQC ops not all enabled, or no wrapper */

int main(void)
{
    printf("pqc_mssim_e2e: PQC (ML-DSA+ML-KEM) + wrapper API required; skipping.\n");
    return 77; /* autoconf convention for SKIP */
}

#endif
