/* pqc_ctrl.c
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

/* Example: single control/validation tool for the TPM 2.0 v1.85 post-quantum
 * algorithms (ML-DSA, Hash-ML-DSA, ML-KEM), modeled on examples/spdm/spdm_ctrl.
 * One CLI runs each operation and controls the board. Each key operation
 * reclaims loaded transient objects first, so a TPM with a small transient-
 * object table (e.g. SealSQ QVault TPM) does not hit TPM_RC_OBJECT_MEMORY
 * when key operations are chained. */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2_wrap.h>
#include <hal/tpm_io.h>
#include <examples/tpm_test.h>

#include <stdio.h>
#include <string.h>

#if !defined(WOLFTPM2_NO_WRAPPER) && \
    defined(WOLFTPM_MLDSA_SIGN) && defined(WOLFTPM_MLDSA_VERIFY) && \
    defined(WOLFTPM_MLKEM_ENCAP) && defined(WOLFTPM_MLKEM_DECAP) && \
    defined(WOLFTPM_HASH_MLDSA)

static const byte gPqcMsg[] = "wolfTPM PQC control example message";

static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/pqc/pqc_ctrl [command(s)]\n");
    printf("Commands run in the given order; default (no args) is --all:\n");
    printf("* --caps                   Print TPM caps (vendor, FW, FIPS)\n");
    printf("* --algs                   List supported algorithms\n");
    printf("* --selftest               Run TPM2_SelfTest\n");
    printf("* --getrandom[=N]          Get N random bytes (default 16)\n");
    printf("* --pcrread[=idx]          Read PCR index (default 0)\n");
    printf("* --pcrextend=idx          Extend PCR (explicit index required)\n");
    printf("* --flush                  Flush transient objects (board reset)\n");
    printf("* --clear                  TPM2_Clear (wipes owner hierarchy!)\n");
    printf("* --mldsa[=44|65|87]       Pure ML-DSA sign/verify (default 65)\n");
    printf("* --hash-mldsa[=44|65|87]  Hash-ML-DSA (SHA-256) sign/verify\n");
    printf("* --mlkem[=512|768|1024]   ML-KEM encapsulate/decapsulate\n");
    printf("* --all                    caps + every parameter set of each op\n");
}

/* Empty value means "bare flag, use default set"; any other non-matching
 * value is rejected rather than silently defaulted. A NULL ps validates only. */
static int parseMldsaSet(const char* val, TPMI_MLDSA_PARAMETER_SET* ps)
{
    TPMI_MLDSA_PARAMETER_SET set;

    if (val[0] == '\0' || XSTRCMP(val, "65") == 0) {
        set = TPM_MLDSA_65;
    }
    else if (XSTRCMP(val, "44") == 0) {
        set = TPM_MLDSA_44;
    }
    else if (XSTRCMP(val, "87") == 0) {
        set = TPM_MLDSA_87;
    }
    else {
        return BAD_FUNC_ARG;
    }
    if (ps != NULL) {
        *ps = set;
    }
    return 0;
}

static int parseMlkemSet(const char* val, TPMI_MLKEM_PARAMETER_SET* ps)
{
    TPMI_MLKEM_PARAMETER_SET set;

    if (val[0] == '\0' || XSTRCMP(val, "768") == 0) {
        set = TPM_MLKEM_768;
    }
    else if (XSTRCMP(val, "512") == 0) {
        set = TPM_MLKEM_512;
    }
    else if (XSTRCMP(val, "1024") == 0) {
        set = TPM_MLKEM_1024;
    }
    else {
        return BAD_FUNC_ARG;
    }
    if (ps != NULL) {
        *ps = set;
    }
    return 0;
}

static const char* mldsaName(TPMI_MLDSA_PARAMETER_SET ps)
{
    return (ps == TPM_MLDSA_44) ? "44" : (ps == TPM_MLDSA_87) ? "87" : "65";
}

static const char* mlkemName(TPMI_MLKEM_PARAMETER_SET ps)
{
    return (ps == TPM_MLKEM_512) ? "512" : (ps == TPM_MLKEM_1024) ? "1024" :
        "768";
}

/* Reclaim the transient object table by flushing exactly the handles the TPM
 * reports as loaded. Parts with a small object table (e.g. SealSQ QVault TPM)
 * hit TPM_RC_OBJECT_MEMORY when a key plus a sign/verify sequence object are
 * live at once. wolfTPM2_UnloadHandles_AllTransient() only covers
 * MAX_HANDLE_NUM (3) fixed handles, so query the actual loaded set instead. */
static int pqc_flush_transient(WOLFTPM2_DEV* dev)
{
    int rc;
    word32 i;
    GetCapability_In in;
    GetCapability_Out out;
    FlushContext_In flushCtx;

    (void)dev; /* operates on the active TPM context */
    XMEMSET(&in, 0, sizeof(in));
    XMEMSET(&out, 0, sizeof(out));
    XMEMSET(&flushCtx, 0, sizeof(flushCtx));
    in.capability = TPM_CAP_HANDLES;
    in.property = TRANSIENT_FIRST;
    in.propertyCount = MAX_CAP_HANDLES;
    rc = TPM2_GetCapability(&in, &out);
    if (rc != TPM_RC_SUCCESS) {
        return rc;
    }
    if (out.capabilityData.capability != TPM_CAP_HANDLES) {
        return TPM_RC_FAILURE;
    }
    for (i = 0; i < out.capabilityData.data.handles.count; i++) {
        flushCtx.flushHandle = out.capabilityData.data.handles.handle[i];
        (void)TPM2_FlushContext(&flushCtx);
    }
    return TPM_RC_SUCCESS;
}

static int do_caps(WOLFTPM2_DEV* dev)
{
    int rc;
    WOLFTPM2_CAPS caps;

    XMEMSET(&caps, 0, sizeof(caps));

    rc = wolfTPM2_GetCapabilities(dev, &caps);
    if (rc != TPM_RC_SUCCESS) {
        printf("GetCapabilities failed 0x%x: %s\n",
            rc, wolfTPM2_GetRCString(rc));
        return rc;
    }
    printf("Caps: Mfg %s, Vendor %s, Fw %u.%u, FIPS %s\n",
        caps.mfgStr, caps.vendorStr, caps.fwVerMajor, caps.fwVerMinor,
        TPM2_GetCapsFipsStr(caps.fips140_3, caps.fips140_2));
    return rc;
}

static const char* algName(TPM_ALG_ID alg)
{
    switch (alg) {
        case TPM_ALG_RSA:        return "RSA";
        case TPM_ALG_SHA1:       return "SHA1";
        case TPM_ALG_SHA256:     return "SHA256";
        case TPM_ALG_SHA384:     return "SHA384";
        case TPM_ALG_SHA512:     return "SHA512";
        case TPM_ALG_AES:        return "AES";
        case TPM_ALG_ECC:        return "ECC";
        case TPM_ALG_HMAC:       return "HMAC";
        case TPM_ALG_KEYEDHASH:  return "KEYEDHASH";
    #ifdef WOLFTPM_PQC
        case TPM_ALG_MLKEM:      return "ML-KEM";
        case TPM_ALG_MLDSA:      return "ML-DSA";
        case TPM_ALG_HASH_MLDSA: return "Hash-ML-DSA";
    #endif
        default:                 return NULL;
    }
}

static int do_algs(WOLFTPM2_DEV* dev)
{
    int rc;
    word32 i;
    word32 count;
    const char* name;
    TPM_ALG_ID alg;
    GetCapability_In in;
    GetCapability_Out out;

    (void)dev;
    XMEMSET(&in, 0, sizeof(in));
    XMEMSET(&out, 0, sizeof(out));
    in.capability = TPM_CAP_ALGS;
    in.property = TPM_ALG_FIRST; /* spec-conformant start; 0 is TPM_RC_VALUE */
    /* MAX_CAP_ALGS covers the whole algorithm range in one request. Paging is
     * avoided deliberately: TPM_CAP_ALGS advances by a property cursor that
     * assumes ascending IDs, but some parts return the list unordered. */
    in.propertyCount = MAX_CAP_ALGS;

    rc = TPM2_GetCapability(&in, &out);
    if (rc != TPM_RC_SUCCESS) {
        printf("GetCapability(ALGS) failed 0x%x: %s\n",
            rc, wolfTPM2_GetRCString(rc));
        return rc;
    }
    if (out.capabilityData.capability != TPM_CAP_ALGS) {
        printf("GetCapability(ALGS) returned unexpected capability 0x%x\n",
            (unsigned)out.capabilityData.capability);
        return TPM_RC_FAILURE;
    }
    count = out.capabilityData.data.algorithms.count;
    printf("Supported algorithms (%u):\n", (unsigned)count);
    for (i = 0; i < count; i++) {
        alg = out.capabilityData.data.algorithms.algProperties[i].alg;
        name = algName(alg);
        if (name != NULL) {
            printf("  0x%04x %s\n", (unsigned)alg, name);
        }
        else {
            printf("  0x%04x\n", (unsigned)alg);
        }
    }
    return rc;
}

static int do_selftest(WOLFTPM2_DEV* dev)
{
    int rc = wolfTPM2_SelfTest(dev);
    if (rc == TPM_RC_SUCCESS)
        printf("PASS  SelfTest\n");
    else
        printf("FAIL  SelfTest  0x%x: %s\n", rc, wolfTPM2_GetRCString(rc));
    return rc;
}

static int do_getrandom(WOLFTPM2_DEV* dev, int len)
{
    int rc;
    int i;
    byte buf[64];

    if (len <= 0 || len > (int)sizeof(buf)) {
        printf("FAIL  GetRandom  invalid length %d (max %d)\n",
            len, (int)sizeof(buf));
        return BAD_FUNC_ARG;
    }
    XMEMSET(buf, 0, sizeof(buf));

    rc = wolfTPM2_GetRandom(dev, buf, (word32)len);
    if (rc != TPM_RC_SUCCESS) {
        printf("FAIL  GetRandom  0x%x: %s\n", rc, wolfTPM2_GetRCString(rc));
        return rc;
    }
    printf("Random %d bytes: ", len);
    for (i = 0; i < len; i++)
        printf("%02x", buf[i]);
    printf("\n");
    return rc;
}

/* Read a PCR, trying the SHA-256 bank first then SHA-384 (a PQC part such as
 * SealSQ QVault TPM allocates only the SHA-384 bank). */
static int do_pcrread(WOLFTPM2_DEV* dev, int idx)
{
    int rc;
    int i;
    int hashAlg = TPM_ALG_SHA256;
    int digestSz = 0;
    byte digest[TPM_MAX_DIGEST_SIZE];

    XMEMSET(digest, 0, sizeof(digest));
    digestSz = (int)sizeof(digest);
    rc = wolfTPM2_ReadPCR(dev, idx, hashAlg, digest, &digestSz);
    /* Fall back to SHA-384 when SHA-256 errors or returns an empty bank. */
    if (rc != TPM_RC_SUCCESS || digestSz == 0) {
        hashAlg = TPM_ALG_SHA384;
        digestSz = (int)sizeof(digest);
        rc = wolfTPM2_ReadPCR(dev, idx, hashAlg, digest, &digestSz);
    }
    if (rc != TPM_RC_SUCCESS) {
        printf("FAIL  PCR%d read  0x%x: %s\n",
            idx, rc, wolfTPM2_GetRCString(rc));
        return rc;
    }
    if (digestSz == 0) {
        printf("FAIL  PCR%d read  no digest returned (no allocated bank)\n", idx);
        return TPM_RC_FAILURE;
    }
    printf("PCR%d (%s): ", idx, hashAlg == TPM_ALG_SHA384 ? "SHA384" : "SHA256");
    for (i = 0; i < digestSz; i++)
        printf("%02x", digest[i]);
    printf("\n");
    return rc;
}

/* PCR extend is irreversible, so extend exactly one bank: the TPM's first
 * bank that actually has PCRs allocated (a part may allocate only SHA-384).
 * Never fall back to a second extend, which would touch two banks. */
static int do_pcrextend(WOLFTPM2_DEV* dev, int idx)
{
    int rc;
    int hashAlg;
    int digestSz;
    word32 b;
    TPML_PCR_SELECTION* banks;
    GetCapability_In in;
    GetCapability_Out out;
    byte digest[TPM_MAX_DIGEST_SIZE];

    XMEMSET(&in, 0, sizeof(in));
    XMEMSET(&out, 0, sizeof(out));
    in.capability = TPM_CAP_PCRS;
    in.property = 0;
    in.propertyCount = HASH_COUNT; /* return every assigned bank, not just one */
    rc = TPM2_GetCapability(&in, &out);
    if (rc != TPM_RC_SUCCESS) {
        printf("FAIL  PCR%d extend  0x%x: %s\n",
            idx, rc, wolfTPM2_GetRCString(rc));
        return rc;
    }
    banks = &out.capabilityData.data.assignedPCR;
    if (out.capabilityData.capability != TPM_CAP_PCRS || banks->count == 0) {
        printf("FAIL  PCR%d extend  no assigned PCR bank\n", idx);
        return TPM_RC_FAILURE;
    }

    /* Pick the first bank that has the requested PCR index allocated. */
    hashAlg = TPM_ALG_ERROR;
    for (b = 0; b < banks->count && hashAlg == TPM_ALG_ERROR; b++) {
        if ((idx / 8) < (int)banks->pcrSelections[b].sizeofSelect &&
                (banks->pcrSelections[b].pcrSelect[idx / 8] &
                    (1 << (idx % 8))) != 0) {
            hashAlg = banks->pcrSelections[b].hash;
        }
    }
    if (hashAlg == TPM_ALG_ERROR) {
        printf("FAIL  PCR%d extend  index not allocated in any bank\n", idx);
        return TPM_RC_FAILURE;
    }
    digestSz = TPM2_GetHashDigestSize((TPMI_ALG_HASH)hashAlg);
    if (digestSz <= 0 || digestSz > (int)sizeof(digest)) {
        printf("FAIL  PCR%d extend  unsupported bank 0x%x\n", idx, hashAlg);
        return TPM_RC_FAILURE;
    }

    XMEMSET(digest, 0x11, sizeof(digest));
    rc = wolfTPM2_ExtendPCR(dev, idx, hashAlg, digest, digestSz);
    if (rc == TPM_RC_SUCCESS) {
        printf("PASS  PCR%d extend (bank 0x%x)\n", idx, hashAlg);
    }
    else {
        printf("FAIL  PCR%d extend  0x%x: %s\n",
            idx, rc, wolfTPM2_GetRCString(rc));
    }
    return rc;
}

static int do_clear(WOLFTPM2_DEV* dev)
{
    int rc;

    printf("WARNING: TPM2_Clear wipes the owner hierarchy and persistent keys\n");
    rc = wolfTPM2_Clear(dev);
    if (rc == TPM_RC_SUCCESS)
        printf("PASS  Clear (TPM reset to defaults)\n");
    else
        printf("FAIL  Clear  0x%x: %s\n", rc, wolfTPM2_GetRCString(rc));
    return rc;
}

static int do_mldsa(WOLFTPM2_DEV* dev, TPMI_MLDSA_PARAMETER_SET ps)
{
    int rc;
    WOLFTPM2_KEY key;
    TPMT_PUBLIC tpl;
    TPM_HANDLE seq = 0;
    TPMT_TK_VERIFIED validation;
    FlushContext_In flushCtx;
    byte* sig = NULL;
    int sigSz = MAX_MLDSA_SIG_SIZE;

    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(&tpl, 0, sizeof(tpl));
    XMEMSET(&validation, 0, sizeof(validation));
    XMEMSET(&flushCtx, 0, sizeof(flushCtx));

    (void)pqc_flush_transient(dev);

    sig = (byte*)XMALLOC(MAX_MLDSA_SIG_SIZE, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (sig == NULL)
        return MEMORY_E;

    rc = wolfTPM2_GetKeyTemplate_MLDSA(&tpl,
        TPMA_OBJECT_sign | TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent |
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_noDA, ps, 0);
    if (rc != TPM_RC_SUCCESS) goto exit;

    rc = wolfTPM2_CreatePrimaryKey(dev, &key, TPM_RH_OWNER, &tpl, NULL, 0);
    if (rc != TPM_RC_SUCCESS) goto exit;

    rc = wolfTPM2_SignSequenceStart(dev, &key, NULL, 0, &seq);
    if (rc != TPM_RC_SUCCESS) goto exit;
    rc = wolfTPM2_SignSequenceComplete(dev, seq, &key,
        gPqcMsg, (int)sizeof(gPqcMsg) - 1, sig, &sigSz);
    if (rc != TPM_RC_SUCCESS) goto exit;
    seq = 0; /* Complete consumed the sequence object */

    rc = wolfTPM2_VerifySequenceStart(dev, &key, NULL, 0, &seq);
    if (rc != TPM_RC_SUCCESS) goto exit;
    rc = wolfTPM2_VerifySequenceUpdate(dev, seq,
        gPqcMsg, (int)sizeof(gPqcMsg) - 1);
    if (rc != TPM_RC_SUCCESS) goto exit;
    rc = wolfTPM2_VerifySequenceComplete(dev, seq, &key, NULL, 0,
        sig, sigSz, &validation);
    if (rc != TPM_RC_SUCCESS) goto exit;
    seq = 0; /* Complete consumed the sequence object */

    if (validation.tag != TPM_ST_MESSAGE_VERIFIED) {
        printf("ML-DSA-%s verify: unexpected ticket tag 0x%x\n",
            mldsaName(ps), (unsigned)validation.tag);
        rc = TPM_RC_FAILURE;
    }

exit:
    if (rc == TPM_RC_SUCCESS) {
        printf("PASS  ML-DSA-%-3s      sign+verify (sig %d bytes)\n",
            mldsaName(ps), sigSz);
    }
    else {
        printf("FAIL  ML-DSA-%-3s      0x%x: %s\n",
            mldsaName(ps), rc, wolfTPM2_GetRCString(rc));
    }
    if (seq != 0) {
        flushCtx.flushHandle = seq;
        (void)TPM2_FlushContext(&flushCtx);
    }
    wolfTPM2_UnloadHandle(dev, &key.handle);
    XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return rc;
}

static int do_hash_mldsa(WOLFTPM2_DEV* dev, TPMI_MLDSA_PARAMETER_SET ps)
{
    int rc;
    WOLFTPM2_KEY key;
    TPMT_PUBLIC tpl;
    TPMT_TK_VERIFIED validation;
    byte digest[TPM_SHA256_DIGEST_SIZE];
    byte* sig = NULL;
    int sigSz = MAX_MLDSA_SIG_SIZE;

    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(&tpl, 0, sizeof(tpl));
    XMEMSET(&validation, 0, sizeof(validation));
    XMEMSET(digest, 0xAA, sizeof(digest));

    (void)pqc_flush_transient(dev);

    sig = (byte*)XMALLOC(MAX_MLDSA_SIG_SIZE, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (sig == NULL)
        return MEMORY_E;

    rc = wolfTPM2_GetKeyTemplate_HASH_MLDSA(&tpl,
        TPMA_OBJECT_sign | TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent |
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_noDA, ps, TPM_ALG_SHA256);
    if (rc != TPM_RC_SUCCESS) goto exit;

    rc = wolfTPM2_CreatePrimaryKey(dev, &key, TPM_RH_OWNER, &tpl, NULL, 0);
    if (rc != TPM_RC_SUCCESS) goto exit;

    rc = wolfTPM2_SignDigest(dev, &key, digest, (int)sizeof(digest),
        NULL, 0, sig, &sigSz);
    if (rc != TPM_RC_SUCCESS) goto exit;

    rc = wolfTPM2_VerifyDigestSignature(dev, &key, digest, (int)sizeof(digest),
        sig, sigSz, NULL, 0, &validation);
    if (rc != TPM_RC_SUCCESS) goto exit;

    if (validation.tag != TPM_ST_DIGEST_VERIFIED) {
        printf("HashML-DSA-%s verify: unexpected ticket tag 0x%x\n",
            mldsaName(ps), (unsigned)validation.tag);
        rc = TPM_RC_FAILURE;
    }

exit:
    if (rc == TPM_RC_SUCCESS) {
        printf("PASS  HashML-DSA-%-3s  signdigest+verify (sig %d bytes)\n",
            mldsaName(ps), sigSz);
    }
    else {
        printf("FAIL  HashML-DSA-%-3s  0x%x: %s\n",
            mldsaName(ps), rc, wolfTPM2_GetRCString(rc));
    }
    wolfTPM2_UnloadHandle(dev, &key.handle);
    XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return rc;
}

static int do_mlkem(WOLFTPM2_DEV* dev, TPMI_MLKEM_PARAMETER_SET ps)
{
    int rc;
    WOLFTPM2_KEY key;
    TPMT_PUBLIC tpl;
    byte ss1[64];
    byte ss2[64];
    int ss1Sz = (int)sizeof(ss1);
    int ss2Sz = (int)sizeof(ss2);
    byte* ct = NULL;
    int ctSz = MAX_MLKEM_CT_SIZE;

    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(&tpl, 0, sizeof(tpl));
    XMEMSET(ss1, 0, sizeof(ss1));
    XMEMSET(ss2, 0, sizeof(ss2));

    (void)pqc_flush_transient(dev);

    ct = (byte*)XMALLOC(MAX_MLKEM_CT_SIZE, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (ct == NULL)
        return MEMORY_E;

    rc = wolfTPM2_GetKeyTemplate_MLKEM(&tpl,
        TPMA_OBJECT_decrypt | TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent |
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_noDA, ps);
    if (rc != TPM_RC_SUCCESS) goto exit;

    rc = wolfTPM2_CreatePrimaryKey(dev, &key, TPM_RH_OWNER, &tpl, NULL, 0);
    if (rc != TPM_RC_SUCCESS) goto exit;

    rc = wolfTPM2_Encapsulate(dev, &key, ct, &ctSz, ss1, &ss1Sz);
    if (rc != TPM_RC_SUCCESS) goto exit;

    rc = wolfTPM2_Decapsulate(dev, &key, ct, ctSz, ss2, &ss2Sz);
    if (rc != TPM_RC_SUCCESS) goto exit;

    if (ss1Sz <= 0 || ss1Sz != ss2Sz || XMEMCMP(ss1, ss2, ss1Sz) != 0) {
        printf("ML-KEM-%s: decapsulated secret does not match\n",
            mlkemName(ps));
        rc = TPM_RC_FAILURE;
    }

exit:
    if (rc == TPM_RC_SUCCESS) {
        printf("PASS  ML-KEM-%-3s      encap+decap (ct %d bytes)\n",
            mlkemName(ps), ctSz);
    }
    else {
        printf("FAIL  ML-KEM-%-3s      0x%x: %s\n",
            mlkemName(ps), rc, wolfTPM2_GetRCString(rc));
    }
    wc_ForceZero(ss1, sizeof(ss1));
    wc_ForceZero(ss2, sizeof(ss2));
    wolfTPM2_UnloadHandle(dev, &key.handle);
    XFREE(ct, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return rc;
}

/* Run one --all step and keep the first non-zero return code. */
static void allStep(int rc, int* firstErr)
{
    if (rc != 0 && *firstErr == 0) {
        *firstErr = rc;
    }
}

static int do_all(WOLFTPM2_DEV* dev)
{
    int firstErr = 0;

    printf("=== TPM control + PQC full matrix ===\n");
    allStep(do_caps(dev), &firstErr);
    allStep(do_algs(dev), &firstErr);
    allStep(do_selftest(dev), &firstErr);
    allStep(do_getrandom(dev, 16), &firstErr);
    allStep(do_pcrread(dev, 0), &firstErr);
    allStep(do_mldsa(dev, TPM_MLDSA_44), &firstErr);
    allStep(do_mldsa(dev, TPM_MLDSA_65), &firstErr);
    allStep(do_mldsa(dev, TPM_MLDSA_87), &firstErr);
    allStep(do_hash_mldsa(dev, TPM_MLDSA_44), &firstErr);
    allStep(do_hash_mldsa(dev, TPM_MLDSA_65), &firstErr);
    allStep(do_hash_mldsa(dev, TPM_MLDSA_87), &firstErr);
    allStep(do_mlkem(dev, TPM_MLKEM_512), &firstErr);
    allStep(do_mlkem(dev, TPM_MLKEM_768), &firstErr);
    allStep(do_mlkem(dev, TPM_MLKEM_1024), &firstErr);
    return firstErr;
}

/* Match "name" (bare flag, sets val="") or "name=VALUE" (sets val=VALUE).
 * Returns 0 when arg is a different option, so a missing '=' such as
 * "--pcrextend16" does not match and is reported as unrecognized. */
static int matchOpt(const char* arg, const char* name, const char** val)
{
    word32 nameLen = (word32)XSTRLEN(name);

    if (XSTRNCMP(arg, name, nameLen) != 0) {
        return 0;
    }
    if (arg[nameLen] == '\0') {
        *val = "";
        return 1;
    }
    if (arg[nameLen] == '=') {
        if (arg[nameLen + 1] == '\0') {
            return 0; /* "name=" with no value is not a valid option */
        }
        *val = arg + nameLen + 1;
        return 1;
    }
    return 0;
}

/* Return 1 if val is all digits and parses to a number in [lo, hi]. An empty
 * string returns 0, so callers decide whether a bare flag is acceptable. */
static int validNum(const char* val, int lo, int hi)
{
    int i;
    int n;

    /* Reject empty and over-long inputs (guards XATOI against overflow, which
     * could otherwise wrap a huge value back into [lo, hi]). */
    if (val[0] == '\0' || XSTRLEN(val) > 3) {
        return 0;
    }
    for (i = 0; val[i] != '\0'; i++) {
        if (val[i] < '0' || val[i] > '9') {
            return 0;
        }
    }
    n = XATOI(val);
    return (n >= lo && n <= hi);
}

/* Handle one option. When validateOnly is set, only check that the option is
 * recognized and its value is valid — no TPM access, dev may be NULL; otherwise
 * execute it. This is the single source of truth for the option set, shared by
 * the pre-execution validation pass and the execution pass, so there is no
 * duplicated option table. Returns 0 on success, BAD_FUNC_ARG for an unknown
 * option or bad value, or a TPM return code from the executed operation. */
static int handleOpt(WOLFTPM2_DEV* dev, const char* arg, int validateOnly)
{
    int rc;
    const char* val;
    TPMI_MLDSA_PARAMETER_SET ms;
    TPMI_MLKEM_PARAMETER_SET ks;

    if (XSTRCMP(arg, "--caps") == 0) {
        return validateOnly ? 0 : do_caps(dev);
    }
    if (XSTRCMP(arg, "--algs") == 0) {
        return validateOnly ? 0 : do_algs(dev);
    }
    if (XSTRCMP(arg, "--selftest") == 0) {
        return validateOnly ? 0 : do_selftest(dev);
    }
    if (XSTRCMP(arg, "--clear") == 0) {
        return validateOnly ? 0 : do_clear(dev);
    }
    if (XSTRCMP(arg, "--all") == 0) {
        return validateOnly ? 0 : do_all(dev);
    }
    if (XSTRCMP(arg, "--flush") == 0) {
        if (validateOnly) {
            return 0;
        }
        rc = pqc_flush_transient(dev);
        if (rc != TPM_RC_SUCCESS) {
            printf("FAIL  flush  0x%x: %s\n", rc, wolfTPM2_GetRCString(rc));
            return rc;
        }
        printf("Flushed transient objects\n");
        return TPM_RC_SUCCESS;
    }
    if (matchOpt(arg, "--getrandom", &val)) {
        if (val[0] != '\0' && !validNum(val, 1, 64)) {
            printf("Error: --getrandom length must be 1..64: %s\n", arg);
            return BAD_FUNC_ARG;
        }
        return validateOnly ? 0 :
            do_getrandom(dev, val[0] == '\0' ? 16 : XATOI(val));
    }
    if (matchOpt(arg, "--pcrread", &val)) {
        if (val[0] != '\0' && !validNum(val, 0, 23)) {
            printf("Error: --pcrread index must be 0..23: %s\n", arg);
            return BAD_FUNC_ARG;
        }
        return validateOnly ? 0 : do_pcrread(dev, XATOI(val));
    }
    if (matchOpt(arg, "--pcrextend", &val)) {
        /* extend is irreversible: require an explicit in-range index */
        if (!validNum(val, 0, 23)) {
            printf("Error: --pcrextend needs an explicit PCR 0..23: %s\n", arg);
            return BAD_FUNC_ARG;
        }
        return validateOnly ? 0 : do_pcrextend(dev, XATOI(val));
    }
    if (matchOpt(arg, "--hash-mldsa", &val)) {
        if (parseMldsaSet(val, &ms) != 0) {
            printf("Error: invalid ML-DSA parameter set: %s\n", arg);
            return BAD_FUNC_ARG;
        }
        return validateOnly ? 0 : do_hash_mldsa(dev, ms);
    }
    if (matchOpt(arg, "--mldsa", &val)) {
        if (parseMldsaSet(val, &ms) != 0) {
            printf("Error: invalid ML-DSA parameter set: %s\n", arg);
            return BAD_FUNC_ARG;
        }
        return validateOnly ? 0 : do_mldsa(dev, ms);
    }
    if (matchOpt(arg, "--mlkem", &val)) {
        if (parseMlkemSet(val, &ks) != 0) {
            printf("Error: invalid ML-KEM parameter set: %s\n", arg);
            return BAD_FUNC_ARG;
        }
        return validateOnly ? 0 : do_mlkem(dev, ks);
    }
    printf("Error: Unrecognized option: %s\n", arg);
    return BAD_FUNC_ARG;
}

static int pqc_ctrl_run(int argc, char* argv[])
{
    int rc = 0;
    int opRc;
    int i;
    WOLFTPM2_DEV dev;

    for (i = 1; i < argc; i++) {
        if (XSTRCMP(argv[i], "-?") == 0 || XSTRCMP(argv[i], "-h") == 0 ||
                XSTRCMP(argv[i], "--help") == 0) {
            usage();
            return 0;
        }
    }

    /* Validation pass: reject a bad argument set before touching the TPM or
     * running any op, so a typo cannot run an earlier --clear or PCR extend. */
    for (i = 1; i < argc; i++) {
        if (handleOpt(NULL, argv[i], 1) != 0) {
            usage();
            return BAD_FUNC_ARG;
        }
    }

    XMEMSET(&dev, 0, sizeof(dev));
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, NULL);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_Init failed 0x%x: %s\n",
            rc, wolfTPM2_GetRCString(rc));
        return rc;
    }

    /* No arguments: run the full control + PQC matrix. */
    if (argc <= 1) {
        rc = do_all(&dev);
    }

    /* Execution pass: every argument was validated above. */
    for (i = 1; i < argc; i++) {
        opRc = handleOpt(&dev, argv[i], 0);
        if (opRc != 0 && rc == 0) {
            rc = opRc;
        }
    }

    wolfTPM2_Cleanup(&dev);
    return rc;
}

#endif /* !WOLFTPM2_NO_WRAPPER && PQC ops */

#ifndef NO_MAIN_DRIVER
int main(int argc, char* argv[])
{
#if !defined(WOLFTPM2_NO_WRAPPER) && \
    defined(WOLFTPM_MLDSA_SIGN) && defined(WOLFTPM_MLDSA_VERIFY) && \
    defined(WOLFTPM_MLKEM_ENCAP) && defined(WOLFTPM_MLKEM_DECAP) && \
    defined(WOLFTPM_HASH_MLDSA)
    int rc = pqc_ctrl_run(argc, argv);
    return (rc == 0) ? 0 : 1;
#else
    (void)argc;
    (void)argv;
    printf("pqc_ctrl requires --enable-v185 (ML-DSA + ML-KEM + Hash-ML-DSA)\n");
    return 0;
#endif
}
#endif /* NO_MAIN_DRIVER */
