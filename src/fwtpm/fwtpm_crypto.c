/* fwtpm_crypto.c
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

/* fwTPM Cryptographic Helpers
 * Shared cryptographic operations extracted from fwtpm_command.c:
 * hashing, key generation, key wrapping, signing/verification,
 * import/export, attestation, and credential helpers.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2_types.h>

#ifdef WOLFTPM_FWTPM

#include <wolftpm/tpm2_packet.h>
#include <wolftpm/tpm2_param_enc.h>
#include <wolftpm/fwtpm/fwtpm.h>
#include <wolftpm/fwtpm/fwtpm_nv.h>
#include <wolftpm/fwtpm/fwtpm_crypto.h>

#include <stdio.h>
#include <string.h>

/* fwTPM requires wolfCrypt for all cryptographic operations */
#ifdef WOLFTPM2_NO_WOLFCRYPT
    #error "fwTPM requires wolfCrypt. Do not use --disable-wolfcrypt with --enable-fwtpm."
#endif

#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/random.h>
#ifndef NO_RSA
#include <wolfssl/wolfcrypt/rsa.h>
#endif
#ifdef HAVE_ECC
#include <wolfssl/wolfcrypt/ecc.h>
#endif
#ifndef NO_AES
#include <wolfssl/wolfcrypt/aes.h>
#endif
#include <wolfssl/wolfcrypt/hmac.h>
#ifdef WOLFTPM_V185
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/mlkem.h>
#endif

/* ================================================================== */
/* Small utility helpers                                               */
/* ================================================================== */

/* Wrapper to avoid -Werror=bad-function-cast with TPM2_GetHashType */
enum wc_HashType FwGetWcHashType(UINT16 hashAlg)
{
    int ret = TPM2_GetHashType(hashAlg);
    return (enum wc_HashType)ret;
}

#ifndef NO_RSA
int FwGetMgfType(UINT16 hashAlg)
{
    switch (hashAlg) {
    #ifdef WOLFSSL_SHA512
        case TPM_ALG_SHA512: return WC_MGF1SHA512;
    #endif
    #ifdef WOLFSSL_SHA384
        case TPM_ALG_SHA384: return WC_MGF1SHA384;
    #endif
        case TPM_ALG_SHA256: /* fallthrough */
        default:             return WC_MGF1SHA256;
    }
}
#endif /* !NO_RSA */

/* Compute unique = H(keyData) for KEYEDHASH/SYMCIPHER key types.
 * Stores the hash in outBuf and returns the digest size, or 0 on error. */
int FwComputeUniqueHash(TPMI_ALG_HASH nameAlg, const byte* keyData,
    int keyDataSz, byte* outBuf)
{
    int rc = 0;
    enum wc_HashType wcHash = FwGetWcHashType(nameAlg);
    int hSz = TPM2_GetHashDigestSize(nameAlg);

    if (hSz > 0) {
        FWTPM_DECLARE_VAR(hCtx, wc_HashAlg);
        FWTPM_ALLOC_VAR(hCtx, wc_HashAlg);
        if (rc == 0 && wc_HashInit(hCtx, wcHash) == 0) {
            rc = wc_HashUpdate(hCtx, wcHash, keyData, (word32)keyDataSz);
            if (rc == 0) {
                rc = wc_HashFinal(hCtx, wcHash, outBuf);
            }
            wc_HashFree(hCtx, wcHash);
            if (rc == 0) {
                FWTPM_FREE_VAR(hCtx);
                return hSz;
            }
        }
        FWTPM_FREE_VAR(hCtx);
    }
    return 0;
}

/* Compute hashUnique = H_nameAlg(sensitiveCreate.data || unique_bytes).
 * Per TPM 2.0 Part 1 Section 26.1: used as context for primary key derivation.
 * Returns digest size on success, 0 on error. */
int FwComputeHashUnique(TPMI_ALG_HASH nameAlg,
    const byte* sensData, int sensDataSz,
    const byte* uniqueData, int uniqueDataSz,
    byte* hashOut)
{
    int rc = 0;
    enum wc_HashType wcHash = FwGetWcHashType(nameAlg);
    int hSz = TPM2_GetHashDigestSize(nameAlg);

    if (hSz > 0) {
        FWTPM_DECLARE_VAR(hCtx, wc_HashAlg);
        FWTPM_ALLOC_VAR(hCtx, wc_HashAlg);
        rc = wc_HashInit(hCtx, wcHash);
        if (rc == 0 && sensData != NULL && sensDataSz > 0) {
            rc = wc_HashUpdate(hCtx, wcHash, sensData, (word32)sensDataSz);
        }
        if (rc == 0 && uniqueData != NULL && uniqueDataSz > 0) {
            rc = wc_HashUpdate(hCtx, wcHash, uniqueData, (word32)uniqueDataSz);
        }
        if (rc == 0) {
            rc = wc_HashFinal(hCtx, wcHash, hashOut);
        }
        wc_HashFree(hCtx, wcHash);
        FWTPM_FREE_VAR(hCtx);
        if (rc == 0) {
            return hSz;
        }
    }
    return 0;
}

/* Derive a symmetric primary key from hierarchy seed via KDFa.
 * Per TPM 2.0 Part 1 Section 26.1:
 *   key = KDFa(nameAlg, seed, label, hashUnique, NULL, keySz*8)
 * label is "KEYEDHASH" or "SYMCIPHER" depending on type.
 * Returns TPM_RC_SUCCESS or error. */
TPM_RC FwDeriveSymmetricPrimaryKey(TPMI_ALG_HASH nameAlg,
    const byte* seed, const byte* hashUnique, int hashUniqueSz,
    const char* label, byte* keyOut, int keySz)
{
    int kdfRet;

    kdfRet = TPM2_KDFa_ex(nameAlg, seed, FWTPM_SEED_SIZE,
        label, hashUnique, (UINT32)hashUniqueSz,
        NULL, 0, keyOut, (UINT32)keySz);
    if (kdfRet != keySz) {
        return TPM_RC_FAILURE;
    }
    return TPM_RC_SUCCESS;
}

/* ================================================================== */
/* Object/NV name computation                                          */
/* ================================================================== */

/** \brief Compute TPM object name: nameAlg(2) || Hash(marshaledPublicArea).
 *  Stores result in obj->name. */
int FwComputeObjectName(FWTPM_Object* obj)
{
    int rc = TPM_RC_SUCCESS;
    FWTPM_DECLARE_BUF(pubBuf, FWTPM_MAX_PUB_BUF);
    TPM2_Packet tmpPkt;
    int pubSz;
    enum wc_HashType wcHash;
    int digestSz;

    FWTPM_ALLOC_BUF(pubBuf, FWTPM_MAX_PUB_BUF);

    /* Marshal public area into temp buffer */
    tmpPkt.buf = pubBuf;
    tmpPkt.pos = 0;
    tmpPkt.size = (int)FWTPM_MAX_PUB_BUF;
    TPM2_Packet_AppendPublicArea(&tmpPkt, &obj->pub);
    pubSz = tmpPkt.pos;

    wcHash = FwGetWcHashType(obj->pub.nameAlg);
    digestSz = TPM2_GetHashDigestSize(obj->pub.nameAlg);
    if (wcHash == WC_HASH_TYPE_NONE || digestSz == 0) {
        rc = TPM_RC_HASH;
    }

    if (rc == 0) {
        /* name = nameAlg(2 bytes big-endian) || Hash(publicArea) */
        obj->name.size = 2 + digestSz;
        FwStoreU16BE(obj->name.name, obj->pub.nameAlg);
        rc = wc_Hash(wcHash, pubBuf, pubSz, obj->name.name + 2, digestSz);
        if (rc != 0) {
            rc = TPM_RC_FAILURE;
        }
    }

    FWTPM_FREE_BUF(pubBuf);
    return rc;
}

/** \brief Get hierarchy seed pointer for a given hierarchy handle.
 *  \return Pointer to seed bytes, or NULL for unknown hierarchy. */
byte* FwGetHierarchySeed(FWTPM_CTX* ctx, UINT32 hierarchy)
{
    switch (hierarchy) {
        case TPM_RH_OWNER:
            return ctx->ownerSeed;
        case TPM_RH_ENDORSEMENT:
            return ctx->endorsementSeed;
        case TPM_RH_PLATFORM:
            return ctx->platformSeed;
        case TPM_RH_NULL:
            return ctx->nullSeed;
        default:
            return NULL;
    }
}

/** \brief Derive proof value from a hierarchy seed via KDFa.
 *  proofValue = KDFa(hashAlg, seed, "PROOF", NULL, NULL, digestSize).
 *  Used for HMAC-based ticket verification (Hash, Sign, VerifySignature). */
int FwComputeProofValue(FWTPM_CTX* ctx, UINT32 hierarchy,
    TPMI_ALG_HASH hashAlg, byte* proofOut, int proofSize)
{
    byte* seed = FwGetHierarchySeed(ctx, hierarchy);
    int rc;
    if (seed == NULL) {
        return TPM_RC_FAILURE;
    }
    rc = TPM2_KDFa_ex(hashAlg, seed, FWTPM_SEED_SIZE,
        "PROOF", NULL, 0, NULL, 0, proofOut, proofSize);
    if (rc != proofSize) {
        return TPM_RC_FAILURE;
    }
    return 0;
}

/** \brief Compute ticket HMAC per Part 2 Sec.10.6.5 Eq (5):
 *    hmac = HMAC(proof(hierarchy), ticketTag || data || metadata)
 * Pass metadata=NULL and metadataSz=0 for ticket types whose
 * TPMU_TK_VERIFIED_META is empty (HASHCHECK, VERIFIED, CREATION,
 * MESSAGE_VERIFIED, AUTH_*). */
int FwComputeTicketHmac(FWTPM_CTX* ctx, UINT32 hierarchy,
    TPMI_ALG_HASH hashAlg, UINT16 ticketTag,
    const byte* data, int dataSz,
    const byte* metadata, int metadataSz,
    byte* hmacOut, int* hmacOutSz)
{
    byte proof[TPM_MAX_DIGEST_SIZE];
    byte tagBytes[2];
    int proofSz = TPM2_GetHashDigestSize(hashAlg);
    FWTPM_DECLARE_VAR(hmacCtx, Hmac);
    enum wc_HashType wcHash = FwGetWcHashType(hashAlg);
    int rc;

    FWTPM_ALLOC_VAR(hmacCtx, Hmac);

    if (proofSz <= 0) {
        FWTPM_FREE_VAR(hmacCtx);
        return TPM_RC_HASH;
    }

    tagBytes[0] = (byte)(ticketTag >> 8);
    tagBytes[1] = (byte)(ticketTag);

    rc = FwComputeProofValue(ctx, hierarchy, hashAlg, proof, proofSz);
    if (rc == 0) {
        rc = wc_HmacInit(hmacCtx, NULL, INVALID_DEVID);
    }
    if (rc == 0) {
        rc = wc_HmacSetKey(hmacCtx, (int)wcHash, proof, (word32)proofSz);
    }
    if (rc == 0) {
        rc = wc_HmacUpdate(hmacCtx, tagBytes, 2);
    }
    if (rc == 0 && dataSz > 0) {
        rc = wc_HmacUpdate(hmacCtx, data, (word32)dataSz);
    }
    if (rc == 0 && metadataSz > 0) {
        rc = wc_HmacUpdate(hmacCtx, metadata, (word32)metadataSz);
    }
    if (rc == 0) {
        rc = wc_HmacFinal(hmacCtx, hmacOut);
    }
    wc_HmacFree(hmacCtx);

    if (rc == 0) {
        *hmacOutSz = proofSz;
    }
    else {
        rc = TPM_RC_FAILURE;
    }

    TPM2_ForceZero(proof, sizeof(proof));
    FWTPM_FREE_VAR(hmacCtx);
    return rc;
}

/** \brief Compute and append a ticket (TPMT_TK_*) to a response packet.
 *  Per Part 2 Sec.10.6.5 Eq (5):
 *    hmac = HMAC(proofValue, ticketTag || data || metadata)
 *  ticketTag is bound into the HMAC so two different ticket types over the
 *  same data can't be substituted. metadata (selected on tag per
 *  TPMU_TK_VERIFIED_META) is also bound when non-empty — for
 *  TPM_ST_DIGEST_VERIFIED that is the 2-byte sigHashAlg.
 *  Wire format: ticketTag || hierarchy || metadata || hmacSize || hmac.
 *  For NULL hierarchy, appends a NULL ticket (digest size = 0). */
int FwAppendTicket(FWTPM_CTX* ctx, TPM2_Packet* rsp,
    UINT16 ticketTag, UINT32 hierarchy, TPMI_ALG_HASH hashAlg,
    const byte* data, int dataSz,
    const byte* metadata, int metadataSz)
{
    byte ticketHmac[TPM_MAX_DIGEST_SIZE];
    int ticketHmacSz = 0;
    int rc;

    if (hierarchy == TPM_RH_NULL) {
        /* Part 2 Sec.10.6.5: every NULL Verified/Hashcheck Ticket is the
         * 3-tuple <tag, TPM_RH_NULL, 0x0000>. TPMU_*_META bytes (e.g.
         * the metaAlg field on TPM_ST_DIGEST_VERIFIED) are omitted when
         * hierarchy == TPM_RH_NULL — the ticket carries no semantic
         * binding to discriminate. */
        TPM2_Packet_AppendU16(rsp, ticketTag);
        TPM2_Packet_AppendU32(rsp, TPM_RH_NULL);
        TPM2_Packet_AppendU16(rsp, 0);
        (void)metadata;
        (void)metadataSz;
        return TPM_RC_SUCCESS;
    }

    rc = FwComputeTicketHmac(ctx, hierarchy, hashAlg, ticketTag,
        data, dataSz, metadata, metadataSz,
        ticketHmac, &ticketHmacSz);
    if (rc == 0) {
        TPM2_Packet_AppendU16(rsp, ticketTag);
        TPM2_Packet_AppendU32(rsp, hierarchy);
        if (metadataSz > 0) {
            TPM2_Packet_AppendBytes(rsp, (byte*)metadata, metadataSz);
        }
        TPM2_Packet_AppendU16(rsp, (UINT16)ticketHmacSz);
        TPM2_Packet_AppendBytes(rsp, ticketHmac, ticketHmacSz);
    }
    TPM2_ForceZero(ticketHmac, sizeof(ticketHmac));
    return rc;
}

/** \brief Compute creationHash from serialized creationData in response buffer,
 *  append creationHash(TPM2B) + creationTicket(TPMT_TK_CREATION) to response. */
int FwAppendCreationHashAndTicket(FWTPM_CTX* ctx, TPM2_Packet* rsp,
    UINT32 hierarchy, TPMI_ALG_HASH nameAlg,
    int cdStart, int cdSize,
    const byte* objName, int objNameSz)
{
    byte creationHash[TPM_MAX_DIGEST_SIZE];
    byte ticketData[TPM_MAX_DIGEST_SIZE + sizeof(TPM2B_NAME)];
    int chSz = TPM2_GetHashDigestSize(nameAlg);
    int ticketDataSz = 0;
    int hashRc = 0;

    if (chSz > 0) {
        hashRc = wc_Hash(FwGetWcHashType(nameAlg),
            rsp->buf + cdStart, cdSize, creationHash, chSz);
        if (hashRc != 0) {
            chSz = 0;
        }
    }
    TPM2_Packet_AppendU16(rsp, (UINT16)chSz);
    if (chSz > 0) {
        TPM2_Packet_AppendBytes(rsp, creationHash, chSz);
        XMEMCPY(ticketData, creationHash, chSz);
        ticketDataSz = chSz;
    }
    if (objNameSz > 0) {
        if (ticketDataSz + objNameSz > (int)sizeof(ticketData)) {
            return TPM_RC_SIZE;
        }
        XMEMCPY(ticketData + ticketDataSz, objName, objNameSz);
        ticketDataSz += objNameSz;
    }
    return FwAppendTicket(ctx, rsp, TPM_ST_CREATION, hierarchy,
        nameAlg, ticketData, ticketDataSz, NULL, 0);
}

/* ================================================================== */
/* ECC curve helpers                                                   */
/* ================================================================== */

#ifdef HAVE_ECC
/* Map TPM ECC curve to wolfCrypt curve ID */
int FwGetWcCurveId(UINT16 tpmCurve)
{
    switch (tpmCurve) {
        case TPM_ECC_NIST_P256:
            return ECC_SECP256R1;
        case TPM_ECC_NIST_P384:
            return ECC_SECP384R1;
    #ifdef HAVE_ECC521
        case TPM_ECC_NIST_P521:
            return ECC_SECP521R1;
    #endif
        default:
            return -1;
    }
}
#endif /* HAVE_ECC */

/* Get ECC key size in bytes from TPM curve */
int FwGetEccKeySize(UINT16 tpmCurve)
{
    switch (tpmCurve) {
        case TPM_ECC_NIST_P256:
            return 32;
        case TPM_ECC_NIST_P384:
            return 48;
    #ifdef HAVE_ECC521
        case TPM_ECC_NIST_P521:
            return 66;
    #endif
        default:
            return 0;
    }
}

/* ================================================================== */
/* Key generation                                                      */
/* ================================================================== */

/* --- Shared helper: generate RSA keypair, export public modulus + private DER --- */
#ifndef NO_RSA
#ifdef WOLFSSL_KEY_GEN
TPM_RC FwGenerateRsaKey(WC_RNG* rng,
    int keyBits, UINT32 exponent,
    TPM2B_PUBLIC_KEY_RSA* pubOut,
    byte* privKeyDer, int privKeyDerBufSz, int* privKeyDerSz)
{
    TPM_RC rc;
    FWTPM_DECLARE_VAR(rsaKey, RsaKey);
    int rsaInit = 0;
    word32 modSz, eSz;
    byte eBuf[8];

    FWTPM_ALLOC_VAR(rsaKey, RsaKey);

    if (keyBits == 0) {
        keyBits = 2048;
    }
    if (exponent == 0) {
        exponent = WC_RSA_EXPONENT;
    }

    rc = wc_InitRsaKey(rsaKey, NULL);
    if (rc == 0) {
        rsaInit = 1;
        rc = wc_MakeRsaKey(rsaKey, keyBits, (long)exponent, rng);
    }

    /* Extract public modulus */
    if (rc == 0) {
        modSz = keyBits / 8;
        if (modSz > sizeof(pubOut->buffer)) {
            modSz = sizeof(pubOut->buffer);
        }
        eSz = (word32)sizeof(eBuf);
        rc = wc_RsaFlattenPublicKey(rsaKey, eBuf, &eSz,
            pubOut->buffer, &modSz);
    }
    if (rc == 0) {
        pubOut->size = (UINT16)modSz;
    }

    /* Export private key to DER */
    if (rc == 0) {
        *privKeyDerSz = wc_RsaKeyToDer(rsaKey, privKeyDer, privKeyDerBufSz);
        if (*privKeyDerSz < 0) {
            rc = TPM_RC_FAILURE;
        }
    }

    if (rsaInit) {
        wc_FreeRsaKey(rsaKey);
    }
    FWTPM_FREE_VAR(rsaKey);
    if (rc != 0 && rc != TPM_RC_COMMAND_CODE) {
        rc = TPM_RC_FAILURE;
    }
    return rc;
}
#endif /* WOLFSSL_KEY_GEN */
#endif /* !NO_RSA */

/* --- Shared helper: generate ECC keypair, export public point + private DER --- */
#ifdef HAVE_ECC
TPM_RC FwGenerateEccKey(WC_RNG* rng,
    UINT16 curveId,
    TPMS_ECC_POINT* pubOut,
    byte* privKeyDer, int privKeyDerBufSz, int* privKeyDerSz)
{
    TPM_RC rc;
    FWTPM_DECLARE_VAR(eccKey, ecc_key);
    int eccInit = 0;
    int wcCurve = FwGetWcCurveId(curveId);
    int keySz = FwGetEccKeySize(curveId);
    word32 xSz, ySz;

    FWTPM_ALLOC_VAR(eccKey, ecc_key);

    if (wcCurve < 0 || keySz == 0) {
        FWTPM_FREE_VAR(eccKey);
        return TPM_RC_CURVE;
    }

    rc = wc_ecc_init(eccKey);
    if (rc == 0) {
        eccInit = 1;
        rc = wc_ecc_make_key_ex(rng, keySz, eccKey, wcCurve);
    }

    /* Extract public point x, y */
    if (rc == 0) {
        xSz = (word32)keySz;
        ySz = (word32)keySz;
        rc = wc_ecc_export_public_raw(eccKey,
            pubOut->x.buffer, &xSz,
            pubOut->y.buffer, &ySz);
    }
    if (rc == 0) {
        pubOut->x.size = (UINT16)xSz;
        pubOut->y.size = (UINT16)ySz;
    }

    /* Export private key to DER */
    if (rc == 0) {
        *privKeyDerSz = wc_EccKeyToDer(eccKey, privKeyDer, privKeyDerBufSz);
        if (*privKeyDerSz < 0) {
            rc = TPM_RC_FAILURE;
        }
    }

    if (eccInit) {
        wc_ecc_free(eccKey);
    }
    FWTPM_FREE_VAR(eccKey);
    if (rc != 0 && rc != TPM_RC_CURVE) {
        rc = TPM_RC_FAILURE;
    }
    return rc;
}
#endif /* HAVE_ECC */

/* ================================================================== */
/* Seed-based primary key derivation (TPM 2.0 Part 1 Section 26)       */
/* ================================================================== */

#ifdef HAVE_ECC
/* Derive ECC primary key from hierarchy seed per TPM 2.0 Part 1 Section 26.3.
 *   d = KDFa(nameAlg, seed, "ECC", hashUnique, counter, keySz*8)
 *   Q = d * G
 * The counter in contextV is incremented if d >= order or d == 0. */
TPM_RC FwDeriveEccPrimaryKey(TPMI_ALG_HASH nameAlg,
    const byte* seed, const byte* hashUnique, int hashUniqueSz,
    UINT16 curveId,
    TPMS_ECC_POINT* pubOut,
    byte* privKeyDer, int privKeyDerBufSz, int* privKeyDerSz)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    FWTPM_DECLARE_VAR(eccKey, ecc_key);
    int eccInit = 0;
    int wcCurve = FwGetWcCurveId(curveId);
    int keySz = FwGetEccKeySize(curveId);
    word32 xSz, ySz;
    byte dBuf[MAX_ECC_BYTES];
    byte counterBuf[4];
    UINT32 counter = 1;
    int kdfRet;
    int valid = 0;
    int i;
    int allZero;
    volatile byte orAccum;

    FWTPM_ALLOC_VAR(eccKey, ecc_key);

    if (wcCurve < 0 || keySz == 0 || keySz > (int)sizeof(dBuf)) {
        FWTPM_FREE_VAR(eccKey);
        return TPM_RC_CURVE;
    }

    /* Derive private scalar d via KDFa, retry if out of range */
    while (!valid && counter < 100) {
        FwStoreU32BE(counterBuf, counter);
        kdfRet = TPM2_KDFa_ex(nameAlg, seed, FWTPM_SEED_SIZE,
            "ECC", hashUnique, (UINT32)hashUniqueSz,
            counterBuf, sizeof(counterBuf),
            dBuf, (UINT32)keySz);
        if (kdfRet != keySz) {
            rc = TPM_RC_FAILURE;
            break;
        }
        /* Constant-time check d != 0 (all zeros) */
        orAccum = 0;
        for (i = 0; i < keySz; i++) {
            orAccum |= dBuf[i];
        }
        allZero = (orAccum == 0);
        if (!allZero) {
            valid = 1; /* Accept — range check done by import */
        }
        counter++;
    }
    if (rc == 0 && !valid) {
        rc = TPM_RC_NO_RESULT;
    }

    /* Import private scalar and compute public point Q = d*G */
    if (rc == 0) {
        rc = wc_ecc_init(eccKey);
    }
    if (rc == 0) {
        eccInit = 1;
        rc = wc_ecc_import_private_key_ex(dBuf, (word32)keySz,
            NULL, 0, eccKey, wcCurve);
    }
    if (rc == 0) {
    #ifdef ECC_TIMING_RESISTANT
        rc = wc_ecc_make_pub_ex(eccKey, NULL, NULL);
    #else
        rc = wc_ecc_make_pub(eccKey, NULL);
    #endif
    }

    /* Export public point (x, y) */
    if (rc == 0) {
        xSz = (word32)keySz;
        ySz = (word32)keySz;
        rc = wc_ecc_export_public_raw(eccKey,
            pubOut->x.buffer, &xSz,
            pubOut->y.buffer, &ySz);
    }
    if (rc == 0) {
        pubOut->x.size = (UINT16)xSz;
        pubOut->y.size = (UINT16)ySz;
    }

    /* Export private key to DER */
    if (rc == 0) {
        *privKeyDerSz = wc_EccKeyToDer(eccKey, privKeyDer, privKeyDerBufSz);
        if (*privKeyDerSz < 0) {
            rc = TPM_RC_FAILURE;
        }
    }

    TPM2_ForceZero(dBuf, sizeof(dBuf));
    if (eccInit) {
        wc_ecc_free(eccKey);
    }
    FWTPM_FREE_VAR(eccKey);
    if (rc != 0 && rc != TPM_RC_CURVE && rc != TPM_RC_NO_RESULT) {
        rc = TPM_RC_FAILURE;
    }
    return rc;
}
#endif /* HAVE_ECC */

#ifdef WOLFTPM_V185
/* ================================================================== */
/* v1.85 PQC primary-key derivation (ML-DSA / ML-KEM)                  */
/* ================================================================== */

/* TCG Part 4 v1.85 (which would normatively pin the KDFa labels for
 * primary-key derivation) is unpublished as of the v1.85 rc4 release.
 * The "MLDSA" / "HASH_MLDSA" / "MLKEM" labels below are wolfTPM's
 * interpretation; if the final spec prescribes different labels every
 * primary key derived against this build will require migration.
 * See docs/FWTPM.md and FwDeriveMldsaPrimaryKeySeed for details. */

/* Map TPM v1.85 ML-DSA parameter set to wolfCrypt dilithium level. */
static int FwGetWcMldsaLevel(TPMI_MLDSA_PARAMETER_SET ps)
{
    switch (ps) {
        case TPM_MLDSA_44: return WC_ML_DSA_44;
        case TPM_MLDSA_65: return WC_ML_DSA_65;
        case TPM_MLDSA_87: return WC_ML_DSA_87;
        default:           return -1;
    }
}

/* Map TPM v1.85 ML-KEM parameter set to wolfCrypt ML-KEM type. */
static int FwGetWcMlkemType(TPMI_MLKEM_PARAMETER_SET ps)
{
    switch (ps) {
        case TPM_MLKEM_512:  return WC_ML_KEM_512;
        case TPM_MLKEM_768:  return WC_ML_KEM_768;
        case TPM_MLKEM_1024: return WC_ML_KEM_1024;
        default:             return -1;
    }
}

/** \brief Derive 32-byte ML-DSA seed xi from hierarchy primary seed via KDFa.
 *  Caller selects label: "MLDSA" for TPM_ALG_MLDSA or "HASH_MLDSA" for
 *  TPM_ALG_HASH_MLDSA (interpretation, pending Part 4 v185 publication).
 *  The derived seed is fed into FIPS 204 deterministic keygen. */
TPM_RC FwDeriveMldsaPrimaryKeySeed(TPMI_ALG_HASH nameAlg,
    const byte* seed, const byte* hashUnique, int hashUniqueSz,
    const char* label, byte* seedXiOut)
{
    int kdfRet;

    kdfRet = TPM2_KDFa_ex(nameAlg, seed, FWTPM_SEED_SIZE,
        label, hashUnique, (UINT32)hashUniqueSz,
        NULL, 0, seedXiOut, MAX_MLDSA_PRIV_SEED_SIZE);
    if (kdfRet != MAX_MLDSA_PRIV_SEED_SIZE) {
        return TPM_RC_FAILURE;
    }
    return TPM_RC_SUCCESS;
}

/** \brief Derive 64-byte ML-KEM seed (d || z) from hierarchy primary seed
 *  via KDFa using the label "MLKEM" (interpretation, pending Part 4 v185
 *  publication). The derived seed is fed into FIPS 203 deterministic
 *  keygen (ML-KEM.KeyGen_internal). */
TPM_RC FwDeriveMlkemPrimaryKeySeed(TPMI_ALG_HASH nameAlg,
    const byte* seed, const byte* hashUnique, int hashUniqueSz,
    byte* seedDZOut)
{
    int kdfRet;

    kdfRet = TPM2_KDFa_ex(nameAlg, seed, FWTPM_SEED_SIZE,
        "MLKEM", hashUnique, (UINT32)hashUniqueSz,
        NULL, 0, seedDZOut, MAX_MLKEM_PRIV_SEED_SIZE);
    if (kdfRet != MAX_MLKEM_PRIV_SEED_SIZE) {
        return TPM_RC_FAILURE;
    }
    return TPM_RC_SUCCESS;
}

/** \brief Generate ML-DSA keypair deterministically from a 32-byte seed xi
 *  (FIPS 204 Algorithm 1 ML-DSA.KeyGen). Exports public key to pubOut.
 *  The expanded private key is not returned — callers hold the 32-byte seed
 *  in TPM2B_PRIVATE_KEY_MLDSA and re-expand on every use per TCG Table 210. */
TPM_RC FwGenerateMldsaKey(TPMI_MLDSA_PARAMETER_SET parameterSet,
    const byte* seedXi,
    TPM2B_PUBLIC_KEY_MLDSA* pubOut)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    FWTPM_DECLARE_VAR(dilithiumKey, dilithium_key);
    int level;
    word32 outSz;
    int wcRet;
    int keyInit = 0;

    FWTPM_ALLOC_VAR(dilithiumKey, dilithium_key);

    level = FwGetWcMldsaLevel(parameterSet);
    if (level < 0) {
        rc = TPM_RC_PARMS;
    }

    if (rc == 0) {
        wcRet = wc_dilithium_init(dilithiumKey);
        if (wcRet != 0) {
            rc = TPM_RC_FAILURE;
        }
    }
    if (rc == 0) {
        keyInit = 1;
        wcRet = wc_dilithium_set_level(dilithiumKey, (byte)level);
        if (wcRet != 0) {
            rc = TPM_RC_FAILURE;
        }
    }
    if (rc == 0) {
        wcRet = wc_dilithium_make_key_from_seed(dilithiumKey, seedXi);
        if (wcRet != 0) {
            rc = TPM_RC_FAILURE;
        }
    }
    if (rc == 0) {
        outSz = (word32)sizeof(pubOut->buffer);
        wcRet = wc_dilithium_export_public(dilithiumKey, pubOut->buffer, &outSz);
        if (wcRet != 0) {
            rc = TPM_RC_FAILURE;
        }
        else {
            pubOut->size = (UINT16)outSz;
        }
    }

    if (keyInit) {
        wc_dilithium_free(dilithiumKey);
    }
    FWTPM_FREE_VAR(dilithiumKey);
    return rc;
}

/** \brief Generate ML-KEM keypair deterministically from a 64-byte seed (d||z)
 *  (FIPS 203 Algorithm 16 ML-KEM.KeyGen_internal). Exports public key to
 *  pubOut. Private key on the wire is the 64-byte seed per TCG Table 206. */
TPM_RC FwGenerateMlkemKey(TPMI_MLKEM_PARAMETER_SET parameterSet,
    const byte* seedDZ,
    TPM2B_PUBLIC_KEY_MLKEM* pubOut)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    FWTPM_DECLARE_VAR(mlkemKey, MlKemKey);
    int type;
    word32 outSz = 0;
    int wcRet;
    int keyInit = 0;

    FWTPM_ALLOC_VAR(mlkemKey, MlKemKey);

    type = FwGetWcMlkemType(parameterSet);
    if (type < 0) {
        rc = TPM_RC_PARMS;
    }

    if (rc == 0) {
        wcRet = wc_MlKemKey_Init(mlkemKey, type, NULL, INVALID_DEVID);
        if (wcRet != 0) {
            rc = TPM_RC_FAILURE;
        }
    }
    if (rc == 0) {
        keyInit = 1;
        wcRet = wc_MlKemKey_MakeKeyWithRandom(mlkemKey, seedDZ,
            MAX_MLKEM_PRIV_SEED_SIZE);
        if (wcRet != 0) {
            rc = TPM_RC_FAILURE;
        }
    }
    if (rc == 0) {
        wcRet = wc_MlKemKey_PublicKeySize(mlkemKey, &outSz);
        if (wcRet != 0) {
            rc = TPM_RC_FAILURE;
        }
    }
    if (rc == 0) {
        if (outSz > sizeof(pubOut->buffer)) {
            rc = TPM_RC_SIZE;
        }
        else {
            wcRet = wc_MlKemKey_EncodePublicKey(mlkemKey, pubOut->buffer, outSz);
            if (wcRet != 0) {
                rc = TPM_RC_FAILURE;
            }
            else {
                pubOut->size = (UINT16)outSz;
            }
        }
    }

    if (keyInit) {
        wc_MlKemKey_Free(mlkemKey);
    }
    FWTPM_FREE_VAR(mlkemKey);
    return rc;
}

/** \brief Perform ML-KEM encapsulation with a loaded public key.
 *  Decodes the TPM's public-key bytes into an MlKemKey, runs FIPS 203
 *  Encapsulate using the context RNG, and returns the 32-byte shared secret
 *  plus the variable-length ciphertext. */
TPM_RC FwEncapsulateMlkem(WC_RNG* rng,
    TPMI_MLKEM_PARAMETER_SET parameterSet,
    const TPM2B_PUBLIC_KEY_MLKEM* pubIn,
    TPM2B_SHARED_SECRET* sharedSecretOut,
    TPM2B_KEM_CIPHERTEXT* ciphertextOut)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    FWTPM_DECLARE_VAR(mlkemKey, MlKemKey);
    int type;
    word32 ctSz = 0, ssSz = 0;
    int wcRet;
    int keyInit = 0;

    FWTPM_ALLOC_VAR(mlkemKey, MlKemKey);

    type = FwGetWcMlkemType(parameterSet);
    if (type < 0) {
        rc = TPM_RC_PARMS;
    }

    if (rc == 0) {
        wcRet = wc_MlKemKey_Init(mlkemKey, type, NULL, INVALID_DEVID);
        if (wcRet != 0) {
            rc = TPM_RC_FAILURE;
        }
    }
    if (rc == 0) {
        keyInit = 1;
        wcRet = wc_MlKemKey_DecodePublicKey(mlkemKey,
            pubIn->buffer, pubIn->size);
        if (wcRet != 0) {
            rc = TPM_RC_KEY;
        }
    }
    if (rc == 0) {
        wcRet = wc_MlKemKey_CipherTextSize(mlkemKey, &ctSz);
        if (wcRet == 0) {
            wcRet = wc_MlKemKey_SharedSecretSize(mlkemKey, &ssSz);
        }
        if (wcRet != 0) {
            rc = TPM_RC_FAILURE;
        }
    }
    if (rc == 0) {
        if (ctSz > sizeof(ciphertextOut->buffer) ||
                ssSz > sizeof(sharedSecretOut->buffer)) {
            rc = TPM_RC_SIZE;
        }
    }
    if (rc == 0) {
        wcRet = wc_MlKemKey_Encapsulate(mlkemKey,
            ciphertextOut->buffer, sharedSecretOut->buffer, rng);
        if (wcRet != 0) {
            rc = TPM_RC_FAILURE;
        }
        else {
            ciphertextOut->size = (UINT16)ctSz;
            sharedSecretOut->size = (UINT16)ssSz;
        }
    }

    if (keyInit) {
        wc_MlKemKey_Free(mlkemKey);
    }
    FWTPM_FREE_VAR(mlkemKey);
    return rc;
}

/** \brief Perform ML-KEM decapsulation given the stored 64-byte seed and
 *  an incoming ciphertext. Regenerates the keypair from the seed (no
 *  expanded private key is persisted), then runs FIPS 203 Decapsulate.
 *  Returns the 32-byte shared secret. */
TPM_RC FwDecapsulateMlkem(TPMI_MLKEM_PARAMETER_SET parameterSet,
    const byte* seedDZ,
    const byte* ctBuf, UINT16 ctSize,
    TPM2B_SHARED_SECRET* sharedSecretOut)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    FWTPM_DECLARE_VAR(mlkemKey, MlKemKey);
    int type;
    word32 expectedCtSz = 0, ssSz = 0;
    int wcRet;
    int keyInit = 0;

    FWTPM_ALLOC_VAR(mlkemKey, MlKemKey);

    type = FwGetWcMlkemType(parameterSet);
    if (type < 0) {
        rc = TPM_RC_PARMS;
    }

    if (rc == 0) {
        wcRet = wc_MlKemKey_Init(mlkemKey, type, NULL, INVALID_DEVID);
        if (wcRet != 0) {
            rc = TPM_RC_FAILURE;
        }
    }
    if (rc == 0) {
        keyInit = 1;
        /* Regenerate full keypair deterministically from stored seed. */
        wcRet = wc_MlKemKey_MakeKeyWithRandom(mlkemKey, seedDZ,
            MAX_MLKEM_PRIV_SEED_SIZE);
        if (wcRet != 0) {
            rc = TPM_RC_FAILURE;
        }
    }
    if (rc == 0) {
        wcRet = wc_MlKemKey_CipherTextSize(mlkemKey, &expectedCtSz);
        if (wcRet == 0) {
            wcRet = wc_MlKemKey_SharedSecretSize(mlkemKey, &ssSz);
        }
        if (wcRet != 0) {
            rc = TPM_RC_FAILURE;
        }
    }
    if (rc == 0 && ctSize != (UINT16)expectedCtSz) {
        rc = TPM_RC_SIZE;
    }
    if (rc == 0 && ssSz > sizeof(sharedSecretOut->buffer)) {
        rc = TPM_RC_SIZE;
    }
    if (rc == 0) {
        wcRet = wc_MlKemKey_Decapsulate(mlkemKey,
            sharedSecretOut->buffer, ctBuf, ctSize);
        if (wcRet != 0) {
            rc = TPM_RC_FAILURE;
        }
        else {
            sharedSecretOut->size = (UINT16)ssSz;
        }
    }

    if (keyInit) {
        wc_MlKemKey_Free(mlkemKey);
    }
    FWTPM_FREE_VAR(mlkemKey);
    return rc;
}

#ifdef HAVE_ECC
/* RFC 9180 Sec.7 kem_id mapping for the curve+hash pairings the TPM accepts.
 * Returns 0 on a supported pairing; -1 otherwise (caller maps to TPM_RC_KDF). */
static int FwDhkemParamsLookup(int wcCurve, TPMI_ALG_HASH kdfHash,
    UINT16* kemIdOut, int* nSecretOut, int* nPkOut,
    enum wc_HashType* hkdfHashOut)
{
    if (wcCurve == ECC_SECP256R1 && kdfHash == TPM_ALG_SHA256) {
        *kemIdOut = 0x0010; *nSecretOut = 32; *nPkOut = 65;
        *hkdfHashOut = WC_HASH_TYPE_SHA256;
        return 0;
    }
    if (wcCurve == ECC_SECP384R1 && kdfHash == TPM_ALG_SHA384) {
        *kemIdOut = 0x0011; *nSecretOut = 48; *nPkOut = 97;
        *hkdfHashOut = WC_HASH_TYPE_SHA384;
        return 0;
    }
#ifdef HAVE_ECC521
    if (wcCurve == ECC_SECP521R1 && kdfHash == TPM_ALG_SHA512) {
        *kemIdOut = 0x0012; *nSecretOut = 64; *nPkOut = 133;
        *hkdfHashOut = WC_HASH_TYPE_SHA512;
        return 0;
    }
#endif
    return -1;
}

/* RFC 9180 Sec.4 LabeledExtract: prk = HKDF-Extract(salt,
 *     "HPKE-v1" || "KEM" || I2OSP(kem_id,2) || label || ikm).
 * Caller-supplied scratch buffer keeps stack usage bounded. */
static TPM_RC FwDhkemLabeledExtract(enum wc_HashType hashType, UINT16 kemId,
    const byte* salt, word32 saltSz,
    const char* label, const byte* ikm, word32 ikmSz,
    byte* scratch, word32 scratchSz, byte* prkOut)
{
    word32 pos = 0;
    word32 labelLen = (word32)XSTRLEN(label);

    if (7 + 3 + 2 + labelLen + ikmSz > scratchSz)
        return TPM_RC_FAILURE;
    XMEMCPY(scratch + pos, "HPKE-v1", 7); pos += 7;
    XMEMCPY(scratch + pos, "KEM", 3); pos += 3;
    scratch[pos++] = (byte)((kemId >> 8) & 0xFF);
    scratch[pos++] = (byte)(kemId & 0xFF);
    if (labelLen > 0) {
        XMEMCPY(scratch + pos, label, labelLen); pos += labelLen;
    }
    if (ikmSz > 0) {
        XMEMCPY(scratch + pos, ikm, ikmSz); pos += ikmSz;
    }
    if (wc_HKDF_Extract((int)hashType, salt, saltSz, scratch, pos, prkOut) != 0)
        return TPM_RC_FAILURE;
    return TPM_RC_SUCCESS;
}

/* RFC 9180 Sec.4 LabeledExpand: out = HKDF-Expand(prk,
 *     I2OSP(L,2) || "HPKE-v1" || "KEM" || I2OSP(kem_id,2) || label || info, L). */
static TPM_RC FwDhkemLabeledExpand(enum wc_HashType hashType, UINT16 kemId,
    const byte* prk, word32 prkSz,
    const char* label, const byte* info, word32 infoSz,
    byte* scratch, word32 scratchSz, byte* out, word32 L)
{
    word32 pos = 0;
    word32 labelLen = (word32)XSTRLEN(label);

    if (2 + 7 + 3 + 2 + labelLen + infoSz > scratchSz)
        return TPM_RC_FAILURE;
    scratch[pos++] = (byte)((L >> 8) & 0xFF);
    scratch[pos++] = (byte)(L & 0xFF);
    XMEMCPY(scratch + pos, "HPKE-v1", 7); pos += 7;
    XMEMCPY(scratch + pos, "KEM", 3); pos += 3;
    scratch[pos++] = (byte)((kemId >> 8) & 0xFF);
    scratch[pos++] = (byte)(kemId & 0xFF);
    if (labelLen > 0) {
        XMEMCPY(scratch + pos, label, labelLen); pos += labelLen;
    }
    if (infoSz > 0) {
        XMEMCPY(scratch + pos, info, infoSz); pos += infoSz;
    }
    if (wc_HKDF_Expand((int)hashType, prk, prkSz, scratch, pos, out, L) != 0)
        return TPM_RC_FAILURE;
    return TPM_RC_SUCCESS;
}

/* RFC 9180 Sec.4.1.4 ExtractAndExpand. Output: shared_secret of Nsecret bytes. */
static TPM_RC FwDhkemExtractAndExpand(enum wc_HashType hashType, UINT16 kemId,
    const byte* dh, word32 dhSz,
    const byte* kemContext, word32 kemContextSz,
    byte* sharedSecret, word32 nSecret)
{
    TPM_RC rc;
    byte prk[WC_MAX_DIGEST_SIZE];
    byte scratch[512]; /* max labeled blob: I2OSP(2)+HPKE-v1(7)+KEM(3)+id(2)
                        * +label(13)+info(2*Npk=266) ~= 293 */
    int prkSz = wc_HashGetDigestSize(hashType);

    if (prkSz <= 0 || prkSz > (int)sizeof(prk))
        return TPM_RC_FAILURE;
    rc = FwDhkemLabeledExtract(hashType, kemId, NULL, 0,
        "eae_prk", dh, dhSz, scratch, sizeof(scratch), prk);
    if (rc == 0) {
        rc = FwDhkemLabeledExpand(hashType, kemId, prk, (word32)prkSz,
            "shared_secret", kemContext, kemContextSz,
            scratch, sizeof(scratch), sharedSecret, nSecret);
    }
    TPM2_ForceZero(prk, sizeof(prk));
    return rc;
}

TPM_RC FwEncapsulateEcdhDhkem(WC_RNG* rng,
    const TPMT_PUBLIC* recipPub, TPMI_ALG_HASH kdfHash,
    TPM2B_SHARED_SECRET* sharedSecretOut,
    TPM2B_KEM_CIPHERTEXT* ciphertextOut)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    int wcCurve;
    UINT16 kemId = 0;
    int nSecret = 0, nPk = 0;
    enum wc_HashType hashType = WC_HASH_TYPE_NONE;
    int recipInit = 0, ephInit = 0;
    byte enc[133]; /* RFC 9180 Sec.7: Npk_max = 133 (P-521 uncompressed) */
    byte pkRm[133];
    byte dh[66];
    byte kemContext[266];
    word32 encSz = sizeof(enc), pkRmSz = sizeof(pkRm), dhSz = sizeof(dh);
    FWTPM_DECLARE_VAR(recipKey, ecc_key);
    FWTPM_DECLARE_VAR(ephKey, ecc_key);

    FWTPM_CALLOC_VAR(recipKey, ecc_key);
    FWTPM_CALLOC_VAR(ephKey, ecc_key);

    wcCurve = FwGetWcCurveId(recipPub->parameters.eccDetail.curveID);
    if (wcCurve < 0) {
        rc = TPM_RC_CURVE;
    }
    if (rc == 0 && FwDhkemParamsLookup(wcCurve, kdfHash,
            &kemId, &nSecret, &nPk, &hashType) != 0) {
        rc = TPM_RC_KDF;
    }

    if (rc == 0) {
        rc = FwImportEccPubFromPublic(recipPub, recipKey);
        if (rc == 0) recipInit = 1;
        else rc = TPM_RC_KEY;
    }
    if (rc == 0) {
        if (wc_ecc_init(ephKey) != 0) rc = TPM_RC_FAILURE;
        else {
            ephInit = 1;
            wc_ecc_set_rng(ephKey, rng);
            if (wc_ecc_make_key_ex(rng,
                    wc_ecc_get_curve_size_from_id(wcCurve),
                    ephKey, wcCurve) != 0) {
                rc = TPM_RC_FAILURE;
            }
        }
    }
    if (rc == 0) {
        if (wc_ecc_shared_secret(ephKey, recipKey, dh, &dhSz) != 0)
            rc = TPM_RC_FAILURE;
    }
    if (rc == 0) {
        if (wc_ecc_export_x963(ephKey, enc, &encSz) != 0) rc = TPM_RC_FAILURE;
    }
    if (rc == 0) {
        if (wc_ecc_export_x963(recipKey, pkRm, &pkRmSz) != 0) rc = TPM_RC_FAILURE;
    }
    if (rc == 0 && encSz + pkRmSz > sizeof(kemContext)) {
        rc = TPM_RC_FAILURE;
    }
    if (rc == 0) {
        XMEMCPY(kemContext, enc, encSz);
        XMEMCPY(kemContext + encSz, pkRm, pkRmSz);
    }
    if (rc == 0 && ((word32)nSecret > sizeof(sharedSecretOut->buffer) ||
                    encSz > sizeof(ciphertextOut->buffer))) {
        rc = TPM_RC_FAILURE;
    }
    if (rc == 0) {
        rc = FwDhkemExtractAndExpand(hashType, kemId, dh, dhSz,
            kemContext, encSz + pkRmSz,
            sharedSecretOut->buffer, (word32)nSecret);
    }
    if (rc == 0) {
        sharedSecretOut->size = (UINT16)nSecret;
        XMEMCPY(ciphertextOut->buffer, enc, encSz);
        ciphertextOut->size = (UINT16)encSz;
    }

    if (recipInit) wc_ecc_free(recipKey);
    if (ephInit) wc_ecc_free(ephKey);
    TPM2_ForceZero(dh, sizeof(dh));
    FWTPM_FREE_VAR(recipKey);
    FWTPM_FREE_VAR(ephKey);
    (void)nPk;
    return rc;
}

TPM_RC FwDecapsulateEcdhDhkem(WC_RNG* rng, const FWTPM_Object* recipObj,
    TPMI_ALG_HASH kdfHash,
    const byte* ctBuf, UINT16 ctSize,
    TPM2B_SHARED_SECRET* sharedSecretOut)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    int wcCurve;
    UINT16 kemId = 0;
    int nSecret = 0, nPk = 0;
    enum wc_HashType hashType = WC_HASH_TYPE_NONE;
    int recipInit = 0, ephInit = 0;
    byte pkRm[133];
    byte dh[66];
    byte kemContext[266];
    word32 pkRmSz = sizeof(pkRm), dhSz = sizeof(dh);
    FWTPM_DECLARE_VAR(recipKey, ecc_key);
    FWTPM_DECLARE_VAR(ephKey, ecc_key);

    FWTPM_CALLOC_VAR(recipKey, ecc_key);
    FWTPM_CALLOC_VAR(ephKey, ecc_key);

    wcCurve = FwGetWcCurveId(recipObj->pub.parameters.eccDetail.curveID);
    if (wcCurve < 0) {
        rc = TPM_RC_CURVE;
    }
    if (rc == 0 && FwDhkemParamsLookup(wcCurve, kdfHash,
            &kemId, &nSecret, &nPk, &hashType) != 0) {
        rc = TPM_RC_KDF;
    }

    if (rc == 0) {
        rc = FwImportEccKey(recipObj, recipKey);
        if (rc == 0) {
            recipInit = 1;
            wc_ecc_set_rng(recipKey, rng);
        }
        else rc = TPM_RC_KEY;
    }
    if (rc == 0) {
        if (wc_ecc_init(ephKey) != 0) rc = TPM_RC_FAILURE;
        else ephInit = 1;
    }
    if (rc == 0) {
        /* Wire ciphertext = SerializePublicKey(pkE) per RFC 9180 Sec.4.1.4
         * (uncompressed SEC1: 0x04 || x || y, length Npk). */
        if (ctSize != (UINT16)nPk || ctBuf[0] != 0x04) {
            rc = TPM_RC_VALUE;
        }
        else if (wc_ecc_import_x963_ex(ctBuf, ctSize, ephKey, wcCurve) != 0) {
            rc = TPM_RC_VALUE;
        }
    }
    if (rc == 0) {
        if (wc_ecc_shared_secret(recipKey, ephKey, dh, &dhSz) != 0)
            rc = TPM_RC_FAILURE;
    }
    if (rc == 0) {
        if (wc_ecc_export_x963(recipKey, pkRm, &pkRmSz) != 0)
            rc = TPM_RC_FAILURE;
    }
    if (rc == 0 && (word32)ctSize + pkRmSz > sizeof(kemContext)) {
        rc = TPM_RC_FAILURE;
    }
    if (rc == 0) {
        XMEMCPY(kemContext, ctBuf, ctSize);
        XMEMCPY(kemContext + ctSize, pkRm, pkRmSz);
    }
    if (rc == 0 && (word32)nSecret > sizeof(sharedSecretOut->buffer)) {
        rc = TPM_RC_FAILURE;
    }
    if (rc == 0) {
        rc = FwDhkemExtractAndExpand(hashType, kemId, dh, dhSz,
            kemContext, (word32)ctSize + pkRmSz,
            sharedSecretOut->buffer, (word32)nSecret);
    }
    if (rc == 0) {
        sharedSecretOut->size = (UINT16)nSecret;
    }

    if (recipInit) wc_ecc_free(recipKey);
    if (ephInit) wc_ecc_free(ephKey);
    TPM2_ForceZero(dh, sizeof(dh));
    FWTPM_FREE_VAR(recipKey);
    FWTPM_FREE_VAR(ephKey);
    return rc;
}
#endif /* HAVE_ECC */

/* Internal helper: rebuild a deterministic ML-DSA keypair from its stored
 * 32-byte xi seed and return a ready-to-use dilithium_key plus wcLevel. */
static TPM_RC FwLoadMldsaFromSeed(TPMI_MLDSA_PARAMETER_SET parameterSet,
    const byte* seedXi, dilithium_key* keyOut, int* keyInitOut)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    int level;
    int wcRet;

    *keyInitOut = 0;

    level = FwGetWcMldsaLevel(parameterSet);
    if (level < 0) {
        return TPM_RC_PARMS;
    }

    wcRet = wc_dilithium_init(keyOut);
    if (wcRet != 0) {
        return TPM_RC_FAILURE;
    }
    *keyInitOut = 1;

    wcRet = wc_dilithium_set_level(keyOut, (byte)level);
    if (wcRet != 0) {
        rc = TPM_RC_FAILURE;
    }
    if (rc == 0) {
        wcRet = wc_dilithium_make_key_from_seed(keyOut, seedXi);
        if (wcRet != 0) {
            rc = TPM_RC_FAILURE;
        }
    }
    return rc;
}

/** \brief Pure ML-DSA sign: full-message signing per FIPS 204 ML-DSA.Sign.
 *  Takes the stored 32-byte xi seed and the raw message. The TPM computes
 *  mu internally. */
TPM_RC FwSignMldsaMessage(WC_RNG* rng,
    TPMI_MLDSA_PARAMETER_SET parameterSet,
    const byte* seedXi,
    const byte* context, int contextSz,
    const byte* msg, int msgSz,
    TPM2B_MLDSA_SIGNATURE* sigOut)
{
    TPM_RC rc;
    FWTPM_DECLARE_VAR(keyVar, dilithium_key);
    int keyInit = 0;
    word32 sigSz;
    int wcRet;

    /* wc_dilithium_*_ctx_* take contextSz as a byte; guard the cast. */
    if (contextSz < 0 || contextSz > 255) {
        return TPM_RC_VALUE;
    }

    FWTPM_ALLOC_VAR(keyVar, dilithium_key);

    rc = FwLoadMldsaFromSeed(parameterSet, seedXi, keyVar, &keyInit);

    if (rc == 0) {
        sigSz = (word32)sizeof(sigOut->buffer);
        /* FIPS 204 Algorithm 2 hedged sign: wolfCrypt requires a non-NULL
         * RNG to source the 32-byte `rnd` value. Passing the TPM's internal
         * RNG matches normal TPM signing practice (side-channel hedging). */
        wcRet = wc_dilithium_sign_ctx_msg(
            context, (byte)contextSz,
            msg, (word32)msgSz,
            sigOut->buffer, &sigSz,
            keyVar, rng);
        if (wcRet != 0) {
            rc = TPM_RC_FAILURE;
        }
        else {
            sigOut->size = (UINT16)sigSz;
        }
    }

    if (keyInit) {
        wc_dilithium_free(keyVar);
    }
    FWTPM_FREE_VAR(keyVar);
    return rc;
}

/** \brief Pure ML-DSA verify: checks a signature over the raw message. */
TPM_RC FwVerifyMldsaMessage(TPMI_MLDSA_PARAMETER_SET parameterSet,
    const TPM2B_PUBLIC_KEY_MLDSA* pubIn,
    const byte* context, int contextSz,
    const byte* msg, int msgSz,
    const byte* sig, int sigSz)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    FWTPM_DECLARE_VAR(keyVar, dilithium_key);
    int level;
    int keyInit = 0;
    int verifyRes = 0;
    int wcRet;

    if (contextSz < 0 || contextSz > 255) {
        return TPM_RC_VALUE;
    }

    FWTPM_ALLOC_VAR(keyVar, dilithium_key);

    level = FwGetWcMldsaLevel(parameterSet);
    if (level < 0) {
        rc = TPM_RC_PARMS;
    }
    if (rc == 0) {
        wcRet = wc_dilithium_init(keyVar);
        if (wcRet != 0) {
            rc = TPM_RC_FAILURE;
        }
    }
    if (rc == 0) {
        keyInit = 1;
        wcRet = wc_dilithium_set_level(keyVar, (byte)level);
        if (wcRet != 0) {
            rc = TPM_RC_FAILURE;
        }
    }
    if (rc == 0) {
        wcRet = wc_dilithium_import_public(pubIn->buffer, pubIn->size, keyVar);
        if (wcRet != 0) {
            rc = TPM_RC_KEY;
        }
    }
    if (rc == 0) {
        wcRet = wc_dilithium_verify_ctx_msg(
            sig, (word32)sigSz,
            context, (byte)contextSz,
            msg, (word32)msgSz,
            &verifyRes, keyVar);
        if (wcRet != 0 || verifyRes != 1) {
            rc = TPM_RC_SIGNATURE;
        }
    }

    if (keyInit) {
        wc_dilithium_free(keyVar);
    }
    FWTPM_FREE_VAR(keyVar);
    return rc;
}

/** \brief Hash-ML-DSA sign: pre-hashed variant per FIPS 204 Algorithm 4. */
TPM_RC FwSignMldsaHash(WC_RNG* rng,
    TPMI_MLDSA_PARAMETER_SET parameterSet,
    const byte* seedXi,
    const byte* context, int contextSz,
    TPMI_ALG_HASH hashAlg,
    const byte* digest, int digestSz,
    TPM2B_MLDSA_SIGNATURE* sigOut)
{
    TPM_RC rc;
    FWTPM_DECLARE_VAR(keyVar, dilithium_key);
    int keyInit = 0;
    word32 sigSz;
    int wcHash;
    int wcRet;

    if (contextSz < 0 || contextSz > 255) {
        return TPM_RC_VALUE;
    }

    FWTPM_ALLOC_VAR(keyVar, dilithium_key);

    wcHash = FwGetWcHashType(hashAlg);
    if (wcHash == WC_HASH_TYPE_NONE) {
        rc = TPM_RC_HASH;
    }
    else {
        rc = FwLoadMldsaFromSeed(parameterSet, seedXi, keyVar, &keyInit);
    }

    if (rc == 0) {
        sigSz = (word32)sizeof(sigOut->buffer);
        /* Hedged sign (FIPS 204 Alg 2 step 7) — wolfCrypt requires RNG. */
        wcRet = wc_dilithium_sign_ctx_hash(
            context, (byte)contextSz,
            wcHash, digest, (word32)digestSz,
            sigOut->buffer, &sigSz,
            keyVar, rng);
        if (wcRet != 0) {
            rc = TPM_RC_FAILURE;
        }
        else {
            sigOut->size = (UINT16)sigSz;
        }
    }

    if (keyInit) {
        wc_dilithium_free(keyVar);
    }
    FWTPM_FREE_VAR(keyVar);
    return rc;
}

/** \brief Hash-ML-DSA verify: verifies a signature over a pre-hashed digest. */
TPM_RC FwVerifyMldsaHash(TPMI_MLDSA_PARAMETER_SET parameterSet,
    const TPM2B_PUBLIC_KEY_MLDSA* pubIn,
    const byte* context, int contextSz,
    TPMI_ALG_HASH hashAlg,
    const byte* digest, int digestSz,
    const byte* sig, int sigSz)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    FWTPM_DECLARE_VAR(keyVar, dilithium_key);
    int level;
    int keyInit = 0;
    int verifyRes = 0;
    int wcHash;
    int wcRet;

    if (contextSz < 0 || contextSz > 255) {
        return TPM_RC_VALUE;
    }

    FWTPM_ALLOC_VAR(keyVar, dilithium_key);

    wcHash = FwGetWcHashType(hashAlg);
    if (wcHash == WC_HASH_TYPE_NONE) {
        rc = TPM_RC_HASH;
    }

    level = FwGetWcMldsaLevel(parameterSet);
    if (rc == 0 && level < 0) {
        rc = TPM_RC_PARMS;
    }

    if (rc == 0) {
        wcRet = wc_dilithium_init(keyVar);
        if (wcRet != 0) {
            rc = TPM_RC_FAILURE;
        }
    }
    if (rc == 0) {
        keyInit = 1;
        wcRet = wc_dilithium_set_level(keyVar, (byte)level);
        if (wcRet != 0) {
            rc = TPM_RC_FAILURE;
        }
    }
    if (rc == 0) {
        wcRet = wc_dilithium_import_public(pubIn->buffer, pubIn->size, keyVar);
        if (wcRet != 0) {
            rc = TPM_RC_KEY;
        }
    }
    if (rc == 0) {
        wcRet = wc_dilithium_verify_ctx_hash(
            sig, (word32)sigSz,
            context, (byte)contextSz,
            wcHash, digest, (word32)digestSz,
            &verifyRes, keyVar);
        if (wcRet != 0 || verifyRes != 1) {
            rc = TPM_RC_SIGNATURE;
        }
    }

    if (keyInit) {
        wc_dilithium_free(keyVar);
    }
    FWTPM_FREE_VAR(keyVar);
    return rc;
}
#endif /* WOLFTPM_V185 */

#ifndef NO_RSA
#ifdef WOLFSSL_KEY_GEN
/* Derive a single RSA prime from hierarchy seed via iterative KDFa.
 * Per TPM 2.0 Part 1 Section 26.2:
 *   candidate = KDFa(nameAlg, seed, label, hashUnique, counter, fieldBits)
 *   Set top 2 bits and bottom bit, test for primality.
 * Returns 0 on success, stores prime in outPrime. */
static TPM_RC FwDerivePrime(TPMI_ALG_HASH nameAlg,
    const byte* seed, const byte* hashUnique, int hashUniqueSz,
    const char* label, WC_RNG* rng,
    mp_int* outPrime, int fieldBytes)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    byte primeBuf[256]; /* max RSA-4096 half = 256 bytes */
    byte counterBuf[4];
    UINT32 counter = 1;
    int isPrime = 0;
    int kdfRet;

    if (fieldBytes <= 0 || fieldBytes > (int)sizeof(primeBuf)) {
        return TPM_RC_KEY_SIZE;
    }

    while (!isPrime && counter < 10000) {
        FwStoreU32BE(counterBuf, counter);
        kdfRet = TPM2_KDFa_ex(nameAlg, seed, FWTPM_SEED_SIZE,
            label, hashUnique, (UINT32)hashUniqueSz,
            counterBuf, sizeof(counterBuf),
            primeBuf, (UINT32)fieldBytes);
        if (kdfRet != fieldBytes) {
            rc = TPM_RC_FAILURE;
            break;
        }

        /* Set top 2 bits (ensure correct bit length) and bottom bit (odd) */
        primeBuf[0] |= 0xC0;
        primeBuf[fieldBytes - 1] |= 0x01;

        rc = mp_read_unsigned_bin(outPrime, primeBuf, (word32)fieldBytes);
        if (rc != 0) {
            rc = TPM_RC_FAILURE;
            break;
        }

        /* FIPS 186-4 Table C.3: 28 rounds for RSA-2048 */
        rc = mp_prime_is_prime_ex(outPrime, 28, &isPrime, rng);
        if (rc != 0) {
            rc = TPM_RC_FAILURE;
            break;
        }
        counter++;
    }

    TPM2_ForceZero(primeBuf, sizeof(primeBuf));

    if (rc == 0 && !isPrime) {
        rc = TPM_RC_NO_RESULT;
    }
    return rc;
}

/* Derive RSA primary key from hierarchy seed per TPM 2.0 Part 1 Section 26.2.
 * Uses KDFa to derive prime candidates p, q, then constructs the RSA key. */
TPM_RC FwDeriveRsaPrimaryKey(TPMI_ALG_HASH nameAlg,
    const byte* seed, const byte* hashUnique, int hashUniqueSz,
    int keyBits, UINT32 exponent, WC_RNG* rng,
    TPM2B_PUBLIC_KEY_RSA* pubOut,
    byte* privKeyDer, int privKeyDerBufSz, int* privKeyDerSz)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    FWTPM_DECLARE_VAR(rsaKey, RsaKey);
    int rsaInit = 0;
    int fieldBytes;
    word32 modSz, eSz;
    byte eBuf[8];

    FWTPM_ALLOC_VAR(rsaKey, RsaKey);

    if (keyBits == 0) {
        keyBits = 2048;
    }
    if (exponent == 0) {
        exponent = WC_RSA_EXPONENT;
    }
    fieldBytes = keyBits / 16; /* half key in bytes */

    rc = wc_InitRsaKey(rsaKey, NULL);
    if (rc == 0) {
        rsaInit = 1;
    }

    /* Set public exponent */
    if (rc == 0) {
        rc = mp_set_int(&rsaKey->e, (unsigned long)exponent);
        if (rc != 0) {
            rc = TPM_RC_FAILURE;
        }
    }

    /* Derive p */
    if (rc == 0) {
        rc = FwDerivePrime(nameAlg, seed, hashUnique, hashUniqueSz,
            "RSA p", rng, &rsaKey->p, fieldBytes);
    }

    /* Derive q */
    if (rc == 0) {
        rc = FwDerivePrime(nameAlg, seed, hashUnique, hashUniqueSz,
            "RSA q", rng, &rsaKey->q, fieldBytes);
    }

    /* Verify p != q */
    if (rc == 0) {
        if (mp_cmp(&rsaKey->p, &rsaKey->q) == MP_EQ) {
            rc = TPM_RC_NO_RESULT;
        }
    }

    /* Compute n = p * q */
    if (rc == 0) {
        rc = mp_mul(&rsaKey->p, &rsaKey->q, &rsaKey->n);
        if (rc != 0) {
            rc = TPM_RC_FAILURE;
        }
    }

    /* Compute CRT values: d, dP, dQ, u */
    if (rc == 0) {
        rc = FwRsaComputeCRT(rsaKey);
    }

    /* Mark as private key */
    if (rc == 0) {
        rsaKey->type = RSA_PRIVATE;
    }

    /* Export public modulus */
    if (rc == 0) {
        modSz = (word32)(keyBits / 8);
        if (modSz > sizeof(pubOut->buffer)) {
            modSz = sizeof(pubOut->buffer);
        }
        eSz = (word32)sizeof(eBuf);
        rc = wc_RsaFlattenPublicKey(rsaKey, eBuf, &eSz,
            pubOut->buffer, &modSz);
    }
    if (rc == 0) {
        pubOut->size = (UINT16)modSz;
    }

    /* Export private key to DER */
    if (rc == 0) {
        *privKeyDerSz = wc_RsaKeyToDer(rsaKey, privKeyDer, privKeyDerBufSz);
        if (*privKeyDerSz < 0) {
            rc = TPM_RC_FAILURE;
        }
    }

    if (rsaInit) {
        wc_FreeRsaKey(rsaKey);
    }
    FWTPM_FREE_VAR(rsaKey);
    if (rc != 0 && rc != TPM_RC_KEY_SIZE && rc != TPM_RC_NO_RESULT) {
        rc = TPM_RC_FAILURE;
    }
    return rc;
}
#endif /* WOLFSSL_KEY_GEN */
#endif /* !NO_RSA */

/* ================================================================== */
/* Private key wrapping/unwrapping for Create/Load                     */
/* ================================================================== */

/* Derive a 32-byte AES key and 16-byte IV from parent's private key.
 * Used to wrap child key sensitive data in TPM2B_PRIVATE. */
int FwDeriveWrapKey(const FWTPM_Object* parent,
    byte* aesKey, byte* aesIV)
{
    int rc;
    byte keyMaterial[WC_SHA256_DIGEST_SIZE];
    byte ivMaterial[WC_SHA256_DIGEST_SIZE];
    FWTPM_DECLARE_VAR(hmac, Hmac);

    FWTPM_ALLOC_VAR(hmac, Hmac);

    rc = wc_HmacInit(hmac, NULL, INVALID_DEVID);

    /* AES key = HMAC-SHA256(parentPriv, "fwTPM-wrap-key")
     * Use full parent private key as HMAC key — HMAC handles arbitrary-length
     * keys via internal hashing. The previous 32-byte truncation used
     * predictable ASN.1 DER header bytes for RSA keys. */
    if (rc == 0) {
        rc = wc_HmacSetKey(hmac, WC_SHA256, parent->privKey,
            parent->privKeySize);
    }
    if (rc == 0) {
        rc = wc_HmacUpdate(hmac, (const byte*)"fwTPM-wrap-key", 14);
    }
    if (rc == 0) {
        rc = wc_HmacFinal(hmac, keyMaterial);
    }
    if (rc == 0) {
        XMEMCPY(aesKey, keyMaterial, 32);
    }

    /* IV = HMAC-SHA256(parentPriv, "fwTPM-wrap-iv") truncated to 16.
     * Use full parent private key (same as AES key above) — HMAC handles
     * arbitrary-length keys via internal hashing. */
    if (rc == 0) {
        rc = wc_HmacSetKey(hmac, WC_SHA256, parent->privKey,
            parent->privKeySize);
    }
    if (rc == 0) {
        rc = wc_HmacUpdate(hmac, (const byte*)"fwTPM-wrap-iv", 13);
    }
    if (rc == 0) {
        rc = wc_HmacFinal(hmac, ivMaterial);
    }
    if (rc == 0) {
        XMEMCPY(aesIV, ivMaterial, AES_BLOCK_SIZE);
    }

    if (rc != 0) {
        rc = TPM_RC_FAILURE;
    }

    TPM2_ForceZero(keyMaterial, sizeof(keyMaterial));
    TPM2_ForceZero(ivMaterial, sizeof(ivMaterial));
    wc_HmacFree(hmac);
    FWTPM_FREE_VAR(hmac);
    return rc;
}

/* Marshal inner sensitive: type(2) + auth(2+N) + der(2+N) */
int FwMarshalSensitive(byte* buf, int bufSz,
    UINT16 sensitiveType, const TPM2B_AUTH* auth,
    const byte* privKeyDer, int privKeyDerSz)
{
    int pos = 0;
    if (pos + 2 > bufSz)
        return -1;
    FwStoreU16BE(buf + pos, sensitiveType);
    pos += 2;

    if (pos + 2 + auth->size > bufSz)
        return -1;
    FwStoreU16BE(buf + pos, auth->size);
    pos += 2;
    if (auth->size > 0) {
        XMEMCPY(buf + pos, auth->buffer, auth->size);
        pos += auth->size;
    }

    if (pos + 2 + privKeyDerSz > bufSz)
        return -1;
    FwStoreU16BE(buf + pos, (UINT16)privKeyDerSz);
    pos += 2;
    XMEMCPY(buf + pos, privKeyDer, privKeyDerSz);
    pos += privKeyDerSz;

    return pos;
}

/* Marshal sensitive in standard TPM 2.0 format (for Duplicate outer wrapping).
 * Format: totalSize(2) + type(2) + auth(TPM2B) + seedValue(TPM2B) + sensitive(TPM2B)
 * sensData is the raw sensitive component (RSA prime p or ECC scalar d),
 * NOT the DER-encoded private key.
 * This format matches what FwImportParseSensitive and other TPMs expect. */
int FwMarshalSensitiveStd(byte* buf, int bufSz,
    UINT16 sensitiveType, const TPM2B_AUTH* auth,
    const byte* sensData, int sensDataSz)
{
    int pos = 0;
    int innerStart;
    UINT16 innerSize;

    /* Leave space for totalSize(2), fill in later */
    if (pos + 2 > bufSz)
        return -1;
    pos += 2;
    innerStart = pos;

    /* sensitiveType */
    if (pos + 2 > bufSz)
        return -1;
    FwStoreU16BE(buf + pos, sensitiveType);
    pos += 2;

    /* authValue (TPM2B) */
    if (pos + 2 + auth->size > bufSz)
        return -1;
    FwStoreU16BE(buf + pos, auth->size);
    pos += 2;
    if (auth->size > 0) {
        XMEMCPY(buf + pos, auth->buffer, auth->size);
        pos += auth->size;
    }

    /* seedValue (TPM2B) - empty for non-derived keys */
    if (pos + 2 > bufSz)
        return -1;
    buf[pos++] = 0;
    buf[pos++] = 0;

    /* sensitive data (TPM2B) - raw sensitive component */
    if (pos + 2 + sensDataSz > bufSz)
        return -1;
    FwStoreU16BE(buf + pos, (UINT16)sensDataSz);
    pos += 2;
    XMEMCPY(buf + pos, sensData, sensDataSz);
    pos += sensDataSz;

    /* Fill in totalSize */
    innerSize = (UINT16)(pos - innerStart);
    FwStoreU16BE(buf, innerSize);

    return pos;
}

/* Unmarshal inner sensitive */
int FwUnmarshalSensitive(const byte* buf, int bufSz,
    UINT16* sensitiveType, TPM2B_AUTH* auth,
    byte* privKeyDer, int* privKeyDerSz)
{
    int pos = 0;
    UINT16 sz;

    if (pos + 2 > bufSz)
        return -1;
    *sensitiveType = FwLoadU16BE(buf + pos);
    pos += 2;

    if (pos + 2 > bufSz)
        return -1;
    auth->size = FwLoadU16BE(buf + pos);
    pos += 2;
    if (auth->size > sizeof(auth->buffer))
        return -1;
    if (pos + auth->size > bufSz)
        return -1;
    if (auth->size > 0) {
        XMEMCPY(auth->buffer, buf + pos, auth->size);
        pos += auth->size;
    }

    if (pos + 2 > bufSz)
        return -1;
    sz = FwLoadU16BE(buf + pos);
    pos += 2;
    if (pos + sz > bufSz)
        return -1;
    if (sz > FWTPM_MAX_PRIVKEY_DER)
        return -1;
    XMEMCPY(privKeyDer, buf + pos, sz);
    *privKeyDerSz = (int)sz;
    pos += sz;

    return pos;
}

/* Wrap sensitive into TPM2B_PRIVATE using parent's key.
 * Format: integritySize(2) + integrity(32) + encSensSize(2) + encSens(N)
 */
int FwWrapPrivate(FWTPM_Object* parent,
    UINT16 sensitiveType, const TPM2B_AUTH* auth,
    const byte* privKeyDer, int privKeyDerSz,
    TPM2B_PRIVATE* outPriv)
{
    int rc = TPM_RC_SUCCESS;
    byte aesKey[FWTPM_MAX_SYM_KEY_SIZE], aesIV[AES_BLOCK_SIZE];
    FWTPM_DECLARE_BUF(sensBuf, FWTPM_MAX_PRIVKEY_DER + 128);
    byte hmacDigest[WC_SHA256_DIGEST_SIZE];
    FWTPM_DECLARE_VAR(aes, Aes);
    FWTPM_DECLARE_VAR(hmac, Hmac);
    int sensSz;
    int aesInit = 0;
    int pos = 0;

    FWTPM_ALLOC_BUF(sensBuf, FWTPM_MAX_PRIVKEY_DER + 128);
    FWTPM_ALLOC_VAR(aes, Aes);
    FWTPM_ALLOC_VAR(hmac, Hmac);

    /* Marshal inner sensitive */
    sensSz = FwMarshalSensitive(sensBuf, (int)(FWTPM_MAX_PRIVKEY_DER + 128),
        sensitiveType, auth, privKeyDer, privKeyDerSz);
    if (sensSz < 0) {
        rc = TPM_RC_FAILURE;
    }

    /* Derive wrapping key/IV from parent */
    if (rc == 0) {
        rc = FwDeriveWrapKey(parent, aesKey, aesIV);
    }

    /* AES-CFB encrypt in place */
    if (rc == 0) {
        rc = wc_AesInit(aes, NULL, INVALID_DEVID);
        if (rc == 0) {
            aesInit = 1;
            rc = wc_AesSetKey(aes, aesKey, 32, aesIV, AES_ENCRYPTION);
        }
        if (rc == 0) {
            rc = wc_AesCfbEncrypt(aes, sensBuf, sensBuf, sensSz);
        }
        if (aesInit) {
            wc_AesFree(aes);
        }
    }

    /* HMAC integrity over encrypted data */
    if (rc == 0) {
        rc = wc_HmacInit(hmac, NULL, INVALID_DEVID);
    }
    if (rc == 0) {
        rc = wc_HmacSetKey(hmac, WC_SHA256, aesKey, 32);
    }
    if (rc == 0) {
        rc = wc_HmacUpdate(hmac, sensBuf, sensSz);
    }
    if (rc == 0) {
        rc = wc_HmacFinal(hmac, hmacDigest);
    }
    wc_HmacFree(hmac);

    /* Pack into TPM2B_PRIVATE */
    if (rc == 0) {
        int totalSz = 2 + WC_SHA256_DIGEST_SIZE + 2 + sensSz;
        if (totalSz > (int)sizeof(outPriv->buffer)) {
            rc = TPM_RC_SIZE;
        }
    }
    if (rc == 0) {
        /* integritySize(2) + integrity(32) + encSensSize(2) + encSens(N) */
        outPriv->buffer[pos++] = 0;
        outPriv->buffer[pos++] = WC_SHA256_DIGEST_SIZE;
        XMEMCPY(outPriv->buffer + pos, hmacDigest, WC_SHA256_DIGEST_SIZE);
        pos += WC_SHA256_DIGEST_SIZE;
        FwStoreU16BE(outPriv->buffer + pos, (UINT16)sensSz);
        pos += 2;
        XMEMCPY(outPriv->buffer + pos, sensBuf, sensSz);
        pos += sensSz;
        outPriv->size = (UINT16)pos;
    }

    if (rc != 0 && rc != TPM_RC_FAILURE) {
        rc = TPM_RC_FAILURE;
    }

    TPM2_ForceZero(aesKey, sizeof(aesKey));
    TPM2_ForceZero(aesIV, sizeof(aesIV));
    TPM2_ForceZero(hmacDigest, sizeof(hmacDigest));
    TPM2_ForceZero(sensBuf, FWTPM_MAX_PRIVKEY_DER + 128);
    FWTPM_FREE_BUF(sensBuf);
    FWTPM_FREE_VAR(aes);
    FWTPM_FREE_VAR(hmac);
    return rc;
}

/* Unwrap TPM2B_PRIVATE using parent's key */
int FwUnwrapPrivate(FWTPM_Object* parent,
    const TPM2B_PRIVATE* inPriv,
    UINT16* sensitiveType, TPM2B_AUTH* auth,
    byte* privKeyDer, int* privKeyDerSz)
{
    int rc = TPM_RC_SUCCESS;
    byte aesKey[FWTPM_MAX_SYM_KEY_SIZE], aesIV[AES_BLOCK_SIZE];
    byte hmacDigest[WC_SHA256_DIGEST_SIZE];
    byte hmacCheck[WC_SHA256_DIGEST_SIZE];
    FWTPM_DECLARE_BUF(decBuf, FWTPM_MAX_PRIVKEY_DER + 128);
    FWTPM_DECLARE_VAR(aes, Aes);
    FWTPM_DECLARE_VAR(hmac, Hmac);
    int aesInit = 0;
    int pos = 0;
    UINT16 integritySize = 0, encSensSize = 0;

    FWTPM_ALLOC_BUF(decBuf, FWTPM_MAX_PRIVKEY_DER + 128);
    FWTPM_ALLOC_VAR(aes, Aes);
    FWTPM_ALLOC_VAR(hmac, Hmac);

    if (inPriv->size < 36) {
        rc = TPM_RC_FAILURE; /* min: 2+32+2 */
    }

    /* Parse integrity */
    if (rc == 0) {
        integritySize = FwLoadU16BE(inPriv->buffer + pos);
        pos += 2;
        if (integritySize != WC_SHA256_DIGEST_SIZE) {
            rc = TPM_RC_INTEGRITY;
        }
    }
    if (rc == 0) {
        XMEMCPY(hmacDigest, inPriv->buffer + pos, WC_SHA256_DIGEST_SIZE);
        pos += WC_SHA256_DIGEST_SIZE;
    }

    /* Parse encrypted sensitive size */
    if (rc == 0) {
        if (pos + 2 > inPriv->size) {
            rc = TPM_RC_FAILURE;
        }
    }
    if (rc == 0) {
        encSensSize = FwLoadU16BE(inPriv->buffer + pos);
        pos += 2;
        if (pos + encSensSize > inPriv->size ||
            encSensSize > (int)(FWTPM_MAX_PRIVKEY_DER + 128)) {
            rc = TPM_RC_FAILURE;
        }
    }

    /* Derive wrapping key/IV from parent */
    if (rc == 0) {
        rc = FwDeriveWrapKey(parent, aesKey, aesIV);
    }

    /* Verify HMAC */
    if (rc == 0) {
        rc = wc_HmacInit(hmac, NULL, INVALID_DEVID);
    }
    if (rc == 0) {
        rc = wc_HmacSetKey(hmac, WC_SHA256, aesKey, 32);
    }
    if (rc == 0) {
        rc = wc_HmacUpdate(hmac, inPriv->buffer + pos, encSensSize);
    }
    if (rc == 0) {
        rc = wc_HmacFinal(hmac, hmacCheck);
    }
    if (rc == 0) {
        if (TPM2_ConstantCompare(hmacDigest, hmacCheck, WC_SHA256_DIGEST_SIZE) != 0) {
            rc = TPM_RC_INTEGRITY;
        }
    }

    /* AES-CFB decrypt (CFB mode uses encryption direction for both) */
    if (rc == 0) {
        XMEMCPY(decBuf, inPriv->buffer + pos, encSensSize);
        rc = wc_AesInit(aes, NULL, INVALID_DEVID);
        if (rc == 0) {
            aesInit = 1;
            rc = wc_AesSetKey(aes, aesKey, 32, aesIV, AES_ENCRYPTION);
        }
        if (rc == 0) {
            rc = wc_AesCfbDecrypt(aes, decBuf, decBuf, encSensSize);
        }
        if (aesInit) {
            wc_AesFree(aes);
        }
    }

    /* Unmarshal sensitive */
    if (rc == 0) {
        if (FwUnmarshalSensitive(decBuf, encSensSize,
                sensitiveType, auth, privKeyDer, privKeyDerSz) < 0) {
            rc = TPM_RC_FAILURE;
        }
    }

    if (rc != 0 && rc != TPM_RC_INTEGRITY && rc != TPM_RC_FAILURE) {
        rc = TPM_RC_FAILURE;
    }

    TPM2_ForceZero(aesKey, sizeof(aesKey));
    TPM2_ForceZero(aesIV, sizeof(aesIV));
    TPM2_ForceZero(hmacCheck, sizeof(hmacCheck));
    TPM2_ForceZero(decBuf, FWTPM_MAX_PRIVKEY_DER + 128);
    FWTPM_FREE_BUF(decBuf);
    FWTPM_FREE_VAR(aes);
    FWTPM_FREE_VAR(hmac);
    return rc;
}

/* ================================================================== */
/* Context blob wrap/unwrap (ContextSave/ContextLoad)                  */
/* ================================================================== */

/* Encrypt-then-MAC context blob protection using the per-boot key.
 * Layout: iv(16) | ciphertext(plainSz) | hmac(32)
 * Returns 0 on success, sets *outSz. */
int FwWrapContextBlob(FWTPM_CTX* ctx,
    const byte* plain, int plainSz,
    byte* out, int outBufSz, int* outSz)
{
    int rc = TPM_RC_SUCCESS;
    byte iv[AES_BLOCK_SIZE];
    FWTPM_DECLARE_VAR(aes, Aes);
    FWTPM_DECLARE_VAR(hmac, Hmac);
    int aesInit = 0;
    int totalSz = AES_BLOCK_SIZE + plainSz + WC_SHA256_DIGEST_SIZE;

    *outSz = 0;
    if (!ctx->ctxProtectKeyValid || totalSz > outBufSz) {
        return TPM_RC_FAILURE;
    }

    FWTPM_ALLOC_VAR(aes, Aes);
    FWTPM_ALLOC_VAR(hmac, Hmac);

    /* Generate random IV */
    rc = wc_RNG_GenerateBlock(&ctx->rng, iv, AES_BLOCK_SIZE);

    /* AES-CFB encrypt */
    if (rc == 0) {
        rc = wc_AesInit(aes, NULL, INVALID_DEVID);
        if (rc == 0) {
            aesInit = 1;
            rc = wc_AesSetKey(aes, ctx->ctxProtectKey, AES_256_KEY_SIZE, iv, AES_ENCRYPTION);
        }
    }
    if (rc == 0) {
        XMEMCPY(out, iv, AES_BLOCK_SIZE);
        rc = wc_AesCfbEncrypt(aes, out + AES_BLOCK_SIZE, plain, plainSz);
    }
    if (aesInit) {
        wc_AesFree(aes);
    }

    /* HMAC-SHA256 over iv || ciphertext */
    if (rc == 0) {
        rc = wc_HmacInit(hmac, NULL, INVALID_DEVID);
    }
    if (rc == 0) {
        rc = wc_HmacSetKey(hmac, WC_SHA256,
            ctx->ctxProtectKey, sizeof(ctx->ctxProtectKey));
    }
    if (rc == 0) {
        rc = wc_HmacUpdate(hmac, out, AES_BLOCK_SIZE + plainSz);
    }
    if (rc == 0) {
        rc = wc_HmacFinal(hmac, out + AES_BLOCK_SIZE + plainSz);
    }
    wc_HmacFree(hmac);

    if (rc == 0) {
        *outSz = totalSz;
    }
    else {
        TPM2_ForceZero(out, totalSz);
        rc = TPM_RC_FAILURE;
    }

    TPM2_ForceZero(iv, sizeof(iv));
    FWTPM_FREE_VAR(aes);
    FWTPM_FREE_VAR(hmac);
    return rc;
}

/* Verify-then-decrypt context blob. Returns 0 on success, sets *outSz. */
int FwUnwrapContextBlob(FWTPM_CTX* ctx,
    const byte* in, int inSz,
    byte* out, int outBufSz, int* outSz)
{
    int rc = TPM_RC_SUCCESS;
    byte computedHmac[WC_SHA256_DIGEST_SIZE];
    FWTPM_DECLARE_VAR(aes, Aes);
    FWTPM_DECLARE_VAR(hmac, Hmac);
    int aesInit = 0;
    int cipherSz;

    *outSz = 0;
    /* Minimum: iv(16) + at least 1 byte ciphertext + hmac(32) */
    if (!ctx->ctxProtectKeyValid ||
        inSz < AES_BLOCK_SIZE + 1 + WC_SHA256_DIGEST_SIZE) {
        return TPM_RC_FAILURE;
    }

    cipherSz = inSz - AES_BLOCK_SIZE - WC_SHA256_DIGEST_SIZE;
    if (cipherSz > outBufSz) {
        return TPM_RC_SIZE;
    }

    FWTPM_ALLOC_VAR(aes, Aes);
    FWTPM_ALLOC_VAR(hmac, Hmac);

    /* Verify HMAC over iv || ciphertext */
    if (rc == 0) {
        rc = wc_HmacInit(hmac, NULL, INVALID_DEVID);
    }
    if (rc == 0) {
        rc = wc_HmacSetKey(hmac, WC_SHA256,
            ctx->ctxProtectKey, sizeof(ctx->ctxProtectKey));
    }
    if (rc == 0) {
        rc = wc_HmacUpdate(hmac, in, AES_BLOCK_SIZE + cipherSz);
    }
    if (rc == 0) {
        rc = wc_HmacFinal(hmac, computedHmac);
    }
    wc_HmacFree(hmac);

    if (rc == 0) {
        if (TPM2_ConstantCompare(computedHmac,
                in + AES_BLOCK_SIZE + cipherSz,
                WC_SHA256_DIGEST_SIZE) != 0) {
            rc = TPM_RC_INTEGRITY;
        }
    }

    /* AES-CFB decrypt using IV from blob.
     * CFB mode uses the encrypt direction internally for both
     * encryption and decryption (encrypts IV, XORs with data). */
    if (rc == 0) {
        rc = wc_AesInit(aes, NULL, INVALID_DEVID);
        if (rc == 0) {
            aesInit = 1;
            rc = wc_AesSetKey(aes, ctx->ctxProtectKey, AES_256_KEY_SIZE, in, AES_ENCRYPTION);
        }
    }
    if (rc == 0) {
        rc = wc_AesCfbDecrypt(aes, out, in + AES_BLOCK_SIZE, cipherSz);
    }
    if (aesInit) {
        wc_AesFree(aes);
    }

    if (rc == 0) {
        *outSz = cipherSz;
    }
    else if (rc != TPM_RC_INTEGRITY) {
        TPM2_ForceZero(out, cipherSz);
        rc = TPM_RC_FAILURE;
    }

    TPM2_ForceZero(computedHmac, sizeof(computedHmac));
    FWTPM_FREE_VAR(aes);
    FWTPM_FREE_VAR(hmac);
    return rc;
}

/* ================================================================== */
/* Seed encrypt/decrypt                                                */
/* ================================================================== */

/* --- Shared helper: decrypt encrypted seed with RSA OAEP or ECC ECDH+KDFe ---
 * Used by Import ("DUPLICATE"), StartAuthSession ("SECRET"),
 * and ActivateCredential ("IDENTITY\0" + objectName). */
TPM_RC FwDecryptSeed(FWTPM_CTX* ctx,
    const FWTPM_Object* keyObj,
    const byte* encSeedBuf, UINT16 encSeedSz,
    const byte* oaepLabel, int oaepLabelSz,
    const char* kdfLabel,
    byte* seedBuf, int seedBufSz, int* seedSzOut)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    TPMI_ALG_HASH nameAlg = keyObj->pub.nameAlg;
    int digestSz = TPM2_GetHashDigestSize(nameAlg);

#ifndef NO_RSA
    if (keyObj->pub.type == TPM_ALG_RSA) {
        FWTPM_DECLARE_VAR(rsaKey, RsaKey);
        int rsaKeyInit = 0;
        enum wc_HashType wcHash = FwGetWcHashType(nameAlg);

        FWTPM_ALLOC_VAR(rsaKey, RsaKey);

        rc = FwImportRsaKeyFromDer(keyObj, rsaKey);
        if (rc == 0) {
            rsaKeyInit = 1;
            wc_RsaSetRNG(rsaKey, &ctx->rng);
            rc = wc_RsaPrivateDecrypt_ex(encSeedBuf, (word32)encSeedSz,
                seedBuf, (word32)seedBufSz, rsaKey,
                WC_RSA_OAEP_PAD, wcHash,
                FwGetMgfType(nameAlg), (byte*)(uintptr_t)oaepLabel,
                oaepLabelSz);
            if (rc <= 0) {
                TPM2_ForceZero(seedBuf, seedBufSz);
                rc = TPM_RC_FAILURE;
            }
            else {
                *seedSzOut = rc;
                rc = 0;
            }
        }
        else {
            rc = TPM_RC_FAILURE;
        }
        if (rsaKeyInit) {
            wc_FreeRsaKey(rsaKey);
        }
        FWTPM_FREE_VAR(rsaKey);
    }
    else
#endif /* !NO_RSA */
#ifdef HAVE_ECC
    if (keyObj->pub.type == TPM_ALG_ECC) {
        FWTPM_DECLARE_VAR(privKey, ecc_key);
        FWTPM_DECLARE_VAR(ephemPub, ecc_key);
        int privKeyInit = 0;
        int ephemPubInit = 0;
        byte sharedZ[MAX_ECC_BYTES];
        word32 sharedZSz = sizeof(sharedZ);
        UINT16 xSz = 0, ySz = 0;
        byte xBuf[MAX_ECC_BYTES], yBuf[MAX_ECC_BYTES];
        int wcCurve;
        int p;

        FWTPM_ALLOC_VAR(privKey, ecc_key);
        FWTPM_ALLOC_VAR(ephemPub, ecc_key);

        if (encSeedSz < 4) {
            rc = TPM_RC_COMMAND_SIZE;
        }
        if (rc == 0) {
            p = 0;
            xSz = FwLoadU16BE(encSeedBuf + p);
            p += 2;
            if (xSz > MAX_ECC_BYTES || p + xSz > encSeedSz) {
                rc = TPM_RC_SIZE;
            }
        }
        if (rc == 0) {
            XMEMCPY(xBuf, encSeedBuf + p, xSz);
            p += xSz;
            if (p + 2 > encSeedSz) {
                rc = TPM_RC_SIZE;
            }
        }
        if (rc == 0) {
            ySz = FwLoadU16BE(encSeedBuf + p);
            p += 2;
            if (ySz > MAX_ECC_BYTES || p + ySz > encSeedSz) {
                rc = TPM_RC_SIZE;
            }
        }
        if (rc == 0) {
            XMEMCPY(yBuf, encSeedBuf + p, ySz);
            wcCurve = FwGetWcCurveId(
                keyObj->pub.parameters.eccDetail.curveID);
            if (wcCurve < 0) {
                rc = TPM_RC_CURVE;
            }
        }

        if (rc == 0) {
            rc = FwImportEccKeyFromDer(keyObj, privKey);
            if (rc == 0) {
                privKeyInit = 1;
                wc_ecc_set_rng(privKey, &ctx->rng);
            }
            else {
                rc = TPM_RC_FAILURE;
            }
        }
        if (rc == 0) {
            rc = wc_ecc_init(ephemPub);
            if (rc == 0) {
                ephemPubInit = 1;
                rc = wc_ecc_import_unsigned(ephemPub, xBuf, yBuf,
                    NULL, wcCurve);
            }
            if (rc != 0) {
                rc = TPM_RC_FAILURE;
            }
        }
        /* Validate ephemeral point is on the expected curve to
         * prevent invalid curve attacks */
        if (rc == 0) {
            rc = wc_ecc_check_key(ephemPub);
            if (rc != 0) {
                rc = TPM_RC_ECC_POINT;
            }
        }
        if (rc == 0) {
            rc = wc_ecc_shared_secret(privKey, ephemPub,
                sharedZ, &sharedZSz);
            if (rc != 0) {
                rc = TPM_RC_FAILURE;
            }
        }

        if (ephemPubInit) {
            wc_ecc_free(ephemPub);
        }
        if (privKeyInit) {
            wc_ecc_free(privKey);
        }

        if (rc == 0) {
            *seedSzOut = TPM2_KDFe_ex(nameAlg,
                sharedZ, (int)sharedZSz, kdfLabel,
                xBuf, (int)xSz,
                keyObj->pub.unique.ecc.x.buffer,
                    (int)keyObj->pub.unique.ecc.x.size,
                seedBuf, digestSz);
            if (*seedSzOut != digestSz) {
                TPM2_ForceZero(seedBuf, seedBufSz);
                rc = TPM_RC_FAILURE;
            }
        }
        TPM2_ForceZero(sharedZ, sizeof(sharedZ));
        FWTPM_FREE_VAR(privKey);
        FWTPM_FREE_VAR(ephemPub);
    }
    else
#endif /* HAVE_ECC */
#ifdef WOLFTPM_V185
    if (keyObj->pub.type == TPM_ALG_MLKEM) {
        /* ML-KEM Labeled KEM per Part 1 Sec.47.4 Eq.66:
         *   K = ML-KEM.Decap(privateKey, ciphertext)
         *   seed = KDFa(nameAlg, K, label, ciphertext, publicKey, bits) */
        TPM2B_SHARED_SECRET sharedK;
        XMEMSET(&sharedK, 0, sizeof(sharedK));
        rc = FwDecapsulateMlkem(
            keyObj->pub.parameters.mlkemDetail.parameterSet,
            keyObj->privKey,
            encSeedBuf, encSeedSz, &sharedK);
        if (rc == 0) {
            int kdfRc = TPM2_KDFa_ex(nameAlg,
                sharedK.buffer, sharedK.size, kdfLabel,
                encSeedBuf, (UINT32)encSeedSz,
                keyObj->pub.unique.mlkem.buffer,
                    (UINT32)keyObj->pub.unique.mlkem.size,
                seedBuf, (UINT32)digestSz);
            if (kdfRc != digestSz) {
                TPM2_ForceZero(seedBuf, seedBufSz);
                rc = TPM_RC_FAILURE;
            }
            else {
                *seedSzOut = digestSz;
            }
        }
        TPM2_ForceZero(&sharedK, sizeof(sharedK));
        (void)oaepLabel; (void)oaepLabelSz;
    }
    else
#endif /* WOLFTPM_V185 */
    {
        (void)ctx; (void)encSeedBuf; (void)encSeedSz;
        (void)oaepLabel; (void)oaepLabelSz; (void)kdfLabel;
        (void)seedBuf; (void)seedBufSz; (void)seedSzOut;
        (void)nameAlg; (void)digestSz;
        rc = TPM_RC_KEY;
    }
    return rc;
}

/* Encrypt a seed to a public key (inverse of FwDecryptSeed).
 * RSA: generates random seed, RSA OAEP encrypts to keyObj's public key.
 * ECC: generates ephemeral ECDH key, derives seed via KDFe.
 * Returns seed in seedBuf, encrypted seed (for outSymSeed) in encSeedBuf. */
TPM_RC FwEncryptSeed(FWTPM_CTX* ctx,
    const FWTPM_Object* keyObj,
    const byte* oaepLabel, int oaepLabelSz,
    const char* kdfLabel,
    byte* seedBuf, int seedBufSz, int* seedSzOut,
    byte* encSeedBuf, int encSeedBufSz, int* encSeedSzOut)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    TPMI_ALG_HASH nameAlg = keyObj->pub.nameAlg;
    int digestSz = TPM2_GetHashDigestSize(nameAlg);

    *seedSzOut = 0;
    *encSeedSzOut = 0;

#ifndef NO_RSA
    if (keyObj->pub.type == TPM_ALG_RSA) {
        FWTPM_DECLARE_VAR(rsaKey, RsaKey);
        int rsaKeyInit = 0;
        enum wc_HashType wcHash = FwGetWcHashType(nameAlg);
        int encSz;

        FWTPM_ALLOC_VAR(rsaKey, RsaKey);

        /* Generate random seed */
        if (digestSz <= 0 || digestSz > seedBufSz) {
            rc = TPM_RC_SIZE;
        }
        if (rc == 0) {
            rc = wc_RNG_GenerateBlock(&ctx->rng, seedBuf, (word32)digestSz);
            if (rc != 0) {
                rc = TPM_RC_FAILURE;
            }
        }

        /* Load newParent's public key */
        if (rc == 0) {
            rc = FwImportRsaPubFromPublic(&keyObj->pub, rsaKey);
            if (rc == 0) {
                rsaKeyInit = 1;
                wc_RsaSetRNG(rsaKey, &ctx->rng);
            }
            else {
                rc = TPM_RC_KEY;
            }
        }

        /* RSA OAEP encrypt seed */
        if (rc == 0) {
            encSz = wc_RsaPublicEncrypt_ex(seedBuf, (word32)digestSz,
                encSeedBuf, (word32)encSeedBufSz, rsaKey, &ctx->rng,
                WC_RSA_OAEP_PAD, wcHash,
                FwGetMgfType(nameAlg), (byte*)(uintptr_t)oaepLabel,
                oaepLabelSz);
            if (encSz <= 0) {
                rc = TPM_RC_FAILURE;
            }
            else {
                *seedSzOut = digestSz;
                *encSeedSzOut = encSz;
            }
        }

        if (rsaKeyInit) {
            wc_FreeRsaKey(rsaKey);
        }
        FWTPM_FREE_VAR(rsaKey);
        if (rc != 0) {
            TPM2_ForceZero(seedBuf, seedBufSz);
        }
    }
    else
#endif /* !NO_RSA */
#ifdef HAVE_ECC
    if (keyObj->pub.type == TPM_ALG_ECC) {
        FWTPM_DECLARE_VAR(parentPub, ecc_key);
        FWTPM_DECLARE_VAR(ephemKey, ecc_key);
        int parentPubInit = 0;
        int ephemKeyInit = 0;
        byte sharedZ[MAX_ECC_BYTES];
        word32 sharedZSz = sizeof(sharedZ);
        byte ephemX[MAX_ECC_BYTES], ephemY[MAX_ECC_BYTES];
        word32 ephemXSz = sizeof(ephemX);
        word32 ephemYSz = sizeof(ephemY);
        int wcCurve;
        int p;

        FWTPM_ALLOC_VAR(parentPub, ecc_key);
        FWTPM_ALLOC_VAR(ephemKey, ecc_key);

        wcCurve = FwGetWcCurveId(
            keyObj->pub.parameters.eccDetail.curveID);
        if (wcCurve < 0) {
            rc = TPM_RC_CURVE;
        }

        /* Import parent's public key */
        if (rc == 0) {
            rc = FwImportEccPubFromPublic(&keyObj->pub, parentPub);
            if (rc == 0) {
                parentPubInit = 1;
            }
            else {
                rc = TPM_RC_KEY;
            }
        }

        /* Generate ephemeral key pair on same curve */
        if (rc == 0) {
            rc = wc_ecc_init(ephemKey);
            if (rc == 0) {
                ephemKeyInit = 1;
                wc_ecc_set_rng(ephemKey, &ctx->rng);
                rc = wc_ecc_make_key(&ctx->rng,
                    wc_ecc_get_curve_size_from_id(wcCurve), ephemKey);
            }
            if (rc != 0) {
                rc = TPM_RC_FAILURE;
            }
        }

        /* ECDH shared secret */
        if (rc == 0) {
            rc = wc_ecc_shared_secret(ephemKey, parentPub,
                sharedZ, &sharedZSz);
            if (rc != 0) {
                rc = TPM_RC_FAILURE;
            }
        }

        /* Export ephemeral public key */
        if (rc == 0) {
            rc = wc_ecc_export_public_raw(ephemKey,
                ephemX, &ephemXSz, ephemY, &ephemYSz);
            if (rc != 0) {
                rc = TPM_RC_FAILURE;
            }
        }

        /* Derive seed via KDFe(nameAlg, Z, label, ephemX, parentX) */
        if (rc == 0) {
            if (digestSz <= 0 || digestSz > seedBufSz) {
                rc = TPM_RC_SIZE;
            }
        }
        if (rc == 0) {
            int kdfRc = TPM2_KDFe_ex(nameAlg,
                sharedZ, (int)sharedZSz, kdfLabel,
                ephemX, (int)ephemXSz,
                keyObj->pub.unique.ecc.x.buffer,
                    (int)keyObj->pub.unique.ecc.x.size,
                seedBuf, digestSz);
            if (kdfRc != digestSz) {
                rc = TPM_RC_FAILURE;
            }
            else {
                *seedSzOut = digestSz;
            }
        }

        /* Pack encSeed: xSz(2) + x(N) + ySz(2) + y(N) */
        if (rc == 0) {
            p = 0;
            if ((int)(4 + ephemXSz + ephemYSz) > encSeedBufSz) {
                rc = TPM_RC_SIZE;
            }
            else {
                FwStoreU16BE(encSeedBuf + p, ephemXSz);
                p += 2;
                XMEMCPY(encSeedBuf + p, ephemX, ephemXSz);
                p += (int)ephemXSz;
                FwStoreU16BE(encSeedBuf + p, ephemYSz);
                p += 2;
                XMEMCPY(encSeedBuf + p, ephemY, ephemYSz);
                p += (int)ephemYSz;
                *encSeedSzOut = p;
            }
        }

        if (ephemKeyInit) {
            wc_ecc_free(ephemKey);
        }
        if (parentPubInit) {
            wc_ecc_free(parentPub);
        }
        TPM2_ForceZero(sharedZ, sizeof(sharedZ));
        FWTPM_FREE_VAR(parentPub);
        FWTPM_FREE_VAR(ephemKey);
        if (rc != 0) {
            TPM2_ForceZero(seedBuf, seedBufSz);
        }
    }
    else
#endif /* HAVE_ECC */
#ifdef WOLFTPM_V185
    if (keyObj->pub.type == TPM_ALG_MLKEM) {
        /* ML-KEM Labeled KEM per Part 1 Sec.47.4 Eq.66:
         *   (K, ciphertext) = ML-KEM.Encap(publicKey)
         *   seed = KDFa(nameAlg, K, label, ciphertext, publicKey, bits)
         *   encSeed = ciphertext (TPM2B_KEM_CIPHERTEXT contents). */
        TPM2B_SHARED_SECRET sharedK;
        FWTPM_DECLARE_VAR(ciphertext, TPM2B_KEM_CIPHERTEXT);

        FWTPM_CALLOC_VAR(ciphertext, TPM2B_KEM_CIPHERTEXT);
        XMEMSET(&sharedK, 0, sizeof(sharedK));

        if (digestSz <= 0 || digestSz > seedBufSz) {
            rc = TPM_RC_SIZE;
        }
        if (rc == 0) {
            rc = FwEncapsulateMlkem(&ctx->rng,
                keyObj->pub.parameters.mlkemDetail.parameterSet,
                &keyObj->pub.unique.mlkem,
                &sharedK, ciphertext);
        }
        if (rc == 0 && ciphertext->size > encSeedBufSz) {
            rc = TPM_RC_SIZE;
        }
        if (rc == 0) {
            int kdfRc = TPM2_KDFa_ex(nameAlg,
                sharedK.buffer, sharedK.size, kdfLabel,
                ciphertext->buffer, (UINT32)ciphertext->size,
                keyObj->pub.unique.mlkem.buffer,
                    (UINT32)keyObj->pub.unique.mlkem.size,
                seedBuf, (UINT32)digestSz);
            if (kdfRc != digestSz) {
                rc = TPM_RC_FAILURE;
            }
            else {
                *seedSzOut = digestSz;
                XMEMCPY(encSeedBuf, ciphertext->buffer, ciphertext->size);
                *encSeedSzOut = ciphertext->size;
            }
        }
        if (rc != 0) {
            TPM2_ForceZero(seedBuf, seedBufSz);
        }
        TPM2_ForceZero(&sharedK, sizeof(sharedK));
        FWTPM_FREE_VAR(ciphertext);
        (void)oaepLabel; (void)oaepLabelSz;
    }
    else
#endif /* WOLFTPM_V185 */
    {
        (void)ctx; (void)oaepLabel; (void)oaepLabelSz; (void)kdfLabel;
        (void)seedBuf; (void)seedBufSz; (void)seedSzOut;
        (void)encSeedBuf; (void)encSeedBufSz; (void)encSeedSzOut;
        (void)nameAlg; (void)digestSz;
        rc = TPM_RC_KEY;
    }
    return rc;
}

/* ================================================================== */
/* Import helpers                                                      */
/* ================================================================== */

/* --- Import helper: verify HMAC integrity and AES-CFB decrypt duplicate --- */
TPM_RC FwImportVerifyAndDecrypt(
    TPMI_ALG_HASH parentNameAlg,
    const byte* hmacKeyBuf, int digestSz,
    const byte* aesKey, int symKeySz,
    const byte* nameBuf, int nameSz,
    const byte* dupBuf, UINT16 dupSz,
    byte* plainSens, int plainSensBufSz, int* plainSensSzOut)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    int dupPos;
    UINT16 integritySize;
    const byte* integrity;
    const byte* encSens;
    int encSensSz;
    byte hmacCalc[64];
    FWTPM_DECLARE_VAR(aesObj, Aes);
    int aesInit = 0;
    FWTPM_DECLARE_VAR(hmacObj, Hmac);
    byte zeroIV[AES_BLOCK_SIZE];
    enum wc_HashType wcHmacType;
    int sizeMismatch;
    int hmacDiff;

    FWTPM_ALLOC_VAR(aesObj, Aes);
    FWTPM_ALLOC_VAR(hmacObj, Hmac);

    /* Parse duplicate structure */
    if (dupSz < 4) {
        rc = TPM_RC_FAILURE;
    }
    if (rc == 0) {
        integritySize = FwLoadU16BE(dupBuf);
        dupPos = 2;
        if (integritySize > (UINT16)sizeof(hmacCalc)) {
            rc = TPM_RC_SIZE;
        }
    }
    if (rc == 0 && dupPos + integritySize > (int)dupSz) {
        rc = TPM_RC_FAILURE;
    }
    if (rc == 0) {
        integrity = dupBuf + dupPos;
        dupPos += integritySize;
        encSens = dupBuf + dupPos;
        encSensSz = (int)dupSz - dupPos;
        if (encSensSz <= 0) {
            rc = TPM_RC_FAILURE;
        }
    }

    /* Verify HMAC integrity:
     * HMAC-nameAlg(hmacKeyBuf, encSens || name.name) */
    if (rc == 0) {
        wcHmacType = FwGetWcHashType(parentNameAlg);
        rc = wc_HmacInit(hmacObj, NULL, INVALID_DEVID);
    }
    if (rc == 0) {
        rc = wc_HmacSetKey(hmacObj, (int)wcHmacType,
            hmacKeyBuf, (word32)digestSz);
        if (rc == 0) {
            rc = wc_HmacUpdate(hmacObj, encSens, (word32)encSensSz);
        }
        if (rc == 0) {
            rc = wc_HmacUpdate(hmacObj, nameBuf, (word32)nameSz);
        }
        if (rc == 0) {
            rc = wc_HmacFinal(hmacObj, hmacCalc);
        }
        wc_HmacFree(hmacObj);
        if (rc != 0) {
            rc = TPM_RC_FAILURE;
        }
    }
    if (rc == 0) {
        /* Always run TPM2_ConstantCompare over min(sizes) so timing doesn't
         * leak size match and we don't read past integrity[integritySize] */
        word32 cmpSz = (integritySize < (UINT16)digestSz) ?
            (word32)integritySize : (word32)digestSz;
        sizeMismatch = (integritySize != (UINT16)digestSz);
        hmacDiff = TPM2_ConstantCompare(integrity, hmacCalc, cmpSz);
        if (sizeMismatch | hmacDiff) {
            rc = TPM_RC_INTEGRITY;
        }
    }

    /* AES-CFB decrypt encSens -> plainSens, IV = 0 */
    if (rc == 0) {
        if (encSensSz > plainSensBufSz) {
            rc = TPM_RC_SIZE;
        }
    }
    if (rc == 0) {
        XMEMCPY(plainSens, encSens, (size_t)encSensSz);
        XMEMSET(zeroIV, 0, sizeof(zeroIV));
        rc = wc_AesInit(aesObj, NULL, INVALID_DEVID);
        if (rc == 0) {
            aesInit = 1;
            rc = wc_AesSetKey(aesObj, aesKey, (word32)symKeySz,
                zeroIV, AES_ENCRYPTION);
        }
        if (rc == 0) {
            rc = wc_AesCfbDecrypt(aesObj, plainSens, plainSens,
                (word32)encSensSz);
        }
        if (aesInit) {
            wc_AesFree(aesObj);
        }
        if (rc != 0) {
            rc = TPM_RC_FAILURE;
        }
    }

    if (rc == 0) {
        *plainSensSzOut = encSensSz;
    }
    else {
        /* Zero caller's output buffer on any failure — it may contain
         * partially decrypted sensitive data. */
        TPM2_ForceZero(plainSens, plainSensBufSz);
    }

    TPM2_ForceZero(hmacCalc, sizeof(hmacCalc));
    FWTPM_FREE_VAR(aesObj);
    FWTPM_FREE_VAR(hmacObj);
    return rc;
}

/* --- Import helper: parse decrypted TPM2B_SENSITIVE --- */
TPM_RC FwImportParseSensitive(
    const byte* plainSens, int plainSensSz,
    UINT16* sensType, TPM2B_AUTH* importedAuth,
    UINT16* primeSzOut, byte* primeBuf, int primeBufSz)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    int sp = 0;
    UINT16 totalSensSize, avSz, svSz, primeSz;

    if (sp + 2 > plainSensSz) {
        rc = TPM_RC_FAILURE;
    }
    if (rc == 0) {
        totalSensSize = FwLoadU16BE(plainSens + sp);
        sp += 2;
        if (totalSensSize + 2 > (UINT16)plainSensSz) {
            return TPM_RC_SIZE;
        }
        if (sp + 2 > plainSensSz) {
            rc = TPM_RC_FAILURE;
        }
    }
    if (rc == 0) {
        *sensType = FwLoadU16BE(plainSens + sp);
        sp += 2;
        if (sp + 2 > plainSensSz) {
            rc = TPM_RC_FAILURE;
        }
    }

    /* authValue */
    if (rc == 0) {
        avSz = FwLoadU16BE(plainSens + sp);
        sp += 2;
        XMEMSET(importedAuth, 0, sizeof(*importedAuth));
        if (avSz > sizeof(importedAuth->buffer)) {
            rc = TPM_RC_SIZE;
        }
    }
    if (rc == 0) {
        importedAuth->size = avSz;
        if (avSz > 0) {
            if (sp + avSz > plainSensSz) {
                rc = TPM_RC_FAILURE;
            }
            if (rc == 0) {
                XMEMCPY(importedAuth->buffer, plainSens + sp, avSz);
                sp += avSz;
            }
        }
    }

    /* seedValue (skip) */
    if (rc == 0) {
        if (sp + 2 > plainSensSz) {
            rc = TPM_RC_FAILURE;
        }
    }
    if (rc == 0) {
        svSz = FwLoadU16BE(plainSens + sp);
        sp += 2;
        if (sp + svSz > plainSensSz) {
            rc = TPM_RC_FAILURE;
        }
    }
    if (rc == 0) {
        sp += svSz;
        if (sp + 2 > plainSensSz) {
            rc = TPM_RC_FAILURE;
        }
    }

    /* sensitive (prime q for RSA, private scalar d for ECC) */
    if (rc == 0) {
        primeSz = FwLoadU16BE(plainSens + sp);
        sp += 2;
        if (primeSz > (UINT16)primeBufSz) {
            rc = TPM_RC_SIZE;
        }
    }
    if (rc == 0 && sp + primeSz > plainSensSz) {
        rc = TPM_RC_FAILURE;
    }
    if (rc == 0) {
        XMEMCPY(primeBuf, plainSens + sp, primeSz);
        *primeSzOut = primeSz;
    }

    return rc;
}

/* --- Import helper: reconstruct ECC/RSA private key from sensitive data --- */
TPM_RC FwImportReconstructKey(
    const TPM2B_PUBLIC* objectPublic, UINT16 sensType,
    const byte* primeBuf, UINT16 primeSz,
    byte* privKeyDer, int privKeyDerBufSz, int* privKeyDerSzOut)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    /* Validate that sensitive type matches the public area type to prevent
     * type confusion (e.g., ECC scalar used with RSA public params) */
    if (sensType != objectPublic->publicArea.type) {
        return TPM_RC_TYPE;
    }

#ifdef HAVE_ECC
    if (sensType == TPM_ALG_ECC && primeSz > 0) {
        FWTPM_DECLARE_VAR(eccKey, ecc_key);
        int eccKeyInit = 0;
        UINT16 curveId;
        int wcCurve;

        FWTPM_ALLOC_VAR(eccKey, ecc_key);

        curveId = objectPublic->publicArea.parameters.eccDetail.curveID;
        wcCurve = FwGetWcCurveId(curveId);
        if (wcCurve < 0) {
            rc = TPM_RC_CURVE;
        }
        if (rc == 0) {
            rc = wc_ecc_init(eccKey);
            if (rc == 0) {
                eccKeyInit = 1;
                rc = wc_ecc_import_unsigned(eccKey,
                    objectPublic->publicArea.unique.ecc.x.buffer,
                    objectPublic->publicArea.unique.ecc.y.buffer,
                    primeBuf, wcCurve);
            }
            if (rc == 0) {
                *privKeyDerSzOut = wc_EccKeyToDer(eccKey, privKeyDer,
                    privKeyDerBufSz);
                if (*privKeyDerSzOut <= 0) {
                    rc = TPM_RC_FAILURE;
                }
            }
            if (eccKeyInit) {
                wc_ecc_free(eccKey);
            }
            if (rc != 0) {
                rc = TPM_RC_FAILURE;
            }
        }
        FWTPM_FREE_VAR(eccKey);
    }
    else
#endif /* HAVE_ECC */
#ifndef NO_RSA
    if (sensType == TPM_ALG_RSA && primeSz > 0) {
        FWTPM_DECLARE_VAR(rsaKey, RsaKey);
        int rsaKeyInit = 0;
        UINT32 exponent;

        FWTPM_ALLOC_VAR(rsaKey, RsaKey);

        exponent = objectPublic->publicArea.parameters.rsaDetail.exponent;
        if (exponent == 0) {
            exponent = WC_RSA_EXPONENT;
        }

        rc = wc_InitRsaKey(rsaKey, NULL);
        if (rc == 0) {
            rsaKeyInit = 1;
        }
        else {
            rc = TPM_RC_FAILURE;
        }
        if (rc == 0) {
            rc = mp_read_unsigned_bin(&rsaKey->n,
                objectPublic->publicArea.unique.rsa.buffer,
                (word32)objectPublic->publicArea.unique.rsa.size);
        }
        if (rc == 0) {
            rc = mp_set_int(&rsaKey->e, (unsigned long)exponent);
        }
        if (rc == 0) {
            rc = mp_read_unsigned_bin(&rsaKey->q,
                primeBuf, (word32)primeSz);
        }
        if (rc == 0) {
            mp_int rem;
            rc = mp_init(&rem);
            if (rc == 0) {
                rc = mp_div(&rsaKey->n, &rsaKey->q, &rsaKey->p, &rem);
                if (rc == 0 && !mp_iszero(&rem)) {
                    rc = TPM_RC_BINDING; /* q does not divide n evenly */
                }
                mp_forcezero(&rem);
            }
        }
        if (rc == 0) {
            rc = FwRsaComputeCRT(rsaKey);
        }
        if (rc == 0) {
            rsaKey->type = RSA_PRIVATE;
            *privKeyDerSzOut = wc_RsaKeyToDer(rsaKey, privKeyDer,
                privKeyDerBufSz);
            if (*privKeyDerSzOut < 0) {
                rc = TPM_RC_FAILURE;
            }
        }
        if (rsaKeyInit) {
            wc_FreeRsaKey(rsaKey);
        }
        FWTPM_FREE_VAR(rsaKey);
        if (rc != 0) {
            rc = TPM_RC_FAILURE;
        }
    }
    else
#endif /* !NO_RSA */
    {
        (void)objectPublic; (void)primeBuf; (void)primeSz;
        (void)privKeyDer; (void)privKeyDerBufSz; (void)privKeyDerSzOut;
        rc = TPM_RC_TYPE;
    }
    return rc;
}

/* ================================================================== */
/* Key import from DER/Public                                          */
/* ================================================================== */

/* --- Helper: import key from DER for crypto operations --- */
#ifndef NO_RSA
int FwImportRsaKeyFromDer(const FWTPM_Object* obj, RsaKey* key)
{
    word32 idx = 0;
    int rc;
    rc = wc_InitRsaKey(key, NULL);
    if (rc != 0)
        return rc;
    rc = wc_RsaPrivateKeyDecode(obj->privKey, &idx, key, obj->privKeySize);
    if (rc != 0) { wc_FreeRsaKey(key); return rc; }
    return 0;
}
#endif /* !NO_RSA */

#ifdef HAVE_ECC
int FwImportEccKeyFromDer(const FWTPM_Object* obj, ecc_key* key)
{
    word32 idx = 0;
    int rc;
    rc = wc_ecc_init(key);
    if (rc != 0)
        return rc;
    rc = wc_EccPrivateKeyDecode(obj->privKey, &idx, key, obj->privKeySize);
    if (rc != 0) { wc_ecc_free(key); return rc; }
    return 0;
}
#endif /* HAVE_ECC */

#ifndef NO_RSA
/* Import public-only RSA key from TPMT_PUBLIC */
int FwImportRsaPubFromPublic(const TPMT_PUBLIC* pub, RsaKey* key)
{
    int rc;
    UINT32 exponent = pub->parameters.rsaDetail.exponent;
    byte expBuf[4]; /* big-endian exponent for wc_RsaPublicKeyDecodeRaw */
    int expSz;

    if (exponent == 0) {
        exponent = WC_RSA_EXPONENT;
    }

    /* Store exponent as big-endian, trimming leading zeros */
    FwStoreU32BE(expBuf, exponent);
    expSz = 4;
    while (expSz > 1 && expBuf[4 - expSz] == 0) {
        expSz--;
    }

    rc = wc_InitRsaKey(key, NULL);
    if (rc != 0)
        return rc;
    rc = wc_RsaPublicKeyDecodeRaw(
        pub->unique.rsa.buffer, pub->unique.rsa.size,
        expBuf + (4 - expSz), expSz, key);
    if (rc != 0) { wc_FreeRsaKey(key); return rc; }
    return 0;
}
#endif /* !NO_RSA */

#ifdef HAVE_ECC
/* Import public-only ECC key from TPMT_PUBLIC */
int FwImportEccPubFromPublic(const TPMT_PUBLIC* pub, ecc_key* key)
{
    int rc;
    int wcCurve = FwGetWcCurveId(pub->parameters.eccDetail.curveID);
    if (wcCurve < 0)
        return TPM_RC_CURVE;

    rc = wc_ecc_init(key);
    if (rc != 0)
        return rc;
    rc = wc_ecc_import_unsigned(key,
        (byte*)pub->unique.ecc.x.buffer,
        (byte*)pub->unique.ecc.y.buffer,
        NULL, wcCurve);
    if (rc != 0) { wc_ecc_free(key); return rc; }
    return 0;
}
#endif /* HAVE_ECC */

#ifndef NO_RSA
/* Import RSA key: use private DER if available, else public from TPMT_PUBLIC */
int FwImportRsaKey(const FWTPM_Object* obj, RsaKey* key)
{
    if (obj->privKeySize > 0) {
        return FwImportRsaKeyFromDer(obj, key);
    }
    return FwImportRsaPubFromPublic(&obj->pub, key);
}
#endif /* !NO_RSA */

#ifdef HAVE_ECC
/* Import ECC key: use private DER if available, else public from TPMT_PUBLIC */
int FwImportEccKey(const FWTPM_Object* obj, ecc_key* key)
{
    if (obj->privKeySize > 0) {
        return FwImportEccKeyFromDer(obj, key);
    }
    return FwImportEccPubFromPublic(&obj->pub, key);
}

/* Compute ECDH shared point R = priv.k * peer.pub, returning both x and y
 * coordinates. wc_ecc_shared_secret only returns x; ZGen_2Phase marshals a
 * full TPM2B_ECC_POINT and TPM_ALG_ECMQV requires y as well.
 * xBuf/yBuf must each hold at least curve byte length. */
int FwEccSharedPoint(ecc_key* priv, ecc_key* peer,
    byte* xBuf, word32* xSz, byte* yBuf, word32* ySz)
{
    int rc;
    int curveIdx;
    ecc_point* R = NULL;
    mp_int prime, a;
    const ecc_set_type* dp;
    int primeInit = 0, aInit = 0;

    if (priv == NULL || peer == NULL || xBuf == NULL || xSz == NULL ||
        yBuf == NULL || ySz == NULL) {
        return BAD_FUNC_ARG;
    }

    curveIdx = wc_ecc_get_curve_idx(priv->dp->id);
    if (curveIdx < 0)
        return ECC_BAD_ARG_E;
    dp = wc_ecc_get_curve_params(curveIdx);
    if (dp == NULL)
        return ECC_BAD_ARG_E;

    R = wc_ecc_new_point();
    if (R == NULL)
        return MEMORY_E;

    rc = mp_init(&prime);
    if (rc == 0) {
        primeInit = 1;
        rc = mp_init(&a);
    }
    if (rc == 0) {
        aInit = 1;
        rc = mp_read_radix(&prime, dp->prime, MP_RADIX_HEX);
    }
    if (rc == 0)
        rc = mp_read_radix(&a, dp->Af, MP_RADIX_HEX);
    if (rc == 0)
        rc = wc_ecc_mulmod(ecc_get_k(priv), &peer->pubkey, R, &a, &prime, 1);

    /* Export x and y with fixed-size left-zero padding to the curve byte
     * length. Using mp_unsigned_bin_size/mp_to_unsigned_bin here would drop
     * leading zero bytes (~1/256 per coordinate for a random point), which
     * both breaks ZGen_2Phase callers that expect curve-length outputs and
     * leaks the leading-zero count of the shared point. */
    if (rc == 0) {
        *xSz = (word32)dp->size;
        rc = mp_to_unsigned_bin_len(R->x, xBuf, dp->size);
    }
    if (rc == 0) {
        *ySz = (word32)dp->size;
        rc = mp_to_unsigned_bin_len(R->y, yBuf, dp->size);
    }

    if (aInit)
        mp_clear(&a);
    if (primeInit)
        mp_clear(&prime);
    wc_ecc_del_point(R);
    return rc;
}
#endif /* HAVE_ECC */

#ifndef NO_RSA
/* Map TPM sig scheme to wolfCrypt for RSA */
int FwGetRsaPadding(UINT16 scheme)
{
    switch (scheme) {
        case TPM_ALG_RSASSA: return WC_RSA_PKCSV15_PAD;
        case TPM_ALG_RSAPSS: return WC_RSA_PSS_PAD;
        default:             return -1;
    }
}

/* Helper: compute RSA CRT parameters (d, dP, dQ, u) from p, q, e.
 * Returns 0 on success. */
int FwRsaComputeCRT(RsaKey* rsaKey)
{
    int rc;
    mp_int pm1, qm1, phi;

    rc = mp_init(&pm1);
    if (rc == 0) {
        rc = mp_init(&qm1);
    }
    if (rc == 0) {
        rc = mp_init(&phi);
    }
    if (rc != 0) {
        return TPM_RC_FAILURE;
    }

    /* phi = (p-1)(q-1) */
    rc = mp_sub_d(&rsaKey->p, 1, &pm1);
    if (rc == 0) {
        rc = mp_sub_d(&rsaKey->q, 1, &qm1);
    }
    if (rc == 0) {
        rc = mp_mul(&pm1, &qm1, &phi);
    }

    /* d = e^{-1} mod phi */
    if (rc == 0) {
        rc = mp_invmod(&rsaKey->e, &phi, &rsaKey->d);
    }
    if (rc == 0) {
        rc = mp_mod(&rsaKey->d, &pm1, &rsaKey->dP);
    }
    if (rc == 0) {
        rc = mp_mod(&rsaKey->d, &qm1, &rsaKey->dQ);
    }
    if (rc == 0) {
        rc = mp_invmod(&rsaKey->q, &rsaKey->p, &rsaKey->u);
    }

    mp_forcezero(&pm1);
    mp_forcezero(&qm1);
    mp_forcezero(&phi);
    mp_clear(&pm1);
    mp_clear(&qm1);
    mp_clear(&phi);

    if (rc != 0) {
        rc = TPM_RC_FAILURE;
    }
    return rc;
}

/* Map TPM hash alg to wolfCrypt hash type for RSA signing */
int FwGetRsaHashOid(UINT16 hashAlg)
{
    switch (hashAlg) {
        case TPM_ALG_SHA256: return WC_HASH_TYPE_SHA256;
    #ifdef WOLFSSL_SHA384
        case TPM_ALG_SHA384: return WC_HASH_TYPE_SHA384;
    #endif
    #ifndef NO_SHA
        case TPM_ALG_SHA1:   return WC_HASH_TYPE_SHA;
    #endif
        default:             return WC_HASH_TYPE_NONE;
    }
}
#endif /* !NO_RSA */

/* ================================================================== */
/* Sign/Verify                                                         */
/* ================================================================== */

/** \brief Sign a digest and append TPMT_SIGNATURE to a response packet.
 *  Supports RSA (PSS/PKCS#1 v1.5) and ECC (ECDSA). */
TPM_RC FwSignDigestAndAppend(FWTPM_CTX* ctx, FWTPM_Object* obj,
    UINT16 sigScheme, UINT16 sigHashAlg,
    const byte* digest, int digestSz, TPM2_Packet* rsp)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    switch (obj->pub.type) {
#ifndef NO_RSA
        case TPM_ALG_RSA: {
            FWTPM_DECLARE_VAR(rsaKey, RsaKey);
            FWTPM_DECLARE_BUF(sigBuf, FWTPM_MAX_PUB_BUF);
            word32 sigSz = (word32)FWTPM_MAX_PUB_BUF;
            int pad = FwGetRsaPadding(sigScheme);
            int wcHashType = FwGetRsaHashOid(sigHashAlg);
            int wcRc;
            int rsaInit = 0;

            FWTPM_ALLOC_VAR(rsaKey, RsaKey);
            FWTPM_ALLOC_BUF(sigBuf, FWTPM_MAX_PUB_BUF);

            if (pad < 0)
                rc = TPM_RC_SCHEME;

            if (rc == 0) {
                wcRc = FwImportRsaKeyFromDer(obj, rsaKey);
                if (wcRc != 0)
                    rc = TPM_RC_FAILURE;
                else
                    rsaInit = 1;
            }

            if (rc == 0) {
                if (pad == WC_RSA_PSS_PAD) {
                    int mgf = FwGetMgfType(sigHashAlg);
                    wcRc = wc_RsaPSS_Sign_ex(digest, digestSz,
                        sigBuf, sigSz, (enum wc_HashType)wcHashType, mgf,
                        RSA_PSS_SALT_LEN_DEFAULT, rsaKey, &ctx->rng);
                }
                else {
                    /* RSASSA PKCS#1 v1.5: wrap in ASN.1 DigestInfo */
                    byte encHash[WC_MAX_DIGEST_SIZE +
                        MAX_ENCODED_DIG_ASN_SZ];
                    int encSz;
                    int oid = wc_HashGetOID(
                        (enum wc_HashType)wcHashType);
                    encSz = wc_EncodeSignature(encHash,
                        digest, digestSz, oid);
                    if (encSz > 0) {
                        wcRc = wc_RsaSSL_Sign(encHash, (word32)encSz,
                            sigBuf, sigSz, rsaKey, &ctx->rng);
                    }
                    else {
                        wcRc = encSz;
                    }
                }
                if (wcRc < 0)
                    rc = TPM_RC_FAILURE;
                else
                    sigSz = (word32)wcRc;
            }

            if (rsaInit)
                wc_FreeRsaKey(rsaKey);

            if (rc == 0) {
                TPM2_Packet_AppendU16(rsp, sigScheme);
                TPM2_Packet_AppendU16(rsp, sigHashAlg);
                TPM2_Packet_AppendU16(rsp, (UINT16)sigSz);
                TPM2_Packet_AppendBytes(rsp, sigBuf, (int)sigSz);
            }
            FWTPM_FREE_VAR(rsaKey);
            FWTPM_FREE_BUF(sigBuf);
            break;
        }
#endif /* !NO_RSA */
#ifdef HAVE_ECC
        case TPM_ALG_ECC: {
            FWTPM_DECLARE_VAR(eccKey, ecc_key);
            FWTPM_DECLARE_BUF(derSig, FWTPM_MAX_DER_SIG_BUF);
            word32 derSigSz = (word32)FWTPM_MAX_DER_SIG_BUF;
            byte rBuf[66], sBuf[66];
            word32 rSz = (word32)sizeof(rBuf);
            word32 sSz = (word32)sizeof(sBuf);
            int wcRc;
            int eccInit = 0;

            FWTPM_ALLOC_VAR(eccKey, ecc_key);
            FWTPM_ALLOC_BUF(derSig, FWTPM_MAX_DER_SIG_BUF);

            wcRc = FwImportEccKeyFromDer(obj, eccKey);
            if (wcRc != 0)
                rc = TPM_RC_FAILURE;
            else
                eccInit = 1;

            if (rc == 0) {
                wcRc = wc_ecc_sign_hash(digest, digestSz,
                    derSig, &derSigSz, &ctx->rng, eccKey);
                if (wcRc != 0)
                    rc = TPM_RC_FAILURE;
            }

            if (eccInit)
                wc_ecc_free(eccKey);

            if (rc == 0) {
                wcRc = wc_ecc_sig_to_rs(derSig, derSigSz,
                    rBuf, &rSz, sBuf, &sSz);
                if (wcRc != 0)
                    rc = TPM_RC_FAILURE;
            }

            if (rc == 0) {
                TPM2_Packet_AppendU16(rsp, sigScheme);
                TPM2_Packet_AppendU16(rsp, sigHashAlg);
                TPM2_Packet_AppendU16(rsp, (UINT16)rSz);
                TPM2_Packet_AppendBytes(rsp, rBuf, (int)rSz);
                TPM2_Packet_AppendU16(rsp, (UINT16)sSz);
                TPM2_Packet_AppendBytes(rsp, sBuf, (int)sSz);
            }
            FWTPM_FREE_VAR(eccKey);
            FWTPM_FREE_BUF(derSig);
            break;
        }
#endif /* HAVE_ECC */
        default:
            rc = TPM_RC_KEY;
            break;
    }
    return rc;
}

TPM_RC FwVerifySignatureCore(FWTPM_Object* obj,
    const byte* digest, int digestSz, const TPMT_SIGNATURE* sig)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    switch (obj->pub.type) {
#ifndef NO_RSA
        case TPM_ALG_RSA: {
            FWTPM_DECLARE_VAR(rsaKey, RsaKey);
            int wcRc;
            int pad = FwGetRsaPadding(sig->sigAlg);
            int rsaInit = 0;

            FWTPM_ALLOC_VAR(rsaKey, RsaKey);

            if (pad < 0)
                rc = TPM_RC_SCHEME;

            if (rc == 0) {
                wcRc = FwImportRsaKey(obj, rsaKey);
                if (wcRc != 0)
                    rc = TPM_RC_FAILURE;
                else
                    rsaInit = 1;
            }

            if (rc == 0) {
                if (pad == WC_RSA_PSS_PAD) {
                    FWTPM_DECLARE_BUF(decSig, FWTPM_MAX_PUB_BUF);
                    int wcHashType = FwGetRsaHashOid(
                        sig->signature.rsassa.hash);
                    int mgf = FwGetMgfType(sig->signature.rsassa.hash);
                    FWTPM_ALLOC_BUF(decSig, FWTPM_MAX_PUB_BUF);
                    wcRc = wc_RsaPSS_VerifyCheck(
                        sig->signature.rsapss.sig.buffer,
                        sig->signature.rsapss.sig.size,
                        decSig, (word32)FWTPM_MAX_PUB_BUF,
                        digest, digestSz,
                        (enum wc_HashType)wcHashType, mgf,
                        rsaKey);
                    FWTPM_FREE_BUF(decSig);
                }
                else {
                    FWTPM_DECLARE_BUF(decSig, FWTPM_MAX_PUB_BUF);
                    byte expDI[WC_MAX_DIGEST_SIZE +
                        MAX_ENCODED_DIG_ASN_SZ];
                    int wcHash = FwGetRsaHashOid(
                        sig->signature.rsassa.hash);
                    int oid = wc_HashGetOID(
                        (enum wc_HashType)wcHash);
                    int expSz = wc_EncodeSignature(expDI,
                        digest, digestSz, oid);
                    int sizeMismatch;
                    int sigDiff;
                    word32 cmpSz;

                    FWTPM_ALLOC_BUF(decSig, FWTPM_MAX_PUB_BUF);
                    wcRc = wc_RsaSSL_Verify(
                        sig->signature.rsassa.sig.buffer,
                        sig->signature.rsassa.sig.size,
                        decSig, (word32)FWTPM_MAX_PUB_BUF, rsaKey);
                    if (wcRc >= 0 && expSz > 0) {
                        /* Always run TPM2_ConstantCompare so timing doesn't
                         * leak decoded-length vs expected-length match */
                        sizeMismatch = (wcRc != expSz);
                        cmpSz = (wcRc < expSz) ? (word32)wcRc :
                            (word32)expSz;
                        sigDiff = TPM2_ConstantCompare(decSig, expDI, cmpSz);
                        if (sizeMismatch | sigDiff) {
                            wcRc = -1;
                        }
                    }
                    else if (wcRc >= 0) {
                        wcRc = -1;
                    }
                    FWTPM_FREE_BUF(decSig);
                }
                if (wcRc < 0)
                    rc = TPM_RC_SIGNATURE;
            }

            if (rsaInit)
                wc_FreeRsaKey(rsaKey);
            FWTPM_FREE_VAR(rsaKey);
            break;
        }
#endif /* !NO_RSA */
#ifdef HAVE_ECC
        case TPM_ALG_ECC: {
            FWTPM_DECLARE_VAR(eccKey, ecc_key);
            FWTPM_DECLARE_BUF(derSig, FWTPM_MAX_DER_SIG_BUF);
            word32 derSigSz = (word32)FWTPM_MAX_DER_SIG_BUF;
            int wcRc;
            int verified = 0;
            int eccInit = 0;

            FWTPM_ALLOC_VAR(eccKey, ecc_key);
            FWTPM_ALLOC_BUF(derSig, FWTPM_MAX_DER_SIG_BUF);

            wcRc = FwImportEccKey(obj, eccKey);
            if (wcRc != 0)
                rc = TPM_RC_FAILURE;
            else
                eccInit = 1;

            if (rc == 0) {
                wcRc = wc_ecc_rs_raw_to_sig(
                    sig->signature.ecdsa.signatureR.buffer,
                    sig->signature.ecdsa.signatureR.size,
                    sig->signature.ecdsa.signatureS.buffer,
                    sig->signature.ecdsa.signatureS.size,
                    derSig, &derSigSz);
                if (wcRc != 0)
                    rc = TPM_RC_FAILURE;
            }

            if (rc == 0) {
                wcRc = wc_ecc_verify_hash(derSig, derSigSz,
                    digest, digestSz, &verified, eccKey);
                if (wcRc != 0 || !verified)
                    rc = TPM_RC_SIGNATURE;
            }

            if (eccInit)
                wc_ecc_free(eccKey);
            FWTPM_FREE_VAR(eccKey);
            FWTPM_FREE_BUF(derSig);
            break;
        }
#endif /* HAVE_ECC */
        default:
            rc = TPM_RC_KEY;
            break;
    }
    return rc;
}

/* ================================================================== */
/* NV name computation                                                 */
/* ================================================================== */

#ifndef FWTPM_NO_NV
/* Compute NV name = nameAlg(BE) || Hash(marshaledNvPublic)
 * buf must hold at least 2 + TPM_MAX_DIGEST_SIZE bytes */
int FwComputeNvName(FWTPM_NvIndex* nv, byte* buf, UINT16* sz)
{
    byte marshaled[sizeof(TPMS_NV_PUBLIC)];
    TPM2_Packet pkt;
    FWTPM_DECLARE_VAR(hash, wc_HashAlg);
    enum wc_HashType hashType = FwGetWcHashType(nv->nvPublic.nameAlg);
    int hSz = TPM2_GetHashDigestSize(nv->nvPublic.nameAlg);
    int rc;

    FWTPM_ALLOC_VAR(hash, wc_HashAlg);

    if (hSz <= 0) {
        FWTPM_FREE_VAR(hash);
        return BAD_FUNC_ARG;
    }

    /* Marshal TPMS_NV_PUBLIC */
    pkt.buf = marshaled;
    pkt.pos = 0;
    pkt.size = sizeof(marshaled);
    TPM2_Packet_AppendU32(&pkt, nv->nvPublic.nvIndex);
    TPM2_Packet_AppendU16(&pkt, nv->nvPublic.nameAlg);
    TPM2_Packet_AppendU32(&pkt, nv->nvPublic.attributes);
    TPM2_Packet_AppendU16(&pkt, nv->nvPublic.authPolicy.size);
    TPM2_Packet_AppendBytes(&pkt, nv->nvPublic.authPolicy.buffer,
        nv->nvPublic.authPolicy.size);
    TPM2_Packet_AppendU16(&pkt, nv->nvPublic.dataSize);

    /* nameAlg big-endian at front */
    FwStoreU16BE(buf, nv->nvPublic.nameAlg);

    /* Hash the marshaled public area */
    rc = wc_HashInit(hash, hashType);
    if (rc == 0) {
        rc = wc_HashUpdate(hash, hashType, marshaled, pkt.pos);
    }
    if (rc == 0) {
        rc = wc_HashFinal(hash, hashType, buf + 2);
    }
    wc_HashFree(hash, hashType);
    if (rc == 0) {
        *sz = (UINT16)(2 + hSz);
    }
    FWTPM_FREE_VAR(hash);
    return rc;
}
#endif /* !FWTPM_NO_NV */

/* ================================================================== */
/* Attestation helpers                                                 */
/* ================================================================== */

/* Helper: resolve signing scheme from key defaults if NULL.
 * If sigScheme is TPM_ALG_NULL, use the key's scheme. If still NULL,
 * default to RSASSA/ECDSA with SHA-256. */
void FwResolveSignScheme(FWTPM_Object* obj, UINT16* sigScheme,
    UINT16* sigHashAlg)
{
    if (*sigScheme == TPM_ALG_NULL) {
        if (obj->pub.type == TPM_ALG_RSA) {
            *sigScheme = obj->pub.parameters.rsaDetail.scheme.scheme;
            *sigHashAlg = obj->pub.parameters.rsaDetail.scheme.details
                .anySig.hashAlg;
        }
        else if (obj->pub.type == TPM_ALG_ECC) {
            *sigScheme = obj->pub.parameters.eccDetail.scheme.scheme;
            *sigHashAlg = obj->pub.parameters.eccDetail.scheme.details
                .any.hashAlg;
        }
    }
    if (*sigScheme == TPM_ALG_NULL) {
        *sigScheme = (obj->pub.type == TPM_ALG_RSA) ?
            TPM_ALG_RSASSA : TPM_ALG_ECDSA;
    }
    if (*sigHashAlg == TPM_ALG_NULL) {
        *sigHashAlg = TPM_ALG_SHA256;
    }
}

#ifndef FWTPM_NO_ATTESTATION
/* Helper: build attestation response -- append TPM2B_ATTEST, sign, finalize.
 * Caller has already built attestBuf via attestPkt. */
TPM_RC FwBuildAttestResponse(FWTPM_CTX* ctx, TPM2_Packet* rsp,
    UINT16 cmdTag, FWTPM_Object* sigObj, UINT16 sigScheme, UINT16 sigHashAlg,
    byte* attestBuf, int attestSize)
{
    TPM_RC rc;
    int paramSzPos, paramStart;

    paramStart = FwRspParamsBegin(rsp, cmdTag, &paramSzPos);
    TPM2_Packet_AppendU16(rsp, (UINT16)attestSize);
    TPM2_Packet_AppendBytes(rsp, attestBuf, attestSize);

    rc = FwSignAttest(ctx, sigObj, sigScheme, sigHashAlg,
        attestBuf, attestSize, rsp);
    if (rc == 0) {
        FwRspParamsEnd(rsp, cmdTag, paramSzPos, paramStart);
    }
    return rc;
}

/* Helper: sign attestation buffer with signing key.
 * attestBuf/attestSz: serialized TPMS_ATTEST bytes
 * obj: signing key object
 * sigScheme/sigHashAlg: from command inScheme (TPM_ALG_NULL = use key default)
 * rsp: where to write TPMT_SIGNATURE */
TPM_RC FwSignAttest(FWTPM_CTX* ctx, FWTPM_Object* obj,
    UINT16 sigScheme, UINT16 sigHashAlg,
    const byte* attestBuf, int attestSz,
    TPM2_Packet* rsp)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    byte digest[TPM_MAX_DIGEST_SIZE];
    int digestSz;
    enum wc_HashType wcHash;

    /* Resolve scheme/hash from key if NULL */
    FwResolveSignScheme(obj, &sigScheme, &sigHashAlg);

    wcHash = FwGetWcHashType(sigHashAlg);
    digestSz = TPM2_GetHashDigestSize(sigHashAlg);
    if (wcHash == WC_HASH_TYPE_NONE || digestSz == 0) {
        rc = TPM_RC_HASH;
    }

    /* Hash the attest buffer */
    if (rc == 0) {
        if (wc_Hash(wcHash, attestBuf, attestSz, digest, digestSz) != 0) {
            rc = TPM_RC_FAILURE;
        }
    }

    if (rc == 0) {
        rc = FwSignDigestAndAppend(ctx, obj, sigScheme, sigHashAlg,
            digest, digestSz, rsp);
    }

    TPM2_ForceZero(digest, sizeof(digest));
    return rc;
}
#endif /* !FWTPM_NO_ATTESTATION */

/* ================================================================== */
/* Credential helpers                                                  */
/* ================================================================== */

#ifndef FWTPM_NO_CREDENTIAL

/* Derive AES symmetric key ("STORAGE") and HMAC key ("INTEGRITY") from seed.
 * Per TPM 2.0 Part 1 Section 24. */
TPM_RC FwCredentialDeriveKeys(
    const byte* seed, int seedSz,
    const byte* name, int nameSz,
    byte* symKey, int symKeySz,
    byte* hmacKey, int hmacKeySz)
{
    int kdfRc;

    kdfRc = TPM2_KDFa_ex(TPM_ALG_SHA256, seed, seedSz,
        "STORAGE", name, nameSz, NULL, 0, symKey, symKeySz);
    if (kdfRc != symKeySz) {
        return TPM_RC_FAILURE;
    }
    kdfRc = TPM2_KDFa_ex(TPM_ALG_SHA256, seed, seedSz,
        "INTEGRITY", NULL, 0, NULL, 0, hmacKey, hmacKeySz);
    if (kdfRc != hmacKeySz) {
        TPM2_ForceZero(symKey, symKeySz);
        return TPM_RC_FAILURE;
    }
    return TPM_RC_SUCCESS;
}

/* Encrypt credential and compute outer HMAC (MakeCredential direction).
 * encCred = AES-128-CFB(symKey, 0-IV, size(2) || credential)
 * outerHmac = HMAC(hmacKey, encCred || name) */
TPM_RC FwCredentialWrap(
    const byte* symKey, int symKeySz,
    const byte* hmacKey, int hmacKeySz,
    const byte* credential, UINT16 credSz,
    const byte* name, int nameSz,
    byte* encCred, word32* encCredSz,
    byte* outerHmac)
{
    TPM_RC rc;
    byte iv[AES_BLOCK_SIZE];
    FWTPM_DECLARE_VAR(aes, Aes);
    FWTPM_DECLARE_VAR(hmac, Hmac);

    FWTPM_ALLOC_VAR(aes, Aes);
    FWTPM_ALLOC_VAR(hmac, Hmac);

    /* Prepend size(2) to credential, then AES-CFB encrypt */
    FwStoreU16BE(encCred, credSz);
    XMEMCPY(encCred + 2, credential, credSz);
    *encCredSz = 2 + credSz;

    XMEMSET(iv, 0, sizeof(iv));
    rc = wc_AesInit(aes, NULL, INVALID_DEVID);
    if (rc == 0)
        rc = wc_AesSetKey(aes, symKey, (word32)symKeySz, iv, AES_ENCRYPTION);
    if (rc == 0)
        rc = wc_AesCfbEncrypt(aes, encCred, encCred, *encCredSz);
    wc_AesFree(aes);
    if (rc != 0) {
        rc = TPM_RC_FAILURE;
    }

    /* HMAC(hmacKey, encCred || name) */
    if (rc == 0) {
        rc = wc_HmacInit(hmac, NULL, INVALID_DEVID);
        if (rc == 0)
            rc = wc_HmacSetKey(hmac, WC_SHA256, hmacKey, (word32)hmacKeySz);
        if (rc == 0)
            rc = wc_HmacUpdate(hmac, encCred, *encCredSz);
        if (rc == 0)
            rc = wc_HmacUpdate(hmac, name, nameSz);
        if (rc == 0)
            rc = wc_HmacFinal(hmac, outerHmac);
        wc_HmacFree(hmac);
        if (rc != 0)
            rc = TPM_RC_FAILURE;
    }

    FWTPM_FREE_VAR(aes);
    FWTPM_FREE_VAR(hmac);
    return rc;
}

/* Verify outer HMAC and decrypt credential (ActivateCredential direction).
 * blobBuf layout: integrityHmac(TPM2B) || encIdentity(raw bytes)
 * Verifies HMAC(hmacKey, encIdentity || name) then AES-CFB decrypts. */
TPM_RC FwCredentialUnwrap(
    const byte* symKey, int symKeySz,
    const byte* hmacKey, int hmacKeySz,
    const byte* blobBuf, UINT16 blobSz,
    const byte* name, int nameSz,
    byte* credOut, int credBufSz, UINT16* credSzOut)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    TPM2_Packet blobPkt;
    UINT16 integrityHmacSz = 0;
    byte integrityHmac[TPM_SHA256_DIGEST_SIZE];
    byte computedHmac[TPM_SHA256_DIGEST_SIZE];
    const byte* encIdentity;
    int encIdentitySz;
    byte iv[AES_BLOCK_SIZE];
    int sizeMismatch;
    int hmacDiff;
    FWTPM_DECLARE_VAR(aes, Aes);
    FWTPM_DECLARE_VAR(hmac, Hmac);
    FWTPM_DECLARE_BUF(decBuf, FWTPM_MAX_NV_DATA + 2);

    /* Zero-init so tail bytes are deterministic when integrityHmacSz < 32 */
    TPM2_ForceZero(integrityHmac, sizeof(integrityHmac));

    FWTPM_ALLOC_VAR(aes, Aes);
    FWTPM_ALLOC_VAR(hmac, Hmac);
    FWTPM_ALLOC_BUF(decBuf, FWTPM_MAX_NV_DATA + 2);

    /* Parse blob: integrity(TPM2B) | encIdentity(raw) */
    if (rc == 0) {
        blobPkt.buf = (byte*)(uintptr_t)blobBuf;
        blobPkt.pos = 0;
        blobPkt.size = blobSz;
        TPM2_Packet_ParseU16(&blobPkt, &integrityHmacSz);
        if (integrityHmacSz > TPM_SHA256_DIGEST_SIZE) {
            rc = TPM_RC_SIZE;
        }
    }
    if (rc == 0) {
        TPM2_Packet_ParseBytes(&blobPkt, integrityHmac, integrityHmacSz);
        encIdentity = blobBuf + blobPkt.pos;
        encIdentitySz = blobSz - blobPkt.pos;
        if (encIdentitySz <= 0) {
            rc = TPM_RC_SIZE;
        }
    }

    /* Verify HMAC(hmacKey, encIdentity || name) */
    if (rc == 0) {
        rc = wc_HmacInit(hmac, NULL, INVALID_DEVID);
        if (rc == 0)
            rc = wc_HmacSetKey(hmac, WC_SHA256, hmacKey, (word32)hmacKeySz);
        if (rc == 0)
            rc = wc_HmacUpdate(hmac, encIdentity, encIdentitySz);
        if (rc == 0)
            rc = wc_HmacUpdate(hmac, name, nameSz);
        if (rc == 0)
            rc = wc_HmacFinal(hmac, computedHmac);
        wc_HmacFree(hmac);
        if (rc != 0) {
            rc = TPM_RC_FAILURE;
        }
    }
    if (rc == 0) {
        /* Always run TPM2_ConstantCompare so timing doesn't leak size match */
        sizeMismatch = (integrityHmacSz != TPM_SHA256_DIGEST_SIZE);
        hmacDiff = TPM2_ConstantCompare(computedHmac, integrityHmac,
            TPM_SHA256_DIGEST_SIZE);
        if (sizeMismatch | hmacDiff) {
            rc = TPM_RC_INTEGRITY;
        }
    }

    /* AES-CFB decrypt encIdentity */
    if (rc == 0) {
        if (encIdentitySz > (int)(FWTPM_MAX_NV_DATA + 2)) {
            rc = TPM_RC_SIZE;
        }
    }
    if (rc == 0) {
        XMEMSET(iv, 0, sizeof(iv));
        XMEMCPY(decBuf, encIdentity, encIdentitySz);
        rc = wc_AesInit(aes, NULL, INVALID_DEVID);
        if (rc == 0)
            rc = wc_AesSetKey(aes, symKey, (word32)symKeySz, iv,
                AES_ENCRYPTION);
        if (rc == 0)
            rc = wc_AesCfbDecrypt(aes, decBuf, decBuf, encIdentitySz);
        wc_AesFree(aes);
        if (rc != 0)
            rc = TPM_RC_FAILURE;
    }

    /* Extract credential: first 2 bytes = size */
    if (rc == 0) {
        if (encIdentitySz < 2) {
            rc = TPM_RC_SIZE;
        }
    }
    if (rc == 0) {
        *credSzOut = FwLoadU16BE(decBuf);
        if (*credSzOut > encIdentitySz - 2 || *credSzOut > credBufSz) {
            rc = TPM_RC_SIZE;
        }
    }
    if (rc == 0) {
        XMEMCPY(credOut, decBuf + 2, *credSzOut);
    }

    TPM2_ForceZero(decBuf, FWTPM_MAX_NV_DATA + 2);
    TPM2_ForceZero(computedHmac, sizeof(computedHmac));
    TPM2_ForceZero(integrityHmac, sizeof(integrityHmac));
    FWTPM_FREE_BUF(decBuf);
    FWTPM_FREE_VAR(aes);
    FWTPM_FREE_VAR(hmac);
    return rc;
}

#endif /* !FWTPM_NO_CREDENTIAL */

#endif /* WOLFTPM_FWTPM */
