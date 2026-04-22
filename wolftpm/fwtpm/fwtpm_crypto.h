/* fwtpm_crypto.h
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

#ifndef _FWTPM_CRYPTO_H_
#define _FWTPM_CRYPTO_H_

#ifdef WOLFTPM_FWTPM

#include <wolftpm/fwtpm/fwtpm.h>
#include <wolftpm/tpm2_crypto.h>

#ifndef WOLFTPM2_NO_WOLFCRYPT
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/hmac.h>
#ifndef NO_RSA
#include <wolfssl/wolfcrypt/rsa.h>
#endif
#ifdef HAVE_ECC
#include <wolfssl/wolfcrypt/ecc.h>
#endif
#ifndef NO_AES
#include <wolfssl/wolfcrypt/aes.h>
#endif
#endif /* !WOLFTPM2_NO_WOLFCRYPT */

#ifdef __cplusplus
    extern "C" {
#endif

/* --- Small utility helpers --- */

enum wc_HashType FwGetWcHashType(UINT16 hashAlg);
#ifndef NO_RSA
int FwGetMgfType(UINT16 hashAlg);
#endif

int FwComputeUniqueHash(TPMI_ALG_HASH nameAlg, const byte* keyData,
    int keyDataSz, byte* outBuf);

/* hashUnique = H(sensitiveCreate.data || unique_bytes) for primary derivation */
int FwComputeHashUnique(TPMI_ALG_HASH nameAlg,
    const byte* sensData, int sensDataSz,
    const byte* uniqueData, int uniqueDataSz,
    byte* hashOut);

/* Derive symmetric primary key via KDFa (KEYEDHASH / SYMCIPHER) */
TPM_RC FwDeriveSymmetricPrimaryKey(TPMI_ALG_HASH nameAlg,
    const byte* seed, const byte* hashUnique, int hashUniqueSz,
    const char* label, byte* keyOut, int keySz);

/* --- Object/NV name computation --- */

int FwComputeObjectName(FWTPM_Object* obj);

byte* FwGetHierarchySeed(FWTPM_CTX* ctx, UINT32 hierarchy);

int FwComputeProofValue(FWTPM_CTX* ctx, UINT32 hierarchy,
    TPMI_ALG_HASH hashAlg, byte* proofOut, int proofSize);

int FwComputeTicketHmac(FWTPM_CTX* ctx, UINT32 hierarchy,
    TPMI_ALG_HASH hashAlg,
    const byte* data, int dataSz,
    byte* hmacOut, int* hmacOutSz);

int FwAppendTicket(FWTPM_CTX* ctx, TPM2_Packet* rsp,
    UINT16 ticketTag, UINT32 hierarchy, TPMI_ALG_HASH hashAlg,
    const byte* data, int dataSz);

int FwAppendCreationHashAndTicket(FWTPM_CTX* ctx, TPM2_Packet* rsp,
    UINT32 hierarchy, TPMI_ALG_HASH nameAlg,
    int cdStart, int cdSize,
    const byte* objName, int objNameSz);

/* --- ECC curve helpers --- */

#ifdef HAVE_ECC
int FwGetWcCurveId(UINT16 tpmCurve);
#endif

int FwGetEccKeySize(UINT16 tpmCurve);

/* --- Key generation --- */

#ifndef NO_RSA
#ifdef WOLFSSL_KEY_GEN
TPM_RC FwGenerateRsaKey(WC_RNG* rng,
    int keyBits, UINT32 exponent,
    TPM2B_PUBLIC_KEY_RSA* pubOut,
    byte* privKeyDer, int privKeyDerBufSz, int* privKeyDerSz);
#endif /* WOLFSSL_KEY_GEN */
#endif /* !NO_RSA */

#ifdef HAVE_ECC
TPM_RC FwGenerateEccKey(WC_RNG* rng,
    UINT16 curveId,
    TPMS_ECC_POINT* pubOut,
    byte* privKeyDer, int privKeyDerBufSz, int* privKeyDerSz);
#endif /* HAVE_ECC */

/* --- Seed-based primary key derivation (TPM 2.0 Part 1 Section 26) --- */

#ifdef HAVE_ECC
TPM_RC FwDeriveEccPrimaryKey(TPMI_ALG_HASH nameAlg,
    const byte* seed, const byte* hashUnique, int hashUniqueSz,
    UINT16 curveId, TPMS_ECC_POINT* pubOut,
    byte* privKeyDer, int privKeyDerBufSz, int* privKeyDerSz);
#endif

#ifndef NO_RSA
#ifdef WOLFSSL_KEY_GEN
TPM_RC FwDeriveRsaPrimaryKey(TPMI_ALG_HASH nameAlg,
    const byte* seed, const byte* hashUnique, int hashUniqueSz,
    int keyBits, UINT32 exponent, WC_RNG* rng,
    TPM2B_PUBLIC_KEY_RSA* pubOut,
    byte* privKeyDer, int privKeyDerBufSz, int* privKeyDerSz);
#endif /* WOLFSSL_KEY_GEN */
#endif /* !NO_RSA */

/* --- Key wrapping --- */

int FwDeriveWrapKey(const FWTPM_Object* parent,
    byte* aesKey, byte* aesIV);

int FwMarshalSensitive(byte* buf, int bufSz,
    UINT16 sensitiveType, const TPM2B_AUTH* auth,
    const byte* privKeyDer, int privKeyDerSz);

int FwMarshalSensitiveStd(byte* buf, int bufSz,
    UINT16 sensitiveType, const TPM2B_AUTH* auth,
    const byte* sensData, int sensDataSz);

int FwUnmarshalSensitive(const byte* buf, int bufSz,
    UINT16* sensitiveType, TPM2B_AUTH* auth,
    byte* privKeyDer, int* privKeyDerSz);

int FwWrapPrivate(FWTPM_Object* parent,
    UINT16 sensitiveType, const TPM2B_AUTH* auth,
    const byte* privKeyDer, int privKeyDerSz,
    TPM2B_PRIVATE* outPriv);

int FwUnwrapPrivate(FWTPM_Object* parent,
    const TPM2B_PRIVATE* inPriv,
    UINT16* sensitiveType, TPM2B_AUTH* auth,
    byte* privKeyDer, int* privKeyDerSz);

/* --- Context blob wrap/unwrap (ContextSave/Load) --- */

int FwWrapContextBlob(FWTPM_CTX* ctx,
    const byte* plain, int plainSz,
    byte* out, int outBufSz, int* outSz);
int FwUnwrapContextBlob(FWTPM_CTX* ctx,
    const byte* in, int inSz,
    byte* out, int outBufSz, int* outSz);

/* --- Seed encrypt/decrypt --- */

TPM_RC FwDecryptSeed(FWTPM_CTX* ctx,
    const FWTPM_Object* keyObj,
    const byte* encSeedBuf, UINT16 encSeedSz,
    const byte* oaepLabel, int oaepLabelSz,
    const char* kdfLabel,
    byte* seedBuf, int seedBufSz, int* seedSzOut);

TPM_RC FwEncryptSeed(FWTPM_CTX* ctx,
    const FWTPM_Object* keyObj,
    const byte* oaepLabel, int oaepLabelSz,
    const char* kdfLabel,
    byte* seedBuf, int seedBufSz, int* seedSzOut,
    byte* encSeedBuf, int encSeedBufSz, int* encSeedSzOut);

/* --- Import helpers --- */

TPM_RC FwImportVerifyAndDecrypt(
    TPMI_ALG_HASH parentNameAlg,
    const byte* hmacKeyBuf, int digestSz,
    const byte* aesKey, int symKeySz,
    const byte* nameBuf, int nameSz,
    const byte* dupBuf, UINT16 dupSz,
    byte* plainSens, int plainSensBufSz, int* plainSensSzOut);

TPM_RC FwImportParseSensitive(
    const byte* plainSens, int plainSensSz,
    UINT16* sensType, TPM2B_AUTH* importedAuth,
    UINT16* primeSzOut, byte* primeBuf, int primeBufSz);

TPM_RC FwImportReconstructKey(
    const TPM2B_PUBLIC* objectPublic, UINT16 sensType,
    const byte* primeBuf, UINT16 primeSz,
    byte* privKeyDer, int privKeyDerBufSz, int* privKeyDerSzOut);

/* --- Key import from DER/Public --- */

#ifndef NO_RSA
int FwImportRsaKeyFromDer(const FWTPM_Object* obj, RsaKey* key);
int FwImportRsaPubFromPublic(const TPMT_PUBLIC* pub, RsaKey* key);
int FwImportRsaKey(const FWTPM_Object* obj, RsaKey* key);
int FwRsaComputeCRT(RsaKey* rsaKey);
int FwGetRsaPadding(UINT16 scheme);
int FwGetRsaHashOid(UINT16 hashAlg);
#endif /* !NO_RSA */

#ifdef HAVE_ECC
int FwImportEccKeyFromDer(const FWTPM_Object* obj, ecc_key* key);
int FwImportEccPubFromPublic(const TPMT_PUBLIC* pub, ecc_key* key);
int FwImportEccKey(const FWTPM_Object* obj, ecc_key* key);
int FwEccSharedPoint(ecc_key* priv, ecc_key* peer,
    byte* xBuf, word32* xSz, byte* yBuf, word32* ySz);
#endif /* HAVE_ECC */

/* --- Sign/Verify --- */

TPM_RC FwSignDigestAndAppend(FWTPM_CTX* ctx, FWTPM_Object* obj,
    UINT16 sigScheme, UINT16 sigHashAlg,
    const byte* digest, int digestSz, TPM2_Packet* rsp);

TPM_RC FwVerifySignatureCore(FWTPM_Object* obj,
    const byte* digest, int digestSz, const TPMT_SIGNATURE* sig);

/* --- NV name computation --- */

#ifndef FWTPM_NO_NV
int FwComputeNvName(FWTPM_NvIndex* nv, byte* buf, UINT16* sz);
#endif /* !FWTPM_NO_NV */

/* --- Attestation helpers --- */

void FwResolveSignScheme(FWTPM_Object* obj, UINT16* sigScheme,
    UINT16* sigHashAlg);

#ifndef FWTPM_NO_ATTESTATION
TPM_RC FwBuildAttestResponse(FWTPM_CTX* ctx, TPM2_Packet* rsp,
    UINT16 cmdTag, FWTPM_Object* sigObj, UINT16 sigScheme, UINT16 sigHashAlg,
    byte* attestBuf, int attestSize);

TPM_RC FwSignAttest(FWTPM_CTX* ctx, FWTPM_Object* obj,
    UINT16 sigScheme, UINT16 sigHashAlg,
    const byte* attestBuf, int attestSz,
    TPM2_Packet* rsp);
#endif /* !FWTPM_NO_ATTESTATION */

/* --- Credential helpers --- */

#ifndef FWTPM_NO_CREDENTIAL
TPM_RC FwCredentialDeriveKeys(
    const byte* seed, int seedSz,
    const byte* name, int nameSz,
    byte* symKey, int symKeySz,
    byte* hmacKey, int hmacKeySz);

TPM_RC FwCredentialWrap(
    const byte* symKey, int symKeySz,
    const byte* hmacKey, int hmacKeySz,
    const byte* credential, UINT16 credSz,
    const byte* name, int nameSz,
    byte* encCred, word32* encCredSz,
    byte* outerHmac);

TPM_RC FwCredentialUnwrap(
    const byte* symKey, int symKeySz,
    const byte* hmacKey, int hmacKeySz,
    const byte* blobBuf, UINT16 blobSz,
    const byte* name, int nameSz,
    byte* credOut, int credBufSz, UINT16* credSzOut);
#endif /* !FWTPM_NO_CREDENTIAL */

/* --- Response helpers (defined in fwtpm_command.c, used by attestation) --- */

int FwRspParamsBegin(TPM2_Packet* rsp, UINT16 cmdTag, int* paramSzPos);
void FwRspParamsEnd(TPM2_Packet* rsp, UINT16 cmdTag,
    int paramSzPos, int paramStart);

#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* WOLFTPM_FWTPM */

#endif /* _FWTPM_CRYPTO_H_ */
