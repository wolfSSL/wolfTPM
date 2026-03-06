/* spdm_crypto.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSPDM.
 *
 * wolfSPDM is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSPDM is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#include "spdm_internal.h"

/* Left-pad a buffer in-place to targetSz with leading zeros */
static void wolfSPDM_LeftPadToSize(byte* buf, word32 currentSz, word32 targetSz)
{
    if (currentSz < targetSz) {
        word32 padLen = targetSz - currentSz;
        XMEMMOVE(buf + padLen, buf, currentSz);
        XMEMSET(buf, 0, padLen);
    }
}

/* --- Random Number Generation --- */

int wolfSPDM_GetRandom(WOLFSPDM_CTX* ctx, byte* out, word32 outSz)
{
    int rc;

    if (ctx == NULL || out == NULL || outSz == 0) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (!ctx->flags.rngInitialized) {
        return WOLFSPDM_E_BAD_STATE;
    }

    rc = wc_RNG_GenerateBlock(&ctx->rng, out, outSz);
    if (rc != 0) {
        return WOLFSPDM_E_CRYPTO_FAIL;
    }

    return WOLFSPDM_SUCCESS;
}

/* --- ECDHE Key Generation (P-384) --- */

int wolfSPDM_GenerateEphemeralKey(WOLFSPDM_CTX* ctx)
{
    int rc;

    if (ctx == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (!ctx->flags.rngInitialized) {
        return WOLFSPDM_E_BAD_STATE;
    }

    /* Free existing key if any */
    if (ctx->flags.ephemeralKeyInit) {
        wc_ecc_free(&ctx->ephemeralKey);
        ctx->flags.ephemeralKeyInit = 0;
    }

    /* Initialize new key */
    rc = wc_ecc_init(&ctx->ephemeralKey);
    if (rc != 0) {
        return WOLFSPDM_E_CRYPTO_FAIL;
    }

    /* Generate P-384 key pair */
    rc = wc_ecc_make_key(&ctx->rng, WOLFSPDM_ECC_KEY_SIZE, &ctx->ephemeralKey);
    if (rc != 0) {
        wc_ecc_free(&ctx->ephemeralKey);
        return WOLFSPDM_E_CRYPTO_FAIL;
    }

    ctx->flags.ephemeralKeyInit = 1;
    wolfSPDM_DebugPrint(ctx, "Generated P-384 ephemeral key\n");

    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_ExportEphemeralPubKey(WOLFSPDM_CTX* ctx,
    byte* pubKeyX, word32* pubKeyXSz,
    byte* pubKeyY, word32* pubKeyYSz)
{
    int rc;

    if (ctx == NULL || pubKeyX == NULL || pubKeyXSz == NULL ||
        pubKeyY == NULL || pubKeyYSz == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (!ctx->flags.ephemeralKeyInit) {
        return WOLFSPDM_E_BAD_STATE;
    }

    if (*pubKeyXSz < WOLFSPDM_ECC_KEY_SIZE ||
        *pubKeyYSz < WOLFSPDM_ECC_KEY_SIZE) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    rc = wc_ecc_export_public_raw(&ctx->ephemeralKey,
        pubKeyX, pubKeyXSz, pubKeyY, pubKeyYSz);
    if (rc != 0) {
        return WOLFSPDM_E_CRYPTO_FAIL;
    }

    /* Left-pad coordinates to full size (wolfSSL may strip leading zeros) */
    wolfSPDM_LeftPadToSize(pubKeyX, *pubKeyXSz, WOLFSPDM_ECC_KEY_SIZE);
    *pubKeyXSz = WOLFSPDM_ECC_KEY_SIZE;
    wolfSPDM_LeftPadToSize(pubKeyY, *pubKeyYSz, WOLFSPDM_ECC_KEY_SIZE);
    *pubKeyYSz = WOLFSPDM_ECC_KEY_SIZE;

    return WOLFSPDM_SUCCESS;
}

/* --- ECDH Shared Secret Computation --- */

int wolfSPDM_ComputeSharedSecret(WOLFSPDM_CTX* ctx,
    const byte* peerPubKeyX, const byte* peerPubKeyY)
{
    ecc_key peerKey;
    int rc;
    int peerKeyInit = 0;

    if (ctx == NULL || peerPubKeyX == NULL || peerPubKeyY == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (!ctx->flags.ephemeralKeyInit) {
        return WOLFSPDM_E_BAD_STATE;
    }

    /* Initialize peer key structure */
    rc = wc_ecc_init(&peerKey);
    if (rc != 0) {
        return WOLFSPDM_E_CRYPTO_FAIL;
    }
    peerKeyInit = 1;

    /* Import peer's public key */
    rc = wc_ecc_import_unsigned(&peerKey,
        peerPubKeyX, peerPubKeyY,
        NULL,  /* No private key */
        ECC_SECP384R1);
    if (rc != 0) {
        wolfSPDM_DebugPrint(ctx, "Failed to import peer public key: %d\n", rc);
        goto cleanup;
    }

    /* Compute ECDH shared secret */
    ctx->sharedSecretSz = sizeof(ctx->sharedSecret);
    rc = wc_ecc_shared_secret(&ctx->ephemeralKey, &peerKey,
        ctx->sharedSecret, &ctx->sharedSecretSz);
    if (rc != 0) {
        wolfSPDM_DebugPrint(ctx, "ECDH shared_secret failed: %d\n", rc);
        goto cleanup;
    }

    /* Zero-pad if needed (P-384 should always return 48 bytes, but just in case) */
    wolfSPDM_LeftPadToSize(ctx->sharedSecret, ctx->sharedSecretSz,
        WOLFSPDM_ECC_KEY_SIZE);
    ctx->sharedSecretSz = WOLFSPDM_ECC_KEY_SIZE;

    wolfSPDM_DebugPrint(ctx, "ECDH shared secret computed (%u bytes)\n",
        ctx->sharedSecretSz);

    rc = 0;

cleanup:
    if (peerKeyInit) {
        wc_ecc_free(&peerKey);
    }

    return (rc == 0) ? WOLFSPDM_SUCCESS : WOLFSPDM_E_CRYPTO_FAIL;
}

/* --- ECDSA Signing (P-384) --- */

int wolfSPDM_SignHash(WOLFSPDM_CTX* ctx, const byte* hash, word32 hashSz,
    byte* sig, word32* sigSz)
{
    ecc_key sigKey;
    int rc;
    int keyInit = 0;
    byte derSig[104];  /* P-384 DER sig max: 2 + (2+49) + (2+49) = 104 */
    word32 derSigSz = sizeof(derSig);
    word32 rLen, sLen;

    if (ctx == NULL || hash == NULL || sig == NULL || sigSz == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (!ctx->flags.hasReqKeyPair || ctx->reqPrivKeyLen == 0) {
        wolfSPDM_DebugPrint(ctx, "No requester key pair for signing\n");
        return WOLFSPDM_E_BAD_STATE;
    }

    /* Need at least 96 bytes for P-384 signature (R||S) */
    if (*sigSz < WOLFSPDM_ECC_POINT_SIZE) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    /* Initialize key structure */
    rc = wc_ecc_init(&sigKey);
    if (rc != 0) {
        wolfSPDM_DebugPrint(ctx, "wc_ecc_init failed: %d\n", rc);
        return WOLFSPDM_E_CRYPTO_FAIL;
    }
    keyInit = 1;

    /* Import private key and public key */
    rc = wc_ecc_import_unsigned(&sigKey,
        ctx->reqPubKey,                         /* X coordinate */
        ctx->reqPubKey + WOLFSPDM_ECC_KEY_SIZE, /* Y coordinate */
        ctx->reqPrivKey,                        /* Private key (d) */
        ECC_SECP384R1);
    if (rc != 0) {
        wolfSPDM_DebugPrint(ctx, "wc_ecc_import_unsigned failed: %d\n", rc);
        goto cleanup;
    }

    /* Sign the hash - wolfSSL returns DER encoded signature */
    rc = wc_ecc_sign_hash(hash, hashSz, derSig, &derSigSz, &ctx->rng, &sigKey);
    if (rc != 0) {
        wolfSPDM_DebugPrint(ctx, "wc_ecc_sign_hash failed: %d\n", rc);
        goto cleanup;
    }

    /* Convert DER signature to raw R||S format (96 bytes for P-384) */
    rLen = WOLFSPDM_ECC_KEY_SIZE;
    sLen = WOLFSPDM_ECC_KEY_SIZE;
    rc = wc_ecc_sig_to_rs(derSig, derSigSz, sig, &rLen,
                          sig + WOLFSPDM_ECC_KEY_SIZE, &sLen);
    if (rc != 0) {
        wolfSPDM_DebugPrint(ctx, "wc_ecc_sig_to_rs failed: %d\n", rc);
        goto cleanup;
    }

    /* Pad R and S to 48 bytes if needed */
    wolfSPDM_LeftPadToSize(sig, rLen, WOLFSPDM_ECC_KEY_SIZE);
    wolfSPDM_LeftPadToSize(sig + WOLFSPDM_ECC_KEY_SIZE, sLen,
        WOLFSPDM_ECC_KEY_SIZE);

    *sigSz = WOLFSPDM_ECC_POINT_SIZE; /* 96 bytes */

    wolfSPDM_DebugPrint(ctx, "Signed hash with P-384 key (sig=%u bytes)\n", *sigSz);

    rc = 0;

cleanup:
    if (keyInit) {
        wc_ecc_free(&sigKey);
    }

    return (rc == 0) ? WOLFSPDM_SUCCESS : WOLFSPDM_E_CRYPTO_FAIL;
}
