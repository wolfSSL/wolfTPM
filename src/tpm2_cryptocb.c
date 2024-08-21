/* tpm2_cryptocb.c
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
 *
 * This file is part of wolfTPM.
 *
 * wolfTPM is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2_wrap.h>

#if !defined(WOLFTPM2_NO_WRAPPER)

#if defined(HAVE_ECC) && (defined(WOLFTPM_CRYPTOCB) || \
   (defined(HAVE_PK_CALLBACKS) && !defined(WOLFCRYPT_ONLY)))
/* Helper to trim leading zeros when not required  */
static byte* wolfTPM2_ASNTrimZeros(byte* in, word32* len)
{
    word32 idx = 0;
    while (idx+1 < *len && in[idx] == 0 && (in[idx+1] & 0x80) == 0) {
        idx++;
        in++;
    }
    *len -= idx;
    return in;
}
#endif

#ifdef WOLFTPM_CRYPTOCB

/* Internal structure for tracking hash state */
typedef struct WOLFTPM2_HASHCTX {
    TPM_HANDLE handle;
#ifdef WOLFTPM_USE_SYMMETRIC
    byte*  cacheBuf;   /* buffer */
    word32 cacheBufSz; /* buffer size */
    word32 cacheSz;    /* filled size */
#endif
} WOLFTPM2_HASHCTX;

#ifdef WOLFTPM_USE_SYMMETRIC
#ifndef WOLFTPM2_HASH_BLOCK_SZ
#define WOLFTPM2_HASH_BLOCK_SZ 256
#endif

/* Forward declaration */
static int wolfTPM2_HashUpdateCache(WOLFTPM2_HASHCTX* hashCtx,
    const byte* in, word32 inSz);
#endif /* WOLFTPM_USE_SYMMETRIC */

int wolfTPM2_CryptoDevCb(int devId, wc_CryptoInfo* info, void* ctx)
{
    int rc = CRYPTOCB_UNAVAILABLE;
    int exit_rc;
    TpmCryptoDevCtx* tlsCtx = (TpmCryptoDevCtx*)ctx;

    if (info == NULL || ctx == NULL || tlsCtx->dev == NULL)
        return BAD_FUNC_ARG;

    /* for FIPS mode default error is not allowed, otherwise try and fallback
        to software crypto */
    exit_rc = tlsCtx->useFIPSMode ? FIPS_NOT_ALLOWED_E : CRYPTOCB_UNAVAILABLE;

    (void)devId;

#if defined(DEBUG_CRYPTOCB) && defined(DEBUG_WOLFTPM)
    wc_CryptoCb_InfoString(info);
#endif

    if (info->algo_type == WC_ALGO_TYPE_RNG) {
    #ifndef WC_NO_RNG
        rc = wolfTPM2_GetRandom(tlsCtx->dev, info->rng.out, info->rng.sz);
    #endif /* !WC_NO_RNG */
    }
    else if (info->algo_type == WC_ALGO_TYPE_SEED) {
    #ifndef WC_NO_RNG
        rc = wolfTPM2_GetRandom(tlsCtx->dev, info->seed.seed, info->seed.sz);
    #endif /* !WC_NO_RNG */
    }
#if !defined(NO_RSA) || defined(HAVE_ECC)
    else if (info->algo_type == WC_ALGO_TYPE_PK) {
    #ifndef NO_RSA
        /* RSA */
        if (info->pk.type == WC_PK_TYPE_RSA_KEYGEN) {
        #ifdef WOLFSSL_KEY_GEN
            if (tlsCtx->rsaKeyGen != NULL && tlsCtx->storageKey != NULL) {
                /* create a new RSA key */
                TPMT_PUBLIC publicTemplate;
                XMEMSET(&publicTemplate, 0, sizeof(publicTemplate));
                rc = GetKeyTemplateRSA(&publicTemplate,
                    WOLFTPM2_WRAP_DIGEST,   /* name algorithm */
                    (                       /* objectAttributes */
                        TPMA_OBJECT_sensitiveDataOrigin |
                        TPMA_OBJECT_userWithAuth |
                        TPMA_OBJECT_decrypt |
                        TPMA_OBJECT_noDA
                    ),
                    info->pk.rsakg.size,    /* keyBits */
                    info->pk.rsakg.e,       /* exponent */
                    TPM_ALG_NULL,           /* sigScheme */
                    WOLFTPM2_WRAP_DIGEST    /* sigHash */
                );
                if (rc == 0) {
                    rc = wolfTPM2_CreateKey(tlsCtx->dev, tlsCtx->rsaKeyGen,
                        &tlsCtx->storageKey->handle, &publicTemplate, NULL, 0);
                }
                if (rc == 0) {
                    rc = wolfTPM2_LoadKey(tlsCtx->dev, tlsCtx->rsaKeyGen,
                        &tlsCtx->storageKey->handle);
                }
                if (rc == 0) {
                    /* export public portion of new key to wolf RsaKey struct */
                    rc = wolfTPM2_RsaKey_TpmToWolf(tlsCtx->dev,
                        (WOLFTPM2_KEY*)tlsCtx->rsaKeyGen, info->pk.rsakg.key);
                }
            }
            else
        #endif
                rc = exit_rc;
        }
        else if (info->pk.type == WC_PK_TYPE_RSA) {
            switch (info->pk.rsa.type) {
                case RSA_PUBLIC_ENCRYPT:
                case RSA_PUBLIC_DECRYPT:
                {
                    /* public operations */
                    WOLFTPM2_KEY rsaPub;

                    /* load public key into TPM */
                    XMEMSET(&rsaPub, 0, sizeof(rsaPub));
                    rc = wolfTPM2_RsaKey_WolfToTpm(tlsCtx->dev,
                        info->pk.rsa.key, &rsaPub);
                    if (rc != 0) {
                        /* A failure of TPM_RC_KEY can happen due to unsupported
                         * RSA exponent. For those cases fallback to using
                         * software (or fail if FIPS mode) */
                        rc = exit_rc;
                        break;
                    }

                    /* public operations */
                    rc = wolfTPM2_RsaEncrypt(tlsCtx->dev, &rsaPub,
                        TPM_ALG_NULL, /* no padding */
                        info->pk.rsa.in, info->pk.rsa.inLen,
                        info->pk.rsa.out, (int*)info->pk.rsa.outLen);

                    wolfTPM2_UnloadHandle(tlsCtx->dev, &rsaPub.handle);
                    break;
                }
                case RSA_PRIVATE_ENCRYPT:
                case RSA_PRIVATE_DECRYPT:
                {
                    /* private operations */
                    rc = wolfTPM2_RsaDecrypt(tlsCtx->dev, tlsCtx->rsaKey,
                        TPM_ALG_NULL, /* no padding */
                        info->pk.rsa.in, info->pk.rsa.inLen,
                        info->pk.rsa.out, (int*)info->pk.rsa.outLen);
                    break;
                }
            }
        }
    #endif /* !NO_RSA */
    #ifdef HAVE_ECC
        if (info->pk.type == WC_PK_TYPE_EC_KEYGEN) {
        #ifdef WOLFTPM2_USE_SW_ECDHE
            rc = exit_rc;
        #else
            int curve_id;
            WOLFTPM2_KEY* key;

            /* Make sure an ECDH key has been set and curve is supported */
            curve_id = info->pk.eckg.curveId;
            if (curve_id == 0 && info->pk.eckg.key->dp != NULL) {
                curve_id = info->pk.eckg.key->dp->id; /* use dp */
            }
            rc = TPM2_GetTpmCurve(curve_id);
            if (rc < 0 || (tlsCtx->ecdhKey == NULL && tlsCtx->eccKey == NULL)) {
                return exit_rc;
            }
            curve_id = rc;
            rc = 0;

            /* If ecdhKey is NULL then it is a signing key */
            if (tlsCtx->ecdhKey == NULL) {
                /* Create an ECC key for ECDSA - if one isn't already created */
                key = tlsCtx->eccKey;
                if (key->handle.hndl == 0 ||
                    key->handle.hndl == TPM_RH_NULL
                ) {
                    TPMT_PUBLIC publicTemplate;
                    XMEMSET(&publicTemplate, 0, sizeof(publicTemplate));

                    rc = wolfTPM2_GetKeyTemplate_ECC(&publicTemplate,
                        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
                        TPMA_OBJECT_sign | TPMA_OBJECT_noDA,
                        curve_id, TPM_ALG_ECDSA);
                    if (rc == 0) {
                        publicTemplate.nameAlg = TPM_ALG_SHA256; /* make sure its SHA256 */
                        rc = wolfTPM2_CreateAndLoadKey(tlsCtx->dev, key,
                            &tlsCtx->storageKey->handle, &publicTemplate,
                            (byte*)key->handle.auth.buffer,
                            key->handle.auth.size);
                    }
                }
            }
            else {
                /* Generate ephemeral key - if one isn't already created */
                key = tlsCtx->ecdhKey;
                if (key->handle.hndl == 0 ||
                    key->handle.hndl == TPM_RH_NULL) {
                    rc = wolfTPM2_ECDHGenKey(tlsCtx->dev, key, curve_id,
                        NULL, 0 /* no auth for ephemeral key */
                    );
                }
            }
            if (rc == 0) {
                /* Export public key info to wolf ecc_key */
                rc = wolfTPM2_EccKey_TpmToWolf(tlsCtx->dev, key,
                    info->pk.eckg.key);
                if (rc != 0) {
                    /* if failure, release key */
                    wolfTPM2_UnloadHandle(tlsCtx->dev, &tlsCtx->ecdhKey->handle);
                }
            }
            else if (rc & TPM_RC_CURVE) {
                /* if the curve is not supported on TPM, then fall-back to software */
                rc = exit_rc;
                /* Make sure ECDHE key indicates nothing loaded */
                key->handle.hndl = TPM_RH_NULL;
            }
        #endif /* WOLFTPM2_USE_SW_ECDHE */
        }
        else if (info->pk.type == WC_PK_TYPE_ECDSA_SIGN) {
            byte sigRS[MAX_ECC_BYTES*2];
            word32 rsLen = sizeof(sigRS), keySz;
            word32 inlen = info->pk.eccsign.inlen;

            /* get key size from wolf signing key */
            keySz = wc_ecc_size(info->pk.eccsign.key);
            if (keySz == 0) {
                /* if not populated fallback to key size for TPM key */
                keySz = TPM2_GetCurveSize(
                   tlsCtx->eccKey->pub.publicArea.parameters.eccDetail.curveID);
            }
            /* truncate input to match key size */
            if (inlen > keySz)
                inlen = keySz;

            rc = wolfTPM2_SignHash(tlsCtx->dev, tlsCtx->eccKey,
                info->pk.eccsign.in, inlen, sigRS, (int*)&rsLen);
            if (rc == 0) {
                byte *r, *s;
                word32 rLen, sLen;

                /* Make sure leading zero's not required are trimmed */
                rLen = sLen = rsLen / 2;
                r = &sigRS[0];
                s = &sigRS[rLen];
                r = wolfTPM2_ASNTrimZeros(r, &rLen);
                s = wolfTPM2_ASNTrimZeros(s, &sLen);

                /* Encode ECDSA Header */
                rc = wc_ecc_rs_raw_to_sig(r, rLen, s, sLen,
                    info->pk.eccsign.out, info->pk.eccsign.outlen);
            }
        }
        else if (info->pk.type == WC_PK_TYPE_ECDSA_VERIFY) {
            WOLFTPM2_KEY eccPub;
            byte sigRS[MAX_ECC_BYTES*2];
            byte *r = sigRS, *s = &sigRS[MAX_ECC_BYTES];
            word32 rLen = MAX_ECC_BYTES, sLen = MAX_ECC_BYTES;

            XMEMSET(&eccPub, 0, sizeof(eccPub));
            XMEMSET(sigRS, 0, sizeof(sigRS));

            /* Decode ECDSA Header */
            rc = wc_ecc_sig_to_rs(info->pk.eccverify.sig,
                info->pk.eccverify.siglen, r, &rLen, s, &sLen);
            if (rc == 0) {
                /* load public key into TPM */
                rc = wolfTPM2_EccKey_WolfToTpm(tlsCtx->dev,
                    info->pk.eccverify.key, &eccPub);
                if (rc == 0) {
                    /* combine R and S at key size (zero pad leading) */
                    word32 keySz = wc_ecc_size(info->pk.eccverify.key);
                    XMEMCPY(&sigRS[keySz-rLen], r, rLen);
                    XMEMSET(&sigRS[0], 0, keySz-rLen);
                    XMEMCPY(&sigRS[keySz + (keySz-sLen)], s, sLen);
                    XMEMSET(&sigRS[keySz], 0, keySz-sLen);
                    rc = wolfTPM2_VerifyHash(tlsCtx->dev, &eccPub,
                        sigRS, keySz*2,
                        info->pk.eccverify.hash, info->pk.eccverify.hashlen);
                    if (info->pk.eccverify.res) {
                        if ((rc & TPM_RC_SIGNATURE) == TPM_RC_SIGNATURE) {
                            /* mark invalid signature */
                            *info->pk.eccverify.res = 0;
                            rc = 0;
                        }
                        else if (rc == 0) {
                            *info->pk.eccverify.res = 1;
                        }
                    }
                    wolfTPM2_UnloadHandle(tlsCtx->dev, &eccPub.handle);
                }
                else if (rc & TPM_RC_CURVE) {
                    /* if the curve is not supported on TPM, then fall-back to software */
                    rc = exit_rc;
                }
            }
        }
        else if (info->pk.type == WC_PK_TYPE_ECDH) {
        #ifdef WOLFTPM2_USE_SW_ECDHE
            rc = exit_rc;
        #else
            TPM2B_ECC_POINT pubPoint;

            /* Make sure an ECDH key has been set */
            if (tlsCtx->ecdhKey == NULL || tlsCtx->eccKey == NULL ||
                    tlsCtx->ecdhKey->handle.hndl == TPM_RH_NULL) {
                return exit_rc;
            }

            rc = wolfTPM2_EccKey_WolfToPubPoint(tlsCtx->dev,
                info->pk.ecdh.public_key, &pubPoint);
            if (rc == 0) {
                /* Compute shared secret and compare results */
                rc = wolfTPM2_ECDHGenZ(tlsCtx->dev, tlsCtx->ecdhKey,
                    &pubPoint, info->pk.ecdh.out, (int*)info->pk.ecdh.outlen);
            }

            /* done with ephemeral key */
            wolfTPM2_UnloadHandle(tlsCtx->dev, &tlsCtx->ecdhKey->handle);
        #endif /* !WOLFTPM2_USE_SW_ECDHE */
        }
    #endif /* HAVE_ECC */
    }
#endif /* !NO_RSA || HAVE_ECC */
#ifndef NO_AES
    else if (info->algo_type == WC_ALGO_TYPE_CIPHER) {
        if (info->cipher.type != WC_CIPHER_AES_CBC) {
            return exit_rc;
        }

    #ifdef WOLFTPM_USE_SYMMETRIC
        if (info->cipher.aescbc.aes) {
            WOLFTPM2_KEY symKey;
            Aes* aes = info->cipher.aescbc.aes;

            if (aes == NULL) {
                return BAD_FUNC_ARG;
            }

            if (!tlsCtx->useSymmetricOnTPM) {
                return exit_rc;
            }

            /* load key */
            XMEMSET(&symKey, 0, sizeof(symKey));
            rc = wolfTPM2_LoadSymmetricKey(tlsCtx->dev, &symKey,
                TPM_ALG_CBC, (byte*)aes->devKey, aes->keylen);
            if (rc == 0) {
                /* perform symmetric encrypt/decrypt */
                rc = wolfTPM2_EncryptDecrypt(tlsCtx->dev, &symKey,
                    info->cipher.aescbc.in,
                    info->cipher.aescbc.out,
                    info->cipher.aescbc.sz,
                    (byte*)aes->reg, MAX_AES_BLOCK_SIZE_BYTES,
                    info->cipher.enc ? WOLFTPM2_ENCRYPT : WOLFTPM2_DECRYPT);

                /* done with handle */
                wolfTPM2_UnloadHandle(tlsCtx->dev, &symKey.handle);
            }
        }
    #endif /* WOLFTPM_USE_SYMMETRIC */
    }
#endif /* !NO_AES */
#if !defined(NO_SHA) || !defined(NO_SHA256)
    else if (info->algo_type == WC_ALGO_TYPE_HASH) {
    #ifdef WOLFTPM_USE_SYMMETRIC
        WOLFTPM2_HASH hash;
        WOLFTPM2_HASHCTX* hashCtx = NULL;
        TPM_ALG_ID hashAlg = TPM_ALG_ERROR;
        word32 hashFlags = 0;
    #endif

        if (info->hash.type != WC_HASH_TYPE_SHA &&
            info->hash.type != WC_HASH_TYPE_SHA256) {
            return exit_rc;
        }

    #ifdef WOLFTPM_USE_SYMMETRIC
        if (!tlsCtx->useSymmetricOnTPM) {
            return exit_rc;
        }

    #ifndef NO_SHA
        if (info->hash.type == WC_HASH_TYPE_SHA) {
            hashAlg = TPM_ALG_SHA1;
            if (info->hash.sha1) {
                hashCtx = (WOLFTPM2_HASHCTX*)info->hash.sha1->devCtx;
                hashFlags = info->hash.sha1->flags;
            }
        }
    #endif
    #ifndef NO_SHA256
        if (info->hash.type == WC_HASH_TYPE_SHA256) {
            hashAlg = TPM_ALG_SHA256;
            if (info->hash.sha256) {
                hashCtx = (WOLFTPM2_HASHCTX*)info->hash.sha256->devCtx;
                hashFlags = info->hash.sha256->flags;
            }
        }
    #endif
        if (hashAlg == TPM_ALG_ERROR) {
            return exit_rc;
        }

        XMEMSET(&hash, 0, sizeof(hash));
        if (hashCtx)
            hash.handle.hndl = hashCtx->handle;

        rc = 0; /* initialize return code */
        if (info->hash.in != NULL) { /* Update */
            /* If not single shot (update and final) then allocate context */
            if (hashCtx == NULL && info->hash.digest == NULL) {
                hashCtx = (WOLFTPM2_HASHCTX*)XMALLOC(sizeof(*hashCtx), NULL,
                    DYNAMIC_TYPE_TMP_BUFFER);
                if (hashCtx == NULL) {
                    return MEMORY_E;
                }
                XMEMSET(hashCtx, 0, sizeof(*hashCtx));
            }
            if (rc == 0) {
                if (hashCtx && (hashFlags & WC_HASH_FLAG_WILLCOPY)) {
                    rc = wolfTPM2_HashUpdateCache(hashCtx,
                        info->hash.in, info->hash.inSz);
                }
                else {
                    if (hash.handle.hndl == 0) {
                        rc = wolfTPM2_HashStart(tlsCtx->dev, &hash, hashAlg,
                            NULL, 0);
                        if (rc == 0) {
                            /* save new handle to hash context */
                            if (hashCtx)
                                hashCtx->handle = hash.handle.hndl;
                        }
                    }
                    if (rc == 0) {
                        rc = wolfTPM2_HashUpdate(tlsCtx->dev, &hash,
                            info->hash.in, info->hash.inSz);
                    }
                }
            }
        }
        if (info->hash.digest != NULL) { /* Final */
            word32 digestSz = TPM2_GetHashDigestSize(hashAlg);
            if (hashCtx && (hashFlags & WC_HASH_FLAG_WILLCOPY)) {
                if (hash.handle.hndl == 0) {
                    rc = wolfTPM2_HashStart(tlsCtx->dev, &hash, hashAlg,
                        NULL, 0);
                    if (rc == 0) {
                        /* save new handle to hash context */
                        if (hashCtx)
                            hashCtx->handle = hash.handle.hndl;
                    }
                }
                if (rc == 0) {
                    rc = wolfTPM2_HashUpdate(tlsCtx->dev, &hash,
                            hashCtx->cacheBuf, hashCtx->cacheSz);
                }
            }
            if (rc == 0) {
                rc = wolfTPM2_HashFinish(tlsCtx->dev, &hash, info->hash.digest,
                    &digestSz);
            }
        }
        /* if final or failure cleanup */
        if (info->hash.digest != NULL || rc != 0) {
            if (hashCtx) {
                hashCtx->handle = 0; /* clear hash handle */
                if ((hashFlags & WC_HASH_FLAG_ISCOPY) == 0) {
                    if (hashCtx->cacheBuf) {
                        XFREE(hashCtx->cacheBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                        hashCtx->cacheBuf = NULL;
                    }
                    XFREE(hashCtx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                }
                hashCtx = NULL;
            }
            /* Make sure hash if free'd in case of failure */
            wolfTPM2_UnloadHandle(tlsCtx->dev, &hash.handle);
        }

        /* save hashCtx to hash structure */
    #ifndef NO_SHA
        if (info->hash.type == WC_HASH_TYPE_SHA && info->hash.sha1)
            info->hash.sha1->devCtx = hashCtx;
    #endif
    #ifndef NO_SHA256
        if (info->hash.type == WC_HASH_TYPE_SHA256 && info->hash.sha256)
            info->hash.sha256->devCtx = hashCtx;
    #endif
    #endif /* WOLFTPM_USE_SYMMETRIC */
    }
#endif /* !NO_SHA || !NO_SHA256 */
#ifndef NO_HMAC
    else if (info->algo_type == WC_ALGO_TYPE_HMAC) {
    #ifdef WOLFTPM_USE_SYMMETRIC
        WOLFTPM2_HMAC* hmacCtx;
        TPM_ALG_ID hashAlg = TPM_ALG_ERROR;
    #endif

        if (info->hmac.macType != WC_HASH_TYPE_SHA &&
            info->hmac.macType != WC_HASH_TYPE_SHA256) {
            return exit_rc;
        }
        if (info->hmac.hmac == NULL) {
            /* make sure HMAC context exists */
            return exit_rc;
        }

    #ifdef WOLFTPM_USE_SYMMETRIC
        if (!tlsCtx->useSymmetricOnTPM) {
            return exit_rc;
        }

    #ifndef NO_SHA
        if (info->hmac.macType == WC_HASH_TYPE_SHA) {
            hashAlg = TPM_ALG_SHA1;
        }
    #endif
    #ifndef NO_SHA256
        if (info->hmac.macType == WC_HASH_TYPE_SHA256) {
            hashAlg = TPM_ALG_SHA256;
        }
    #endif
        if (hashAlg == TPM_ALG_ERROR) {
            return exit_rc;
        }

        hmacCtx = (WOLFTPM2_HMAC*)info->hmac.hmac->devCtx;
        if (hmacCtx && hmacCtx->hash.handle.hndl == 0) {
        #ifdef DEBUG_WOLFTPM
            printf("Error: HMAC context invalid!\n");
            return BAD_FUNC_ARG;
        #endif
        }

        if (info->hmac.in != NULL) { /* Update */
            rc = 0;
            if (hmacCtx == NULL) {
                const byte* keyBuf = info->hmac.hmac->keyRaw;
                word32 keySz = info->hmac.hmac->keyLen;

                hmacCtx = (WOLFTPM2_HMAC*)XMALLOC(sizeof(*hmacCtx), NULL,
                    DYNAMIC_TYPE_TMP_BUFFER);
                if (hmacCtx == NULL) {
                    return MEMORY_E;
                }
                XMEMSET(hmacCtx, 0, sizeof(*hmacCtx));

                rc = wolfTPM2_HmacStart(tlsCtx->dev, hmacCtx,
                    tlsCtx->storageKey ? &tlsCtx->storageKey->handle : NULL,
                    hashAlg, keyBuf, keySz, NULL, 0);
            }
            if (rc == 0) {
                rc = wolfTPM2_HmacUpdate(tlsCtx->dev, hmacCtx,
                    info->hmac.in, info->hmac.inSz);
            }
        }
        if (info->hmac.digest != NULL) { /* Final */
            word32 digestSz = TPM2_GetHashDigestSize(hashAlg);
            rc = wolfTPM2_HmacFinish(tlsCtx->dev, hmacCtx, info->hmac.digest,
                &digestSz);
        }

        /* clean hmac context */
        if (rc != 0 || info->hmac.digest != NULL) {
            wolfTPM2_UnloadHandle(tlsCtx->dev, &hmacCtx->hash.handle);
            wolfTPM2_UnloadHandle(tlsCtx->dev, &hmacCtx->key.handle);
            XFREE(hmacCtx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            hmacCtx = NULL;
        }
        info->hmac.hmac->devCtx = hmacCtx;
    #endif /* WOLFTPM_USE_SYMMETRIC */
    }
#endif /* !NO_HMAC */

    /* need to return negative here for error */
    if (rc != TPM_RC_SUCCESS && rc != exit_rc) {
    #ifdef DEBUG_WOLFTPM
        printf("wolfTPM2_CryptoDevCb failed rc = %d\n", rc);
    #endif
        rc = WC_HW_E;
    }

    return rc;
}

int wolfTPM2_SetCryptoDevCb(WOLFTPM2_DEV* dev, CryptoDevCallbackFunc cb,
    TpmCryptoDevCtx* tpmCtx, int* pDevId)
{
    int rc;
    int devId = INVALID_DEVID;

    if (dev == NULL || cb == NULL || tpmCtx == NULL) {
        return BAD_FUNC_ARG;
    }

    /* register a crypto device callback for TPM private key */
    rc = wolfTPM2_GetTpmDevId(dev);
    if (rc >= 0) {
        devId = rc;
        tpmCtx->dev = dev;

        rc = wc_CryptoCb_RegisterDevice(devId, cb, tpmCtx);
    }

    if (pDevId) {
        *pDevId = devId;
    }

    return rc;
}

int wolfTPM2_ClearCryptoDevCb(WOLFTPM2_DEV* dev, int devId)
{
    int rc = 0;

    if (dev == NULL) {
        return BAD_FUNC_ARG;
    }

    /* get device Id */
    if (devId == INVALID_DEVID) {
        rc = wolfTPM2_GetTpmDevId(dev);
        if (rc >= 0) {
            devId = rc;
            rc = 0;
        }
    }
    if (devId != INVALID_DEVID) {
        wc_CryptoCb_UnRegisterDevice(devId);
    }

    return rc;
}

#ifdef WOLFTPM_USE_SYMMETRIC
static int wolfTPM2_HashUpdateCache(WOLFTPM2_HASHCTX* hashCtx,
    const byte* in, word32 inSz)
{
    int ret = 0;

    /* allocate new cache buffer */
    if (hashCtx->cacheBuf == NULL) {
        hashCtx->cacheSz = 0;
        hashCtx->cacheBufSz = (inSz + WOLFTPM2_HASH_BLOCK_SZ - 1)
            & ~(WOLFTPM2_HASH_BLOCK_SZ - 1);
        if (hashCtx->cacheBufSz == 0)
            hashCtx->cacheBufSz = WOLFTPM2_HASH_BLOCK_SZ;
        hashCtx->cacheBuf = (byte*)XMALLOC(hashCtx->cacheBufSz,
            NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (hashCtx->cacheBuf == NULL) {
            return MEMORY_E;
        }
    }
    /* determine if we need to grow buffer */
    else if ((hashCtx->cacheSz + inSz) > hashCtx->cacheBufSz) {
        byte* oldIn = hashCtx->cacheBuf;
        hashCtx->cacheBufSz = (hashCtx->cacheSz + inSz +
            WOLFTPM2_HASH_BLOCK_SZ - 1) & ~(WOLFTPM2_HASH_BLOCK_SZ - 1);
            hashCtx->cacheBuf = (byte*)XMALLOC(hashCtx->cacheBufSz,
            NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (hashCtx->cacheBuf == NULL) {
            return MEMORY_E;
        }
        XMEMCPY(hashCtx->cacheBuf, oldIn, hashCtx->cacheSz);
        XFREE(oldIn, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    /* copy input to new buffer */
    XMEMCPY(&hashCtx->cacheBuf[hashCtx->cacheSz], in, inSz);
    hashCtx->cacheSz += inSz;

    return ret;
}
#endif /* WOLFTPM_USE_SYMMETRIC */
#endif /* WOLFTPM_CRYPTOCB */


#if defined(HAVE_PK_CALLBACKS) && !defined(WOLFCRYPT_ONLY)

#ifndef NO_RSA

#ifndef RSA_MAX_SIZE
#define RSA_MAX_SIZE 4096
#endif

/* Padding Function, PKCSv15 (not exposed in wolfCrypt FIPS 3389) */
static int RsaPadPkcsv15Type1(const byte* input, word32 inputLen,
    byte* pkcsBlock, word32 pkcsBlockLen)
{
    if (input == NULL || inputLen == 0 || pkcsBlock == NULL ||
         pkcsBlockLen == 0) {
        return BAD_FUNC_ARG;
    }
    if (pkcsBlockLen > RSA_MAX_SIZE/8) {
        return RSA_BUFFER_E;
    }
    if (pkcsBlockLen - RSA_MIN_PAD_SZ < inputLen) {
    #ifdef DEBUG_WOLFTPM
        printf("RsaPad error, invalid length\n");
    #endif
        return RSA_PAD_E;
    }

    pkcsBlock[0] = 0x0; /* set first byte to zero and advance */
    pkcsBlock++; pkcsBlockLen--;
    pkcsBlock[0] = RSA_BLOCK_TYPE_1; /* insert padValue */

    /* pad with 0xff bytes */
    XMEMSET(&pkcsBlock[1], 0xFF, pkcsBlockLen - inputLen - 2);

    pkcsBlock[pkcsBlockLen-inputLen-1] = 0; /* separator */
    XMEMCPY(pkcsBlock+pkcsBlockLen-inputLen, input, inputLen);

    return 0;
}

int wolfTPM2_PK_RsaSign(WOLFSSL* ssl,
    const unsigned char* in, unsigned int inSz,
    unsigned char* out, word32* outSz,
    const unsigned char* keyDer, unsigned int keySz,
    void* ctx)
{
    int ret;
    RsaKey rsapub;
    TpmCryptoDevCtx* tlsCtx = (TpmCryptoDevCtx*)ctx;

    (void)ssl;

#ifdef DEBUG_WOLFTPM
    printf("PK RSA Sign: inSz %u, keySz %u\n", inSz, keySz);
#endif

    /* load RSA public key */
    ret = wc_InitRsaKey(&rsapub, NULL);
    if (ret == 0) {
        word32 keyIdx = 0;
        ret = wc_RsaPublicKeyDecode(keyDer, &keyIdx, &rsapub, (word32)keySz);
        if (ret == 0) {
            byte   inPad[RSA_MAX_SIZE/8];
            word32 inPadSz = wc_RsaEncryptSize(&rsapub);
            /* Pad with PKCSv1.5 type 1 */
            ret = RsaPadPkcsv15Type1(in, inSz, inPad, inPadSz);
            if (ret == 0) {
                /* private operations */
                ret = wolfTPM2_RsaDecrypt(tlsCtx->dev, tlsCtx->rsaKey,
                    TPM_ALG_NULL, /* no padding */
                    inPad, inPadSz,
                    out, (int*)outSz);
            }
        }
        wc_FreeRsaKey(&rsapub);
    }

    if (ret > 0) {
        ret = WC_HW_E;
    }

#ifdef DEBUG_WOLFTPM
    printf("PK RSA Sign: ret %d, outSz %u\n", ret, *outSz);
#endif
    return ret;
}

int wolfTPM2_PK_RsaSignCheck(WOLFSSL* ssl,
    unsigned char* sig, unsigned int sigSz,
    unsigned char** out,
    const unsigned char* keyDer, unsigned int keySz,
    void* ctx)
{
    TpmCryptoDevCtx* tlsCtx = (TpmCryptoDevCtx*)ctx;

    (void)ssl;
    (void)sig;
    (void)sigSz;
    (void)out;
    (void)keyDer;
    (void)keySz;
    (void)tlsCtx;
    /* We used sign hardware, so assume sign is good */
    return 0;
}

#ifdef WC_RSA_PSS

/* Uses MGF1 standard as a mask generation function
   hType: hash type used
   seed:  seed to use for generating mask
   seedSz: size of seed buffer
   out:   mask output after generation
   outSz: size of output buffer
 */
static int RsaMGF1(wc_HashAlg* hash, enum wc_HashType hType,
    byte* seed, word32 seedSz, byte* out, word32 outSz)
{
    int ret;
    /* needs to be large enough for seed size plus counter(4) */
    byte tmp[WC_MAX_DIGEST_SIZE + 4];
    word32 tmpSz = 0, counter = 0, idx = 0;
    int hLen, i = 0;

    hLen = wc_HashGetDigestSize(hType);
    if (hLen < 0) {
        return hLen;
    }

    /* find largest amount of memory needed, which will be the max of
     * hLen and (seedSz + 4) */
    tmpSz = ((seedSz + 4) > (word32)hLen) ? seedSz + 4: (word32)hLen;
    if (tmpSz > sizeof(tmp)) {
        return BAD_FUNC_ARG;
    }

    XMEMSET(tmp, 0, sizeof(tmp));

    do {
        XMEMCPY(tmp, seed, seedSz);

        /* counter to byte array appended to tmp */
        tmp[seedSz]     = (byte)((counter >> 24) & 0xFF);
        tmp[seedSz + 1] = (byte)((counter >> 16) & 0xFF);
        tmp[seedSz + 2] = (byte)((counter >>  8) & 0xFF);
        tmp[seedSz + 3] = (byte)((counter)       & 0xFF);

        /* hash and append to existing output */
        ret = wc_HashUpdate(hash, hType, tmp, (seedSz + 4));
        if (ret == 0) {
            ret = wc_HashFinal(hash, hType, tmp);
        }
        if (ret == 0) {
            for (i = 0; i < hLen && idx < outSz; i++) {
                out[idx++] = tmp[i];
            }
        }
        counter++;
    } while (ret == 0 && idx < outSz);

    return ret;
}

/* This routine performs a bitwise XOR operation of <*buf> and <*mask> of n
 * counts, placing the result in <*buf>. */
static void xorbuf(void* buf, const void* mask, word32 count)
{
    word32      i;
    byte*       b = (byte*)buf;
    const byte* m = (const byte*)mask;
    for (i = 0; i < count; i++) {
        b[i] ^= m[i];
    }
}

/* 0x00 .. 0x00 0x01 | Salt | Gen Hash | 0xbc
 * XOR MGF over all bytes down to end of Salt
 * Gen Hash = HASH(8 * 0x00 | Message Hash | Salt)
 *
 * input         Digest of the message.
 * inputLen      Length of digest.
 * pkcsBlock     Buffer to write to.
 * pkcsBlockLen  Length of buffer to write to.
 * rng           Random number generator (for salt).
 * htype         Hash function to use.
 * mgf           Mask generation function.
 * saltLen       Length of salt to put in padding.
 * bits          Length of key in bits.
 * returns 0 on success, PSS_SALTLEN_E when the salt length is invalid
 * and other negative values on error.
 */
static int RsaPadPss(const byte* input, word32 inputLen, byte* pkcsBlock,
    word32 pkcsBlockLen, WC_RNG* rng, int hash, int mgf,
    int saltLen, int bits)
{
    int ret = 0, hLen, o, maskLen, hiBits;
    byte *m, *s;
    byte salt[WC_MAX_DIGEST_SIZE];
    enum wc_HashType hType;
    wc_HashAlg hashCtx; /* big stack consumer */

    switch (hash) {
    #ifndef NO_SHA256
        case SHA256h:
            hType = WC_HASH_TYPE_SHA256;
            break;
    #endif
    #ifdef WOLFSSL_SHA384
        case SHA384h:
            hType = WC_HASH_TYPE_SHA384;
            break;
    #endif
    #ifdef WOLFSSL_SHA512
        case SHA512h:
            hType = WC_HASH_TYPE_SHA512;
            break;
    #endif
        default:
            return NOT_COMPILED_IN;
    }

    ret = wc_HashGetDigestSize(hType);
    if (ret < 0) {
        return ret;
    }
    hLen = ret;

    if ((int)inputLen != hLen) {
        return BAD_FUNC_ARG;
    }

    hiBits = (bits - 1) & 0x7;
    if (hiBits == 0) {
        /* Per RFC8017, set the leftmost 8emLen - emBits bits of the
         * leftmost octet in DB to zero. */
        *(pkcsBlock++) = 0;
        pkcsBlockLen--;
    }

    if (saltLen == RSA_PSS_SALT_LEN_DEFAULT) {
        saltLen = hLen;
    #ifdef WOLFSSL_SHA512
        /* See FIPS 186-4 section 5.5 item (e). */
        if (bits == 1024 && hLen == WC_SHA512_DIGEST_SIZE) {
            saltLen = RSA_PSS_SALT_MAX_SZ;
        }
    #endif
    }
    if ((int)pkcsBlockLen - hLen < saltLen + 2) {
        return PSS_SALTLEN_E;
    }

    ret = wc_HashInit_ex(&hashCtx, hType, NULL, INVALID_DEVID);
    if (ret != 0) {
        return ret;
    }

    maskLen = (int)pkcsBlockLen - 1 - hLen;

    s = m = pkcsBlock;
    XMEMSET(m, 0, RSA_PSS_PAD_SZ);
    m += RSA_PSS_PAD_SZ;
    XMEMCPY(m, input, inputLen);
    m += inputLen;
    o = 0;
    if (saltLen > 0) {
        ret = wc_RNG_GenerateBlock(rng, salt, (word32)saltLen);
        if (ret == 0) {
            XMEMCPY(m, salt, (size_t)saltLen);
            m += saltLen;
        }
    }
    if (ret == 0) {
        /* Put Hash at end of pkcsBlock - 1 */
        ret = wc_HashUpdate(&hashCtx, hType, s, (word32)(m - s));
        if (ret == 0) {
            ret = wc_HashFinal(&hashCtx, hType, pkcsBlock + maskLen);
        }
    }
    if (ret == 0) {
        /* Set the last eight bits or trailer field to the octet 0xbc */
        pkcsBlock[pkcsBlockLen - 1] = RSA_PSS_PAD_TERM;

        ret = RsaMGF1(&hashCtx, hType, pkcsBlock + maskLen, (word32)hLen,
            pkcsBlock, (word32)maskLen);
        (void)mgf; /* not needed, using hType */
    }
    if (ret == 0) {
        /* Clear the first high bit when "8emLen - emBits" is non-zero,
         * where emBits = n modBits - 1 */
        if (hiBits) {
            pkcsBlock[0] &= (byte)((1 << hiBits) - 1);
        }
        m = pkcsBlock + maskLen - saltLen - 1;
        *(m++) ^= 0x01;
        xorbuf(m, salt + o, (word32)saltLen);
    }
    wc_HashFree(&hashCtx, hType);
    return ret;
}

int wolfTPM2_PK_RsaPssSign(WOLFSSL* ssl,
    const unsigned char* in, unsigned int inSz,
    unsigned char* out, unsigned int* outSz,
    int hash, int mgf,
    const unsigned char* keyDer, unsigned int keySz,
    void* ctx)
{
    int ret;
    TpmCryptoDevCtx* tlsCtx = (TpmCryptoDevCtx*)ctx;
    RsaKey rsapub;

    (void)ssl;

#ifdef DEBUG_WOLFTPM
    printf("PK RSA PSS Sign: inSz %u, keySz %u, hash %d\n", inSz, keySz, hash);
#endif

    /* load RSA public key */
    ret = wc_InitRsaKey(&rsapub, NULL);
    if (ret == 0) {
        word32 keyIdx = 0;
        ret = wc_RsaPublicKeyDecode(keyDer, &keyIdx, &rsapub, (word32)keySz);
        if (ret == 0) {
            byte   inPad[RSA_MAX_SIZE/8];
            word32 inPadSz = (word32)wc_RsaEncryptSize(&rsapub);
            XMEMSET(inPad, 0, sizeof(inPad));
        #if 1
            /* Use local PSS padding function */
            ret = RsaPadPss(
                in, inSz,
                inPad, inPadSz,
                wolfTPM2_GetRng(tlsCtx->dev), hash, mgf,
                RSA_PSS_SALT_LEN_DEFAULT, inPadSz*8);
        #else
            /* Pad with PSS using internal wolfSSL API, if available */
            ret = wc_RsaPad_ex(in, inSz, inPad, inPadSz, RSA_BLOCK_TYPE_1,
                wolfTPM2_GetRng(tlsCtx->dev), WC_RSA_PSS_PAD, hash, mgf,
                NULL, 0, RSA_PSS_SALT_LEN_DEFAULT, inPadSz*8, NULL);
        #endif
            if (ret == 0) {
                /* private operations */
                ret = wolfTPM2_RsaDecrypt(tlsCtx->dev, tlsCtx->rsaKey,
                    TPM_ALG_NULL, /* no padding */
                    inPad, inPadSz,
                    out, (int*)outSz);
            }
        }
        wc_FreeRsaKey(&rsapub);
    }

    if (ret > 0) {
    #ifdef DEBUG_WOLFTPM
        printf("PK RSA PSS Sign Hash Failure 0x%x: %s\n",
            ret, wolfTPM2_GetRCString(ret));
    #endif
        ret = WC_HW_E;
    }

#ifdef DEBUG_WOLFTPM
    printf("PK RSA PSS Sign: ret %d, outSz %u\n", ret, *outSz);
#endif
    return ret;
}

int wolfTPM2_PK_RsaPssSignCheck(WOLFSSL* ssl,
    unsigned char* sig, unsigned int sigSz, unsigned char** out,
    int hash, int mgf,
    const unsigned char* keyDer, unsigned int keySz,
    void* ctx)
{
    TpmCryptoDevCtx* tlsCtx = (TpmCryptoDevCtx*)ctx;

    (void)ssl;
    (void)sig;
    (void)sigSz;
    (void)out;
    (void)hash;
    (void)mgf;
    (void)keyDer;
    (void)keySz;
    (void)tlsCtx;
    /* We used sign hardware, so assume sign is good */
    return 0;
}

#endif /* WC_RSA_PSS */
#endif /* !NO_RSA */

#ifdef HAVE_ECC
int wolfTPM2_PK_EccSign(WOLFSSL* ssl,
    const unsigned char* in, unsigned int inSz,
    unsigned char* out, word32* outSz,
    const unsigned char* keyDer, unsigned int keyDerSz,
    void* ctx)
{
    int ret;
    TpmCryptoDevCtx* tlsCtx = (TpmCryptoDevCtx*)ctx;
    ecc_key eccpub;

    (void)ssl;

#ifdef DEBUG_WOLFTPM
    printf("PK ECC Sign: inSz %u, keyDerSz %u\n", inSz, keyDerSz);
#endif

    /* load ECC public key */
    ret = wc_ecc_init_ex(&eccpub, NULL, INVALID_DEVID);
    if (ret == 0) {
        word32 keyIdx = 0;
        ret = wc_EccPublicKeyDecode(keyDer, &keyIdx, &eccpub, (word32)keyDerSz);
        if (ret == 0) {
            byte sigRS[MAX_ECC_BYTES*2];
            word32 rsLen = sizeof(sigRS), keySz;

            /* truncate input to match key size */
            keySz = wc_ecc_size(&eccpub);
            if (inSz > keySz)
                inSz = keySz;

            ret = wolfTPM2_SignHash(tlsCtx->dev, tlsCtx->eccKey,
                in, inSz, sigRS, (int*)&rsLen);
            if (ret == 0) {
                byte *r, *s;
                word32 rLen, sLen;

                /* Make sure leading zero's not required are trimmed */
                rLen = sLen = rsLen / 2;
                r = &sigRS[0];
                s = &sigRS[rLen];
                r = wolfTPM2_ASNTrimZeros(r, &rLen);
                s = wolfTPM2_ASNTrimZeros(s, &sLen);

                /* Encode ECDSA Header */
                ret = wc_ecc_rs_raw_to_sig(r, rLen, s, sLen, out, outSz);
            }
        }
        wc_ecc_free(&eccpub);
    }

    if (ret > 0) {
    #ifdef DEBUG_WOLFTPM
        printf("PK ECC Sign Hash Failure 0x%x: %s\n",
            ret, wolfTPM2_GetRCString(ret));
    #endif
        ret = WC_HW_E;
    }

#ifdef DEBUG_WOLFTPM
    printf("PK ECC Sign: ret %d, outSz %u\n", ret, *outSz);
#endif
    return ret;
}
#endif

/* Setup PK callbacks */
int wolfTPM_PK_SetCb(WOLFSSL_CTX* ctx)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;

#ifndef NO_RSA
    wolfSSL_CTX_SetRsaSignCb(ctx, wolfTPM2_PK_RsaSign);
    wolfSSL_CTX_SetRsaSignCheckCb(ctx, wolfTPM2_PK_RsaSignCheck);
    #ifdef WC_RSA_PSS
    wolfSSL_CTX_SetRsaPssSignCb(ctx, wolfTPM2_PK_RsaPssSign);
    wolfSSL_CTX_SetRsaPssSignCheckCb(ctx, wolfTPM2_PK_RsaPssSignCheck);
    #endif
#endif
#ifdef HAVE_ECC
    wolfSSL_CTX_SetEccSignCb(ctx, wolfTPM2_PK_EccSign);
#endif
    return 0;
}

/* Setup PK Callback context */
int wolfTPM_PK_SetCbCtx(WOLFSSL* ssl, void* userCtx)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

#ifndef NO_RSA
    wolfSSL_SetRsaSignCtx(ssl, userCtx);
    #ifdef WC_RSA_PSS
    wolfSSL_SetRsaPssSignCtx(ssl, userCtx);
    #endif
#endif
#ifdef HAVE_ECC
    wolfSSL_SetEccSignCtx(ssl, userCtx);
#endif
    return 0;
}

#endif /* HAVE_PK_CALLBACKS && !WOLFCRYPT_ONLY */

#endif /* !WOLFTPM2_NO_WRAPPER */
