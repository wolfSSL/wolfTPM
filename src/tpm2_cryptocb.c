/* tpm2_cryptocb.c
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
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

#include <wolftpm/tpm2_wrap.h>

#if defined(WOLFTPM_CRYPTOCB) && !defined(WOLFTPM2_NO_WRAPPER)

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

            /* Make sure an ECDH key has been set and curve is supported */
            rc = TPM2_GetTpmCurve(info->pk.eckg.curveId);
            if (rc < 0 || tlsCtx->ecdhKey == NULL || tlsCtx->eccKey == NULL) {
                return exit_rc;
            }
            curve_id = rc;
            rc = 0;

            /* Generate ephemeral key - if one isn't already created */
            if (tlsCtx->ecdhKey->handle.hndl == 0 ||
                tlsCtx->ecdhKey->handle.hndl == TPM_RH_NULL) {
                rc = wolfTPM2_ECDHGenKey(tlsCtx->dev, tlsCtx->ecdhKey, curve_id,
                    (byte*)tlsCtx->eccKey->handle.auth.buffer,
                    tlsCtx->eccKey->handle.auth.size);
            }
            if (rc == 0) {
                /* Export public key info to wolf ecc_key */
                rc = wolfTPM2_EccKey_TpmToWolf(tlsCtx->dev, tlsCtx->ecdhKey,
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
                tlsCtx->ecdhKey->handle.hndl = TPM_RH_NULL;
            }
        #endif /* WOLFTPM2_USE_SW_ECDHE */
        }
        else if (info->pk.type == WC_PK_TYPE_ECDSA_SIGN) {
            byte sigRS[MAX_ECC_BYTES*2];
            byte *r = sigRS, *s;
            word32 rsLen = sizeof(sigRS), rLen, sLen;
            word32 inlen = info->pk.eccsign.inlen;

            /* truncate input to match key size */
            rLen = wc_ecc_size(info->pk.eccsign.key);
            if (inlen > rLen)
                inlen = rLen;

            rc = wolfTPM2_SignHash(tlsCtx->dev, tlsCtx->eccKey,
                info->pk.eccsign.in, inlen, sigRS, (int*)&rsLen);
            if (rc == 0) {
                /* Encode ECDSA Header */
                rLen = sLen = rsLen / 2;
                s = &sigRS[rLen];
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

            /* Decode ECDSA Header */
            rc = wc_ecc_sig_to_rs(info->pk.eccverify.sig,
                info->pk.eccverify.siglen, r, &rLen, s, &sLen);
            if (rc == 0) {
                /* load public key into TPM */
                rc = wolfTPM2_EccKey_WolfToTpm(tlsCtx->dev,
                    info->pk.eccverify.key, &eccPub);
                if (rc == 0) {
                    /* combine R and S */
                    XMEMCPY(sigRS + rLen, s, sLen);
                    rc = wolfTPM2_VerifyHash(tlsCtx->dev, &eccPub,
                        sigRS, rLen + sLen,
                        info->pk.eccverify.hash, info->pk.eccverify.hashlen);

                    if (rc == 0 && info->pk.eccverify.res) {
                        *info->pk.eccverify.res = 1;
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

        if (info->hash.in != NULL) { /* Update */
            rc = 0;
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

#endif /* WOLFTPM_CRYPTOCB && !WOLFTPM2_NO_WRAPPER */
