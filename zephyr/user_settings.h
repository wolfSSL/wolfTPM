/* user_settings.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

#ifndef _ZEPHYR_USER_SETTINGS_H_
#define _ZEPHYR_USER_SETTINGS_H_

#ifdef __cplusplus
extern "C" {
#endif

/* -- WOLFTPM ZEPHYR SETTINGS -- */

#undef  WOLFTPM_USER_SETTINGS
#define WOLFTPM_USER_SETTINGS

#undef  WOLFTPM_EXAMPLE_HAL
#define WOLFTPM_EXAMPLE_HAL

#undef  WOLFTPM_ZEPHYR
#define WOLFTPM_ZEPHYR

/* -- WOLFSSL SETTINGS -- */
#undef  WOLFSSL_USER_SETTINGS
#define WOLFSSL_USER_SETTINGS

#undef  WOLF_CRYPT_SETTINGS_H
#define WOLF_CRYPT_SETTINGS_H

#if 0
    #undef  WOLFTPM_SWTPM
    #define WOLFTPM_SWTPM
#endif

#undef  WOLF_CRYPTO_CB
#define WOLF_CRYPTO_CB

#undef  WOLFSSL_AES_CFB
#define WOLFSSL_AES_CFB

/* -- WOLFTPM SETTINGS -- */

/* enable for low resource options */
#if 0
    #define USE_LOW_RESOURCE
#endif

#ifdef USE_LOW_RESOURCE
    /* wolfCrypt only (no SSL/TLS) */
    #define WOLFCRYPT_ONLY
#else
    /* wolfTPM with TLS example (v1.3 only) */
    #define WOLFSSL_TLS13
    #define WOLFSSL_NO_TLS12
    #define NO_OLD_TLS

    #define HAVE_TLS_EXTENSIONS
    #define HAVE_SUPPORTED_CURVES
    #define HAVE_SERVER_RENEGOTIATION_INFO
    #define HAVE_ENCRYPT_THEN_MAC

    #define HAVE_HKDF
    #define WC_RSA_PSS
    #define WOLFSSL_PSS_LONG_SALT
#endif

/* No threading or file system */
#define SINGLE_THREADED

/* Enable crypto callbacks */
#define WOLF_CRYPTO_CB

#ifdef USE_LOW_RESOURCE
    /* Single Precision math for RSA 2048 only (small) */
    #define WOLFSSL_HAVE_SP_RSA
    #define WOLFSSL_SP_MATH
    #define WOLFSSL_SP_SMALL
    #define WOLFSSL_SP_NO_3072 /* 2048-only */
#else
    /* Enable SP math all (sp_int.c) with multi-precision support */
    #define WOLFSSL_SP_MATH_ALL
#endif

/* Enable hardening (timing resistance) */
#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING

/* Enable PRNG (SHA2-256) */
#ifdef USE_LOW_RESOURCE
    /* use TPM TRNG */
    #define WC_NO_HASHDRBG
#else
    #define HAVE_HASHDRBG
#endif

/* Asymmetric */
#if 1 /* RSA - needed to encrypt salt */
    #undef  NO_RSA
    #ifdef USE_LOW_RESOURCE
        #define WOLFSSL_RSA_PUBLIC_ONLY
        #define WOLFSSL_RSA_VERIFY_INLINE
        #define NO_CHECK_PRIVATE_KEY
    #endif
#else
    #define NO_RSA
#endif
#if 1 /* ECC - needed for encrypt ECC salt */
    #define HAVE_ECC
    #define ECC_USER_CURVES /* default to only SECP256R1 */
#endif
#ifndef USE_LOW_RESOURCE /* DH */
    #undef  NO_DH
    #define HAVE_FFDHE_2048
    #define HAVE_DH_DEFAULT_PARAMS
#else
    #define NO_DH
#endif

/* Symmetric Hash */
#undef NO_SHA
#undef NO_SHA256
#ifndef USE_LOW_RESOURCE
    #define WOLFSSL_SHA512
    #define WOLFSSL_SHA384
#endif

/* Symmetric Cipher */
#define WOLFSSL_AES_CFB
#define HAVE_AES_DECRYPT
#ifndef USE_LOW_RESOURCE
    #define HAVE_AES_KEYWRAP
    #define WOLFSSL_AES_DIRECT
    #define HAVE_AESGCM
    #define GCM_TABLE_4BIT
#else
    #define NO_AES_CBC
#endif

#if 0 /* ChaCha20 / Poly1305 */
    #define HAVE_POLY1305
    #define HAVE_CHACHA
#endif

/* Features */
#define WOLFSSL_ASN_TEMPLATE
#define WOLFSSL_USER_IO /* user recv/send callbacks for network IO */
#ifndef USE_LOW_RESOURCE
    #define WOLFSSL_CERT_GEN
    #define WOLFSSL_CERT_REQ
    #define WOLFSSL_CERT_EXT

    #define HAVE_PKCS7
    #define HAVE_X963_KDF
    #define WOLFSSL_BASE64_ENCODE
#endif

/* Disables */
#define NO_PKCS8
#define NO_PKCS12
#define NO_PWDBASED
#define NO_DSA
#define NO_DES3
#define NO_RC4
#define NO_PSK
#define NO_MD4
#define NO_MD5
#define WOLFSSL_NO_SHAKE128
#define WOLFSSL_NO_SHAKE256
#define NO_WRITEV

/* Low Resource Options */
#ifdef USE_LOW_RESOURCE
    #define NO_FILESYSTEM /* File system disable */
    #define NO_ERROR_STRINGS
    #define WOLFSSL_NO_ASM
    #define TFM_NO_ASM
    #define NO_WOLFSSL_MEMORY
    #define NO_SESSION_CACHE
    #define RSA_LOW_MEM
    #define WOLFSSL_AES_SMALL_TABLES
    #define WOLFSSL_AES_NO_UNROLL
    #define GCM_SMALL
    #undef  GCM_TABLE_4BIT
    #define NO_AES_192
    #define NO_AES_256
    #define USE_SLOW_SHA
    #define USE_SLOW_SHA256
    #define USE_SLOW_SHA512
    #define NO_SIG_WRAPPER
    #define NO_ASN_TIME
    #define NO_CODING
    #define NO_BIG_INT
#endif

#ifdef __cplusplus
}
#endif

#endif /* _ZEPHYR_USER_SETTINGS_H_ */
