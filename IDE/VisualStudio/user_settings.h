/* user_settings.h
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

/* Template for wolfTPM and wolfCrypt (FIPS optional) with TLS v1.2 and v1.3 */

#ifndef _USER_SETTINGS_H_
#define _USER_SETTINGS_H_

#ifdef __cplusplus
extern "C" {
#endif

#if 0 /* enable for FIPS ready */
    /* FIPS v5-ready 140-3 */
    #define HAVE_FIPS
    #define HAVE_FIPS_VERSION 5
    #define HAVE_FIPS_VERSION_MINOR 3
#endif

/* Platform */
#define HAVE_THREAD_LS /* thread local storage */
#ifdef _WIN32
    #define WOLFTPM_WINAPI
    #define _WINSOCK_DEPRECATED_NO_WARNINGS
    #define _CRT_SECURE_NO_WARNINGS
#endif

/* TPM */
#define WOLFSSL_AES_CFB /* required for parameter encryption */
#define WOLFSSL_PUBLIC_MP /* expose mp_ math functions - required for tpm ECC secret encrypt */
#define WOLFTPM_AUTODETECT /* support any TPM model (unknown/safe options) */

/* Callbacks */
#define WOLF_CRYPTO_CB
#define HAVE_PK_CALLBACKS

/* TLS Versions v1.2 and v1.3 */
#define WOLFSSL_TLS13
#define NO_OLD_TLS

/* TLS Extensions */
#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES
#define HAVE_EXTENDED_MASTER
#define HAVE_SERVER_RENEGOTIATION_INFO
#define HAVE_ENCRYPT_THEN_MAC
#define HAVE_SNI

/* Math Option */
#ifdef HAVE_FIPS
    #define USE_FAST_MATH /* tfm.c */
    #define FP_MAX_BITS 16384
#else
    #define WOLFSSL_SP_MATH_ALL /* sp_int.c */
    #define SP_INT_BITS 8192
#endif
#define WOLFSSL_USE_ALIGN
#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING

/* No ASM (optional) */
#if 0
    #define TFM_NO_ASM
    #define WOLFSSL_NO_ASM
    #define NO_CHACHA_ASM
#endif

/* Debugging */
#if 1
    #define DEBUG_WOLFSSL
    #define ERROR_QUEUE_PER_THREAD
#else
    //#define NO_ERROR_STRINGS
#endif

/* Certificate */
#define WOLFSSL_ASN_TEMPLATE
#define WOLFSSL_BASE64_ENCODE
#define WOLFSSL_CERT_GEN
#define WOLFSSL_CERT_REQ
#define WOLFSSL_CERT_EXT

/* RNG */
#define HAVE_HASHDRBG
#define WC_RNG_SEED_CB

/* Asymmetric */
#define HAVE_ECC
#define ECC_SHAMIR
#define ECC_USER_CURVES
#define HAVE_ECC192
#define HAVE_ECC224
#define HAVE_ECC256
#define HAVE_ECC384
#define HAVE_ECC521
#define WOLFSSL_ECDSA_SET_K
#define HAVE_ECC_CDH
#define WOLFSSL_VALIDATE_ECC_IMPORT
#define WOLFSSL_VALIDATE_ECC_KEYGEN

#define WC_RSA_PSS
#define WOLFSSL_PSS_LONG_SALT
#define WC_RSA_NO_PADDING
#define WOLFSSL_KEY_GEN

#define HAVE_DH_DEFAULT_PARAMS
#define HAVE_FFDHE_Q
#define HAVE_FFDHE_2048
#define HAVE_FFDHE_3072
#define HAVE_FFDHE_4096
#define HAVE_FFDHE_6144
#define HAVE_FFDHE_8192
#define WOLFSSL_VALIDATE_FFC_IMPORT

#define WOLFSSL_SHA224
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
#define WOLFSSL_NOSHA512_224
#define WOLFSSL_NOSHA512_256

#define WOLFSSL_SHA3
#define WOLFSSL_NO_SHAKE128
#define WOLFSSL_NO_SHAKE256

#define HAVE_HKDF

#define WOLFSSL_AES_DIRECT
#define HAVE_AES_ECB
#define WOLFSSL_AES_COUNTER
#define WOLFSSL_AES_OFB
#define HAVE_AESCCM
#define HAVE_AESGCM
#define GCM_TABLE_4BIT
#define HAVE_AES_KEYWRAP
#define WOLFSSL_AES_DIRECT
#define HAVE_PKCS7
#define WOLFSSL_CMAC

#define HAVE_X963_KDF

/* Disabled features */
#undef  NO_RC4
#define NO_RC4
#define NO_PSK
#define NO_MD4
#define NO_DES3
#define NO_DSA


#ifdef __cplusplus
}
#endif

#endif /* _USER_SETTINGS_H_ */
