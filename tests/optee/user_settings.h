/* user_settings.h
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

/* wolfCrypt and wolfTPM configuration for optee_core_tests.c: the trusted
 * application's settings (WOLFSSL_OPTEE, no filesystem, single threaded)
 * built for the host against the mock TEE, without post-quantum algorithms
 * or assembly so it builds anywhere. */

#ifndef OPTEE_MOCK_USER_SETTINGS_H
#define OPTEE_MOCK_USER_SETTINGS_H

#define WOLFTPM_FWTPM
#define WOLFTPM_SMALL_STACK

#define WOLFCRYPT_ONLY
#define SINGLE_THREADED
#define NO_FILESYSTEM
#define NO_WRITEV
#define WOLFSSL_NO_SOCK
#define NO_WOLFSSL_DIR
#define NO_MAIN_DRIVER
#define NO_ASN_TIME

#define WOLFSSL_SP_MATH_ALL
#define WOLFSSL_KEY_GEN
#define WOLFSSL_NO_DER_TO_PEM
#define WC_RSA_PSS
#define WC_RSA_NO_PADDING
#define WC_RSA_BLINDING
#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT

#define HAVE_ECC
#define ECC_USER_CURVES
#define HAVE_ECC256
#define HAVE_ECC384
#define ECC_SHAMIR
#define HAVE_ECC_SIGN
#define HAVE_ECC_VERIFY
#define HAVE_ECC_DHE
#define HAVE_ECC_KEY_EXPORT
#define HAVE_ECC_KEY_IMPORT
#define WOLFSSL_CUSTOM_CURVES
#define WOLFSSL_PUBLIC_MP

#define WOLFSSL_AES_128
#define WOLFSSL_AES_256
#define WOLFSSL_AES_DIRECT
#define WOLFSSL_AES_CFB
#define HAVE_AES_DECRYPT
#define HAVE_AES_CBC

#define WOLFSSL_SHA224
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
#define HAVE_HKDF

#define NO_DH
#define NO_DSA
#define NO_DES3
#define NO_RC4
#define NO_MD4
#define NO_MD5
#define NO_PSK
#define NO_OLD_TLS
#define NO_PKCS12
#define NO_PWDBASED
#define WOLFSSL_NO_PKCS8

#endif /* OPTEE_MOCK_USER_SETTINGS_H */
