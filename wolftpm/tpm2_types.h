/* tpm2_types.h
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
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

#ifndef __TPM2_TYPES_H__
#define __TPM2_TYPES_H__

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/visibility.h>
#include <stdint.h>

#ifndef WOLFTPM_USER_SETTINGS
    /* use generated options.h or a custom one */
    #include <wolftpm/options.h>
#endif

#ifdef __cplusplus
    extern "C" {
#endif

/* ---------------------------------------------------------------------------*/
/* TPM TYPES */
/* ---------------------------------------------------------------------------*/

typedef uint8_t  UINT8;
typedef uint8_t  BYTE;
typedef int8_t   INT8;
#if !defined(BOOL) && !defined(HAVE_BOOL)
typedef int      BOOL;
#endif
typedef uint16_t UINT16;
typedef int16_t  INT16;
typedef uint32_t UINT32;
typedef int32_t  INT32;
typedef uint64_t UINT64;
typedef int64_t  INT64;

#ifndef YES
#define YES 1
#endif
#ifndef NO
#define NO 0
#endif


/* ---------------------------------------------------------------------------*/
/* WOLFCRYPT */
/* ---------------------------------------------------------------------------*/

#ifndef WOLFTPM2_NO_WOLFCRYPT
    #ifndef WOLFSSL_USER_SETTINGS
        #include <wolfssl/options.h>
    #endif
	#include <wolfssl/wolfcrypt/settings.h>
    #include <wolfssl/wolfcrypt/types.h>
    #include <wolfssl/wolfcrypt/logging.h>
    #include <wolfssl/wolfcrypt/error-crypt.h>
    #include <wolfssl/error-ssl.h>
    #include <wolfssl/wolfcrypt/hash.h>
    #include <wolfssl/wolfcrypt/rsa.h>
    #include <wolfssl/wolfcrypt/ecc.h>
    #include <wolfssl/wolfcrypt/asn_public.h>
    #include <wolfssl/wolfcrypt/hmac.h>
    #include <wolfssl/wolfcrypt/aes.h>
    #ifdef WOLF_CRYPTO_CB
        #include <wolfssl/wolfcrypt/cryptocb.h>
    #elif defined(WOLF_CRYPTO_DEV)
        /* old name for crypto callback support */
        #include <wolfssl/wolfcrypt/cryptodev.h>
    #endif
    #ifndef WOLFCRYPT_ONLY
        /* for additional error codes */
        #include <wolfssl/ssl.h> /* for wolfSSL_ERR_reason_error_string */
    #endif

	#ifdef DEBUG_WOLFTPM
		#include <stdio.h>
	#endif

    #include <wolfssl/version.h>
    #if defined(LIBWOLFSSL_VERSION_HEX) && LIBWOLFSSL_VERSION_HEX < 0x03015004
        /* The wc_HashFree was added in v3.15.4, so use stub to allow building */
        #define wc_HashFree(h, t) (0)
    #endif
    #ifndef XFEOF
        #define XFEOF      feof
    #endif

#else

    #include <stdio.h>
    #include <string.h>

    typedef uint8_t  byte;
    typedef uint16_t word16;
    typedef uint32_t word32;
    typedef uint64_t word64;

    /* Errors from wolfssl/wolfcrypt/error-crypt.h */
    #define BAD_FUNC_ARG          -173  /* Bad function argument provided */
    #define BUFFER_E              -132  /* output buffer too small or input too large */
    #define NOT_COMPILED_IN       -174  /* Feature not compiled in */
    #define BAD_MUTEX_E           -106  /* Bad mutex operation */
    #define WC_TIMEOUT_E          -107  /* timeout error */

    /* Errors from wolfssl/error-ssl.h */
    #define SOCKET_ERROR_E        -308  /* error state on socket    */

#ifndef WOLFTPM_CUSTOM_TYPES
    #define XMEMCPY(d,s,l)    memcpy((d),(s),(l))
    #define XMEMSET(b,c,l)    memset((b),(c),(l))
    #define XMEMCMP(s1,s2,n)  memcmp((s1),(s2),(n))
    #define XSTRLEN(s1)       strlen((s1))
    #define XSTRNCMP(s1,s2,n) strncmp((s1),(s2),(n))
#endif /* !WOLFTPM_CUSTOM_TYPES */

    /* Endianess */
    #ifndef BIG_ENDIAN_ORDER
        #define LITTLE_ENDIAN_ORDER
    #endif

    /* GCC Version */
    #ifndef __GNUC_PREREQ
        #if defined(__GNUC__) && defined(__GNUC_MINOR__)
            #define __GNUC_PREREQ(maj, min) \
                ((__GNUC__ << 16) + __GNUC_MINOR__ >= ((maj) << 16) + (min))
        #else
            #define __GNUC_PREREQ(maj, min) (0) /* not GNUC */
        #endif
    #endif

#if !defined(WOLFTPM_CUSTOM_STDIO) && !defined(NO_FILESYSTEM)
    /* stdio, default case */
    #define XFILE      FILE*
    #define XFOPEN     fopen
    #define XFSEEK     fseek
    #define XFTELL     ftell
    #define XREWIND    rewind
    #define XFREAD     fread
    #define XFWRITE    fwrite
    #define XFCLOSE    fclose
    #define XSEEK_END  SEEK_END
    #define XBADFILE   NULL
    #define XFGETS     fgets
    #define XFEOF      feof
#endif

#endif /* !WOLFTPM2_NO_WOLFCRYPT */

/* enable way for customer to override printf */
#ifdef XPRINTF
    #undef  printf
    #define printf XPRINTF
#endif



/* ---------------------------------------------------------------------------*/
/* TPM HARDWARE TYPE */
/* ---------------------------------------------------------------------------*/
/* Microchip ATTPM20 */
/* #define WOLFTPM_MCHP */

/* ST ST33TP TPM 2.0 */
/* #define WOLFTPM_ST33 */

/* Nuvoton NPCT75x TPM 2.0 module */
/* #define WOLFTPM_NUVOTON */

/* Infineon SLB9670 TPM 2.0 (default) */
/* #define WOLFTPM_SLB9670 */

/* Define a default chip */
#if !defined(WOLFTPM_ST33) && !defined(WOLFTPM_MCHP) && \
    !defined(WOLFTPM_NUVOTON) && !defined(WOLFTPM_SLB9670)
    #define WOLFTPM_SLB9670
#endif


/* Chip Specific Settings */
#ifdef WOLFTPM_MCHP
    /* Microchip ATTPM20 */
    /* Requires SPI wait states */
    #ifndef WOLFTPM_CHECK_WAIT_STATE
        #define WOLFTPM_CHECK_WAIT_STATE
    #endif
    /* Max: 36MHz (has issues so using 33MHz) */
    #define TPM2_SPI_MAX_HZ_MICROCHIP 33000000
    #ifndef TPM2_SPI_MAX_HZ
        #define TPM2_SPI_MAX_HZ TPM2_SPI_MAX_HZ_MICROCHIP
    #endif
#elif defined(WOLFTPM_ST33)
    /* ST ST33TPM20 modules */
    /* Requires wait state support */
    #ifndef WOLFTPM_CHECK_WAIT_STATE
        #define WOLFTPM_CHECK_WAIT_STATE
    #endif
    /* Max: 33MHz */
    #define TPM2_SPI_MAX_HZ_ST 33000000
    #ifndef TPM2_SPI_MAX_HZ
        #define TPM2_SPI_MAX_HZ TPM2_SPI_MAX_HZ_ST
    #endif
#elif defined(WOLFTPM_NUVOTON)
    /* Nuvoton NPCT75x module */
    /* Requires wait state support */
    #ifndef WOLFTPM_CHECK_WAIT_STATE
        #define WOLFTPM_CHECK_WAIT_STATE
    #endif
    #define TPM2_SPI_MAX_HZ_NUVOTON 43000000
    #ifndef TPM2_SPI_MAX_HZ
        /* Max: 43MHz */
        #define TPM2_SPI_MAX_HZ TPM2_SPI_MAX_HZ_NUVOTON
    #endif
#else
    /* Infineon OPTIGA SLB9670 */
    /* Max: 43MHz */
    #define TPM2_SPI_MAX_HZ_INFINEON 43000000
    #ifndef TPM2_SPI_MAX_HZ
        #define TPM2_SPI_MAX_HZ TPM2_SPI_MAX_HZ_INFINEON
    #endif
#endif

/* Auto-chip detection requires SPI wait state support and safe SPI bus speed */
#ifdef WOLFTPM_AUTODETECT
    /* SPI wait state checking must be enabled */
    #undef  WOLFTPM_CHECK_WAIT_STATE
    #define WOLFTPM_CHECK_WAIT_STATE

    /* use a safe MHz (minimum of above) */
    #undef TPM2_SPI_MAX_HZ
    #define TPM2_SPI_MAX_HZ 33000000

    /* always perform self-test (some chips require) */
    #undef  WOLFTPM_PERFORM_SELFTEST
    #define WOLFTPM_PERFORM_SELFTEST
#endif



/* ---------------------------------------------------------------------------*/
/* ALGORITHMS */
/* ---------------------------------------------------------------------------*/
#define TPM_MD5_DIGEST_SIZE    16
#define TPM_SHA_DIGEST_SIZE    20
#define TPM_SHA224_DIGEST_SIZE 28
#define TPM_SHA256_DIGEST_SIZE 32
#define TPM_SHA384_DIGEST_SIZE 48
#define TPM_SHA512_DIGEST_SIZE 64

#ifndef MAX_ECC_KEY_BYTES
#define MAX_ECC_KEY_BYTES     66
#endif

#ifndef TPM_MAX_BLOCK_SIZE
#define TPM_MAX_BLOCK_SIZE     128
#endif

#ifndef TPM_MAX_DIGEST_SIZE
#define TPM_MAX_DIGEST_SIZE    TPM_SHA512_DIGEST_SIZE
#endif


/* ---------------------------------------------------------------------------*/
/* CONFIGURABLE LIMITS */
/* ---------------------------------------------------------------------------*/

#ifndef MAX_SPI_FRAMESIZE
#define MAX_SPI_FRAMESIZE 64
#endif

#ifndef TPM_STARTUP_TEST_TRIES
#define TPM_STARTUP_TEST_TRIES 2
#endif

#ifndef TPM_TIMEOUT_TRIES
    #if defined(WOLFTPM_LINUX_DEV) || defined(WOLFTPM_SWTPM) || defined(WOLFTPM_WINAPI)
    #define TPM_TIMEOUT_TRIES 0
    #else
    #define TPM_TIMEOUT_TRIES 1000000
    #endif
#endif

#ifndef TPM_SPI_WAIT_RETRY
#define TPM_SPI_WAIT_RETRY 50
#endif

#ifndef MAX_SYM_BLOCK_SIZE
#define MAX_SYM_BLOCK_SIZE 20
#endif
#ifndef MAX_SYM_KEY_BYTES
#define MAX_SYM_KEY_BYTES 256
#endif
#ifndef LABEL_MAX_BUFFER
#define LABEL_MAX_BUFFER 128
#endif
#ifndef MAX_RSA_KEY_BITS
#define MAX_RSA_KEY_BITS 2048
#endif
#ifndef MAX_RSA_KEY_BYTES
#define MAX_RSA_KEY_BYTES (((MAX_RSA_KEY_BITS+7)/8)*2)
#endif

#ifndef MAX_ECC_KEY_BITS
#define MAX_ECC_KEY_BITS 521
#endif
#ifndef MAX_ECC_KEY_BYTES
#define MAX_ECC_KEY_BYTES (((MAX_ECC_KEY_BITS+7)/8)*2)
#endif

#ifndef MAX_AES_KEY_BITS
#define MAX_AES_KEY_BITS 128
#endif
#ifndef MAX_AES_BLOCK_SIZE_BYTES
#define MAX_AES_BLOCK_SIZE_BYTES 16
#endif
#ifndef MAX_AES_KEY_BYTES
#define MAX_AES_KEY_BYTES (MAX_AES_KEY_BITS/8)
#endif


/* ---------------------------------------------------------------------------*/
/* IMPLEMENTATION SPECIFIC VALUES */
/* ---------------------------------------------------------------------------*/

/* Optional delay between polling */
#if defined(WOLFTPM_SLB9670) && !defined(XTPM_WAIT)
    /* For Infineon SLB9670 adding 10us delay improves performance */
    #ifdef __linux__
        #ifndef XTPM_WAIT_POLLING_US
            #define XTPM_WAIT_POLLING_US 10 /* 0.01ms */
        #endif
        #include <unistd.h>
        #define XTPM_WAIT() usleep(XTPM_WAIT_POLLING_US);
    #endif
#endif
#ifndef XTPM_WAIT
    #define XTPM_WAIT() /* just poll without delay by default */
#endif

#ifndef BUFFER_ALIGNMENT
#define BUFFER_ALIGNMENT 4
#endif
#ifndef IMPLEMENTATION_PCR
#define IMPLEMENTATION_PCR 24
#endif
#ifndef PLATFORM_PCR
#define PLATFORM_PCR 24
#endif
#ifndef DRTM_PCR
#define DRTM_PCR 17
#endif
#ifndef HCRTM_PCR
#define HCRTM_PCR 0
#endif
#ifndef NUM_LOCALITIES
#define NUM_LOCALITIES 1
#endif
#ifndef MAX_HANDLE_NUM
#define MAX_HANDLE_NUM 3
#endif
#ifndef MAX_ACTIVE_SESSIONS
#define MAX_ACTIVE_SESSIONS 64
#endif
#ifndef MAX_LOADED_SESSIONS
#define MAX_LOADED_SESSIONS 3
#endif
#ifndef MAX_SESSION_NUM
#define MAX_SESSION_NUM 3
#endif
#ifndef MAX_LOADED_OBJECTS
#define MAX_LOADED_OBJECTS 3
#endif
#ifndef MIN_EVICT_OBJECTS
#define MIN_EVICT_OBJECTS 2
#endif
#ifndef PCR_SELECT_MIN
#define PCR_SELECT_MIN ((PLATFORM_PCR+7)/8)
#endif
#ifndef PCR_SELECT_MAX
#define PCR_SELECT_MAX ((IMPLEMENTATION_PCR+7)/8)
#endif
#ifndef MAX_CONTEXT_SIZE
#define MAX_CONTEXT_SIZE 2048
#endif
#ifndef MAX_DIGEST_BUFFER
#define MAX_DIGEST_BUFFER 1024
#endif
#ifndef MAX_NV_INDEX_SIZE
#define MAX_NV_INDEX_SIZE 2048
#endif
#ifndef MAX_NV_BUFFER_SIZE
#define MAX_NV_BUFFER_SIZE 768
#endif
#ifndef MAX_CAP_BUFFER
#define MAX_CAP_BUFFER 1024
#endif
#ifndef NV_MEMORY_SIZE
#define NV_MEMORY_SIZE 16384
#endif
#ifndef NUM_STATIC_PCR
#define NUM_STATIC_PCR 16
#endif
#ifndef MAX_ALG_LIST_SIZE
#define MAX_ALG_LIST_SIZE 64
#endif
#ifndef TIMER_PRESCALE
#define TIMER_PRESCALE 100000
#endif
#ifndef PRIMARY_SEED_SIZE
#define PRIMARY_SEED_SIZE 32
#endif
#ifndef CONTEXT_ENCRYPT_ALG
#define CONTEXT_ENCRYPT_ALG TPM_ALG_AES
#endif
#ifndef CONTEXT_ENCRYPT_KEY_BITS
#define CONTEXT_ENCRYPT_KEY_BITS MAX_SYM_KEY_BITS
#endif
#ifndef CONTEXT_ENCRYPT_KEY_BYTES
#define CONTEXT_ENCRYPT_KEY_BYTES ((CONTEXT_ENCRYPT_KEY_BITS+7 )/8)
#endif
#ifndef CONTEXT_INTEGRITY_HASH_ALG
#define CONTEXT_INTEGRITY_HASH_ALG TPM_ALG_SHA256
#endif
#ifndef CONTEXT_INTEGRITY_HASH_SIZE
#define CONTEXT_INTEGRITY_HASH_SIZE SHA256_DIGEST_SIZE
#endif
#ifndef PROOF_SIZE
#define PROOF_SIZE CONTEXT_INTEGRITY_HASH_SIZE
#endif
#ifndef NV_CLOCK_UPDATE_INTERVAL
#define NV_CLOCK_UPDATE_INTERVAL 12
#endif
#ifndef NUM_POLICY_PCR
#define NUM_POLICY_PCR 1
#endif
#ifndef MAX_COMMAND_SIZE
#define MAX_COMMAND_SIZE 4096
#endif
#ifndef MAX_RESPONSE_SIZE
#define MAX_RESPONSE_SIZE 4096
#endif
#ifndef ORDERLY_BITS
#define ORDERLY_BITS 8
#endif
#ifndef MAX_ORDERLY_COUNT
#define MAX_ORDERLY_COUNT ((1 << ORDERLY_BITS) - 1)
#endif
#ifndef ALG_ID_FIRST
#define ALG_ID_FIRST TPM_ALG_FIRST
#endif
#ifndef ALG_ID_LAST
#define ALG_ID_LAST TPM_ALG_LAST
#endif
#ifndef MAX_SYM_DATA
#define MAX_SYM_DATA 128
#endif
#ifndef MAX_RNG_ENTROPY_SIZE
#define MAX_RNG_ENTROPY_SIZE 64
#endif
#ifndef MAX_RNG_REQ_SIZE
#define MAX_RNG_REQ_SIZE 32 /* ST33 and SLB9670 max is 32-bytes */
#endif
#ifndef RAM_INDEX_SPACE
#define RAM_INDEX_SPACE 512
#endif
#ifndef RSA_DEFAULT_PUBLIC_EXPONENT
#define RSA_DEFAULT_PUBLIC_EXPONENT 0x00010001
#endif
#ifndef ENABLE_PCR_NO_INCREMENT
#define ENABLE_PCR_NO_INCREMENT 1
#endif
#ifndef CRT_FORMAT_RSA
#define CRT_FORMAT_RSA 1
#endif
#ifndef PRIVATE_VENDOR_SPECIFIC_BYTES
#define PRIVATE_VENDOR_SPECIFIC_BYTES ((MAX_RSA_KEY_BYTES/2) * (3 + CRT_FORMAT_RSA * 2))
#endif
#ifndef MAX_CAP_CC
#define MAX_CAP_CC ((TPM_CC_LAST - TPM_CC_FIRST) + 1)
#endif
#ifndef MAX_CAP_DATA
#define MAX_CAP_DATA (MAX_CAP_BUFFER - sizeof(TPM_CAP) - sizeof(UINT32))
#endif
#ifndef MAX_CAP_HANDLES
#define MAX_CAP_HANDLES (MAX_CAP_DATA / sizeof(TPM_HANDLE))
#endif
#ifndef HASH_COUNT
#define HASH_COUNT (2) /* SHA1 and SHA256 */
#endif
#ifndef MAX_CAP_ALGS
#define MAX_CAP_ALGS (MAX_CAP_DATA / sizeof(TPMS_ALG_PROPERTY))
#endif
#ifndef MAX_TPM_PROPERTIES
#define MAX_TPM_PROPERTIES (MAX_CAP_DATA / sizeof(TPMS_TAGGED_PROPERTY))
#endif
#ifndef MAX_PCR_PROPERTIES
#define MAX_PCR_PROPERTIES (MAX_CAP_DATA / sizeof(TPMS_TAGGED_PCR_SELECT))
#endif
#ifndef MAX_ECC_CURVES
#define MAX_ECC_CURVES (MAX_CAP_DATA / sizeof(TPM_ECC_CURVE))
#endif
#ifndef MAX_TAGGED_POLICIES
#define MAX_TAGGED_POLICIES (MAX_CAP_DATA / sizeof(TPMS_TAGGED_POLICY))
#endif


/* ---------------------------------------------------------------------------*/
/* WRAPPER CONFIGURATION */
/* ---------------------------------------------------------------------------*/

/* Defines the default digest algo type to use for the wrapper functions */
#ifndef WOLFTPM2_WRAP_DIGEST
    #define WOLFTPM2_WRAP_DIGEST TPM_ALG_SHA256
#endif
/* Defines the default RSA key bits for the wrapper functions */
#ifndef WOLFTPM2_WRAP_RSA_KEY_BITS
    #define WOLFTPM2_WRAP_RSA_KEY_BITS MAX_RSA_KEY_BITS
#endif
#ifndef WOLFTPM2_WRAP_RSA_EXPONENT
    #define WOLFTPM2_WRAP_RSA_EXPONENT RSA_DEFAULT_PUBLIC_EXPONENT
#endif
#ifndef WOLFTPM2_WRAP_ECC_KEY_BITS
    #define WOLFTPM2_WRAP_ECC_KEY_BITS (MAX_ECC_KEY_BITS*8)
#endif

#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* __TPM2_TYPES_H__ */
