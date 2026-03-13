/* spdm_types.h
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

#ifndef WOLFSPDM_TYPES_H
#define WOLFSPDM_TYPES_H

/* wolfSSL options MUST be included first */
#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>

/* Visibility: when built as part of wolfTPM, use WOLFTPM_API for export */
#ifdef BUILDING_WOLFTPM
    #include <wolftpm/visibility.h>
    #define WOLFSPDM_API WOLFTPM_API
#else
    #ifndef WOLFSPDM_API
    #define WOLFSPDM_API
    #endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Include wolfSSL types */
#ifndef WOLFSSL_TYPES
    #include <wolfssl/wolfcrypt/types.h>
#endif

/* ----- SPDM Protocol Constants (DMTF DSP0274 / DSP0277) ----- */

/* SPDM Version Numbers (used in version negotiation and key derivation) */
#define SPDM_VERSION_12             0x12    /* SPDM 1.2 */
#define SPDM_VERSION_13             0x13    /* SPDM 1.3 */
#define SPDM_VERSION_14             0x14    /* SPDM 1.4 */

/* SPDM Request Codes (used by this implementation) */
#define SPDM_GET_VERSION            0x84
#define SPDM_KEY_EXCHANGE           0xE4
#define SPDM_FINISH                 0xE5
#define SPDM_END_SESSION            0xEA
#define SPDM_VENDOR_DEFINED_REQUEST 0xFE

/* SPDM Response Codes (used by this implementation) */
#define SPDM_VERSION                0x04
#define SPDM_KEY_EXCHANGE_RSP       0x64
#define SPDM_FINISH_RSP             0x65
#define SPDM_ERROR                  0x7F

/* SPDM Error Codes (in Param1 of ERROR response) */
#define SPDM_ERROR_INVALID_REQUEST      0x01
#define SPDM_ERROR_BUSY                 0x03
#define SPDM_ERROR_UNEXPECTED_REQUEST   0x04
#define SPDM_ERROR_UNSPECIFIED          0x05
#define SPDM_ERROR_DECRYPT_ERROR        0x06
#define SPDM_ERROR_UNSUPPORTED_REQUEST  0x07
#define SPDM_ERROR_REQUEST_IN_FLIGHT    0x08
#define SPDM_ERROR_INVALID_RESPONSE     0x09
#define SPDM_ERROR_SESSION_LIMIT        0x0A
#define SPDM_ERROR_SESSION_REQUIRED     0x0B
#define SPDM_ERROR_RESET_REQUIRED       0x0C
#define SPDM_ERROR_RESPONSE_TOO_LARGE   0x0D
#define SPDM_ERROR_REQUEST_TOO_LARGE    0x0E
#define SPDM_ERROR_LARGE_RESPONSE       0x0F
#define SPDM_ERROR_MSG_LOST             0x10
#define SPDM_ERROR_MAJOR_VERSION_MISMATCH 0x41
#define SPDM_ERROR_RESPONSE_NOT_READY   0x42
#define SPDM_ERROR_REQUEST_RESYNCH      0x43

/* Algorithm Set B Fixed Parameters (FIPS 140-3 Level 3 compliant)
 * P-384 ECDSA/ECDH, SHA-384, AES-256-GCM, HKDF */
#define WOLFSPDM_HASH_SIZE          48  /* SHA-384 output size */
#define WOLFSPDM_ECC_KEY_SIZE       48  /* P-384 coordinate size */
#define WOLFSPDM_ECC_POINT_SIZE     (2 * WOLFSPDM_ECC_KEY_SIZE)  /* P-384 X||Y */
#define WOLFSPDM_ECC_SIG_SIZE       (2 * WOLFSPDM_ECC_KEY_SIZE)  /* ECDSA r||s */
#define WOLFSPDM_AEAD_KEY_SIZE      32  /* AES-256 key size */
#define WOLFSPDM_AEAD_IV_SIZE       12  /* AES-GCM IV size */
#define WOLFSPDM_AEAD_TAG_SIZE      16  /* AES-GCM tag size */
#define WOLFSPDM_AEAD_OVERHEAD      48  /* Max AEAD record overhead (hdr+pad+tag) */

/* ----- Buffer/Message Size Limits ----- */

#define WOLFSPDM_MAX_MSG_SIZE       4096    /* Maximum SPDM message size */
#define WOLFSPDM_MAX_TRANSCRIPT     4096    /* Maximum transcript buffer */
#define WOLFSPDM_RANDOM_SIZE        32      /* Random data in KEY_EXCHANGE */

/* ----- MCTP Transport Constants ----- */

#define MCTP_MESSAGE_TYPE_SPDM      0x05    /* SPDM over MCTP */

/* ----- Key Derivation Labels (SPDM 1.2 per DSP0277) ----- */

#define SPDM_BIN_CONCAT_PREFIX_12   "spdm1.2 "
#define SPDM_BIN_CONCAT_PREFIX_13   "spdm1.3 "
#define SPDM_BIN_CONCAT_PREFIX_14   "spdm1.4 "
#define SPDM_BIN_CONCAT_PREFIX_LEN  8

#define SPDM_LABEL_REQ_HS_DATA      "req hs data"
#define SPDM_LABEL_RSP_HS_DATA      "rsp hs data"
#define SPDM_LABEL_REQ_DATA         "req app data"
#define SPDM_LABEL_RSP_DATA         "rsp app data"
#define SPDM_LABEL_FINISHED         "finished"
#define SPDM_LABEL_KEY              "key"
#define SPDM_LABEL_IV               "iv"
#ifdef __cplusplus
}
#endif

#endif /* WOLFSPDM_TYPES_H */
