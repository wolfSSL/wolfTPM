/* spdm_error.h
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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

#ifndef WOLFSPDM_ERROR_H
#define WOLFSPDM_ERROR_H

#include <wolfspdm/spdm_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* wolfSPDM Error Codes */
enum WOLFSPDM_ERROR {
    WOLFSPDM_SUCCESS            =   0,  /* Operation successful */
    WOLFSPDM_E_INVALID_ARG      =  -1,  /* Invalid argument provided */
    WOLFSPDM_E_BUFFER_SMALL     =  -2,  /* Buffer too small for operation */
    WOLFSPDM_E_BAD_STATE        =  -3,  /* Invalid state for operation */
    WOLFSPDM_E_VERSION_MISMATCH =  -4,  /* SPDM version negotiation failed */
    WOLFSPDM_E_CRYPTO_FAIL      =  -5,  /* Cryptographic operation failed */
    WOLFSPDM_E_BAD_SIGNATURE    =  -6,  /* Signature verification failed */
    WOLFSPDM_E_BAD_HMAC         =  -7,  /* HMAC verification failed */
    WOLFSPDM_E_IO_FAIL          =  -8,  /* I/O callback failed */
    WOLFSPDM_E_TIMEOUT          =  -9,  /* Operation timed out */
    WOLFSPDM_E_PEER_ERROR       = -10,  /* Responder sent ERROR message */
    WOLFSPDM_E_DECRYPT_FAIL     = -11,  /* AEAD decryption/tag verification failed */
    WOLFSPDM_E_SEQUENCE         = -12,  /* Sequence number error */
    WOLFSPDM_E_NOT_CONNECTED    = -13,  /* Session not established */
    WOLFSPDM_E_ALREADY_INIT     = -14,  /* Context already initialized */
    WOLFSPDM_E_NO_MEMORY        = -15,  /* Memory allocation failed */
    WOLFSPDM_E_SESSION_INVALID  = -16,  /* Session ID invalid or mismatch */
    WOLFSPDM_E_KEY_EXCHANGE     = -17,  /* Key exchange failed */
};

/* Get human-readable error string */
WOLFSPDM_API const char* wolfSPDM_GetErrorString(int error);

#ifdef __cplusplus
}
#endif

#endif /* WOLFSPDM_ERROR_H */
