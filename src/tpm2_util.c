/* tpm2_util.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

/* Shared utility functions used by both libwolftpm and fwtpm_server.
 * These were previously in tpm2.c but are extracted here so fwtpm_server
 * can use them without pulling in the full TPM client transport stack.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2_types.h>
#include <wolftpm/tpm2.h>
#include <stdio.h>

#ifndef WOLFTPM2_NO_WOLFCRYPT
#include <wolfssl/wolfcrypt/hash.h>
#endif

int TPM2_GetHashDigestSize(TPMI_ALG_HASH hashAlg)
{
    switch (hashAlg) {
        case TPM_ALG_SHA1:
            return TPM_SHA_DIGEST_SIZE;
        case TPM_ALG_SHA256:
            return TPM_SHA256_DIGEST_SIZE;
        case TPM_ALG_SHA384:
            return TPM_SHA384_DIGEST_SIZE;
        case TPM_ALG_SHA512:
            return TPM_SHA512_DIGEST_SIZE;
        default:
            break;
    }
    return 0;
}

TPMI_ALG_HASH TPM2_GetTpmHashType(int hashType)
{
#ifndef WOLFTPM2_NO_WOLFCRYPT
    switch (hashType) {
        case (int)WC_HASH_TYPE_SHA:
            return TPM_ALG_SHA1;
        case (int)WC_HASH_TYPE_SHA256:
            return TPM_ALG_SHA256;
        case (int)WC_HASH_TYPE_SHA384:
            return TPM_ALG_SHA384;
        case (int)WC_HASH_TYPE_SHA512:
            return TPM_ALG_SHA512;
        default:
            break;
    }
#endif
    (void)hashType;
    return TPM_ALG_ERROR;
}

int TPM2_GetHashType(TPMI_ALG_HASH hashAlg)
{
#ifndef WOLFTPM2_NO_WOLFCRYPT
    switch (hashAlg) {
        case TPM_ALG_SHA1:
            return (int)WC_HASH_TYPE_SHA;
        case TPM_ALG_SHA256:
            return (int)WC_HASH_TYPE_SHA256;
        case TPM_ALG_SHA384:
            return (int)WC_HASH_TYPE_SHA384;
        case TPM_ALG_SHA512:
            return (int)WC_HASH_TYPE_SHA512;
        default:
            break;
    }
#endif
    (void)hashAlg;
    return 0;
}

/* Constant time memory comparison. Returns 0 if equal, non-zero if different.
 * Compares all bytes regardless of early match to prevent timing attacks. */
int TPM2_ConstantCompare(const byte* a, const byte* b, word32 len)
{
    word32 i;
    volatile word32 result = 0;
    for (i = 0; i < len; i++) {
        result |= (word32)(a[i] ^ b[i]);
    }
    return (result != 0) ? 1 : 0;
}

/* This routine fills the first len bytes of the memory area pointed by mem
   with zeros. It ensures compiler optimizations doesn't skip it  */
void TPM2_ForceZero(void* mem, word32 len)
{
    volatile byte* z = (volatile byte*)mem;
    while (len--) {
        *z++ = 0;
    }
}

#ifdef DEBUG_WOLFTPM
#define LINE_LEN 16
void TPM2_PrintBin(const byte* buffer, word32 length)
{
    word32 i, sz;

    if (!buffer) {
        printf("\tNULL\n");
        return;
    }

    while (length > 0) {
        sz = length;
        if (sz > LINE_LEN)
            sz = LINE_LEN;

        printf("\t");
        for (i = 0; i < LINE_LEN; i++) {
            if (i < length)
                printf("%02x ", buffer[i]);
            else
                printf("   ");
        }
        printf("| ");
        for (i = 0; i < sz; i++) {
            if (buffer[i] > 31 && buffer[i] < 127)
                printf("%c", buffer[i]);
            else
                printf(".");
        }
        printf("\r\n");

        buffer += sz;
        length -= sz;
    }
}

void TPM2_PrintAuth(const TPMS_AUTH_COMMAND* authCmd)
{
    if (authCmd == NULL)
        return;

    printf("authCmd:\n");
    printf("sessionHandle=0x%08X\n", (unsigned int)authCmd->sessionHandle);
    printf("nonceSize=%u nonceBuffer:\n", authCmd->nonce.size);
    TPM2_PrintBin(authCmd->nonce.buffer, authCmd->nonce.size);
    printf("sessionAttributes=0x%02X\n", authCmd->sessionAttributes);
    printf("hmacSize=%u hmacBuffer:\n", authCmd->hmac.size);
    TPM2_PrintBin(authCmd->hmac.buffer, authCmd->hmac.size);
}
#endif /* DEBUG_WOLFTPM */
