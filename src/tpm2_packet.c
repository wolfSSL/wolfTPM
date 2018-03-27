/* tpm2_packet.c
 *
 * Copyright (C) 2006-2018 wolfSSL Inc.
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


#include <wolftpm/tpm2_packet.h>


/* Endianess Helpers */
#ifdef LITTLE_ENDIAN_ORDER
    #define cpu_to_be16(d) ByteReverseWord16(d)
    #define cpu_to_be32(d) ByteReverseWord32(d)
    #define cpu_to_be64(d) ByteReverseWord64(d)
    #define be16_to_cpu(d) ByteReverseWord16(d)
    #define be32_to_cpu(d) ByteReverseWord32(d)
    #define be64_to_cpu(d) ByteReverseWord64(d)

    static inline word32 rotlFixed(word32 x, word32 y) {
        return (x << y) | (x >> (sizeof(y) * 8 - y));
    }
    static inline word32 rotrFixed(word32 x, word32 y) {
        return (x >> y) | (x << (sizeof(y) * 8 - y));
    }

    static inline word16 ByteReverseWord16(word16 value)
    {
    #if defined(__ICCARM__)
        return (word16)__REV16(value);
    #elif defined(KEIL_INTRINSICS)
        return (word16)__rev16(value);
    #elif defined(__GNUC_PREREQ) && __GNUC_PREREQ(4, 3)
        return (word16)__builtin_bswap16(value);
    #else
        return (value >> 8) | (value << 8);
    #endif
    }

    static inline word32 ByteReverseWord32(word32 value)
    {
    #ifdef PPC_INTRINSICS
        /* PPC: load reverse indexed instruction */
        return (word32)__lwbrx(&value,0);
    #elif defined(__ICCARM__)
        return (word32)__REV(value);
    #elif defined(KEIL_INTRINSICS)
        return (word32)__rev(value);
    #elif defined(__GNUC_PREREQ) && __GNUC_PREREQ(4, 3)
        return (word32)__builtin_bswap32(value);
    #elif defined(FAST_ROTATE)
        /* 5 instructions with rotate instruction, 9 without */
        return (rotrFixed(value, 8U) & 0xff00ff00) |
               (rotlFixed(value, 8U) & 0x00ff00ff);
    #else
        /* 6 instructions with rotate instruction, 8 without */
        value = ((value & 0xFF00FF00) >> 8) | ((value & 0x00FF00FF) << 8);
        return rotlFixed(value, 16U);
    #endif
    }

    static inline word64 ByteReverseWord64(word64 value)
    {
        return (word64)((word64)ByteReverseWord32((word32) value)) << 32 |
                        (word64)ByteReverseWord32((word32)(value   >> 32));
    }

#else
    #define cpu_to_be16(d) (d)
    #define cpu_to_be32(d) (d)
    #define cpu_to_be64(d) (d)
    #define be16_to_cpu(d) (d)
    #define be32_to_cpu(d) (d)
    #define be64_to_cpu(d) (d)
#endif

static byte* TPM2_Packet_GetPtr(TPM2_Packet* packet)
{
    return &packet->buf[packet->pos];
}



/******************************************************************************/
/* --- BEGIN TPM Packet Assembly / Parsing -- */
/******************************************************************************/
UINT16 TPM2_Packet_SwapU16(UINT16 data) {
    return cpu_to_be16(data);
}
UINT32 TPM2_Packet_SwapU32(UINT32 data) {
    return cpu_to_be32(data);
}
UINT64 TPM2_Packet_SwapU64(UINT64 data) {
    return cpu_to_be64(data);
}

void TPM2_Packet_Init(TPM2_CTX* ctx, TPM2_Packet* packet)
{
    if (ctx && packet) {
        packet->buf  = ctx->cmdBuf;
        packet->pos = sizeof(TPM2_HEADER); /* skip header (fill during finalize) */
        packet->size = sizeof(ctx->cmdBuf);
    }
}


void TPM2_Packet_AppendU8(TPM2_Packet* packet, UINT8 data)
{
    if (packet && (packet->pos + (int)sizeof(UINT8) <= packet->size)) {
        packet->buf[packet->pos] = data;
        packet->pos += sizeof(UINT8);
    }
}
void TPM2_Packet_ParseU8(TPM2_Packet* packet, UINT8* data)
{
    UINT8 value = 0;
    if (packet && (packet->pos + (int)sizeof(UINT8) <= packet->size)) {
        if (data)
            value = packet->buf[packet->pos];
        packet->pos += sizeof(UINT8);
    }
    if (data)
        *data = value;
}

void TPM2_Packet_AppendU16(TPM2_Packet* packet, UINT16 data)
{
    if (packet && (packet->pos + (int)sizeof(UINT16) <= packet->size)) {
        data = cpu_to_be16(data);
        XMEMCPY(&packet->buf[packet->pos], &data, sizeof(UINT16));
        packet->pos += sizeof(UINT16);
    }
}
void TPM2_Packet_ParseU16(TPM2_Packet* packet, UINT16* data)
{
    UINT16 value = 0;
    if (packet && (packet->pos + (int)sizeof(UINT16) <= packet->size)) {
        XMEMCPY(&value, &packet->buf[packet->pos], sizeof(UINT16));
        value = be16_to_cpu(value);
        packet->pos += sizeof(UINT16);
    }
    if (data)
        *data = value;
}

void TPM2_Packet_AppendU32(TPM2_Packet* packet, UINT32 data)
{
    if (packet && (packet->pos + (int)sizeof(UINT32) <= packet->size)) {
        data = cpu_to_be32(data);
        XMEMCPY(&packet->buf[packet->pos], &data, sizeof(UINT32));
        packet->pos += sizeof(UINT32);
    }
}
void TPM2_Packet_ParseU32(TPM2_Packet* packet, UINT32* data)
{
    UINT32 value = 0;
    if (packet && (packet->pos + (int)sizeof(UINT32) <= packet->size)) {
        if (data) {
            XMEMCPY(&value, &packet->buf[packet->pos], sizeof(UINT32));
            value = be32_to_cpu(value);
        }
        packet->pos += sizeof(UINT32);
    }
    if (data)
        *data = value;
}

void TPM2_Packet_AppendU64(TPM2_Packet* packet, UINT64 data)
{
    if (packet && (packet->pos + (int)sizeof(UINT64) <= packet->size)) {
        data = cpu_to_be64(data);
        XMEMCPY(&packet->buf[packet->pos], &data, sizeof(UINT64));
        packet->pos += sizeof(UINT64);
    }
}
void TPM2_Packet_ParseU64(TPM2_Packet* packet, UINT64* data)
{
    UINT64 value = 0;
    if (packet && (packet->pos + (int)sizeof(UINT64) <= packet->size)) {
        if (data) {
            XMEMCPY(&value, &packet->buf[packet->pos], sizeof(UINT64));
            value = be64_to_cpu(value);
        }
        packet->pos += sizeof(UINT64);
    }
    if (data)
        *data = value;
}

void TPM2_Packet_AppendS32(TPM2_Packet* packet, INT32 data)
{
    if (packet && (packet->pos + (int)sizeof(INT32) <= packet->size)) {
        data = cpu_to_be32(data);
        XMEMCPY(&packet->buf[packet->pos], &data, sizeof(INT32));
        packet->pos += sizeof(INT32);
    }
}

void TPM2_Packet_AppendBytes(TPM2_Packet* packet, byte* buf, int size)
{
    if (packet && (packet->pos + size <= packet->size)) {
        if (buf)
            XMEMCPY(&packet->buf[packet->pos], buf, size);
        packet->pos += size;
    }
}
void TPM2_Packet_ParseBytes(TPM2_Packet* packet, byte* buf, int size)
{
    if (packet) {
        if (buf) {
            /* truncate result */
            int sizeToCopy = size;
            if (packet->pos + sizeToCopy > packet->size)
                sizeToCopy = packet->size - packet->pos;
            XMEMCPY(buf, &packet->buf[packet->pos], sizeToCopy);
        }
        packet->pos += size;
    }
}


void TPM2_Packet_AppendAuth(TPM2_Packet* packet, TPMS_AUTH_COMMAND* auth)
{
    word32 sz;

    if (auth == NULL)
        return;

    /* make sure continueSession is set for TPM_RS_PW */
    if (auth->sessionHandle == TPM_RS_PW &&
       (auth->sessionAttributes & TPMA_SESSION_continueSession) == 0) {
        auth->sessionAttributes |= TPMA_SESSION_continueSession;
    }

    sz = sizeof(UINT32) + /* session handle */
         sizeof(UINT16) + auth->nonce.size + 1 +  /* none and session attribute */
         sizeof(UINT16) + auth->auth.size;        /* auth */
    TPM2_Packet_AppendU32(packet, sz);
    TPM2_Packet_AppendU32(packet, auth->sessionHandle);

    TPM2_Packet_AppendU16(packet, auth->nonce.size);
    TPM2_Packet_AppendBytes(packet, auth->nonce.buffer, auth->nonce.size);
    TPM2_Packet_AppendU8(packet, auth->sessionAttributes);
    TPM2_Packet_AppendU16(packet, auth->auth.size);
    TPM2_Packet_AppendBytes(packet, auth->auth.buffer, auth->auth.size);
}
void TPM2_Packet_ParseAuth(TPM2_Packet* packet, TPMS_AUTH_RESPONSE* auth)
{
    if (auth == NULL)
        return;

    TPM2_Packet_ParseU16(packet, &auth->nonce.size);
    TPM2_Packet_ParseBytes(packet, auth->nonce.buffer, auth->nonce.size);
    TPM2_Packet_ParseU8(packet, &auth->sessionAttributes);
    TPM2_Packet_ParseU16(packet, &auth->auth.size);
    TPM2_Packet_ParseBytes(packet, auth->auth.buffer, auth->auth.size);
}

void TPM2_Packet_AppendPCR(TPM2_Packet* packet, TPML_PCR_SELECTION* pcr)
{
    int i;
    TPM2_Packet_AppendU32(packet, pcr->count);
    for (i=0; i<(int)pcr->count; i++) {
        TPM2_Packet_AppendU16(packet, pcr->pcrSelections[i].hash);
        TPM2_Packet_AppendU8(packet, pcr->pcrSelections[i].sizeofSelect);
        TPM2_Packet_AppendBytes(packet,
            pcr->pcrSelections[i].pcrSelect,
            pcr->pcrSelections[i].sizeofSelect);
    }
}
void TPM2_Packet_ParsePCR(TPM2_Packet* packet, TPML_PCR_SELECTION* pcr)
{
    int i;
    TPM2_Packet_ParseU32(packet, &pcr->count);
    for (i=0; i<(int)pcr->count; i++) {
        TPM2_Packet_ParseU16(packet, &pcr->pcrSelections[i].hash);
        TPM2_Packet_ParseU8(packet, &pcr->pcrSelections[i].sizeofSelect);
        TPM2_Packet_ParseBytes(packet,
            pcr->pcrSelections[i].pcrSelect,
            pcr->pcrSelections[i].sizeofSelect);
    }
}

void TPM2_Packet_AppendSymmetric(TPM2_Packet* packet, TPMT_SYM_DEF* symmetric)
{
    TPM2_Packet_AppendU16(packet, symmetric->algorithm);
    if (symmetric->algorithm != TPM_ALG_NULL) {
        TPM2_Packet_AppendU16(packet, symmetric->keyBits.sym);
        TPM2_Packet_AppendU16(packet, symmetric->mode.sym);
    }
}
void TPM2_Packet_ParseSymmetric(TPM2_Packet* packet, TPMT_SYM_DEF* symmetric)
{
    TPM2_Packet_ParseU16(packet, &symmetric->algorithm);
    if (symmetric->algorithm != TPM_ALG_NULL) {
        TPM2_Packet_ParseU16(packet, &symmetric->keyBits.sym);
        TPM2_Packet_ParseU16(packet, &symmetric->mode.sym);
    }
}

void TPM2_Packet_AppendEccScheme(TPM2_Packet* packet, TPMT_SIG_SCHEME* scheme)
{
    TPM2_Packet_AppendU16(packet, scheme->scheme);
    if (scheme->scheme != TPM_ALG_NULL)
        TPM2_Packet_AppendU16(packet, scheme->details.any.hashAlg);
}
void TPM2_Packet_ParseEccScheme(TPM2_Packet* packet, TPMT_SIG_SCHEME* scheme)
{
    TPM2_Packet_ParseU16(packet, &scheme->scheme);
    if (scheme->scheme != TPM_ALG_NULL)
        TPM2_Packet_ParseU16(packet, &scheme->details.any.hashAlg);
}

void TPM2_Packet_AppendRsaScheme(TPM2_Packet* packet, TPMT_RSA_SCHEME* scheme)
{
    TPM2_Packet_AppendU16(packet, scheme->scheme);
    if (scheme->scheme != TPM_ALG_NULL)
        TPM2_Packet_AppendU16(packet, scheme->details.anySig.hashAlg);
}
void TPM2_Packet_ParseRsaScheme(TPM2_Packet* packet, TPMT_RSA_SCHEME* scheme)
{
    TPM2_Packet_ParseU16(packet, &scheme->scheme);
    if (scheme->scheme != TPM_ALG_NULL)
        TPM2_Packet_ParseU16(packet, &scheme->details.anySig.hashAlg);
}

void TPM2_Packet_AppendKeyedHashScheme(TPM2_Packet* packet, TPMT_KEYEDHASH_SCHEME* scheme)
{
    TPM2_Packet_AppendU16(packet, scheme->scheme);
    if (scheme->scheme != TPM_ALG_NULL)
        TPM2_Packet_AppendU16(packet, scheme->details.hmac.hashAlg);
}
void TPM2_Packet_ParseKeyedHashScheme(TPM2_Packet* packet, TPMT_KEYEDHASH_SCHEME* scheme)
{
    TPM2_Packet_ParseU16(packet, &scheme->scheme);
    if (scheme->scheme != TPM_ALG_NULL)
        TPM2_Packet_ParseU16(packet, &scheme->details.hmac.hashAlg);
}

void TPM2_Packet_AppendKdfScheme(TPM2_Packet* packet, TPMT_KDF_SCHEME* scheme)
{
    TPM2_Packet_AppendU16(packet, scheme->scheme);
    if (scheme->scheme != TPM_ALG_NULL)
        TPM2_Packet_AppendU16(packet, scheme->details.any.hashAlg);
}
void TPM2_Packet_ParseKdfScheme(TPM2_Packet* packet, TPMT_KDF_SCHEME* scheme)
{
    TPM2_Packet_ParseU16(packet, &scheme->scheme);
    if (scheme->scheme != TPM_ALG_NULL)
        TPM2_Packet_ParseU16(packet, &scheme->details.any.hashAlg);
}

void TPM2_Packet_AppendAsymScheme(TPM2_Packet* packet, TPMT_ASYM_SCHEME* scheme)
{
    TPM2_Packet_AppendU16(packet, scheme->scheme);
    if (scheme->scheme != TPM_ALG_NULL)
        TPM2_Packet_AppendU16(packet, scheme->details.anySig.hashAlg);
}
void TPM2_Packet_ParseAsymScheme(TPM2_Packet* packet, TPMT_ASYM_SCHEME* scheme)
{
    TPM2_Packet_ParseU16(packet, &scheme->scheme);
    if (scheme->scheme != TPM_ALG_NULL)
        TPM2_Packet_ParseU16(packet, &scheme->details.anySig.hashAlg);
}

void TPM2_Packet_AppendEccPoint(TPM2_Packet* packet, TPMS_ECC_POINT* point)
{
    TPM2_Packet_AppendU16(packet, point->x.size);
    TPM2_Packet_AppendBytes(packet, point->x.buffer, point->x.size);
    TPM2_Packet_AppendU16(packet, point->y.size);
    TPM2_Packet_AppendBytes(packet, point->y.buffer, point->y.size);
}
void TPM2_Packet_ParseEccPoint(TPM2_Packet* packet, TPMS_ECC_POINT* point)
{
    TPM2_Packet_ParseU16(packet, &point->x.size);
    TPM2_Packet_ParseBytes(packet, point->x.buffer, point->x.size);
    TPM2_Packet_ParseU16(packet, &point->y.size);
    TPM2_Packet_ParseBytes(packet, point->y.buffer, point->y.size);
}

void TPM2_Packet_AppendPoint(TPM2_Packet* packet, TPM2B_ECC_POINT* point)
{
    int sz = point->point.x.size + point->point.y.size;
    TPM2_Packet_AppendU16(packet, sz);
    TPM2_Packet_AppendEccPoint(packet, &point->point);
}
void TPM2_Packet_ParsePoint(TPM2_Packet* packet, TPM2B_ECC_POINT* point)
{
    TPM2_Packet_ParseU16(packet, &point->size);
    TPM2_Packet_ParseEccPoint(packet, &point->point);
}

void TPM2_Packet_AppendSensitive(TPM2_Packet* packet, TPM2B_SENSITIVE_CREATE* sensitive)
{
    UINT16 sz = 2 + sensitive->sensitive.userAuth.size +
                2 + sensitive->sensitive.data.size;
    TPM2_Packet_AppendU16(packet, sz);
    TPM2_Packet_AppendU16(packet, sensitive->sensitive.userAuth.size);
    TPM2_Packet_AppendBytes(packet, sensitive->sensitive.userAuth.buffer,
        sensitive->sensitive.userAuth.size);
    TPM2_Packet_AppendU16(packet, sensitive->sensitive.data.size);
    TPM2_Packet_AppendBytes(packet, sensitive->sensitive.data.buffer,
        sensitive->sensitive.data.size);
}

void TPM2_Packet_AppendPublicParms(TPM2_Packet* packet, TPMI_ALG_PUBLIC type,
    TPMU_PUBLIC_PARMS* parameters)
{
    switch (type) {
        case TPM_ALG_KEYEDHASH:
            TPM2_Packet_AppendKeyedHashScheme(packet, &parameters->keyedHashDetail.scheme);
            break;
        case TPM_ALG_SYMCIPHER:
            TPM2_Packet_AppendU16(packet, parameters->symDetail.sym.algorithm);
            TPM2_Packet_AppendU16(packet, parameters->symDetail.sym.keyBits.sym);
            TPM2_Packet_AppendU16(packet, parameters->symDetail.sym.mode.sym);
            break;
        case TPM_ALG_RSA:
            TPM2_Packet_AppendSymmetric(packet, &parameters->rsaDetail.symmetric);
            TPM2_Packet_AppendRsaScheme(packet, &parameters->rsaDetail.scheme);
            TPM2_Packet_AppendU16(packet, parameters->rsaDetail.keyBits);
            TPM2_Packet_AppendU32(packet, parameters->rsaDetail.exponent);
            break;
        case TPM_ALG_ECC:
            TPM2_Packet_AppendSymmetric(packet, &parameters->eccDetail.symmetric);
            TPM2_Packet_AppendEccScheme(packet, &parameters->eccDetail.scheme);
            TPM2_Packet_AppendU16(packet, parameters->eccDetail.curveID);
            TPM2_Packet_AppendKdfScheme(packet, &parameters->eccDetail.kdf);
            break;
        default:
            TPM2_Packet_AppendSymmetric(packet, &parameters->asymDetail.symmetric);
            TPM2_Packet_AppendAsymScheme(packet, &parameters->asymDetail.scheme);
            break;
    }
}
void TPM2_Packet_ParsePublicParms(TPM2_Packet* packet, TPMI_ALG_PUBLIC type,
    TPMU_PUBLIC_PARMS* parameters)
{
    switch (type) {
        case TPM_ALG_KEYEDHASH:
            TPM2_Packet_ParseKeyedHashScheme(packet, &parameters->keyedHashDetail.scheme);
            break;
        case TPM_ALG_SYMCIPHER:
            TPM2_Packet_ParseU16(packet, &parameters->symDetail.sym.algorithm);
            TPM2_Packet_ParseU16(packet, &parameters->symDetail.sym.keyBits.sym);
            TPM2_Packet_ParseU16(packet, &parameters->symDetail.sym.mode.sym);
            break;
        case TPM_ALG_RSA:
            TPM2_Packet_ParseSymmetric(packet, &parameters->rsaDetail.symmetric);
            TPM2_Packet_ParseRsaScheme(packet, &parameters->rsaDetail.scheme);
            TPM2_Packet_ParseU16(packet, &parameters->rsaDetail.keyBits);
            TPM2_Packet_ParseU32(packet, &parameters->rsaDetail.exponent);
            break;
        case TPM_ALG_ECC:
            TPM2_Packet_ParseSymmetric(packet, &parameters->eccDetail.symmetric);
            TPM2_Packet_ParseEccScheme(packet, &parameters->eccDetail.scheme);
            TPM2_Packet_ParseU16(packet, &parameters->eccDetail.curveID);
            TPM2_Packet_ParseKdfScheme(packet, &parameters->eccDetail.kdf);
            break;
        default:
            TPM2_Packet_ParseSymmetric(packet, &parameters->asymDetail.symmetric);
            TPM2_Packet_ParseAsymScheme(packet, &parameters->asymDetail.scheme);
            break;
    }
}

void TPM2_Packet_AppendPublic(TPM2_Packet* packet, TPM2B_PUBLIC* pub)
{
    byte* sizePtr;
    int sz;

    /* placeholder for final size */
    sizePtr = TPM2_Packet_GetPtr(packet);
    TPM2_Packet_AppendU16(packet, 0);
    sz = packet->pos;

    TPM2_Packet_AppendU16(packet, pub->publicArea.type);
    TPM2_Packet_AppendU16(packet, pub->publicArea.nameAlg);
    TPM2_Packet_AppendU32(packet, pub->publicArea.objectAttributes);
    TPM2_Packet_AppendU16(packet, pub->publicArea.authPolicy.size);
    TPM2_Packet_AppendBytes(packet, pub->publicArea.authPolicy.buffer,
        pub->publicArea.authPolicy.size);

    TPM2_Packet_AppendPublicParms(packet, pub->publicArea.type,
        &pub->publicArea.parameters);

    switch (pub->publicArea.type) {
    case TPM_ALG_KEYEDHASH:
        TPM2_Packet_AppendU16(packet, pub->publicArea.unique.keyedHash.size);
        TPM2_Packet_AppendBytes(packet, pub->publicArea.unique.keyedHash.buffer,
            pub->publicArea.unique.keyedHash.size);
        break;
    case TPM_ALG_SYMCIPHER:
        TPM2_Packet_AppendU16(packet, pub->publicArea.unique.sym.size);
        TPM2_Packet_AppendBytes(packet, pub->publicArea.unique.sym.buffer,
            pub->publicArea.unique.sym.size);
        break;
    case TPM_ALG_RSA:
        TPM2_Packet_AppendU16(packet, pub->publicArea.unique.rsa.size);
        TPM2_Packet_AppendBytes(packet, pub->publicArea.unique.rsa.buffer,
            pub->publicArea.unique.rsa.size);
        break;
    case TPM_ALG_ECC:
        TPM2_Packet_AppendEccPoint(packet, &pub->publicArea.unique.ecc);
        break;
    default:
        /* TPMS_DERIVE derive; ? */
        break;
    }

    /* update with actual size */
    sz = packet->pos - sz;
    *((UINT16*)sizePtr) = cpu_to_be16(sz);
}
void TPM2_Packet_ParsePublic(TPM2_Packet* packet, TPM2B_PUBLIC* pub)
{
    TPM2_Packet_ParseU16(packet, &pub->size);
    if (pub->size > 0) {
        TPM2_Packet_ParseU16(packet, &pub->publicArea.type);
        TPM2_Packet_ParseU16(packet, &pub->publicArea.nameAlg);
        TPM2_Packet_ParseU32(packet, &pub->publicArea.objectAttributes);
        TPM2_Packet_ParseU16(packet, &pub->publicArea.authPolicy.size);
        TPM2_Packet_ParseBytes(packet, pub->publicArea.authPolicy.buffer,
            pub->publicArea.authPolicy.size);

        TPM2_Packet_ParsePublicParms(packet, pub->publicArea.type,
            &pub->publicArea.parameters);

        switch (pub->publicArea.type) {
        case TPM_ALG_KEYEDHASH:
            TPM2_Packet_ParseU16(packet, &pub->publicArea.unique.keyedHash.size);
            TPM2_Packet_ParseBytes(packet, pub->publicArea.unique.keyedHash.buffer,
                pub->publicArea.unique.keyedHash.size);
            break;
        case TPM_ALG_SYMCIPHER:
            TPM2_Packet_ParseU16(packet, &pub->publicArea.unique.sym.size);
            TPM2_Packet_ParseBytes(packet, pub->publicArea.unique.sym.buffer,
                pub->publicArea.unique.sym.size);
            break;
        case TPM_ALG_RSA:
            TPM2_Packet_ParseU16(packet, &pub->publicArea.unique.rsa.size);
            TPM2_Packet_ParseBytes(packet, pub->publicArea.unique.rsa.buffer,
                pub->publicArea.unique.rsa.size);
            break;
        case TPM_ALG_ECC:
            TPM2_Packet_ParseEccPoint(packet, &pub->publicArea.unique.ecc);
            break;
        default:
            /* TPMS_DERIVE derive; ? */
            break;
        }
    }
}

void TPM2_Packet_AppendSignature(TPM2_Packet* packet, TPMT_SIGNATURE* sig)
{
    int digestSz;

    TPM2_Packet_AppendU16(packet, sig->sigAlgo);

    switch (sig->sigAlgo) {
    case TPM_ALG_ECDSA:
    case TPM_ALG_ECDAA:
        TPM2_Packet_AppendU16(packet, sig->signature.ecdsa.hash);

        TPM2_Packet_AppendU16(packet, sig->signature.ecdsa.signatureR.size);
        TPM2_Packet_AppendBytes(packet, sig->signature.ecdsa.signatureR.buffer,
            sig->signature.ecdsa.signatureR.size);

        TPM2_Packet_AppendU16(packet, sig->signature.ecdsa.signatureS.size);
        TPM2_Packet_AppendBytes(packet, sig->signature.ecdsa.signatureS.buffer,
            sig->signature.ecdsa.signatureS.size);
        break;
    case TPM_ALG_RSASSA:
    case TPM_ALG_RSAPSS:
        TPM2_Packet_AppendU16(packet, sig->signature.rsassa.hash);

        TPM2_Packet_AppendU16(packet, sig->signature.rsassa.sig.size);
        TPM2_Packet_AppendBytes(packet, sig->signature.rsassa.sig.buffer,
            sig->signature.rsassa.sig.size);
        break;
    case TPM_ALG_HMAC:
        TPM2_Packet_AppendU16(packet, sig->signature.hmac.hashAlg);
        digestSz = TPM2_GetHashDigestSize(sig->signature.hmac.hashAlg);
        TPM2_Packet_AppendBytes(packet, sig->signature.hmac.digest.H, digestSz);
        break;
    default:
        break;
    }
}
void TPM2_Packet_ParseSignature(TPM2_Packet* packet, TPMT_SIGNATURE* sig)
{
    int digestSz;

    TPM2_Packet_ParseU16(packet, &sig->sigAlgo);

    switch (sig->sigAlgo) {
    case TPM_ALG_ECDSA:
    case TPM_ALG_ECDAA:
        TPM2_Packet_ParseU16(packet, &sig->signature.ecdsa.hash);

        TPM2_Packet_ParseU16(packet, &sig->signature.ecdsa.signatureR.size);
        TPM2_Packet_ParseBytes(packet, sig->signature.ecdsa.signatureR.buffer,
            sig->signature.ecdsa.signatureR.size);

        TPM2_Packet_ParseU16(packet, &sig->signature.ecdsa.signatureS.size);
        TPM2_Packet_ParseBytes(packet, sig->signature.ecdsa.signatureS.buffer,
            sig->signature.ecdsa.signatureS.size);
        break;
    case TPM_ALG_RSASSA:
    case TPM_ALG_RSAPSS:
        TPM2_Packet_ParseU16(packet, &sig->signature.rsassa.hash);

        TPM2_Packet_ParseU16(packet, &sig->signature.rsassa.sig.size);
        TPM2_Packet_ParseBytes(packet, sig->signature.rsassa.sig.buffer,
            sig->signature.rsassa.sig.size);
        break;
    case TPM_ALG_HMAC:
        TPM2_Packet_ParseU16(packet, &sig->signature.hmac.hashAlg);
        digestSz = TPM2_GetHashDigestSize(sig->signature.hmac.hashAlg);
        TPM2_Packet_ParseBytes(packet, sig->signature.hmac.digest.H, digestSz);
        break;
    default:
        break;
    }
}

TPM_RC TPM2_Packet_Parse(TPM_RC rc, TPM2_Packet* packet)
{
    if (rc == TPM_RC_SUCCESS && packet) {
        UINT32 tmpRc;
        UINT32 respSz;
        packet->pos = 0; /* reset position */
        TPM2_Packet_ParseU16(packet, NULL);     /* tag */
        TPM2_Packet_ParseU32(packet, &respSz);  /* response size */
        TPM2_Packet_ParseU32(packet, &tmpRc);   /* response code */
        packet->size = respSz;
        rc = tmpRc;
    }
    return rc;
}

    int TPM2_Packet_Finalize(TPM2_Packet* packet, TPM_ST tag, TPM_CC cc)
{
    word32 cmdSz = packet->pos; /* get total packet size */
    packet->pos = 0; /* reset position to front */
    TPM2_Packet_AppendU16(packet, tag);    /* tag */
    TPM2_Packet_AppendU32(packet, cmdSz);  /* command size */
    TPM2_Packet_AppendU32(packet, cc);     /* command code */
    packet->pos = cmdSz; /* restore total size */
    return cmdSz;
}

/******************************************************************************/
/* --- END TPM Packet Assembly / Parsing -- */
/******************************************************************************/
