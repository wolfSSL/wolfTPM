/* tpm2_packet.c
 *
 * Copyright (C) 2006-2022 wolfSSL Inc.
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

#include <wolftpm/tpm2_packet.h>

/* convert 16 bit integer to opaque */
static inline void c16toa(word16 wc_u16, byte* c)
{
    c[0] = (wc_u16 >> 8) & 0xff;
    c[1] =  wc_u16 & 0xff;
}
/* convert 32 bit integer to opaque */
static inline void c32toa(word32 wc_u32, byte* c)
{
    c[0] = (wc_u32 >> 24) & 0xff;
    c[1] = (wc_u32 >> 16) & 0xff;
    c[2] = (wc_u32 >>  8) & 0xff;
    c[3] =  wc_u32 & 0xff;
}

/******************************************************************************/
/* --- BEGIN TPM Packet Assembly / Parsing -- */
/******************************************************************************/
void TPM2_Packet_U16ToByteArray(UINT16 val, BYTE* b)
{
    if (b)
        c16toa(val, b);
}
void TPM2_Packet_U32ToByteArray(UINT32 val, BYTE* b)
{
    if (b)
        c32toa(val, b);
}

UINT16 TPM2_Packet_SwapU16(UINT16 data)
{
    return cpu_to_be16(data);
}
UINT32 TPM2_Packet_SwapU32(UINT32 data)
{
    return cpu_to_be32(data);
}
UINT64 TPM2_Packet_SwapU64(UINT64 data)
{
    return cpu_to_be64(data);
}

void TPM2_Packet_InitBuf(TPM2_Packet* packet, byte* buf, int size)
{
    if (packet) {
        packet->buf  = buf;
        packet->pos = TPM2_HEADER_SIZE; /* skip header (fill during finalize) */
        packet->size = size;
    }
}

void TPM2_Packet_Init(TPM2_CTX* ctx, TPM2_Packet* packet)
{
    if (ctx) {
        TPM2_Packet_InitBuf(packet, ctx->cmdBuf, (int)sizeof(ctx->cmdBuf));
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

void TPM2_Packet_MarkU16(TPM2_Packet* packet, int* markSz)
{
    if (packet) {
        /* mark placeholder for final size */
        if (markSz)
            *markSz = packet->pos;
        TPM2_Packet_AppendU16(packet, 0);
    }
}
int TPM2_Packet_PlaceU16(TPM2_Packet* packet, int markSz)
{
    int rc = 0;
    /* update with actual size */
    if (packet) {
        UINT16 data;
        byte* sizePtr = &packet->buf[markSz];
        markSz += sizeof(UINT16); /* skip marker */
        if (markSz <= packet->pos) {
            rc = packet->pos - markSz;

            data = cpu_to_be16(rc);
            XMEMCPY(sizePtr, &data, sizeof(UINT16));
        }
    }
    return rc;
}

void TPM2_Packet_MarkU32(TPM2_Packet* packet, int* markSz)
{
    if (packet) {
        /* mark placeholder for final size */
        if (markSz)
            *markSz = packet->pos;
        TPM2_Packet_AppendU32(packet, 0);
    }
}
void TPM2_Packet_PlaceU32(TPM2_Packet* packet, int markSz)
{
    /* update with actual size */
    if (packet) {
        UINT32 data;
        byte* sizePtr = &packet->buf[markSz];
        markSz += sizeof(UINT32); /* skip marker */
        if (markSz <= packet->pos) {
            markSz = packet->pos - markSz;

            data = cpu_to_be32(markSz);
            XMEMCPY(sizePtr, &data, sizeof(UINT32));
        }
    }
}

void TPM2_Packet_AppendAuthCmd(TPM2_Packet* packet, TPMS_AUTH_COMMAND* authCmd)
{
    if (packet == NULL || authCmd == NULL)
        return;

#ifdef WOLFTPM_DEBUG_VERBOSE
    TPM2_PrintAuth(authCmd);
#endif

    /* make sure continueSession is set for TPM_RS_PW */
    if (authCmd->sessionHandle == TPM_RS_PW &&
        (authCmd->sessionAttributes & TPMA_SESSION_continueSession) == 0) {
        authCmd->sessionAttributes |= TPMA_SESSION_continueSession;
    }
    TPM2_Packet_AppendU32(packet, authCmd->sessionHandle);
    TPM2_Packet_AppendU16(packet, authCmd->nonce.size);
    TPM2_Packet_AppendBytes(packet, authCmd->nonce.buffer, authCmd->nonce.size);
    TPM2_Packet_AppendU8(packet, authCmd->sessionAttributes);
    TPM2_Packet_AppendU16(packet, authCmd->hmac.size);
    TPM2_Packet_AppendBytes(packet, authCmd->hmac.buffer, authCmd->hmac.size);
}

/* Finds the number of active Auth Session in the given TPM2 context.
 * If the info is not provided then returns the populated ctx->session,
 * otherwise adjusted based on the command information provided.
 */
int TPM2_GetCmdAuthCount(TPM2_CTX* ctx, const CmdInfo_t* info)
{
    int authSessCount = 0, sessionCount;
    TPMI_SH_AUTH_SESSION sessionHandle;
    TPMA_SESSION sessionAttributes;
    unsigned char flags = 0xFF;

    if (info != NULL)
        flags = info->flags;

    /* The auth sessions must be first in the list */
    for (sessionCount = 0; sessionCount < MAX_SESSION_NUM; sessionCount++) {
        int authReq = 0;
        sessionHandle = ctx->session[sessionCount].sessionHandle;
        sessionAttributes = ctx->session[sessionCount].sessionAttributes;

        if (info != NULL &&
            ((sessionCount == 0 && (flags &
                (CMD_FLAG_AUTH_USER1 |
                 CMD_FLAG_AUTH_ADMIN |
                 CMD_FLAG_AUTH_DUP))) ||
             (sessionCount == 1 && (flags &
                (CMD_FLAG_AUTH_USER2))))) {
            authReq = 1;
        }

        /* Only a password auth if command user auth set */
        if (sessionHandle == TPM_RS_PW && authReq) {
            authSessCount++;
        }

        /* Only an HMAC session with encrypt, decrypt or audit set */
        else if (authSessCount > 0 && TPM2_IS_HMAC_SESSION(sessionHandle)) {
            if (((sessionAttributes & TPMA_SESSION_decrypt) && (flags &
                    (CMD_FLAG_ENC2 | CMD_FLAG_ENC4))) ||
                ((sessionAttributes & TPMA_SESSION_encrypt) && (flags &
                    (CMD_FLAG_DEC2 | CMD_FLAG_DEC4))) ||
                 (sessionAttributes & TPMA_SESSION_audit))
                authSessCount++;
        }

        /* Allow policy auth */
        else if (authReq && TPM2_IS_POLICY_SESSION(sessionHandle)) {
            authSessCount++;
        }
        else if (!authReq) {
            /* we cannot accept further authentications */
            break;
        }
        else {
            /* This will result in a TPM_RC_AUTH_MISSING auth error from the TPM
             * Make sure the wolfTPM2_SetAuth* API is called for the index! */
        #ifdef DEBUG_WOLFTPM
            printf("Warning: Command requires auth at index %d!\n",
                sessionCount);
        #endif
        }
    }
    return authSessCount;
}

TPM_ST TPM2_Packet_AppendAuth(TPM2_Packet* packet, TPM2_CTX* ctx, CmdInfo_t* info)
{
    TPM_ST st = TPM_ST_NO_SESSIONS;

    if (ctx == NULL || info == NULL)
        return BAD_FUNC_ARG;
    if (ctx->session == NULL)
        return st;

    info->authCnt = TPM2_GetCmdAuthCount(ctx, info);
    if (info->authCnt > 0) {
        int i, tmpSz = 0;
        TPM2_Packet_MarkU32(packet, &tmpSz);
        for (i=0; i<info->authCnt; i++) {
            /* Note: Casting a TPM2_AUTH_SESSION to TPMS_AUTH_COMMAND here,
             * this is allowed because top of structure matches */
            TPM2_Packet_AppendAuthCmd(packet, (TPMS_AUTH_COMMAND*)&ctx->session[i]);
        }
        /* based on position difference places calculated size at marked U32 above */
        TPM2_Packet_PlaceU32(packet, tmpSz);
        st = TPM_ST_SESSIONS;
    }
    return st;
}

void TPM2_Packet_ParseAuth(TPM2_Packet* packet, TPMS_AUTH_RESPONSE* authRsp)
{
    if (authRsp == NULL)
        return;

    TPM2_Packet_ParseU16(packet, &authRsp->nonce.size);
    TPM2_Packet_ParseBytes(packet, authRsp->nonce.buffer, authRsp->nonce.size);
    TPM2_Packet_ParseU8(packet, &authRsp->sessionAttributes);
    TPM2_Packet_ParseU16(packet, &authRsp->hmac.size);
    TPM2_Packet_ParseBytes(packet, authRsp->hmac.buffer, authRsp->hmac.size);
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
    switch (symmetric->algorithm) {
        case TPM_ALG_XOR:
            TPM2_Packet_AppendU16(packet, symmetric->keyBits.xorr);
            break;
        case TPM_ALG_AES:
            TPM2_Packet_AppendU16(packet, symmetric->keyBits.aes);
            TPM2_Packet_AppendU16(packet, symmetric->mode.aes);
            break;
        case TPM_ALG_NULL:
            break;
        default:
            TPM2_Packet_AppendU16(packet, symmetric->keyBits.sym);
            TPM2_Packet_AppendU16(packet, symmetric->mode.sym);
            break;
    }
}
void TPM2_Packet_ParseSymmetric(TPM2_Packet* packet, TPMT_SYM_DEF* symmetric)
{
    XMEMSET(symmetric, 0, sizeof(TPMT_SYM_DEF));
    TPM2_Packet_ParseU16(packet, &symmetric->algorithm);
    switch (symmetric->algorithm) {
        case TPM_ALG_XOR:
            TPM2_Packet_ParseU16(packet, &symmetric->keyBits.xorr);
            break;
        case TPM_ALG_AES:
            TPM2_Packet_ParseU16(packet, &symmetric->keyBits.aes);
            TPM2_Packet_ParseU16(packet, &symmetric->mode.aes);
            break;
        case TPM_ALG_NULL:
            break;
        default:
            TPM2_Packet_ParseU16(packet, &symmetric->keyBits.sym);
            TPM2_Packet_ParseU16(packet, &symmetric->mode.sym);
            break;
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
    if (point == NULL) {
#ifdef DEBUG_WOLFTPM
        printf("Error null argument passed to TPM2_Packet_ParseEccPoint()\n");
#endif
        return; /* help out static analysis */
    }

    TPM2_Packet_ParseU16(packet, &point->x.size);
    TPM2_Packet_ParseBytes(packet, point->x.buffer, point->x.size);
    TPM2_Packet_ParseU16(packet, &point->y.size);
    TPM2_Packet_ParseBytes(packet, point->y.buffer, point->y.size);
}

void TPM2_Packet_AppendPoint(TPM2_Packet* packet, TPM2B_ECC_POINT* point)
{
    int tmpSz = 0;

    TPM2_Packet_MarkU16(packet, &tmpSz);
    TPM2_Packet_AppendEccPoint(packet, &point->point);
    TPM2_Packet_PlaceU16(packet, tmpSz);
}
void TPM2_Packet_ParsePoint(TPM2_Packet* packet, TPM2B_ECC_POINT* point)
{
    TPM2_Packet_ParseU16(packet, &point->size);
    TPM2_Packet_ParseEccPoint(packet, &point->point);
}

void TPM2_Packet_AppendSensitive(TPM2_Packet* packet, TPM2B_SENSITIVE* sensitive)
{
    int tmpSz = 0;
    TPMU_SENSITIVE_COMPOSITE* sens = &sensitive->sensitiveArea.sensitive;

    TPM2_Packet_MarkU16(packet, &tmpSz);

    TPM2_Packet_AppendU16(packet, sensitive->sensitiveArea.sensitiveType);

    TPM2_Packet_AppendU16(packet, sensitive->sensitiveArea.authValue.size);
    TPM2_Packet_AppendBytes(packet, sensitive->sensitiveArea.authValue.buffer,
        sensitive->sensitiveArea.authValue.size);

    TPM2_Packet_AppendU16(packet, sensitive->sensitiveArea.seedValue.size);
    TPM2_Packet_AppendBytes(packet, sensitive->sensitiveArea.seedValue.buffer,
        sensitive->sensitiveArea.seedValue.size);

    switch (sensitive->sensitiveArea.sensitiveType) {
    case TPM_ALG_RSA:
        TPM2_Packet_AppendU16(packet, sens->rsa.size);
        TPM2_Packet_AppendBytes(packet, sens->rsa.buffer, sens->rsa.size);
        break;
    case TPM_ALG_ECC:
        TPM2_Packet_AppendU16(packet, sens->ecc.size);
        TPM2_Packet_AppendBytes(packet, sens->ecc.buffer, sens->ecc.size);
        break;
    case TPM_ALG_KEYEDHASH:
        TPM2_Packet_AppendU16(packet, sens->bits.size);
        TPM2_Packet_AppendBytes(packet, sens->bits.buffer, sens->bits.size);
        break;
    case TPM_ALG_SYMCIPHER:
        TPM2_Packet_AppendU16(packet, sens->sym.size);
        TPM2_Packet_AppendBytes(packet, sens->sym.buffer, sens->sym.size);
        break;
    }

    TPM2_Packet_PlaceU16(packet, tmpSz);
}

void TPM2_Packet_AppendSensitiveCreate(TPM2_Packet* packet, TPM2B_SENSITIVE_CREATE* sensitive)
{
    int tmpSz = 0;

    TPM2_Packet_MarkU16(packet, &tmpSz);

    TPM2_Packet_AppendU16(packet, sensitive->sensitive.userAuth.size);
    TPM2_Packet_AppendBytes(packet, sensitive->sensitive.userAuth.buffer,
        sensitive->sensitive.userAuth.size);
    TPM2_Packet_AppendU16(packet, sensitive->sensitive.data.size);
    TPM2_Packet_AppendBytes(packet, sensitive->sensitive.data.buffer,
        sensitive->sensitive.data.size);

    TPM2_Packet_PlaceU16(packet, tmpSz);
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

void TPM2_Packet_AppendPublicArea(TPM2_Packet* packet, TPMT_PUBLIC* publicArea)
{
    TPM2_Packet_AppendU16(packet, publicArea->type);
    TPM2_Packet_AppendU16(packet, publicArea->nameAlg);
    TPM2_Packet_AppendU32(packet, publicArea->objectAttributes);
    TPM2_Packet_AppendU16(packet, publicArea->authPolicy.size);
    TPM2_Packet_AppendBytes(packet, publicArea->authPolicy.buffer,
        publicArea->authPolicy.size);

    TPM2_Packet_AppendPublicParms(packet, publicArea->type,
        &publicArea->parameters);

    switch (publicArea->type) {
    case TPM_ALG_KEYEDHASH:
        TPM2_Packet_AppendU16(packet, publicArea->unique.keyedHash.size);
        TPM2_Packet_AppendBytes(packet, publicArea->unique.keyedHash.buffer,
            publicArea->unique.keyedHash.size);
        break;
    case TPM_ALG_SYMCIPHER:
        TPM2_Packet_AppendU16(packet, publicArea->unique.sym.size);
        TPM2_Packet_AppendBytes(packet, publicArea->unique.sym.buffer,
            publicArea->unique.sym.size);
        break;
    case TPM_ALG_RSA:
        TPM2_Packet_AppendU16(packet, publicArea->unique.rsa.size);
        TPM2_Packet_AppendBytes(packet, publicArea->unique.rsa.buffer,
            publicArea->unique.rsa.size);
        break;
    case TPM_ALG_ECC:
        TPM2_Packet_AppendEccPoint(packet, &publicArea->unique.ecc);
        break;
    default:
        /* TPMS_DERIVE derive; ? */
        break;
    }
}
void TPM2_Packet_AppendPublic(TPM2_Packet* packet, TPM2B_PUBLIC* pub)
{
    int tmpSz = 0;

    TPM2_Packet_MarkU16(packet, &tmpSz);
    TPM2_Packet_AppendPublicArea(packet, &pub->publicArea);
    pub->size = TPM2_Packet_PlaceU16(packet, tmpSz);
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

    TPM2_Packet_AppendU16(packet, sig->sigAlg);

    switch (sig->sigAlg) {
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

    TPM2_Packet_ParseU16(packet, &sig->sigAlg);

    switch (sig->sigAlg) {
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

void TPM2_Packet_ParseAttest(TPM2_Packet* packet, TPMS_ATTEST* out)
{
    XMEMSET(out, 0, sizeof(TPMS_ATTEST));

    TPM2_Packet_ParseU32(packet, &out->magic);
    if (out->magic != TPM_GENERATED_VALUE) {
    #ifdef DEBUG_WOLFTPM
        printf("Attestation magic invalid!\n");
    #endif
        return;
    }

    TPM2_Packet_ParseU16(packet, &out->type);

    TPM2_Packet_ParseU16(packet, &out->qualifiedSigner.size);
    TPM2_Packet_ParseBytes(packet, out->qualifiedSigner.name,
        out->qualifiedSigner.size);

    TPM2_Packet_ParseU16(packet, &out->extraData.size);
    TPM2_Packet_ParseBytes(packet, out->extraData.buffer,
        out->extraData.size);

    TPM2_Packet_ParseU64(packet, &out->clockInfo.clock);
    TPM2_Packet_ParseU32(packet, &out->clockInfo.resetCount);
    TPM2_Packet_ParseU32(packet, &out->clockInfo.restartCount);
    TPM2_Packet_ParseU8(packet, &out->clockInfo.safe);

    TPM2_Packet_ParseU64(packet, &out->firmwareVersion);

    switch (out->type) {
        case TPM_ST_ATTEST_CERTIFY:
            TPM2_Packet_ParseU16(packet, &out->attested.certify.name.size);
            TPM2_Packet_ParseBytes(packet, out->attested.certify.name.name,
                out->attested.certify.name.size);
            TPM2_Packet_ParseU16(packet, &out->attested.certify.qualifiedName.size);
            TPM2_Packet_ParseBytes(packet, out->attested.certify.qualifiedName.name,
                out->attested.certify.qualifiedName.size);
            break;
        case TPM_ST_ATTEST_CREATION:
            TPM2_Packet_ParseU16(packet, &out->attested.creation.objectName.size);
            TPM2_Packet_ParseBytes(packet, out->attested.creation.objectName.name,
                out->attested.creation.objectName.size);
            TPM2_Packet_ParseU16(packet, &out->attested.creation.creationHash.size);
            TPM2_Packet_ParseBytes(packet, out->attested.creation.creationHash.buffer,
                out->attested.creation.creationHash.size);
            break;
        case TPM_ST_ATTEST_QUOTE:
            TPM2_Packet_ParsePCR(packet, &out->attested.quote.pcrSelect);
            TPM2_Packet_ParseU16(packet, &out->attested.quote.pcrDigest.size);
            TPM2_Packet_ParseBytes(packet, out->attested.quote.pcrDigest.buffer,
                out->attested.quote.pcrDigest.size);
            break;
        case TPM_ST_ATTEST_COMMAND_AUDIT:
            TPM2_Packet_ParseU64(packet, &out->attested.commandAudit.auditCounter);
            TPM2_Packet_ParseU16(packet, &out->attested.commandAudit.digestAlg);
            TPM2_Packet_ParseU16(packet, &out->attested.commandAudit.auditDigest.size);
            TPM2_Packet_ParseBytes(packet, out->attested.commandAudit.auditDigest.buffer,
                out->attested.commandAudit.auditDigest.size);
            TPM2_Packet_ParseU16(packet, &out->attested.commandAudit.commandDigest.size);
            TPM2_Packet_ParseBytes(packet, out->attested.commandAudit.commandDigest.buffer,
                out->attested.commandAudit.commandDigest.size);
            break;
        case TPM_ST_ATTEST_SESSION_AUDIT:
            TPM2_Packet_ParseU8(packet, &out->attested.sessionAudit.exclusiveSession);
            TPM2_Packet_ParseU16(packet, &out->attested.sessionAudit.sessionDigest.size);
            TPM2_Packet_ParseBytes(packet, out->attested.sessionAudit.sessionDigest.buffer,
                out->attested.sessionAudit.sessionDigest.size);
            break;
        case TPM_ST_ATTEST_TIME:
            TPM2_Packet_ParseU64(packet, &out->attested.time.time.time);
            TPM2_Packet_ParseU64(packet, &out->attested.time.time.clockInfo.clock);
            TPM2_Packet_ParseU32(packet, &out->attested.time.time.clockInfo.resetCount);
            TPM2_Packet_ParseU32(packet, &out->attested.time.time.clockInfo.restartCount);
            TPM2_Packet_ParseU8(packet, &out->attested.time.time.clockInfo.safe);
            TPM2_Packet_ParseU64(packet, &out->attested.time.firmwareVersion);
            break;
        case TPM_ST_ATTEST_NV:
            TPM2_Packet_ParseU16(packet, &out->attested.nv.indexName.size);
            TPM2_Packet_ParseBytes(packet, out->attested.nv.indexName.name,
                out->attested.nv.indexName.size);
            TPM2_Packet_ParseU16(packet, &out->attested.nv.offset);
            TPM2_Packet_ParseU16(packet, &out->attested.nv.nvContents.size);
            TPM2_Packet_ParseBytes(packet, out->attested.nv.nvContents.buffer,
                out->attested.nv.nvContents.size);
            break;
        default:
            /* unknown attestation type */
        #ifdef DEBUG_WOLFTPM
            printf("Unknown attestation type: 0x%x\n", out->type);
        #endif
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
