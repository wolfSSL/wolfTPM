/* tpm2_packet.h
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

#ifndef __TPM2_PACKET_H__
#define __TPM2_PACKET_H__

#include <wolftpm/tpm2.h>

#ifdef __cplusplus
    extern "C" {
#endif

#define TPM2_HEADER_SIZE 10 /* expected TPM2 header size */

/* Endianess Helpers */
#ifdef LITTLE_ENDIAN_ORDER
    #define cpu_to_be16(d) ByteReverseWord16(d)
    #define cpu_to_be32(d) ByteReverseWord32(d)
    #define cpu_to_be64(d) ByteReverseWord64(d)
    #define be16_to_cpu(d) ByteReverseWord16(d)
    #define be32_to_cpu(d) ByteReverseWord32(d)
    #define be64_to_cpu(d) ByteReverseWord64(d)
#else
    #define cpu_to_be16(d) (d)
    #define cpu_to_be32(d) (d)
    #define cpu_to_be64(d) (d)
    #define be16_to_cpu(d) (d)
    #define be32_to_cpu(d) (d)
    #define be64_to_cpu(d) (d)
#endif

/* For reference here is the TPM2 header (not used) */
typedef struct TPM2_HEADER {
    UINT16 tag;
    UINT32 size;
    union {
        UINT32 code;
        TPM_CC cc;
        TPM_RC rc;
    };
} TPM2_HEADER;

typedef struct TPM2_Packet {
    byte* buf;
    int pos;
    int size;
} TPM2_Packet;


/* Send Command Wrapper */
typedef enum CmdFlags {
    CMD_FLAG_NONE = 0x00,
    CMD_FLAG_ENC2 = 0x01, /* 16-bit size of first command parameter */
    CMD_FLAG_ENC4 = 0x02, /* 32-bit size (not used) */
    CMD_FLAG_DEC2 = 0x04, /* 16-bit size of first response parameter */
    CMD_FLAG_DEC4 = 0x08, /* 32-bit size (not used) */
    CMD_FLAG_AUTH_USER1 = 0x10,
    CMD_FLAG_AUTH_USER2 = 0x20,
    CMD_FLAG_AUTH_ADMIN = 0x40,
    CMD_FLAG_AUTH_DUP   = 0x80,
} CmdFlags_t;


/* Command Details */
typedef struct {
    unsigned char authCnt;      /* number of authentication handles - determined at run-time */
    unsigned char inHandleCnt;  /* number of input handles - fixed */
    unsigned char outHandleCnt; /* number of output handles - fixed */
    unsigned char flags;        /* see CmdFlags_t - fixed */
} CmdInfo_t;


WOLFTPM_LOCAL void TPM2_Packet_U16ToByteArray(UINT16 val, BYTE* b);
WOLFTPM_LOCAL void TPM2_Packet_U32ToByteArray(UINT32 val, BYTE* b);

WOLFTPM_LOCAL UINT16 TPM2_Packet_SwapU16(UINT16 data);
WOLFTPM_LOCAL UINT32 TPM2_Packet_SwapU32(UINT32 data);
WOLFTPM_LOCAL UINT64 TPM2_Packet_SwapU64(UINT64 data);

WOLFTPM_LOCAL void TPM2_Packet_InitBuf(TPM2_Packet* packet, byte* buf, int size);
WOLFTPM_LOCAL void TPM2_Packet_Init(TPM2_CTX* ctx, TPM2_Packet* packet);
WOLFTPM_LOCAL void TPM2_Packet_AppendU8(TPM2_Packet* packet, UINT8 data);
WOLFTPM_LOCAL void TPM2_Packet_ParseU8(TPM2_Packet* packet, UINT8* data);
WOLFTPM_LOCAL void TPM2_Packet_AppendU16(TPM2_Packet* packet, UINT16 data);
WOLFTPM_LOCAL void TPM2_Packet_ParseU16(TPM2_Packet* packet, UINT16* data);
WOLFTPM_LOCAL void TPM2_Packet_AppendU32(TPM2_Packet* packet, UINT32 data);
WOLFTPM_LOCAL void TPM2_Packet_ParseU32(TPM2_Packet* packet, UINT32* data);
WOLFTPM_LOCAL void TPM2_Packet_AppendU64(TPM2_Packet* packet, UINT64 data);
WOLFTPM_LOCAL void TPM2_Packet_ParseU64(TPM2_Packet* packet, UINT64* data);
WOLFTPM_LOCAL void TPM2_Packet_AppendS32(TPM2_Packet* packet, INT32 data);
WOLFTPM_LOCAL void TPM2_Packet_AppendBytes(TPM2_Packet* packet, byte* buf, int size);
WOLFTPM_LOCAL void TPM2_Packet_ParseBytes(TPM2_Packet* packet, byte* buf, int size);
WOLFTPM_LOCAL void TPM2_Packet_MarkU16(TPM2_Packet* packet, int* markSz);
WOLFTPM_LOCAL int  TPM2_Packet_PlaceU16(TPM2_Packet* packet, int markSz);
WOLFTPM_LOCAL void TPM2_Packet_MarkU32(TPM2_Packet* packet, int* markSz);
WOLFTPM_LOCAL void TPM2_Packet_PlaceU32(TPM2_Packet* packet, int markSz);
WOLFTPM_LOCAL TPM_ST TPM2_Packet_AppendAuth(TPM2_Packet* packet, TPM2_CTX* ctx, CmdInfo_t* info);
WOLFTPM_LOCAL void TPM2_Packet_AppendAuthCmd(TPM2_Packet* packet, TPMS_AUTH_COMMAND* authCmd);
WOLFTPM_LOCAL void TPM2_Packet_ParseAuth(TPM2_Packet* packet, TPMS_AUTH_RESPONSE* auth);
WOLFTPM_LOCAL void TPM2_Packet_AppendPCR(TPM2_Packet* packet, TPML_PCR_SELECTION* pcr);
WOLFTPM_LOCAL void TPM2_Packet_ParsePCR(TPM2_Packet* packet, TPML_PCR_SELECTION* pcr);
WOLFTPM_LOCAL void TPM2_Packet_AppendSymmetric(TPM2_Packet* packet, TPMT_SYM_DEF* symmetric);
WOLFTPM_LOCAL void TPM2_Packet_ParseSymmetric(TPM2_Packet* packet, TPMT_SYM_DEF* symmetric);
WOLFTPM_LOCAL void TPM2_Packet_AppendEccScheme(TPM2_Packet* packet, TPMT_SIG_SCHEME* scheme);
WOLFTPM_LOCAL void TPM2_Packet_ParseEccScheme(TPM2_Packet* packet, TPMT_SIG_SCHEME* scheme);
WOLFTPM_LOCAL void TPM2_Packet_AppendRsaScheme(TPM2_Packet* packet, TPMT_RSA_SCHEME* scheme);
WOLFTPM_LOCAL void TPM2_Packet_ParseRsaScheme(TPM2_Packet* packet, TPMT_RSA_SCHEME* scheme);
WOLFTPM_LOCAL void TPM2_Packet_AppendKeyedHashScheme(TPM2_Packet* packet, TPMT_KEYEDHASH_SCHEME* scheme);
WOLFTPM_LOCAL void TPM2_Packet_ParseKeyedHashScheme(TPM2_Packet* packet, TPMT_KEYEDHASH_SCHEME* scheme);
WOLFTPM_LOCAL void TPM2_Packet_AppendKdfScheme(TPM2_Packet* packet, TPMT_KDF_SCHEME* scheme);
WOLFTPM_LOCAL void TPM2_Packet_ParseKdfScheme(TPM2_Packet* packet, TPMT_KDF_SCHEME* scheme);
WOLFTPM_LOCAL void TPM2_Packet_AppendAsymScheme(TPM2_Packet* packet, TPMT_ASYM_SCHEME* scheme);
WOLFTPM_LOCAL void TPM2_Packet_ParseAsymScheme(TPM2_Packet* packet, TPMT_ASYM_SCHEME* scheme);
WOLFTPM_LOCAL void TPM2_Packet_AppendEccPoint(TPM2_Packet* packet, TPMS_ECC_POINT* point);
WOLFTPM_LOCAL void TPM2_Packet_ParseEccPoint(TPM2_Packet* packet, TPMS_ECC_POINT* point);
WOLFTPM_LOCAL void TPM2_Packet_AppendPoint(TPM2_Packet* packet, TPM2B_ECC_POINT* point);
WOLFTPM_LOCAL void TPM2_Packet_ParsePoint(TPM2_Packet* packet, TPM2B_ECC_POINT* point);
WOLFTPM_LOCAL void TPM2_Packet_AppendSensitive(TPM2_Packet* packet, TPM2B_SENSITIVE* sensitive);
WOLFTPM_LOCAL void TPM2_Packet_AppendSensitiveCreate(TPM2_Packet* packet, TPM2B_SENSITIVE_CREATE* sensitive);
WOLFTPM_LOCAL void TPM2_Packet_AppendPublicParms(TPM2_Packet* packet, TPMI_ALG_PUBLIC type, TPMU_PUBLIC_PARMS* parameters);
WOLFTPM_LOCAL void TPM2_Packet_ParsePublicParms(TPM2_Packet* packet, TPMI_ALG_PUBLIC type, TPMU_PUBLIC_PARMS* parameters);
WOLFTPM_LOCAL void TPM2_Packet_AppendPublicArea(TPM2_Packet* packet, TPMT_PUBLIC* publicArea);
WOLFTPM_LOCAL void TPM2_Packet_AppendPublic(TPM2_Packet* packet, TPM2B_PUBLIC* pub);
WOLFTPM_LOCAL void TPM2_Packet_ParsePublic(TPM2_Packet* packet, TPM2B_PUBLIC* pub);
WOLFTPM_LOCAL void TPM2_Packet_AppendSignature(TPM2_Packet* packet, TPMT_SIGNATURE* sig);
WOLFTPM_LOCAL void TPM2_Packet_ParseSignature(TPM2_Packet* packet, TPMT_SIGNATURE* sig);
WOLFTPM_LOCAL void TPM2_Packet_ParseAttest(TPM2_Packet* packet, TPMS_ATTEST* out);

WOLFTPM_LOCAL TPM_RC TPM2_Packet_Parse(TPM_RC rc, TPM2_Packet* packet);
WOLFTPM_LOCAL int TPM2_Packet_Finalize(TPM2_Packet* packet, TPM_ST tag, TPM_CC cc);


WOLFTPM_LOCAL int TPM2_GetCmdAuthCount(TPM2_CTX* ctx, const CmdInfo_t* info);

#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* __TPM2_PACKET_H__ */
