/* spdm_tcg.c
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#ifdef WOLFTPM_SPDM

/* Shared TCG SPDM code used by both Nuvoton and Nations Technology TPMs. */

#include "spdm_internal.h"

#ifdef WOLFTPM_SPDM_TCG

#include <wolftpm/spdm/spdm_tcg.h>

/* ----- Vendor Command Helpers ----- */

int wolfSPDM_TCG_VendorCmdClear(WOLFSPDM_CTX* ctx, const char* vdCode,
    const byte* payload, word32 payloadSz, WOLFSPDM_VENDOR_RSP* rsp)
{
    byte spdmMsg[WOLFSPDM_VENDOR_BUF_SZ];
    int spdmMsgSz;
    byte rxBuf[WOLFSPDM_VENDOR_RX_SZ];
    word32 rxSz;
    int rc;
    byte ver;

    ver = ctx->spdmVersion ? ctx->spdmVersion : SPDM_VERSION_13;
    spdmMsgSz = wolfSPDM_BuildVendorDefined(ver, vdCode, payload,
        payloadSz, spdmMsg, sizeof(spdmMsg));
    if (spdmMsgSz < 0) {
        return spdmMsgSz;
    }

    rxSz = sizeof(rxBuf);
    rc = wolfSPDM_SendReceive(ctx, spdmMsg, (word32)spdmMsgSz, rxBuf, &rxSz);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    if (rxSz >= 4 && rxBuf[1] == SPDM_ERROR) {
        wolfSPDM_DebugPrint(ctx, "%s: SPDM ERROR 0x%02x 0x%02x\n",
            vdCode, rxBuf[2], rxBuf[3]);
        return WOLFSPDM_E_PEER_ERROR;
    }

    if (rsp != NULL) {
        rsp->payloadSz = sizeof(rsp->payload);
        XMEMSET(rsp->vdCode, 0, sizeof(rsp->vdCode));
        rc = wolfSPDM_ParseVendorDefined(rxBuf, rxSz,
            rsp->vdCode, rsp->payload, &rsp->payloadSz);
        if (rc < 0) {
            return rc;
        }
        /* Validate response VdCode matches the request */
        if (XMEMCMP(rsp->vdCode, vdCode, WOLFSPDM_VDCODE_LEN) != 0) {
            wolfSPDM_DebugPrint(ctx, "%s: unexpected VdCode '%.8s'\n",
                vdCode, rsp->vdCode);
            return WOLFSPDM_E_PEER_ERROR;
        }
    }

    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_TCG_VendorCmdSecured(WOLFSPDM_CTX* ctx, const char* vdCode,
    const byte* payload, word32 payloadSz)
{
    byte spdmMsg[WOLFSPDM_VENDOR_BUF_SZ];
    int spdmMsgSz;
    byte decBuf[WOLFSPDM_VENDOR_BUF_SZ];
    word32 decSz = 0;
    int rc;
    byte ver;

    ver = ctx->spdmVersion ? ctx->spdmVersion : SPDM_VERSION_13;
    spdmMsgSz = wolfSPDM_BuildVendorDefined(ver, vdCode, payload,
        payloadSz, spdmMsg, sizeof(spdmMsg));
    if (spdmMsgSz < 0) {
        rc = spdmMsgSz;
    }
    else {
        decSz = sizeof(decBuf);
        rc = wolfSPDM_SecuredExchange(ctx, spdmMsg, (word32)spdmMsgSz,
            decBuf, &decSz);
    }

    if (rc == WOLFSPDM_SUCCESS && decSz >= 4 && decBuf[1] == SPDM_ERROR) {
        wolfSPDM_DebugPrint(ctx, "%s: SPDM ERROR 0x%02x 0x%02x\n",
            vdCode, decBuf[2], decBuf[3]);
        rc = WOLFSPDM_E_PEER_ERROR;
    }

    /* Always zero sensitive stack buffers */
    wc_ForceZero(spdmMsg, sizeof(spdmMsg));
    wc_ForceZero(decBuf, sizeof(decBuf));

    return rc;
}

/* ----- TCG SPDM Binding Message Framing ----- */

int wolfSPDM_BuildTcgClearMessage(
    WOLFSPDM_CTX* ctx,
    const byte* spdmPayload, word32 spdmPayloadSz,
    byte* outBuf, word32 outBufSz)
{
    word32 totalSz;

    if (ctx == NULL || spdmPayload == NULL || outBuf == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    totalSz = WOLFSPDM_TCG_HEADER_SIZE + spdmPayloadSz;

    if (outBufSz < totalSz) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    wolfSPDM_WriteTcgHeader(outBuf, WOLFSPDM_TCG_TAG_CLEAR, totalSz,
        ctx->connectionHandle, ctx->fipsIndicator);
    XMEMCPY(outBuf + WOLFSPDM_TCG_HEADER_SIZE, spdmPayload, spdmPayloadSz);

    return (int)totalSz;
}

int wolfSPDM_ParseTcgClearMessage(
    const byte* inBuf, word32 inBufSz,
    byte* spdmPayload, word32* spdmPayloadSz,
    WOLFSPDM_TCG_CLEAR_HDR* hdr)
{
    word16 tag;
    word32 msgSize;
    word32 payloadSz;

    if (inBuf == NULL || spdmPayload == NULL || spdmPayloadSz == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (inBufSz < WOLFSPDM_TCG_HEADER_SIZE) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    tag = SPDM_Get16BE(inBuf);
    if (tag != WOLFSPDM_TCG_TAG_CLEAR) {
        return WOLFSPDM_E_PEER_ERROR;
    }

    msgSize = SPDM_Get32BE(inBuf + 2);
    if (msgSize < WOLFSPDM_TCG_HEADER_SIZE || msgSize > inBufSz) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    payloadSz = msgSize - WOLFSPDM_TCG_HEADER_SIZE;
    if (*spdmPayloadSz < payloadSz) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    if (hdr != NULL) {
        hdr->tag = tag;
        hdr->size = msgSize;
        hdr->connectionHandle = SPDM_Get32BE(inBuf + 6);
        hdr->fipsIndicator = SPDM_Get16BE(inBuf + 10);
        hdr->reserved = SPDM_Get32BE(inBuf + 12);
    }

    XMEMCPY(spdmPayload, inBuf + WOLFSPDM_TCG_HEADER_SIZE, payloadSz);
    *spdmPayloadSz = payloadSz;

    return (int)payloadSz;
}

/* ----- SPDM Vendor Defined Message Helpers ----- */

int wolfSPDM_BuildVendorDefined(
    byte spdmVersion,
    const char* vdCode,
    const byte* payload, word32 payloadSz,
    byte* outBuf, word32 outBufSz)
{
    word32 totalSz;
    word32 offset = 0;

    if (vdCode == NULL || outBuf == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    /* SPDM VENDOR_DEFINED_REQUEST format:
     * SPDMVersion(1) + reqRspCode(1) + param1(1) + param2(1) +
     * standardId(2/LE) + vendorIdLen(1) + reqLength(2/LE) +
     * vdCode(8) + payload */
    totalSz = 1 + 1 + 1 + 1 + 2 + 1 + 2 + WOLFSPDM_VDCODE_LEN + payloadSz;

    if (outBufSz < totalSz) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    outBuf[offset++] = spdmVersion;
    outBuf[offset++] = SPDM_VENDOR_DEFINED_REQUEST;
    outBuf[offset++] = 0x00;
    outBuf[offset++] = 0x00;
    /* Standard ID (0x0001 = TCG, little-endian) */
    SPDM_Set16LE(outBuf + offset, 0x0001);
    offset += 2;
    /* Vendor ID Length (0 for TCG) */
    outBuf[offset++] = 0x00;
    /* Request Length (vdCode + payload, little-endian) */
    SPDM_Set16LE(outBuf + offset, (word16)(WOLFSPDM_VDCODE_LEN + payloadSz));
    offset += 2;
    /* VdCode (8-byte ASCII) */
    XMEMCPY(outBuf + offset, vdCode, WOLFSPDM_VDCODE_LEN);
    offset += WOLFSPDM_VDCODE_LEN;
    /* Payload */
    if (payload != NULL && payloadSz > 0) {
        XMEMCPY(outBuf + offset, payload, payloadSz);
        offset += payloadSz;
    }

    return (int)offset;
}

int wolfSPDM_ParseVendorDefined(
    const byte* inBuf, word32 inBufSz,
    char* vdCode,
    byte* payload, word32* payloadSz)
{
    word32 offset = 0;
    word16 reqLength;
    word32 dataLen;
    byte vendorIdLen;

    if (inBuf == NULL || vdCode == NULL || payload == NULL ||
        payloadSz == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    /* Minimum: version(1) + code(1) + param1(1) + param2(1) + stdId(2/LE) +
     *          vidLen(1) + reqLen(2/LE) + vdCode(8) = 17 */
    if (inBufSz < 17) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    offset += 1; /* SPDM version */
    offset += 3; /* request/response code + params */
    offset += 2; /* standard ID */
    vendorIdLen = inBuf[offset];
    offset += 1 + vendorIdLen;

    if (offset + 2 > inBufSz) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    reqLength = SPDM_Get16LE(inBuf + offset);
    offset += 2;

    if (reqLength < WOLFSPDM_VDCODE_LEN) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    if (offset + reqLength > inBufSz) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    XMEMCPY(vdCode, inBuf + offset, WOLFSPDM_VDCODE_LEN);
    vdCode[WOLFSPDM_VDCODE_LEN] = '\0';
    offset += WOLFSPDM_VDCODE_LEN;

    dataLen = reqLength - WOLFSPDM_VDCODE_LEN;
    if (*payloadSz < dataLen) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    if (dataLen > 0) {
        XMEMCPY(payload, inBuf + offset, dataLen);
    }
    *payloadSz = dataLen;

    return (int)dataLen;
}

/* ----- Shared TCG SPDM Functions ----- */

int wolfSPDM_TCG_GetPubKey(
    WOLFSPDM_CTX* ctx,
    byte* pubKey, word32* pubKeySz)
{
    WOLFSPDM_VENDOR_RSP rsp;
    int rc;

    if (ctx == NULL || pubKey == NULL || pubKeySz == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    wolfSPDM_DebugPrint(ctx, "TCG: GET_PUBK\n");

    rc = wolfSPDM_TCG_VendorCmdClear(ctx, WOLFSPDM_VDCODE_GET_PUBK,
        NULL, 0, &rsp);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    if (XMEMCMP(rsp.vdCode, WOLFSPDM_VDCODE_GET_PUBK,
            WOLFSPDM_VDCODE_LEN) != 0) {
        wolfSPDM_DebugPrint(ctx, "GET_PUBK: Unexpected VdCode '%.8s'\n",
            rsp.vdCode);
        return WOLFSPDM_E_PEER_ERROR;
    }

    wolfSPDM_DebugPrint(ctx, "GET_PUBK: Got TPMT_PUBLIC (%u bytes)\n",
        rsp.payloadSz);

    if (*pubKeySz < rsp.payloadSz) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }
    XMEMCPY(pubKey, rsp.payload, rsp.payloadSz);
    *pubKeySz = rsp.payloadSz;

    /* Store for cert_chain_buffer_hash computation */
    if (rsp.payloadSz <= sizeof(ctx->rspPubKey)) {
        XMEMCPY(ctx->rspPubKey, rsp.payload, rsp.payloadSz);
        ctx->rspPubKeyLen = rsp.payloadSz;
        ctx->flags.hasRspPubKey = 1;
    }

    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_TCG_GivePubKey(
    WOLFSPDM_CTX* ctx,
    const byte* pubKey, word32 pubKeySz)
{
    int rc;

    if (ctx == NULL || pubKey == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (ctx->state < WOLFSPDM_STATE_KEY_EX) {
        return WOLFSPDM_E_BAD_STATE;
    }

    wolfSPDM_DebugPrint(ctx, "TCG: GIVE_PUB (%u bytes)\n", pubKeySz);

    rc = wolfSPDM_TCG_VendorCmdSecured(ctx, WOLFSPDM_VDCODE_GIVE_PUB,
        pubKey, pubKeySz);
    if (rc != WOLFSPDM_SUCCESS) {
        wolfSPDM_DebugPrint(ctx, "GIVE_PUB: SecuredExchange failed %d\n", rc);
        return rc;
    }

    wolfSPDM_DebugPrint(ctx, "GIVE_PUB: Success\n");
    return WOLFSPDM_SUCCESS;
}

/* ----- Shared GET_CAPABILITIES + NEGOTIATE_ALGORITHMS ----- */

int wolfSPDM_TCG_GetCapabilities(WOLFSPDM_CTX* ctx, word32 capsFlags)
{
    byte capsReq[20];
    byte capsRsp[64];
    word32 capsRspSz = sizeof(capsRsp);
    word32 off = 0;
    int rc;

    capsReq[off++] = ctx->spdmVersion;
    capsReq[off++] = 0xE1; /* GET_CAPABILITIES */
    capsReq[off++] = 0x00; capsReq[off++] = 0x00;
    /* Reserved(1) + CTExponent(1) + Reserved(2) */
    capsReq[off++] = 0x00; capsReq[off++] = 0x1F;
    capsReq[off++] = 0x00; capsReq[off++] = 0x00;
    /* Flags (4 bytes LE) */
    SPDM_Set32LE(capsReq + off, capsFlags);
    off += 4;
    /* DataTransferSize */
    capsReq[off++] = 0xC0; capsReq[off++] = 0x07;
    capsReq[off++] = 0x00; capsReq[off++] = 0x00;
    /* MaxSPDMmsgSize */
    capsReq[off++] = 0xC0; capsReq[off++] = 0x07;
    capsReq[off++] = 0x00; capsReq[off++] = 0x00;

    wolfSPDM_DebugPrint(ctx, "TCG: GET_CAPABILITIES\n");
    rc = wolfSPDM_TranscriptAdd(ctx, capsReq, off);
    if (rc == WOLFSPDM_SUCCESS)
        rc = wolfSPDM_SendReceive(ctx, capsReq, off, capsRsp, &capsRspSz);
    if (rc == WOLFSPDM_SUCCESS)
        rc = wolfSPDM_TranscriptAdd(ctx, capsRsp, capsRspSz);
    if (rc != WOLFSPDM_SUCCESS) {
        ctx->state = WOLFSPDM_STATE_ERROR;
    }
    return rc;
}

int wolfSPDM_TCG_NegotiateAlgorithms(WOLFSPDM_CTX* ctx)
{
    /* Algorithm Set B: P-384/SHA-384/AES-256-GCM */
    byte algReq[48];
    byte algRsp[128];
    word32 algRspSz = sizeof(algRsp);
    word32 off = 0;
    int rc;

    algReq[off++] = ctx->spdmVersion;
    algReq[off++] = 0xE3; /* NEGOTIATE_ALGORITHMS */
    algReq[off++] = 0x04; /* Param1: NumAlgStructs = 4 */
    algReq[off++] = 0x00;
    algReq[off++] = 0x30; algReq[off++] = 0x00; /* Length = 48 */
    algReq[off++] = 0x00; algReq[off++] = 0x02; /* MeasurementSpec + Reserved */
    /* BaseAsymAlgo: ECDSA_ECC_NIST_P384 */
    algReq[off++] = 0x80; algReq[off++] = 0x00;
    algReq[off++] = 0x00; algReq[off++] = 0x00;
    /* BaseHashAlgo: SHA_384 */
    algReq[off++] = 0x02; algReq[off++] = 0x00;
    algReq[off++] = 0x00; algReq[off++] = 0x00;
    /* Reserved (16 bytes) */
    XMEMSET(&algReq[off], 0, 16); off += 16;
    /* AlgStruct[0]: DHE = SECP_384_R1 */
    algReq[off++] = 0x02; algReq[off++] = 0x20;
    algReq[off++] = 0x10; algReq[off++] = 0x00;
    /* AlgStruct[1]: AEAD = AES_256_GCM */
    algReq[off++] = 0x03; algReq[off++] = 0x20;
    algReq[off++] = 0x02; algReq[off++] = 0x00;
    /* AlgStruct[2]: ReqBaseAsymAlg = ECDSA_P384 */
    algReq[off++] = 0x04; algReq[off++] = 0x20;
    algReq[off++] = 0x80; algReq[off++] = 0x00;
    /* AlgStruct[3]: KeySchedule = SPDM */
    algReq[off++] = 0x05; algReq[off++] = 0x20;
    algReq[off++] = 0x01; algReq[off++] = 0x00;

    wolfSPDM_DebugPrint(ctx, "TCG: NEGOTIATE_ALGORITHMS\n");
    rc = wolfSPDM_TranscriptAdd(ctx, algReq, off);
    if (rc == WOLFSPDM_SUCCESS)
        rc = wolfSPDM_SendReceive(ctx, algReq, off, algRsp, &algRspSz);
    if (rc == WOLFSPDM_SUCCESS)
        rc = wolfSPDM_TranscriptAdd(ctx, algRsp, algRspSz);
    if (rc != WOLFSPDM_SUCCESS) {
        ctx->state = WOLFSPDM_STATE_ERROR;
    }
    return rc;
}

/* ----- TCG SPDM Connection Flow ----- */

/* GET_VERSION -> [GET_CAPS -> NEG_ALGO] -> GET_PUBK -> KEY_EXCHANGE ->
 * GIVE_PUB -> FINISH */
int wolfSPDM_ConnectTCG(WOLFSPDM_CTX* ctx)
{
    int rc;
    byte pubKey[WOLFSPDM_PUBKEY_BUF_SZ];
    word32 pubKeySz;

    if (ctx == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (!ctx->flags.initialized) {
        return WOLFSPDM_E_BAD_STATE;
    }

    if (ctx->ioCb == NULL) {
        return WOLFSPDM_E_IO_FAIL;
    }

    wolfSPDM_DebugPrint(ctx, "TCG: Starting SPDM connection\n");

    ctx->state = WOLFSPDM_STATE_INIT;
    wolfSPDM_TranscriptReset(ctx);

    /* Step 1: GET_VERSION */
    SPDM_CONNECT_STEP(ctx, "TCG Step 1: GET_VERSION\n",
        wolfSPDM_GetVersion(ctx));

#ifdef WOLFSPDM_NATIONS
    /* Steps 2-3: GET_CAPABILITIES + NEGOTIATE_ALGORITHMS
     * Required by Nations (TCG spec mandates these before GET_PUB_KEY).
     * Nuvoton skips these — its simplified flow goes directly to GET_PUB_KEY.*/
    if (ctx->mode == WOLFSPDM_MODE_NATIONS) {
        SPDM_CONNECT_STEP(ctx, "TCG Step 2: GET_CAPABILITIES\n",
            wolfSPDM_TCG_GetCapabilities(ctx, WOLFSPDM_TCG_CAPS_FLAGS_DEFAULT));
        SPDM_CONNECT_STEP(ctx, "TCG Step 3: NEGOTIATE_ALGORITHMS\n",
            wolfSPDM_TCG_NegotiateAlgorithms(ctx));
    }
#endif

    /* Step 4: GET_PUBK */
    wolfSPDM_DebugPrint(ctx, "TCG Step 4: GET_PUBK\n");
    pubKeySz = sizeof(pubKey);
    rc = wolfSPDM_TCG_GetPubKey(ctx, pubKey, &pubKeySz);
    if (rc != WOLFSPDM_SUCCESS) {
        wolfSPDM_DebugPrint(ctx, "GET_PUBK failed: %d\n", rc);
        ctx->state = WOLFSPDM_STATE_ERROR;
        return rc;
    }
    ctx->state = WOLFSPDM_STATE_CERT;

    /* Compute Ct = SHA-384(TPMT_PUBLIC) and add to transcript */
    if (ctx->flags.hasRspPubKey && ctx->rspPubKeyLen > 0) {
        wolfSPDM_DebugPrint(ctx, "TCG: Computing Ct = SHA-384(TPMT_PUBLIC[%u])\n",
            ctx->rspPubKeyLen);
        rc = wolfSPDM_Sha384Hash(ctx->certChainHash,
            ctx->rspPubKey, ctx->rspPubKeyLen, NULL, 0, NULL, 0);
        if (rc != WOLFSPDM_SUCCESS) {
            ctx->state = WOLFSPDM_STATE_ERROR;
            return rc;
        }
        rc = wolfSPDM_TranscriptAdd(ctx, ctx->certChainHash,
            WOLFSPDM_HASH_SIZE);
        if (rc != WOLFSPDM_SUCCESS) {
            ctx->state = WOLFSPDM_STATE_ERROR;
            return rc;
        }
    } else {
        wolfSPDM_DebugPrint(ctx,
            "TCG: Warning - no responder public key for Ct\n");
    }

    /* Step 5: KEY_EXCHANGE */
    SPDM_CONNECT_STEP(ctx, "TCG Step 5: KEY_EXCHANGE\n",
        wolfSPDM_KeyExchange(ctx));

    /* Step 6: GIVE_PUB (secured) */
    if (ctx->flags.hasReqKeyPair && ctx->reqPubKeyTPMTLen > 0) {
        wolfSPDM_DebugPrint(ctx, "TCG Step 6: GIVE_PUB\n");
        rc = wolfSPDM_TCG_GivePubKey(ctx, ctx->reqPubKeyTPMT,
            ctx->reqPubKeyTPMTLen);
        if (rc != WOLFSPDM_SUCCESS) {
            wolfSPDM_DebugPrint(ctx, "GIVE_PUB failed: %d\n", rc);
            ctx->state = WOLFSPDM_STATE_ERROR;
            return rc;
        }
    } else {
        wolfSPDM_DebugPrint(ctx,
            "TCG Step 6: GIVE_PUB (skipped, no host key)\n");
    }

    /* Step 7: FINISH */
    SPDM_CONNECT_STEP(ctx, "TCG Step 7: FINISH\n",
        wolfSPDM_Finish(ctx));

    ctx->state = WOLFSPDM_STATE_CONNECTED;
    wolfSPDM_DebugPrint(ctx, "TCG: SPDM Session Established! "
        "SessionID=0x%08x\n", ctx->sessionId);

    return WOLFSPDM_SUCCESS;
}

#endif /* WOLFTPM_SPDM_TCG */

#endif /* WOLFTPM_SPDM */
