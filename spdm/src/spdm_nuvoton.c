/* spdm_nuvoton.c
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

/* Nuvoton TPM SPDM Support
 *
 * This file implements Nuvoton-specific SPDM functionality:
 * - TCG SPDM Binding message framing (per TCG SPDM Binding Spec v1.0)
 * - Nuvoton vendor-defined commands (GET_PUBK, GIVE_PUB, GET_STS_, SPDMONLY)
 * - Nuvoton SPDM handshake flow
 *
 * Reference: Nuvoton SPDM Guidance Rev 1.11
 */

#include "spdm_internal.h"

#ifdef WOLFSPDM_NUVOTON

#include <wolfspdm/spdm_nuvoton.h>
#include <string.h>

/* Check for SPDM ERROR in response payload */
#define SPDM_CHECK_ERROR_RSP(ctx, buf, sz, label) \
    if ((sz) >= 4 && (buf)[1] == SPDM_ERROR) { \
        wolfSPDM_DebugPrint(ctx, label ": SPDM ERROR 0x%02x 0x%02x\n", \
            (buf)[2], (buf)[3]); \
        return WOLFSPDM_E_PEER_ERROR; \
    }

/* --- Vendor Command Helper Types --- */

/* Response container for clear vendor commands */
typedef struct {
    char   vdCode[WOLFSPDM_VDCODE_LEN + 1];
    byte   payload[256];
    word32 payloadSz;
} WOLFSPDM_VENDOR_RSP;

/* Clear vendor command: build → SendReceive → check error → parse response */
static int wolfSPDM_VendorCmdClear(WOLFSPDM_CTX* ctx, const char* vdCode,
    const byte* payload, word32 payloadSz, WOLFSPDM_VENDOR_RSP* rsp)
{
    byte spdmMsg[256];
    int spdmMsgSz;
    byte rxBuf[512];
    word32 rxSz;
    int rc;

    spdmMsgSz = wolfSPDM_BuildVendorDefined(vdCode, payload, payloadSz,
        spdmMsg, sizeof(spdmMsg));
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
    }

    return WOLFSPDM_SUCCESS;
}

/* Secured vendor command: build → SecuredExchange → check error */
static int wolfSPDM_VendorCmdSecured(WOLFSPDM_CTX* ctx, const char* vdCode,
    const byte* payload, word32 payloadSz)
{
    byte spdmMsg[256];
    int spdmMsgSz;
    byte decBuf[256];
    word32 decSz;
    int rc;

    spdmMsgSz = wolfSPDM_BuildVendorDefined(vdCode, payload, payloadSz,
        spdmMsg, sizeof(spdmMsg));
    if (spdmMsgSz < 0) {
        return spdmMsgSz;
    }

    decSz = sizeof(decBuf);
    rc = wolfSPDM_SecuredExchange(ctx, spdmMsg, (word32)spdmMsgSz,
        decBuf, &decSz);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    if (decSz >= 4 && decBuf[1] == SPDM_ERROR) {
        wolfSPDM_DebugPrint(ctx, "%s: SPDM ERROR 0x%02x 0x%02x\n",
            vdCode, decBuf[2], decBuf[3]);
        return WOLFSPDM_E_PEER_ERROR;
    }

    return WOLFSPDM_SUCCESS;
}

/* --- TCG SPDM Binding Message Framing --- */

int wolfSPDM_BuildTcgClearMessage(
    WOLFSPDM_CTX* ctx,
    const byte* spdmPayload, word32 spdmPayloadSz,
    byte* outBuf, word32 outBufSz)
{
    word32 totalSz;

    if (ctx == NULL || spdmPayload == NULL || outBuf == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    /* TCG binding header (16 bytes per Nuvoton spec):
     * tag(2/BE) + size(4/BE) + connHandle(4/BE) + fips(2/BE) + reserved(4) */
    totalSz = WOLFSPDM_TCG_HEADER_SIZE + spdmPayloadSz;

    if (outBufSz < totalSz) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    wolfSPDM_WriteTcgHeader(outBuf, WOLFSPDM_TCG_TAG_CLEAR, totalSz,
        ctx->connectionHandle, ctx->fipsIndicator);
    /* SPDM Payload */
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

    /* Parse header */
    tag = SPDM_Get16BE(inBuf);
    if (tag != WOLFSPDM_TCG_TAG_CLEAR) {
        return WOLFSPDM_E_PEER_ERROR;
    }

    msgSize = SPDM_Get32BE(inBuf + 2);
    if (msgSize > inBufSz) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    payloadSz = msgSize - WOLFSPDM_TCG_HEADER_SIZE;
    if (*spdmPayloadSz < payloadSz) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    /* Fill header if requested */
    if (hdr != NULL) {
        hdr->tag = tag;
        hdr->size = msgSize;
        hdr->connectionHandle = SPDM_Get32BE(inBuf + 6);
        hdr->fipsIndicator = SPDM_Get16BE(inBuf + 10);
        hdr->reserved = SPDM_Get32BE(inBuf + 12);
    }

    /* Extract payload */
    XMEMCPY(spdmPayload, inBuf + WOLFSPDM_TCG_HEADER_SIZE, payloadSz);
    *spdmPayloadSz = payloadSz;

    return (int)payloadSz;
}

int wolfSPDM_BuildTcgSecuredMessage(
    WOLFSPDM_CTX* ctx,
    const byte* encPayload, word32 encPayloadSz,
    const byte* mac, word32 macSz,
    byte* outBuf, word32 outBufSz)
{
    word32 totalSz;
    word32 offset;
    word16 recordLen;

    if (ctx == NULL || encPayload == NULL || mac == NULL || outBuf == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    /* Total: TCG header(16) + sessionId(4/LE) + seqNum(8/LE) +
     *        length(2/LE) + encPayload + MAC */
    totalSz = WOLFSPDM_TCG_HEADER_SIZE + WOLFSPDM_TCG_SECURED_HDR_SIZE +
              encPayloadSz + macSz;

    if (outBufSz < totalSz) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    /* TCG binding header (16 bytes, all BE) */
    wolfSPDM_WriteTcgHeader(outBuf, WOLFSPDM_TCG_TAG_SECURED, totalSz,
        ctx->connectionHandle, ctx->fipsIndicator);

    offset = WOLFSPDM_TCG_HEADER_SIZE;

    /* Session ID (4 bytes LE per DSP0277):
     * ReqSessionId(2/LE) || RspSessionId(2/LE) */
    SPDM_Set16LE(outBuf + offset, ctx->reqSessionId);
    offset += 2;
    SPDM_Set16LE(outBuf + offset, ctx->rspSessionId);
    offset += 2;

    /* Sequence Number (8 bytes LE per DSP0277) */
    SPDM_Set64LE(outBuf + offset, ctx->reqSeqNum);
    offset += 8;

    /* Length (2 bytes LE per DSP0277) = encrypted data + MAC */
    recordLen = (word16)(encPayloadSz + macSz);
    SPDM_Set16LE(outBuf + offset, recordLen);
    offset += 2;

    /* Encrypted payload */
    XMEMCPY(outBuf + offset, encPayload, encPayloadSz);
    offset += encPayloadSz;

    /* MAC (AES-256-GCM tag) */
    XMEMCPY(outBuf + offset, mac, macSz);

    /* Note: Sequence number increment is handled by caller */

    return (int)totalSz;
}

int wolfSPDM_ParseTcgSecuredMessage(
    const byte* inBuf, word32 inBufSz,
    word32* sessionId, word64* seqNum,
    byte* encPayload, word32* encPayloadSz,
    byte* mac, word32* macSz,
    WOLFSPDM_TCG_SECURED_HDR* hdr)
{
    word16 tag;
    word32 msgSize;
    word32 offset;
    word16 recordLen;
    word32 payloadSz;

    if (inBuf == NULL || sessionId == NULL || seqNum == NULL ||
        encPayload == NULL || encPayloadSz == NULL ||
        mac == NULL || macSz == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (inBufSz < WOLFSPDM_TCG_HEADER_SIZE + WOLFSPDM_TCG_SECURED_HDR_SIZE +
                  WOLFSPDM_AEAD_TAG_SIZE) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    /* Parse TCG binding header (16 bytes, all BE) */
    tag = SPDM_Get16BE(inBuf);
    if (tag != WOLFSPDM_TCG_TAG_SECURED) {
        return WOLFSPDM_E_PEER_ERROR;
    }

    msgSize = SPDM_Get32BE(inBuf + 2);
    if (msgSize > inBufSz) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    /* Fill header if requested */
    if (hdr != NULL) {
        hdr->tag = tag;
        hdr->size = msgSize;
        hdr->connectionHandle = SPDM_Get32BE(inBuf + 6);
        hdr->fipsIndicator = SPDM_Get16BE(inBuf + 10);
        hdr->reserved = SPDM_Get32BE(inBuf + 12);
    }

    offset = WOLFSPDM_TCG_HEADER_SIZE;

    /* Session ID (4 bytes LE per DSP0277):
     * ReqSessionId(2/LE) || RspSessionId(2/LE) */
    {
        word16 reqSid = SPDM_Get16LE(inBuf + offset);
        word16 rspSid = SPDM_Get16LE(inBuf + offset + 2);
        *sessionId = ((word32)reqSid << 16) | rspSid;
    }
    offset += 4;

    /* Sequence Number (8 bytes LE per DSP0277) */
    *seqNum = SPDM_Get64LE(inBuf + offset);
    offset += 8;

    /* Length (2 bytes LE per DSP0277) = encrypted data + MAC */
    recordLen = SPDM_Get16LE(inBuf + offset);
    offset += 2;

    /* Validate record length */
    if (recordLen < WOLFSPDM_AEAD_TAG_SIZE) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }
    if (offset + recordLen > inBufSz) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    /* Encrypted payload size = recordLen - MAC */
    payloadSz = recordLen - WOLFSPDM_AEAD_TAG_SIZE;
    if (*encPayloadSz < payloadSz || *macSz < WOLFSPDM_AEAD_TAG_SIZE) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    /* Encrypted payload */
    XMEMCPY(encPayload, inBuf + offset, payloadSz);
    *encPayloadSz = payloadSz;
    offset += payloadSz;

    /* MAC */
    XMEMCPY(mac, inBuf + offset, WOLFSPDM_AEAD_TAG_SIZE);
    *macSz = WOLFSPDM_AEAD_TAG_SIZE;

    return (int)payloadSz;
}

/* --- SPDM Vendor Defined Message Helpers --- */

int wolfSPDM_BuildVendorDefined(
    const char* vdCode,
    const byte* payload, word32 payloadSz,
    byte* outBuf, word32 outBufSz)
{
    word32 totalSz;
    word32 offset = 0;

    if (vdCode == NULL || outBuf == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    /* SPDM VENDOR_DEFINED_REQUEST format (per Nuvoton SPDM Guidance):
     * SPDMVersion(1) + reqRspCode(1) + param1(1) + param2(1) +
     * standardId(2/LE) + vendorIdLen(1) + reqLength(2/LE) +
     * vdCode(8) + payload */
    totalSz = 1 + 1 + 1 + 1 + 2 + 1 + 2 + WOLFSPDM_VDCODE_LEN + payloadSz;

    if (outBufSz < totalSz) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    /* SPDM Version (v1.3 = 0x13) */
    outBuf[offset++] = SPDM_VERSION_13;
    /* Request/Response Code */
    outBuf[offset++] = SPDM_VENDOR_DEFINED_REQUEST;
    /* Param1, Param2 */
    outBuf[offset++] = 0x00;
    outBuf[offset++] = 0x00;
    /* Standard ID (0x0001 = TCG, little-endian per Nuvoton spec) */
    SPDM_Set16LE(outBuf + offset, 0x0001);
    offset += 2;
    /* Vendor ID Length (0 for TCG) */
    outBuf[offset++] = 0x00;
    /* Request Length (vdCode + payload, little-endian per Nuvoton spec) */
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

    /* Skip SPDM version */
    offset += 1;
    /* Skip request/response code + params */
    offset += 3;
    /* Skip standard ID (2 bytes LE) */
    offset += 2;
    /* Vendor ID length and vendor ID data */
    vendorIdLen = inBuf[offset];
    offset += 1 + vendorIdLen;

    if (offset + 2 > inBufSz) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    /* Request/Response Length (2 bytes LE per Nuvoton spec) */
    reqLength = SPDM_Get16LE(inBuf + offset);
    offset += 2;

    if (reqLength < WOLFSPDM_VDCODE_LEN) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    if (offset + reqLength > inBufSz) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    /* VdCode */
    XMEMCPY(vdCode, inBuf + offset, WOLFSPDM_VDCODE_LEN);
    vdCode[WOLFSPDM_VDCODE_LEN] = '\0';  /* Null-terminate */
    offset += WOLFSPDM_VDCODE_LEN;

    /* Payload */
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

/* --- Nuvoton-Specific SPDM Functions --- */

int wolfSPDM_Nuvoton_GetPubKey(
    WOLFSPDM_CTX* ctx,
    byte* pubKey, word32* pubKeySz)
{
    WOLFSPDM_VENDOR_RSP rsp;
    int rc;

    if (ctx == NULL || pubKey == NULL || pubKeySz == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    wolfSPDM_DebugPrint(ctx, "Nuvoton: GET_PUBK\n");

    rc = wolfSPDM_VendorCmdClear(ctx, WOLFSPDM_VDCODE_GET_PUBK,
        NULL, 0, &rsp);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    /* Verify VdCode */
    if (XMEMCMP(rsp.vdCode, WOLFSPDM_VDCODE_GET_PUBK, WOLFSPDM_VDCODE_LEN) != 0) {
        wolfSPDM_DebugPrint(ctx, "GET_PUBK: Unexpected VdCode '%.8s'\n", rsp.vdCode);
        return WOLFSPDM_E_PEER_ERROR;
    }

    wolfSPDM_DebugPrint(ctx, "GET_PUBK: Got TPMT_PUBLIC (%u bytes)\n", rsp.payloadSz);

    /* Copy public key to output */
    if (*pubKeySz < rsp.payloadSz) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }
    XMEMCPY(pubKey, rsp.payload, rsp.payloadSz);
    *pubKeySz = rsp.payloadSz;

    /* Store for KEY_EXCHANGE cert_chain_buffer_hash computation.
     * Per Nuvoton SPDM Guidance: cert_chain_buffer_hash = SHA-384(TPMT_PUBLIC) */
    if (rsp.payloadSz <= sizeof(ctx->rspPubKey)) {
        XMEMCPY(ctx->rspPubKey, rsp.payload, rsp.payloadSz);
        ctx->rspPubKeyLen = rsp.payloadSz;
        ctx->flags.hasRspPubKey = 1;
    }

    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_Nuvoton_GivePubKey(
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

    wolfSPDM_DebugPrint(ctx, "Nuvoton: GIVE_PUB (%u bytes) - sending ENCRYPTED\n", pubKeySz);

    rc = wolfSPDM_VendorCmdSecured(ctx, WOLFSPDM_VDCODE_GIVE_PUB,
        pubKey, pubKeySz);
    if (rc != WOLFSPDM_SUCCESS) {
        wolfSPDM_DebugPrint(ctx, "GIVE_PUB: SecuredExchange failed %d\n", rc);
        return rc;
    }

    wolfSPDM_DebugPrint(ctx, "GIVE_PUB: Success\n");
    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_Nuvoton_GetStatus(
    WOLFSPDM_CTX* ctx,
    WOLFSPDM_NUVOTON_STATUS* status)
{
    WOLFSPDM_VENDOR_RSP rsp;
    byte statusType[4] = {0x00, 0x00, 0x00, 0x00}; /* All */
    int rc;

    if (ctx == NULL || status == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    XMEMSET(status, 0, sizeof(*status));

    wolfSPDM_DebugPrint(ctx, "Nuvoton: GET_STS_\n");

    rc = wolfSPDM_VendorCmdClear(ctx, WOLFSPDM_VDCODE_GET_STS,
        statusType, sizeof(statusType), &rsp);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    wolfSPDM_DebugPrint(ctx, "GET_STS_: VdCode='%.8s', %u bytes\n",
        rsp.vdCode, rsp.payloadSz);

    /* Parse status fields per Nuvoton spec page 9:
     * Byte 0: SpecVersionMajor (0 for SPDM 1.x)
     * Byte 1: SpecVersionMinor (1 = SPDM 1.1, 3 = SPDM 1.3)
     * Byte 2: Reserved
     * Byte 3: SPDMOnly lock state (0 = unlocked, 1 = locked) */
    if (rsp.payloadSz >= 4) {
        byte specMajor = rsp.payload[0];
        byte specMinor = rsp.payload[1];
        byte spdmOnly = rsp.payload[3];

        status->specVersionMajor = specMajor;
        status->specVersionMinor = specMinor;
        status->spdmOnlyLocked = (spdmOnly != 0);
        status->spdmEnabled = 1; /* If GET_STS works, SPDM is enabled */

        /* Session active can't be determined from GET_STS alone -
         * if we're getting a response, SPDM is working */
        status->sessionActive = 0;

        wolfSPDM_DebugPrint(ctx, "GET_STS_: SpecVersion=%u.%u, SPDMOnly=%s\n",
            specMajor, specMinor, spdmOnly ? "LOCKED" : "unlocked");
    }
    else if (rsp.payloadSz >= 1) {
        /* Minimal response - just SPDMOnly */
        status->spdmOnlyLocked = (rsp.payload[0] != 0);
        status->spdmEnabled = 1;
        wolfSPDM_DebugPrint(ctx, "GET_STS_: SPDMOnly=%s (minimal response)\n",
            status->spdmOnlyLocked ? "LOCKED" : "unlocked");
    }
    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_Nuvoton_SetOnlyMode(
    WOLFSPDM_CTX* ctx,
    int lock)
{
    byte param[1];
    int rc;

    if (ctx == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (ctx->state != WOLFSPDM_STATE_CONNECTED) {
        return WOLFSPDM_E_NOT_CONNECTED;
    }

    param[0] = lock ? WOLFSPDM_SPDMONLY_LOCK : WOLFSPDM_SPDMONLY_UNLOCK;

    wolfSPDM_DebugPrint(ctx, "Nuvoton: SPDMONLY %s\n",
        lock ? "LOCK" : "UNLOCK");

    rc = wolfSPDM_VendorCmdSecured(ctx, WOLFSPDM_VDCODE_SPDMONLY,
        param, sizeof(param));
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    wolfSPDM_DebugPrint(ctx, "SPDMONLY: Success\n");
    return WOLFSPDM_SUCCESS;
}

/* --- Nuvoton SPDM Connection Flow --- */

/* Nuvoton-specific connection flow:
 * GET_VERSION -> GET_PUB_KEY -> KEY_EXCHANGE -> GIVE_PUB_KEY -> FINISH
 *
 * Key differences from standard SPDM:
 * - No GET_CAPABILITIES or NEGOTIATE_ALGORITHMS (Algorithm Set B is fixed)
 * - Uses GET_PUBK vendor command instead of GET_CERTIFICATE
 * - Uses GIVE_PUB vendor command for mutual authentication
 * - All messages wrapped in TCG binding headers
 */
int wolfSPDM_ConnectNuvoton(WOLFSPDM_CTX* ctx)
{
    int rc;
    byte pubKey[256];
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

    wolfSPDM_DebugPrint(ctx, "Nuvoton: Starting SPDM connection\n");

    /* Reset state for new connection */
    ctx->state = WOLFSPDM_STATE_INIT;
    wolfSPDM_TranscriptReset(ctx);

    /* Step 1: GET_VERSION / VERSION */
    SPDM_CONNECT_STEP(ctx, "Nuvoton Step 1: GET_VERSION\n",
        wolfSPDM_GetVersion(ctx));

    /* Step 2: GET_PUBK (Nuvoton vendor command)
     * Gets the TPM's SPDM-Identity public key (TPMT_PUBLIC format) */
    wolfSPDM_DebugPrint(ctx, "Nuvoton Step 2: GET_PUBK\n");
    pubKeySz = sizeof(pubKey);
    rc = wolfSPDM_Nuvoton_GetPubKey(ctx, pubKey, &pubKeySz);
    if (rc != WOLFSPDM_SUCCESS) {
        wolfSPDM_DebugPrint(ctx, "GET_PUBK failed: %d\n", rc);
        ctx->state = WOLFSPDM_STATE_ERROR;
        return rc;
    }
    ctx->state = WOLFSPDM_STATE_CERT;

    /* Step 2.5: Compute Ct = SHA-384(TPMT_PUBLIC) and add to transcript
     * For Nuvoton, the cert_chain_buffer_hash is SHA-384(TPMT_PUBLIC)
     * instead of the standard certificate chain hash */
    if (ctx->flags.hasRspPubKey && ctx->rspPubKeyLen > 0) {
        wolfSPDM_DebugPrint(ctx, "Nuvoton: Computing Ct = SHA-384(TPMT_PUBLIC[%u])\n",
            ctx->rspPubKeyLen);
        rc = wolfSPDM_Sha384Hash(ctx->certChainHash,
            ctx->rspPubKey, ctx->rspPubKeyLen, NULL, 0, NULL, 0);
        if (rc != WOLFSPDM_SUCCESS) {
            ctx->state = WOLFSPDM_STATE_ERROR;
            return rc;
        }
        rc = wolfSPDM_TranscriptAdd(ctx, ctx->certChainHash, WOLFSPDM_HASH_SIZE);
        if (rc != WOLFSPDM_SUCCESS) {
            ctx->state = WOLFSPDM_STATE_ERROR;
            return rc;
        }
    }
    else {
        wolfSPDM_DebugPrint(ctx, "Nuvoton: Warning - no responder public key for Ct\n");
    }

    SPDM_CONNECT_STEP(ctx, "Nuvoton Step 3: KEY_EXCHANGE\n",
        wolfSPDM_KeyExchange(ctx));

    /* Step 4: GIVE_PUB (Nuvoton vendor command) - sent as SECURED message
     * Gives the host's SPDM-Identity public key to the TPM.
     * Per Nuvoton spec Rev 1.11 section 4.2.4, GIVE_PUB uses tag 0x8201 (secured). */
    if (ctx->flags.hasReqKeyPair && ctx->reqPubKeyTPMTLen > 0) {
        wolfSPDM_DebugPrint(ctx, "Nuvoton Step 4: GIVE_PUB\n");
        rc = wolfSPDM_Nuvoton_GivePubKey(ctx, ctx->reqPubKeyTPMT,
            ctx->reqPubKeyTPMTLen);
        if (rc != WOLFSPDM_SUCCESS) {
            wolfSPDM_DebugPrint(ctx, "GIVE_PUB failed: %d\n", rc);
            /* Don't fail - continue to FINISH for debug */
        }
        else {
            wolfSPDM_DebugPrint(ctx, "GIVE_PUB succeeded!\n");
        }
    }
    else {
        wolfSPDM_DebugPrint(ctx, "Nuvoton Step 4: GIVE_PUB (skipped, no host key)\n");
    }

    /* Step 5: FINISH */
    SPDM_CONNECT_STEP(ctx, "Nuvoton Step 5: FINISH\n",
        wolfSPDM_Finish(ctx));

    ctx->state = WOLFSPDM_STATE_CONNECTED;
    wolfSPDM_DebugPrint(ctx, "Nuvoton: SPDM Session Established! "
        "SessionID=0x%08x\n", ctx->sessionId);

    return WOLFSPDM_SUCCESS;
}

#endif /* WOLFSPDM_NUVOTON */
