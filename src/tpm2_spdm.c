/* tpm2_spdm.c
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

/* SPDM Session Manager and Transport Layer for wolfTPM
 *
 * This file implements:
 * 1. TCG SPDM binding message framing (clear and secured)
 * 2. SPDM session lifecycle management (connect/disconnect)
 * 3. TPM command wrapping/unwrapping over SPDM secured channel
 * 4. SPDM vendor-defined command helpers (GET_PUBK, GIVE_PUB, etc.)
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_spdm.h>

#ifdef WOLFTPM_SPDM

#include <wolftpm/tpm2_wrap.h>
#include <wolftpm/tpm2_packet.h>

/* -------------------------------------------------------------------------- */
/* Internal Helpers */
/* -------------------------------------------------------------------------- */

/* Store a 16-bit value in big-endian format */
static void SPDM_Set16(byte* buf, word16 val)
{
    buf[0] = (byte)(val >> 8);
    buf[1] = (byte)(val & 0xFF);
}

/* Read a 16-bit value from big-endian format */
static word16 SPDM_Get16(const byte* buf)
{
    return (word16)((buf[0] << 8) | buf[1]);
}

/* Store a 16-bit value in little-endian format */
static void SPDM_Set16LE(byte* buf, word16 val)
{
    buf[0] = (byte)(val & 0xFF);
    buf[1] = (byte)(val >> 8);
}

/* Read a 16-bit value from little-endian format */
static word16 SPDM_Get16LE(const byte* buf)
{
    return (word16)(buf[0] | (buf[1] << 8));
}

/* Store a 32-bit value in big-endian format */
static void SPDM_Set32(byte* buf, word32 val)
{
    buf[0] = (byte)(val >> 24);
    buf[1] = (byte)(val >> 16);
    buf[2] = (byte)(val >> 8);
    buf[3] = (byte)(val & 0xFF);
}

/* Read a 32-bit value from big-endian format */
static word32 SPDM_Get32(const byte* buf)
{
    return ((word32)buf[0] << 24) | ((word32)buf[1] << 16) |
           ((word32)buf[2] << 8) | (word32)buf[3];
}

/* Store a 64-bit value in big-endian format */
static void SPDM_Set64(byte* buf, word64 val)
{
    buf[0] = (byte)(val >> 56);
    buf[1] = (byte)(val >> 48);
    buf[2] = (byte)(val >> 40);
    buf[3] = (byte)(val >> 32);
    buf[4] = (byte)(val >> 24);
    buf[5] = (byte)(val >> 16);
    buf[6] = (byte)(val >> 8);
    buf[7] = (byte)(val & 0xFF);
}

/* Read a 64-bit value from big-endian format */
static word64 SPDM_Get64(const byte* buf)
{
    return ((word64)buf[0] << 56) | ((word64)buf[1] << 48) |
           ((word64)buf[2] << 40) | ((word64)buf[3] << 32) |
           ((word64)buf[4] << 24) | ((word64)buf[5] << 16) |
           ((word64)buf[6] << 8) | (word64)buf[7];
}

/* -------------------------------------------------------------------------- */
/* TCG SPDM Binding Message Framing */
/* -------------------------------------------------------------------------- */

int SPDM_BuildClearMessage(
    WOLFTPM2_SPDM_CTX* ctx,
    const byte* spdmPayload, word32 spdmPayloadSz,
    byte* outBuf, word32 outBufSz)
{
    word32 totalSz;

    if (ctx == NULL || spdmPayload == NULL || outBuf == NULL) {
        return BAD_FUNC_ARG;
    }

    /* TCG binding header (16 bytes per Nuvoton spec):
     * tag(2/BE) + size(4/BE) + connHandle(4/BE) + fips(2/BE) + reserved(4) */
    totalSz = SPDM_TCG_BINDING_HEADER_SIZE + spdmPayloadSz;

    if (outBufSz < totalSz) {
        return BUFFER_E;
    }

    /* Tag (2 bytes BE) */
    SPDM_Set16(outBuf, SPDM_TAG_CLEAR);
    /* Size (4 bytes BE, total including header) */
    SPDM_Set32(outBuf + 2, totalSz);
    /* Connection Handle (4 bytes BE) */
    SPDM_Set32(outBuf + 6, ctx->connectionHandle);
    /* FIPS Service Indicator (2 bytes BE) */
    SPDM_Set16(outBuf + 10, ctx->fipsIndicator);
    /* Reserved (4 bytes, must be 0) */
    XMEMSET(outBuf + 12, 0, 4);
    /* SPDM Payload */
    XMEMCPY(outBuf + SPDM_TCG_BINDING_HEADER_SIZE, spdmPayload, spdmPayloadSz);

    return (int)totalSz;
}

int SPDM_ParseClearMessage(
    const byte* inBuf, word32 inBufSz,
    byte* spdmPayload, word32* spdmPayloadSz,
    SPDM_TCG_CLEAR_HDR* hdr)
{
    word16 tag;
    word32 msgSize;
    word32 payloadSz;

    if (inBuf == NULL || spdmPayload == NULL || spdmPayloadSz == NULL) {
        return BAD_FUNC_ARG;
    }

    if (inBufSz < SPDM_TCG_BINDING_HEADER_SIZE) {
        return BUFFER_E;
    }

    /* Parse header */
    tag = SPDM_Get16(inBuf);
    if (tag != SPDM_TAG_CLEAR) {
        return TPM_RC_TAG;
    }

    msgSize = SPDM_Get32(inBuf + 2);
    if (msgSize > inBufSz) {
        return TPM_RC_SIZE;
    }

    payloadSz = msgSize - SPDM_TCG_BINDING_HEADER_SIZE;
    if (*spdmPayloadSz < payloadSz) {
        return BUFFER_E;
    }

    /* Fill header if requested (16-byte header per Nuvoton spec) */
    if (hdr != NULL) {
        hdr->tag = tag;
        hdr->size = msgSize;
        hdr->connectionHandle = SPDM_Get32(inBuf + 6);
        hdr->fipsIndicator = SPDM_Get16(inBuf + 10);
        hdr->reserved = SPDM_Get32(inBuf + 12);
    }

    /* Extract payload */
    XMEMCPY(spdmPayload, inBuf + SPDM_TCG_BINDING_HEADER_SIZE, payloadSz);
    *spdmPayloadSz = payloadSz;

    return (int)payloadSz;
}

int SPDM_BuildSecuredMessage(
    WOLFTPM2_SPDM_CTX* ctx,
    const byte* encPayload, word32 encPayloadSz,
    const byte* mac, word32 macSz,
    byte* outBuf, word32 outBufSz)
{
    word32 totalSz;
    word32 offset;

    if (ctx == NULL || encPayload == NULL || mac == NULL || outBuf == NULL) {
        return BAD_FUNC_ARG;
    }

    /* Total: TCG header(16) + sessionId(4) + seqNum(8) + encPayload + MAC */
    totalSz = SPDM_TCG_BINDING_HEADER_SIZE + SPDM_SECURED_MSG_HEADER_SIZE +
              encPayloadSz + macSz;

    if (outBufSz < totalSz) {
        return BUFFER_E;
    }

    /* TCG binding header (16 bytes per Nuvoton spec) */
    SPDM_Set16(outBuf, SPDM_TAG_SECURED);
    SPDM_Set32(outBuf + 2, totalSz);
    SPDM_Set32(outBuf + 6, ctx->connectionHandle);
    SPDM_Set16(outBuf + 10, ctx->fipsIndicator);
    XMEMSET(outBuf + 12, 0, 4);

    offset = SPDM_TCG_BINDING_HEADER_SIZE;

    /* Session ID (4 bytes) */
    SPDM_Set32(outBuf + offset, ctx->sessionId);
    offset += 4;

    /* Sequence Number (8 bytes) */
    SPDM_Set64(outBuf + offset, ctx->reqSeqNum);
    offset += 8;

    /* Encrypted payload */
    XMEMCPY(outBuf + offset, encPayload, encPayloadSz);
    offset += encPayloadSz;

    /* MAC (AES-256-GCM tag) */
    XMEMCPY(outBuf + offset, mac, macSz);
    offset += macSz;

    /* Increment requester sequence number */
    ctx->reqSeqNum++;

    return (int)totalSz;
}

int SPDM_ParseSecuredMessage(
    const byte* inBuf, word32 inBufSz,
    word32* sessionId, word64* seqNum,
    byte* encPayload, word32* encPayloadSz,
    byte* mac, word32* macSz,
    SPDM_TCG_SECURED_HDR* hdr)
{
    word16 tag;
    word32 msgSize;
    word32 offset;
    word32 payloadSz;

    if (inBuf == NULL || sessionId == NULL || seqNum == NULL ||
        encPayload == NULL || encPayloadSz == NULL ||
        mac == NULL || macSz == NULL) {
        return BAD_FUNC_ARG;
    }

    if (inBufSz < SPDM_TCG_BINDING_HEADER_SIZE + SPDM_SECURED_MSG_HEADER_SIZE +
                  SPDM_AEAD_TAG_SIZE) {
        return BUFFER_E;
    }

    /* Parse TCG binding header */
    tag = SPDM_Get16(inBuf);
    if (tag != SPDM_TAG_SECURED) {
        return TPM_RC_TAG;
    }

    msgSize = SPDM_Get32(inBuf + 2);
    if (msgSize > inBufSz) {
        return TPM_RC_SIZE;
    }

    /* Fill header if requested (16-byte header per Nuvoton spec) */
    if (hdr != NULL) {
        hdr->tag = tag;
        hdr->size = msgSize;
        hdr->connectionHandle = SPDM_Get32(inBuf + 6);
        hdr->fipsIndicator = SPDM_Get16(inBuf + 10);
        hdr->reserved = SPDM_Get32(inBuf + 12);
    }

    offset = SPDM_TCG_BINDING_HEADER_SIZE;

    /* Session ID */
    *sessionId = SPDM_Get32(inBuf + offset);
    offset += 4;

    /* Sequence Number */
    *seqNum = SPDM_Get64(inBuf + offset);
    offset += 8;

    /* Encrypted payload size = total - headers - MAC */
    payloadSz = msgSize - offset - SPDM_AEAD_TAG_SIZE;
    if (*encPayloadSz < payloadSz || *macSz < SPDM_AEAD_TAG_SIZE) {
        return BUFFER_E;
    }

    /* Encrypted payload */
    XMEMCPY(encPayload, inBuf + offset, payloadSz);
    *encPayloadSz = payloadSz;
    offset += payloadSz;

    /* MAC */
    XMEMCPY(mac, inBuf + offset, SPDM_AEAD_TAG_SIZE);
    *macSz = SPDM_AEAD_TAG_SIZE;

    return (int)payloadSz;
}

/* -------------------------------------------------------------------------- */
/* SPDM Vendor Defined Message Helpers */
/* -------------------------------------------------------------------------- */

int SPDM_BuildVendorDefined(
    const char* vdCode,
    const byte* payload, word32 payloadSz,
    byte* outBuf, word32 outBufSz)
{
    word32 totalSz;
    word32 offset = 0;

    if (vdCode == NULL || outBuf == NULL) {
        return BAD_FUNC_ARG;
    }

    /* SPDM VENDOR_DEFINED_REQUEST format (per Nuvoton SPDM Guidance):
     * SPDMVersion(1) + reqRspCode(1) + param1(1) + param2(1) +
     * standardId(2/LE) + vendorIdLen(1) + reqLength(2/LE) +
     * vdCode(8) + payload */
    totalSz = 1 + 1 + 1 + 1 + 2 + 1 + 2 + SPDM_VDCODE_LEN + payloadSz;

    if (outBufSz < totalSz) {
        return BUFFER_E;
    }

    /* SPDM Version (v1.3 = 0x13) */
    outBuf[offset++] = SPDM_VERSION_1_3;
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
    SPDM_Set16LE(outBuf + offset, (word16)(SPDM_VDCODE_LEN + payloadSz));
    offset += 2;
    /* VdCode (8-byte ASCII) */
    XMEMCPY(outBuf + offset, vdCode, SPDM_VDCODE_LEN);
    offset += SPDM_VDCODE_LEN;
    /* Payload */
    if (payload != NULL && payloadSz > 0) {
        XMEMCPY(outBuf + offset, payload, payloadSz);
        offset += payloadSz;
    }

    return (int)offset;
}

int SPDM_ParseVendorDefined(
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
        return BAD_FUNC_ARG;
    }

    /* Minimum: version(1) + code(1) + param1(1) + param2(1) + stdId(2/LE) +
     *          vidLen(1) + reqLen(2/LE) + vdCode(8) = 17 */
    if (inBufSz < 17) {
        return BUFFER_E;
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
        return BUFFER_E;
    }

    /* Request/Response Length (2 bytes LE per Nuvoton spec) */
    reqLength = SPDM_Get16LE(inBuf + offset);
    offset += 2;

    if (reqLength < SPDM_VDCODE_LEN) {
        return TPM_RC_SIZE;
    }

    if (offset + reqLength > inBufSz) {
        return BUFFER_E;
    }

    /* VdCode */
    XMEMCPY(vdCode, inBuf + offset, SPDM_VDCODE_LEN);
    offset += SPDM_VDCODE_LEN;

    /* Payload */
    dataLen = reqLength - SPDM_VDCODE_LEN;
    if (*payloadSz < dataLen) {
        return BUFFER_E;
    }

    if (dataLen > 0) {
        XMEMCPY(payload, inBuf + offset, dataLen);
    }
    *payloadSz = dataLen;

    return (int)dataLen;
}

/* -------------------------------------------------------------------------- */
/* Default SPDM I/O Callback (uses TPM2_SendRawBytes) */
/* -------------------------------------------------------------------------- */

/* This callback sends TCG-framed SPDM messages through the same TIS FIFO
 * used for regular TPM commands. The userCtx is a pointer to TPM2_CTX. */
static int spdm_default_io_callback(
    struct WOLFTPM2_SPDM_CTX* ctx,
    const byte* txBuf, word32 txSz,
    byte* rxBuf, word32* rxSz,
    void* userCtx)
{
    TPM2_CTX* tpmCtx = (TPM2_CTX*)userCtx;
    int rc;

    if (tpmCtx == NULL || txBuf == NULL || rxBuf == NULL || rxSz == NULL) {
        return BAD_FUNC_ARG;
    }

    (void)ctx; /* SPDM context not needed for raw transport */

#ifdef DEBUG_WOLFTPM
    printf("SPDM I/O: Sending %u bytes\n", txSz);
    TPM2_PrintBin(txBuf, txSz);
#endif

    rc = (int)TPM2_SendRawBytes(tpmCtx, txBuf, txSz, rxBuf, rxSz);

#ifdef DEBUG_WOLFTPM
    if (rc == 0) {
        printf("SPDM I/O: Received %u bytes\n", *rxSz);
        TPM2_PrintBin(rxBuf, *rxSz);
    }
    else {
        printf("SPDM I/O: SendRawBytes failed rc=%d (0x%x)\n", rc, rc);
    }
#endif

    return rc;
}

/* -------------------------------------------------------------------------- */
/* SPDM Context Management */
/* -------------------------------------------------------------------------- */

int wolfTPM2_SPDM_InitCtx(
    WOLFTPM2_SPDM_CTX* ctx,
    WOLFTPM2_SPDM_BACKEND* backend,
    WOLFTPM2_SPDM_IoCallback ioCb,
    void* userCtx)
{
    int rc;

    if (ctx == NULL || backend == NULL) {
        return BAD_FUNC_ARG;
    }

    XMEMSET(ctx, 0, sizeof(*ctx));

    ctx->backend = backend;
    ctx->ioCb = ioCb;
    ctx->ioUserCtx = userCtx;
    ctx->connectionHandle = (word32)SPDM_CONNECTION_ID;
    ctx->fipsIndicator = (word16)SPDM_FIPS_NON_FIPS;
    ctx->reqSessionId = SPDM_REQ_SESSION_ID;
    ctx->state = SPDM_STATE_DISCONNECTED;

    /* Initialize backend */
    if (backend->Init != NULL) {
        rc = backend->Init(ctx, ioCb, userCtx);
        if (rc != 0) {
            return rc;
        }
    }

    ctx->state = SPDM_STATE_INITIALIZED;
    return 0;
}

/* -------------------------------------------------------------------------- */
/* SPDM Enable (NTC2_PreConfig) */
/* -------------------------------------------------------------------------- */

int wolfTPM2_SPDM_Enable(
    WOLFTPM2_SPDM_CTX* ctx,
    TPM2_CTX* tpmCtx)
{
    int rc;
    NTC2_GetConfig_Out getConfig;
    NTC2_PreConfig_In preConfig;

    (void)ctx;
    (void)tpmCtx;

    /* Step 1: Read current TPM configuration */
    XMEMSET(&getConfig, 0, sizeof(getConfig));
    rc = TPM2_NTC2_GetConfig(&getConfig);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("SPDM Enable: NTC2_GetConfig failed 0x%x: %s\n",
               rc, TPM2_GetRCString(rc));
    #endif
        return rc;
    }

#ifdef DEBUG_WOLFTPM
    printf("SPDM Enable: Current Cfg_H = 0x%02x (SPDM %s)\n",
           getConfig.preConfig.Cfg_H,
           (getConfig.preConfig.Cfg_H & NTC2_CFG_H_SPDM_DISABLE) ?
               "disabled" : "enabled");
#endif

    /* Check if SPDM is already enabled (bit 1 = 0) */
    if ((getConfig.preConfig.Cfg_H & NTC2_CFG_H_SPDM_DISABLE) == 0) {
    #ifdef DEBUG_WOLFTPM
        printf("SPDM Enable: SPDM is already enabled\n");
    #endif
        return TPM_RC_SUCCESS;
    }

    /* Step 2: Clear bit 1 of Cfg_H to enable SPDM */
    XMEMSET(&preConfig, 0, sizeof(preConfig));
    preConfig.authHandle = TPM_RH_PLATFORM;
    XMEMCPY(&preConfig.preConfig, &getConfig.preConfig,
             sizeof(preConfig.preConfig));
    preConfig.preConfig.Cfg_H &= (BYTE)(~NTC2_CFG_H_SPDM_DISABLE);

#ifdef DEBUG_WOLFTPM
    printf("SPDM Enable: Setting Cfg_H = 0x%02x\n",
           preConfig.preConfig.Cfg_H);
#endif

    rc = TPM2_NTC2_PreConfig(&preConfig);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("SPDM Enable: NTC2_PreConfig failed 0x%x: %s\n",
               rc, TPM2_GetRCString(rc));
    #endif
        return rc;
    }

#ifdef DEBUG_WOLFTPM
    printf("SPDM Enable: Configuration written. TPM reset required.\n");
#endif

    return TPM_RC_SUCCESS;
}

/* -------------------------------------------------------------------------- */
/* SPDM Get Status */
/* -------------------------------------------------------------------------- */

int wolfTPM2_SPDM_GetStatus(
    WOLFTPM2_SPDM_CTX* ctx,
    WOLFTPM2_SPDM_STATUS* status)
{
    int rc;
    byte spdmMsg[256];
    int spdmMsgSz;
    byte rxBuf[256];
    word32 rxSz;
    byte rspPayload[64];
    word32 rspPayloadSz;
    word32 spdmPayloadSz;
    char rspVdCode[SPDM_VDCODE_LEN + 1];

    if (ctx == NULL || status == NULL) {
        return BAD_FUNC_ARG;
    }

    XMEMSET(status, 0, sizeof(*status));

    /* Build GET_STS_ vendor-defined request with statusType parameter.
     * Per Nuvoton SPDM Guidance Rev 1.11 section 4.1.1:
     * statusType is a 4-byte uint32 (0x00000000 = "All") */
    {
        byte statusType[4] = {0x00, 0x00, 0x00, 0x00}; /* All */
        spdmMsgSz = SPDM_BuildVendorDefined(SPDM_VDCODE_GET_STS,
            statusType, sizeof(statusType), ctx->msgBuf, sizeof(ctx->msgBuf));
    }
    if (spdmMsgSz < 0) {
        return spdmMsgSz;
    }

    /* Wrap in TCG clear message */
    rc = SPDM_BuildClearMessage(ctx, ctx->msgBuf, (word32)spdmMsgSz,
        spdmMsg, sizeof(spdmMsg));
    if (rc < 0) {
        return rc;
    }

    /* Send via I/O callback */
    if (ctx->ioCb == NULL) {
        return TPM_RC_FAILURE;
    }

    rxSz = sizeof(rxBuf);
    rc = ctx->ioCb(ctx, spdmMsg, (word32)rc, rxBuf, &rxSz, ctx->ioUserCtx);
    if (rc != 0) {
        return rc;
    }

    /* Parse response: TCG clear message -> vendor-defined response */
    spdmPayloadSz = sizeof(ctx->msgBuf);
    rc = SPDM_ParseClearMessage(rxBuf, rxSz, ctx->msgBuf, &spdmPayloadSz, NULL);
    if (rc < 0) {
    #ifdef DEBUG_WOLFTPM
        printf("SPDM GetStatus: ParseClearMessage failed rc=%d\n", rc);
    #endif
        return rc;
    }

#ifdef DEBUG_WOLFTPM
    printf("SPDM GetStatus: SPDM payload (%u bytes):\n", spdmPayloadSz);
    TPM2_PrintBin(ctx->msgBuf, spdmPayloadSz);
#endif

    /* Check if this is an SPDM error response (code 0x7F = ERROR).
     * SPDM format: Version(1) + Code(1) + Param1(1) + Param2(1) */
    if (spdmPayloadSz >= 4 && ctx->msgBuf[1] == SPDM_ERROR) {
    #ifdef DEBUG_WOLFTPM
        printf("SPDM GetStatus: SPDM ERROR response - ErrorCode=0x%02x "
               "ErrorData=0x%02x\n",
               ctx->msgBuf[2], ctx->msgBuf[3]);
    #endif
        return TPM_RC_COMMAND_CODE;
    }

    /* Parse as vendor-defined response.
     * Minimum size: version(1) + code(1) + p1(1) + p2(1) + stdId(2) +
     *               vidLen(1) + rspLen(2) + vdCode(8) = 17 */
    if (spdmPayloadSz < 17) {
    #ifdef DEBUG_WOLFTPM
        printf("SPDM GetStatus: Response too short for vendor-defined "
               "(%u < 17)\n", spdmPayloadSz);
    #endif
        return TPM_RC_SIZE;
    }

    rspPayloadSz = sizeof(rspPayload);
    XMEMSET(rspVdCode, 0, sizeof(rspVdCode));
    rc = SPDM_ParseVendorDefined(ctx->msgBuf, spdmPayloadSz,
        rspVdCode, rspPayload, &rspPayloadSz);
    if (rc < 0) {
    #ifdef DEBUG_WOLFTPM
        printf("SPDM GetStatus: ParseVendorDefined failed rc=%d\n", rc);
    #endif
        return rc;
    }

#ifdef DEBUG_WOLFTPM
    printf("SPDM GetStatus: VdCode='%.8s', payload %u bytes\n",
           rspVdCode, rspPayloadSz);
    if (rspPayloadSz > 0) {
        TPM2_PrintBin(rspPayload, rspPayloadSz);
    }
#endif

    /* Parse status fields from response payload.
     * Per Nuvoton SPDM Guidance, GET_STS_ returns status data.
     * The exact format depends on statusType. For "All" (0x00000000):
     * Byte[0]: SPDM enabled flag
     * Remaining bytes: vendor-specific status data */
    if (rspPayloadSz >= 4) {
        status->spdmEnabled = (rspPayload[0] != 0);
        status->sessionActive = (rspPayload[1] != 0);
        status->spdmOnlyLocked = (rspPayload[2] != 0);
    }

    return 0;
}

/* -------------------------------------------------------------------------- */
/* SPDM Get Public Key */
/* -------------------------------------------------------------------------- */

int wolfTPM2_SPDM_GetPubKey(
    WOLFTPM2_SPDM_CTX* ctx,
    byte* pubKey, word32* pubKeySz)
{
    int rc;
    byte spdmMsg[512];
    int spdmMsgSz;
    byte rxBuf[512];
    word32 rxSz;
    byte rspPayload[256];
    word32 rspPayloadSz;
    char rspVdCode[SPDM_VDCODE_LEN + 1];

    if (ctx == NULL || pubKey == NULL || pubKeySz == NULL) {
        return BAD_FUNC_ARG;
    }

    /* Build GET_PUBK vendor-defined request */
    spdmMsgSz = SPDM_BuildVendorDefined(SPDM_VDCODE_GET_PUBK,
        NULL, 0, ctx->msgBuf, sizeof(ctx->msgBuf));
    if (spdmMsgSz < 0) {
        return spdmMsgSz;
    }

    /* Wrap in TCG clear message */
    rc = SPDM_BuildClearMessage(ctx, ctx->msgBuf, (word32)spdmMsgSz,
        spdmMsg, sizeof(spdmMsg));
    if (rc < 0) {
        return rc;
    }

    /* Send via I/O callback */
    if (ctx->ioCb == NULL) {
        return TPM_RC_FAILURE;
    }

    rxSz = sizeof(rxBuf);
    rc = ctx->ioCb(ctx, spdmMsg, (word32)rc, rxBuf, &rxSz, ctx->ioUserCtx);
    if (rc != 0) {
        return rc;
    }

    /* Parse response */
    rspPayloadSz = sizeof(ctx->msgBuf);
    rc = SPDM_ParseClearMessage(rxBuf, rxSz, ctx->msgBuf, &rspPayloadSz, NULL);
    if (rc < 0) {
        return rc;
    }

    rspPayloadSz = sizeof(rspPayload);
    rc = SPDM_ParseVendorDefined(ctx->msgBuf, (word32)rc,
        rspVdCode, rspPayload, &rspPayloadSz);
    if (rc < 0) {
        return rc;
    }

    /* Verify VdCode */
    if (XMEMCMP(rspVdCode, SPDM_VDCODE_GET_PUBK, SPDM_VDCODE_LEN) != 0) {
        return TPM_RC_VALUE;
    }

    /* Copy public key to output and internal storage */
    if (*pubKeySz < rspPayloadSz) {
        return BUFFER_E;
    }
    XMEMCPY(pubKey, rspPayload, rspPayloadSz);
    *pubKeySz = rspPayloadSz;

    /* Store in context for use during KEY_EXCHANGE */
    if (rspPayloadSz <= sizeof(ctx->rspPubKey)) {
        XMEMCPY(ctx->rspPubKey, rspPayload, rspPayloadSz);
        ctx->rspPubKeyLen = rspPayloadSz;
    }

    ctx->state = SPDM_STATE_PUBKEY_DONE;
    return 0;
}

/* -------------------------------------------------------------------------- */
/* SPDM Connect (Full Handshake) */
/* -------------------------------------------------------------------------- */

int wolfTPM2_SPDM_Connect(
    WOLFTPM2_SPDM_CTX* ctx,
    const byte* reqPubKey, word32 reqPubKeySz,
    const byte* reqPrivKey, word32 reqPrivKeySz)
{
    int rc;

    if (ctx == NULL || ctx->backend == NULL) {
        return BAD_FUNC_ARG;
    }

    if (ctx->state < SPDM_STATE_INITIALIZED) {
        return TPM_RC_INITIALIZE;
    }

    /* Step 1: GET_VERSION / VERSION */
    if (ctx->backend->GetVersion != NULL) {
        rc = ctx->backend->GetVersion(ctx);
        if (rc != 0) {
            ctx->state = SPDM_STATE_ERROR;
            return rc;
        }
        ctx->state = SPDM_STATE_VERSION_DONE;
    }

    /* Step 2: GET_PUB_KEY (vendor-defined, get TPM's SPDM-Identity key) */
    if (ctx->rspPubKeyLen == 0) {
        byte tmpPubKey[128];
        word32 tmpPubKeySz = sizeof(tmpPubKey);
        rc = wolfTPM2_SPDM_GetPubKey(ctx, tmpPubKey, &tmpPubKeySz);
        if (rc != 0) {
            ctx->state = SPDM_STATE_ERROR;
            return rc;
        }
    }

    /* Step 3: KEY_EXCHANGE / KEY_EXCHANGE_RSP */
    if (ctx->backend->KeyExchange != NULL) {
        rc = ctx->backend->KeyExchange(ctx, ctx->rspPubKey, ctx->rspPubKeyLen);
        if (rc != 0) {
            ctx->state = SPDM_STATE_ERROR;
            return rc;
        }
        ctx->state = SPDM_STATE_KEY_EXCHANGE_DONE;
    }

    /* Step 4: GIVE_PUB_KEY (vendor-defined within handshake session) */
    if (reqPubKey != NULL && reqPubKeySz > 0) {
        int vdSz;
        byte spdmMsg[512];
        byte rxBuf[512];
        word32 rxSz;

        /* Store requester public key */
        if (reqPubKeySz <= sizeof(ctx->reqPubKey)) {
            XMEMCPY(ctx->reqPubKey, reqPubKey, reqPubKeySz);
            ctx->reqPubKeyLen = reqPubKeySz;
        }

        /* Build GIVE_PUB vendor-defined with public key as payload */
        vdSz = SPDM_BuildVendorDefined(SPDM_VDCODE_GIVE_PUB,
            reqPubKey, reqPubKeySz, ctx->msgBuf, sizeof(ctx->msgBuf));
        if (vdSz < 0) {
            ctx->state = SPDM_STATE_ERROR;
            return vdSz;
        }

        /* This is sent within the handshake session (secured) */
        /* The backend should handle encryption for handshake phase */
        rc = SPDM_BuildClearMessage(ctx, ctx->msgBuf, (word32)vdSz,
            spdmMsg, sizeof(spdmMsg));
        if (rc < 0) {
            ctx->state = SPDM_STATE_ERROR;
            return rc;
        }

        if (ctx->ioCb != NULL) {
            rxSz = sizeof(rxBuf);
            rc = ctx->ioCb(ctx, spdmMsg, (word32)rc, rxBuf, &rxSz,
                ctx->ioUserCtx);
            if (rc != 0) {
                ctx->state = SPDM_STATE_ERROR;
                return rc;
            }
        }
        ctx->state = SPDM_STATE_GIVE_PUBKEY_DONE;
    }

    /* Step 5: FINISH / FINISH_RSP */
    if (ctx->backend->Finish != NULL) {
        rc = ctx->backend->Finish(ctx, reqPrivKey, reqPrivKeySz);
        if (rc != 0) {
            ctx->state = SPDM_STATE_ERROR;
            return rc;
        }
    }

    /* Session established */
    ctx->rspSessionId = SPDM_RSP_SESSION_ID;
    ctx->sessionId = ((word32)ctx->reqSessionId << 16) | ctx->rspSessionId;
    ctx->reqSeqNum = 0;
    ctx->rspSeqNum = 0;
    ctx->state = SPDM_STATE_CONNECTED;

    return 0;
}

int wolfTPM2_SPDM_IsConnected(WOLFTPM2_SPDM_CTX* ctx)
{
    if (ctx == NULL) {
        return 0;
    }
    return (ctx->state == SPDM_STATE_CONNECTED) ? 1 : 0;
}

/* -------------------------------------------------------------------------- */
/* SPDM Command Wrapping (Transport Layer) */
/* -------------------------------------------------------------------------- */

int wolfTPM2_SPDM_WrapCommand(
    WOLFTPM2_SPDM_CTX* ctx,
    const byte* tpmCmd, word32 tpmCmdSz,
    byte* spdmMsg, word32* spdmMsgSz)
{
    int rc;
    int vdSz;
    byte encBuf[SPDM_MAX_MSG_SIZE];
    word32 encBufSz;
    byte mac[SPDM_AEAD_TAG_SIZE];

    if (ctx == NULL || tpmCmd == NULL || spdmMsg == NULL || spdmMsgSz == NULL) {
        return BAD_FUNC_ARG;
    }

    if (ctx->state != SPDM_STATE_CONNECTED) {
        return TPM_RC_AUTH_MISSING;
    }

    /* Build VENDOR_DEFINED(TPM2_CMD) with the raw TPM command as payload */
    vdSz = SPDM_BuildVendorDefined(SPDM_VDCODE_TPM2_CMD,
        tpmCmd, tpmCmdSz, ctx->msgBuf, sizeof(ctx->msgBuf));
    if (vdSz < 0) {
        return vdSz;
    }

    /* Encrypt via backend */
    if (ctx->backend == NULL || ctx->backend->EncryptMessage == NULL) {
        return TPM_RC_FAILURE;
    }

    encBufSz = sizeof(encBuf) - SPDM_AEAD_TAG_SIZE;
    rc = ctx->backend->EncryptMessage(ctx, ctx->msgBuf, (word32)vdSz,
        encBuf, &encBufSz);
    if (rc != 0) {
        return rc;
    }

    /* The backend puts the MAC at the end of encBuf.
     * Split: encPayload = encBuf[0..encBufSz-TAG_SIZE], mac = last TAG_SIZE */
    if (encBufSz < SPDM_AEAD_TAG_SIZE) {
        return TPM_RC_SIZE;
    }

    XMEMCPY(mac, encBuf + encBufSz - SPDM_AEAD_TAG_SIZE, SPDM_AEAD_TAG_SIZE);
    encBufSz -= SPDM_AEAD_TAG_SIZE;

    /* Build TCG secured message */
    rc = SPDM_BuildSecuredMessage(ctx, encBuf, encBufSz,
        mac, SPDM_AEAD_TAG_SIZE, spdmMsg, *spdmMsgSz);
    if (rc < 0) {
        return rc;
    }

    *spdmMsgSz = (word32)rc;
    return 0;
}

int wolfTPM2_SPDM_UnwrapResponse(
    WOLFTPM2_SPDM_CTX* ctx,
    const byte* spdmMsg, word32 spdmMsgSz,
    byte* tpmResp, word32* tpmRespSz)
{
    int rc;
    word32 sessionId;
    word64 seqNum;
    byte encPayload[SPDM_MAX_MSG_SIZE];
    word32 encPayloadSz = sizeof(encPayload);
    byte mac[SPDM_AEAD_TAG_SIZE];
    word32 macSz = sizeof(mac);
    byte plainBuf[SPDM_MAX_MSG_SIZE];
    word32 plainSz;
    char vdCode[SPDM_VDCODE_LEN + 1];
    word32 payloadSz;

    if (ctx == NULL || spdmMsg == NULL || tpmResp == NULL ||
        tpmRespSz == NULL) {
        return BAD_FUNC_ARG;
    }

    if (ctx->state != SPDM_STATE_CONNECTED) {
        return TPM_RC_AUTH_MISSING;
    }

    /* Parse TCG secured message */
    rc = SPDM_ParseSecuredMessage(spdmMsg, spdmMsgSz,
        &sessionId, &seqNum, encPayload, &encPayloadSz,
        mac, &macSz, NULL);
    if (rc < 0) {
        return rc;
    }

    /* Verify session ID */
    if (sessionId != ctx->sessionId) {
        return TPM_RC_VALUE;
    }

    /* Verify sequence number */
    if (seqNum != ctx->rspSeqNum) {
        return TPM_RC_VALUE;
    }
    ctx->rspSeqNum++;

    /* Reassemble encrypted data + MAC for decryption */
    if (encPayloadSz + macSz > sizeof(ctx->msgBuf)) {
        return BUFFER_E;
    }
    XMEMCPY(ctx->msgBuf, encPayload, encPayloadSz);
    XMEMCPY(ctx->msgBuf + encPayloadSz, mac, macSz);

    /* Decrypt via backend */
    if (ctx->backend == NULL || ctx->backend->DecryptMessage == NULL) {
        return TPM_RC_FAILURE;
    }

    plainSz = sizeof(plainBuf);
    rc = ctx->backend->DecryptMessage(ctx, ctx->msgBuf,
        encPayloadSz + macSz, plainBuf, &plainSz);
    if (rc != 0) {
        return rc;
    }

    /* Parse VENDOR_DEFINED_RESPONSE to extract TPM response */
    XMEMSET(vdCode, 0, sizeof(vdCode));
    payloadSz = *tpmRespSz;
    rc = SPDM_ParseVendorDefined(plainBuf, plainSz,
        vdCode, tpmResp, &payloadSz);
    if (rc < 0) {
        return rc;
    }

    /* Verify VdCode is TPM2_CMD response */
    if (XMEMCMP(vdCode, SPDM_VDCODE_TPM2_CMD, SPDM_VDCODE_LEN) != 0) {
        return TPM_RC_VALUE;
    }

    *tpmRespSz = payloadSz;
    return 0;
}

/* -------------------------------------------------------------------------- */
/* SPDM Only Mode */
/* -------------------------------------------------------------------------- */

int wolfTPM2_SPDM_SetOnlyMode(
    WOLFTPM2_SPDM_CTX* ctx,
    int lock)
{
    int rc;
    int vdSz;
    byte payload[4];
    byte spdmMsg[256];
    byte rxBuf[256];
    word32 rxSz;

    if (ctx == NULL) {
        return BAD_FUNC_ARG;
    }

    if (ctx->state != SPDM_STATE_CONNECTED) {
        return TPM_RC_AUTH_MISSING;
    }

    /* Build SPDMONLY vendor-defined with lock/unlock byte */
    payload[0] = (byte)(lock ? SPDM_ONLY_LOCK : SPDM_ONLY_UNLOCK);
    vdSz = SPDM_BuildVendorDefined(SPDM_VDCODE_SPDMONLY,
        payload, 1, ctx->msgBuf, sizeof(ctx->msgBuf));
    if (vdSz < 0) {
        return vdSz;
    }

    /* This command is sent within the secured session */
    /* For now, wrap in clear message - will use secured once backend
     * encryption is wired up */
    rc = SPDM_BuildClearMessage(ctx, ctx->msgBuf, (word32)vdSz,
        spdmMsg, sizeof(spdmMsg));
    if (rc < 0) {
        return rc;
    }

    if (ctx->ioCb != NULL) {
        rxSz = sizeof(rxBuf);
        rc = ctx->ioCb(ctx, spdmMsg, (word32)rc, rxBuf, &rxSz,
            ctx->ioUserCtx);
        if (rc != 0) {
            return rc;
        }
    }

    ctx->spdmOnlyLocked = lock;
    return 0;
}

/* -------------------------------------------------------------------------- */
/* SPDM Disconnect and Cleanup */
/* -------------------------------------------------------------------------- */

int wolfTPM2_SPDM_Disconnect(WOLFTPM2_SPDM_CTX* ctx)
{
    int rc = 0;

    if (ctx == NULL) {
        return BAD_FUNC_ARG;
    }

    if (ctx->state != SPDM_STATE_CONNECTED) {
        return 0; /* Already disconnected */
    }

    /* End session via backend */
    if (ctx->backend != NULL && ctx->backend->EndSession != NULL) {
        rc = ctx->backend->EndSession(ctx);
    }

    ctx->state = SPDM_STATE_DISCONNECTED;
    ctx->sessionId = 0;
    ctx->reqSeqNum = 0;
    ctx->rspSeqNum = 0;

    return rc;
}

void wolfTPM2_SPDM_FreeCtx(WOLFTPM2_SPDM_CTX* ctx)
{
    if (ctx == NULL) {
        return;
    }

    /* Disconnect if still connected */
    if (ctx->state == SPDM_STATE_CONNECTED) {
        wolfTPM2_SPDM_Disconnect(ctx);
    }

    /* Cleanup backend */
    if (ctx->backend != NULL && ctx->backend->Cleanup != NULL) {
        ctx->backend->Cleanup(ctx);
    }

    /* Zero sensitive data */
    XMEMSET(ctx->rspPubKey, 0, sizeof(ctx->rspPubKey));
    XMEMSET(ctx->reqPubKey, 0, sizeof(ctx->reqPubKey));

    ctx->backendCtx = NULL;
    ctx->backend = NULL;
    ctx->state = SPDM_STATE_DISCONNECTED;
}

/* -------------------------------------------------------------------------- */
/* Backend Registration */
/* -------------------------------------------------------------------------- */

#ifdef WOLFTPM_WITH_LIBSPDM
    extern WOLFTPM2_SPDM_BACKEND spdm_libspdm_backend;
#endif
#ifdef WOLFTPM_WITH_WOLFSPDM
    extern WOLFTPM2_SPDM_BACKEND spdm_wolfspdm_backend;
#endif

WOLFTPM2_SPDM_BACKEND* wolfTPM2_SPDM_GetLibspdmBackend(void)
{
#ifdef WOLFTPM_WITH_LIBSPDM
    return &spdm_libspdm_backend;
#else
    return NULL;
#endif
}

WOLFTPM2_SPDM_BACKEND* wolfTPM2_SPDM_GetWolfSPDMBackend(void)
{
#ifdef WOLFTPM_WITH_WOLFSPDM
    return &spdm_wolfspdm_backend;
#else
    return NULL;
#endif
}

WOLFTPM2_SPDM_BACKEND* wolfTPM2_SPDM_GetDefaultBackend(void)
{
    WOLFTPM2_SPDM_BACKEND* backend = NULL;

    /* Prefer wolfSPDM if available */
    backend = wolfTPM2_SPDM_GetWolfSPDMBackend();
    if (backend != NULL) {
        return backend;
    }

    /* Fall back to libspdm */
    backend = wolfTPM2_SPDM_GetLibspdmBackend();
    return backend;
}

int wolfTPM2_SPDM_SetIoCb(
    WOLFTPM2_SPDM_CTX* ctx,
    WOLFTPM2_SPDM_IoCallback ioCb,
    void* userCtx)
{
    if (ctx == NULL) {
        return BAD_FUNC_ARG;
    }
    ctx->ioCb = ioCb;
    ctx->ioUserCtx = userCtx;
    return 0;
}

WOLFTPM2_SPDM_IoCallback wolfTPM2_SPDM_GetDefaultIoCb(void)
{
    return spdm_default_io_callback;
}

#endif /* WOLFTPM_SPDM */
