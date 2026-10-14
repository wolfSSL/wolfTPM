/* spdm_config_tests.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif
#include <wolftpm/tpm2_wrap.h>
#include <wolftpm/tpm2_packet.h>

static byte captured[MAX_COMMAND_SIZE];
static int capturedSz, failCommand, hmacCalls;
static UINT32 configCount;
static int configTruncate;

/* Compile the command builders with a mock transport, so both request
 * encoding and response decoding run without a TPM, socket, or SPI bus. */
#if defined(WOLFTPM_LINUX_DEV)
    #define TPM2_LINUX_SendCommand test_config_send
#elif defined(WOLFTPM_LINUX_DEV_AUTODETECT)
    #define TPM2_LINUX_AUTODETECT_SendCommand test_config_send
#elif defined(WOLFTPM_SWTPM)
    #define TPM2_SWTPM_SendCommand test_config_send
#elif defined(WOLFTPM_WINAPI)
    #define TPM2_WinApi_SendCommand test_config_send
#else
    #define TPM2_TIS_SendCommand test_config_send
#endif
#include "../src/tpm2.c"

int test_config_send(TPM2_CTX* ctx, TPM2_Packet* packet)
{
    TPM2_Packet rsp;
    UINT32 i;
    int isConfig = packet->buf[9] == (byte)TPM_CC_GetCapability;
    capturedSz = packet->pos;
    XMEMCPY(captured, packet->buf, capturedSz);
    TPM2_Packet_Init(ctx, &rsp);
    if (failCommand) {
        TPM2_Packet_Finalize(&rsp, TPM_ST_NO_SESSIONS, TPM_RC_FAILURE);
    }
    else if (isConfig) {
        TPM2_Packet_AppendU8(&rsp, 0);
        TPM2_Packet_AppendU32(&rsp, TPM_CAP_CONFIGS);
        TPM2_Packet_AppendU32(&rsp, configCount);
        for (i = 0; i < configCount; i++) {
            /* configTruncate stops partway through the last entry, which is
             * the shape a report cut short on the wire has. */
            if (configTruncate && i + 1 == configCount) {
                TPM2_Packet_AppendU32(&rsp, i + 1);
                if (configTruncate > 1) {
                    TPM2_Packet_AppendU8(&rsp, (byte)(i & 1));
                }
                break;
            }
            TPM2_Packet_AppendU32(&rsp, i + 1);
            TPM2_Packet_AppendU8(&rsp, (byte)(i & 1));
            TPM2_Packet_AppendU8(&rsp, (byte)((i + 1) & 1));
        }
        TPM2_Packet_Finalize(&rsp, TPM_ST_NO_SESSIONS, 0);
    }
    else if (TPM2_IS_HMAC_SESSION(ctx->session[0].sessionHandle)) {
        TPM2_AUTH_SESSION* session = &ctx->session[0];
        TPM2B_DIGEST hash;
        TPMS_AUTH_RESPONSE authRsp;
        int rc;
        XMEMSET(&hash, 0, sizeof(hash));
        XMEMSET(&authRsp, 0, sizeof(authRsp));
        hmacCalls++;
        authRsp.nonce.size = TPM_SHA256_DIGEST_SIZE;
        XMEMSET(authRsp.nonce.buffer, 0x33, authRsp.nonce.size);
        authRsp.sessionAttributes = TPMA_SESSION_continueSession;
        rc = TPM2_CalcRpHash(session->authHash, TPM_CC_SetCapability,
            NULL, 0, &hash);
        if (rc == 0) rc = TPM2_CalcHmac(session->authHash, &session->auth,
            &hash, &authRsp.nonce, &session->nonceCaller,
            authRsp.sessionAttributes, &authRsp.hmac);
        if (rc != 0) return rc;
        TPM2_Packet_AppendU32(&rsp, 0);
        TPM2_Packet_AppendU16(&rsp, authRsp.nonce.size);
        TPM2_Packet_AppendBytes(&rsp, authRsp.nonce.buffer, authRsp.nonce.size);
        TPM2_Packet_AppendU8(&rsp, authRsp.sessionAttributes);
        TPM2_Packet_AppendU16(&rsp, authRsp.hmac.size);
        TPM2_Packet_AppendBytes(&rsp, authRsp.hmac.buffer, authRsp.hmac.size);
        TPM2_Packet_Finalize(&rsp, TPM_ST_SESSIONS, 0);
    }
    else {
        TPM2_Packet_AppendU32(&rsp, 0); /* parameterSize */
        TPM2_Packet_AppendU16(&rsp, 0); /* nonce */
        TPM2_Packet_AppendU8(&rsp, 0);  /* attributes */
        TPM2_Packet_AppendU16(&rsp, 0); /* authorization */
        TPM2_Packet_Finalize(&rsp, TPM_ST_SESSIONS, 0);
    }
    packet->size = rsp.pos;
    return 0;
}

#if !defined(WOLFTPM_LINUX_DEV) && !defined(WOLFTPM_SWTPM) && \
    !defined(WOLFTPM_WINAPI)
#ifdef WOLFTPM_ADV_IO
static int test_config_io(TPM2_CTX* ctx, INT32 read, UINT32 addr, BYTE* buf,
    UINT16 sz, void* user)
{ (void)ctx; (void)read; (void)addr; (void)buf; (void)sz; (void)user;
#else
static int test_config_io(TPM2_CTX* ctx, const BYTE* tx, BYTE* rx,
    UINT16 sz, void* user)
{ (void)ctx; (void)tx; (void)rx; (void)sz; (void)user;
#endif
    return TPM_RC_FAILURE;
}
#endif /* callback transports */

int main(void)
{
    static const byte expected[] = {
        0x80,0x02,0,0,0,43,0,0,1,0x9f,
        0x40,0,0,0x0c, 0,0,0,13,
        0x40,0,0,9, 0,0,1,0,4,'t','e','s','t',
        0,10, 0x81,0xc9,0,1, 0,0,0,3, 1,0
    };
    WOLFTPM2_DEV dev;
    TPM2B_AUTH auth;
    GetCapability_In in;
    GetCapability_Out out;
    UINT32 counts[] = { 0, 1, MAX_TAGGED_CONFIGS };
    UINT32 i, j;
    CmdInfo_t info;
    int rc;
    XMEMSET(&dev, 0, sizeof(dev));
    XMEMSET(&auth, 0, sizeof(auth));
    XMEMSET(&in, 0, sizeof(in));
    XMEMSET(&out, 0, sizeof(out));
#if defined(WOLFTPM_LINUX_DEV) || defined(WOLFTPM_SWTPM) || \
    defined(WOLFTPM_WINAPI)
    rc = TPM2_Init_minimal(&dev.ctx);
#else
    rc = TPM2_Init_ex(&dev.ctx, test_config_io, NULL, 0);
#endif
    if (rc != 0) return 1;
    auth.size = 4; XMEMCPY(auth.buffer, "test", 4);
    rc = wolfTPM2_SetAuthPassword(&dev, 0, &auth);
    if (rc != 0) return 2;
    for (i = 0; i < 2; i++) {
        failCommand = (int)i;
        rc = wolfTPM2_SpdmInfineonEnable(&dev, 1, 0);
        if (rc != (i == 0 ? TPM_RC_SUCCESS : TPM_RC_FAILURE) ||
            capturedSz != (int)sizeof(expected) ||
            XMEMCMP(captured, expected, sizeof(expected)) != 0 ||
            dev.session[0].auth.size != 4 ||
            XMEMCMP(dev.session[0].auth.buffer, "test", 4) != 0) {
            printf("FAIL: SetCapability rc=0x%x, captured size=%d\n", rc, capturedSz);
            return 3;
        }
    }
    puts("PASS: SetCapability wire encoding and platform auth on success/failure");
    XMEMSET(&dev.session[0], 0, sizeof(dev.session[0]));
    for (i = 0; i < 2; i++) {
        failCommand = (int)i;
        rc = wolfTPM2_SpdmInfineonEnable(&dev, 1, 0);
        if (rc != (i == 0 ? TPM_RC_SUCCESS : TPM_RC_FAILURE) ||
            capturedSz != 39 || dev.session[0].sessionHandle != 0 ||
            dev.session[0].auth.size != 0) return 6;
    }
    puts("PASS: unused auth slot restored after success/failure");
    failCommand = 0;
    in.capability = TPM_CAP_CONFIGS;
    in.propertyCount = MAX_TAGGED_CONFIGS;
    for (i = 0; i < sizeof(counts) / sizeof(counts[0]); i++) {
        configCount = counts[i];
        XMEMSET(&out, 0, sizeof(out));
        rc = TPM2_GetCapability(&in, &out);
        if (rc != 0 || out.capabilityData.data.tpmConfigs.count != configCount)
            return 4;
        for (j = 0; j < configCount; j++) {
            TPMS_TAGGED_CONFIG* cfg = &out.capabilityData.data.tpmConfigs.configs[j];
            if (cfg->configuration != j + 1 || cfg->enable != (j & 1) ||
                cfg->lock != ((j + 1) & 1)) return 5;
        }
    }
    puts("PASS: TPM_CAP_CONFIGS counts 0, 1 and the maximum");

    /* A count the local array cannot hold, and an entry cut short after its
     * configuration and after its enable byte. Each must be refused whole:
     * a shortened list would read as a complete security report. */
    configCount = MAX_TAGGED_CONFIGS + 1;
    configTruncate = 0;
    XMEMSET(&out, 0, sizeof(out));
    rc = TPM2_GetCapability(&in, &out);
    if (rc != TPM_RC_SIZE ||
            out.capabilityData.data.tpmConfigs.count != 0) {
        printf("FAIL: oversize count rc=0x%x count=%u\n", rc,
            out.capabilityData.data.tpmConfigs.count);
        return 9;
    }
    for (i = 1; i <= 2; i++) {
        configCount = 2;
        configTruncate = (int)i;
        XMEMSET(&out, 0, sizeof(out));
        rc = TPM2_GetCapability(&in, &out);
        if (rc != TPM_RC_SIZE ||
                out.capabilityData.data.tpmConfigs.count != 0) {
            printf("FAIL: truncated entry %u rc=0x%x count=%u\n", i, rc,
                out.capabilityData.data.tpmConfigs.count);
            return 9;
        }
    }
    configTruncate = 0;
    puts("PASS: oversize count and truncated entries refused with TPM_RC_SIZE");

    XMEMSET(&info, 0, sizeof(info));
    XMEMSET(dev.session, 0, sizeof(dev.session));
    info.flags = CMD_FLAG_AUTH_USER1;
    dev.session[0].sessionHandle = HMAC_SESSION_FIRST;
    if (TPM2_GetCmdAuthCount(&dev.ctx, &info) != 1) return 8;
    info.flags = 0;
    if (TPM2_GetCmdAuthCount(&dev.ctx, &info) != 0) return 8;
    info.flags = CMD_FLAG_AUTH_USER1 | CMD_FLAG_ENC2;
    dev.session[0].sessionHandle = TPM_RS_PW;
    dev.session[1].sessionHandle = HMAC_SESSION_FIRST;
    dev.session[1].sessionAttributes = TPMA_SESSION_decrypt;
    if (TPM2_GetCmdAuthCount(&dev.ctx, &info) != 2) return 8;
    XMEMSET(dev.session, 0, sizeof(dev.session));
    dev.session[0].sessionHandle = HMAC_SESSION_FIRST;
    dev.session[0].authHash = TPM_ALG_SHA256;
    dev.session[0].auth.size = 4;
    XMEMCPY(dev.session[0].auth.buffer, "test", 4);
    dev.session[0].nonceCaller.size = TPM_SHA256_DIGEST_SIZE;
    dev.session[0].nonceTPM.size = TPM_SHA256_DIGEST_SIZE;
    XMEMSET(dev.session[0].nonceTPM.buffer, 0x11, TPM_SHA256_DIGEST_SIZE);
    dev.session[0].sessionAttributes = TPMA_SESSION_continueSession;
    rc = wolfTPM2_SpdmInfineonEnable(&dev, 1, 0);
    if (rc != 0 || hmacCalls != 1 || capturedSz != 103 ||
        dev.session[0].nonceTPM.buffer[0] != 0x33) {
        printf("FAIL: primary HMAC authorization rc=0x%x, calls=%d\n", rc, hmacCalls);
        return 7;
    }
    puts("PASS: caller HMAC authorization and authenticated response processing");
    TPM2_Cleanup(&dev.ctx);
    puts("PASS: empty, single and maximum-count TPM_CAP_CONFIGS fixtures");
    return 0;
}
