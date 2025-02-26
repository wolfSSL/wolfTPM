/* tpm2.c
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_packet.h>
#include <wolftpm/tpm2_tis.h>
#include <wolftpm/tpm2_linux.h>
#include <wolftpm/tpm2_swtpm.h>
#include <wolftpm/tpm2_winapi.h>
#include <wolftpm/tpm2_param_enc.h>

#include <hal/tpm_io.h>

/******************************************************************************/
/* --- Local Variables -- */
/******************************************************************************/

static THREAD_LS_T TPM2_CTX* gActiveTPM;

    #define INTERNAL_SEND_COMMAND      TPM2_TIS_SendCommand
    #define TPM2_INTERNAL_CLEANUP(ctx)
/******************************************************************************/
/* --- Local Functions -- */
/******************************************************************************/
static TPM_RC TPM2_AcquireLock(TPM2_CTX* ctx)
{
    (void)ctx;
    return TPM_RC_SUCCESS;
}

static void TPM2_ReleaseLock(TPM2_CTX* ctx)
{
    (void)ctx;
}

static int TPM2_CommandProcess(TPM2_CTX* ctx, TPM2_Packet* packet,
    CmdInfo_t* info, TPM_CC cmdCode, UINT32 cmdSz)
{
    int rc = TPM_RC_SUCCESS;
    UINT32 authSz;
    BYTE *param, *encParam = NULL;
    int paramSz, encParamSz = 0;
    int i, authPos;
    int authTotalSzPos = 0;
	(void)encParam;
	(void)encParamSz;
    /* Skip the header and handles area */
    packet->pos = TPM2_HEADER_SIZE + (info->inHandleCnt * sizeof(TPM_HANDLE));

    /* Parse Auth */
    TPM2_Packet_ParseU32(packet, &authSz);
    packet->pos -= sizeof(authSz);
    /* Get position for total auth size to be updated later */
    TPM2_Packet_MarkU32(packet, &authTotalSzPos);
    /* Mark the position of the Auth Area data */
    authPos = packet->pos;
    packet->pos += authSz;

    /* Mark parameter data */
    param = &packet->buf[packet->pos];
    paramSz = cmdSz - packet->pos;

    /* Mark "first" encryption parameter */
    if (info->flags & CMD_FLAG_ENC2) {
        UINT16 tempSz;
        TPM2_Packet_ParseU16(packet, &tempSz);
        encParam = param + sizeof(UINT16);
        encParamSz = tempSz;
    }
    else if (info->flags & CMD_FLAG_ENC4) {
        UINT32 tempSz;
        TPM2_Packet_ParseU32(packet, &tempSz);
        encParam = param + sizeof(UINT32);
        encParamSz = tempSz;
    }

    (void)paramSz;

    for (i=0; i<info->authCnt; i++) {
        TPM2_AUTH_SESSION* session = &ctx->session[i];
        TPMS_AUTH_COMMAND authCmd;

        if (session->sessionHandle != TPM_RS_PW) {
            /* Generate fresh nonce */
            rc = TPM2_GetNonce(session->nonceCaller.buffer,
                session->nonceCaller.size);
            if (rc != TPM_RC_SUCCESS) {
                return rc;
            }
        }

        /* Build auth */
        XMEMSET(&authCmd, 0, sizeof(authCmd));
        authCmd.sessionHandle = session->sessionHandle;
        authCmd.sessionAttributes = session->sessionAttributes;
        authCmd.nonce.size = session->nonceCaller.size;
        XMEMCPY(authCmd.nonce.buffer, session->nonceCaller.buffer,
            authCmd.nonce.size);

        /* Password Auth */
        if (session->sessionHandle == TPM_RS_PW) {
            authCmd.hmac.size = session->auth.size;
            XMEMCPY(authCmd.hmac.buffer, session->auth.buffer,
                session->auth.size);
        }
        /* HMAC or Policy Session */
        else if (TPM2_IS_HMAC_SESSION(session->sessionHandle) ||
                 TPM2_IS_POLICY_SESSION(session->sessionHandle))
        {
            /* default is a HMAC output (using alg authHash) */
            authCmd.hmac.size = TPM2_GetHashDigestSize(session->authHash);

            /* if param enc is not supported for this command then clear flag */
            /* session attribute flags are from TPM perspective */
            if ((info->flags & (CMD_FLAG_ENC2 | CMD_FLAG_ENC4)) == 0) {
                authCmd.sessionAttributes &= ~TPMA_SESSION_decrypt;
            }
            if ((info->flags & (CMD_FLAG_DEC2 | CMD_FLAG_DEC4)) == 0) {
                authCmd.sessionAttributes &= ~TPMA_SESSION_encrypt;
            }
        }

        /* Place session auth */
        packet->pos = authPos;
        TPM2_Packet_AppendAuthCmd(packet, &authCmd);
        authPos = packet->pos; /* update auth position */
    }

    /* Update the Auth Area total size in the command packet */
    i = TPM2_Packet_PlaceU32(packet, authTotalSzPos);


    (void)cmdCode;
    (void)i;

    return rc;
}

static int TPM2_ResponseProcess(TPM2_CTX* ctx, TPM2_Packet* packet,
    CmdInfo_t* info, TPM_CC cmdCode, UINT32 respSz)
{
    int rc = TPM_RC_SUCCESS;
    BYTE *param, *decParam = NULL;
    UINT32 paramSz, decParamSz = 0, authPos;
    int i;

    /* Skip the header output handles */
    packet->pos = TPM2_HEADER_SIZE + (info->outHandleCnt * sizeof(TPM_HANDLE));

    /* Response Parameter Size */
    TPM2_Packet_ParseU32(packet, &paramSz);
    param = &packet->buf[packet->pos]; /* Mark parameter data */
    authPos = packet->pos + paramSz;

    /* Mark "first" decryption parameter */
    if (info->flags & CMD_FLAG_DEC2) {
        UINT16 tempSz;
        TPM2_Packet_ParseU16(packet, &tempSz);
        decParam = param + sizeof(UINT16);
        decParamSz = tempSz;
    }
    else if (info->flags & CMD_FLAG_DEC4) {
        UINT32 tempSz;
        TPM2_Packet_ParseU32(packet, &tempSz);
        decParam = param + sizeof(UINT32);
        decParamSz = tempSz;
    }


    for (i=0; i<info->authCnt; i++) {
        TPM2_AUTH_SESSION* session = &ctx->session[i];
        TPMS_AUTH_RESPONSE authRsp;
        XMEMSET(&authRsp, 0, sizeof(authRsp));

        /* Parse Auth - if exists */
        if (respSz > authPos) {
            packet->pos = authPos;
            TPM2_Packet_ParseAuth(packet, &authRsp);
            authPos = packet->pos;
        }

        if (session->sessionHandle != TPM_RS_PW) {
            /* update nonceTPM */
            if (authRsp.nonce.size > 0) {
                session->nonceTPM.size = authRsp.nonce.size;
                XMEMCPY(session->nonceTPM.buffer, authRsp.nonce.buffer,
                    authRsp.nonce.size);
            }
            (void)decParam;
            (void)decParamSz;
            (void)cmdCode;
        }
    }

    return rc;
}

static TPM_RC TPM2_SendCommandAuth(TPM2_CTX* ctx, TPM2_Packet* packet,
    CmdInfo_t* info)
{
    TPM_RC rc = TPM_RC_FAILURE;
    TPM_ST tag;
    TPM_CC cmdCode;
    BYTE *cmd;
    UINT32 cmdSz, respSz;

    if (ctx == NULL || packet == NULL || info == NULL)
        return BAD_FUNC_ARG;

    cmd = packet->buf;
    cmdSz = packet->pos;
    (void)cmd;

    /* restart the unmarshalling position */
    packet->pos = 0;
    TPM2_Packet_ParseU16(packet, &tag);
    TPM2_Packet_ParseU32(packet, NULL);
    TPM2_Packet_ParseU32(packet, &cmdCode);  /* Extract TPM Command Code */

    /* Is auth session required for this TPM command? */
    if (tag == TPM_ST_SESSIONS) {
        /* Is there at least one auth session present? */
        if (info->authCnt < 1 || ctx->session == NULL)
            return TPM_RC_AUTH_MISSING;


        rc = TPM2_CommandProcess(ctx, packet, info, cmdCode, cmdSz);
        if (rc != 0)
            return rc;
    }

    /* reset packet->pos to total command length (send command requires it) */
    packet->pos = cmdSz;

    /* submit command and wait for response */
    rc = (TPM_RC)INTERNAL_SEND_COMMAND(ctx, packet);
    if (rc != 0)
        return rc;

    /* parse response */
    rc = TPM2_Packet_Parse(rc, packet);
    respSz = packet->size;

    /* restart the unmarshalling position */
    packet->pos = 0;
    TPM2_Packet_ParseU16(packet, &tag);

    /* Is auth session required for this TPM command? */
    if (rc == TPM_RC_SUCCESS && tag == TPM_ST_SESSIONS) {
        rc = TPM2_ResponseProcess(ctx, packet, info, cmdCode, respSz);
    }

    /* Caller expects packet position to be at end of header */
    packet->pos = TPM2_HEADER_SIZE;

    return rc;
}

static TPM_RC TPM2_SendCommand(TPM2_CTX* ctx, TPM2_Packet* packet)
{
    TPM_RC rc;

    if (ctx == NULL || packet == NULL)
        return BAD_FUNC_ARG;

    /* submit command and wait for response */
    rc = (TPM_RC)INTERNAL_SEND_COMMAND(ctx, packet);
    if (rc != 0)
        return rc;

    return TPM2_Packet_Parse(rc, packet);
}


/******************************************************************************/
/* --- Public Functions -- */
/******************************************************************************/
TPM2_CTX* TPM2_GetActiveCtx(void)
{
    return gActiveTPM;
}

void TPM2_SetActiveCtx(TPM2_CTX* ctx)
{
    gActiveTPM = ctx;
}

TPM_RC TPM2_SetSessionAuth(TPM2_AUTH_SESSION* session)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        ctx->session = session;

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

/* Finds the number of active Auth Session in the given TPM2 context */
int TPM2_GetSessionAuthCount(TPM2_CTX* ctx)
{
    int rc;
    if (ctx == NULL)
        rc = BAD_FUNC_ARG;
    else if (ctx->session == NULL)
        rc = 0;
    else
        rc = TPM2_GetCmdAuthCount(ctx, NULL);
    return rc;
}

TPM_RC TPM2_ChipStartup(TPM2_CTX* ctx, int timeoutTries)
{
    TPM_RC rc;

    if (ctx == NULL) {
        return BAD_FUNC_ARG;
    }

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {

        /* Wait for chip startup to complete */
        rc = TPM2_TIS_StartupWait(ctx, timeoutTries);
        if (rc == TPM_RC_SUCCESS) {

            /* Request locality for TPM module */
            rc = TPM2_TIS_RequestLocality(ctx, timeoutTries);
            if (rc == TPM_RC_SUCCESS) {

                /* Get device information */
                rc = TPM2_TIS_GetInfo(ctx);
            }
        }

        TPM2_ReleaseLock(ctx);
    }

    return rc;
}

TPM_RC TPM2_SetHalIoCb(TPM2_CTX* ctx, TPM2HalIoCb ioCb, void* userCtx)
{
    TPM_RC rc;

    if (ctx == NULL || ioCb == NULL) {
        return BAD_FUNC_ARG;
    }

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        ctx->ioCb = ioCb;
        ctx->userCtx = userCtx;

        TPM2_ReleaseLock(ctx);
    }

    return rc;
}

/* If timeoutTries <= 0 then it will not try and startup chip and will
 * use existing default locality */
TPM_RC TPM2_Init_ex(TPM2_CTX* ctx, TPM2HalIoCb ioCb, void* userCtx,
    int timeoutTries)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (ctx == NULL) {
        return BAD_FUNC_ARG;
    }

    XMEMSET(ctx, 0, sizeof(TPM2_CTX));


#if defined(WOLFTPM_SWTPM)
    ctx->tcpCtx.fd = -1;
#endif

#if defined(WOLFTPM_LINUX_DEV) || defined(WOLFTPM_SWTPM) || defined(WOLFTPM_WINAPI)
    if (ioCb != NULL || userCtx != NULL) {
        return BAD_FUNC_ARG;
    }
#else
    #ifdef WOLFTPM_MMIO
    if (ioCb == NULL)
        ioCb = TPM2_IoCb_Mmio;
    #endif
    /* Setup HAL IO Callback */
    rc = TPM2_SetHalIoCb(ctx, ioCb, userCtx);
    if (rc != TPM_RC_SUCCESS)
        return rc;
#endif

    /* Set the active TPM global */
    TPM2_SetActiveCtx(ctx);

    if (timeoutTries > 0) {
        /* Perform chip startup and assign locality */
        rc = TPM2_ChipStartup(ctx, timeoutTries);
    }
    else {
        /* use existing locality */
        ctx->locality = WOLFTPM_LOCALITY_DEFAULT;
    }

    return rc;
}

TPM_RC TPM2_Init_minimal(TPM2_CTX* ctx)
{
    return TPM2_Init_ex(ctx, NULL, NULL, 0);
}

TPM_RC TPM2_Init(TPM2_CTX* ctx, TPM2HalIoCb ioCb, void* userCtx)
{
    return TPM2_Init_ex(ctx, ioCb, userCtx, TPM_TIMEOUT_TRIES);
}

TPM_RC TPM2_Cleanup(TPM2_CTX* ctx)
{
    TPM_RC rc;

    if (ctx == NULL)
        return BAD_FUNC_ARG;

    /* clear global */
    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {

        if (TPM2_GetActiveCtx() == ctx) {
            TPM2_INTERNAL_CLEANUP(ctx);
            /* set non-active */
            TPM2_SetActiveCtx(NULL);
        }

        TPM2_ReleaseLock(ctx);
    }

    return TPM_RC_SUCCESS;
}


/******************************************************************************/
/* --- BEGIN Standard TPM API's -- */
/******************************************************************************/
TPM_RC TPM2_Startup(Startup_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU16(&packet, in->startupType);
        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_Startup);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_Shutdown(Shutdown_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU16(&packet, in->shutdownType);
        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_Shutdown);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}


TPM_RC TPM2_GetCapability(GetCapability_In* in, GetCapability_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        int i;
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->capability);
        TPM2_Packet_AppendU32(&packet, in->property);
        TPM2_Packet_AppendU32(&packet, in->propertyCount);
        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_GetCapability);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            TPM2_Packet_ParseU8(&packet, &out->moreData);
            TPM2_Packet_ParseU32(&packet, &out->capabilityData.capability);

            switch (out->capabilityData.capability) {
                case TPM_CAP_ALGS:
                {
                    TPML_ALG_PROPERTY* algorithms =
                        &out->capabilityData.data.algorithms;
                    TPM2_Packet_ParseU32(&packet, &algorithms->count);
                    if (algorithms->count > MAX_CAP_ALGS)
                        algorithms->count = MAX_CAP_ALGS;
                    for (i=0; i<(int)algorithms->count; i++) {
                        TPM2_Packet_ParseU16(&packet,
                            &algorithms->algProperties[i].alg);
                        TPM2_Packet_ParseU32(&packet,
                            &algorithms->algProperties[i].algProperties);
                    }
                    break;
                }
                case TPM_CAP_HANDLES:
                {
                    TPML_HANDLE* handles =
                        &out->capabilityData.data.handles;
                    TPM2_Packet_ParseU32(&packet, &handles->count);
                    if (handles->count > MAX_CAP_HANDLES)
                        handles->count = MAX_CAP_HANDLES;
                    for (i=0; i<(int)handles->count; i++) {
                        TPM2_Packet_ParseU32(&packet, &handles->handle[i]);
                    }
                    break;
                }
                case TPM_CAP_COMMANDS:
                {
                    TPML_CCA* cmdAttribs =
                        &out->capabilityData.data.command;
                    TPM2_Packet_ParseU32(&packet, &cmdAttribs->count);
                    if (cmdAttribs->count > MAX_CAP_CC)
                        cmdAttribs->count = MAX_CAP_CC;
                    for (i=0; i<(int)cmdAttribs->count; i++) {
                        TPM2_Packet_ParseU32(&packet,
                            &cmdAttribs->commandAttributes[i]);
                    }
                    break;
                }
                case TPM_CAP_PP_COMMANDS:
                case TPM_CAP_AUDIT_COMMANDS:
                {
                    TPML_CC* cmdCodes =
                        &out->capabilityData.data.ppCommands;
                    TPM2_Packet_ParseU32(&packet, &cmdCodes->count);
                    if (cmdCodes->count > MAX_CAP_CC)
                        cmdCodes->count = MAX_CAP_CC;
                    for (i=0; i<(int)cmdCodes->count; i++) {
                        TPM2_Packet_ParseU32(&packet,
                            &cmdCodes->commandCodes[i]);
                    }
                    break;
                }
                case TPM_CAP_PCRS:
                {
                    TPML_PCR_SELECTION* assignedPCR =
                        &out->capabilityData.data.assignedPCR;
                    TPM2_Packet_ParsePCR(&packet, assignedPCR);
                    break;
                }
                case TPM_CAP_TPM_PROPERTIES:
                {
                    TPML_TAGGED_TPM_PROPERTY* prop =
                        &out->capabilityData.data.tpmProperties;
                    TPM2_Packet_ParseU32(&packet, &prop->count);
                    if (prop->count > MAX_TPM_PROPERTIES)
                        prop->count = MAX_TPM_PROPERTIES;
                    for (i=0; i<(int)prop->count; i++) {
                        TPM2_Packet_ParseU32(&packet,
                            &prop->tpmProperty[i].property);
                        TPM2_Packet_ParseU32(&packet,
                            &prop->tpmProperty[i].value);
                    }
                    break;
                }
                case TPM_CAP_PCR_PROPERTIES:
                {
                    TPML_TAGGED_PCR_PROPERTY* pcrProp =
                        &out->capabilityData.data.pcrProperties;
                    TPM2_Packet_ParseU32(&packet, &pcrProp->count);
                    if (pcrProp->count > MAX_PCR_PROPERTIES)
                        pcrProp->count = MAX_PCR_PROPERTIES;
                    for (i=0; i<(int)pcrProp->count; i++) {
                        TPMS_TAGGED_PCR_SELECT* sel = &pcrProp->pcrProperty[i];
                        TPM2_Packet_ParseU32(&packet, &sel->tag);
                        TPM2_Packet_ParseU8(&packet, &sel->sizeofSelect);
                        if (sel->sizeofSelect > PCR_SELECT_MAX)
                            sel->sizeofSelect = PCR_SELECT_MAX;
                        TPM2_Packet_ParseBytes(&packet, sel->pcrSelect,
                            sel->sizeofSelect);
                    }
                    break;
                }
                case TPM_CAP_ECC_CURVES:
                {
                    TPML_ECC_CURVE* eccCurves =
                        &out->capabilityData.data.eccCurves;
                    TPM2_Packet_ParseU32(&packet, &eccCurves->count);
                    if (eccCurves->count > MAX_ECC_CURVES)
                        eccCurves->count = MAX_ECC_CURVES;
                    for (i=0; i<(int)eccCurves->count; i++) {
                        TPM2_Packet_ParseU16(&packet,
                            &eccCurves->eccCurves[i]);
                    }
                    break;
                }
                case TPM_CAP_AUTH_POLICIES:
                {
                    TPML_TAGGED_POLICY* authPol =
                        &out->capabilityData.data.authPolicies;
                    TPM2_Packet_ParseU32(&packet, &authPol->count);
                    if (authPol->count > MAX_TAGGED_POLICIES)
                        authPol->count = MAX_TAGGED_POLICIES;
                    for (i=0; i<(int)authPol->count; i++) {
                        int digSz;
                        TPMS_TAGGED_POLICY* pol = &authPol->policies[i];
                        TPM2_Packet_ParseU32(&packet, &pol->handle);
                        TPM2_Packet_ParseU16(&packet, &pol->policyHash.hashAlg);
                        digSz = (int)TPM2_GetHashDigestSize(
                            pol->policyHash.hashAlg);
                        if (digSz > (int)sizeof(pol->policyHash.digest)) {
                            digSz = (int)sizeof(pol->policyHash.digest);
                        }
                        TPM2_Packet_ParseBytes(&packet,
                            pol->policyHash.digest.H, digSz);
                    }
                    break;
                }
                case TPM_CAP_ACT:
                {
                    TPML_ACT_DATA* actData =
                        &out->capabilityData.data.actData;
                    TPM2_Packet_ParseU32(&packet, &actData->count);
                    if (actData->count > MAX_ACT_DATA)
                        actData->count = MAX_ACT_DATA;
                    for (i=0; i<(int)actData->count; i++) {
                        TPM2_Packet_ParseU32(&packet,
                            &actData->actData[i].handle);
                        TPM2_Packet_ParseU32(&packet,
                            &actData->actData[i].timeout);
                        TPM2_Packet_ParseU32(&packet,
                            &actData->actData[i].attributes);
                    }
                    break;
                }
                case TPM_CAP_VENDOR_PROPERTY:
                {
                    out->capabilityData.data.vendor.size =
                        packet.size - packet.pos;
                    if (out->capabilityData.data.vendor.size >
                            sizeof(out->capabilityData.data.vendor.buffer)) {
                        out->capabilityData.data.vendor.size =
                            sizeof(out->capabilityData.data.vendor.buffer);
                    }
                    TPM2_Packet_ParseBytes(&packet,
                        out->capabilityData.data.vendor.buffer,
                        out->capabilityData.data.vendor.size);
                    break;
                }
                default:
                    break;
            }
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}


TPM_RC TPM2_PCR_Read(PCR_Read_In* in, PCR_Read_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        int i;
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendPCR(&packet, &in->pcrSelectionIn);
        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_PCR_Read);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            TPM2_Packet_ParseU32(&packet, &out->pcrUpdateCounter);
            TPM2_Packet_ParsePCR(&packet, &out->pcrSelectionOut);
            TPM2_Packet_ParseU32(&packet, &out->pcrValues.count);
            for (i=0; i<(int)out->pcrValues.count; i++) {
                TPM2_Packet_ParseU16(&packet, &out->pcrValues.digests[i].size);
                TPM2_Packet_ParseBytes(&packet,
                    out->pcrValues.digests[i].buffer,
                    out->pcrValues.digests[i].size);
            }
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_PCR_Extend(PCR_Extend_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || ctx->session == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        int i;
        TPM2_Packet packet;
        CmdInfo_t info = {0,0,0,0};
        info.inHandleCnt = 1;
        info.flags = (CMD_FLAG_AUTH_USER1);

        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->pcrHandle);
        TPM2_Packet_AppendAuth(&packet, ctx, &info);
        TPM2_Packet_AppendU32(&packet, in->digests.count);
        for (i=0; i<(int)in->digests.count; i++) {
            UINT16 hashAlg = in->digests.digests[i].hashAlg;
            int digestSz = TPM2_GetHashDigestSize(hashAlg);
            TPM2_Packet_AppendU16(&packet, hashAlg);
            TPM2_Packet_AppendBytes(&packet, in->digests.digests[i].digest.H,
                digestSz);
        }
        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_PCR_Extend);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}


TPM_RC TPM2_Create(Create_In* in, Create_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL || ctx->session == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        CmdInfo_t info = {0,0,0,0};
        info.inHandleCnt = 1;
        info.flags = (CMD_FLAG_ENC2 | CMD_FLAG_DEC2 | CMD_FLAG_AUTH_USER1);

        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->parentHandle);
        TPM2_Packet_AppendAuth(&packet, ctx, &info);
        TPM2_Packet_AppendSensitiveCreate(&packet, &in->inSensitive);
        TPM2_Packet_AppendPublic(&packet, &in->inPublic);
        TPM2_Packet_AppendU16(&packet, in->outsideInfo.size);
        TPM2_Packet_AppendBytes(&packet, in->outsideInfo.buffer,
            in->outsideInfo.size);
        TPM2_Packet_AppendPCR(&packet, &in->creationPCR);
        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_Create);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);
        if (rc == TPM_RC_SUCCESS) {
            UINT32 paramSz = 0;

            TPM2_Packet_ParseU32(&packet, &paramSz);

            TPM2_Packet_ParseU16(&packet, &out->outPrivate.size);
            TPM2_Packet_ParseBytes(&packet, out->outPrivate.buffer,
                out->outPrivate.size);

            TPM2_Packet_ParsePublic(&packet, &out->outPublic);

            TPM2_Packet_ParseU16(&packet, &out->creationData.size);
            TPM2_Packet_ParsePCR(&packet,
                &out->creationData.creationData.pcrSelect);
            TPM2_Packet_ParseU16(&packet,
                &out->creationData.creationData.pcrDigest.size);
            TPM2_Packet_ParseBytes(&packet,
                out->creationData.creationData.pcrDigest.buffer,
                out->creationData.creationData.pcrDigest.size);
            TPM2_Packet_ParseU8(&packet,
                &out->creationData.creationData.locality);
            TPM2_Packet_ParseU16(&packet,
                &out->creationData.creationData.parentNameAlg);
            TPM2_Packet_ParseU16(&packet,
                &out->creationData.creationData.parentName.size);
            TPM2_Packet_ParseBytes(&packet,
                out->creationData.creationData.parentName.name,
                out->creationData.creationData.parentName.size);
            TPM2_Packet_ParseU16(&packet,
                &out->creationData.creationData.parentQualifiedName.size);
            TPM2_Packet_ParseBytes(&packet,
                out->creationData.creationData.parentQualifiedName.name,
                out->creationData.creationData.parentQualifiedName.size);
            TPM2_Packet_ParseU16(&packet,
                &out->creationData.creationData.outsideInfo.size);
            TPM2_Packet_ParseBytes(&packet,
                out->creationData.creationData.outsideInfo.buffer,
                out->creationData.creationData.outsideInfo.size);

            TPM2_Packet_ParseU16(&packet, &out->creationHash.size);
            TPM2_Packet_ParseBytes(&packet, out->creationHash.buffer,
                out->creationHash.size);

            TPM2_Packet_ParseU16(&packet, &out->creationTicket.tag);
            TPM2_Packet_ParseU32(&packet, &out->creationTicket.hierarchy);
            TPM2_Packet_ParseU16(&packet, &out->creationTicket.digest.size);
            TPM2_Packet_ParseBytes(&packet,
                        out->creationTicket.digest.buffer,
                        out->creationTicket.digest.size);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_CreateLoaded(CreateLoaded_In* in, CreateLoaded_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL || ctx->session == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        CmdInfo_t info = {0,0,0,0};
        info.inHandleCnt = 1;
        info.flags = (CMD_FLAG_ENC2 | CMD_FLAG_DEC2 | CMD_FLAG_AUTH_USER1);

        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->parentHandle);
        TPM2_Packet_AppendAuth(&packet, ctx, &info);
        TPM2_Packet_AppendSensitiveCreate(&packet, &in->inSensitive);
        TPM2_Packet_AppendPublic(&packet, &in->inPublic);
        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_CreateLoaded);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);
        if (rc == TPM_RC_SUCCESS) {
            UINT32 paramSz = 0;

            TPM2_Packet_ParseU32(&packet, &out->objectHandle);
            TPM2_Packet_ParseU32(&packet, &paramSz);

            TPM2_Packet_ParseU16(&packet, &out->outPrivate.size);
            TPM2_Packet_ParseBytes(&packet, out->outPrivate.buffer,
                out->outPrivate.size);

            TPM2_Packet_ParsePublic(&packet, &out->outPublic);

            TPM2_Packet_ParseU16(&packet, &out->name.size);
            TPM2_Packet_ParseBytes(&packet, out->name.name, out->name.size);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_CreatePrimary(CreatePrimary_In* in, CreatePrimary_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL || ctx->session == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        CmdInfo_t info = {0,0,0,0};
        info.inHandleCnt = 1;
        info.outHandleCnt = 1;
        info.flags = (CMD_FLAG_ENC2 | CMD_FLAG_DEC2 | CMD_FLAG_AUTH_USER1);

        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->primaryHandle);
        TPM2_Packet_AppendAuth(&packet, ctx, &info);
        TPM2_Packet_AppendSensitiveCreate(&packet, &in->inSensitive);
        TPM2_Packet_AppendPublic(&packet, &in->inPublic);
        TPM2_Packet_AppendU16(&packet, in->outsideInfo.size);
        TPM2_Packet_AppendBytes(&packet, in->outsideInfo.buffer,
            in->outsideInfo.size);
        TPM2_Packet_AppendPCR(&packet, &in->creationPCR);
        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_CreatePrimary);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);
        if (rc == TPM_RC_SUCCESS) {
            UINT32 paramSz = 0;

            TPM2_Packet_ParseU32(&packet, &out->objectHandle);

            TPM2_Packet_ParseU32(&packet, &paramSz);

            TPM2_Packet_ParsePublic(&packet, &out->outPublic);

            TPM2_Packet_ParseU16(&packet, &out->creationData.size);
            TPM2_Packet_ParsePCR(&packet,
                &out->creationData.creationData.pcrSelect);
            TPM2_Packet_ParseU16(&packet,
                &out->creationData.creationData.pcrDigest.size);
            TPM2_Packet_ParseBytes(&packet,
                out->creationData.creationData.pcrDigest.buffer,
                out->creationData.creationData.pcrDigest.size);
            TPM2_Packet_ParseU8(&packet,
                &out->creationData.creationData.locality);
            TPM2_Packet_ParseU16(&packet,
                &out->creationData.creationData.parentNameAlg);
            TPM2_Packet_ParseU16(&packet,
                &out->creationData.creationData.parentName.size);
            TPM2_Packet_ParseBytes(&packet,
                out->creationData.creationData.parentName.name,
                out->creationData.creationData.parentName.size);
            TPM2_Packet_ParseU16(&packet,
                &out->creationData.creationData.parentQualifiedName.size);
            TPM2_Packet_ParseBytes(&packet,
                out->creationData.creationData.parentQualifiedName.name,
                out->creationData.creationData.parentQualifiedName.size);
            TPM2_Packet_ParseU16(&packet,
                &out->creationData.creationData.outsideInfo.size);
            TPM2_Packet_ParseBytes(&packet,
                out->creationData.creationData.outsideInfo.buffer,
                out->creationData.creationData.outsideInfo.size);

            TPM2_Packet_ParseU16(&packet, &out->creationHash.size);
            TPM2_Packet_ParseBytes(&packet, out->creationHash.buffer,
                out->creationHash.size);

            TPM2_Packet_ParseU16(&packet, &out->creationTicket.tag);
            TPM2_Packet_ParseU32(&packet, &out->creationTicket.hierarchy);
            TPM2_Packet_ParseU16(&packet, &out->creationTicket.digest.size);
            TPM2_Packet_ParseBytes(&packet,
                        out->creationTicket.digest.buffer,
                        out->creationTicket.digest.size);

            TPM2_Packet_ParseU16(&packet, &out->name.size);
            TPM2_Packet_ParseBytes(&packet, out->name.name, out->name.size);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_FlushContext(FlushContext_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->flushHandle);
        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_FlushContext);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_StartAuthSession(StartAuthSession_In* in, StartAuthSession_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->tpmKey);
        TPM2_Packet_AppendU32(&packet, in->bind);
        TPM2_Packet_AppendU16(&packet, in->nonceCaller.size);
        TPM2_Packet_AppendBytes(&packet, in->nonceCaller.buffer,
            in->nonceCaller.size);
        TPM2_Packet_AppendU16(&packet, in->encryptedSalt.size);
        TPM2_Packet_AppendBytes(&packet, in->encryptedSalt.secret,
            in->encryptedSalt.size);
        TPM2_Packet_AppendU8(&packet, in->sessionType);
        TPM2_Packet_AppendSymmetric(&packet, &in->symmetric);
        TPM2_Packet_AppendU16(&packet, in->authHash);
        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS,
            TPM_CC_StartAuthSession);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            TPM2_Packet_ParseU32(&packet, &out->sessionHandle);
            TPM2_Packet_ParseU16(&packet, &out->nonceTPM.size);
            TPM2_Packet_ParseBytes(&packet, out->nonceTPM.buffer,
                out->nonceTPM.size);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_PolicyRestart(PolicyRestart_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->sessionHandle);
        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_PolicyRestart);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_LoadExternal(LoadExternal_In* in, LoadExternal_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();
    TPM_ST st;

    if (ctx == NULL || in == NULL || out == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        CmdInfo_t info = {0,0,0,0};
        info.outHandleCnt = 1;
        info.flags = (CMD_FLAG_ENC2 | CMD_FLAG_DEC2);

        TPM2_Packet_Init(ctx, &packet);

        st = TPM2_Packet_AppendAuth(&packet, ctx, &info);
        if (in->inPrivate.sensitiveArea.authValue.size > 0 ||
            in->inPrivate.sensitiveArea.seedValue.size > 0 ||
            in->inPrivate.sensitiveArea.sensitive.any.size > 0) {

            in->inPrivate.size = 2 + /* sensitiveType */
                2 + in->inPrivate.sensitiveArea.authValue.size +
                2 + in->inPrivate.sensitiveArea.seedValue.size +
                2 + in->inPrivate.sensitiveArea.sensitive.any.size;
            TPM2_Packet_AppendU16(&packet, in->inPrivate.size);

            TPM2_Packet_AppendU16(&packet,
                in->inPrivate.sensitiveArea.sensitiveType);
            TPM2_Packet_AppendU16(&packet,
                in->inPrivate.sensitiveArea.authValue.size);
            TPM2_Packet_AppendBytes(&packet,
                in->inPrivate.sensitiveArea.authValue.buffer,
                in->inPrivate.sensitiveArea.authValue.size);
            TPM2_Packet_AppendU16(&packet,
                in->inPrivate.sensitiveArea.seedValue.size);
            TPM2_Packet_AppendBytes(&packet,
                in->inPrivate.sensitiveArea.seedValue.buffer,
                in->inPrivate.sensitiveArea.seedValue.size);

            TPM2_Packet_AppendU16(&packet,
                in->inPrivate.sensitiveArea.sensitive.any.size);
            TPM2_Packet_AppendBytes(&packet,
                in->inPrivate.sensitiveArea.sensitive.any.buffer,
                in->inPrivate.sensitiveArea.sensitive.any.size);
        }
        else {
            TPM2_Packet_AppendU16(&packet, 0);
        }

        TPM2_Packet_AppendPublic(&packet, &in->inPublic);
        TPM2_Packet_AppendU32(&packet, in->hierarchy);
        TPM2_Packet_Finalize(&packet, st, TPM_CC_LoadExternal);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);
        if (rc == TPM_RC_SUCCESS) {
            UINT32 paramSz = 0;

            TPM2_Packet_ParseU32(&packet, &out->objectHandle);

            if (st == TPM_ST_SESSIONS) {
                TPM2_Packet_ParseU32(&packet, &paramSz);
            }

            TPM2_Packet_ParseU16(&packet, &out->name.size);
            TPM2_Packet_ParseBytes(&packet, out->name.name, out->name.size);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_ReadPublic(ReadPublic_In* in, ReadPublic_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->objectHandle);
        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_ReadPublic);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            TPM2_Packet_ParsePublic(&packet, &out->outPublic);

            TPM2_Packet_ParseU16(&packet, &out->name.size);
            TPM2_Packet_ParseBytes(&packet, out->name.name, out->name.size);

            TPM2_Packet_ParseU16(&packet, &out->qualifiedName.size);
            TPM2_Packet_ParseBytes(&packet, out->qualifiedName.name,
                out->qualifiedName.size);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}


TPM_RC TPM2_RSA_Encrypt(RSA_Encrypt_In* in, RSA_Encrypt_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();
    TPM_ST st;

    if (ctx == NULL || in == NULL || out == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        CmdInfo_t info = {0,0,0,0};
        info.inHandleCnt = 1;
        info.flags = (CMD_FLAG_ENC2 | CMD_FLAG_DEC2);

        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->keyHandle);

        st = TPM2_Packet_AppendAuth(&packet, ctx, &info);

        TPM2_Packet_AppendU16(&packet, in->message.size);
        TPM2_Packet_AppendBytes(&packet, in->message.buffer, in->message.size);

        TPM2_Packet_AppendU16(&packet, in->inScheme.scheme);
        if (in->inScheme.scheme != TPM_ALG_NULL &&
            in->inScheme.scheme != TPM_ALG_RSAES)
            TPM2_Packet_AppendU16(&packet, in->inScheme.details.anySig.hashAlg);

        TPM2_Packet_AppendU16(&packet, in->label.size);
        TPM2_Packet_AppendBytes(&packet, in->label.buffer, in->label.size);

        TPM2_Packet_Finalize(&packet, st, TPM_CC_RSA_Encrypt);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);
        if (rc == TPM_RC_SUCCESS) {
            UINT32 paramSz = 0;

            if (st == TPM_ST_SESSIONS) {
                TPM2_Packet_ParseU32(&packet, &paramSz);
            }

            TPM2_Packet_ParseU16(&packet, &out->outData.size);
            TPM2_Packet_ParseBytes(&packet, out->outData.buffer,
                out->outData.size);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_RSA_Decrypt(RSA_Decrypt_In* in, RSA_Decrypt_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL || ctx->session == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        CmdInfo_t info = {0,0,0,0};
        info.inHandleCnt = 1;
        info.flags = (CMD_FLAG_ENC2 | CMD_FLAG_DEC2 | CMD_FLAG_AUTH_USER1);

        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->keyHandle);

        TPM2_Packet_AppendAuth(&packet, ctx, &info);

        TPM2_Packet_AppendU16(&packet, in->cipherText.size);
        TPM2_Packet_AppendBytes(&packet, in->cipherText.buffer,
            in->cipherText.size);

        TPM2_Packet_AppendU16(&packet, in->inScheme.scheme);
        if (in->inScheme.scheme != TPM_ALG_NULL &&
            in->inScheme.scheme != TPM_ALG_RSAES)
            TPM2_Packet_AppendU16(&packet, in->inScheme.details.anySig.hashAlg);

        TPM2_Packet_AppendU16(&packet, in->label.size);
        TPM2_Packet_AppendBytes(&packet, in->label.buffer, in->label.size);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_RSA_Decrypt);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);
        if (rc == TPM_RC_SUCCESS) {
            UINT32 paramSz = 0;

            TPM2_Packet_ParseU32(&packet, &paramSz);

            TPM2_Packet_ParseU16(&packet, &out->message.size);
            TPM2_Packet_ParseBytes(&packet, out->message.buffer,
                out->message.size);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}


/* Deprecated version, use TPM2_EncryptDecrypt2 because it allows
    encryption of the input data */
TPM_RC TPM2_EncryptDecrypt(EncryptDecrypt_In* in, EncryptDecrypt_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL || ctx->session == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        CmdInfo_t info = {0,0,0,0};
        info.inHandleCnt = 1;
        info.flags = (CMD_FLAG_DEC2 | CMD_FLAG_AUTH_USER1);

        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->keyHandle);
        TPM2_Packet_AppendAuth(&packet, ctx, &info);

        TPM2_Packet_AppendU8(&packet, in->decrypt);
        TPM2_Packet_AppendU16(&packet, in->mode);

        TPM2_Packet_AppendU16(&packet, in->ivIn.size);
        TPM2_Packet_AppendBytes(&packet, in->ivIn.buffer, in->ivIn.size);

        TPM2_Packet_AppendU16(&packet, in->inData.size);
        TPM2_Packet_AppendBytes(&packet, in->inData.buffer, in->inData.size);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_EncryptDecrypt);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);
        if (rc == TPM_RC_SUCCESS) {
            UINT32 paramSz = 0;

            TPM2_Packet_ParseU32(&packet, &paramSz);

            TPM2_Packet_ParseU16(&packet, &out->outData.size);
            TPM2_Packet_ParseBytes(&packet, out->outData.buffer,
                out->outData.size);

            TPM2_Packet_ParseU16(&packet, &out->ivOut.size);
            TPM2_Packet_ParseBytes(&packet, out->ivOut.buffer, out->ivOut.size);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_EncryptDecrypt2(EncryptDecrypt2_In* in, EncryptDecrypt2_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL || ctx->session == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        CmdInfo_t info = {0,0,0,0};
        info.inHandleCnt = 1;
        info.flags = (CMD_FLAG_ENC2 | CMD_FLAG_DEC2 | CMD_FLAG_AUTH_USER1);

        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->keyHandle);
        TPM2_Packet_AppendAuth(&packet, ctx, &info);

        TPM2_Packet_AppendU16(&packet, in->inData.size);
        TPM2_Packet_AppendBytes(&packet, in->inData.buffer, in->inData.size);

        TPM2_Packet_AppendU8(&packet, in->decrypt);
        TPM2_Packet_AppendU16(&packet, in->mode);

        TPM2_Packet_AppendU16(&packet, in->ivIn.size);
        TPM2_Packet_AppendBytes(&packet, in->ivIn.buffer, in->ivIn.size);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_EncryptDecrypt2);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);
        if (rc == TPM_RC_SUCCESS) {
            UINT32 paramSz = 0;

            TPM2_Packet_ParseU32(&packet, &paramSz);

            TPM2_Packet_ParseU16(&packet, &out->outData.size);
            TPM2_Packet_ParseBytes(&packet, out->outData.buffer,
                out->outData.size);

            TPM2_Packet_ParseU16(&packet, &out->ivOut.size);
            TPM2_Packet_ParseBytes(&packet, out->ivOut.buffer, out->ivOut.size);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_Hash(Hash_In* in, Hash_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();
    TPM_ST st;

    if (ctx == NULL || in == NULL || out == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        CmdInfo_t info = {0,0,0,0};
        info.flags = (CMD_FLAG_ENC2 | CMD_FLAG_DEC2);

        TPM2_Packet_Init(ctx, &packet);

        st = TPM2_Packet_AppendAuth(&packet, ctx, &info);

        TPM2_Packet_AppendU16(&packet, in->data.size);
        TPM2_Packet_AppendBytes(&packet, in->data.buffer, in->data.size);

        TPM2_Packet_AppendU16(&packet, in->hashAlg);
        TPM2_Packet_AppendU32(&packet, in->hierarchy);

        TPM2_Packet_Finalize(&packet, st, TPM_CC_Hash);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);
        if (rc == TPM_RC_SUCCESS) {
            UINT32 paramSz = 0;

            if (st == TPM_ST_SESSIONS) {
                TPM2_Packet_ParseU32(&packet, &paramSz);
            }

            TPM2_Packet_ParseU16(&packet, &out->outHash.size);
            TPM2_Packet_ParseBytes(&packet, out->outHash.buffer,
                out->outHash.size);

            TPM2_Packet_ParseU16(&packet, &out->validation.tag);
            TPM2_Packet_ParseU32(&packet, &out->validation.hierarchy);

            TPM2_Packet_ParseU16(&packet, &out->validation.digest.size);
            TPM2_Packet_ParseBytes(&packet, out->validation.digest.buffer,
                out->validation.digest.size);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_HashSequenceStart(HashSequenceStart_In* in,
    HashSequenceStart_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();
    TPM_ST st;

    if (ctx == NULL || in == NULL || out == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        CmdInfo_t info = {0,0,0,0};
        info.outHandleCnt = 1;
        info.flags = (CMD_FLAG_ENC2);

        TPM2_Packet_Init(ctx, &packet);

        st = TPM2_Packet_AppendAuth(&packet, ctx, &info);

        TPM2_Packet_AppendU16(&packet, in->auth.size);
        TPM2_Packet_AppendBytes(&packet, in->auth.buffer, in->auth.size);

        TPM2_Packet_AppendU16(&packet, in->hashAlg);

        TPM2_Packet_Finalize(&packet, st, TPM_CC_HashSequenceStart);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);
        if (rc == TPM_RC_SUCCESS) {
            TPM2_Packet_ParseU32(&packet, &out->sequenceHandle);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}
TPM_RC TPM2_SequenceUpdate(SequenceUpdate_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || ctx->session == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        CmdInfo_t info = {0,0,0,0};
        info.inHandleCnt = 1;
        info.flags = (CMD_FLAG_ENC2 | CMD_FLAG_AUTH_USER1);

        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->sequenceHandle);
        TPM2_Packet_AppendAuth(&packet, ctx, &info);

        TPM2_Packet_AppendU16(&packet, in->buffer.size);
        TPM2_Packet_AppendBytes(&packet, in->buffer.buffer, in->buffer.size);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_SequenceUpdate);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_SequenceComplete(SequenceComplete_In* in, SequenceComplete_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL || ctx->session == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        CmdInfo_t info = {0,0,0,0};
        info.inHandleCnt = 1;
        info.flags = (CMD_FLAG_ENC2 | CMD_FLAG_DEC2 | CMD_FLAG_AUTH_USER1);

        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->sequenceHandle);
        TPM2_Packet_AppendAuth(&packet, ctx, &info);

        TPM2_Packet_AppendU16(&packet, in->buffer.size);
        TPM2_Packet_AppendBytes(&packet, in->buffer.buffer, in->buffer.size);

        TPM2_Packet_AppendU32(&packet, in->hierarchy);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_SequenceComplete);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);
        if (rc == TPM_RC_SUCCESS) {
            UINT32 paramSz = 0;

            TPM2_Packet_ParseU32(&packet, &paramSz);

            TPM2_Packet_ParseU16(&packet, &out->result.size);
            TPM2_Packet_ParseBytes(&packet, out->result.buffer,
                out->result.size);

            TPM2_Packet_ParseU16(&packet, &out->validation.tag);
            TPM2_Packet_ParseU32(&packet, &out->validation.hierarchy);

            TPM2_Packet_ParseU16(&packet, &out->validation.digest.size);
            TPM2_Packet_ParseBytes(&packet, out->validation.digest.buffer,
                out->validation.digest.size);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_PCR_Reset(PCR_Reset_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || ctx->session == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        CmdInfo_t info = {0,0,0,0};
        info.inHandleCnt = 1;
        info.flags = (CMD_FLAG_AUTH_USER1);

        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->pcrHandle);
        TPM2_Packet_AppendAuth(&packet, ctx, &info);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_PCR_Reset);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}


TPM_RC TPM2_PolicyPCR(PolicyPCR_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();
    TPM_ST st;

    if (ctx == NULL || in == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        CmdInfo_t info = {0,0,0,0};
        info.inHandleCnt = 1;
        info.flags = (CMD_FLAG_ENC2);

        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->policySession);

        st = TPM2_Packet_AppendAuth(&packet, ctx, &info);

        TPM2_Packet_AppendU16(&packet, in->pcrDigest.size);
        TPM2_Packet_AppendBytes(&packet, in->pcrDigest.buffer,
            in->pcrDigest.size);

        TPM2_Packet_AppendPCR(&packet, &in->pcrs);

        TPM2_Packet_Finalize(&packet, st, TPM_CC_PolicyPCR);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}



TPM_RC TPM2_NV_ReadPublic(NV_ReadPublic_In* in, NV_ReadPublic_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();
    TPM_ST st;

    if (ctx == NULL || in == NULL || out == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        CmdInfo_t info = {0,0,0,0};
        info.inHandleCnt = 1;
        info.flags = (CMD_FLAG_DEC2);

        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->nvIndex);
        st = TPM2_Packet_AppendAuth(&packet, ctx, &info);

        TPM2_Packet_Finalize(&packet, st, TPM_CC_NV_ReadPublic);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);
        if (rc == TPM_RC_SUCCESS) {
            UINT32 paramSz = 0;

            if (st == TPM_ST_SESSIONS) {
                TPM2_Packet_ParseU32(&packet, &paramSz);
            }

            TPM2_Packet_ParseU16(&packet, &out->nvPublic.size);
            TPM2_Packet_ParseU32(&packet, &out->nvPublic.nvPublic.nvIndex);
            TPM2_Packet_ParseU16(&packet, &out->nvPublic.nvPublic.nameAlg);
            TPM2_Packet_ParseU32(&packet, &out->nvPublic.nvPublic.attributes);

            TPM2_Packet_ParseU16(&packet,
                &out->nvPublic.nvPublic.authPolicy.size);
            TPM2_Packet_ParseBytes(&packet,
                out->nvPublic.nvPublic.authPolicy.buffer,
                out->nvPublic.nvPublic.authPolicy.size);

            TPM2_Packet_ParseU16(&packet, &out->nvPublic.nvPublic.dataSize);

            TPM2_Packet_ParseU16(&packet, &out->nvName.size);
            TPM2_Packet_ParseBytes(&packet, out->nvName.name, out->nvName.size);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}


TPM_RC TPM2_NV_Extend(NV_Extend_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || ctx->session == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        CmdInfo_t info = {0,0,0,0};
        info.inHandleCnt = 2;
        info.flags = (CMD_FLAG_ENC2 | CMD_FLAG_AUTH_USER1);

        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->authHandle);
        /* When using an HMAC or Policy session make sure the NV "name" is
         * populated in the TPM2_AUTH_SESSION name.name. This is a computed
         * hash (see TPM2_HashNvPublic) */
        TPM2_Packet_AppendU32(&packet, in->nvIndex);
        TPM2_Packet_AppendAuth(&packet, ctx, &info);

        TPM2_Packet_AppendU16(&packet, in->data.size);
        TPM2_Packet_AppendBytes(&packet, in->data.buffer, in->data.size);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_NV_Extend);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}


TPM_RC TPM2_NV_Read(NV_Read_In* in, NV_Read_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL || ctx->session == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        CmdInfo_t info = {0,0,0,0};
        info.inHandleCnt = 2;
        info.flags = (CMD_FLAG_DEC2 | CMD_FLAG_AUTH_USER1);

        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendU32(&packet, in->nvIndex);
        TPM2_Packet_AppendAuth(&packet, ctx, &info);

        TPM2_Packet_AppendU16(&packet, in->size);
        TPM2_Packet_AppendU16(&packet, in->offset);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_NV_Read);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);
        if (rc == TPM_RC_SUCCESS) {
            UINT32 paramSz = 0;

            TPM2_Packet_ParseU32(&packet, &paramSz);

            TPM2_Packet_ParseU16(&packet, &out->data.size);
            TPM2_Packet_ParseBytes(&packet, out->data.buffer, out->data.size);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}
/******************************************************************************/
/* --- END Standard TPM API's -- */
/******************************************************************************/


/******************************************************************************/
/* --- BEGIN Manufacture Specific TPM API's -- */
/******************************************************************************/
int TPM2_SetCommandSet(SetCommandSet_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || ctx->session == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        CmdInfo_t info = {0,0,0,0};
        info.inHandleCnt = 1;
        info.flags = (CMD_FLAG_AUTH_USER1);

        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendAuth(&packet, ctx, &info);
        TPM2_Packet_AppendU32(&packet, in->commandCode);
        TPM2_Packet_AppendU32(&packet, in->enableFlag);
        TPM2_Packet_AppendU32(&packet, in->lockFlag);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_SetCommandSet);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

int TPM2_SetMode(SetMode_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || ctx->session == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        CmdInfo_t info = {0,0,0,0};
        info.inHandleCnt = 1;
        info.flags = (CMD_FLAG_AUTH_USER1);

        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendAuth(&packet, ctx, &info);
        TPM2_Packet_AppendU8(&packet, in->modeSet.CmdToLowPower);
        TPM2_Packet_AppendU8(&packet, in->modeSet.BootToLowPower);
        TPM2_Packet_AppendU8(&packet, in->modeSet.modeLock);
        TPM2_Packet_AppendU8(&packet, in->modeSet.mode);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_SetMode);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_GetRandom2(GetRandom2_In* in, GetRandom2_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU16(&packet, in->bytesRequested);
        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_GetRandom2);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            TPM2_Packet_ParseU16(&packet, &out->randomBytes.size);
            TPM2_Packet_ParseBytes(&packet, out->randomBytes.buffer,
                out->randomBytes.size);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_GetProductInfo(uint8_t* info, uint16_t size)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || info == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, TPM_CAP_VENDOR_PROPERTY);
        TPM2_Packet_AppendU32(&packet, 3); /* cTPM_SUBCAP_VENDOR_GET_PRODUCT_INFO */
        TPM2_Packet_AppendU32(&packet, 1); /* only 1 property */
        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_GetCapability);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            /* Product info is:
             * Serial Number (7 bytes)
             * Pad (1 byte)
             * Product ID (PIN) (2 bytes)
             * Master Product ID (MPIN) (2 bytes)
             * Product Internal Revision (1 byte)
             * Pad (3 bytes)
             * Firmware kernel version (4 bytes)
             */

            /* start of product info starts at byte 26 */
            if (size > packet.size - 26)
                size = packet.size - 26;
            XMEMCPY(info, &packet.buf[25], size);
        }
    }
    return rc;
}



/******************************************************************************/
/* --- BEGIN Helpful API's -- */
/******************************************************************************/

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

/* Can optionally define WOLFTPM2_USE_HW_RNG to force using TPM hardware for
 * RNG source */
int TPM2_GetNonce(byte* nonceBuf, int nonceSz)
{
    int rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();
#ifdef WOLFTPM2_USE_WOLF_RNG
    WC_RNG* rng = NULL;
#else
    TPM2_Packet packet;
    byte buffer[TPM2_HEADER_SIZE + sizeof(GetRandom_Out)];
    int randSz = 0;
#endif

    if (ctx == NULL || nonceBuf == NULL) {
        return BAD_FUNC_ARG;
    }


#ifdef WOLFTPM2_USE_WOLF_RNG
#else
    /* Call GetRandom directly, so a custom packet buffer can be used.
     * This won't conflict when being called from TPM2_CommandProcess. */
    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        while (randSz < nonceSz) {
            UINT16 inSz = nonceSz - randSz, outSz = 0;
            if (inSz > MAX_RNG_REQ_SIZE) {
                inSz = MAX_RNG_REQ_SIZE;
            }

            TPM2_Packet_InitBuf(&packet, buffer, (int)sizeof(buffer));
            TPM2_Packet_AppendU16(&packet, inSz);
            TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_GetRandom);
            rc = TPM2_SendCommand(ctx, &packet);
            if (rc != TPM_RC_SUCCESS) {
                break;
            }

            TPM2_Packet_ParseU16(&packet, &outSz);
            if (outSz > MAX_RNG_REQ_SIZE) {
                rc = BAD_FUNC_ARG;
                break;
            }
            TPM2_Packet_ParseBytes(&packet, &nonceBuf[randSz], outSz);
            randSz += outSz;
        }
        TPM2_ReleaseLock(ctx);
    }
#endif
    return rc;
}

/* Caller must zeroize/memset(0) pcr (TPML_PCR_SELECTION) */
void TPM2_SetupPCRSel(TPML_PCR_SELECTION* pcr, TPM_ALG_ID alg, int pcrIndex)
{
    int i = 0;

    if (pcr && pcrIndex >= (int)PCR_FIRST && pcrIndex <= (int)PCR_LAST) {
        /* if we have no banks in use, use the 0th one */
        if (pcr->count == 0) {
            pcr->count = 1;
        }
        else {
            /* iterate over all banks until the alg matches */
            for (i = 0; (word32)i < pcr->count; i++) {
                if (pcr->pcrSelections[i].hash == alg)
                    break;
            }

            /* if no match increase the number of banks */
            if ((word32)i >= pcr->count) {
                if (pcr->count + 1 > HASH_COUNT) {
                    return;
                }
                pcr->count++;
            }
        }

        pcr->pcrSelections[i].hash = alg;
        pcr->pcrSelections[i].sizeofSelect = PCR_SELECT_MAX;
        pcr->pcrSelections[i].pcrSelect[pcrIndex >> 3] |=
            (1 << (pcrIndex & 0x7));
    }
}

/* Caller must zeroize/memset(0) pcr (TPML_PCR_SELECTION) */
void TPM2_SetupPCRSelArray(TPML_PCR_SELECTION* pcr, TPM_ALG_ID alg,
    byte* pcrArray, word32 pcrArraySz)
{
    int i;
    for (i = 0; i < (int)pcrArraySz; i++) {
        TPM2_SetupPCRSel(pcr, alg, (int)pcrArray[i]);
    }
}


#define TPM_RC_STRINGIFY(rc) #rc
    #define TPM_RC_STR(rc, desc) case rc: return TPM_RC_STRINGIFY(rc)

const char* TPM2_GetRCString(int rc)
{
    /* for negative return codes use wolfCrypt */
    if (rc < 0) {
        switch (rc) {
            TPM_RC_STR(TPM_RC_TIMEOUT,           "Hardware timeout");
            default:
                break;
        }
        switch (rc) {
            /* copy of the error code strings from wolfCrypt */
            TPM_RC_STR(BAD_FUNC_ARG,             "Bad function argument");
            TPM_RC_STR(BUFFER_E,                 "Buffer error, output too small or input too big");
            TPM_RC_STR(NOT_COMPILED_IN,          "Feature not compiled in");
            TPM_RC_STR(BAD_MUTEX_E,              "Bad mutex, operation failed");
            TPM_RC_STR(MEMORY_E,                 "Out of memory error");
            TPM_RC_STR(LENGTH_ONLY_E,            "Output length only set, not for other use error");
            TPM_RC_STR(WC_TIMEOUT_E,             "Timeout error");

            default:
                break;
        }
    }
    else if (rc == TPM_RC_SUCCESS) {
        return "Success";
    }

    if ((rc & RC_WARN) == RC_WARN && (rc & RC_FMT1) == 0) {
        int rc_warn = rc & RC_MAX_WARN;

        switch (rc_warn) {
            TPM_RC_STR(TPM_RC_CONTEXT_GAP,       "Gap for context ID is too large");
            TPM_RC_STR(TPM_RC_OBJECT_MEMORY,     "Out of memory for object contexts");
            TPM_RC_STR(TPM_RC_SESSION_MEMORY,    "Out of memory for session contexts");
            TPM_RC_STR(TPM_RC_MEMORY,            "Out of shared object/session memory or need space for internal operations");
            TPM_RC_STR(TPM_RC_SESSION_HANDLES,   "Out of session handles; a session must be flushed before a new session may be created");
            TPM_RC_STR(TPM_RC_OBJECT_HANDLES,    "Out of object handles");
            TPM_RC_STR(TPM_RC_LOCALITY,          "Bad locality");
            TPM_RC_STR(TPM_RC_YIELDED,           "The TPM has suspended operation on the command");
            TPM_RC_STR(TPM_RC_CANCELED,          "The command was canceled");
            TPM_RC_STR(TPM_RC_TESTING,           "TPM is performing self-tests");
            TPM_RC_STR(TPM_RC_NV_RATE,           "The TPM is rate-limiting accesses to prevent wearout of NV");
            TPM_RC_STR(TPM_RC_LOCKOUT,           "Authorizations for objects subject to DA protection are not allowed at "
                                                    "this time because the TPM is in DA lockout mode");
            TPM_RC_STR(TPM_RC_RETRY,             "The TPM was not able to start the command");
            TPM_RC_STR(TPM_RC_NV_UNAVAILABLE,    "The command may require writing of NV and NV is not current accessible");
            TPM_RC_STR(TPM_RC_NOT_USED,          "This value is reserved and shall not be returned by the TPM");
        default:
            break;
        }
    }

    else if ((rc & RC_VER1) && (rc & RC_FMT1) == 0) {
        int rc_fm0 = rc & RC_MAX_FM0;

        switch (rc_fm0) {
            TPM_RC_STR(TPM_RC_BAD_TAG,           "Bad Tag");
            TPM_RC_STR(TPM_RC_INITIALIZE,        "TPM not initialized by TPM2_Startup or already initialized");
            TPM_RC_STR(TPM_RC_FAILURE,           "Commands not being accepted because of a TPM failure");
            TPM_RC_STR(TPM_RC_SEQUENCE,          "Improper use of a sequence handle");
            TPM_RC_STR(TPM_RC_DISABLED,          "The command is disabled");
            TPM_RC_STR(TPM_RC_EXCLUSIVE,         "Command failed because audit sequence required exclusivity");
            TPM_RC_STR(TPM_RC_AUTH_TYPE,         "Authorization handle is not correct for command");
            TPM_RC_STR(TPM_RC_AUTH_MISSING,      "Command requires an authorization session for handle and it is not present");
            TPM_RC_STR(TPM_RC_POLICY,            "Policy failure in math operation or an invalid authPolicy value");
            TPM_RC_STR(TPM_RC_PCR,               "PCR check fail");
            TPM_RC_STR(TPM_RC_PCR_CHANGED,       "PCR have changed since checked");
            TPM_RC_STR(TPM_RC_UPGRADE,           "Indicates that the TPM is in field upgrade mode");
            TPM_RC_STR(TPM_RC_TOO_MANY_CONTEXTS, "Context ID counter is at maximum");
            TPM_RC_STR(TPM_RC_AUTH_UNAVAILABLE,  "The authValue or authPolicy is not available for selected entity");
            TPM_RC_STR(TPM_RC_REBOOT,            "A _TPM_Init and Startup(CLEAR) is required before the TPM can resume operation");
            TPM_RC_STR(TPM_RC_UNBALANCED,        "The protection algorithms (hash and symmetric) are not reasonably balanced");
            TPM_RC_STR(TPM_RC_COMMAND_SIZE,      "Command commandSize value is inconsistent with contents of the command buffer");
            TPM_RC_STR(TPM_RC_COMMAND_CODE,      "Command code not supported");
            TPM_RC_STR(TPM_RC_AUTHSIZE,          "The value of authorizationSize is out of range or the number of octets "
                                                    "in the Authorization Area is greater than required");
            TPM_RC_STR(TPM_RC_AUTH_CONTEXT,      "Use of an authorization session with a context command or another command "
                                                    "that cannot have an authorization session");
            TPM_RC_STR(TPM_RC_NV_RANGE,          "NV offset+size is out of range");
            TPM_RC_STR(TPM_RC_NV_SIZE,           "Requested allocation size is larger than allowed");
            TPM_RC_STR(TPM_RC_NV_LOCKED,         "NV access locked");
            TPM_RC_STR(TPM_RC_NV_AUTHORIZATION,  "NV access authorization fails in command actions");
            TPM_RC_STR(TPM_RC_NV_UNINITIALIZED,  "An NV Index is used before being initialized or the state saved by "
                                                    "TPM2_Shutdown(STATE) could not be restored");
            TPM_RC_STR(TPM_RC_NV_SPACE,          "Insufficient space for NV allocation");
            TPM_RC_STR(TPM_RC_NV_DEFINED,        "NV Index or persistent object already defined");
            TPM_RC_STR(TPM_RC_BAD_CONTEXT,       "Context in TPM2_ContextLoad() is not valid");
            TPM_RC_STR(TPM_RC_CPHASH,            "The cpHash value already set or not correct for use");
            TPM_RC_STR(TPM_RC_PARENT,            "Handle for parent is not a valid parent");
            TPM_RC_STR(TPM_RC_NEEDS_TEST,        "Some function needs testing");
            TPM_RC_STR(TPM_RC_NO_RESULT,         "Cannot process a request due to an unspecified problem");
            TPM_RC_STR(TPM_RC_SENSITIVE,         "The sensitive area did not unmarshal correctly after decryption");
        default:
            break;
        }
    }

    /* Format-One Response Codes */
    else if (rc & RC_FMT1) {
        int rc_fmt1 = rc & RC_MAX_FMT1;

        /* Bits:
         *   0-5: Error Number
         *     6: 1=Parameter Number, 0=Session or Handle
         *     7: Format selector
         *  8-11: Number of handle, session or parameter
         *    11: 1=Handle
         */
        if (rc & 0x40) { /* bit 6 */
            /* bits 8-11 */
            int param_num = (rc & 0xF00) >> 8;
            (void)param_num;
        }
        else if (rc & 0x800) { /* bit 11 */
            /* bits 8-10 */
            int session_num = (rc & 0x700) >> 8;
            (void)session_num;
        }
        else {
            /* bits 8-10 */
            int handle_num = (rc & 0x700) >> 8;
            (void)handle_num;
        }

        switch (rc_fmt1) {
            TPM_RC_STR(TPM_RC_ASYMMETRIC,        "Asymmetric algorithm not supported or not correct");
            TPM_RC_STR(TPM_RC_ATTRIBUTES,        "Inconsistent attributes");
            TPM_RC_STR(TPM_RC_HASH,              "Hash algorithm not supported or not appropriate");
            TPM_RC_STR(TPM_RC_VALUE,             "Value is out of range or is not correct for the context");
            TPM_RC_STR(TPM_RC_HIERARCHY,         "Hierarchy is not enabled or is not correct for the use");
            TPM_RC_STR(TPM_RC_KEY_SIZE,          "Key size is not supported");
            TPM_RC_STR(TPM_RC_MGF,               "Mask generation function not supported");
            TPM_RC_STR(TPM_RC_MODE,              "Mode of operation not supported");
            TPM_RC_STR(TPM_RC_TYPE,              "The type of the value is not appropriate for the use");
            TPM_RC_STR(TPM_RC_HANDLE,            "The handle is not correct for the use");
            TPM_RC_STR(TPM_RC_KDF,               "Unsupported key derivation function or function not appropriate for use");
            TPM_RC_STR(TPM_RC_RANGE,             "Value was out of allowed range");
            TPM_RC_STR(TPM_RC_AUTH_FAIL,         "The authorization HMAC check failed and DA counter incremented");
            TPM_RC_STR(TPM_RC_NONCE,             "Invalid nonce size or nonce value mismatch");
            TPM_RC_STR(TPM_RC_PP,                "Authorization requires assertion of PP");
            TPM_RC_STR(TPM_RC_SCHEME,            "Unsupported or incompatible scheme");
            TPM_RC_STR(TPM_RC_SIZE,              "Structure is the wrong size");
            TPM_RC_STR(TPM_RC_SYMMETRIC,         "Unsupported symmetric algorithm or key size, or not appropriate for instance");
            TPM_RC_STR(TPM_RC_TAG,               "Incorrect structure tag");
            TPM_RC_STR(TPM_RC_SELECTOR,          "Union selector is incorrect");
            TPM_RC_STR(TPM_RC_INSUFFICIENT,      "The TPM was unable to unmarshal a value because there were not enough "
                                                    "octets in the input buffer");
            TPM_RC_STR(TPM_RC_SIGNATURE,         "The signature is not valid");
            TPM_RC_STR(TPM_RC_KEY,               "Key fields are not compatible with the selected use");
            TPM_RC_STR(TPM_RC_POLICY_FAIL,       "A policy check failed");
            TPM_RC_STR(TPM_RC_INTEGRITY,         "Integrity check failed");
            TPM_RC_STR(TPM_RC_TICKET,            "Invalid ticket");
            TPM_RC_STR(TPM_RC_RESERVED_BITS,     "Reserved bits not set to zero as required");
            TPM_RC_STR(TPM_RC_BAD_AUTH,          "Authorization failure without DA implications");
            TPM_RC_STR(TPM_RC_EXPIRED,           "The policy has expired");
            TPM_RC_STR(TPM_RC_POLICY_CC,         "The commandCode in the policy is not the commandCode of the command or "
                                                    "the command code in a policy command references a command that is "
                                                    "not implemented");
            TPM_RC_STR(TPM_RC_BINDING,           "Public and sensitive portions of an object are not cryptographically bound");
            TPM_RC_STR(TPM_RC_CURVE,             "Curve not supported");
            TPM_RC_STR(TPM_RC_ECC_POINT,         "Point is not on the required curve");
        default:
            break;
        }
    }

    else if (rc & 0x400) { /* bit 10 */
        return "Vendor defined response code";
    }

    return "Unknown";
}

const char* TPM2_GetAlgName(TPM_ALG_ID alg)
{
    switch (alg) {
        case TPM_ALG_RSA:
            return "RSA";
        case TPM_ALG_SHA1:
            return "SHA1";
        case TPM_ALG_HMAC:
            return "HMAC";
        case TPM_ALG_AES:
            return "AES";
        case TPM_ALG_MGF1:
            return "MGF1";
        case TPM_ALG_KEYEDHASH:
            return "KEYEDHASH";
        case TPM_ALG_XOR:
            return "XOR";
        case TPM_ALG_SHA256:
            return "SHA256";
        case TPM_ALG_SHA384:
            return "SHA384";
        case TPM_ALG_SHA512:
            return "SHA512";
        case TPM_ALG_NULL:
            return "NULL";
        case TPM_ALG_SM3_256:
            return "SM3_256";
        case TPM_ALG_SM4:
            return "SM4";
        case TPM_ALG_RSASSA:
            return "RSASSA";
        case TPM_ALG_RSAES:
            return "RSAES";
        case TPM_ALG_RSAPSS:
            return "RSAPSS";
        case TPM_ALG_OAEP:
            return "OAEP";
        case TPM_ALG_ECDSA:
            return "ECDSA";
        case TPM_ALG_ECDH:
            return "ECDH";
        case TPM_ALG_ECDAA:
            return "ECDAA";
        case TPM_ALG_SM2:
            return "SM2";
        case TPM_ALG_ECSCHNORR:
            return "ECSCHNORR";
        case TPM_ALG_ECMQV:
            return "ECMQV";
        case TPM_ALG_KDF1_SP800_56A:
            return "KDF1_SP800_56A";
        case TPM_ALG_KDF2:
            return "KDF2";
        case TPM_ALG_KDF1_SP800_108:
            return "KDF1_SP800_108";
        case TPM_ALG_ECC:
            return "ECC";
        case TPM_ALG_SYMCIPHER:
            return "SYMCIPHER";
        case TPM_ALG_CTR:
            return "AES-CTR";
        case TPM_ALG_OFB:
            return "AES-OFB";
        case TPM_ALG_CBC:
            return "AES-CBC";
        case TPM_ALG_CFB:
            return "AES-CFB";
        case TPM_ALG_ECB:
            return "AES-ECB";
        default:
            break;
    }
    return "Unknown";
}

int TPM2_GetCurveSize(TPM_ECC_CURVE curveID)
{
    switch (curveID) {
        case TPM_ECC_NIST_P192:
            return 24;
        case TPM_ECC_NIST_P224:
            return 28;
        case TPM_ECC_NIST_P256:
        case TPM_ECC_BN_P256:
        case TPM_ECC_SM2_P256:
            return 32;
        case TPM_ECC_NIST_P384:
            return 48;
        case TPM_ECC_NIST_P521:
            return 66;
        case TPM_ECC_BN_P638:
            return 80;
    }
    return 0;
}

int TPM2_GetTpmCurve(int curve_id)
{
    int ret = -1;
    (void)curve_id;
    return ret;
}

int TPM2_GetWolfCurve(int curve_id)
{
    int ret = -1;
    (void)curve_id;
    return ret;
}

UINT16 TPM2_GetVendorID(void)
{
    UINT16 vid = 0;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();
    if (ctx) {
        vid = (UINT16)(ctx->did_vid & 0xFFFF);
    }
    return vid;
}
/* This routine fills the first len bytes of the memory area pointed by mem
   with zeros. It ensures compiler optimizations doesn't skip it  */
void TPM2_ForceZero(void* mem, word32 len)
{
    volatile byte* z = (volatile byte*)mem;
    while (len--) *z++ = 0;
}


/******************************************************************************/
/* --- END Helpful API's -- */
/******************************************************************************/
