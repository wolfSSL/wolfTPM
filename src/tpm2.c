/* tpm2.c
 *
 * Copyright (C) 2006-2019 wolfSSL Inc.
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


#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_packet.h>
#include <wolftpm/tpm2_tis.h>

/******************************************************************************/
/* --- Local Variables -- */
/******************************************************************************/

static TPM2_CTX* gActiveTPM;
#ifndef WOLFTPM2_NO_WOLFCRYPT
static volatile int gWolfCryptRefCount = 0;
#endif

/******************************************************************************/
/* --- Local Functions -- */
/******************************************************************************/
static TPM_RC TPM2_AcquireLock(TPM2_CTX* ctx)
{
#if defined(WOLFTPM2_NO_WOLFCRYPT) || defined(SINGLE_THREADED)
    (void)ctx;
#else
    int ret;

    if (!ctx->hwLockInit) {
        if (wc_InitMutex(&ctx->hwLock) != 0) {
            WOLFSSL_MSG("TPM Mutex Init failed");
            return TPM_RC_FAILURE;
        }
        ctx->hwLockInit = 1;
    }

    ret = wc_LockMutex(&ctx->hwLock);
    if (ret != 0)
        return TPM_RC_FAILURE;
#endif
    return TPM_RC_SUCCESS;
}

static void TPM2_ReleaseLock(TPM2_CTX* ctx)
{
#if defined(WOLFTPM2_NO_WOLFCRYPT) || defined(SINGLE_THREADED)
    (void)ctx;
#else
    wc_UnLockMutex(&ctx->hwLock);
#endif
}


static int TPM2_Parameter_EncryptDecrypt(int modeMask,
    TPMT_SYM_DEF* symmetric, TPMI_ALG_HASH authHash,
    const BYTE* keyBuf, int keySz,
    const BYTE* nonceBuf, int nonceSz,
    BYTE* dataBuf, int dataSz)
{
    /* TODO: Perform symmetric encrypt or decrypt */
    if (modeMask & TPMA_SESSION_encrypt) {
        /* encrypt */
    }
    else {
        /* decrypt */
    }

    (void)symmetric;
    (void)authHash;
    (void)keyBuf;
    (void)keySz;
    (void)nonceBuf;
    (void)nonceSz;
    (void)dataBuf;
    (void)dataSz;

    return 0;
}

/* Send Command Wrapper */
static TPM_RC TPM2_SendCommandAuth(TPM2_CTX* ctx, TPM2_Packet* packet,
    int authCnt, int inHandleCnt, int outHandleCnt)
{
    TPM_RC rc = TPM_RC_FAILURE;
    TPMS_AUTH_COMMAND* auth;
    TPM_ST* tag;
    TPM2B_SYM_KEY key;
    BYTE *cmd, *param;
    UINT32 cmdSz, paramSz;
    int i;

    if (ctx == NULL || packet == NULL)
        return BAD_FUNC_ARG;

    cmd = packet->buf;
    cmdSz = packet->pos;
    tag = (TPM_ST*)cmd;

    if (*tag == TPM_ST_SESSIONS && (authCnt < 1 || ctx->authCmd == NULL))
        return TPM_RC_AUTH_MISSING;

    /* parameter encryption */
    if (*tag == TPM_ST_SESSIONS) {
        param = cmd + TPM2_HEADER_SIZE + (inHandleCnt * sizeof(TPM_HANDLE));

        paramSz = *(UINT32*)param;
        param += sizeof(UINT32); /* skip the param size */

        for (i=0; i<authCnt; i++) {
            auth = &ctx->authCmd[i];

            /* check if encrypting parameters */
            if (auth->sessionAttributes & TPMA_SESSION_decrypt) {
                /* get new nonce if required */
                if (ctx->authCmd->sessionHandle !=
                                            TPM_RS_PW && auth->nonce.size > 0) {
                    rc = TPM2_GetNonce(auth->nonce.buffer, auth->nonce.size);
                    if (rc != 0)
                        return rc;
                }

                /* build key */
                XMEMCPY(key.buffer, auth->auth.buffer, auth->auth.size);
                key.size = auth->auth.size;

                /* check for object handle auth and append to key */
                if (i < inHandleCnt) {
                    TPM_HANDLE* objHandle = (TPM_HANDLE*)(cmd +
                        TPM2_HEADER_SIZE + (i * sizeof(TPM_HANDLE)));
                    if (*objHandle == auth->objHandle) {
                        /* append to key */
                        XMEMCPY(key.buffer + key.size, auth->objAuth.buffer,
                            auth->objAuth.size);
                        key.size += auth->objAuth.size;
                    }
                }

                /* perform parameter encryption (inline) */
                rc = TPM2_Parameter_EncryptDecrypt(TPMA_SESSION_encrypt,
                    &auth->symmetric,
                    auth->authHash,
                    key.buffer, key.size,
                    auth->nonce.buffer, auth->nonce.size,
                    param, paramSz);
                if (rc != 0)
                    return rc;
            }
        }
    }

    /* submit command and wait for response */
    rc = (TPM_RC)TPM2_TIS_SendCommand(ctx, cmd, cmdSz);

    /* parse response */
    rc = TPM2_Packet_Parse(rc, packet);

    /* parameter decryption */
    if (rc == TPM_RC_SUCCESS && *tag == TPM_ST_SESSIONS) {
        TPMS_AUTH_RESPONSE authResp;
        TPM2_Packet tmpPacket = *packet; /* make copy of packet parse info */

        /* skip handles */
        i = outHandleCnt * sizeof(TPM_HANDLE);
        tmpPacket.buf += i; tmpPacket.pos += i;

        /* get parameter size and buffer */
        TPM2_Packet_ParseU32(&tmpPacket, &paramSz);
        param = tmpPacket.buf;

        /* get auth response */
        tmpPacket.buf += paramSz; tmpPacket.pos += paramSz;
        TPM2_Packet_ParseAuth(&tmpPacket, &authResp);

        for (i=0; i<authCnt; i++) {
            auth = &ctx->authCmd[i];

            /* check if encrypting parameters */
            if (auth->sessionAttributes & TPMA_SESSION_encrypt) {
                /* build key */
                XMEMCPY(key.buffer, auth->auth.buffer, auth->auth.size);
                key.size = auth->auth.size;

                /* check for object handle auth and append to key */
                if (i < outHandleCnt) {
                    TPM_HANDLE* objHandle = (TPM_HANDLE*)(cmd +
                        TPM2_HEADER_SIZE + (i * sizeof(TPM_HANDLE)));
                    if (*objHandle == auth->objHandle) {
                        /* append to key */
                        XMEMCPY(key.buffer + key.size, auth->objAuth.buffer,
                            auth->objAuth.size);
                        key.size += auth->objAuth.size;
                    }
                }

                /* perform parameter decryption (inline) */
                rc = TPM2_Parameter_EncryptDecrypt(TPMA_SESSION_decrypt,
                    &auth->symmetric,
                    auth->authHash,
                    key.buffer, key.size,
                    auth->nonce.buffer, auth->nonce.size,
                    param, paramSz);
                if (rc != 0)
                    return rc;
            }
        }
    }

    return rc;
}
static TPM_RC TPM2_SendCommand(TPM2_CTX* ctx, TPM2_Packet* packet)
{
    TPM_RC rc;

    if (ctx == NULL || packet == NULL)
        return BAD_FUNC_ARG;

    /* submit command and wait for response */
    rc = (TPM_RC)TPM2_TIS_SendCommand(ctx, packet->buf, packet->pos);

    return TPM2_Packet_Parse(rc, packet);
}

static TPM_ST TPM2_GetTag(TPM2_CTX* ctx)
{
    TPM_ST st = TPM_ST_NO_SESSIONS;
    if (ctx && ctx->authCmd &&
        (ctx->authCmd->sessionAttributes &
            (TPMA_SESSION_decrypt | TPMA_SESSION_encrypt))) {
        st = TPM_ST_SESSIONS;
    }
    return st;
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

TPM_RC TPM2_SetSessionAuth(TPMS_AUTH_COMMAND* cmd)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        ctx->authCmd = cmd;

        TPM2_ReleaseLock(ctx);
    }
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

    if (ctx == NULL) {
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
    use existing default locality */
TPM_RC TPM2_Init_ex(TPM2_CTX* ctx, TPM2HalIoCb ioCb, void* userCtx,
    int timeoutTries)
{
    TPM_RC rc;

    if (ctx == NULL || ioCb == NULL) {
        return BAD_FUNC_ARG;
    }

    XMEMSET(ctx, 0, sizeof(TPM2_CTX));

#ifndef WOLFTPM2_NO_WOLFCRYPT
    /* track reference count for wolfCrypt initialization */
    if (gWolfCryptRefCount == 0) {
    #ifdef DEBUG_WOLFSSL
        wolfSSL_Debugging_ON();
    #endif

        wolfCrypt_Init();
    }
    gWolfCryptRefCount++;
#endif /* !WOLFTPM2_NO_WOLFCRYPT */

    /* Setup HAL IO Callback */
    rc = TPM2_SetHalIoCb(ctx, ioCb, userCtx);
    if (rc != TPM_RC_SUCCESS)
        return rc;

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
            /* set non-active */
            TPM2_SetActiveCtx(NULL);
        }

        TPM2_ReleaseLock(ctx);
    }

#ifndef WOLFTPM2_NO_WOLFCRYPT
    #ifndef WC_NO_RNG
    if (ctx->rngInit) {
        ctx->rngInit = 0;
        wc_FreeRng(&ctx->rng);
    }
    #endif
    #ifndef SINGLE_THREADED
    if (ctx->hwLockInit) {
        ctx->hwLockInit = 0;
        wc_FreeMutex(&ctx->hwLock);
    }
    #endif

    /* track wolf initialize reference count in wolfTPM. wolfCrypt does not
        properly track reference count in v4.1 or older releases */
    gWolfCryptRefCount--;
    if (gWolfCryptRefCount < 0)
        gWolfCryptRefCount = 0;
    if (gWolfCryptRefCount == 0) {
        wolfCrypt_Cleanup();
    }
#endif /* !WOLFTPM2_NO_WOLFCRYPT */

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


TPM_RC TPM2_SelfTest(SelfTest_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU8(&packet, in->fullTest);
        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_SelfTest);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_IncrementalSelfTest(IncrementalSelfTest_In* in,
    IncrementalSelfTest_Out* out)
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
        TPM2_Packet_AppendU32(&packet, in->toTest.count);
        for (i=0; i<(int)in->toTest.count; i++) {
            TPM2_Packet_AppendU16(&packet, in->toTest.algorithms[i]);
        }
        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS,
            TPM_CC_IncrementalSelfTest);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            TPM2_Packet_ParseU32(&packet, &out->toDoList.count);
            for (i=0; i<(int)out->toDoList.count; i++) {
                TPM2_Packet_ParseU16(&packet, &out->toDoList.algorithms[i]);
            }
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_GetTestResult(GetTestResult_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || out == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_GetTestResult);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            TPM2_Packet_ParseU16(&packet, &out->outData.size);
            TPM2_Packet_ParseBytes(&packet, out->outData.buffer,
                out->outData.size);
            TPM2_Packet_ParseU16(&packet, &out->testResult);
        }

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
                case TPM_CAP_TPM_PROPERTIES: {
                    TPML_TAGGED_TPM_PROPERTY* prop =
                        &out->capabilityData.data.tpmProperties;
                    TPM2_Packet_ParseU32(&packet, &prop->count);
                    for (i=0; i<(int)prop->count; i++) {
                        TPM2_Packet_ParseU32(&packet,
                            &prop->tpmProperty[i].property);
                        TPM2_Packet_ParseU32(&packet,
                            &prop->tpmProperty[i].value);
                    }
                    break;
                }
                default:
            #ifdef DEBUG_WOLFTPM
                    printf("Unknown capability type 0x%x\n",
                        (unsigned int)out->capabilityData.capability);
            #endif
                    rc = -1;
                    break;
            }
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_GetRandom(GetRandom_In* in, GetRandom_Out* out)
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
        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_GetRandom);

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

TPM_RC TPM2_StirRandom(StirRandom_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU16(&packet, in->inData.size);
        TPM2_Packet_AppendBytes(&packet, in->inData.buffer, in->inData.size);
        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_StirRandom);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);

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

    if (ctx == NULL || in == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        int i;
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->pcrHandle);
        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);
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
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 1, 0);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}


TPM_RC TPM2_Create(Create_In* in, Create_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->parentHandle);
        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);
        TPM2_Packet_AppendSensitiveCreate(&packet, &in->inSensitive);
        TPM2_Packet_AppendPublic(&packet, &in->inPublic);
        TPM2_Packet_AppendU16(&packet, in->outsideInfo.size);
        TPM2_Packet_AppendBytes(&packet, in->outsideInfo.buffer,
            in->outsideInfo.size);
        TPM2_Packet_AppendPCR(&packet, &in->creationPCR);
        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_Create);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 1, 0);
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

TPM_RC TPM2_CreatePrimary(CreatePrimary_In* in, CreatePrimary_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->primaryHandle);
        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);
        TPM2_Packet_AppendSensitiveCreate(&packet, &in->inSensitive);
        TPM2_Packet_AppendPublic(&packet, &in->inPublic);
        TPM2_Packet_AppendU16(&packet, in->outsideInfo.size);
        TPM2_Packet_AppendBytes(&packet, in->outsideInfo.buffer,
            in->outsideInfo.size);
        TPM2_Packet_AppendPCR(&packet, &in->creationPCR);
        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_CreatePrimary);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 1, 1);
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


TPM_RC TPM2_Load(Load_In* in, Load_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->parentHandle);
        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);
        TPM2_Packet_AppendU16(&packet, in->inPrivate.size);
        TPM2_Packet_AppendBytes(&packet, in->inPrivate.buffer,
            in->inPrivate.size);
        TPM2_Packet_AppendPublic(&packet, &in->inPublic);
        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_Load);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 1, 1);
        if (rc == TPM_RC_SUCCESS) {
            UINT32 paramSz = 0;
            TPM2_Packet_ParseU32(&packet, &out->objectHandle);
            TPM2_Packet_ParseU32(&packet, &paramSz);
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

TPM_RC TPM2_Unseal(Unseal_In* in, Unseal_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->itemHandle);
        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);
        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_Unseal);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 1, 0);
        if (rc == TPM_RC_SUCCESS) {
            UINT32 paramSz = 0;
            TPM2_Packet_ParseU32(&packet, &paramSz);
            TPM2_Packet_ParseU16(&packet, &out->outData.size);
            TPM2_Packet_ParseBytes(&packet, out->outData.buffer,
                out->outData.size);
        }

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

        if (in->tpmKey != TPM_RH_NULL) {
            /* TODO: Encrypt salt using "SECRET" */
        }

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
        TPM2_Packet_Init(ctx, &packet);

        st = TPM2_GetTag(ctx);
        if (st == TPM_ST_SESSIONS) {
            TPM2_Packet_AppendAuth(&packet, ctx->authCmd);
        }

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
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 0, 1);
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

TPM_RC TPM2_ActivateCredential(ActivateCredential_In* in,
    ActivateCredential_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->activateHandle);
        TPM2_Packet_AppendU32(&packet, in->keyHandle);
        TPM2_Packet_AppendAuth(&packet, &ctx->authCmd[0]);
        TPM2_Packet_AppendAuth(&packet, &ctx->authCmd[1]);
        TPM2_Packet_AppendU16(&packet, in->credentialBlob.size);
        TPM2_Packet_AppendBytes(&packet, in->credentialBlob.buffer,
            in->credentialBlob.size);
        TPM2_Packet_AppendU16(&packet, in->secret.size);
        TPM2_Packet_AppendBytes(&packet, in->secret.secret, in->secret.size);
        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS,
            TPM_CC_ActivateCredential);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 2, 2, 0);
        if (rc == TPM_RC_SUCCESS) {
            UINT32 paramSz = 0;
            TPM2_Packet_ParseU32(&packet, &paramSz);
            TPM2_Packet_ParseU16(&packet, &out->certInfo.size);
            TPM2_Packet_ParseBytes(&packet, out->certInfo.buffer,
                out->certInfo.size);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_MakeCredential(MakeCredential_In* in, MakeCredential_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->handle);

        TPM2_Packet_AppendU16(&packet, in->credential.size);
        TPM2_Packet_AppendBytes(&packet, in->credential.buffer,
            in->credential.size);

        TPM2_Packet_AppendU16(&packet, in->objectName.size);
        TPM2_Packet_AppendBytes(&packet, in->objectName.name,
            in->objectName.size);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS,
            TPM_CC_MakeCredential);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            TPM2_Packet_ParseU16(&packet, &out->credentialBlob.size);
            TPM2_Packet_ParseBytes(&packet, out->credentialBlob.buffer,
                out->credentialBlob.size);

            TPM2_Packet_ParseU16(&packet, &out->secret.size);
            TPM2_Packet_ParseBytes(&packet, out->secret.secret,
                out->secret.size);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_ObjectChangeAuth(ObjectChangeAuth_In* in, ObjectChangeAuth_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->objectHandle);
        TPM2_Packet_AppendU32(&packet, in->parentHandle);

        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);

        TPM2_Packet_AppendU16(&packet, in->newAuth.size);
        TPM2_Packet_AppendBytes(&packet, in->newAuth.buffer,
            in->newAuth.size);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_ObjectChangeAuth);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 2, 0);
        if (rc == TPM_RC_SUCCESS) {
            UINT32 paramSz = 0;
            TPM2_Packet_ParseU32(&packet, &paramSz);

            TPM2_Packet_ParseU16(&packet, &out->outPrivate.size);
            TPM2_Packet_ParseBytes(&packet, out->outPrivate.buffer,
                out->outPrivate.size);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_Duplicate(Duplicate_In* in, Duplicate_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->objectHandle);
        TPM2_Packet_AppendU32(&packet, in->newParentHandle);

        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);

        TPM2_Packet_AppendU16(&packet, in->encryptionKeyIn.size);
        TPM2_Packet_AppendBytes(&packet, in->encryptionKeyIn.buffer,
            in->encryptionKeyIn.size);

        TPM2_Packet_AppendU16(&packet, in->symmetricAlg.algorithm);
        TPM2_Packet_AppendU16(&packet, in->symmetricAlg.keyBits.sym);
        TPM2_Packet_AppendU16(&packet, in->symmetricAlg.mode.sym);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_Duplicate);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 2, 0);
        if (rc == TPM_RC_SUCCESS) {
            UINT32 paramSz = 0;

            TPM2_Packet_ParseU32(&packet, &paramSz);

            TPM2_Packet_ParseU16(&packet, &out->encryptionKeyOut.size);
            TPM2_Packet_ParseBytes(&packet, out->encryptionKeyOut.buffer,
                out->encryptionKeyOut.size);

            TPM2_Packet_ParseU16(&packet, &out->duplicate.size);
            TPM2_Packet_ParseBytes(&packet, out->duplicate.buffer,
                out->duplicate.size);

            TPM2_Packet_ParseU16(&packet, &out->outSymSeed.size);
            TPM2_Packet_ParseBytes(&packet, out->outSymSeed.secret,
                out->outSymSeed.size);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_Rewrap(Rewrap_In* in, Rewrap_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->oldParent);
        TPM2_Packet_AppendU32(&packet, in->newParent);

        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);

        TPM2_Packet_AppendU16(&packet, in->inDuplicate.size);
        TPM2_Packet_AppendBytes(&packet, in->inDuplicate.buffer,
            in->inDuplicate.size);

        TPM2_Packet_AppendU16(&packet, in->name.size);
        TPM2_Packet_AppendBytes(&packet, in->name.name, in->name.size);

        TPM2_Packet_AppendU16(&packet, in->inSymSeed.size);
        TPM2_Packet_AppendBytes(&packet, in->inSymSeed.secret,
            in->inSymSeed.size);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_Rewrap);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 2, 0);
        if (rc == TPM_RC_SUCCESS) {
            UINT32 paramSz = 0;

            TPM2_Packet_ParseU32(&packet, &paramSz);

            TPM2_Packet_ParseU16(&packet, &out->outDuplicate.size);
            TPM2_Packet_ParseBytes(&packet, out->outDuplicate.buffer,
                out->outDuplicate.size);

            TPM2_Packet_ParseU16(&packet, &out->outSymSeed.size);
            TPM2_Packet_ParseBytes(&packet, out->outSymSeed.secret,
                out->outSymSeed.size);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_Import(Import_In* in, Import_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->parentHandle);
        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);
        TPM2_Packet_AppendU16(&packet, in->encryptionKey.size);
        TPM2_Packet_AppendBytes(&packet, in->encryptionKey.buffer,
            in->encryptionKey.size);
        TPM2_Packet_AppendPublic(&packet, &in->objectPublic);
        TPM2_Packet_AppendU16(&packet, in->duplicate.size);
        TPM2_Packet_AppendBytes(&packet, in->duplicate.buffer,
            in->duplicate.size);
        TPM2_Packet_AppendU16(&packet, in->inSymSeed.size);
        TPM2_Packet_AppendBytes(&packet, in->inSymSeed.secret,
            in->inSymSeed.size);
        TPM2_Packet_AppendSymmetric(&packet, &in->symmetricAlg);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_Import);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 1, 0);
        if (rc == TPM_RC_SUCCESS) {
            UINT32 paramSz = 0;

            TPM2_Packet_ParseU32(&packet, &paramSz);

            TPM2_Packet_ParseU16(&packet, &out->outPrivate.size);
            TPM2_Packet_ParseBytes(&packet, out->outPrivate.buffer,
                out->outPrivate.size);
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
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->keyHandle);

        st = TPM2_GetTag(ctx);
        if (st == TPM_ST_SESSIONS) {
            TPM2_Packet_AppendAuth(&packet, ctx->authCmd);
        }

        TPM2_Packet_AppendU16(&packet, in->message.size);
        TPM2_Packet_AppendBytes(&packet, in->message.buffer, in->message.size);

        TPM2_Packet_AppendU16(&packet, in->inScheme.scheme);
        if (in->inScheme.scheme != TPM_ALG_NULL)
            TPM2_Packet_AppendU16(&packet, in->inScheme.details.anySig.hashAlg);

        TPM2_Packet_AppendU16(&packet, in->label.size);
        TPM2_Packet_AppendBytes(&packet, in->label.buffer, in->label.size);

        TPM2_Packet_Finalize(&packet, st, TPM_CC_RSA_Encrypt);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 1, 0);
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

    if (ctx == NULL || in == NULL || out == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->keyHandle);

        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);

        TPM2_Packet_AppendU16(&packet, in->cipherText.size);
        TPM2_Packet_AppendBytes(&packet, in->cipherText.buffer,
            in->cipherText.size);

        TPM2_Packet_AppendU16(&packet, in->inScheme.scheme);
        if (in->inScheme.scheme != TPM_ALG_NULL)
            TPM2_Packet_AppendU16(&packet, in->inScheme.details.anySig.hashAlg);

        TPM2_Packet_AppendU16(&packet, in->label.size);
        TPM2_Packet_AppendBytes(&packet, in->label.buffer, in->label.size);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_RSA_Decrypt);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 1, 0);
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

TPM_RC TPM2_ECDH_KeyGen(ECDH_KeyGen_In* in, ECDH_KeyGen_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();
    TPM_ST st;

    if (ctx == NULL || in == NULL || out == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->keyHandle);

        st = TPM2_GetTag(ctx);
        if (st == TPM_ST_SESSIONS) {
            TPM2_Packet_AppendAuth(&packet, ctx->authCmd);
        }
        TPM2_Packet_Finalize(&packet, st, TPM_CC_ECDH_KeyGen);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 1, 0);
        if (rc == TPM_RC_SUCCESS) {
            UINT32 paramSz = 0;

            if (st == TPM_ST_SESSIONS) {
                TPM2_Packet_ParseU32(&packet, &paramSz);
            }

            /* results of P ≔ h[de]Qs */
            TPM2_Packet_ParsePoint(&packet, &out->zPoint);
            /* generated ephemeral public point (Qe) */
            TPM2_Packet_ParsePoint(&packet, &out->pubPoint);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_ECDH_ZGen(ECDH_ZGen_In* in, ECDH_ZGen_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->keyHandle);
        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);
        TPM2_Packet_AppendPoint(&packet, &in->inPoint);
        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_ECDH_ZGen);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 1, 0);
        if (rc == TPM_RC_SUCCESS) {
            UINT32 paramSz = 0;

            TPM2_Packet_ParseU32(&packet, &paramSz);

            /* X and Y coordinates of the product of the multiplication
               Z = (xZ , yZ) ≔ [hdS]QB */
            TPM2_Packet_ParsePoint(&packet, &out->outPoint);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_ECC_Parameters(ECC_Parameters_In* in,
    ECC_Parameters_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU16(&packet, in->curveID);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS,
            TPM_CC_ECC_Parameters);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            TPM2_Packet_ParseU16(&packet, &out->parameters.curveID);
            TPM2_Packet_ParseU16(&packet, &out->parameters.keySize);

            TPM2_Packet_ParseU16(&packet, &out->parameters.kdf.scheme);
            if (out->parameters.kdf.scheme != TPM_ALG_NULL)
                TPM2_Packet_ParseU16(&packet,
                    &out->parameters.kdf.details.any.hashAlg);

            TPM2_Packet_ParseU16(&packet, &out->parameters.sign.scheme);
            if (out->parameters.sign.scheme != TPM_ALG_NULL)
                TPM2_Packet_ParseU16(&packet,
                    &out->parameters.sign.details.any.hashAlg);

            TPM2_Packet_ParseU16(&packet, &out->parameters.p.size);
            TPM2_Packet_ParseBytes(&packet, out->parameters.p.buffer,
                out->parameters.p.size);

            TPM2_Packet_ParseU16(&packet, &out->parameters.a.size);
            TPM2_Packet_ParseBytes(&packet, out->parameters.a.buffer,
                out->parameters.a.size);

            TPM2_Packet_ParseU16(&packet, &out->parameters.b.size);
            TPM2_Packet_ParseBytes(&packet, out->parameters.b.buffer,
                out->parameters.b.size);

            TPM2_Packet_ParseU16(&packet, &out->parameters.gX.size);
            TPM2_Packet_ParseBytes(&packet, out->parameters.gX.buffer,
                out->parameters.gX.size);

            TPM2_Packet_ParseU16(&packet, &out->parameters.gY.size);
            TPM2_Packet_ParseBytes(&packet, out->parameters.gY.buffer,
                out->parameters.gY.size);

            TPM2_Packet_ParseU16(&packet, &out->parameters.n.size);
            TPM2_Packet_ParseBytes(&packet, out->parameters.n.buffer,
                out->parameters.n.size);

            TPM2_Packet_ParseU16(&packet, &out->parameters.h.size);
            TPM2_Packet_ParseBytes(&packet, out->parameters.h.buffer,
                out->parameters.h.size);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_ZGen_2Phase(ZGen_2Phase_In* in, ZGen_2Phase_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->keyA);
        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);
        TPM2_Packet_AppendPoint(&packet, &in->inQsB);
        TPM2_Packet_AppendPoint(&packet, &in->inQeB);
        TPM2_Packet_AppendU16(&packet, in->inScheme);
        TPM2_Packet_AppendU16(&packet, in->counter);
        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_ZGen_2Phase);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 1, 0);
        if (rc == TPM_RC_SUCCESS) {
            UINT32 paramSz = 0;

            TPM2_Packet_ParseU32(&packet, &paramSz);

            TPM2_Packet_ParsePoint(&packet, &out->outZ1);
            TPM2_Packet_ParsePoint(&packet, &out->outZ2);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_EncryptDecrypt(EncryptDecrypt_In* in, EncryptDecrypt_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->keyHandle);
        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);

        TPM2_Packet_AppendU8(&packet, in->decrypt);
        TPM2_Packet_AppendU16(&packet, in->mode);

        TPM2_Packet_AppendU16(&packet, in->ivIn.size);
        TPM2_Packet_AppendBytes(&packet, in->ivIn.buffer, in->ivIn.size);

        TPM2_Packet_AppendU16(&packet, in->inData.size);
        TPM2_Packet_AppendBytes(&packet, in->inData.buffer, in->inData.size);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_EncryptDecrypt);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 1, 0);
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

    if (ctx == NULL || in == NULL || out == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->keyHandle);
        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);

        TPM2_Packet_AppendU16(&packet, in->inData.size);
        TPM2_Packet_AppendBytes(&packet, in->inData.buffer, in->inData.size);

        TPM2_Packet_AppendU8(&packet, in->decrypt);
        TPM2_Packet_AppendU16(&packet, in->mode);

        TPM2_Packet_AppendU16(&packet, in->ivIn.size);
        TPM2_Packet_AppendBytes(&packet, in->ivIn.buffer, in->ivIn.size);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_EncryptDecrypt2);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 1, 0);
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
        TPM2_Packet_Init(ctx, &packet);

        st = TPM2_GetTag(ctx);
        if (st == TPM_ST_SESSIONS) {
            TPM2_Packet_AppendAuth(&packet, ctx->authCmd);
        }

        TPM2_Packet_AppendU16(&packet, in->data.size);
        TPM2_Packet_AppendBytes(&packet, in->data.buffer, in->data.size);

        TPM2_Packet_AppendU16(&packet, in->hashAlg);
        TPM2_Packet_AppendU32(&packet, in->hierarchy);

        TPM2_Packet_Finalize(&packet, st, TPM_CC_Hash);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 0, 0);
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

TPM_RC TPM2_HMAC(HMAC_In* in, HMAC_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->handle);
        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);

        TPM2_Packet_AppendU16(&packet, in->buffer.size);
        TPM2_Packet_AppendBytes(&packet, in->buffer.buffer, in->buffer.size);

        TPM2_Packet_AppendU16(&packet, in->hashAlg);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_HMAC);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 1, 0);
        if (rc == TPM_RC_SUCCESS) {
            UINT32 paramSz = 0;

            TPM2_Packet_ParseU32(&packet, &paramSz);

            TPM2_Packet_ParseU16(&packet, &out->outHMAC.size);
            TPM2_Packet_ParseBytes(&packet, out->outHMAC.buffer,
                out->outHMAC.size);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_HMAC_Start(HMAC_Start_In* in, HMAC_Start_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->handle);
        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);

        TPM2_Packet_AppendU16(&packet, in->auth.size);
        TPM2_Packet_AppendBytes(&packet, in->auth.buffer, in->auth.size);

        TPM2_Packet_AppendU16(&packet, in->hashAlg);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_HMAC_Start);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 1, 1);
        if (rc == TPM_RC_SUCCESS) {
            UINT32 paramSz = 0;

            TPM2_Packet_ParseU32(&packet, &out->sequenceHandle);
            TPM2_Packet_ParseU32(&packet, &paramSz);
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
        TPM2_Packet_Init(ctx, &packet);

        st = TPM2_GetTag(ctx);
        if (st == TPM_ST_SESSIONS) {
            TPM2_Packet_AppendAuth(&packet, ctx->authCmd);
        }

        TPM2_Packet_AppendU16(&packet, in->auth.size);
        TPM2_Packet_AppendBytes(&packet, in->auth.buffer, in->auth.size);

        TPM2_Packet_AppendU16(&packet, in->hashAlg);

        TPM2_Packet_Finalize(&packet, st, TPM_CC_HashSequenceStart);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 0, 1);
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

    if (ctx == NULL || in == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->sequenceHandle);
        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);

        TPM2_Packet_AppendU16(&packet, in->buffer.size);
        TPM2_Packet_AppendBytes(&packet, in->buffer.buffer, in->buffer.size);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_SequenceUpdate);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 1, 0);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_SequenceComplete(SequenceComplete_In* in, SequenceComplete_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->sequenceHandle);
        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);

        TPM2_Packet_AppendU16(&packet, in->buffer.size);
        TPM2_Packet_AppendBytes(&packet, in->buffer.buffer, in->buffer.size);

        TPM2_Packet_AppendU32(&packet, in->hierarchy);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_SequenceComplete);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 1, 0);
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

TPM_RC TPM2_EventSequenceComplete(EventSequenceComplete_In* in,
    EventSequenceComplete_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->pcrHandle);
        TPM2_Packet_AppendU32(&packet, in->sequenceHandle);

        TPM2_Packet_AppendAuth(&packet, &ctx->authCmd[0]);
        TPM2_Packet_AppendAuth(&packet, &ctx->authCmd[1]);

        TPM2_Packet_AppendU16(&packet, in->buffer.size);
        TPM2_Packet_AppendBytes(&packet, in->buffer.buffer, in->buffer.size);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS,
            TPM_CC_EventSequenceComplete);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 2, 2, 0);
        if (rc == TPM_RC_SUCCESS) {
            int i, digestSz;
            UINT32 paramSz = 0;

            TPM2_Packet_ParseU32(&packet, &paramSz);

            TPM2_Packet_ParseU32(&packet, &out->results.count);
            for (i=0; i<(int)out->results.count; i++) {
                TPM2_Packet_ParseU16(&packet,
                    &out->results.digests[i].hashAlg);
                digestSz = TPM2_GetHashDigestSize(
                    out->results.digests[i].hashAlg);
                TPM2_Packet_ParseBytes(&packet,
                    out->results.digests[i].digest.H, digestSz);
            }
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_Certify(Certify_In* in, Certify_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->objectHandle);
        TPM2_Packet_AppendU32(&packet, in->signHandle);

        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);

        TPM2_Packet_AppendU16(&packet, in->qualifyingData.size);
        TPM2_Packet_AppendBytes(&packet, in->qualifyingData.buffer,
            in->qualifyingData.size);

        TPM2_Packet_AppendU16(&packet, in->inScheme.scheme);
        TPM2_Packet_AppendU16(&packet, in->inScheme.details.any.hashAlg);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_Certify);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 2, 0);
        if (rc == TPM_RC_SUCCESS) {
            UINT32 paramSz = 0;

            TPM2_Packet_ParseU32(&packet, &paramSz);

            TPM2_Packet_ParseU16(&packet, &out->certifyInfo.size);
            TPM2_Packet_ParseBytes(&packet, out->certifyInfo.attestationData,
                out->certifyInfo.size);

            TPM2_Packet_ParseSignature(&packet, &out->signature);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_CertifyCreation(CertifyCreation_In* in, CertifyCreation_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->signHandle);
        TPM2_Packet_AppendU32(&packet, in->objectHandle);

        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);

        TPM2_Packet_AppendU16(&packet, in->qualifyingData.size);
        TPM2_Packet_AppendBytes(&packet, in->qualifyingData.buffer,
            in->qualifyingData.size);

        TPM2_Packet_AppendU16(&packet, in->creationHash.size);
        TPM2_Packet_AppendBytes(&packet, in->creationHash.buffer,
            in->creationHash.size);

        TPM2_Packet_AppendU16(&packet, in->inScheme.scheme);
        TPM2_Packet_AppendU16(&packet, in->inScheme.details.any.hashAlg);

        TPM2_Packet_AppendU16(&packet, in->creationTicket.tag);
        TPM2_Packet_AppendU32(&packet, in->creationTicket.hierarchy);
        TPM2_Packet_AppendU16(&packet, in->creationTicket.digest.size);
        TPM2_Packet_AppendBytes(&packet,
                    in->creationTicket.digest.buffer,
                    in->creationTicket.digest.size);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_CertifyCreation);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 2, 0);
        if (rc == TPM_RC_SUCCESS) {
            UINT32 paramSz = 0;

            TPM2_Packet_ParseU32(&packet, &paramSz);

            TPM2_Packet_ParseU16(&packet, &out->certifyInfo.size);
            TPM2_Packet_ParseBytes(&packet, out->certifyInfo.attestationData,
                out->certifyInfo.size);

            TPM2_Packet_ParseSignature(&packet, &out->signature);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_Quote(Quote_In* in, Quote_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->signHandle);

        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);

        TPM2_Packet_AppendU16(&packet, in->qualifyingData.size);
        TPM2_Packet_AppendBytes(&packet, in->qualifyingData.buffer,
            in->qualifyingData.size);

        TPM2_Packet_AppendU16(&packet, in->inScheme.scheme);
        TPM2_Packet_AppendU16(&packet, in->inScheme.details.any.hashAlg);

        TPM2_Packet_AppendPCR(&packet, &in->PCRselect);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_Quote);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 1, 0);
        if (rc == TPM_RC_SUCCESS) {
            UINT32 paramSz = 0;

            TPM2_Packet_ParseU32(&packet, &paramSz);

            TPM2_Packet_ParseU16(&packet, &out->quoted.size);
            TPM2_Packet_ParseBytes(&packet, out->quoted.attestationData,
                out->quoted.size);

            TPM2_Packet_ParseSignature(&packet, &out->signature);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_GetSessionAuditDigest(GetSessionAuditDigest_In* in,
    GetSessionAuditDigest_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->privacyAdminHandle);
        TPM2_Packet_AppendU32(&packet, in->signHandle);
        TPM2_Packet_AppendU32(&packet, in->sessionHandle);

        TPM2_Packet_AppendAuth(&packet, &ctx->authCmd[0]);
        TPM2_Packet_AppendAuth(&packet, &ctx->authCmd[1]);

        TPM2_Packet_AppendU16(&packet, in->qualifyingData.size);
        TPM2_Packet_AppendBytes(&packet, in->qualifyingData.buffer,
            in->qualifyingData.size);

        TPM2_Packet_AppendU16(&packet, in->inScheme.scheme);
        TPM2_Packet_AppendU16(&packet, in->inScheme.details.any.hashAlg);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS,
            TPM_CC_GetSessionAuditDigest);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 2, 2, 0);
        if (rc == TPM_RC_SUCCESS) {
            UINT32 paramSz = 0;

            TPM2_Packet_ParseU32(&packet, &paramSz);

            TPM2_Packet_ParseU16(&packet, &out->auditInfo.size);
            TPM2_Packet_ParseBytes(&packet, out->auditInfo.attestationData,
                out->auditInfo.size);

            TPM2_Packet_ParseSignature(&packet, &out->signature);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_GetCommandAuditDigest(GetCommandAuditDigest_In* in,
    GetCommandAuditDigest_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->privacyHandle);
        TPM2_Packet_AppendU32(&packet, in->signHandle);

        TPM2_Packet_AppendAuth(&packet, &ctx->authCmd[0]);
        TPM2_Packet_AppendAuth(&packet, &ctx->authCmd[1]);

        TPM2_Packet_AppendU16(&packet, in->qualifyingData.size);
        TPM2_Packet_AppendBytes(&packet, in->qualifyingData.buffer,
            in->qualifyingData.size);

        TPM2_Packet_AppendU16(&packet, in->inScheme.scheme);
        TPM2_Packet_AppendU16(&packet, in->inScheme.details.any.hashAlg);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS,
            TPM_CC_GetCommandAuditDigest);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 2, 2, 0);
        if (rc == TPM_RC_SUCCESS) {
            UINT32 paramSz = 0;

            TPM2_Packet_ParseU32(&packet, &paramSz);

            TPM2_Packet_ParseU16(&packet, &out->auditInfo.size);
            TPM2_Packet_ParseBytes(&packet, out->auditInfo.attestationData,
                out->auditInfo.size);

            TPM2_Packet_ParseSignature(&packet, &out->signature);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_GetTime(GetTime_In* in, GetTime_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->privacyAdminHandle);
        TPM2_Packet_AppendU32(&packet, in->signHandle);

        TPM2_Packet_AppendAuth(&packet, &ctx->authCmd[0]);
        TPM2_Packet_AppendAuth(&packet, &ctx->authCmd[1]);

        TPM2_Packet_AppendU16(&packet, in->qualifyingData.size);
        TPM2_Packet_AppendBytes(&packet, in->qualifyingData.buffer,
            in->qualifyingData.size);

        TPM2_Packet_AppendU16(&packet, in->inScheme.scheme);
        TPM2_Packet_AppendU16(&packet, in->inScheme.details.any.hashAlg);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_GetTime);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 2, 2, 0);
        if (rc == TPM_RC_SUCCESS) {
            UINT32 paramSz = 0;

            TPM2_Packet_ParseU32(&packet, &paramSz);

            TPM2_Packet_ParseU16(&packet, &out->timeInfo.size);
            TPM2_Packet_ParseBytes(&packet, out->timeInfo.attestationData,
                out->timeInfo.size);

            TPM2_Packet_ParseSignature(&packet, &out->signature);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_Commit(Commit_In* in, Commit_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->signHandle);

        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);

        TPM2_Packet_AppendPoint(&packet, &in->P1);

        TPM2_Packet_AppendU16(&packet, in->s2.size);
        TPM2_Packet_AppendBytes(&packet, in->s2.buffer, in->s2.size);

        TPM2_Packet_AppendU16(&packet, in->y2.size);
        TPM2_Packet_AppendBytes(&packet, in->y2.buffer, in->y2.size);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_Commit);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 1, 0);
        if (rc == TPM_RC_SUCCESS) {
            UINT32 paramSz = 0;

            TPM2_Packet_ParseU32(&packet, &paramSz);

            TPM2_Packet_ParsePoint(&packet, &out->K);
            TPM2_Packet_ParsePoint(&packet, &out->L);
            TPM2_Packet_ParsePoint(&packet, &out->E);
            TPM2_Packet_ParseU16(&packet, &out->counter);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_EC_Ephemeral(EC_Ephemeral_In* in, EC_Ephemeral_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();
    TPM_ST st;

    if (ctx == NULL || in == NULL || out == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        st = TPM2_GetTag(ctx);
        if (st == TPM_ST_SESSIONS) {
            TPM2_Packet_AppendAuth(&packet, ctx->authCmd);
        }
        TPM2_Packet_AppendU32(&packet, in->curveID);
        TPM2_Packet_Finalize(&packet, st, TPM_CC_EC_Ephemeral);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 0, 0);
        if (rc == TPM_RC_SUCCESS) {
            UINT32 paramSz = 0;

            if (st == TPM_ST_SESSIONS) {
                TPM2_Packet_ParseU32(&packet, &paramSz);
            }

            TPM2_Packet_ParsePoint(&packet, &out->Q);
            TPM2_Packet_ParseU16(&packet, &out->counter);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_VerifySignature(VerifySignature_In* in,
    VerifySignature_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();
    TPM_ST st;

    if (ctx == NULL || in == NULL || out == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->keyHandle);

        st = TPM2_GetTag(ctx);
        if (st == TPM_ST_SESSIONS) {
            TPM2_Packet_AppendAuth(&packet, ctx->authCmd);
        }

        TPM2_Packet_AppendU16(&packet, in->digest.size);
        TPM2_Packet_AppendBytes(&packet, in->digest.buffer, in->digest.size);

        TPM2_Packet_AppendSignature(&packet, &in->signature);

        TPM2_Packet_Finalize(&packet, st, TPM_CC_VerifySignature);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 1, 0);
        if (rc == TPM_RC_SUCCESS) {
            UINT32 paramSz = 0;

            if (st == TPM_ST_SESSIONS) {
                TPM2_Packet_ParseU32(&packet, &paramSz);
            }

            TPM2_Packet_ParseU16(&packet, &out->validation.tag);
            TPM2_Packet_ParseU32(&packet, &out->validation.hierarchy);
            TPM2_Packet_ParseU16(&packet, &out->validation.digest.size);
            TPM2_Packet_ParseBytes(&packet,
                        out->validation.digest.buffer,
                        out->validation.digest.size);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_Sign(Sign_In* in, Sign_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->keyHandle);

        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);

        TPM2_Packet_AppendU16(&packet, in->digest.size);
        TPM2_Packet_AppendBytes(&packet, in->digest.buffer, in->digest.size);

        TPM2_Packet_AppendU16(&packet, in->inScheme.scheme);
        TPM2_Packet_AppendU16(&packet, in->inScheme.details.any.hashAlg);

        TPM2_Packet_AppendU16(&packet, in->validation.tag);
        TPM2_Packet_AppendU32(&packet, in->validation.hierarchy);

        TPM2_Packet_AppendU16(&packet, in->validation.digest.size);
        TPM2_Packet_AppendBytes(&packet, in->validation.digest.buffer,
            in->validation.digest.size);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_Sign);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 2, 1, 0);
        if (rc == TPM_RC_SUCCESS) {
            UINT32 paramSz = 0;

            TPM2_Packet_ParseU32(&packet, &paramSz);
            TPM2_Packet_ParseSignature(&packet, &out->signature);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_SetCommandCodeAuditStatus(
    SetCommandCodeAuditStatus_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        int i;
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->auth);

        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);

        TPM2_Packet_AppendU16(&packet, in->auditAlg);

        TPM2_Packet_AppendU32(&packet, in->setList.count);
        for (i=0; i<(int)in->setList.count; i++) {
            TPM2_Packet_AppendU32(&packet, in->setList.commandCodes[i]);
        }

        TPM2_Packet_AppendU32(&packet, in->clearList.count);
        for (i=0; i<(int)in->clearList.count; i++) {
            TPM2_Packet_AppendU32(&packet, in->clearList.commandCodes[i]);
        }

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS,
            TPM_CC_SetCommandCodeAuditStatus);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 1, 0);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_PCR_Event(PCR_Event_In* in, PCR_Event_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->pcrHandle);
        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);

        TPM2_Packet_AppendU16(&packet, in->eventData.size);
        TPM2_Packet_AppendBytes(&packet, in->eventData.buffer,
            in->eventData.size);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_PCR_Event);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 1, 0);
        if (rc == TPM_RC_SUCCESS) {
            int i;
            UINT32 paramSz = 0;

            TPM2_Packet_ParseU32(&packet, &paramSz);

            TPM2_Packet_ParseU32(&packet, &out->digests.count);
            for (i=0; (int)out->digests.count; i++) {
                int digestSz;
                TPM2_Packet_ParseU16(&packet, &out->digests.digests[i].hashAlg);
                digestSz = TPM2_GetHashDigestSize(
                    out->digests.digests[i].hashAlg);
                TPM2_Packet_ParseBytes(&packet,
                    out->digests.digests[i].digest.H, digestSz);
            }
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_PCR_Allocate(PCR_Allocate_In* in, PCR_Allocate_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);

        TPM2_Packet_AppendPCR(&packet, &in->pcrAllocation);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_PCR_Allocate);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 1, 0);
        if (rc == TPM_RC_SUCCESS) {
            UINT32 paramSz = 0;

            TPM2_Packet_ParseU32(&packet, &paramSz);

            TPM2_Packet_ParseU8(&packet, &out->allocationSuccess);
            TPM2_Packet_ParseU32(&packet, &out->maxPCR);
            TPM2_Packet_ParseU32(&packet, &out->sizeNeeded);
            TPM2_Packet_ParseU32(&packet, &out->sizeAvailable);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_PCR_SetAuthPolicy(PCR_SetAuthPolicy_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);

        TPM2_Packet_AppendU16(&packet, in->authPolicy.size);
        TPM2_Packet_AppendBytes(&packet, in->authPolicy.buffer,
            in->authPolicy.size);

        TPM2_Packet_AppendU16(&packet, in->hashAlg);
        TPM2_Packet_AppendU32(&packet, in->pcrNum);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS,
            TPM_CC_PCR_SetAuthPolicy);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 1, 0);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_PCR_SetAuthValue(PCR_SetAuthValue_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->pcrHandle);
        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);

        TPM2_Packet_AppendU16(&packet, in->auth.size);
        TPM2_Packet_AppendBytes(&packet, in->auth.buffer, in->auth.size);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_PCR_SetAuthValue);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 1, 0);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_PCR_Reset(PCR_Reset_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->pcrHandle);
        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_PCR_Reset);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 1, 0);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_PolicySigned(PolicySigned_In* in, PolicySigned_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();
    TPM_ST st;

    if (ctx == NULL || in == NULL || out == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->authObject);
        TPM2_Packet_AppendU32(&packet, in->policySession);

        st = TPM2_GetTag(ctx);
        if (st == TPM_ST_SESSIONS) {
            TPM2_Packet_AppendAuth(&packet, ctx->authCmd);
        }

        TPM2_Packet_AppendU16(&packet, in->nonceTPM.size);
        TPM2_Packet_AppendBytes(&packet, in->nonceTPM.buffer,
            in->nonceTPM.size);

        TPM2_Packet_AppendU16(&packet, in->cpHashA.size);
        TPM2_Packet_AppendBytes(&packet, in->cpHashA.buffer,
            in->cpHashA.size);

        TPM2_Packet_AppendU16(&packet, in->policyRef.size);
        TPM2_Packet_AppendBytes(&packet, in->policyRef.buffer,
            in->policyRef.size);

        TPM2_Packet_AppendS32(&packet, in->expiration);

        TPM2_Packet_AppendSignature(&packet, &in->auth);

        TPM2_Packet_Finalize(&packet, st, TPM_CC_PolicySigned);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 2, 0);
        if (rc == TPM_RC_SUCCESS) {
            UINT32 paramSz = 0;

            if (st == TPM_ST_SESSIONS) {
                TPM2_Packet_ParseU32(&packet, &paramSz);
            }

            TPM2_Packet_ParseU16(&packet, &out->timeout.size);
            TPM2_Packet_ParseBytes(&packet, out->timeout.buffer,
                out->timeout.size);

            TPM2_Packet_ParseU16(&packet, &out->policyTicket.tag);
            TPM2_Packet_ParseU32(&packet, &out->policyTicket.hierarchy);
            TPM2_Packet_ParseU16(&packet, &out->policyTicket.digest.size);
            TPM2_Packet_ParseBytes(&packet,
                        out->policyTicket.digest.buffer,
                        out->policyTicket.digest.size);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_PolicySecret(PolicySecret_In* in, PolicySecret_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendU32(&packet, in->policySession);

        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);

        TPM2_Packet_AppendU16(&packet, in->nonceTPM.size);
        TPM2_Packet_AppendBytes(&packet, in->nonceTPM.buffer,
            in->nonceTPM.size);

        TPM2_Packet_AppendU16(&packet, in->cpHashA.size);
        TPM2_Packet_AppendBytes(&packet, in->cpHashA.buffer,
            in->cpHashA.size);

        TPM2_Packet_AppendU16(&packet, in->policyRef.size);
        TPM2_Packet_AppendBytes(&packet, in->policyRef.buffer,
            in->policyRef.size);

        TPM2_Packet_AppendS32(&packet, in->expiration);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_PolicySecret);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 2, 0);
        if (rc == TPM_RC_SUCCESS) {
            UINT32 paramSz = 0;

            TPM2_Packet_ParseU32(&packet, &paramSz);

            TPM2_Packet_ParseU16(&packet, &out->timeout.size);
            TPM2_Packet_ParseBytes(&packet, out->timeout.buffer,
                out->timeout.size);

            TPM2_Packet_ParseU16(&packet, &out->policyTicket.tag);
            TPM2_Packet_ParseU32(&packet, &out->policyTicket.hierarchy);
            TPM2_Packet_ParseU16(&packet, &out->policyTicket.digest.size);
            TPM2_Packet_ParseBytes(&packet,
                        out->policyTicket.digest.buffer,
                        out->policyTicket.digest.size);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_PolicyTicket(PolicyTicket_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();
    TPM_ST st;

    if (ctx == NULL || in == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->policySession);

        st = TPM2_GetTag(ctx);
        if (st == TPM_ST_SESSIONS) {
            TPM2_Packet_AppendAuth(&packet, ctx->authCmd);
        }

        TPM2_Packet_AppendU16(&packet, in->timeout.size);
        TPM2_Packet_AppendBytes(&packet, in->timeout.buffer,
            in->timeout.size);

        TPM2_Packet_AppendU16(&packet, in->cpHashA.size);
        TPM2_Packet_AppendBytes(&packet, in->cpHashA.buffer,
            in->cpHashA.size);

        TPM2_Packet_AppendU16(&packet, in->policyRef.size);
        TPM2_Packet_AppendBytes(&packet, in->policyRef.buffer,
            in->policyRef.size);

        TPM2_Packet_AppendU16(&packet, in->authName.size);
        TPM2_Packet_AppendBytes(&packet, in->authName.name,
            in->authName.size);

        TPM2_Packet_Finalize(&packet, st, TPM_CC_PolicyTicket);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 1, 0);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_PolicyOR(PolicyOR_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        int i;
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->policySession);

        TPM2_Packet_AppendU32(&packet, in->pHashList.count);
        for (i=0; i<(int)in->pHashList.count; i++) {
            TPM2_Packet_AppendU16(&packet, in->pHashList.digests[i].size);
            TPM2_Packet_AppendBytes(&packet,
                in->pHashList.digests[i].buffer,
                in->pHashList.digests[i].size);
        }

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_PolicyOR);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);

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
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->policySession);

        st = TPM2_GetTag(ctx);
        if (st == TPM_ST_SESSIONS) {
            TPM2_Packet_AppendAuth(&packet, ctx->authCmd);
        }

        TPM2_Packet_AppendU16(&packet, in->pcrDigest.size);
        TPM2_Packet_AppendBytes(&packet, in->pcrDigest.buffer,
            in->pcrDigest.size);

        TPM2_Packet_AppendPCR(&packet, &in->pcrs);

        TPM2_Packet_Finalize(&packet, st, TPM_CC_PolicyPCR);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 1, 0);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_PolicyLocality(PolicyLocality_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->policySession);
        TPM2_Packet_AppendU8(&packet, in->locality);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS,
            TPM_CC_PolicyLocality);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_PolicyNV(PolicyNV_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendU32(&packet, in->nvIndex);
        TPM2_Packet_AppendU32(&packet, in->policySession);

        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);

        TPM2_Packet_AppendU16(&packet, in->operandB.size);
        TPM2_Packet_AppendBytes(&packet, in->operandB.buffer,
            in->operandB.size);

        TPM2_Packet_AppendU16(&packet, in->offset);
        TPM2_Packet_AppendU16(&packet, in->operation);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_PolicyNV);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 3, 0);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_PolicyCounterTimer(PolicyCounterTimer_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();
    TPM_ST st;

    if (ctx == NULL || in == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->policySession);

        st = TPM2_GetTag(ctx);
        if (st == TPM_ST_SESSIONS) {
            TPM2_Packet_AppendAuth(&packet, ctx->authCmd);
        }

        TPM2_Packet_AppendU16(&packet, in->operandB.size);
        TPM2_Packet_AppendBytes(&packet, in->operandB.buffer,
            in->operandB.size);

        TPM2_Packet_AppendU16(&packet, in->offset);
        TPM2_Packet_AppendU16(&packet, in->operation);

        TPM2_Packet_Finalize(&packet, st, TPM_CC_PolicyCounterTimer);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 1, 0);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_PolicyCommandCode(PolicyCommandCode_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->policySession);

        TPM2_Packet_AppendU32(&packet, in->code);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS,
            TPM_CC_PolicyCommandCode);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_PolicyCpHash(PolicyCpHash_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();
    TPM_ST st;

    if (ctx == NULL || in == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->policySession);
        st = TPM2_GetTag(ctx);
        if (st == TPM_ST_SESSIONS) {
            TPM2_Packet_AppendAuth(&packet, ctx->authCmd);
        }

        TPM2_Packet_AppendU16(&packet, in->cpHashA.size);
        TPM2_Packet_AppendBytes(&packet, in->cpHashA.buffer, in->cpHashA.size);

        TPM2_Packet_Finalize(&packet, st, TPM_CC_PolicyCpHash);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 1, 0);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_PolicyNameHash(PolicyNameHash_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();
    TPM_ST st;

    if (ctx == NULL || in == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->policySession);
        st = TPM2_GetTag(ctx);
        if (st == TPM_ST_SESSIONS) {
            TPM2_Packet_AppendAuth(&packet, ctx->authCmd);
        }

        TPM2_Packet_AppendU16(&packet, in->nameHash.size);
        TPM2_Packet_AppendBytes(&packet, in->nameHash.buffer,
            in->nameHash.size);

        TPM2_Packet_Finalize(&packet, st, TPM_CC_PolicyNameHash);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 1, 0);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_PolicyDuplicationSelect(PolicyDuplicationSelect_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();
    TPM_ST st;

    if (ctx == NULL || in == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->policySession);
        st = TPM2_GetTag(ctx);
        if (st == TPM_ST_SESSIONS) {
            TPM2_Packet_AppendAuth(&packet, ctx->authCmd);
        }

        TPM2_Packet_AppendU16(&packet, in->objectName.size);
        TPM2_Packet_AppendBytes(&packet, in->objectName.name,
            in->objectName.size);

        TPM2_Packet_AppendU16(&packet, in->newParentName.size);
        TPM2_Packet_AppendBytes(&packet, in->newParentName.name,
            in->newParentName.size);

        TPM2_Packet_AppendU8(&packet, in->includeObject);

        TPM2_Packet_Finalize(&packet, st, TPM_CC_PolicyDuplicationSelect);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 1, 0);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_PolicyAuthorize(PolicyAuthorize_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();
    TPM_ST st;

    if (ctx == NULL || in == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->policySession);
        st = TPM2_GetTag(ctx);
        if (st == TPM_ST_SESSIONS) {
            TPM2_Packet_AppendAuth(&packet, ctx->authCmd);
        }

        TPM2_Packet_AppendU16(&packet, in->approvedPolicy.size);
        TPM2_Packet_AppendBytes(&packet, in->approvedPolicy.buffer,
            in->approvedPolicy.size);

        TPM2_Packet_AppendU16(&packet, in->policyRef.size);
        TPM2_Packet_AppendBytes(&packet, in->policyRef.buffer,
            in->policyRef.size);

        TPM2_Packet_AppendU16(&packet, in->keySign.size);
        TPM2_Packet_AppendBytes(&packet, in->keySign.name, in->keySign.size);

        TPM2_Packet_AppendU16(&packet, in->checkTicket.tag);
        TPM2_Packet_AppendU32(&packet, in->checkTicket.hierarchy);
        TPM2_Packet_AppendU16(&packet, in->checkTicket.digest.size);
        TPM2_Packet_AppendBytes(&packet,
                    in->checkTicket.digest.buffer,
                    in->checkTicket.digest.size);

        TPM2_Packet_Finalize(&packet, st, TPM_CC_PolicyAuthorize);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 1, 0);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}


static TPM_RC TPM2_PolicySessionOnly(TPM_CC cc, TPMI_SH_POLICY policy)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, policy);
        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, cc);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}


TPM_RC TPM2_PolicyPhysicalPresence(PolicyPhysicalPresence_In* in)
{
    return TPM2_PolicySessionOnly(TPM_CC_PolicyPhysicalPresence,
        in->policySession);
}

TPM_RC TPM2_PolicyAuthValue(PolicyAuthValue_In* in)
{
    return TPM2_PolicySessionOnly(TPM_CC_PolicyAuthValue, in->policySession);
}

TPM_RC TPM2_PolicyPassword(PolicyPassword_In* in)
{
    return TPM2_PolicySessionOnly(TPM_CC_PolicyPassword, in->policySession);
}

TPM_RC TPM2_PolicyGetDigest(PolicyGetDigest_In* in, PolicyGetDigest_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();
    TPM_ST st;

    if (ctx == NULL || in == NULL || out == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->policySession);
        st = TPM2_GetTag(ctx);
        if (st == TPM_ST_SESSIONS) {
            TPM2_Packet_AppendAuth(&packet, ctx->authCmd);
        }
        TPM2_Packet_Finalize(&packet, st, TPM_CC_PolicyGetDigest);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 1, 0);
        if (rc == TPM_RC_SUCCESS) {
            UINT32 paramSz = 0;

            if (st == TPM_ST_SESSIONS) {
                TPM2_Packet_ParseU32(&packet, &paramSz);
            }

            TPM2_Packet_ParseU16(&packet, &out->policyDigest.size);
            TPM2_Packet_ParseBytes(&packet, out->policyDigest.buffer,
                out->policyDigest.size);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_PolicyNvWritten(PolicyNvWritten_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->policySession);
        TPM2_Packet_AppendU8(&packet, in->writtenSet);
        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS,
            TPM_CC_PolicyNvWritten);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_PolicyTemplate(PolicyTemplate_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();
    TPM_ST st;

    if (ctx == NULL || in == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->policySession);
        st = TPM2_GetTag(ctx);
        if (st == TPM_ST_SESSIONS) {
            TPM2_Packet_AppendAuth(&packet, ctx->authCmd);
        }
        TPM2_Packet_AppendU16(&packet, in->templateHash.size);
        TPM2_Packet_AppendBytes(&packet, in->templateHash.buffer,
            in->templateHash.size);
        TPM2_Packet_Finalize(&packet, st, TPM_CC_PolicyTemplate);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 1, 0);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_PolicyAuthorizeNV(PolicyAuthorizeNV_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendU32(&packet, in->nvIndex);
        TPM2_Packet_AppendU32(&packet, in->policySession);
        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);
        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS,
            TPM_CC_PolicyAuthorizeNV);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 3, 0);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}


TPM_RC TPM2_HierarchyControl(HierarchyControl_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);
        TPM2_Packet_AppendU32(&packet, in->enable);
        TPM2_Packet_AppendU8(&packet, in->state);
        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_HierarchyControl);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 1, 0);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_SetPrimaryPolicy(SetPrimaryPolicy_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);
        TPM2_Packet_AppendU16(&packet, in->authPolicy.size);
        TPM2_Packet_AppendBytes(&packet, in->authPolicy.buffer,
            in->authPolicy.size);
        TPM2_Packet_AppendU16(&packet, in->hashAlg);
        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_SetPrimaryPolicy);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 1, 0);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

static TPM_RC TPM2_ChangeSeed(ChangeSeed_In* in, TPM_CC cc)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);
        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, cc);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 1, 0);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_ChangePPS(ChangePPS_In* in)
{
    return TPM2_ChangeSeed(in, TPM_CC_ChangePPS);
}

TPM_RC TPM2_ChangeEPS(ChangeEPS_In* in)
{
    return TPM2_ChangeSeed(in, TPM_CC_ChangeEPS);
}

TPM_RC TPM2_Clear(Clear_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);
        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_Clear);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 1, 0);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_ClearControl(ClearControl_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->auth);
        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);
        TPM2_Packet_AppendU8(&packet, in->disable);
        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_ClearControl);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 1, 0);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_HierarchyChangeAuth(HierarchyChangeAuth_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);
        TPM2_Packet_AppendU16(&packet, in->newAuth.size);
        TPM2_Packet_AppendBytes(&packet, in->newAuth.buffer, in->newAuth.size);
        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS,
            TPM_CC_HierarchyChangeAuth);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 1, 0);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_DictionaryAttackLockReset(DictionaryAttackLockReset_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->lockHandle);
        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);
        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS,
            TPM_CC_DictionaryAttackLockReset);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 1, 0);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_DictionaryAttackParameters(DictionaryAttackParameters_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->lockHandle);
        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);
        TPM2_Packet_AppendU32(&packet, in->newMaxTries);
        TPM2_Packet_AppendU32(&packet, in->newRecoveryTime);
        TPM2_Packet_AppendU32(&packet, in->lockoutRecovery);
        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS,
            TPM_CC_DictionaryAttackParameters);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 1, 0);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_PP_Commands(PP_Commands_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        int i;
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->auth);
        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);

        TPM2_Packet_AppendU32(&packet, in->setList.count);
        for (i=0; i<(int)in->setList.count; i++) {
            TPM2_Packet_AppendU32(&packet, in->setList.commandCodes[i]);
        }
        TPM2_Packet_AppendU32(&packet, in->clearList.count);
        for (i=0; i<(int)in->clearList.count; i++) {
            TPM2_Packet_AppendU32(&packet, in->clearList.commandCodes[i]);
        }

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_PP_Commands);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 1, 0);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_SetAlgorithmSet(SetAlgorithmSet_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);

        TPM2_Packet_AppendU32(&packet, in->algorithmSet);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_SetAlgorithmSet);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 1, 0);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_FieldUpgradeStart(FieldUpgradeStart_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->authorization);
        TPM2_Packet_AppendU32(&packet, in->keyHandle);
        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);

        TPM2_Packet_AppendU16(&packet, in->fuDigest.size);
        TPM2_Packet_AppendBytes(&packet, in->fuDigest.buffer,
            in->fuDigest.size);

        TPM2_Packet_AppendSignature(&packet, &in->manifestSignature);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS,
            TPM_CC_FieldUpgradeStart);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 2, 0);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_FieldUpgradeData(FieldUpgradeData_In* in, FieldUpgradeData_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();
    TPM_ST st;

    if (ctx == NULL || in == NULL || out == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        st = TPM2_GetTag(ctx);
        if (st == TPM_ST_SESSIONS) {
            TPM2_Packet_AppendAuth(&packet, ctx->authCmd);
        }

        TPM2_Packet_AppendU16(&packet, in->fuData.size);
        TPM2_Packet_AppendBytes(&packet, in->fuData.buffer, in->fuData.size);

        TPM2_Packet_Finalize(&packet, st, TPM_CC_FieldUpgradeData);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 0, 0);
        if (rc == TPM_RC_SUCCESS) {
            int digestSz;
            UINT32 paramSz = 0;

            if (st == TPM_ST_SESSIONS) {
                TPM2_Packet_ParseU32(&packet, &paramSz);
            }

            TPM2_Packet_ParseU16(&packet, &out->nextDigest.hashAlg);
            digestSz = TPM2_GetHashDigestSize(out->nextDigest.hashAlg);
            TPM2_Packet_ParseBytes(&packet, out->nextDigest.digest.H, digestSz);

            TPM2_Packet_ParseU16(&packet, &out->firstDigest.hashAlg);
            digestSz = TPM2_GetHashDigestSize(out->firstDigest.hashAlg);
            TPM2_Packet_ParseBytes(&packet,
                out->firstDigest.digest.H, digestSz);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_FirmwareRead(FirmwareRead_In* in, FirmwareRead_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();
    TPM_ST st;

    if (ctx == NULL || in == NULL || out == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        st = TPM2_GetTag(ctx);
        if (st == TPM_ST_SESSIONS) {
            TPM2_Packet_AppendAuth(&packet, ctx->authCmd);
        }
        TPM2_Packet_AppendU32(&packet, in->sequenceNumber);
        TPM2_Packet_Finalize(&packet, st, TPM_CC_FirmwareRead);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 0, 0);
        if (rc == TPM_RC_SUCCESS) {
            UINT32 paramSz = 0;

            if (st == TPM_ST_SESSIONS) {
                TPM2_Packet_ParseU32(&packet, &paramSz);
            }

            TPM2_Packet_ParseU16(&packet, &out->fuData.size);
            TPM2_Packet_ParseBytes(&packet, out->fuData.buffer,
                out->fuData.size);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_ContextSave(ContextSave_In* in, ContextSave_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->saveHandle);
        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_ContextSave);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            TPM2_Packet_ParseU64(&packet, &out->context.sequence);
            TPM2_Packet_ParseU32(&packet, &out->context.savedHandle);
            TPM2_Packet_ParseU32(&packet, &out->context.hierarchy);

            TPM2_Packet_ParseU16(&packet, &out->context.contextBlob.size);
            TPM2_Packet_ParseBytes(&packet, out->context.contextBlob.buffer,
                out->context.contextBlob.size);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_ContextLoad(ContextLoad_In* in, ContextLoad_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU64(&packet, in->context.sequence);
        TPM2_Packet_AppendU32(&packet, in->context.savedHandle);
        TPM2_Packet_AppendU32(&packet, in->context.hierarchy);

        TPM2_Packet_AppendU16(&packet, in->context.contextBlob.size);
        TPM2_Packet_AppendBytes(&packet, in->context.contextBlob.buffer,
            in->context.contextBlob.size);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_ContextLoad);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            TPM2_Packet_ParseU32(&packet, &out->loadedHandle);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_EvictControl(EvictControl_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->auth);
        TPM2_Packet_AppendU32(&packet, in->objectHandle);
        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);
        TPM2_Packet_AppendU32(&packet, in->persistentHandle);
        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_EvictControl);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 3, 0);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_ReadClock(ReadClock_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();
    TPM_ST st;

    if (ctx == NULL || out == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        st = TPM2_GetTag(ctx);
        if (st == TPM_ST_SESSIONS) {
            TPM2_Packet_AppendAuth(&packet, ctx->authCmd);
        }
        TPM2_Packet_Finalize(&packet, st, TPM_CC_ReadClock);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 0, 0);
        if (rc == TPM_RC_SUCCESS) {
            UINT32 paramSz = 0;

            if (st == TPM_ST_SESSIONS) {
                TPM2_Packet_ParseU32(&packet, &paramSz);
            }

            TPM2_Packet_ParseU64(&packet, &out->currentTime.time);
            TPM2_Packet_ParseU64(&packet, &out->currentTime.clockInfo.clock);
            TPM2_Packet_ParseU32(&packet,
                &out->currentTime.clockInfo.resetCount);
            TPM2_Packet_ParseU32(&packet,
                &out->currentTime.clockInfo.restartCount);
            TPM2_Packet_ParseU8(&packet, &out->currentTime.clockInfo.safe);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_ClockSet(ClockSet_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->auth);
        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);

        TPM2_Packet_AppendU64(&packet, in->newTime);
        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_ClockSet);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 1, 0);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_ClockRateAdjust(ClockRateAdjust_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->auth);
        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);
        TPM2_Packet_AppendU8(&packet, in->rateAdjust);
        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_ClockRateAdjust);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 1, 0);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_TestParms(TestParms_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();
    TPM_ST st;

    if (ctx == NULL || in == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        st = TPM2_GetTag(ctx);
        if (st == TPM_ST_SESSIONS) {
            TPM2_Packet_AppendAuth(&packet, ctx->authCmd);
        }

        TPM2_Packet_AppendU16(&packet, in->parameters.type);
        TPM2_Packet_AppendPublicParms(&packet, in->parameters.type,
            &in->parameters.parameters);
        TPM2_Packet_Finalize(&packet, st, TPM_CC_TestParms);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 0, 0);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_NV_DefineSpace(NV_DefineSpace_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);

        TPM2_Packet_AppendU16(&packet, in->auth.size);
        TPM2_Packet_AppendBytes(&packet, in->auth.buffer, in->auth.size);

        in->publicInfo.size = 4 + 2 + 4 + 2 +
            in->publicInfo.nvPublic.authPolicy.size + 2;
        TPM2_Packet_AppendU16(&packet, in->publicInfo.size);
        TPM2_Packet_AppendU32(&packet, in->publicInfo.nvPublic.nvIndex);
        TPM2_Packet_AppendU16(&packet, in->publicInfo.nvPublic.nameAlg);
        TPM2_Packet_AppendU32(&packet, in->publicInfo.nvPublic.attributes);

        TPM2_Packet_AppendU16(&packet, in->publicInfo.nvPublic.authPolicy.size);
        TPM2_Packet_AppendBytes(&packet,
            in->publicInfo.nvPublic.authPolicy.buffer,
            in->publicInfo.nvPublic.authPolicy.size);

        TPM2_Packet_AppendU16(&packet, in->publicInfo.nvPublic.dataSize);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_NV_DefineSpace);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 1, 0);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_NV_UndefineSpace(NV_UndefineSpace_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendU32(&packet, in->nvIndex);
        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_NV_UndefineSpace);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 2, 0);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_NV_UndefineSpaceSpecial(NV_UndefineSpaceSpecial_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->nvIndex);
        TPM2_Packet_AppendU32(&packet, in->platform);
        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS,
            TPM_CC_NV_UndefineSpaceSpecial);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 2, 0);

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
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->nvIndex);
        st = TPM2_GetTag(ctx);
        if (st == TPM_ST_SESSIONS) {
            TPM2_Packet_AppendAuth(&packet, ctx->authCmd);
        }

        TPM2_Packet_Finalize(&packet, st, TPM_CC_NV_ReadPublic);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 1, 0);
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

TPM_RC TPM2_NV_Write(NV_Write_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendU32(&packet, in->nvIndex);
        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);

        TPM2_Packet_AppendU16(&packet, in->data.size);
        TPM2_Packet_AppendBytes(&packet, in->data.buffer, in->data.size);

        TPM2_Packet_AppendU16(&packet, in->offset);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_NV_Write);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 2, 0);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_NV_Increment(NV_Increment_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendU32(&packet, in->nvIndex);
        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_NV_Increment);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 2, 0);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_NV_Extend(NV_Extend_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendU32(&packet, in->nvIndex);
        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);

        TPM2_Packet_AppendU16(&packet, in->data.size);
        TPM2_Packet_AppendBytes(&packet, in->data.buffer, in->data.size);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_NV_Extend);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 2, 0);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_NV_SetBits(NV_SetBits_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendU32(&packet, in->nvIndex);
        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);

        TPM2_Packet_AppendU64(&packet, in->bits);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_NV_SetBits);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 2, 0);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_NV_WriteLock(NV_WriteLock_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendU32(&packet, in->nvIndex);
        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_NV_WriteLock);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 2, 0);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_NV_GlobalWriteLock(NV_GlobalWriteLock_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS,
            TPM_CC_NV_GlobalWriteLock);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 1, 0);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_NV_Read(NV_Read_In* in, NV_Read_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendU32(&packet, in->nvIndex);
        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);

        TPM2_Packet_AppendU16(&packet, in->size);
        TPM2_Packet_AppendU16(&packet, in->offset);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_NV_Read);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 2, 0);
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

TPM_RC TPM2_NV_ReadLock(NV_ReadLock_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendU32(&packet, in->nvIndex);
        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_NV_ReadLock);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 2, 0);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_NV_ChangeAuth(NV_ChangeAuth_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->nvIndex);
        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);

        TPM2_Packet_AppendU16(&packet, in->newAuth.size);
        TPM2_Packet_AppendBytes(&packet, in->newAuth.buffer, in->newAuth.size);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_NV_ChangeAuth);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 1, 0);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_NV_Certify(NV_Certify_In* in, NV_Certify_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->signHandle);
        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendU32(&packet, in->nvIndex);
        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);

        TPM2_Packet_AppendU16(&packet, in->qualifyingData.size);
        TPM2_Packet_AppendBytes(&packet, in->qualifyingData.buffer,
            in->qualifyingData.size);

        TPM2_Packet_AppendU16(&packet, in->inScheme.scheme);
        TPM2_Packet_AppendU16(&packet, in->inScheme.details.any.hashAlg);

        TPM2_Packet_AppendU16(&packet, in->size);
        TPM2_Packet_AppendU16(&packet, in->offset);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_NV_Certify);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 3, 0);
        if (rc == TPM_RC_SUCCESS) {
            UINT32 paramSz = 0;

            TPM2_Packet_ParseU32(&packet, &paramSz);

            TPM2_Packet_ParseU16(&packet, &out->certifyInfo.size);
            TPM2_Packet_ParseBytes(&packet, out->certifyInfo.attestationData,
                out->certifyInfo.size);

            TPM2_Packet_ParseSignature(&packet, &out->signature);
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
#ifdef WOLFTPM_ST33
int TPM2_SetCommandSet(SetCommandSet_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);
        TPM2_Packet_AppendU32(&packet, in->commandCode);
        TPM2_Packet_AppendU32(&packet, in->enableFlag);
        TPM2_Packet_AppendU32(&packet, in->lockFlag);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_SetCommandSet);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 1, 0);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

int TPM2_SetMode(SetMode_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || ctx->authCmd == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendAuth(&packet, ctx->authCmd);
        TPM2_Packet_AppendU8(&packet, in->modeSet.CmdToLowPower);
        TPM2_Packet_AppendU8(&packet, in->modeSet.BootToLowPower);
        TPM2_Packet_AppendU8(&packet, in->modeSet.modeLock);
        TPM2_Packet_AppendU8(&packet, in->modeSet.mode);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_SetMode);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, 1, 1, 0);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}
#endif
/******************************************************************************/
/* --- END Manufacture Specific TPM API's -- */
/******************************************************************************/



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

/* Can optionally define WOLFTPM2_USE_HW_RNG to force using TPM hardware for RNG source */
int TPM2_GetNonce(byte* nonceBuf, int nonceSz)
{
    int rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();
#ifdef WOLFTPM2_USE_WOLF_RNG
    WC_RNG* rng = NULL;
#else
    GetRandom_In in;
    GetRandom_Out out;
    int randSz = 0;
#endif

    if (ctx == NULL || nonceBuf == NULL)
        return BAD_FUNC_ARG;

#ifdef WOLFTPM2_USE_WOLF_RNG
    rc = TPM2_GetWolfRng(&rng);
    if (rc == 0) {
        /* Use wolfCrypt */
        rc = wc_RNG_GenerateBlock(rng, nonceBuf, nonceSz);
    }
#else
    /* Use TPM GetRandom */
    XMEMSET(&in, 0, sizeof(in));
    while (randSz < nonceSz) {
        in.bytesRequested = nonceSz - randSz;
        if (in.bytesRequested > sizeof(out.randomBytes.buffer))
            in.bytesRequested = sizeof(out.randomBytes.buffer);

        rc = TPM2_GetRandom(&in, &out);
        if (rc != TPM_RC_SUCCESS)
            break;

        XMEMCPY(&nonceBuf[randSz], out.randomBytes.buffer, out.randomBytes.size);
        randSz += out.randomBytes.size;
    }
#endif

    return rc;
}

void TPM2_SetupPCRSel(TPML_PCR_SELECTION* pcr, TPM_ALG_ID alg, int pcrIndex)
{
    if (pcr) {
        pcr->count = 1;
        pcr->pcrSelections[0].hash = alg;
        pcr->pcrSelections[0].sizeofSelect = PCR_SELECT_MIN;
        XMEMSET(pcr->pcrSelections[0].pcrSelect, 0, PCR_SELECT_MIN);
        pcr->pcrSelections[0].pcrSelect[pcrIndex >> 3] = (1 << (pcrIndex & 0x7));
    }
}


#define TPM_RC_STRINGIFY(rc) #rc
#ifdef DEBUG_WOLFTPM
    #define TPM_RC_STR(rc, desc) case rc: return TPM_RC_STRINGIFY(rc) ": " desc
#else
    #define TPM_RC_STR(rc, desc) case rc: return TPM_RC_STRINGIFY(rc)
#endif

const char* TPM2_GetRCString(int rc)
{
    /* for negative return codes use wolfCrypt */
    if (rc < 0) {
        switch (rc) {
            TPM_RC_STR(TPM_RC_TIMEOUT, "Hardware timeout");
            default:
                break;
        }
    #ifndef WOLFTPM2_NO_WOLFCRYPT
        #if !defined(WOLFCRYPT_ONLY) && \
            (!defined(NO_WOLFSSL_SERVER) || !defined(NO_WOLFSSL_CLIENT))
            /* include TLS error codes */
            return wolfSSL_ERR_reason_error_string(rc);
        #else
            return wc_GetErrorString(rc);
        #endif
    #endif
    }
    else if (rc == 0) {
        return "Success";
    }

    if (rc & RC_VER1) {
        int rc_fm0 = rc & RC_MAX_FM0;

        switch (rc_fm0) {
            TPM_RC_STR(TPM_RC_SUCCESS, "Success");
            TPM_RC_STR(TPM_RC_BAD_TAG, "Bad Tag");
            TPM_RC_STR(TPM_RC_INITIALIZE, "TPM not initialized by TPM2_Startup or already initialized");
            TPM_RC_STR(TPM_RC_FAILURE, "Commands not being accepted because of a TPM failure");
            TPM_RC_STR(TPM_RC_SEQUENCE, "Improper use of a sequence handle");
            TPM_RC_STR(TPM_RC_DISABLED, "The command is disabled");
            TPM_RC_STR(TPM_RC_EXCLUSIVE, "Command failed because audit sequence required exclusivity");
            TPM_RC_STR(TPM_RC_AUTH_TYPE, "Authorization handle is not correct for command");
            TPM_RC_STR(TPM_RC_AUTH_MISSING, "Command requires an authorization session for handle and it is not present");
            TPM_RC_STR(TPM_RC_POLICY, "Policy failure in math operation or an invalid authPolicy value");
            TPM_RC_STR(TPM_RC_PCR, "PCR check fail");
            TPM_RC_STR(TPM_RC_PCR_CHANGED, "PCR have changed since checked");
            TPM_RC_STR(TPM_RC_UPGRADE, "Indicates that the TPM is in field upgrade mode");
            TPM_RC_STR(TPM_RC_TOO_MANY_CONTEXTS, "Context ID counter is at maximum");
            TPM_RC_STR(TPM_RC_AUTH_UNAVAILABLE, "The authValue or authPolicy is not available for selected entity");
            TPM_RC_STR(TPM_RC_REBOOT, "A _TPM_Init and Startup(CLEAR) is required before the TPM can resume operation");
            TPM_RC_STR(TPM_RC_UNBALANCED, "The protection algorithms (hash and symmetric) are not reasonably balanced");
            TPM_RC_STR(TPM_RC_COMMAND_SIZE, "Command commandSize value is inconsistent with contents of the command buffer");
            TPM_RC_STR(TPM_RC_COMMAND_CODE, "Command code not supported");
            TPM_RC_STR(TPM_RC_AUTHSIZE, "The value of authorizationSize is out of range or the number of octets in the Authorization Area is greater than required");
            TPM_RC_STR(TPM_RC_AUTH_CONTEXT, "Use of an authorization session with a context command or another command that cannot have an authorization session");
            TPM_RC_STR(TPM_RC_NV_RANGE, "NV offset+size is out of range");
            TPM_RC_STR(TPM_RC_NV_SIZE, "Requested allocation size is larger than allowed");
            TPM_RC_STR(TPM_RC_NV_LOCKED, "NV access locked");
            TPM_RC_STR(TPM_RC_NV_AUTHORIZATION, "NV access authorization fails in command actions");
            TPM_RC_STR(TPM_RC_NV_UNINITIALIZED, "An NV Index is used before being initialized or the state saved by TPM2_Shutdown(STATE) could not be restored");
            TPM_RC_STR(TPM_RC_NV_SPACE, "Insufficient space for NV allocation");
            TPM_RC_STR(TPM_RC_NV_DEFINED, "NV Index or persistent object already defined");
            TPM_RC_STR(TPM_RC_BAD_CONTEXT, "Context in TPM2_ContextLoad() is not valid");
            TPM_RC_STR(TPM_RC_CPHASH, "The cpHash value already set or not correct for use");
            TPM_RC_STR(TPM_RC_PARENT, "Handle for parent is not a valid parent");
            TPM_RC_STR(TPM_RC_NEEDS_TEST, "Some function needs testing");
            TPM_RC_STR(TPM_RC_NO_RESULT, "Cannot process a request due to an unspecified problem");
            TPM_RC_STR(TPM_RC_SENSITIVE, "The sensitive area did not unmarshal correctly after decryption");
        default:
            break;
        }
    }

    if (rc & RC_FMT1) {
        int rc_fmt1 = rc & RC_MAX_FMT1;

        switch (rc_fmt1) {
            TPM_RC_STR(TPM_RC_ASYMMETRIC, "Asymmetric algorithm not supported or not correct");
            TPM_RC_STR(TPM_RC_ATTRIBUTES, "Inconsistent attributes");
            TPM_RC_STR(TPM_RC_HASH, "Hash algorithm not supported or not appropriate");
            TPM_RC_STR(TPM_RC_VALUE, "Value is out of range or is not correct for the context");
            TPM_RC_STR(TPM_RC_HIERARCHY, "Hierarchy is not enabled or is not correct for the use");
            TPM_RC_STR(TPM_RC_KEY_SIZE, "Key size is not supported");
            TPM_RC_STR(TPM_RC_MGF, "Mask generation function not supported");
            TPM_RC_STR(TPM_RC_MODE, "Mode of operation not supported");
            TPM_RC_STR(TPM_RC_TYPE, "The type of the value is not appropriate for the use");
            TPM_RC_STR(TPM_RC_HANDLE, "The handle is not correct for the use");
            TPM_RC_STR(TPM_RC_KDF, "Unsupported key derivation function or function not appropriate for use");
            TPM_RC_STR(TPM_RC_RANGE, "Value was out of allowed range");
            TPM_RC_STR(TPM_RC_AUTH_FAIL, "The authorization HMAC check failed and DA counter incremented");
            TPM_RC_STR(TPM_RC_NONCE, "Invalid nonce size or nonce value mismatch");
            TPM_RC_STR(TPM_RC_PP, "Authorization requires assertion of PP");
            TPM_RC_STR(TPM_RC_SCHEME, "Unsupported or incompatible scheme");
            TPM_RC_STR(TPM_RC_SIZE, "Structure is the wrong size");
            TPM_RC_STR(TPM_RC_SYMMETRIC, "Unsupported symmetric algorithm or key size, or not appropriate for instance");
            TPM_RC_STR(TPM_RC_TAG, "Incorrect structure tag");
            TPM_RC_STR(TPM_RC_SELECTOR, "Union selector is incorrect");
            TPM_RC_STR(TPM_RC_INSUFFICIENT, "The TPM was unable to unmarshal a value because there were not enough octets in the input buffer");
            TPM_RC_STR(TPM_RC_SIGNATURE, "The signature is not valid");
            TPM_RC_STR(TPM_RC_KEY, "Key fields are not compatible with the selected use");
            TPM_RC_STR(TPM_RC_POLICY_FAIL, "A policy check failed");
            TPM_RC_STR(TPM_RC_INTEGRITY, "Integrity check failed");
            TPM_RC_STR(TPM_RC_TICKET, "Invalid ticket");
            TPM_RC_STR(TPM_RC_RESERVED_BITS, "Reserved bits not set to zero as required");
            TPM_RC_STR(TPM_RC_BAD_AUTH, "Authorization failure without DA implications");
            TPM_RC_STR(TPM_RC_EXPIRED, "The policy has expired");
            TPM_RC_STR(TPM_RC_POLICY_CC, "The commandCode in the policy is not the commandCode of the command or the command code in a policy command references a command that is not implemented");
            TPM_RC_STR(TPM_RC_BINDING, "Public and sensitive portions of an object are not cryptographically bound");
            TPM_RC_STR(TPM_RC_CURVE, "Curve not supported");
            TPM_RC_STR(TPM_RC_ECC_POINT, "Point is not on the required curve");
        default:
            break;
        }
    }

    if (rc & RC_WARN) {
        int rc_warn = rc & RC_MAX_WARN;

        switch (rc_warn) {
            TPM_RC_STR(TPM_RC_CONTEXT_GAP, "Gap for context ID is too large");
            TPM_RC_STR(TPM_RC_OBJECT_MEMORY, "Out of memory for object contexts");
            TPM_RC_STR(TPM_RC_SESSION_MEMORY, "Out of memory for session contexts");
            TPM_RC_STR(TPM_RC_MEMORY, "Out of shared object/session memory or need space for internal operations");
            TPM_RC_STR(TPM_RC_SESSION_HANDLES, "Out of session handles; a session must be flushed before a new session may be created");
            TPM_RC_STR(TPM_RC_OBJECT_HANDLES, "Out of object handles");
            TPM_RC_STR(TPM_RC_LOCALITY, "Bad locality");
            TPM_RC_STR(TPM_RC_YIELDED, "The TPM has suspended operation on the command");
            TPM_RC_STR(TPM_RC_CANCELED, "The command was canceled");
            TPM_RC_STR(TPM_RC_TESTING, "TPM is performing self-tests");
            TPM_RC_STR(TPM_RC_NV_RATE, "The TPM is rate-limiting accesses to prevent wearout of NV");
            TPM_RC_STR(TPM_RC_LOCKOUT, "Authorizations for objects subject to DA protection are not allowed at this time because the TPM is in DA lockout mode");
            TPM_RC_STR(TPM_RC_RETRY, "The TPM was not able to start the command");
            TPM_RC_STR(TPM_RC_NV_UNAVAILABLE, "The command may require writing of NV and NV is not current accessible");
            TPM_RC_STR(TPM_RC_NOT_USED, "This value is reserved and shall not be returned by the TPM");
        default:
            break;
        }
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
            return "CTR";
        case TPM_ALG_OFB:
            return "OFB";
        case TPM_ALG_CBC:
            return "CBC";
        case TPM_ALG_CFB:
            return "CFB";
        case TPM_ALG_ECB:
            return "ECB";
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
#if !defined(WOLFTPM2_NO_WOLFCRYPT) && defined(HAVE_ECC)
    switch (curve_id) {
        case ECC_SECP192R1:
            ret = TPM_ECC_NIST_P192;
            break;
        case ECC_SECP224R1:
            ret = TPM_ECC_NIST_P224;
            break;
        case ECC_SECP256R1:
            ret = TPM_ECC_NIST_P256;
            break;
        case ECC_SECP384R1:
            ret = TPM_ECC_NIST_P384;
            break;
        case ECC_SECP521R1:
            ret = TPM_ECC_NIST_P521;
            break;
        default:
            ret = ECC_CURVE_OID_E;
    }
#endif
    (void)curve_id;
    return ret;
}

int TPM2_GetWolfCurve(int curve_id)
{
    int ret = -1;
#if !defined(WOLFTPM2_NO_WOLFCRYPT) && defined(HAVE_ECC)
    switch (curve_id) {
        case TPM_ECC_NIST_P192:
            ret = ECC_SECP192R1;
            break;
        case TPM_ECC_NIST_P224:
            ret = ECC_SECP224R1;
            break;
        case TPM_ECC_NIST_P256:
            ret = ECC_SECP256R1;
            break;
        case TPM_ECC_NIST_P384:
            ret = ECC_SECP384R1;
            break;
        case TPM_ECC_NIST_P521:
            ret = ECC_SECP521R1;
            break;
        case TPM_ECC_BN_P256:
        case TPM_ECC_BN_P638:
            ret = ECC_CURVE_OID_E;
    }
#endif
    (void)curve_id;
    return ret;
}

#ifdef WOLFTPM2_USE_WOLF_RNG
int TPM2_GetWolfRng(WC_RNG** rng)
{
    int rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL)
        return BAD_FUNC_ARG;

    if (!ctx->rngInit) {
        rc = wc_InitRng(&ctx->rng);
        if (rc < 0) {
        #ifdef DEBUG_WOLFTPM
            printf("wc_InitRng failed %d: %s\n", (int)rc, wc_GetErrorString(rc));
        #endif
            return rc;
        }
        ctx->rngInit = 1;
    }
    if (rng) {
        *rng = &ctx->rng;
    }

    return 0;
}
#endif /* WOLFTPM2_USE_WOLF_RNG */


#ifdef DEBUG_WOLFTPM
#define LINE_LEN 16
void TPM2_PrintBin(const byte* buffer, word32 length)
{
    word32 i;
    char line[80];

    if (!buffer) {
        printf("\tNULL");
        return;
    }

    sprintf(line, "\t");

    for (i = 0; i < LINE_LEN; i++) {
        if (i < length)
            sprintf(line + 1 + i * 3,"%02x ", buffer[i]);
        else
            sprintf(line + 1 + i * 3, "   ");
    }

    sprintf(line + 1 + LINE_LEN * 3, "| ");

    for (i = 0; i < LINE_LEN; i++)
        if (i < length)
            sprintf(line + 3 + LINE_LEN * 3 + i,
                 "%c", 31 < buffer[i] && buffer[i] < 127 ? buffer[i] : '.');

    printf("%s\n", line);

    if (length > LINE_LEN)
        TPM2_PrintBin(buffer + LINE_LEN, length - LINE_LEN);
}
#endif

/******************************************************************************/
/* --- END Helpful API's -- */
/******************************************************************************/
