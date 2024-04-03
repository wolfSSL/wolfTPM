/* tpm2.c
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
#ifndef WOLFTPM2_NO_WOLFCRYPT
static volatile int gWolfCryptRefCount = 0;
#endif

#ifdef WOLFTPM_LINUX_DEV
#define INTERNAL_SEND_COMMAND      TPM2_LINUX_SendCommand
#define TPM2_INTERNAL_CLEANUP(ctx)
#elif defined(WOLFTPM_SWTPM)
#define INTERNAL_SEND_COMMAND      TPM2_SWTPM_SendCommand
#define TPM2_INTERNAL_CLEANUP(ctx)
#elif defined(WOLFTPM_WINAPI)
#define INTERNAL_SEND_COMMAND      TPM2_WinApi_SendCommand
#define TPM2_INTERNAL_CLEANUP(ctx) TPM2_WinApi_Cleanup(ctx)
#else
#define INTERNAL_SEND_COMMAND      TPM2_TIS_SendCommand
#define TPM2_INTERNAL_CLEANUP(ctx)
#endif

/******************************************************************************/
/* --- Local Functions -- */
/******************************************************************************/
static TPM_RC TPM2_AcquireLock(TPM2_CTX* ctx)
{
#if defined(WOLFTPM2_NO_WOLFCRYPT) || defined(WOLFTPM_NO_LOCK)
    (void)ctx;
#else
    int ret;

    if (!ctx->hwLockInit) {
        if (wc_InitMutex(&ctx->hwLock) != 0) {
        #ifdef DEBUG_WOLFTPM
            printf("TPM Mutex Init failed\n");
        #endif
            return TPM_RC_FAILURE;
        }
        ctx->hwLockInit = 1;
        ctx->lockCount = 0;
    }

    if (ctx->lockCount == 0) {
        ret = wc_LockMutex(&ctx->hwLock);
        if (ret != 0)
            return TPM_RC_FAILURE;
    }
    ctx->lockCount++;
#endif
    return TPM_RC_SUCCESS;
}

static void TPM2_ReleaseLock(TPM2_CTX* ctx)
{
#if defined(WOLFTPM2_NO_WOLFCRYPT) || defined(WOLFTPM_NO_LOCK)
    (void)ctx;
#else
    ctx->lockCount--;
    if (ctx->lockCount == 0) {
        wc_UnLockMutex(&ctx->hwLock);
    }

#endif
}

static int TPM2_CommandProcess(TPM2_CTX* ctx, TPM2_Packet* packet,
    CmdInfo_t* info, TPM_CC cmdCode, UINT32 cmdSz)
{
    int rc = TPM_RC_SUCCESS;
    UINT32 authSz;
    BYTE *param, *encParam = NULL;
    int paramSz, encParamSz = 0;
    int i, authPos;
    int tmpSz = 0; /* Used to calculate the new total size of the Auth Area */
#ifndef WOLFTPM2_NO_WOLFCRYPT
    UINT32 handleValue1, handleValue2, handleValue3;
    int handlePos;
#endif

    /* Skip the header and handles area */
    packet->pos = TPM2_HEADER_SIZE + (info->inHandleCnt * sizeof(TPM_HANDLE));

    /* Parse Auth */
    TPM2_Packet_ParseU32(packet, &authSz);
    packet->pos -= sizeof(authSz);
    /* Later Auth Area size is updated */
    TPM2_Packet_MarkU32(packet, &tmpSz);
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

#ifdef WOLFTPM_DEBUG_VERBOSE
    printf("CommandProcess: Handles (Auth %d, In %d), CmdSz %d, AuthSz %d, ParamSz %d, EncSz %d\n",
        info->authCnt, info->inHandleCnt, (int)cmdSz, (int)authSz, paramSz, encParamSz);
#else
    (void)paramSz;
#endif

    /* Get Handle */
#ifndef WOLFTPM2_NO_WOLFCRYPT
    handlePos = packet->pos;
    packet->pos = TPM2_HEADER_SIZE; /* Handles are right after header */
    TPM2_Packet_ParseU32(packet, &handleValue1);
    TPM2_Packet_ParseU32(packet, &handleValue2);
    TPM2_Packet_ParseU32(packet, &handleValue3);
    packet->pos = handlePos;
#endif

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

        /* Note: Copy between TPM2_AUTH_SESSION and TPMS_AUTH_COMMAND is allowed */
        XMEMCPY(&authCmd, session, sizeof(TPMS_AUTH_COMMAND));

        if (TPM2_IS_HMAC_SESSION(session->sessionHandle) ||
            TPM2_IS_POLICY_SESSION(session->sessionHandle))
        {
        #ifndef WOLFTPM2_NO_WOLFCRYPT
            TPM2B_NAME name1, name2, name3;
            TPM2B_DIGEST hash;
        #endif

            /* if param enc is not supported for this command then clear flag */
            /* session attribute flags are from TPM perspective */
            if ((info->flags & (CMD_FLAG_ENC2 | CMD_FLAG_ENC4)) == 0) {
                authCmd.sessionAttributes &= ~TPMA_SESSION_decrypt;
            }
            if ((info->flags & (CMD_FLAG_DEC2 | CMD_FLAG_DEC4)) == 0) {
                authCmd.sessionAttributes &= ~TPMA_SESSION_encrypt;
            }

            /* Handle session request for encryption */
            if (encParam && authCmd.sessionAttributes & TPMA_SESSION_decrypt) {
                /* Encrypt the first command parameter */
                rc = TPM2_ParamEnc_CmdRequest(session, encParam, encParamSz);
                if (rc != TPM_RC_SUCCESS) {
            #ifdef DEBUG_WOLFTPM
                    printf("Command parameter encryption failed\n");
            #endif
                    return rc;
                }
            }

        #if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_HMAC)
            rc =  TPM2_GetName(ctx, handleValue1, info->inHandleCnt, 0, &name1);
            rc |= TPM2_GetName(ctx, handleValue2, info->inHandleCnt, 1, &name2);
            rc |= TPM2_GetName(ctx, handleValue3, info->inHandleCnt, 2, &name3);
            if (rc != TPM_RC_SUCCESS) {
            #ifdef DEBUG_WOLFTPM
                printf("Error getting names for cpHash!\n");
            #endif
                return BAD_FUNC_ARG;
            }

            /* calculate "cpHash" hash for command code, names and parameters */
            rc = TPM2_CalcCpHash(session->authHash, cmdCode, &name1,
                &name2, &name3, param, paramSz, &hash);
            if (rc != TPM_RC_SUCCESS) {
            #ifdef DEBUG_WOLFTPM
                printf("Error calculating cpHash!\n");
            #endif
                return rc;
            }
            /* Calculate HMAC for policy, hmac or salted sessions */
            /* this is done after encryption */
            rc = TPM2_CalcHmac(session->authHash, &session->auth, &hash,
                &session->nonceCaller, &session->nonceTPM,
                authCmd.sessionAttributes, &authCmd.hmac);
            if (rc != TPM_RC_SUCCESS) {
            #ifdef DEBUG_WOLFTPM
                printf("Error calculating command HMAC!\n");
            #endif
                return rc;
            }
        #endif /* !WOLFTPM2_NO_WOLFCRYPT && !NO_HMAC */
        }

        /* Replace auth in session */
        packet->pos = authPos;
        TPM2_Packet_AppendAuthCmd(packet, &authCmd);
        authPos = packet->pos; /* update auth position */
    }

    /* Update the Auth Area size in the command packet */
    TPM2_Packet_PlaceU32(packet, tmpSz);

    (void)cmdCode;
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

#ifdef WOLFTPM_DEBUG_VERBOSE
    printf("ResponseProcess: Handles (Out %d), RespSz %d, ParamSz %d, DecSz %d, AuthSz %d\n",
        info->outHandleCnt, (int)respSz, (int)paramSz, (int)decParamSz, (int)(respSz - authPos));
#endif

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

        #if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_HMAC)
            if (authRsp.hmac.size > 0) {
                TPM2B_DIGEST hash;
                TPM2B_AUTH hmac;

                /* calculate "rpHash" hash for command code and parameters */
                rc = TPM2_CalcRpHash(session->authHash, cmdCode, param, paramSz,
                    &hash);
                if (rc != TPM_RC_SUCCESS) {
                #ifdef DEBUG_WOLFTPM
                    printf("Error calculating rpHash!\n");
                #endif
                    return rc;
                }

                /* Calculate HMAC prior to decryption */
                rc = TPM2_CalcHmac(session->authHash, &session->auth, &hash,
                    &session->nonceTPM, &session->nonceCaller,
                    authRsp.sessionAttributes, &hmac);
                if (rc != TPM_RC_SUCCESS) {
                #ifdef DEBUG_WOLFTPM
                    printf("Error calculating response HMAC!\n");
                #endif
                    return rc;
                }

                /* Verify HMAC */
                if (hmac.size != authRsp.hmac.size ||
                    XMEMCMP(hmac.buffer, authRsp.hmac.buffer, hmac.size) != 0) {
                #ifdef DEBUG_WOLFTPM
                    printf("Response HMAC verification failed!\n");
                #endif
                    return TPM_RC_HMAC;
                }
            }
        #else
            (void)cmdCode;
        #endif /* !WOLFTPM2_NO_WOLFCRYPT && !NO_HMAC */

            /* Handle session request for decryption */
            /* If the response supports decryption */
            if (decParam && authRsp.sessionAttributes & TPMA_SESSION_encrypt) {
                /* Decrypt the first response parameter */
                rc = TPM2_ParamDec_CmdResponse(session, decParam, decParamSz);
                if (rc != TPM_RC_SUCCESS) {
            #ifdef DEBUG_WOLFTPM
                    printf("Response parameter decryption failed\n");
            #endif
                    return rc;
                }
            }
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

    #ifdef WOLFTPM_DEBUG_VERBOSE
        printf("Found %d auth sessions\n", info->authCnt);
    #endif

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

#ifndef WOLFTPM2_NO_WOLFCRYPT
#ifdef HAVE_FIPS
static void WolfFipsCb(int ok, int err, const char* hash)
{
    printf("in my Fips callback, ok = %d, err = %d\n", ok, err);
    printf("message = %s\n", wc_GetErrorString(err));
    printf("hash = %s\n", hash);

    if (err == IN_CORE_FIPS_E) {
        printf("In core integrity hash check failure, copy above hash\n");
        printf("into verifyCore[] in fips_test.c and rebuild\n");
    }
}
#endif
static inline int TPM2_WolfCrypt_Init(void)
{
    int rc = 0;

    /* track reference count for wolfCrypt initialization */
    if (gWolfCryptRefCount == 0) {
    #ifdef DEBUG_WOLFSSL
        wolfSSL_Debugging_ON();
    #endif
    #ifdef HAVE_FIPS
        wolfCrypt_SetCb_fips(WolfFipsCb);
    #endif
        rc = wolfCrypt_Init();
    #ifdef WC_RNG_SEED_CB
        if (rc == 0)
            rc = wc_SetSeed_Cb(wc_GenerateSeed);
    #endif
    }
    gWolfCryptRefCount++;

    return rc;
}
#endif

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

#ifndef WOLFTPM2_NO_WOLFCRYPT
    rc = TPM2_WolfCrypt_Init();
    if (rc != 0)
        return rc;
#endif

#if defined(WOLFTPM_SWTPM)
    ctx->tcpCtx.fd = -1;
#endif

#if defined(WOLFTPM_LINUX_DEV) || defined(WOLFTPM_SWTPM) || \
    defined(WOLFTPM_WINAPI)
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

#ifndef WOLFTPM2_NO_WOLFCRYPT
    #ifdef WOLFTPM2_USE_WOLF_RNG
    if (ctx->rngInit) {
        ctx->rngInit = 0;
        wc_FreeRng(&ctx->rng);
    }
    #endif
    #ifndef WOLFTPM_NO_LOCK
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
                case TPM_CAP_TPM_PROPERTIES:
                {
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
                case TPM_CAP_HANDLES:
                {
                    TPML_HANDLE* handles =
                        &out->capabilityData.data.handles;
                    TPM2_Packet_ParseU32(&packet, &handles->count);
                    for (i=0; i<(int)handles->count; i++) {
                        TPM2_Packet_ParseU32(&packet, &handles->handle[i]);
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
            #ifdef DEBUG_WOLFTPM
                    printf("Unknown capability type 0x%x\n",
                        (unsigned int)out->capabilityData.capability);
            #endif
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


TPM_RC TPM2_Load(Load_In* in, Load_Out* out)
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
        TPM2_Packet_AppendU32(&packet, in->parentHandle);
        TPM2_Packet_AppendAuth(&packet, ctx, &info);
        TPM2_Packet_AppendU16(&packet, in->inPrivate.size);
        TPM2_Packet_AppendBytes(&packet, in->inPrivate.buffer,
            in->inPrivate.size);
        TPM2_Packet_AppendPublic(&packet, &in->inPublic);
        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_Load);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);
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

    if (ctx == NULL || in == NULL || out == NULL || ctx->session == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        CmdInfo_t info = {0,0,0,0};
        info.inHandleCnt = 1;
        info.flags = (CMD_FLAG_DEC2 | CMD_FLAG_AUTH_USER1);

        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->itemHandle);
        TPM2_Packet_AppendAuth(&packet, ctx, &info);
        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_Unseal);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);
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

TPM_RC TPM2_ActivateCredential(ActivateCredential_In* in,
    ActivateCredential_Out* out)
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
        info.flags = (CMD_FLAG_ENC2 | CMD_FLAG_DEC2 | CMD_FLAG_AUTH_ADMIN |
            CMD_FLAG_AUTH_USER2);

        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->activateHandle);
        TPM2_Packet_AppendU32(&packet, in->keyHandle);
        TPM2_Packet_AppendAuth(&packet, ctx, &info);
        TPM2_Packet_AppendU16(&packet, in->credentialBlob.size);
        TPM2_Packet_AppendBytes(&packet, in->credentialBlob.buffer,
            in->credentialBlob.size);
        TPM2_Packet_AppendU16(&packet, in->secret.size);
        TPM2_Packet_AppendBytes(&packet, in->secret.secret, in->secret.size);
        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS,
            TPM_CC_ActivateCredential);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);
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

    if (ctx == NULL || in == NULL || out == NULL || ctx->session == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        CmdInfo_t info = {0,0,0,0};
        info.inHandleCnt = 2;
        info.flags = (CMD_FLAG_ENC2 | CMD_FLAG_DEC2 | CMD_FLAG_AUTH_ADMIN);

        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->objectHandle);
        TPM2_Packet_AppendU32(&packet, in->parentHandle);

        TPM2_Packet_AppendAuth(&packet, ctx, &info);

        TPM2_Packet_AppendU16(&packet, in->newAuth.size);
        TPM2_Packet_AppendBytes(&packet, in->newAuth.buffer,
            in->newAuth.size);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_ObjectChangeAuth);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);
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

    if (ctx == NULL || in == NULL || out == NULL || ctx->session == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        CmdInfo_t info = {0,0,0,0};
        info.inHandleCnt = 2;
        info.flags = (CMD_FLAG_ENC2 | CMD_FLAG_DEC2 | CMD_FLAG_AUTH_DUP);

        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->objectHandle);
        TPM2_Packet_AppendU32(&packet, in->newParentHandle);

        TPM2_Packet_AppendAuth(&packet, ctx, &info);

        TPM2_Packet_AppendU16(&packet, in->encryptionKeyIn.size);
        TPM2_Packet_AppendBytes(&packet, in->encryptionKeyIn.buffer,
            in->encryptionKeyIn.size);

        TPM2_Packet_AppendU16(&packet, in->symmetricAlg.algorithm);
        TPM2_Packet_AppendU16(&packet, in->symmetricAlg.keyBits.sym);
        TPM2_Packet_AppendU16(&packet, in->symmetricAlg.mode.sym);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_Duplicate);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);
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

    if (ctx == NULL || in == NULL || out == NULL || ctx->session == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        CmdInfo_t info = {0,0,0,0};
        info.inHandleCnt = 2;
        info.flags = (CMD_FLAG_ENC2 | CMD_FLAG_DEC2 | CMD_FLAG_AUTH_USER1);

        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->oldParent);
        TPM2_Packet_AppendU32(&packet, in->newParent);

        TPM2_Packet_AppendAuth(&packet, ctx, &info);

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
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);
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
        CmdInfo_t info = {0,0,0,0};
        info.inHandleCnt = 1;
        info.flags = (CMD_FLAG_ENC2 | CMD_FLAG_DEC2 | CMD_FLAG_AUTH_USER1);

        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->parentHandle);
        TPM2_Packet_AppendAuth(&packet, ctx, &info);
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
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);
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
        CmdInfo_t info = {0,0,0,0};
        info.inHandleCnt = 1;
        info.flags = (CMD_FLAG_DEC2);

        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->keyHandle);

        st = TPM2_Packet_AppendAuth(&packet, ctx, &info);
        TPM2_Packet_Finalize(&packet, st, TPM_CC_ECDH_KeyGen);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);
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
        TPM2_Packet_AppendPoint(&packet, &in->inPoint);
        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_ECDH_ZGen);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);
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

    if (ctx == NULL || in == NULL || out == NULL || ctx->session == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        CmdInfo_t info = {0,0,0,0};
        info.inHandleCnt = 1;
        info.flags = (CMD_FLAG_ENC2 | CMD_FLAG_DEC2 | CMD_FLAG_AUTH_USER1);

        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->keyA);
        TPM2_Packet_AppendAuth(&packet, ctx, &info);
        TPM2_Packet_AppendPoint(&packet, &in->inQsB);
        TPM2_Packet_AppendPoint(&packet, &in->inQeB);
        TPM2_Packet_AppendU16(&packet, in->inScheme);
        TPM2_Packet_AppendU16(&packet, in->counter);
        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_ZGen_2Phase);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);
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

TPM_RC TPM2_HMAC(HMAC_In* in, HMAC_Out* out)
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

        TPM2_Packet_AppendU32(&packet, in->handle);
        TPM2_Packet_AppendAuth(&packet, ctx, &info);

        TPM2_Packet_AppendU16(&packet, in->buffer.size);
        TPM2_Packet_AppendBytes(&packet, in->buffer.buffer, in->buffer.size);

        TPM2_Packet_AppendU16(&packet, in->hashAlg);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_HMAC);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);
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

    if (ctx == NULL || in == NULL || out == NULL || ctx->session == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        CmdInfo_t info = {0,0,0,0};
        info.inHandleCnt = 1;
        info.outHandleCnt = 1;
        info.flags = (CMD_FLAG_ENC2 | CMD_FLAG_AUTH_USER1);

        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->handle);
        TPM2_Packet_AppendAuth(&packet, ctx, &info);

        TPM2_Packet_AppendU16(&packet, in->auth.size);
        TPM2_Packet_AppendBytes(&packet, in->auth.buffer, in->auth.size);

        TPM2_Packet_AppendU16(&packet, in->hashAlg);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_HMAC_Start);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);
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

TPM_RC TPM2_EventSequenceComplete(EventSequenceComplete_In* in,
    EventSequenceComplete_Out* out)
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
        info.flags = (CMD_FLAG_ENC2 | CMD_FLAG_AUTH_USER1 |
            CMD_FLAG_AUTH_USER2);

        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->pcrHandle);
        TPM2_Packet_AppendU32(&packet, in->sequenceHandle);

        TPM2_Packet_AppendAuth(&packet, ctx, &info);

        TPM2_Packet_AppendU16(&packet, in->buffer.size);
        TPM2_Packet_AppendBytes(&packet, in->buffer.buffer, in->buffer.size);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS,
            TPM_CC_EventSequenceComplete);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);
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

    if (ctx == NULL || in == NULL || out == NULL || ctx->session == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        CmdInfo_t info = {0,0,0,0};
        info.inHandleCnt = 2;
        info.flags = (CMD_FLAG_ENC2 | CMD_FLAG_DEC2 | CMD_FLAG_AUTH_ADMIN |
            CMD_FLAG_AUTH_USER2);

        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->objectHandle);
        TPM2_Packet_AppendU32(&packet, in->signHandle);

        TPM2_Packet_AppendAuth(&packet, ctx, &info);

        TPM2_Packet_AppendU16(&packet, in->qualifyingData.size);
        TPM2_Packet_AppendBytes(&packet, in->qualifyingData.buffer,
            in->qualifyingData.size);

        TPM2_Packet_AppendU16(&packet, in->inScheme.scheme);
        TPM2_Packet_AppendU16(&packet, in->inScheme.details.any.hashAlg);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_Certify);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);
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

    if (ctx == NULL || in == NULL || out == NULL || ctx->session == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        CmdInfo_t info = {0,0,0,0};
        info.inHandleCnt = 2;
        info.flags = (CMD_FLAG_ENC2 | CMD_FLAG_DEC2 | CMD_FLAG_AUTH_USER1);

        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->signHandle);
        TPM2_Packet_AppendU32(&packet, in->objectHandle);

        TPM2_Packet_AppendAuth(&packet, ctx, &info);

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
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);
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

    if (ctx == NULL || in == NULL || out == NULL || ctx->session == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        CmdInfo_t info = {0,0,0,0};
        info.inHandleCnt = 1;
        info.flags = (CMD_FLAG_ENC2 | CMD_FLAG_DEC2 | CMD_FLAG_AUTH_USER1);

        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->signHandle);

        TPM2_Packet_AppendAuth(&packet, ctx, &info);

        TPM2_Packet_AppendU16(&packet, in->qualifyingData.size);
        TPM2_Packet_AppendBytes(&packet, in->qualifyingData.buffer,
            in->qualifyingData.size);

        TPM2_Packet_AppendU16(&packet, in->inScheme.scheme);
        TPM2_Packet_AppendU16(&packet, in->inScheme.details.any.hashAlg);

        TPM2_Packet_AppendPCR(&packet, &in->PCRselect);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_Quote);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);
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

    if (ctx == NULL || in == NULL || out == NULL || ctx->session == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        CmdInfo_t info = {0,0,0,0};
        info.inHandleCnt = 2;
        info.flags = (CMD_FLAG_ENC2 | CMD_FLAG_DEC2 | CMD_FLAG_AUTH_USER1 |
            CMD_FLAG_AUTH_USER2);

        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->privacyAdminHandle);
        TPM2_Packet_AppendU32(&packet, in->signHandle);
        TPM2_Packet_AppendU32(&packet, in->sessionHandle);

        TPM2_Packet_AppendAuth(&packet, ctx, &info);

        TPM2_Packet_AppendU16(&packet, in->qualifyingData.size);
        TPM2_Packet_AppendBytes(&packet, in->qualifyingData.buffer,
            in->qualifyingData.size);

        TPM2_Packet_AppendU16(&packet, in->inScheme.scheme);
        TPM2_Packet_AppendU16(&packet, in->inScheme.details.any.hashAlg);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS,
            TPM_CC_GetSessionAuditDigest);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);
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

    if (ctx == NULL || in == NULL || out == NULL || ctx->session == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        CmdInfo_t info = {0,0,0,0};
        info.inHandleCnt = 2;
        info.flags = (CMD_FLAG_ENC2 | CMD_FLAG_DEC2 | CMD_FLAG_AUTH_USER1 |
            CMD_FLAG_AUTH_USER2);

        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->privacyHandle);
        TPM2_Packet_AppendU32(&packet, in->signHandle);

        TPM2_Packet_AppendAuth(&packet, ctx, &info);

        TPM2_Packet_AppendU16(&packet, in->qualifyingData.size);
        TPM2_Packet_AppendBytes(&packet, in->qualifyingData.buffer,
            in->qualifyingData.size);

        TPM2_Packet_AppendU16(&packet, in->inScheme.scheme);
        TPM2_Packet_AppendU16(&packet, in->inScheme.details.any.hashAlg);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS,
            TPM_CC_GetCommandAuditDigest);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);
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

    if (ctx == NULL || in == NULL || out == NULL || ctx->session == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        CmdInfo_t info = {0,0,0,0};
        info.inHandleCnt = 2;
        info.flags = (CMD_FLAG_ENC2 | CMD_FLAG_DEC2 | CMD_FLAG_AUTH_USER1 |
            CMD_FLAG_AUTH_USER2);

        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->privacyAdminHandle);
        TPM2_Packet_AppendU32(&packet, in->signHandle);

        TPM2_Packet_AppendAuth(&packet, ctx, &info);

        TPM2_Packet_AppendU16(&packet, in->qualifyingData.size);
        TPM2_Packet_AppendBytes(&packet, in->qualifyingData.buffer,
            in->qualifyingData.size);

        TPM2_Packet_AppendU16(&packet, in->inScheme.scheme);
        TPM2_Packet_AppendU16(&packet, in->inScheme.details.any.hashAlg);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_GetTime);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);
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

    if (ctx == NULL || in == NULL || out == NULL || ctx->session == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        CmdInfo_t info = {0,0,0,0};
        info.inHandleCnt = 1;
        info.flags = (CMD_FLAG_ENC2 | CMD_FLAG_DEC2 | CMD_FLAG_AUTH_USER1);

        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->signHandle);

        TPM2_Packet_AppendAuth(&packet, ctx, &info);

        TPM2_Packet_AppendPoint(&packet, &in->P1);

        TPM2_Packet_AppendU16(&packet, in->s2.size);
        TPM2_Packet_AppendBytes(&packet, in->s2.buffer, in->s2.size);

        TPM2_Packet_AppendU16(&packet, in->y2.size);
        TPM2_Packet_AppendBytes(&packet, in->y2.buffer, in->y2.size);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_Commit);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);
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
        CmdInfo_t info = {0,0,0,0};
        info.flags = (CMD_FLAG_DEC2);

        TPM2_Packet_Init(ctx, &packet);
        st = TPM2_Packet_AppendAuth(&packet, ctx, &info);
        TPM2_Packet_AppendU32(&packet, in->curveID);
        TPM2_Packet_Finalize(&packet, st, TPM_CC_EC_Ephemeral);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);
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
        CmdInfo_t info = {0,0,0,0};
        info.inHandleCnt = 1;
        info.flags = (CMD_FLAG_ENC2);

        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->keyHandle);

        st = TPM2_Packet_AppendAuth(&packet, ctx, &info);

        TPM2_Packet_AppendU16(&packet, in->digest.size);
        TPM2_Packet_AppendBytes(&packet, in->digest.buffer, in->digest.size);

        TPM2_Packet_AppendSignature(&packet, &in->signature);

        TPM2_Packet_Finalize(&packet, st, TPM_CC_VerifySignature);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);
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

    if (ctx == NULL || in == NULL || out == NULL || ctx->session == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        CmdInfo_t info = {0,0,0,0};
        info.inHandleCnt = 1;
        info.flags = (CMD_FLAG_ENC2 | CMD_FLAG_AUTH_USER1);

        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->keyHandle);

        TPM2_Packet_AppendAuth(&packet, ctx, &info);

        TPM2_Packet_AppendU16(&packet, in->digest.size);
        TPM2_Packet_AppendBytes(&packet, in->digest.buffer, in->digest.size);

        TPM2_Packet_AppendU16(&packet, in->inScheme.scheme);
        if (in->inScheme.scheme != TPM_ALG_NULL) {
            TPM2_Packet_AppendU16(&packet, in->inScheme.details.any.hashAlg);
        }

        TPM2_Packet_AppendU16(&packet, in->validation.tag);
        TPM2_Packet_AppendU32(&packet, in->validation.hierarchy);

        TPM2_Packet_AppendU16(&packet, in->validation.digest.size);
        TPM2_Packet_AppendBytes(&packet, in->validation.digest.buffer,
            in->validation.digest.size);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_Sign);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);
        if (rc == TPM_RC_SUCCESS) {
            UINT32 paramSz = 0;

            TPM2_Packet_ParseU32(&packet, &paramSz);
            TPM2_Packet_ParseSignature(&packet, &out->signature);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_SetCommandCodeAuditStatus(SetCommandCodeAuditStatus_In* in)
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

        TPM2_Packet_AppendU32(&packet, in->auth);

        TPM2_Packet_AppendAuth(&packet, ctx, &info);

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
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_PCR_Event(PCR_Event_In* in, PCR_Event_Out* out)
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
        info.flags = (CMD_FLAG_ENC2 | CMD_FLAG_AUTH_USER1);

        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->pcrHandle);
        TPM2_Packet_AppendAuth(&packet, ctx, &info);

        TPM2_Packet_AppendU16(&packet, in->eventData.size);
        TPM2_Packet_AppendBytes(&packet, in->eventData.buffer,
            in->eventData.size);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_PCR_Event);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);
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

    if (ctx == NULL || in == NULL || out == NULL || ctx->session == NULL)
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

        TPM2_Packet_AppendPCR(&packet, &in->pcrAllocation);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_PCR_Allocate);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);
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

    if (ctx == NULL || in == NULL || ctx->session == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        CmdInfo_t info = {0,0,0,0};
        info.inHandleCnt = 1;
        info.flags = (CMD_FLAG_ENC2);

        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendAuth(&packet, ctx, &info);

        TPM2_Packet_AppendU16(&packet, in->authPolicy.size);
        TPM2_Packet_AppendBytes(&packet, in->authPolicy.buffer,
            in->authPolicy.size);

        TPM2_Packet_AppendU16(&packet, in->hashAlg);
        TPM2_Packet_AppendU32(&packet, in->pcrNum);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS,
            TPM_CC_PCR_SetAuthPolicy);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_PCR_SetAuthValue(PCR_SetAuthValue_In* in)
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

        TPM2_Packet_AppendU32(&packet, in->pcrHandle);
        TPM2_Packet_AppendAuth(&packet, ctx, &info);

        TPM2_Packet_AppendU16(&packet, in->auth.size);
        TPM2_Packet_AppendBytes(&packet, in->auth.buffer, in->auth.size);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_PCR_SetAuthValue);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);

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
        CmdInfo_t info = {0,0,0,0};
        info.inHandleCnt = 2;
        info.flags = (CMD_FLAG_ENC2 | CMD_FLAG_DEC2);

        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->authObject);
        TPM2_Packet_AppendU32(&packet, in->policySession);

        st = TPM2_Packet_AppendAuth(&packet, ctx, &info);

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
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);
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

    if (ctx == NULL || in == NULL || out == NULL || ctx->session == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        CmdInfo_t info = {0,0,0,0};
        info.inHandleCnt = 2;
        info.flags = (CMD_FLAG_ENC2 | CMD_FLAG_DEC2 | CMD_FLAG_AUTH_USER1);

        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendU32(&packet, in->policySession);

        TPM2_Packet_AppendAuth(&packet, ctx, &info);

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
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);
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
        CmdInfo_t info = {0,0,0,0};
        info.inHandleCnt = 1;
        info.flags = (CMD_FLAG_ENC2);

        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->policySession);

        st = TPM2_Packet_AppendAuth(&packet, ctx, &info);

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
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);

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

    if (ctx == NULL || in == NULL || ctx->session == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        CmdInfo_t info = {0,0,0,0};
        info.inHandleCnt = 3;
        info.flags = (CMD_FLAG_ENC2 | CMD_FLAG_AUTH_USER1);

        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendU32(&packet, in->nvIndex);
        TPM2_Packet_AppendU32(&packet, in->policySession);

        TPM2_Packet_AppendAuth(&packet, ctx, &info);

        TPM2_Packet_AppendU16(&packet, in->operandB.size);
        TPM2_Packet_AppendBytes(&packet, in->operandB.buffer,
            in->operandB.size);

        TPM2_Packet_AppendU16(&packet, in->offset);
        TPM2_Packet_AppendU16(&packet, in->operation);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_PolicyNV);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);

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
        CmdInfo_t info = {0,0,0,0};
        info.inHandleCnt = 1;
        info.flags = (CMD_FLAG_ENC2);

        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->policySession);

        st = TPM2_Packet_AppendAuth(&packet, ctx, &info);

        TPM2_Packet_AppendU16(&packet, in->operandB.size);
        TPM2_Packet_AppendBytes(&packet, in->operandB.buffer,
            in->operandB.size);

        TPM2_Packet_AppendU16(&packet, in->offset);
        TPM2_Packet_AppendU16(&packet, in->operation);

        TPM2_Packet_Finalize(&packet, st, TPM_CC_PolicyCounterTimer);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);

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
        CmdInfo_t info = {0,0,0,0};
        info.inHandleCnt = 1;
        info.flags = (CMD_FLAG_ENC2);

        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->policySession);
        st = TPM2_Packet_AppendAuth(&packet, ctx, &info);

        TPM2_Packet_AppendU16(&packet, in->cpHashA.size);
        TPM2_Packet_AppendBytes(&packet, in->cpHashA.buffer, in->cpHashA.size);

        TPM2_Packet_Finalize(&packet, st, TPM_CC_PolicyCpHash);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);

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
        CmdInfo_t info = {0,0,0,0};
        info.inHandleCnt = 1;
        info.flags = (CMD_FLAG_ENC2);

        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->policySession);
        st = TPM2_Packet_AppendAuth(&packet, ctx, &info);

        TPM2_Packet_AppendU16(&packet, in->nameHash.size);
        TPM2_Packet_AppendBytes(&packet, in->nameHash.buffer,
            in->nameHash.size);

        TPM2_Packet_Finalize(&packet, st, TPM_CC_PolicyNameHash);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);

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
        CmdInfo_t info = {0,0,0,0};
        info.inHandleCnt = 1;
        info.flags = (CMD_FLAG_ENC2);

        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->policySession);
        st = TPM2_Packet_AppendAuth(&packet, ctx, &info);

        TPM2_Packet_AppendU16(&packet, in->objectName.size);
        TPM2_Packet_AppendBytes(&packet, in->objectName.name,
            in->objectName.size);

        TPM2_Packet_AppendU16(&packet, in->newParentName.size);
        TPM2_Packet_AppendBytes(&packet, in->newParentName.name,
            in->newParentName.size);

        TPM2_Packet_AppendU8(&packet, in->includeObject);

        TPM2_Packet_Finalize(&packet, st, TPM_CC_PolicyDuplicationSelect);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);

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
        CmdInfo_t info = {0,0,0,0};
        info.inHandleCnt = 1;
        info.flags = (CMD_FLAG_ENC2);

        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->policySession);
        st = TPM2_Packet_AppendAuth(&packet, ctx, &info);

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
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);

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
        CmdInfo_t info = {0,0,0,0};
        info.inHandleCnt = 1;
        info.flags = (CMD_FLAG_DEC2);

        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->policySession);
        st = TPM2_Packet_AppendAuth(&packet, ctx, &info);
        TPM2_Packet_Finalize(&packet, st, TPM_CC_PolicyGetDigest);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);
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
        CmdInfo_t info = {0,0,0,0};
        info.inHandleCnt = 1;
        info.flags = (CMD_FLAG_ENC2);

        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->policySession);
        st = TPM2_Packet_AppendAuth(&packet, ctx, &info);
        TPM2_Packet_AppendU16(&packet, in->templateHash.size);
        TPM2_Packet_AppendBytes(&packet, in->templateHash.buffer,
            in->templateHash.size);
        TPM2_Packet_Finalize(&packet, st, TPM_CC_PolicyTemplate);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_PolicyAuthorizeNV(PolicyAuthorizeNV_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || ctx->session == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        CmdInfo_t info = {0,0,0,0};
        info.inHandleCnt = 3;
        info.flags = (CMD_FLAG_AUTH_USER1);

        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendU32(&packet, in->nvIndex);
        TPM2_Packet_AppendU32(&packet, in->policySession);
        TPM2_Packet_AppendAuth(&packet, ctx, &info);
        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS,
            TPM_CC_PolicyAuthorizeNV);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}


TPM_RC TPM2_HierarchyControl(HierarchyControl_In* in)
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
        TPM2_Packet_AppendU32(&packet, in->enable);
        TPM2_Packet_AppendU8(&packet, in->state);
        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_HierarchyControl);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_SetPrimaryPolicy(SetPrimaryPolicy_In* in)
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
        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendAuth(&packet, ctx, &info);
        TPM2_Packet_AppendU16(&packet, in->authPolicy.size);
        TPM2_Packet_AppendBytes(&packet, in->authPolicy.buffer,
            in->authPolicy.size);
        TPM2_Packet_AppendU16(&packet, in->hashAlg);
        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_SetPrimaryPolicy);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

static TPM_RC TPM2_ChangeSeed(ChangeSeed_In* in, TPM_CC cc)
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
        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, cc);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);

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
        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_Clear);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_ClearControl(ClearControl_In* in)
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
        TPM2_Packet_AppendU32(&packet, in->auth);
        TPM2_Packet_AppendAuth(&packet, ctx, &info);
        TPM2_Packet_AppendU8(&packet, in->disable);
        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_ClearControl);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_HierarchyChangeAuth(HierarchyChangeAuth_In* in)
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
        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendAuth(&packet, ctx, &info);
        TPM2_Packet_AppendU16(&packet, in->newAuth.size);
        TPM2_Packet_AppendBytes(&packet, in->newAuth.buffer, in->newAuth.size);
        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS,
            TPM_CC_HierarchyChangeAuth);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_DictionaryAttackLockReset(DictionaryAttackLockReset_In* in)
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
        TPM2_Packet_AppendU32(&packet, in->lockHandle);
        TPM2_Packet_AppendAuth(&packet, ctx, &info);
        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS,
            TPM_CC_DictionaryAttackLockReset);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_DictionaryAttackParameters(DictionaryAttackParameters_In* in)
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
        TPM2_Packet_AppendU32(&packet, in->lockHandle);
        TPM2_Packet_AppendAuth(&packet, ctx, &info);
        TPM2_Packet_AppendU32(&packet, in->newMaxTries);
        TPM2_Packet_AppendU32(&packet, in->newRecoveryTime);
        TPM2_Packet_AppendU32(&packet, in->lockoutRecovery);
        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS,
            TPM_CC_DictionaryAttackParameters);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_PP_Commands(PP_Commands_In* in)
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
        TPM2_Packet_AppendU32(&packet, in->auth);
        TPM2_Packet_AppendAuth(&packet, ctx, &info);

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
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_SetAlgorithmSet(SetAlgorithmSet_In* in)
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

        TPM2_Packet_AppendU32(&packet, in->algorithmSet);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_SetAlgorithmSet);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_FieldUpgradeStart(FieldUpgradeStart_In* in)
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
        info.flags = (CMD_FLAG_ENC2 | CMD_FLAG_AUTH_ADMIN);

        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->authorization);
        TPM2_Packet_AppendU32(&packet, in->keyHandle);
        TPM2_Packet_AppendAuth(&packet, ctx, &info);

        TPM2_Packet_AppendU16(&packet, in->fuDigest.size);
        TPM2_Packet_AppendBytes(&packet, in->fuDigest.buffer,
            in->fuDigest.size);

        TPM2_Packet_AppendSignature(&packet, &in->manifestSignature);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS,
            TPM_CC_FieldUpgradeStart);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);

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
        CmdInfo_t info = {0,0,0,0};
        info.flags = (CMD_FLAG_ENC2);

        TPM2_Packet_Init(ctx, &packet);

        st = TPM2_Packet_AppendAuth(&packet, ctx, &info);

        TPM2_Packet_AppendU16(&packet, in->fuData.size);
        TPM2_Packet_AppendBytes(&packet, in->fuData.buffer, in->fuData.size);

        TPM2_Packet_Finalize(&packet, st, TPM_CC_FieldUpgradeData);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);
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
        CmdInfo_t info = {0,0,0,0};
        info.flags = (CMD_FLAG_DEC2);

        TPM2_Packet_Init(ctx, &packet);

        st = TPM2_Packet_AppendAuth(&packet, ctx, &info);
        TPM2_Packet_AppendU32(&packet, in->sequenceNumber);
        TPM2_Packet_Finalize(&packet, st, TPM_CC_FirmwareRead);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);
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
        CmdInfo_t info = {0,0,0,0};
        info.inHandleCnt = 2;
        info.flags = (CMD_FLAG_AUTH_USER1);

        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->auth);
        TPM2_Packet_AppendU32(&packet, in->objectHandle);
        TPM2_Packet_AppendAuth(&packet, ctx, &info);
        TPM2_Packet_AppendU32(&packet, in->persistentHandle);
        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_EvictControl);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);

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
        CmdInfo_t info = {0,0,0,0};

        TPM2_Packet_Init(ctx, &packet);

        st = TPM2_Packet_AppendAuth(&packet, ctx, &info);
        TPM2_Packet_Finalize(&packet, st, TPM_CC_ReadClock);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);
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

    if (ctx == NULL || in == NULL || ctx->session == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        CmdInfo_t info = {0,0,0,0};
        info.inHandleCnt = 1;
        info.flags = (CMD_FLAG_AUTH_USER1);

        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->auth);
        TPM2_Packet_AppendAuth(&packet, ctx, &info);

        TPM2_Packet_AppendU64(&packet, in->newTime);
        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_ClockSet);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_ClockRateAdjust(ClockRateAdjust_In* in)
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
        TPM2_Packet_AppendU32(&packet, in->auth);
        TPM2_Packet_AppendAuth(&packet, ctx, &info);
        TPM2_Packet_AppendU8(&packet, in->rateAdjust);
        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_ClockRateAdjust);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);

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
        CmdInfo_t info = {0,0,0,0};

        TPM2_Packet_Init(ctx, &packet);

        st = TPM2_Packet_AppendAuth(&packet, ctx, &info);

        TPM2_Packet_AppendU16(&packet, in->parameters.type);
        TPM2_Packet_AppendPublicParms(&packet, in->parameters.type,
            &in->parameters.parameters);
        TPM2_Packet_Finalize(&packet, st, TPM_CC_TestParms);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_NV_DefineSpace(NV_DefineSpace_In* in)
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

        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendAuth(&packet, ctx, &info);

        /* 1st TPM2B parameter, TPM2B_AUTH different from Authorization Area */
        TPM2_Packet_AppendU16(&packet, in->auth.size);
        TPM2_Packet_AppendBytes(&packet, in->auth.buffer, in->auth.size);
        /* 2nd TPM2B parameter, TPM2B_PUBLIC */
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
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_NV_UndefineSpace(NV_UndefineSpace_In* in)
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
        info.flags = (CMD_FLAG_AUTH_USER1);

        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendU32(&packet, in->nvIndex);
        TPM2_Packet_AppendAuth(&packet, ctx, &info);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_NV_UndefineSpace);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_NV_UndefineSpaceSpecial(NV_UndefineSpaceSpecial_In* in)
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
        info.flags = (CMD_FLAG_AUTH_ADMIN | CMD_FLAG_AUTH_USER2);

        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->nvIndex);
        TPM2_Packet_AppendU32(&packet, in->platform);
        TPM2_Packet_AppendAuth(&packet, ctx, &info);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS,
            TPM_CC_NV_UndefineSpaceSpecial);

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

TPM_RC TPM2_NV_Write(NV_Write_In* in)
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
        TPM2_Packet_AppendU32(&packet, in->nvIndex);
        TPM2_Packet_AppendAuth(&packet, ctx, &info);

        TPM2_Packet_AppendU16(&packet, in->data.size);
        TPM2_Packet_AppendBytes(&packet, in->data.buffer, in->data.size);

        TPM2_Packet_AppendU16(&packet, in->offset);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_NV_Write);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_NV_Increment(NV_Increment_In* in)
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
        info.flags = (CMD_FLAG_AUTH_USER1);

        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendU32(&packet, in->nvIndex);
        TPM2_Packet_AppendAuth(&packet, ctx, &info);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_NV_Increment);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);

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

TPM_RC TPM2_NV_SetBits(NV_SetBits_In* in)
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
        info.flags = (CMD_FLAG_AUTH_USER1);

        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendU32(&packet, in->nvIndex);
        TPM2_Packet_AppendAuth(&packet, ctx, &info);

        TPM2_Packet_AppendU64(&packet, in->bits);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_NV_SetBits);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_NV_WriteLock(NV_WriteLock_In* in)
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
        info.flags = (CMD_FLAG_AUTH_USER1);

        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendU32(&packet, in->nvIndex);
        TPM2_Packet_AppendAuth(&packet, ctx, &info);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_NV_WriteLock);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_NV_GlobalWriteLock(NV_GlobalWriteLock_In* in)
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

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS,
            TPM_CC_NV_GlobalWriteLock);

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

TPM_RC TPM2_NV_ReadLock(NV_ReadLock_In* in)
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
        info.flags = (CMD_FLAG_AUTH_USER1);

        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendU32(&packet, in->nvIndex);
        TPM2_Packet_AppendAuth(&packet, ctx, &info);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_NV_ReadLock);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_NV_ChangeAuth(NV_ChangeAuth_In* in)
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
        info.flags = (CMD_FLAG_ENC2 | CMD_FLAG_AUTH_ADMIN);

        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->nvIndex);
        TPM2_Packet_AppendAuth(&packet, ctx, &info);

        TPM2_Packet_AppendU16(&packet, in->newAuth.size);
        TPM2_Packet_AppendBytes(&packet, in->newAuth.buffer, in->newAuth.size);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_NV_ChangeAuth);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_NV_Certify(NV_Certify_In* in, NV_Certify_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL || ctx->session == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        CmdInfo_t info = {0,0,0,0};
        info.inHandleCnt = 3;
        info.flags = (CMD_FLAG_ENC2 | CMD_FLAG_DEC2 | CMD_FLAG_AUTH_USER1 |
            CMD_FLAG_AUTH_USER2);

        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->signHandle);
        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendU32(&packet, in->nvIndex);
        TPM2_Packet_AppendAuth(&packet, ctx, &info);

        TPM2_Packet_AppendU16(&packet, in->qualifyingData.size);
        TPM2_Packet_AppendBytes(&packet, in->qualifyingData.buffer,
            in->qualifyingData.size);

        TPM2_Packet_AppendU16(&packet, in->inScheme.scheme);
        TPM2_Packet_AppendU16(&packet, in->inScheme.details.any.hashAlg);

        TPM2_Packet_AppendU16(&packet, in->size);
        TPM2_Packet_AppendU16(&packet, in->offset);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_NV_Certify);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);
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
#if defined(WOLFTPM_ST33) || defined(WOLFTPM_AUTODETECT)
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
#endif /* WOLFTPM_ST33 || WOLFTPM_AUTODETECT */

/* GPIO Vendor Specific API's */
#ifdef WOLFTPM_ST33
int TPM2_GPIO_Config(GpioConfig_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();
    UINT32 i;

    if (ctx == NULL || in == NULL || ctx->session == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        CmdInfo_t info = {0,0,0,0};
        info.inHandleCnt = 1;

        TPM2_Packet_Init(ctx, &packet);
        /* Process the nvIndex used for GPIO configuration */
        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendAuth(&packet, ctx, &info);
        TPM2_Packet_AppendU32(&packet, in->config.count);
        /* Process the GPIO configuration */
        for (i=0; i < in->config.count; i++) {
            TPM2_Packet_AppendU32(&packet, in->config.gpio[i].name);
            TPM2_Packet_AppendU32(&packet, in->config.gpio[i].index);
            TPM2_Packet_AppendU32(&packet, in->config.gpio[i].mode);
        }
        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_GPIO_Config);

        /* send command */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

#elif defined(WOLFTPM_NUVOTON)

int TPM2_NTC2_PreConfig(NTC2_PreConfig_In* in)
{
    int rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (in == NULL || ctx == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        CmdInfo_t info = {0,0,0,0};
        info.inHandleCnt = 1;

        TPM2_Packet_Init(ctx, &packet);
        /* Process the auth handle for GPIO configuration */
        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendAuth(&packet, ctx, &info);
        /* Process the NPCT7xx configuration */
        TPM2_Packet_AppendBytes(&packet, (byte*)&in->preConfig, sizeof(in->preConfig));
        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_NTC2_PreConfig);

        /* Send the new NPCT7xx configuration */
        rc = TPM2_SendCommandAuth(ctx, &packet, &info);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

int TPM2_NTC2_GetConfig(NTC2_GetConfig_Out* out)
{
    int rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (out == NULL || ctx == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_NTC2_GetConfig);

        /* Request the current NPCT7xx configuration */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            TPM2_Packet_ParseBytes(&packet, (byte*)&out->preConfig, sizeof(out->preConfig));
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}
#endif /* WOLFTPM_NUVOTON */


#ifdef WOLFTPM_FIRMWARE_UPGRADE
#if defined(WOLFTPM_SLB9672) || defined(WOLFTPM_SLB9673)
int TPM2_IFX_FieldUpgradeStart(TPM_HANDLE sessionHandle,
    uint8_t* data, uint32_t size)
{
    int rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();
    TPMS_AUTH_COMMAND session;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        int tmpSz = 0;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, TPM_RH_PLATFORM);

        XMEMSET(&session, 0, sizeof(session));
        session.sessionHandle = sessionHandle;

        TPM2_Packet_MarkU32(&packet, &tmpSz);
        TPM2_Packet_AppendAuthCmd(&packet, &session);
        TPM2_Packet_PlaceU32(&packet, tmpSz);

        TPM2_Packet_AppendBytes(&packet, data, size);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS,
            TPM_CC_FieldUpgradeStartVendor);

        rc = TPM2_SendCommand(ctx, &packet);

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}
int TPM2_IFX_FieldUpgradeCommand(TPM_CC cc, uint8_t* data, uint32_t size)
{
    int rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendBytes(&packet, data, size);
        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, cc);
        rc = TPM2_SendCommand(ctx, &packet);
        TPM2_ReleaseLock(ctx);
    }
    return rc;
}


#endif /* WOLFTPM_SLB9672 || WOLFTPM_SLB9673 */
#endif /* WOLFTPM_FIRMWARE_UPGRADE */

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

#ifdef WOLFTPM_DEBUG_VERBOSE
    printf("TPM2_GetNonce (%d bytes)\n", nonceSz);
#endif

#ifdef WOLFTPM2_USE_WOLF_RNG
    rc = TPM2_GetWolfRng(&rng);
    if (rc == 0) {
        /* Use wolfCrypt */
        rc = wc_RNG_GenerateBlock(rng, nonceBuf, nonceSz);
    }
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
        #ifdef WOLFTPM_DEBUG_VERBOSE
            printf("TPM2_GetNonce (%d bytes at %d): %d (%s)\n",
                inSz, randSz, rc, TPM2_GetRCString(rc));
        #endif
            if (rc != TPM_RC_SUCCESS) {
                break;
            }

            TPM2_Packet_ParseU16(&packet, &outSz);
            if (outSz > MAX_RNG_REQ_SIZE) {
            #ifdef DEBUG_WOLFTPM
                printf("TPM2_GetNonce out size error\n");
            #endif
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

/* Get name for object/handle */
int TPM2_GetName(TPM2_CTX* ctx, UINT32 handleValue, int handleCnt, int idx, TPM2B_NAME* name)
{
    TPM2_AUTH_SESSION* session;

    if (ctx == NULL || name == NULL) {
        return BAD_FUNC_ARG;
    }

    XMEMSET(name, 0, sizeof(TPM2B_NAME));

    if (idx >= handleCnt)
        return TPM_RC_SUCCESS;

    session = &ctx->session[idx];

    if ((handleValue >= TRANSIENT_FIRST) ||
        (handleValue >= NV_INDEX_FIRST && handleValue <= NV_INDEX_LAST)) {
        if (session->name.size > 0) {
            name->size = session->name.size;
            XMEMCPY(name->name, session->name.name, name->size);
        }
    }
    else {
        handleValue = TPM2_Packet_SwapU32(handleValue);
        name->size = sizeof(handleValue);
        XMEMCPY(name->name, (byte*)&handleValue, name->size);
    }

#ifdef WOLFTPM_DEBUG_VERBOSE
    printf("Name %d: %d\n", idx, name->size);
    TPM2_PrintBin(name->name, name->size);
#endif
    return TPM_RC_SUCCESS;
}

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
                if (pcr->pcrSelections[0].hash == alg)
                    break;
            }

            /* if no match increase the number of banks */
            if ((word32)i >= pcr->count)
                pcr->count++;
        }

        pcr->pcrSelections[i].hash = alg;
        pcr->pcrSelections[i].sizeofSelect = PCR_SELECT_MAX;
        pcr->pcrSelections[i].pcrSelect[pcrIndex >> 3] = (1 << (pcrIndex & 0x7));
    }
}

void TPM2_SetupPCRSelArray(TPML_PCR_SELECTION* pcr, TPM_ALG_ID alg,
    byte* pcrArray, word32 pcrArraySz)
{
    int i;
    for (i = 0; i < (int)pcrArraySz; i++) {
        TPM2_SetupPCRSel(pcr, alg, (int)pcrArray[i]);
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
            TPM_RC_STR(TPM_RC_TIMEOUT,           "Hardware timeout");
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
    #else
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
    #endif
    }
    else if (rc == TPM_RC_SUCCESS) {
        return "Success";
    }

    if ((rc & RC_WARN) && (rc & RC_FMT1) == 0 && (rc & RC_VER1) == 0) {
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
        #ifdef DEBUG_WOLFTPM
            printf("Error: Parameter Number %d\n", param_num);
        #endif
            (void)param_num;
        }
        else if (rc & 0x800) { /* bit 11 */
            /* bits 8-10 */
            int session_num = (rc & 0x700) >> 8;
        #ifdef DEBUG_WOLFTPM
            printf("Error: Session Number %d\n", session_num);
        #endif
            (void)session_num;
        }
        else {
            /* bits 8-10 */
            int handle_num = (rc & 0x700) >> 8;
        #ifdef DEBUG_WOLFTPM
            printf("Error: Handle Number %d\n", handle_num);
        #endif
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
        /* Use did_vid for devId (conforms with wolfTPM2_GetTpmDevId) */
        rc = wc_InitRng_ex(&ctx->rng, NULL, ctx->did_vid);
        if (rc < 0) {
        #ifdef DEBUG_WOLFTPM
            printf("wc_InitRng_ex failed %d: %s\n",
                (int)rc, wc_GetErrorString(rc));
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

int TPM2_ParseAttest(const TPM2B_ATTEST* in, TPMS_ATTEST* out)
{
    TPM2_Packet packet;

    if (in == NULL || out == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(&packet, 0, sizeof(packet));
    packet.buf = (byte*)in->attestationData;
    packet.size = in->size;

    TPM2_Packet_ParseAttest(&packet, out);
    return TPM_RC_SUCCESS;
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

/* Stores nameAlg + the digest of nvPublic in buffer, total size in size */
int TPM2_HashNvPublic(TPMS_NV_PUBLIC* nvPublic, byte* buffer, UINT16* size)
{
#ifndef WOLFTPM2_NO_WOLFCRYPT
    int rc;
    int hashSize, nameAlgSize;
    UINT16 nameAlgValue;
    wc_HashAlg hash;
    enum wc_HashType hashType;
    byte appending[sizeof(TPMS_NV_PUBLIC)];
    TPM2_Packet packet;

    if (nvPublic == NULL || buffer == NULL || size == NULL) {
        return BAD_FUNC_ARG;
    }

    /* Prepare temporary buffer */
    packet.buf = appending;
    packet.pos = 0;
    packet.size = sizeof(appending);

    /* nvPublic must be in Marshaled state for hashing */
    TPM2_Packet_AppendU32(&packet, nvPublic->nvIndex);
    TPM2_Packet_AppendU16(&packet, nvPublic->nameAlg);
    TPM2_Packet_AppendU32(&packet, nvPublic->attributes);
    TPM2_Packet_AppendU16(&packet, nvPublic->authPolicy.size);
    TPM2_Packet_AppendBytes(&packet, nvPublic->authPolicy.buffer,
        nvPublic->authPolicy.size);
    TPM2_Packet_AppendU16(&packet, nvPublic->dataSize);

    /* Hashing nvPublic */
    rc = TPM2_GetHashType(nvPublic->nameAlg);
    hashType = (enum wc_HashType)rc;
    rc = wc_HashGetDigestSize(hashType);
    if (rc < 0) {
        return rc;
    }
    hashSize = rc;

    rc = wc_HashInit(&hash, hashType);
    if (rc == 0) {
        rc = wc_HashUpdate(&hash, hashType, packet.buf, packet.pos);
    }
    if (rc == 0) {
        rc = wc_HashFinal(&hash, hashType, &buffer[2]);
    }

    if (rc == 0) {
        /* Concatenate the nvPublic digest with nameAlg at the front */
        nameAlgValue = TPM2_Packet_SwapU16(nvPublic->nameAlg);
        nameAlgSize = sizeof(nvPublic->nameAlg);
        XMEMCPY(buffer, (byte*)&nameAlgValue, nameAlgSize);
        /* account for nameAlg concatenation */
        *size = hashSize + nameAlgSize;
        rc = TPM_RC_SUCCESS;
    }

    wc_HashFree(&hash, hashType);

    return rc;
#else
    (void)nvPublic;
    (void)buffer;
    (void)size;
    return NOT_COMPILED_IN;
#endif
}

int TPM2_AppendPublic(byte* buf, word32 size, int* sizeUsed, TPM2B_PUBLIC* pub)
{
    TPM2_Packet packet;

    if (buf == NULL || pub == NULL || sizeUsed == NULL)
        return BAD_FUNC_ARG;

    if (size < sizeof(TPM2B_PUBLIC)) {
    #ifdef DEBUG_WOLFTPM
        printf("Insufficient buffer size for TPM2B_PUBLIC operations\n");
    #endif
        return TPM_RC_FAILURE;
    }

    /* Prepare temporary buffer */
    packet.buf = buf;
    packet.pos = 0;
    packet.size = (int)size;

    TPM2_Packet_AppendPublic(&packet, pub);
    *sizeUsed = packet.pos;

    return TPM_RC_SUCCESS;
}

int TPM2_ParsePublic(TPM2B_PUBLIC* pub, byte* buf, word32 size, int* sizeUsed)
{
    TPM2_Packet packet;

    if (buf == NULL || pub == NULL || sizeUsed == NULL)
        return BAD_FUNC_ARG;

    if (size < sizeof(TPM2B_PUBLIC)) {
    #ifdef DEBUG_WOLFTPM
        printf("Insufficient buffer size for TPM2B_PUBLIC operations\n");
    #endif
        return TPM_RC_FAILURE;
    }

    /* Prepare temporary buffer */
    packet.buf = buf;
    packet.pos = 0;
    packet.size = (int)size;

    TPM2_Packet_ParsePublic(&packet, pub);
    *sizeUsed = packet.pos;

    return TPM_RC_SUCCESS;
}

/* This routine fills the first len bytes of the memory area pointed by mem
   with zeros. It ensures compiler optimizations doesn't skip it  */
void TPM2_ForceZero(void* mem, word32 len)
{
    volatile byte* z = (volatile byte*)mem;
    while (len--) *z++ = 0;
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

void TPM2_PrintPublicArea(const TPM2B_PUBLIC* pub)
{
    printf("Public Area (size %d):\n", pub->size);

    /* Sanity check */
    if (pub->size > (sizeof(TPM2B_PUBLIC))) {
        printf("Invalid TPM2B_PUBLIC size\n");
        return;
    }
    printf("  Type: %s (0x%X), name: %s (0x%X), objAttr: 0x%X, authPolicy sz: %d\n",
        TPM2_GetAlgName(pub->publicArea.type), pub->publicArea.type,
        TPM2_GetAlgName(pub->publicArea.nameAlg), pub->publicArea.nameAlg,
        (unsigned int)pub->publicArea.objectAttributes,
        pub->publicArea.authPolicy.size);
    #ifdef WOLFTPM_DEBUG_VERBOSE
    TPM2_PrintBin(pub->publicArea.authPolicy.buffer, pub->publicArea.authPolicy.size);
    #endif

    /* parameters and unique field depend on algType */
    switch (pub->publicArea.type) {
        case TPM_ALG_KEYEDHASH:
            printf("  Keyed Hash: scheme: %s (0x%X), scheme hash: %s (0x%X), unique size %d\n",
                TPM2_GetAlgName(pub->publicArea.parameters.keyedHashDetail.scheme.scheme),
                pub->publicArea.parameters.keyedHashDetail.scheme.scheme,
                TPM2_GetAlgName(pub->publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg),
                pub->publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg,
                pub->publicArea.unique.keyedHash.size);
            #ifdef WOLFTPM_DEBUG_VERBOSE
            TPM2_PrintBin(pub->publicArea.unique.keyedHash.buffer, pub->publicArea.unique.keyedHash.size);
            #endif
            break;
        case TPM_ALG_SYMCIPHER:
            printf("  Symmetric Cipher: algorithm: %s (0x%X), keyBits: %d, mode: %s (0x%X), unique size %d\n",
                TPM2_GetAlgName(pub->publicArea.parameters.symDetail.sym.algorithm),
                pub->publicArea.parameters.symDetail.sym.algorithm,
                pub->publicArea.parameters.symDetail.sym.keyBits.sym,
                TPM2_GetAlgName(pub->publicArea.parameters.symDetail.sym.mode.sym),
                pub->publicArea.parameters.symDetail.sym.mode.sym,
                pub->publicArea.unique.sym.size);
            #ifdef WOLFTPM_DEBUG_VERBOSE
            TPM2_PrintBin(pub->publicArea.unique.sym.buffer, pub->publicArea.unique.sym.size);
            #endif
            break;
        case TPM_ALG_RSA:
            printf("  RSA: sym algorithm: %s (0x%X), sym keyBits: %d, sym mode: %s (0x%X)\n",
                TPM2_GetAlgName(pub->publicArea.parameters.rsaDetail.symmetric.algorithm),
                pub->publicArea.parameters.rsaDetail.symmetric.algorithm,
                pub->publicArea.parameters.rsaDetail.symmetric.keyBits.sym,
                TPM2_GetAlgName(pub->publicArea.parameters.rsaDetail.symmetric.mode.sym),
                pub->publicArea.parameters.rsaDetail.symmetric.mode.sym);
            printf("       scheme: %s (0x%X), scheme hash: %s (0x%X)\n",
                TPM2_GetAlgName(pub->publicArea.parameters.rsaDetail.scheme.scheme),
                pub->publicArea.parameters.rsaDetail.scheme.scheme,
                TPM2_GetAlgName(pub->publicArea.parameters.rsaDetail.scheme.details.anySig.hashAlg),
                pub->publicArea.parameters.rsaDetail.scheme.details.anySig.hashAlg);
            printf("       keyBits: %d, exponent: 0x%X, unique size %d\n",
                pub->publicArea.parameters.rsaDetail.keyBits,
                (unsigned int)pub->publicArea.parameters.rsaDetail.exponent,
                pub->publicArea.unique.rsa.size);
            #ifdef WOLFTPM_DEBUG_VERBOSE
            TPM2_PrintBin(pub->publicArea.unique.rsa.buffer, pub->publicArea.unique.rsa.size);
            #endif
            break;
        case TPM_ALG_ECC:
            printf("  ECC: sym algorithm: %s (0x%X), sym keyBits: %d, sym mode: %s (0x%X)\n",
                TPM2_GetAlgName(pub->publicArea.parameters.eccDetail.symmetric.algorithm),
                pub->publicArea.parameters.eccDetail.symmetric.algorithm,
                pub->publicArea.parameters.eccDetail.symmetric.keyBits.sym,
                TPM2_GetAlgName(pub->publicArea.parameters.eccDetail.symmetric.mode.sym),
                pub->publicArea.parameters.eccDetail.symmetric.mode.sym);
            printf("       scheme: %s (0x%X), scheme hash: %s (0x%X), curveID: size %d, 0x%X\n",
                TPM2_GetAlgName(pub->publicArea.parameters.eccDetail.scheme.scheme),
                pub->publicArea.parameters.eccDetail.scheme.scheme,
                TPM2_GetAlgName(pub->publicArea.parameters.eccDetail.scheme.details.any.hashAlg),
                pub->publicArea.parameters.eccDetail.scheme.details.any.hashAlg,
                TPM2_GetCurveSize(pub->publicArea.parameters.eccDetail.curveID),
                pub->publicArea.parameters.eccDetail.curveID);
            printf("       KDF scheme: %s (0x%X), KDF alg: %s (0x%X), unique X/Y size %d/%d\n",
                TPM2_GetAlgName(pub->publicArea.parameters.eccDetail.kdf.scheme),
                pub->publicArea.parameters.eccDetail.kdf.scheme,
                TPM2_GetAlgName(pub->publicArea.parameters.eccDetail.kdf.details.any.hashAlg),
                pub->publicArea.parameters.eccDetail.kdf.details.any.hashAlg,
                pub->publicArea.unique.ecc.x.size,
                pub->publicArea.unique.ecc.y.size);
            #ifdef WOLFTPM_DEBUG_VERBOSE
            TPM2_PrintBin(pub->publicArea.unique.ecc.x.buffer, pub->publicArea.unique.ecc.x.size);
            TPM2_PrintBin(pub->publicArea.unique.ecc.y.buffer, pub->publicArea.unique.ecc.y.size);
            #endif
            break;
        default:
            /* derive does not seem to have specific fields in the parameters struct */
            printf("Derive Type: unique label size %d, context size %d\n",
                pub->publicArea.unique.derive.label.size,
                pub->publicArea.unique.derive.context.size);
            #ifdef WOLFTPM_DEBUG_VERBOSE
            TPM2_PrintBin(pub->publicArea.unique.derive.label.buffer,pub->publicArea.unique.derive.label.size);
            TPM2_PrintBin(pub->publicArea.unique.derive.context.buffer, pub->publicArea.unique.derive.context.size);
            #endif
            break;
    }
}
#endif /* DEBUG_WOLFTPM */

/******************************************************************************/
/* --- END Helpful API's -- */
/******************************************************************************/
