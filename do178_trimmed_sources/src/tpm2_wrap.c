/* tpm2_wrap.c
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

#include <wolftpm/tpm2_wrap.h>
#include <wolftpm/tpm2_param_enc.h>

#ifndef WOLFTPM2_NO_WRAPPER

/* For some struct to buffer conversions */
#include <wolftpm/tpm2_packet.h>
#include <hal/tpm_io.h> /* for default IO callback */


/* Local Functions */
static int wolfTPM2_GetCapabilities_NoDev(WOLFTPM2_CAPS* cap);
static void wolfTPM2_CopySymmetric(TPMT_SYM_DEF* out, const TPMT_SYM_DEF* in);
static void wolfTPM2_CopyName(TPM2B_NAME* out, const TPM2B_NAME* in);
static void wolfTPM2_CopyAuth(TPM2B_AUTH* out, const TPM2B_AUTH* in);
static void wolfTPM2_CopyPub(TPM2B_PUBLIC* out, const TPM2B_PUBLIC* in);
static void wolfTPM2_CopyNvPublic(TPMS_NV_PUBLIC* out, const TPMS_NV_PUBLIC* in);

/******************************************************************************/
/* --- BEGIN Wrapper Device Functions -- */
/******************************************************************************/

static int wolfTPM2_Init_ex(TPM2_CTX* ctx, TPM2HalIoCb ioCb, void* userCtx,
    int timeoutTries)
{
    int rc;

#if !defined(WOLFTPM_LINUX_DEV) && !defined(WOLFTPM_WINAPI)
    Startup_In startupIn;
#endif /* ! WOLFTPM_LINUX_DEV */

    if (ctx == NULL)
        return BAD_FUNC_ARG;

#if defined(WOLFTPM_LINUX_DEV) || defined(WOLFTPM_SWTPM) || defined(WOLFTPM_WINAPI)
    rc = TPM2_Init_minimal(ctx);
    /* Using standard file I/O for the Linux TPM device */
    (void)ioCb;
    (void)userCtx;
    (void)timeoutTries;
#else
    rc = TPM2_Init_ex(ctx, ioCb, userCtx, timeoutTries);
#endif
    if (rc != TPM_RC_SUCCESS) {
        return rc;
    }

#if !defined(WOLFTPM_LINUX_DEV) && !defined(WOLFTPM_WINAPI)
    /* startup */
    XMEMSET(&startupIn, 0, sizeof(Startup_In));
    startupIn.startupType = TPM_SU_CLEAR;
    rc = TPM2_Startup(&startupIn);
    if (rc != TPM_RC_SUCCESS &&
        rc != TPM_RC_INITIALIZE /* TPM_RC_INITIALIZE = Already started */ ) {
        return rc;
    }
    rc = TPM_RC_SUCCESS;
#endif /* !WOLFTPM_LINUX_DEV && !WOLFTPM_WINAPI */

    return rc;
}

/* Single-shot API for testing access to hardware and optionally return capabilities */
int wolfTPM2_Test(TPM2HalIoCb ioCb, void* userCtx, WOLFTPM2_CAPS* caps)
{
    int rc;
    TPM2_CTX* current_ctx;
    TPM2_CTX ctx;

    /* Backup active TPM context */
    current_ctx = TPM2_GetActiveCtx();

    /* Perform startup and test device */
    rc = wolfTPM2_Init_ex(&ctx, ioCb, userCtx, TPM_STARTUP_TEST_TRIES);
    if (rc != TPM_RC_SUCCESS) {
        return rc;
    }

    /* Optionally get and return capabilities */
    if (caps) {
        rc = wolfTPM2_GetCapabilities_NoDev(caps);
    }

    /* Perform cleanup */
    TPM2_Cleanup(&ctx);

    /* Restore original context */
    TPM2_SetActiveCtx(current_ctx);

    return rc;
}

int wolfTPM2_Init(WOLFTPM2_DEV* dev, TPM2HalIoCb ioCb, void* userCtx)
{
    int rc;

    if (dev == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(dev, 0, sizeof(WOLFTPM2_DEV));

    rc = wolfTPM2_Init_ex(&dev->ctx, ioCb, userCtx, TPM_TIMEOUT_TRIES);
    if (rc != TPM_RC_SUCCESS) {
        return rc;
    }

    /* define the default session auth */
    XMEMSET(dev->session, 0, sizeof(dev->session));
    wolfTPM2_SetAuthPassword(dev, 0, NULL);

    return rc;
}
/* ST33TP
 *  TPM_PT_MANUFACTURER 0x53544D20: "STM"
 *  TPM_PT_FIRMWARE_VERSION_1 TPM FW version: 0x00006400
 *  TPM_PT_VENDOR_TPM_TYPE 1: TPM 2.0
 *  TPM_PT_MODES: BIT 0 SET (1): indicates that the TPM is designed to
 *      comply with all of the FIPS 140-2 requirements at Level 1 or higher.
 *   TPM_PT_FIRMWARE_VERSION_2: ST Internal Additional Version
 */
static int wolfTPM2_ParseCapabilities(WOLFTPM2_CAPS* caps,
    TPML_TAGGED_TPM_PROPERTY* props)
{
    int rc = 0;
    word32 i, val, len;

    for (i=0; i<props->count && i<MAX_TPM_PROPERTIES; i++) {
        val = props->tpmProperty[i].value;
        switch (props->tpmProperty[i].property) {
            case TPM_PT_MANUFACTURER:
                val = TPM2_Packet_SwapU32(val); /* swap for little endian */
                XMEMCPY(&caps->mfgStr, &val, sizeof(UINT32));
                if (XMEMCMP(&caps->mfgStr, "IFX", 3) == 0) {
                    caps->mfg = TPM_MFG_INFINEON;
                }
                else if (XMEMCMP(&caps->mfgStr, "STM", 3) == 0) {
                    caps->mfg = TPM_MFG_STM;
                    caps->req_wait_state = 1;
                }
                else if (XMEMCMP(&caps->mfgStr, "MCHP", 4) == 0) {
                    caps->mfg = TPM_MFG_MCHP;
                    caps->req_wait_state = 1;
                }
                else if (XMEMCMP(&caps->mfgStr, "NTC", 4) == 0) {
                    caps->mfg = TPM_MFG_NUVOTON;
                    caps->req_wait_state = 1;
                }
                else if (XMEMCMP(&caps->mfgStr, "NTZ", 4) == 0) {
                    caps->mfg = TPM_MFG_NATIONTECH;
                    caps->req_wait_state = 1;
                }
                break;
            case TPM_PT_VENDOR_STRING_1:
            case TPM_PT_VENDOR_STRING_2:
            case TPM_PT_VENDOR_STRING_3:
            case TPM_PT_VENDOR_STRING_4:
                val = TPM2_Packet_SwapU32(val); /* swap for little endian */
                len = (word32)XSTRLEN(caps->vendorStr); /* add to existing string */
                if (len + sizeof(UINT32) < sizeof(caps->vendorStr)) {
                    XMEMCPY(&caps->vendorStr[len], &val, sizeof(UINT32));
                }
                if (val == 0x46495053) { /* FIPS */
                    caps->fips140_2 = 1;
                }
                break;
            case TPM_PT_VENDOR_TPM_TYPE:
                caps->tpmType = val;
                break;
            case TPM_PT_FIRMWARE_VERSION_1:
                caps->fwVerMajor = val >> 16;
                caps->fwVerMinor = val & 0xFFFF;
                break;
            case TPM_PT_FIRMWARE_VERSION_2:
                if (caps->mfg == TPM_MFG_INFINEON) {
                    caps->fwVerVendor = val >> 8;
                    caps->cc_eal4 = (val & 0x00000002) ? 0 : 1;
                }
                else {
                    caps->fwVerVendor = val;
                }
                break;
            case TPM_PT_MODES:
                caps->fips140_2 = (val & 0x00000001) ? 1: 0;
                break;
            default:
                break;
        }
    }
    return rc;
}


static int wolfTPM2_GetCapabilities_NoDev(WOLFTPM2_CAPS* cap)
{
    int rc;
    GetCapability_In  in;
    GetCapability_Out out;

    if (cap == NULL)
        return BAD_FUNC_ARG;

    /* clear caps */
    XMEMSET(cap, 0, sizeof(WOLFTPM2_CAPS));

    /* Get Capabilities TPM_PT_MANUFACTURER thru TPM_PT_FIRMWARE_VERSION_2 */
    XMEMSET(&in, 0, sizeof(in));
    XMEMSET(&out, 0, sizeof(out));
    in.capability = TPM_CAP_TPM_PROPERTIES;
    in.property = TPM_PT_MANUFACTURER;
    in.propertyCount = 8;
    rc = TPM2_GetCapability(&in, &out);
    if (rc != TPM_RC_SUCCESS) {
        return rc;
    }
    rc = wolfTPM2_ParseCapabilities(cap, &out.capabilityData.data.tpmProperties);
    if (rc != 0)
        return rc;

    /* Get Capability TPM_PT_MODES */
    XMEMSET(&in, 0, sizeof(in));
    XMEMSET(&out, 0, sizeof(out));
    in.capability = TPM_CAP_TPM_PROPERTIES;
    in.property = TPM_PT_MODES;
    in.propertyCount = 1;
    rc = TPM2_GetCapability(&in, &out);
    if (rc != TPM_RC_SUCCESS) {
        return rc;
    }
    rc = wolfTPM2_ParseCapabilities(cap, &out.capabilityData.data.tpmProperties);

    return rc;
}

int wolfTPM2_GetCapabilities(WOLFTPM2_DEV* dev, WOLFTPM2_CAPS* cap)
{
    if (dev == NULL)
        return BAD_FUNC_ARG;

    return wolfTPM2_GetCapabilities_NoDev(cap);
}

int wolfTPM2_GetHandles(TPM_HANDLE handle, TPML_HANDLE* handles)
{
    int rc;
    GetCapability_In  in;
    GetCapability_Out out;

    /* Get Capability TPM_CAP_HANDLES - PCR */
    XMEMSET(&in, 0, sizeof(in));
    in.capability = TPM_CAP_HANDLES;
    in.property = handle;
    in.propertyCount = MAX_CAP_HANDLES;
    rc = TPM2_GetCapability(&in, &out);
    if (rc != TPM_RC_SUCCESS) {
        return rc;
    }
    if (handles != NULL) {
        /* optionally return handles count/list */
        XMEMCPY(handles, &out.capabilityData.data.handles, sizeof(TPML_HANDLE));
    }
    handles = &out.capabilityData.data.handles;
    return handles->count;
}

int wolfTPM2_UnsetAuth(WOLFTPM2_DEV* dev, int index)
{
    TPM2_AUTH_SESSION* session;

    if (dev == NULL || index >= MAX_SESSION_NUM || index < 0) {
        return BAD_FUNC_ARG;
    }

    session = &dev->session[index];
    XMEMSET(session, 0, sizeof(TPM2_AUTH_SESSION));

    return TPM2_SetSessionAuth(dev->session);
}

int wolfTPM2_UnsetAuthSession(WOLFTPM2_DEV* dev, int index,
    WOLFTPM2_SESSION* tpmSession)
{
    TPM2_AUTH_SESSION* devSession;

    if (dev == NULL || tpmSession == NULL ||
            index >= MAX_SESSION_NUM || index < 0) {
        return BAD_FUNC_ARG;
    }

    devSession = &dev->session[index];

    /* save off nonce from TPM to support continued use of session */
    XMEMCPY(&tpmSession->nonceTPM, &devSession->nonceTPM, sizeof(TPM2B_NONCE));

    XMEMSET(devSession, 0, sizeof(TPM2_AUTH_SESSION));

    return TPM2_SetSessionAuth(dev->session);
}

int wolfTPM2_SetAuth(WOLFTPM2_DEV* dev, int index,
    TPM_HANDLE sessionHandle, const TPM2B_AUTH* auth,
    TPMA_SESSION sessionAttributes, const TPM2B_NAME* name)
{
    TPM2_AUTH_SESSION* session;

    if (dev == NULL || index >= MAX_SESSION_NUM || index < 0) {
        return BAD_FUNC_ARG;
    }

    session = &dev->session[index];


    XMEMSET(session, 0, sizeof(TPM2_AUTH_SESSION));
    session->sessionHandle = sessionHandle;
    session->sessionAttributes = sessionAttributes;
    if (auth) {
        session->auth.size = auth->size;
        XMEMCPY(session->auth.buffer, auth->buffer, auth->size);
    }
    if (name) {
        session->name.size = name->size;
        XMEMCPY(session->name.name, name->name, name->size);
    }

    TPM2_SetSessionAuth(dev->session);

    return TPM_RC_SUCCESS;
}

int wolfTPM2_SetAuthPassword(WOLFTPM2_DEV* dev, int index,
    const TPM2B_AUTH* auth)
{
    return wolfTPM2_SetAuth(dev, index, TPM_RS_PW, auth, 0, NULL);
}

int wolfTPM2_SetAuthHandle(WOLFTPM2_DEV* dev, int index,
    const WOLFTPM2_HANDLE* handle)
{
    const TPM2B_AUTH* auth = NULL;
    const TPM2B_NAME* name = NULL;
    if (dev == NULL || index >= MAX_SESSION_NUM) {
        return BAD_FUNC_ARG;
    }

    if (handle) {
        /* don't set auth for policy session, just name */
        if (handle->policyAuth) {
            TPM2_AUTH_SESSION* session = &dev->session[index];
            int authDigestSz = TPM2_GetHashDigestSize(session->authHash);
            session->policyAuth = handle->policyAuth;
            if ((word32)handle->auth.size + authDigestSz >
                    sizeof(session->auth.buffer)) {
                return BUFFER_E;
            }
            session->auth.size = authDigestSz + handle->auth.size;
            XMEMCPY(&session->auth.buffer[authDigestSz], handle->auth.buffer,
                handle->auth.size);
            session->name.size = handle->name.size;
            XMEMCPY(session->name.name, handle->name.name, handle->name.size);
            return TPM_RC_SUCCESS;
        }
        auth = &handle->auth;
        name = &handle->name;
    }
    return wolfTPM2_SetAuth(dev, index, TPM_RS_PW, auth, 0, name);
}

int wolfTPM2_SetAuthHandleName(WOLFTPM2_DEV* dev, int index,
    const WOLFTPM2_HANDLE* handle)
{
    const TPM2B_NAME* name = NULL;
    TPM2_AUTH_SESSION* session;

    if (dev == NULL || handle == NULL || index >= MAX_SESSION_NUM) {
        return BAD_FUNC_ARG;
    }

    name = &handle->name;
    session = &dev->session[index];

    if (handle->auth.size > 0) {
        if (session->sessionHandle == TPM_RS_PW) {
            /* password based authentication */
            session->auth.size = handle->auth.size;
            XMEMCPY(session->auth.buffer, handle->auth.buffer, handle->auth.size);
        }
        else {
            if (handle->policyPass) {
                /* use policy password directly */
                session->auth.size = handle->auth.size;
                XMEMCPY(session->auth.buffer, handle->auth.buffer, handle->auth.size);
                session->policyPass = handle->policyPass;
            }
            else if (handle->policyAuth) {
                /* HMAC + policy auth value */
                int authDigestSz = TPM2_GetHashDigestSize(session->authHash);
                session->auth.size = authDigestSz + handle->auth.size;
                XMEMCPY(&session->auth.buffer[authDigestSz], handle->auth.buffer, handle->auth.size);
                session->policyAuth = handle->policyAuth;
            }
        }
    }
    session->name.size = name->size;
    XMEMCPY(session->name.name, name->name, session->name.size);

    return TPM_RC_SUCCESS;
}

int wolfTPM2_SetSessionHandle(WOLFTPM2_DEV* dev, int index,
    WOLFTPM2_SESSION* tpmSession)
{
    TPM2_AUTH_SESSION* session;

    if (dev == NULL || index >= MAX_SESSION_NUM || index < 0) {
        return BAD_FUNC_ARG;
    }

    session = &dev->session[index];
    session->sessionHandle = TPM_RS_PW;

    /* Set password handle unless TPM session is available */
    if (tpmSession) {
        session->sessionHandle = tpmSession->handle.hndl;

        session->auth.size = tpmSession->handle.auth.size;
        XMEMCPY(session->auth.buffer, tpmSession->handle.auth.buffer, tpmSession->handle.auth.size);

        session->name.size = tpmSession->handle.name.size;
        XMEMCPY(session->name.name, tpmSession->handle.name.name, tpmSession->handle.name.size);

        session->policyAuth = tpmSession->handle.policyAuth;
        session->policyPass = tpmSession->handle.policyPass;
    }

    TPM2_SetSessionAuth(dev->session);

    return TPM_RC_SUCCESS;
}


int wolfTPM2_Cleanup_ex(WOLFTPM2_DEV* dev, int doShutdown)
{
    int rc = 0;

    if (dev == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLFTPM_CRYPTOCB
    /* make sure crypto dev callback is unregistered */
    rc = wolfTPM2_ClearCryptoDevCb(dev, INVALID_DEVID);
    if (rc != 0)
        return rc;
#endif

    if (doShutdown && TPM2_GetActiveCtx() != NULL)  {
        Shutdown_In shutdownIn;
        XMEMSET(&shutdownIn, 0, sizeof(shutdownIn));
        shutdownIn.shutdownType = TPM_SU_CLEAR;
        rc = TPM2_Shutdown(&shutdownIn);
        if (rc != TPM_RC_SUCCESS) {
            /* finish cleanup and return error */
        }
    }

    TPM2_Cleanup(&dev->ctx);

    return rc;
}

int wolfTPM2_Cleanup(WOLFTPM2_DEV* dev)
{
#if defined(WOLFTPM_WINAPI)
    return wolfTPM2_Cleanup_ex(dev, 0);
#else
    return wolfTPM2_Cleanup_ex(dev, 1);
#endif
}


int wolfTPM2_CreatePrimaryKey_ex(WOLFTPM2_DEV* dev, WOLFTPM2_PKEY* pkey,
    TPM_HANDLE primaryHandle, TPMT_PUBLIC* publicTemplate,
    const byte* auth, int authSz)
{
    int rc;
    CreatePrimary_In  createPriIn;
    CreatePrimary_Out createPriOut;

    if (dev == NULL || pkey == NULL || publicTemplate == NULL)
        return BAD_FUNC_ARG;

    /* set session auth to blank */
    wolfTPM2_SetAuthPassword(dev, 0, NULL);

    /* clear output key buffer */
    XMEMSET(pkey, 0, sizeof(*pkey));

    /* setup create primary command */
    XMEMSET(&createPriIn, 0, sizeof(createPriIn));
    /* TPM_RH_OWNER, TPM_RH_ENDORSEMENT, TPM_RH_PLATFORM or TPM_RH_NULL */
    createPriIn.primaryHandle = primaryHandle;
    if (auth && authSz > 0) {
        int nameAlgDigestSz = TPM2_GetHashDigestSize(publicTemplate->nameAlg);
        /* truncate if longer than name size */
        if (nameAlgDigestSz > 0 && authSz > nameAlgDigestSz)
            authSz = nameAlgDigestSz;
        XMEMCPY(createPriIn.inSensitive.sensitive.userAuth.buffer, auth, authSz);
        /* make sure auth is same size as nameAlg digest size */
        if (nameAlgDigestSz > 0 && authSz < nameAlgDigestSz)
            authSz = nameAlgDigestSz;
        createPriIn.inSensitive.sensitive.userAuth.size = authSz;
    }
    XMEMCPY(&createPriIn.inPublic.publicArea, publicTemplate,
        sizeof(TPMT_PUBLIC));
    rc = TPM2_CreatePrimary(&createPriIn, &createPriOut);
    if (rc != TPM_RC_SUCCESS) {
        return rc;
    }
    pkey->handle.hndl = createPriOut.objectHandle;
    wolfTPM2_CopyAuth(&pkey->handle.auth,
        &createPriIn.inSensitive.sensitive.userAuth);
    wolfTPM2_CopyName(&pkey->handle.name, &createPriOut.name);
    wolfTPM2_CopySymmetric(&pkey->handle.symmetric,
        &createPriOut.outPublic.publicArea.parameters.asymDetail.symmetric);
    wolfTPM2_CopyPub(&pkey->pub, &createPriOut.outPublic);

    pkey->creationHash.size = createPriOut.creationHash.size;
    XMEMCPY(pkey->creationHash.buffer, createPriOut.creationHash.buffer,
        createPriOut.creationHash.size);

    pkey->creationTicket.tag = createPriOut.creationTicket.tag;
    pkey->creationTicket.hierarchy = createPriOut.creationTicket.hierarchy;
    pkey->creationTicket.digest.size = createPriOut.creationTicket.digest.size;
    XMEMCPY(pkey->creationTicket.digest.buffer,
        createPriOut.creationTicket.digest.buffer,
        createPriOut.creationTicket.digest.size);


    return rc;
}

int wolfTPM2_CreatePrimaryKey(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    TPM_HANDLE primaryHandle, TPMT_PUBLIC* publicTemplate,
    const byte* auth, int authSz)
{
    int rc;
    WOLFTPM2_PKEY pKey;
    if (dev == NULL || key == NULL || publicTemplate == NULL)
        return BAD_FUNC_ARG;
    rc = wolfTPM2_CreatePrimaryKey_ex(dev, &pKey, primaryHandle, publicTemplate,
        auth, authSz);
    if (rc == 0) {
        /* return only the handle and public information */
        XMEMCPY(&key->handle, &pKey.handle, sizeof(WOLFTPM2_HANDLE));
        XMEMCPY(&key->pub, &pKey.pub, sizeof(TPM2B_PUBLIC));
    }
    return rc;
}

int wolfTPM2_LoadPublicKey_ex(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    const TPM2B_PUBLIC* pub, TPM_HANDLE hierarchy)
{
    int rc;
    LoadExternal_In  loadExtIn;
    LoadExternal_Out loadExtOut;

    if (dev == NULL || key == NULL || pub == NULL)
        return BAD_FUNC_ARG;

    /* Loading public key */
    XMEMSET(&loadExtIn, 0, sizeof(loadExtIn));
    wolfTPM2_CopyPub(&loadExtIn.inPublic, pub);
    loadExtIn.hierarchy = hierarchy;
    rc = TPM2_LoadExternal(&loadExtIn, &loadExtOut);
    if (rc != TPM_RC_SUCCESS) {
        return rc;
    }
    key->handle.hndl = loadExtOut.objectHandle;
    wolfTPM2_CopySymmetric(&key->handle.symmetric,
            &loadExtIn.inPublic.publicArea.parameters.asymDetail.symmetric);
    wolfTPM2_CopyName(&key->handle.name, &loadExtOut.name);
    wolfTPM2_CopyPub(&key->pub, &loadExtIn.inPublic);


    return rc;
}
int wolfTPM2_LoadPublicKey(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    const TPM2B_PUBLIC* pub)
{
    return wolfTPM2_LoadPublicKey_ex(dev, key, pub, TPM_RH_OWNER);
}




int wolfTPM2_RsaEncrypt(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    TPM_ALG_ID padScheme, const byte* msg, int msgSz, byte* out, int* outSz)
{
    int rc;
    RSA_Encrypt_In  rsaEncIn;
    RSA_Encrypt_Out rsaEncOut;

    if (dev == NULL || key == NULL || msg == NULL || out == NULL ||
                                                                outSz == NULL) {
        return BAD_FUNC_ARG;
    }

    /* set session auth for key */
    wolfTPM2_SetAuthHandle(dev, 0, &key->handle);

    /* RSA Encrypt */
    XMEMSET(&rsaEncIn, 0, sizeof(rsaEncIn));
    rsaEncIn.keyHandle = key->handle.hndl;
    rsaEncIn.message.size = msgSz;
    XMEMCPY(rsaEncIn.message.buffer, msg, msgSz);
    /* TPM_ALG_NULL, TPM_ALG_OAEP, TPM_ALG_RSASSA or TPM_ALG_RSAPSS */
    rsaEncIn.inScheme.scheme = padScheme;
    rsaEncIn.inScheme.details.anySig.hashAlg = WOLFTPM2_WRAP_DIGEST;


    rc = TPM2_RSA_Encrypt(&rsaEncIn, &rsaEncOut);
    if (rc != TPM_RC_SUCCESS) {
        return rc;
    }

    *outSz = rsaEncOut.outData.size;
    XMEMCPY(out, rsaEncOut.outData.buffer, *outSz);


    return rc;
}

int wolfTPM2_RsaDecrypt(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    TPM_ALG_ID padScheme, const byte* in, int inSz, byte* msg, int* msgSz)
{
    int rc;
    RSA_Decrypt_In  rsaDecIn;
    RSA_Decrypt_Out rsaDecOut;

    if (dev == NULL || key == NULL || in == NULL || msg == NULL ||
                                                                msgSz == NULL) {
        return BAD_FUNC_ARG;
    }

    /* set session auth and name for key */
    wolfTPM2_SetAuthHandle(dev, 0, &key->handle);

    /* RSA Decrypt */
    XMEMSET(&rsaDecIn, 0, sizeof(rsaDecIn));
    rsaDecIn.keyHandle = key->handle.hndl;
    rsaDecIn.cipherText.size = inSz;
    XMEMCPY(rsaDecIn.cipherText.buffer, in, inSz);
    /* TPM_ALG_NULL, TPM_ALG_OAEP, TPM_ALG_RSASSA or TPM_ALG_RSAPSS */
    rsaDecIn.inScheme.scheme = padScheme;
    rsaDecIn.inScheme.details.anySig.hashAlg = WOLFTPM2_WRAP_DIGEST;


    rc = TPM2_RSA_Decrypt(&rsaDecIn, &rsaDecOut);
    if (rc != TPM_RC_SUCCESS) {
        return rc;
    }

    *msgSz = rsaDecOut.message.size;
    XMEMCPY(msg, rsaDecOut.message.buffer, *msgSz);


    return rc;
}

int wolfTPM2_ResetPCR(WOLFTPM2_DEV* dev, int pcrIndex)
{
    int rc;
    PCR_Reset_In pcrReset;
    XMEMSET(&pcrReset, 0, sizeof(pcrReset));
    pcrReset.pcrHandle = pcrIndex;
    rc = TPM2_PCR_Reset(&pcrReset);
    (void)dev;
    return rc;
}

/* TODO: Version that can read up to 8 PCR's at a time */
int wolfTPM2_ReadPCR(WOLFTPM2_DEV* dev, int pcrIndex, int hashAlg, byte* digest,
    int* pDigestLen)
{
    int rc;
    PCR_Read_In  pcrReadIn;
    PCR_Read_Out pcrReadOut;
    int digestLen = 0;

    if (dev == NULL || pcrIndex < (int)PCR_FIRST || pcrIndex > (int)PCR_LAST)
        return BAD_FUNC_ARG;

    /* set session auth to blank */
    if (dev->ctx.session) {
        wolfTPM2_SetAuthPassword(dev, 0, NULL);
    }

    XMEMSET(&pcrReadIn, 0, sizeof(pcrReadIn));
    wolfTPM2_SetupPCRSel(&pcrReadIn.pcrSelectionIn, hashAlg, pcrIndex);
    rc = TPM2_PCR_Read(&pcrReadIn, &pcrReadOut);
    if (rc != TPM_RC_SUCCESS) {
        return rc;
    }

    digestLen = (int)pcrReadOut.pcrValues.digests[0].size;
    if (digest)
        XMEMCPY(digest, pcrReadOut.pcrValues.digests[0].buffer, digestLen);


    if (pDigestLen)
        *pDigestLen = digestLen;

    return rc;
}

int wolfTPM2_ExtendPCR(WOLFTPM2_DEV* dev, int pcrIndex, int hashAlg,
    const byte* digest, int digestLen)
{
    int rc;
    PCR_Extend_In pcrExtend;

    if (dev == NULL || digestLen > TPM_MAX_DIGEST_SIZE) {
        return BAD_FUNC_ARG;
    }

    /* set session auth to blank */
    if (dev->ctx.session) {
        wolfTPM2_SetAuthPassword(dev, 0, NULL);
    }

    XMEMSET(&pcrExtend, 0, sizeof(pcrExtend));
    pcrExtend.pcrHandle = pcrIndex;
    pcrExtend.digests.count = 1;
    pcrExtend.digests.digests[0].hashAlg = hashAlg;
    XMEMCPY(pcrExtend.digests.digests[0].digest.H, digest, digestLen);
    rc = TPM2_PCR_Extend(&pcrExtend);
    if (rc != TPM_RC_SUCCESS) {
    }


    return rc;
}

int wolfTPM2_UnloadHandle(WOLFTPM2_DEV* dev, WOLFTPM2_HANDLE* handle)
{
    int rc;
    FlushContext_In in;

    if (dev == NULL || handle == NULL)
        return BAD_FUNC_ARG;

    /* don't try and unload null or persistent handles */
    if (handle->hndl == 0 || handle->hndl == TPM_RH_NULL ||
        (handle->hndl >= PERSISTENT_FIRST && handle->hndl <= PERSISTENT_LAST)) {
        return TPM_RC_SUCCESS;
    }

    XMEMSET(&in, 0, sizeof(in));
    in.flushHandle = handle->hndl;
    rc = TPM2_FlushContext(&in);
    if (rc != TPM_RC_SUCCESS) {
        return rc;
    }


    handle->hndl = TPM_RH_NULL;

    return TPM_RC_SUCCESS;
}

int wolfTPM2_NVReadAuthPolicy(WOLFTPM2_DEV* dev, WOLFTPM2_SESSION* tpmSession,
    TPM_ALG_ID pcrAlg, byte* pcrArray, word32 pcrArraySz, WOLFTPM2_NV* nv,
    word32 nvIndex, byte* dataBuf, word32* pDataSz, word32 offset)
{
    int rc = TPM_RC_SUCCESS;
    word32 pos = 0, toread, dataSz;
    NV_Read_In in;
    NV_Read_Out out;

    if (dev == NULL || nv == NULL || pDataSz == NULL || dataBuf == NULL) {
        return BAD_FUNC_ARG;
    }

    dataSz = *pDataSz;
    while (dataSz > 0) {
        toread = dataSz;
        if (toread > MAX_NV_BUFFER_SIZE)
            toread = MAX_NV_BUFFER_SIZE;

        /* Make sure the name is computed for the handle.
         * Name changes on each iteration for policy session. */
        if (!nv->handle.nameLoaded || (tpmSession != NULL
                         && TPM2_IS_POLICY_SESSION(tpmSession->handle.hndl))) {
            rc = wolfTPM2_NVOpen(dev, nv, nvIndex, NULL, 0);
            if (rc != 0)
                break;
        }
        /* For policy session recompute PCR for each iteration */
        if (tpmSession != NULL
                           && TPM2_IS_POLICY_SESSION(tpmSession->handle.hndl)) {
            /* PCR resets after each call for TPMA_SESSION_continueSession */
            rc = wolfTPM2_PolicyPCR(dev, tpmSession->handle.hndl,
                pcrAlg, pcrArray, pcrArraySz);
            if (rc != 0)
                break;

            /* Set policy session while saving nonceTPM */
            wolfTPM2_SetSessionHandle(dev, 0, tpmSession);
        }

        /* Necessary, because NVWrite has two handles, second is NV Index
         * If policy session Name will update via nonceTPM each iteration */
        rc  = wolfTPM2_SetAuthHandleName(dev, 0, &nv->handle);
        rc |= wolfTPM2_SetAuthHandleName(dev, 1, &nv->handle);
        if (rc != TPM_RC_SUCCESS) {
            rc = TPM_RC_FAILURE;
            break;
        }

        XMEMSET(&in, 0, sizeof(in));
        in.authHandle = nv->handle.hndl;
        in.nvIndex = nvIndex;
        in.offset = offset+pos;
        in.size = toread;

        rc = TPM2_NV_Read(&in, &out);
        if (rc != TPM_RC_SUCCESS) {
            break;
        }

        toread = out.data.size;
        if (dataBuf) {
            XMEMCPY(&dataBuf[pos], out.data.buffer, toread);
        }


        /* if we are done reading, exit loop */
        if (toread == 0) {
            break;
        }

        pos += toread;
        dataSz -= toread;
    }
    *pDataSz = pos;


    return rc;
}

int wolfTPM2_NVReadAuth(WOLFTPM2_DEV* dev, WOLFTPM2_NV* nv,
    word32 nvIndex, byte* dataBuf, word32* pDataSz, word32 offset)
{
    return wolfTPM2_NVReadAuthPolicy(dev, NULL, TPM_ALG_NULL, NULL, 0,
        nv, nvIndex, dataBuf, pDataSz, offset);
}

/* older API kept for compatibility, recommend using wolfTPM2_NVReadAuth */
int wolfTPM2_NVRead(WOLFTPM2_DEV* dev, TPM_HANDLE authHandle,
    word32 nvIndex, byte* dataBuf, word32* pDataSz, word32 offset)
{
    WOLFTPM2_NV nv;
    XMEMSET(&nv, 0, sizeof(nv));
    nv.handle.hndl = (TPM_HANDLE)nvIndex;
    (void)authHandle;
    return wolfTPM2_NVReadAuth(dev, &nv, nvIndex, dataBuf, pDataSz, offset);
}

int wolfTPM2_NVOpen(WOLFTPM2_DEV* dev, WOLFTPM2_NV* nv, word32 nvIndex,
    const byte* auth, word32 authSz)
{
    int rc = TPM_RC_SUCCESS;
    TPMS_NV_PUBLIC nvPublic;

    if (dev == NULL || nv == NULL || authSz > sizeof(nv->handle.auth.buffer)) {
        return BAD_FUNC_ARG;
    }

    /* build the "handle" */
    nv->handle.hndl = nvIndex;
    /* auth can also be set already via nv->handle */
    if (auth != NULL && authSz > 0) {
        nv->handle.auth.size = authSz;
        XMEMCPY(nv->handle.auth.buffer, auth, authSz);
    }

    /* Read the NV Index publicArea to have up to date NV Index Name */
    rc = wolfTPM2_NVReadPublic(dev, nv->handle.hndl, &nvPublic);
    if (rc != TPM_RC_SUCCESS) {
        return rc;
    }

    /* flag that the NV was "opened" and name was loaded */
    nv->handle.nameLoaded = 1;
    nv->attributes = nvPublic.attributes;

    return rc;
}

int wolfTPM2_NVReadPublic(WOLFTPM2_DEV* dev, word32 nvIndex,
    TPMS_NV_PUBLIC* nvPublic)
{
    int rc;
    NV_ReadPublic_In  in;
    NV_ReadPublic_Out out;

    if (dev == NULL) {
        return BAD_FUNC_ARG;
    }

    XMEMSET(&in, 0, sizeof(in));
    in.nvIndex = nvIndex;
    rc = TPM2_NV_ReadPublic(&in, &out);
    if (rc != TPM_RC_SUCCESS) {
        return rc;
    }


    if (nvPublic) {
        wolfTPM2_CopyNvPublic(nvPublic, &out.nvPublic.nvPublic);
    }

    return rc;
}

/* Hashing */
/* usageAuth: Optional auth for handle */
int wolfTPM2_HashStart(WOLFTPM2_DEV* dev, WOLFTPM2_HASH* hash,
    TPMI_ALG_HASH hashAlg, const byte* usageAuth, word32 usageAuthSz)
{
    int rc;
    HashSequenceStart_In in;
    HashSequenceStart_Out out;

    if (dev == NULL || hash == NULL || hashAlg == TPM_ALG_NULL ||
        (usageAuthSz > 0 && usageAuth == NULL)) {
        return BAD_FUNC_ARG;
    }

    /* Capture usage auth */
    if (usageAuthSz > sizeof(hash->handle.auth.buffer))
        usageAuthSz = sizeof(hash->handle.auth.buffer);
    XMEMSET(hash, 0, sizeof(WOLFTPM2_HASH));
    hash->handle.auth.size = usageAuthSz;
    if (usageAuth != NULL)
        XMEMCPY(hash->handle.auth.buffer, usageAuth, usageAuthSz);

    XMEMSET(&in, 0, sizeof(in));
    wolfTPM2_CopyAuth(&in.auth, &hash->handle.auth);
    in.hashAlg = hashAlg;
    rc = TPM2_HashSequenceStart(&in, &out);
    if (rc != TPM_RC_SUCCESS) {
        return rc;
    }

    /* Capture hash sequence handle */
    hash->handle.hndl = out.sequenceHandle;


    return rc;
}

int wolfTPM2_HashUpdate(WOLFTPM2_DEV* dev, WOLFTPM2_HASH* hash,
    const byte* data, word32 dataSz)
{
    int rc = TPM_RC_SUCCESS;
    SequenceUpdate_In in;
    word32 pos = 0, hashSz;

    if (dev == NULL || hash == NULL || (data == NULL && dataSz > 0) ||
            hash->handle.hndl == 0) {
        return BAD_FUNC_ARG;
    }

    /* set session auth for hash handle */
    wolfTPM2_SetAuthHandle(dev, 0, &hash->handle);

    XMEMSET(&in, 0, sizeof(in));
    in.sequenceHandle = hash->handle.hndl;

    while (pos < dataSz) {
        hashSz = dataSz - pos;
        if (hashSz > sizeof(in.buffer.buffer))
            hashSz = sizeof(in.buffer.buffer);

        in.buffer.size = hashSz;
        XMEMCPY(in.buffer.buffer, &data[pos], hashSz);
        rc = TPM2_SequenceUpdate(&in);
        if (rc != TPM_RC_SUCCESS) {
            return rc;
        }
        pos += hashSz;
    }


    return rc;
}

int wolfTPM2_HashFinish(WOLFTPM2_DEV* dev, WOLFTPM2_HASH* hash,
    byte* digest, word32* digestSz)
{
    int rc;
    SequenceComplete_In in;
    SequenceComplete_Out out;

    if (dev == NULL || hash == NULL || digest == NULL || digestSz == NULL ||
            hash->handle.hndl == 0) {
        return BAD_FUNC_ARG;
    }

    /* set session auth for hash handle */
    wolfTPM2_SetAuthHandle(dev, 0, &hash->handle);

    XMEMSET(&in, 0, sizeof(in));
    in.sequenceHandle = hash->handle.hndl;
    in.hierarchy = TPM_RH_NULL;
    rc = TPM2_SequenceComplete(&in, &out);

    /* mark hash handle as done */
    hash->handle.hndl = TPM_RH_NULL;

    if (rc != TPM_RC_SUCCESS) {
        return rc;
    }

    if (out.result.size > *digestSz)
        out.result.size = *digestSz;
    *digestSz = out.result.size;
    XMEMCPY(digest, out.result.buffer, *digestSz);


    return rc;
}


int wolfTPM2_UnloadHandles(WOLFTPM2_DEV* dev, word32 handleStart,
    word32 handleCount)
{
    int rc = TPM_RC_SUCCESS;
    word32 hndl;
    WOLFTPM2_HANDLE handle;
    if (dev == NULL) {
        return BAD_FUNC_ARG;
    }
    XMEMSET(&handle, 0, sizeof(handle));
    wolfTPM2_CopyAuth(&handle.auth, &dev->session[0].auth);

    for (hndl=handleStart; hndl < handleStart+handleCount; hndl++) {
        handle.hndl = hndl;
        /* ignore return code failures */
        (void)wolfTPM2_UnloadHandle(dev, &handle);
    }
    return rc;
}

/******************************************************************************/
/* --- END Wrapper Device Functions-- */
/******************************************************************************/


/******************************************************************************/
/* --- BEGIN Utility Functions -- */
/******************************************************************************/

int GetKeyTemplateRSA(TPMT_PUBLIC* publicTemplate,
    TPM_ALG_ID nameAlg, TPMA_OBJECT objectAttributes, int keyBits, long exponent,
    TPM_ALG_ID sigScheme, TPM_ALG_ID sigHash)
{
    if (publicTemplate == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(publicTemplate, 0, sizeof(TPMT_PUBLIC));
    publicTemplate->type = TPM_ALG_RSA;
    publicTemplate->unique.rsa.size = keyBits / 8;
    publicTemplate->nameAlg = nameAlg;
    publicTemplate->objectAttributes = objectAttributes;
    publicTemplate->parameters.rsaDetail.keyBits = keyBits;
    publicTemplate->parameters.rsaDetail.exponent = (UINT32)exponent;
    publicTemplate->parameters.rsaDetail.scheme.scheme = sigScheme;
    publicTemplate->parameters.rsaDetail.scheme.details.anySig.hashAlg = sigHash;
    /* For restricted decryption key enable symmetric */
    if ((objectAttributes & TPMA_OBJECT_decrypt) &&
        (objectAttributes & TPMA_OBJECT_restricted)) {
        publicTemplate->parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
        publicTemplate->parameters.rsaDetail.symmetric.keyBits.aes =
            (keyBits > 2048) ? 256 : 128;
        publicTemplate->parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_CFB;
    }
    else {
        publicTemplate->parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
    }

    return TPM_RC_SUCCESS;
}

int wolfTPM2_GetKeyTemplate_EK(TPMT_PUBLIC* publicTemplate, TPM_ALG_ID alg,
    int keyBits, TPM_ECC_CURVE curveID, TPM_ALG_ID nameAlg, int highRange)
{
    int rc;
    (void)nameAlg;
    (void)curveID;
    TPMA_OBJECT objectAttributes = (
        TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent |
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_adminWithPolicy |
        TPMA_OBJECT_restricted | TPMA_OBJECT_decrypt);
    if (highRange) {
        /* High range requires userWithAuth=1 */
        objectAttributes |= TPMA_OBJECT_userWithAuth;
    }

    if (alg == TPM_ALG_RSA) {
        rc = GetKeyTemplateRSA(publicTemplate, nameAlg,
            objectAttributes, keyBits, 0, TPM_ALG_NULL, TPM_ALG_NULL);
        if (rc == 0 && highRange) { /* high range uses 0 unique size */
            publicTemplate->unique.rsa.size = 0;
        }
    }
    else {
        rc = BAD_FUNC_ARG; /* not supported */
    }

    if (rc == 0) {
        if (nameAlg == TPM_ALG_SHA256 && !highRange) {
            publicTemplate->authPolicy.size = sizeof(TPM_20_EK_AUTH_POLICY);
            XMEMCPY(publicTemplate->authPolicy.buffer,
                TPM_20_EK_AUTH_POLICY, publicTemplate->authPolicy.size);
        }
        else if (nameAlg == TPM_ALG_SHA256) {
            publicTemplate->authPolicy.size = sizeof(TPM_20_EK_AUTH_POLICY_SHA256);
            XMEMCPY(publicTemplate->authPolicy.buffer,
                TPM_20_EK_AUTH_POLICY_SHA256, publicTemplate->authPolicy.size);
        }
    #ifdef WOLFSSL_SHA384
        else if (nameAlg == TPM_ALG_SHA384) {
            publicTemplate->authPolicy.size = sizeof(TPM_20_EK_AUTH_POLICY_SHA384);
            XMEMCPY(publicTemplate->authPolicy.buffer,
                TPM_20_EK_AUTH_POLICY_SHA384, publicTemplate->authPolicy.size);
        }
    #endif
    #ifdef WOLFSSL_SHA512
        else if (nameAlg == TPM_ALG_SHA512) {
            publicTemplate->authPolicy.size = sizeof(TPM_20_EK_AUTH_POLICY_SHA512);
            XMEMCPY(publicTemplate->authPolicy.buffer,
                TPM_20_EK_AUTH_POLICY_SHA512, publicTemplate->authPolicy.size);
        }
    #endif
    }

    return rc;
}

int wolfTPM2_GetKeyTemplate_EKIndex(word32 nvIndex,
    TPMT_PUBLIC* publicTemplate)
{
    TPM_ALG_ID alg = TPM_ALG_NULL;
    TPM_ALG_ID nameAlg = TPM_ALG_NULL;
    TPM_ECC_CURVE curveID = TPM_ECC_NONE;
    uint32_t keyBits = 0;
    int highRange = 0;

    /* validate index is in NV EK range */
    if (nvIndex < TPM_20_TCG_NV_SPACE ||
        nvIndex > TPM_20_TCG_NV_SPACE + 0x1FF) {
        return BAD_FUNC_ARG;
    }

    /* determine if low or high range */
    if (nvIndex >= TPM2_NV_EK_RSA2048) {
        highRange = 1;
    }

    /* Determine algorithm based on index */
    switch (nvIndex) {
        case TPM2_NV_RSA_EK_CERT: /* EK (Low Range): RSA 2048 */
        case TPM2_NV_EK_RSA2048:  /* EK (High Range) */
            alg = TPM_ALG_RSA;
            nameAlg = TPM_ALG_SHA256;
            keyBits = 2048;
            break;
        case TPM2_NV_EK_RSA3072:
            alg = TPM_ALG_RSA;
            nameAlg = TPM_ALG_SHA384;
            keyBits = 3072;
            break;
        case TPM2_NV_EK_RSA4096:
            alg = TPM_ALG_RSA;
            nameAlg = TPM_ALG_SHA512;
            keyBits = 4096;
            break;
        case TPM2_NV_ECC_EK_CERT: /* EK (Low Range): ECC P256 */
        case TPM2_NV_EK_ECC_P256: /* EK (High Range) */
            alg = TPM_ALG_ECC;
            curveID = TPM_ECC_NIST_P256;
            nameAlg = TPM_ALG_SHA256;
            keyBits = 256;
            break;
        case TPM2_NV_EK_ECC_P384:
            alg = TPM_ALG_ECC;
            curveID = TPM_ECC_NIST_P384;
            nameAlg = TPM_ALG_SHA384;
            keyBits = 384;
            break;
        case TPM2_NV_EK_ECC_P521:
            alg = TPM_ALG_ECC;
            curveID = TPM_ECC_NIST_P521;
            nameAlg = TPM_ALG_SHA512;
            keyBits = 521;
            break;
        case TPM2_NV_EK_ECC_SM2:
            alg = TPM_ALG_SM2;
            curveID = TPM_ECC_SM2_P256;
            nameAlg = TPM_ALG_SHA256;
            keyBits = 256;
            break;
        default:
            alg = TPM_ALG_NULL;
            curveID = TPM_ECC_NONE;
            nameAlg = TPM_ALG_NULL;
            keyBits = 0;
            break;
    }

    return wolfTPM2_GetKeyTemplate_EK(publicTemplate, alg, keyBits, curveID,
            nameAlg, highRange);
}


static void wolfTPM2_CopySymmetric(TPMT_SYM_DEF* out, const TPMT_SYM_DEF* in)
{
    if (out == NULL || in == NULL)
        return;

    out->algorithm = in->algorithm;
    switch (out->algorithm) {
        case TPM_ALG_XOR:
            out->keyBits.xorr = in->keyBits.xorr;
            break;
        case TPM_ALG_AES:
            out->keyBits.aes = in->keyBits.aes;
            out->mode.aes = in->mode.aes;
            break;
        case TPM_ALG_NULL:
            break;
        default:
            out->keyBits.sym = in->keyBits.sym;
            out->mode.sym = in->mode.sym;
            break;
    }
}

static void wolfTPM2_CopyName(TPM2B_NAME* out, const TPM2B_NAME* in)
{
    if (out != NULL && in != NULL) {
        out->size = in->size;
        if (out->size > (UINT16)sizeof(out->name))
            out->size = (UINT16)sizeof(out->name);
        XMEMCPY(out->name, in->name, out->size);
    }
}

static void wolfTPM2_CopyAuth(TPM2B_AUTH* out, const TPM2B_AUTH* in)
{
    if (out != NULL && in != NULL) {
        out->size = in->size;
        if (out->size > (UINT16)sizeof(out->buffer))
            out->size = (UINT16)sizeof(out->buffer);
        XMEMCPY(out->buffer, in->buffer, out->size);
    }
}

static void wolfTPM2_CopyPubT(TPMT_PUBLIC* out, const TPMT_PUBLIC* in)
{
    if (out == NULL || in == NULL)
        return;

    out->type = in->type;
    out->nameAlg = in->nameAlg;
    out->objectAttributes = in->objectAttributes;
    out->authPolicy.size = in->authPolicy.size;
    if (out->authPolicy.size > 0) {
        if (out->authPolicy.size >
                (UINT16)sizeof(out->authPolicy.buffer))
            out->authPolicy.size =
                (UINT16)sizeof(out->authPolicy.buffer);
        XMEMCPY(out->authPolicy.buffer,
                in->authPolicy.buffer,
                out->authPolicy.size);
    }

    switch (out->type) {
    case TPM_ALG_KEYEDHASH:
        out->parameters.keyedHashDetail.scheme =
            in->parameters.keyedHashDetail.scheme;

        out->unique.keyedHash.size =
            in->unique.keyedHash.size;
        if (out->unique.keyedHash.size >
                (UINT16)sizeof(out->unique.keyedHash.buffer)) {
            out->unique.keyedHash.size =
                (UINT16)sizeof(out->unique.keyedHash.buffer);
        }
        XMEMCPY(out->unique.keyedHash.buffer,
                in->unique.keyedHash.buffer,
                out->unique.keyedHash.size);
        break;
    case TPM_ALG_SYMCIPHER:
        out->parameters.symDetail.sym.algorithm =
            in->parameters.symDetail.sym.algorithm;
        out->parameters.symDetail.sym.keyBits.sym =
            in->parameters.symDetail.sym.keyBits.sym;
        out->parameters.symDetail.sym.mode.sym =
            in->parameters.symDetail.sym.mode.sym;

        out->unique.sym.size =
            in->unique.sym.size;
        if (out->unique.sym.size >
                (UINT16)sizeof(out->unique.sym.buffer)) {
            out->unique.sym.size =
                (UINT16)sizeof(out->unique.sym.buffer);
        }
        XMEMCPY(out->unique.sym.buffer,
                in->unique.sym.buffer,
                out->unique.sym.size);
        break;
    case TPM_ALG_RSA:
        wolfTPM2_CopySymmetric(&out->parameters.rsaDetail.symmetric,
            &in->parameters.rsaDetail.symmetric);
        out->parameters.rsaDetail.scheme.scheme =
            in->parameters.rsaDetail.scheme.scheme;
        if (out->parameters.rsaDetail.scheme.scheme != TPM_ALG_NULL)
            out->parameters.rsaDetail.scheme.details.anySig.hashAlg =
                in->parameters.rsaDetail.scheme.details.anySig.hashAlg;
        out->parameters.rsaDetail.keyBits =
            in->parameters.rsaDetail.keyBits;
        out->parameters.rsaDetail.exponent =
            in->parameters.rsaDetail.exponent;

        out->unique.rsa.size =
            in->unique.rsa.size;
        if (out->unique.rsa.size >
                (UINT16)sizeof(out->unique.rsa.buffer)) {
            out->unique.rsa.size =
                (UINT16)sizeof(out->unique.rsa.buffer);
        }
        XMEMCPY(out->unique.rsa.buffer,
                in->unique.rsa.buffer,
                out->unique.rsa.size);
        break;
    case TPM_ALG_ECC:
        break;
    default:
        wolfTPM2_CopySymmetric(&out->parameters.asymDetail.symmetric,
            &in->parameters.asymDetail.symmetric);
        out->parameters.asymDetail.scheme.scheme =
            in->parameters.asymDetail.scheme.scheme;
        out->parameters.asymDetail.scheme.details.anySig.hashAlg =
            in->parameters.asymDetail.scheme.details.anySig.hashAlg;
        break;
    }
}

static void wolfTPM2_CopyPub(TPM2B_PUBLIC* out, const TPM2B_PUBLIC* in)
{
    if (out != NULL && in != NULL) {
        out->size = in->size;
        wolfTPM2_CopyPubT(&out->publicArea, &in->publicArea);
    }
}


static void wolfTPM2_CopyNvPublic(TPMS_NV_PUBLIC* out, const TPMS_NV_PUBLIC* in)
{
    if (out != NULL && in != NULL) {
        out->attributes = in->attributes;
        out->authPolicy.size = in->authPolicy.size;
        if (out->authPolicy.size > 0) {
            if (out->authPolicy.size > (UINT16)sizeof(out->authPolicy.buffer)) {
                out->authPolicy.size = (UINT16)sizeof(out->authPolicy.buffer);
            }
            XMEMCPY(out->authPolicy.buffer, in->authPolicy.buffer, out->authPolicy.size);
        }
        out->dataSize = in->dataSize;
        out->nameAlg = in->nameAlg;
        out->nvIndex = in->nvIndex;
    }
}


int wolfTPM2_PolicyPCR(WOLFTPM2_DEV* dev, TPM_HANDLE sessionHandle,
    TPM_ALG_ID pcrAlg, byte* pcrArray, word32 pcrArraySz)
{
    int rc;
    PolicyPCR_In policyPcr[1];

    if (dev == NULL || pcrArray == NULL || pcrArraySz == 0)
        return BAD_FUNC_ARG;

    XMEMSET(policyPcr, 0, sizeof(PolicyPCR_In));

    /* add PolicyPCR to the policy */
    policyPcr->policySession = sessionHandle;
    TPM2_SetupPCRSelArray(&policyPcr->pcrs, pcrAlg, pcrArray, pcrArraySz);

    rc = TPM2_PolicyPCR(policyPcr);

    return rc;
}

#endif /* !WOLFTPM2_NO_WRAPPER */
