/* tpm2_wrap.c
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
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

#include <wolftpm/tpm2_wrap.h>
#include <wolftpm/tpm2_param_enc.h>

#ifndef WOLFTPM2_NO_WRAPPER

/* For some struct to buffer conversions */
#include <wolftpm/tpm2_packet.h>
#ifndef WOLFTPM2_NO_WOLFCRYPT
/* Required in wolfTPM2_CreateAuth() for name computation of NV handles */
#include <wolfssl/wolfcrypt/hash.h>
#endif


/* Local Functions */
static int wolfTPM2_GetCapabilities_NoDev(WOLFTPM2_CAPS* cap);


/******************************************************************************/
/* --- BEGIN Wrapper Device Functions -- */
/******************************************************************************/

static int wolfTPM2_Init_ex(TPM2_CTX* ctx, TPM2HalIoCb ioCb, void* userCtx,
    int timeoutTries)
{
    int rc;

#if !defined(WOLFTPM_LINUX_DEV) && !defined(WOLFTPM_WINAPI)
    Startup_In startupIn;
#if defined(WOLFTPM_MCHP) || defined(WOLFTPM_PERFORM_SELFTEST)
    SelfTest_In selfTest;
#endif
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
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_Init failed %d: %s\n", rc, wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }
#ifdef DEBUG_WOLFTPM
    printf("TPM2: Caps 0x%08x, Did 0x%04x, Vid 0x%04x, Rid 0x%2x \n",
        ctx->caps,
        ctx->did_vid >> 16,
        ctx->did_vid & 0xFFFF,
        ctx->rid);
#endif

#if !defined(WOLFTPM_LINUX_DEV) && !defined(WOLFTPM_WINAPI)
    /* startup */
    XMEMSET(&startupIn, 0, sizeof(Startup_In));
    startupIn.startupType = TPM_SU_CLEAR;
    rc = TPM2_Startup(&startupIn);
    if (rc != TPM_RC_SUCCESS &&
        rc != TPM_RC_INITIALIZE /* TPM_RC_INITIALIZE = Already started */ ) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_Startup failed %d: %s\n", rc, wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }
#ifdef DEBUG_WOLFTPM
    printf("TPM2_Startup pass\n");
#endif

#if defined(WOLFTPM_MCHP) || defined(WOLFTPM_PERFORM_SELFTEST)
    /* Do full self-test (Chips such as ATTPM20 require this before some operations) */
    XMEMSET(&selfTest, 0, sizeof(selfTest));
    selfTest.fullTest = YES;
    rc = TPM2_SelfTest(&selfTest);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_SelfTest failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
    #endif
        return rc;
    }
#ifdef DEBUG_WOLFTPM
    printf("TPM2_SelfTest pass\n");
#endif
#else
    rc = TPM_RC_SUCCESS;
#endif /* WOLFTPM_MCHP || WOLFTPM_PERFORM_SELFTEST */
#endif /* !defined(WOLFTPM_LINUX_DEV) && !defined(WOLFTPM_WINAPI) */

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

/* Access already started TPM module */
int wolfTPM2_OpenExisting(WOLFTPM2_DEV* dev, TPM2HalIoCb ioCb, void* userCtx)
{
    int rc;

    if (dev == NULL) {
        return BAD_FUNC_ARG;
    }

    XMEMSET(dev, 0, sizeof(WOLFTPM2_DEV));

    /* The 0 startup indicates use existing locality */
    rc = wolfTPM2_Init_ex(&dev->ctx, ioCb, userCtx, 0);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_Init failed %d: %s\n", rc, wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }

    /* define the default session auth */
    XMEMSET(dev->session, 0, sizeof(dev->session));
    wolfTPM2_SetAuthPassword(dev, 0, NULL);

    return rc;
}

int wolfTPM2_GetTpmDevId(WOLFTPM2_DEV* dev)
{
    if (dev == NULL) {
        return BAD_FUNC_ARG;
    }

    return dev->ctx.did_vid; /* return something besides INVALID_DEVID */
}

int wolfTPM2_SelfTest(WOLFTPM2_DEV* dev)
{
    int rc;
    SelfTest_In selfTest;

    if (dev == NULL)
        return BAD_FUNC_ARG;

    /* Full self test */
    XMEMSET(&selfTest, 0, sizeof(selfTest));
    selfTest.fullTest = YES;
    rc = TPM2_SelfTest(&selfTest);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_SelfTest failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
    #endif
        return rc;
    }
#ifdef DEBUG_WOLFTPM
    printf("TPM2_SelfTest pass\n");
#endif

    return rc;
}

/* Infineon SLB9670
 *  TPM_PT_MANUFACTURER     "IFX"
 *  TPM_PT_VENDOR_STRING_1  "SLB9"
 *  TPM_PT_VENDOR_STRING_2  "670 "
 *  TPM_PT_FIRMWARE_VERSION_1 0x00070055 = v7.85
 *  TPM_PT_FIRMWARE_VERSION_2 0x0011CB02
 *      Byte  1: reserved.
 *      Bytes 2-3: build num = 11CB,
 *      Byte  4: 0x00 (TPM CC), 0x02 (no CC)
 *  TPM_PT_MODES = Bit 0 = FIPS_140_2
 */

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
                if (caps->mfg == TPM_MFG_INFINEON || caps->mfg == TPM_MFG_NUVOTON) {
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
    in.capability = TPM_CAP_TPM_PROPERTIES;
    in.property = TPM_PT_MANUFACTURER;
    in.propertyCount = 8;
    rc = TPM2_GetCapability(&in, &out);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_GetCapability failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
    #endif
        return rc;
    }
    rc = wolfTPM2_ParseCapabilities(cap, &out.capabilityData.data.tpmProperties);
    if (rc != 0)
        return rc;

    /* Get Capability TPM_PT_MODES */
    XMEMSET(&in, 0, sizeof(in));
    in.capability = TPM_CAP_TPM_PROPERTIES;
    in.property = TPM_PT_MODES;
    in.propertyCount = 1;
    rc = TPM2_GetCapability(&in, &out);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_GetCapability failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
    #endif
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

int wolfTPM2_UnsetAuth(WOLFTPM2_DEV* dev, int index)
{
    TPM2_AUTH_SESSION* session;

    if (dev == NULL || index >= MAX_SESSION_NUM) {
        return BAD_FUNC_ARG;
    }

    session = &dev->session[index];
    XMEMSET(session, 0, sizeof(TPM2_AUTH_SESSION));

    return TPM2_SetSessionAuth(dev->session);
}

int wolfTPM2_SetAuth(WOLFTPM2_DEV* dev, int index,
    TPM_HANDLE sessionHandle, const TPM2B_AUTH* auth,
    TPMA_SESSION sessionAttributes, const TPM2B_NAME* name)
{
    TPM2_AUTH_SESSION* session;

    if (dev == NULL || index >= MAX_SESSION_NUM) {
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
    if (handle) {
        auth = &handle->auth;
        name = &handle->name;
    }
    return wolfTPM2_SetAuth(dev, index, TPM_RS_PW, auth, 0, name);
}

int wolfTPM2_SetNameHandle(WOLFTPM2_DEV* dev, int index,
    const WOLFTPM2_HANDLE* handle)
{
    const TPM2B_NAME* name = NULL;
    TPM2_AUTH_SESSION* session;

    if (dev == NULL || handle == NULL || index >= MAX_SESSION_NUM) {
        return BAD_FUNC_ARG;
    }

    name = &handle->name;
    session = &dev->session[index];

    session->name.size = name->size;
    XMEMCPY(session->name.name, name->name, session->name.size);
    return TPM_RC_SUCCESS;
}

int wolfTPM2_SetAuthSession(WOLFTPM2_DEV* dev, int index,
    const WOLFTPM2_SESSION* tpmSession, TPMA_SESSION sessionAttributes)
{
    int rc;

    if (dev == NULL || index >= MAX_SESSION_NUM) {
        return BAD_FUNC_ARG;
    }

    if (tpmSession == NULL) {
        /* clearing auth session */
        XMEMSET(&dev->session[index], 0, sizeof(TPM2_AUTH_SESSION));
        return TPM_RC_SUCCESS;
    }

    rc = wolfTPM2_SetAuth(dev, index, tpmSession->handle.hndl,
        &tpmSession->handle.auth, sessionAttributes, NULL);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_AUTH_SESSION* session = &dev->session[index];

        /* define the symmetric algorithm */
        session->authHash = tpmSession->authHash;
        session->symmetric = tpmSession->handle.symmetric;

        /* fresh nonce generated in TPM2_CommandProcess based on this size */
        session->nonceCaller.size = TPM2_GetHashDigestSize(WOLFTPM2_WRAP_DIGEST);

        /* Capture TPM provided nonce */
        session->nonceTPM.size = tpmSession->nonceTPM.size;
        XMEMCPY(session->nonceTPM.buffer, tpmSession->nonceTPM.buffer,
            session->nonceTPM.size);

        /* Parameter Encryption session will have an hmac added later.
         * Reserve space, the same way it was done for nonceCaller above.
         */
        if (session->sessionHandle != TPM_RS_PW &&
            ((session->sessionAttributes & TPMA_SESSION_encrypt) ||
             (session->sessionAttributes & TPMA_SESSION_decrypt))) {
            session->auth.size = TPM2_GetHashDigestSize(session->authHash);
        }
    }
    return rc;
}

int wolfTPM2_Cleanup_ex(WOLFTPM2_DEV* dev, int doShutdown)
{
    int rc = 0;

    if (dev == NULL) {
        return BAD_FUNC_ARG;
    }

#if !defined(WOLFTPM2_NO_WOLFCRYPT) && (defined(WOLF_CRYPTO_DEV) || defined(WOLF_CRYPTO_CB))
    /* make sure crypto dev callback is unregistered */
    rc = wolfTPM2_ClearCryptoDevCb(dev, INVALID_DEVID);
    if (rc != 0)
    	return rc;
#endif

    if (doShutdown)  {
        Shutdown_In shutdownIn;
        XMEMSET(&shutdownIn, 0, sizeof(shutdownIn));
        shutdownIn.shutdownType = TPM_SU_CLEAR;
        rc = TPM2_Shutdown(&shutdownIn);
        if (rc != TPM_RC_SUCCESS) {
        #ifdef DEBUG_WOLFTPM
            printf("TPM2_Shutdown failed %d: %s\n", rc, wolfTPM2_GetRCString(rc));
        #endif
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

#ifndef WOLFTPM2_NO_WOLFCRYPT
#ifndef NO_RSA
/* returns both the plaintext and encrypted salt, based on the salt key bPublic. */
int wolfTPM2_RSA_Salt(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* tpmKey,
    TPM2B_DIGEST *salt, TPM2B_ENCRYPTED_SECRET *encSalt, TPMT_PUBLIC *publicArea)
{
    int rc;
    WC_RNG* rng;
    enum wc_HashType hashType;
    const char* label = "SECRET";
    int mgf;
    RsaKey rsaKey;

    if (dev == NULL || salt == NULL || encSalt == NULL || publicArea == NULL) {
        return BAD_FUNC_ARG;
    }

    if (publicArea->nameAlg == TPM_ALG_SHA1) {
        hashType = WC_HASH_TYPE_SHA;
        mgf = WC_MGF1SHA1;
    }
    else if (publicArea->nameAlg == TPM_ALG_SHA256) {
        hashType = WC_HASH_TYPE_SHA256;
        mgf = WC_MGF1SHA256;
    }
    else {
        return NOT_COMPILED_IN;
    }

    rc = TPM2_GetWolfRng(&rng);
    if (rc != TPM_RC_SUCCESS)
        return rc;

    rc = wc_InitRsaKey_ex(&rsaKey, NULL, INVALID_DEVID);
    if (rc != 0) {
        return rc;
    }
    wc_RsaSetRNG(&rsaKey, rng);
    rc = wolfTPM2_RsaKey_TpmToWolf(dev, tpmKey, &rsaKey);
    if (rc != 0) {
        wc_FreeRsaKey(&rsaKey);
        return rc;
    }

    encSalt->size = publicArea->unique.rsa.size;
    rc = wc_RsaPublicEncrypt_ex(
        salt->buffer,    /* in pointer to the buffer for encryption */
        salt->size,      /* inLen length of in parameter */
        encSalt->secret, /* out encrypted msg created */
        encSalt->size,   /* outLen length of buffer available to hold encrypted msg */
        &rsaKey,         /* key initialized RSA key struct */
        rng,             /* rng initialized WC_RNG struct */
        WC_RSA_OAEP_PAD, /* type type of padding to use (WC_RSA_OAEP_PAD or WC_RSA_PKCSV15_PAD) */
        hashType,        /* hash type of hash to use (choices can be found in hash.h) */
        mgf,             /* mgf type of mask generation function to use */
        (byte*)label,    /* label an optional label to associate with encrypted message */
        (word32)XSTRLEN(label)+1 /* labelSz size of the optional label used */
    );

    wc_FreeRsaKey(&rsaKey);

    if (rc != encSalt->size) {
        return BUFFER_E;
    }

    return 0;
}
#endif /* !NO_RSA */

int wolfTPM2_EncryptSalt(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* tpmKey,
    StartAuthSession_In* in, TPM2B_AUTH* bindAuth, TPM2B_DIGEST* salt)
{
    int rc;

    /* if a tpmKey is not present then we are using an unsalted session */
    if (tpmKey == NULL) {
        return TPM_RC_SUCCESS;
    }

    /* generate a salt */
    salt->size = TPM2_GetHashDigestSize(in->authHash);
    if (salt->size <= 0) {
        return TPM_RC_FAILURE;
    }
    rc = TPM2_GetNonce(salt->buffer, salt->size);
    if (rc != 0) {
        return rc;
    }

#ifdef WOLFTPM_DEBUG_VERBOSE
    printf("Session Salt %d\n", salt->size);
    TPM2_PrintBin(salt->buffer, salt->size);
#endif

    switch (tpmKey->pub.publicArea.type) {
    #ifdef HAVE_ECC
        case TPM_ALG_ECC:
            /* TODO: Add ECC encrypted salt */
            rc = NOT_COMPILED_IN;
            break;
    #endif
    #ifndef NO_RSA
        case TPM_ALG_RSA:
            rc = wolfTPM2_RSA_Salt(dev, tpmKey, salt, &in->encryptedSalt,
                &tpmKey->pub.publicArea);
            break;
    #endif
        default:
            rc = NOT_COMPILED_IN;
            break;
    }

    (void)bindAuth; /* TODO: Add bind support */

    return rc;
}
#endif /* !WOLFTPM2_NO_WOLFCRYPT */

int wolfTPM2_StartSession(WOLFTPM2_DEV* dev, WOLFTPM2_SESSION* session,
    WOLFTPM2_KEY* tpmKey, WOLFTPM2_HANDLE* bind, TPM_SE sesType,
    int encDecAlg)
{
    int rc;
    StartAuthSession_In  authSesIn;
    StartAuthSession_Out authSesOut;
    TPM2B_AUTH* bindAuth = NULL;
    TPM2B_DATA keyIn;
    TPMI_ALG_HASH authHash = WOLFTPM2_WRAP_DIGEST;
    int hashDigestSz;

    if (dev == NULL || session == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(session, 0, sizeof(WOLFTPM2_SESSION));
    XMEMSET(&authSesIn, 0, sizeof(authSesIn));

    authSesIn.authHash = authHash;
    hashDigestSz = TPM2_GetHashDigestSize(authHash);
    if (hashDigestSz <= 0) {
        return NOT_COMPILED_IN;
    }

    /* set session auth for key */
    if (tpmKey) {
        wolfTPM2_SetAuthHandle(dev, 0, &tpmKey->handle);
        authSesIn.tpmKey = tpmKey->handle.hndl;
    }
    else {
        wolfTPM2_SetAuthPassword(dev, 0, NULL);
        authSesIn.tpmKey = (TPMI_DH_OBJECT)TPM_RH_NULL;
    }
    /* setup bind key */
    authSesIn.bind = (TPMI_DH_ENTITY)TPM_RH_NULL;
    if (bind) {
        authSesIn.bind = bind->hndl;
        bindAuth = &bind->auth;
    }

    authSesIn.sessionType = sesType;
#ifdef WOLFSSL_AES_CFB
    if (encDecAlg == TPM_ALG_CFB) {
        authSesIn.symmetric.algorithm = TPM_ALG_AES;
        authSesIn.symmetric.keyBits.aes = 128;
        authSesIn.symmetric.mode.aes = TPM_ALG_CFB;
    }
    else
#endif
    if (encDecAlg == TPM_ALG_XOR) {
        authSesIn.symmetric.algorithm = TPM_ALG_XOR;
        authSesIn.symmetric.keyBits.xorr = TPM_ALG_SHA256;
        authSesIn.symmetric.mode.sym = TPM_ALG_NULL;
    }
    else {
        authSesIn.symmetric.algorithm = TPM_ALG_NULL;
    }
    authSesIn.nonceCaller.size = hashDigestSz;
    rc = TPM2_GetNonce(authSesIn.nonceCaller.buffer,
                       authSesIn.nonceCaller.size);
    if (rc < 0) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_GetNonce failed %d: %s\n", rc, wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }

#ifndef WOLFTPM2_NO_WOLFCRYPT
    /* Generate and Encrypt salt using "SECRET" */
    rc = wolfTPM2_EncryptSalt(dev, tpmKey, &authSesIn, bindAuth, &session->salt);
    if (rc != 0) {
    #ifdef DEBUG_WOLFTPM
        printf("Building encrypted salt failed %d: %s!\n", rc,
            wolfTPM2_GetRCString(rc));
    #endif
    }
#endif

    rc = TPM2_StartAuthSession(&authSesIn, &authSesOut);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_StartAuthSession failed %d: %s\n", rc,
            wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }

    /* Calculate "key" and store into auth */
    /* key is bindAuthValue || salt */
    XMEMSET(&keyIn, 0, sizeof(keyIn));
    if (bindAuth && bindAuth->size > 0) {
        XMEMCPY(&keyIn.buffer[keyIn.size], bindAuth->buffer, bindAuth->size);
        keyIn.size += bindAuth->size;
    }
    if (session->salt.size > 0) {
        XMEMCPY(&keyIn.buffer[keyIn.size], session->salt.buffer, session->salt.size);
        keyIn.size += session->salt.size;
    }

    if (keyIn.size > 0) {
        session->handle.auth.size = hashDigestSz;
        rc = TPM2_KDFa(authSesIn.authHash, &keyIn, "ATH",
            &authSesOut.nonceTPM, &authSesIn.nonceCaller,
            session->handle.auth.buffer, session->handle.auth.size);
        if (rc != hashDigestSz) {
        #ifdef DEBUG_WOLFTPM
            printf("KDFa ATH Gen Error %d\n", rc);
        #endif
            return TPM_RC_FAILURE;
        }
        rc = TPM_RC_SUCCESS;
    }

#ifdef WOLFTPM_DEBUG_VERBOSE
    printf("Session Key %d\n", session->handle.auth.size);
    TPM2_PrintBin(session->handle.auth.buffer, session->handle.auth.size);
#endif


    /* return session */
    session->type = authSesIn.sessionType;
    session->authHash = authSesIn.authHash;
    session->handle.hndl = authSesOut.sessionHandle;
    session->handle.symmetric = authSesIn.symmetric;
    if (bind)
        session->handle.name = bind->name;
    session->nonceCaller = authSesIn.nonceCaller;
    session->nonceTPM = authSesOut.nonceTPM;

#ifdef DEBUG_WOLFTPM
    printf("TPM2_StartAuthSession: handle 0x%x, algorithm %s\n",
        (word32)session->handle.hndl,
        TPM2_GetAlgName(authSesIn.symmetric.algorithm));
#endif

    return rc;
}


int wolfTPM2_CreatePrimaryKey(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    TPM_HANDLE primaryHandle, TPMT_PUBLIC* publicTemplate,
    const byte* auth, int authSz)
{
    int rc;
    CreatePrimary_In  createPriIn;
    CreatePrimary_Out createPriOut;

    if (dev == NULL || key == NULL || publicTemplate == NULL)
        return BAD_FUNC_ARG;

    /* set session auth to blank */
    wolfTPM2_SetAuthPassword(dev, 0, NULL);

    /* clear output key buffer */
    XMEMSET(key, 0, sizeof(WOLFTPM2_KEY));

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
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_CreatePrimary: failed %d: %s\n", rc,
            wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }
    key->handle.hndl = createPriOut.objectHandle;
    key->handle.auth = createPriIn.inSensitive.sensitive.userAuth;
    key->handle.name = createPriOut.name;
    key->handle.symmetric = createPriOut.outPublic.publicArea.parameters.asymDetail.symmetric;

    key->pub = createPriOut.outPublic;

#ifdef DEBUG_WOLFTPM
    printf("TPM2_CreatePrimary: 0x%x (%d bytes)\n",
        (word32)key->handle.hndl, key->pub.size);
#endif

    return rc;
}

int wolfTPM2_ChangeAuthKey(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    WOLFTPM2_HANDLE* parent, const byte* auth, int authSz)
{
    int rc;
    ObjectChangeAuth_In changeIn;
    ObjectChangeAuth_Out changeOut;
    Load_In  loadIn;
    Load_Out loadOut;

    if (dev == NULL || key == NULL || parent == NULL)
        return BAD_FUNC_ARG;

    /* set session auth for key */
    wolfTPM2_SetAuthHandle(dev, 0, &key->handle);

    XMEMSET(&changeIn, 0, sizeof(changeIn));
    changeIn.objectHandle = key->handle.hndl;
    changeIn.parentHandle = parent->hndl;
    if (auth) {
        if (authSz > (int)sizeof(changeIn.newAuth.buffer))
            authSz = (int)sizeof(changeIn.newAuth.buffer);
        changeIn.newAuth.size = authSz;
        XMEMCPY(changeIn.newAuth.buffer, auth, changeIn.newAuth.size);
    }

    rc = TPM2_ObjectChangeAuth(&changeIn, &changeOut);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_ObjectChangeAuth failed %d: %s\n", rc,
                wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }

    /* unload old key */
    wolfTPM2_UnloadHandle(dev, &key->handle);

    /* set session auth for parent key */
    wolfTPM2_SetAuthHandle(dev, 0, parent);

    /* Load new key */
    XMEMSET(&loadIn, 0, sizeof(loadIn));
    loadIn.parentHandle = parent->hndl;
    loadIn.inPrivate = changeOut.outPrivate;
    loadIn.inPublic = key->pub;
    rc = TPM2_Load(&loadIn, &loadOut);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_Load key failed %d: %s\n", rc, wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }
    key->handle.hndl = loadOut.objectHandle;
    key->handle.auth = changeIn.newAuth;
    key->handle.name = loadOut.name;

#ifdef DEBUG_WOLFTPM
    printf("wolfTPM2_ChangeAuthKey: Key Handle 0x%x\n", (word32)key->handle.hndl);
#endif

    return rc;
}

int wolfTPM2_CreateKey(WOLFTPM2_DEV* dev, WOLFTPM2_KEYBLOB* keyBlob,
    WOLFTPM2_HANDLE* parent, TPMT_PUBLIC* publicTemplate,
    const byte* auth, int authSz)
{
    int rc;
    Create_In  createIn;
    Create_Out createOut;

    if (dev == NULL || keyBlob == NULL || parent == NULL || publicTemplate == NULL)
        return BAD_FUNC_ARG;

    /* clear output key buffer */
    XMEMSET(keyBlob, 0, sizeof(WOLFTPM2_KEYBLOB));

    /* set session auth for parent key */
    wolfTPM2_SetAuthHandle(dev, 0, parent);

    XMEMSET(&createIn, 0, sizeof(createIn));
    createIn.parentHandle = parent->hndl;
    if (auth) {
        createIn.inSensitive.sensitive.userAuth.size = authSz;
        XMEMCPY(createIn.inSensitive.sensitive.userAuth.buffer, auth,
            createIn.inSensitive.sensitive.userAuth.size);
    }
    XMEMCPY(&createIn.inPublic.publicArea, publicTemplate, sizeof(TPMT_PUBLIC));

#if 0
    /* Optional creation nonce */
    createIn.outsideInfo.size = createNoneSz;
    XMEMCPY(createIn.outsideInfo.buffer, createNonce, createIn.outsideInfo.size);
#endif

    rc = TPM2_Create(&createIn, &createOut);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_Create key failed %d: %s\n", rc, wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }

#ifdef DEBUG_WOLFTPM
    printf("TPM2_Create key: pub %d, priv %d\n",
        createOut.outPublic.size, createOut.outPrivate.size);
    TPM2_PrintBin(createOut.outPrivate.buffer, createOut.outPrivate.size);
#endif

    keyBlob->handle.auth = createIn.inSensitive.sensitive.userAuth;
    keyBlob->handle.symmetric = createOut.outPublic.publicArea.parameters.asymDetail.symmetric;

    keyBlob->pub = createOut.outPublic;
    keyBlob->priv = createOut.outPrivate;

    return rc;
}

int wolfTPM2_LoadKey(WOLFTPM2_DEV* dev, WOLFTPM2_KEYBLOB* keyBlob,
    WOLFTPM2_HANDLE* parent)
{
    int rc;
    Load_In loadIn;
    Load_Out loadOut;

    if (dev == NULL || keyBlob == NULL || parent == NULL)
        return BAD_FUNC_ARG;

    /* set session auth for parent key */
    if (dev->ctx.session) {
        wolfTPM2_SetAuthHandle(dev, 0, parent);
    }

    /* Load new key */
    XMEMSET(&loadIn, 0, sizeof(loadIn));
    loadIn.parentHandle = parent->hndl;
    loadIn.inPrivate = keyBlob->priv;
    loadIn.inPublic = keyBlob->pub;
    rc = TPM2_Load(&loadIn, &loadOut);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_Load key failed %d: %s\n", rc, wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }
    keyBlob->handle.hndl = loadOut.objectHandle;
    keyBlob->handle.name = loadOut.name;

#ifdef DEBUG_WOLFTPM
    printf("TPM2_Load Key Handle 0x%x\n", (word32)keyBlob->handle.hndl);
#endif

    return rc;
}

int wolfTPM2_CreateAndLoadKey(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    WOLFTPM2_HANDLE* parent, TPMT_PUBLIC* publicTemplate,
    const byte* auth, int authSz)
{
    int rc;
    WOLFTPM2_KEYBLOB keyBlob;

    if (dev == NULL || key == NULL)
        return BAD_FUNC_ARG;

    rc = wolfTPM2_CreateKey(dev, &keyBlob, parent, publicTemplate, auth, authSz);
    if (rc == TPM_RC_SUCCESS) {
        rc = wolfTPM2_LoadKey(dev, &keyBlob, parent);
    }

    /* return loaded key */
    XMEMCPY(key, &keyBlob, sizeof(WOLFTPM2_KEY));

    return rc;
}

int wolfTPM2_LoadPublicKey(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    const TPM2B_PUBLIC* pub)
{
    int rc;
    LoadExternal_In  loadExtIn;
    LoadExternal_Out loadExtOut;

    if (dev == NULL || key == NULL || pub == NULL)
        return BAD_FUNC_ARG;

    /* Loading public key */
    XMEMSET(&loadExtIn, 0, sizeof(loadExtIn));
    loadExtIn.inPublic = *pub;
    loadExtIn.hierarchy = TPM_RH_NULL;
    rc = TPM2_LoadExternal(&loadExtIn, &loadExtOut);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_LoadExternal: failed %d: %s\n", rc,
            wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }
    key->handle.hndl = loadExtOut.objectHandle;
    key->handle.symmetric = loadExtIn.inPublic.publicArea.parameters.asymDetail.symmetric;
    key->handle.name = loadExtOut.name;

    key->pub = loadExtIn.inPublic;

#ifdef DEBUG_WOLFTPM
    printf("TPM2_LoadExternal: 0x%x\n", (word32)loadExtOut.objectHandle);
#endif

    return rc;
}

int wolfTPM2_ComputeName(const TPM2B_PUBLIC* pub, TPM2B_NAME* out)
{
    int rc;
    TPMI_ALG_HASH nameAlg;
#ifndef WOLFTPM2_NO_WOLFCRYPT
    TPM2_Packet packet;
    TPM2B_DATA data;
    wc_HashAlg hash;
    enum wc_HashType hashType;
    int hashSz;
#endif

    if (pub == NULL || out == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(out, 0, sizeof(TPM2B_NAME));
    nameAlg = pub->publicArea.nameAlg;
    if (nameAlg == TPM_ALG_NULL)
        return TPM_RC_SUCCESS;

#ifndef WOLFTPM2_NO_WOLFCRYPT
    /* Encode public into buffer */
    XMEMSET(&packet, 0, sizeof(packet));
    packet.buf = data.buffer;
    packet.size = sizeof(data.buffer);
    TPM2_Packet_AppendPublic(&packet, (TPM2B_PUBLIC*)pub);
    data.size = packet.pos;

    /* Hash data - first two bytes are TPM_ALG_ID */
    rc = TPM2_GetHashType(nameAlg);
    hashType = (enum wc_HashType)rc;
    rc = wc_HashGetDigestSize(hashType);
    if (rc < 0)
        return rc;
    hashSz = rc;

    /* Encode hash algorithm in first 2 bytes */
    nameAlg = TPM2_Packet_SwapU16(nameAlg);
    XMEMCPY(&out->name[0], &nameAlg, sizeof(UINT16));

    /* Hash of data (name) goes into remainder */
    rc = wc_HashInit(&hash, hashType);
    if (rc == 0) {
        rc = wc_HashUpdate(&hash, hashType, data.buffer, data.size);
        if (rc == 0)
            rc = wc_HashFinal(&hash, hashType, &out->name[sizeof(UINT16)]);

        wc_HashFree(&hash, hashType);
    }

    /* compute final size */
    out->size = hashSz + (int)sizeof(UINT16);

#else
    (void)out;
    rc = NOT_COMPILED_IN;
#endif
    return rc;
}

/* Convert TPM2B_SENSITIVE to TPM2B_PRIVATE */
int wolfTPM2_SensitiveToPrivate(TPM2B_SENSITIVE* sens, TPM2B_PRIVATE* priv,
    TPMI_ALG_HASH nameAlg, TPM2B_NAME* name, const WOLFTPM2_KEY* parentKey,
    TPMT_SYM_DEF_OBJECT* sym, TPM2B_ENCRYPTED_SECRET* symSeed)
{
    int rc = 0;
    int innerWrap = 0;
    int outerWrap = 0;
    TPMI_ALG_HASH innerAlg, outerAlg;
    TPM2_Packet packet;
    int pos = 0;
    int digestSz, innerSz, outerSz, sensSz;

    if (sens == NULL || priv == NULL)
        return BAD_FUNC_ARG;

    digestSz = TPM2_GetHashDigestSize(nameAlg);

    innerSz = outerSz = sensSz = 0;
    if (sym && sym->algorithm != TPM_ALG_NULL) {
        innerWrap = 1;

        innerAlg = nameAlg;
        innerSz = sizeof(word16) + digestSz;
        pos += innerSz;
    }

    if (symSeed && symSeed->size > 0 && parentKey) {
        outerWrap = 1;

        outerAlg = parentKey->pub.publicArea.nameAlg;
        outerSz = sizeof(word16) + TPM2_GetHashDigestSize(outerAlg);
        pos += outerSz;
    }

    /* Encode sensitive into private buffer */
    XMEMSET(&packet, 0, sizeof(packet));
    packet.buf = &priv->buffer[pos];
    packet.size = sizeof(priv->buffer) - pos;
    TPM2_Packet_AppendSensitive(&packet, sens);
    priv->size = packet.pos;
    /* Calculate the size of the sensitive area for later use */
    sensSz = packet.pos - innerSz - outerSz;

    if (innerWrap) {
    #if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_AES) && defined(WOLFSSL_AES_CFB)
        Aes enc;
        TPM2B_IV ivField;
        TPM2B_SYM_KEY symKey;

        /* Generate IV */
        ivField.size = digestSz;
        rc = TPM2_GetNonce(ivField.buffer, ivField.size);
        if (rc != 0)
            return rc;

        /* Generate symmetric key for encryption of inner values */
        symKey.size = (sym->keyBits.sym + 7) / 8; /* round up */
        rc = TPM2_KDFa(innerAlg, (TPM2B_DATA*)&sens->sensitiveArea.seedValue,
                  "STORAGE", (TPM2B_NONCE*)name, NULL,
                  symKey.buffer, symKey.size);
        if (rc != symKey.size) {
        #ifdef DEBUG_WOLFTPM
            printf("KDFa STORAGE Gen Error %d\n", rc);
        #endif
            return TPM_RC_FAILURE;
        }

        /* Encrypt the Sensitive Area using the generated symmetric key */
        rc = wc_AesInit(&enc, NULL, INVALID_DEVID);
        if (rc == 0) {
            rc = wc_AesSetKey(&enc, symKey.buffer, symKey.size,
                              ivField.buffer, AES_ENCRYPTION);
            /* Encryption in-place */
            if (rc == 0)
                rc = wc_AesCfbEncrypt(&enc, &packet.buf[innerSz], &packet.buf[innerSz], sensSz);
            wc_AesFree(&enc);
        }
    #else
        (void)innerAlg;
        (void)sensSz;
    #endif
    }

    if (outerWrap) {
    #if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_HMAC)
        Hmac hmac_ctx;
        TPM2B_DIGEST hmacKey;
        /* Generate HMAC key for generation of the integrity value */
        hmacKey.size = TPM2_GetHashDigestSize(outerAlg);
        if (hmacKey.size == 0)
            return TPM_RC_FAILURE;

        rc = TPM2_KDFa(outerAlg, (TPM2B_DATA*)&sens->sensitiveArea.seedValue,
                  "INTEGRITY", NULL, NULL,
                  hmacKey.buffer, hmacKey.size);
        if (rc != hmacKey.size) {
        #ifdef DEBUG_WOLFTPM
            printf("KDFa INTEGRITY Gen Error %d\n", rc);
        #endif
            return rc;
        }

        /* setup HMAC */
        rc = wc_HmacInit(&hmac_ctx, NULL, INVALID_DEVID);
        if (rc != 0)
            return rc;
        /* start HMAC */
        rc = wc_HmacSetKey(&hmac_ctx, outerAlg, hmacKey.buffer, hmacKey.size);

        /* consume IV area */
        if (rc == 0)
            rc = wc_HmacUpdate(&hmac_ctx, &packet.buf[outerSz], innerSz);
        /* consume sensitive area */
        if (rc == 0)
            rc = wc_HmacUpdate(&hmac_ctx, &packet.buf[innerSz], sensSz);
        /* consume name field */
        if (rc == 0)
            rc = wc_HmacUpdate(&hmac_ctx, name->name, name->size);

        /* write result at position after Priv->size and Outer->Size field */
        if (rc == 0)
            rc = wc_HmacFinal(&hmac_ctx, &packet.buf[sizeof(word16)+sizeof(word16)]);
        wc_HmacFree(&hmac_ctx);
        if (rc != 0)
            return rc;

        /* store the size of the outer integrity in the Outer->Size field */
        hmacKey.size = TPM2_Packet_SwapU16(hmacKey.size);
        XMEMCPY(&packet.buf[sizeof(word16)], &hmacKey.size, sizeof(word16));
    #endif
    }
    (void)name;

    return rc;
}

/* Import external private key */
int wolfTPM2_ImportPrivateKey(WOLFTPM2_DEV* dev, const WOLFTPM2_KEY* parentKey,
    WOLFTPM2_KEYBLOB* keyBlob, const TPM2B_PUBLIC* pub, TPM2B_SENSITIVE* sens)
{
    int rc;
    Import_In  importIn;
    Import_Out importOut;
    TPM2B_NAME name;
    TPM_HANDLE parentHandle;

    if (dev == NULL || keyBlob == NULL || pub == NULL ||
            sens == NULL) {
        return BAD_FUNC_ARG;
    }

    /* set session auth for key */
    if (parentKey != NULL) {
        /* set session auth for parent key */
        wolfTPM2_SetAuthHandle(dev, 0, &parentKey->handle);
        parentHandle = parentKey->handle.hndl;
    }
    else {
        parentHandle = TPM_RH_OWNER;
    }

    /* Import private key */
    XMEMSET(&importIn, 0, sizeof(importIn));
    importIn.parentHandle = parentHandle;
    importIn.objectPublic = *pub;
    importIn.symmetricAlg.algorithm = TPM_ALG_NULL;
    rc = wolfTPM2_ComputeName(pub, &name);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("wolfTPM2_ComputeName: failed %d: %s\n", rc,
            wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }
    rc = wolfTPM2_SensitiveToPrivate(sens, &importIn.duplicate,
        pub->publicArea.nameAlg, &name, parentKey, &importIn.symmetricAlg,
        &importIn.inSymSeed);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("wolfTPM2_SensitiveToPrivate: failed %d: %s\n", rc,
            wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }
    rc = TPM2_Import(&importIn, &importOut);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_Import: failed %d: %s\n", rc,
            wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }

    keyBlob->handle.symmetric = importIn.objectPublic.publicArea.parameters.asymDetail.symmetric;
    keyBlob->pub = importIn.objectPublic;
    keyBlob->priv = importOut.outPrivate;

    return rc;
}

/* Import and Load external private key to TPM */
int wolfTPM2_LoadPrivateKey(WOLFTPM2_DEV* dev, const WOLFTPM2_KEY* parentKey,
    WOLFTPM2_KEY* key, const TPM2B_PUBLIC* pub, TPM2B_SENSITIVE* sens)
{
    int rc;
    WOLFTPM2_KEYBLOB keyBlob;

    if (dev == NULL || key == NULL || pub == NULL || sens == NULL) {
        return BAD_FUNC_ARG;
    }

    XMEMCPY(&keyBlob, key, sizeof(WOLFTPM2_KEY));
    rc = wolfTPM2_ImportPrivateKey(dev, parentKey, &keyBlob, pub, sens);
    if (rc == 0) {
        WOLFTPM2_HANDLE parentHandle_lcl, *parentHandle = &parentHandle_lcl;
        if (parentKey != NULL) {
            parentHandle = (WOLFTPM2_HANDLE*)&parentKey->handle;
        }
        else {
            XMEMSET(parentHandle, 0, sizeof(*parentHandle));
            parentHandle->hndl = TPM_RH_OWNER;
        }

        rc = wolfTPM2_LoadKey(dev, &keyBlob, parentHandle);
    }

    /* return loaded key */
    XMEMCPY(key, &keyBlob, sizeof(WOLFTPM2_KEY));
    key->handle.auth = sens->sensitiveArea.authValue;

    return rc;
}

int wolfTPM2_LoadRsaPublicKey_ex(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    const byte* rsaPub, word32 rsaPubSz, word32 exponent,
    TPMI_ALG_RSA_SCHEME scheme, TPMI_ALG_HASH hashAlg)
{
    TPM2B_PUBLIC pub;

    if (dev == NULL || key == NULL || rsaPub == NULL)
        return BAD_FUNC_ARG;
    if (rsaPubSz > sizeof(pub.publicArea.unique.rsa.buffer))
        return BUFFER_E;

    /* To support TPM hardware and firmware versions that do not allow
        small exponents */
#ifndef WOLFTPM_NO_SOFTWARE_RSA
    /* The TPM reference implementation does not support an exponent size
       smaller than 7 nor does it allow keys to be created on the TPM with a
       public exponent less than 2^16 + 1. */
    if (exponent < 7) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM based RSA with exponent %u not allowed! Using soft RSA\n",
            exponent);
    #endif
        return TPM_RC_KEY;
    }
#endif

    XMEMSET(&pub, 0, sizeof(pub));
    pub.publicArea.type = TPM_ALG_RSA;
    pub.publicArea.nameAlg = TPM_ALG_NULL;
    pub.publicArea.objectAttributes = (TPMA_OBJECT_sign | TPMA_OBJECT_decrypt |
        TPMA_OBJECT_userWithAuth | TPMA_OBJECT_noDA);
    pub.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
    pub.publicArea.parameters.rsaDetail.keyBits = rsaPubSz * 8;
    pub.publicArea.parameters.rsaDetail.exponent = exponent;
    pub.publicArea.parameters.rsaDetail.scheme.scheme = scheme;
    pub.publicArea.parameters.rsaDetail.scheme.details.anySig.hashAlg = hashAlg;
    pub.publicArea.unique.rsa.size = rsaPubSz;
    XMEMCPY(pub.publicArea.unique.rsa.buffer, rsaPub, rsaPubSz);

    return wolfTPM2_LoadPublicKey(dev, key, &pub);
}

int wolfTPM2_LoadRsaPublicKey(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    const byte* rsaPub, word32 rsaPubSz, word32 exponent)
{
    return wolfTPM2_LoadRsaPublicKey_ex(dev, key, rsaPub, rsaPubSz, exponent,
        TPM_ALG_NULL, TPM_ALG_NULL);
}

int wolfTPM2_ImportRsaPrivateKey(WOLFTPM2_DEV* dev, const WOLFTPM2_KEY* parentKey,
    WOLFTPM2_KEYBLOB* keyBlob, const byte* rsaPub, word32 rsaPubSz, word32 exponent,
    const byte* rsaPriv, word32 rsaPrivSz,
    TPMI_ALG_RSA_SCHEME scheme, TPMI_ALG_HASH hashAlg)
{
    TPM2B_PUBLIC pub;
    TPM2B_SENSITIVE sens;

    if (dev == NULL || keyBlob == NULL || rsaPub == NULL || rsaPriv == NULL)
        return BAD_FUNC_ARG;
    if (rsaPubSz > sizeof(pub.publicArea.unique.rsa.buffer))
        return BUFFER_E;
    if (rsaPrivSz > sizeof(sens.sensitiveArea.sensitive.rsa.buffer))
        return BUFFER_E;

    /* Set up public key */
    XMEMSET(&pub, 0, sizeof(pub));
    pub.publicArea.type = TPM_ALG_RSA;
    pub.publicArea.nameAlg = WOLFTPM2_WRAP_DIGEST;
    pub.publicArea.objectAttributes = (TPMA_OBJECT_sign | TPMA_OBJECT_decrypt |
        TPMA_OBJECT_userWithAuth | TPMA_OBJECT_noDA);
    pub.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
    pub.publicArea.parameters.rsaDetail.keyBits = rsaPubSz * 8;
    pub.publicArea.parameters.rsaDetail.exponent = exponent;
    pub.publicArea.parameters.rsaDetail.scheme.scheme = scheme;
    pub.publicArea.parameters.rsaDetail.scheme.details.anySig.hashAlg = hashAlg;
    pub.publicArea.unique.rsa.size = rsaPubSz;
    XMEMCPY(pub.publicArea.unique.rsa.buffer, rsaPub, rsaPubSz);

    /* Set up private key */
    XMEMSET(&sens, 0, sizeof(sens));
    sens.sensitiveArea.sensitiveType = TPM_ALG_RSA;
    if (keyBlob->handle.auth.size > 0) {
        sens.sensitiveArea.authValue.size = keyBlob->handle.auth.size;
        XMEMCPY(sens.sensitiveArea.authValue.buffer, keyBlob->handle.auth.buffer,
            keyBlob->handle.auth.size);
    }
    sens.sensitiveArea.sensitive.rsa.size = rsaPrivSz;
    XMEMCPY(sens.sensitiveArea.sensitive.rsa.buffer, rsaPriv, rsaPrivSz);

    return wolfTPM2_ImportPrivateKey(dev, parentKey, keyBlob, &pub, &sens);
}

int wolfTPM2_LoadRsaPrivateKey_ex(WOLFTPM2_DEV* dev, const WOLFTPM2_KEY* parentKey,
    WOLFTPM2_KEY* key, const byte* rsaPub, word32 rsaPubSz, word32 exponent,
    const byte* rsaPriv, word32 rsaPrivSz,
    TPMI_ALG_RSA_SCHEME scheme, TPMI_ALG_HASH hashAlg)
{
    int rc;
    WOLFTPM2_KEYBLOB keyBlob;

    if (dev == NULL || key == NULL || rsaPub == NULL || rsaPriv == NULL)
        return BAD_FUNC_ARG;

    XMEMCPY(&keyBlob, key, sizeof(WOLFTPM2_KEY));
    rc = wolfTPM2_ImportRsaPrivateKey(dev, parentKey, &keyBlob, rsaPub, rsaPubSz,
        exponent, rsaPriv, rsaPrivSz, scheme, hashAlg);
    if (rc == 0) {
        rc = wolfTPM2_LoadKey(dev, &keyBlob, (WOLFTPM2_HANDLE*)&parentKey->handle);
    }

    /* return loaded key */
    XMEMCPY(key, &keyBlob, sizeof(WOLFTPM2_KEY));

    return rc;
}
int wolfTPM2_LoadRsaPrivateKey(WOLFTPM2_DEV* dev, const WOLFTPM2_KEY* parentKey,
    WOLFTPM2_KEY* key, const byte* rsaPub, word32 rsaPubSz, word32 exponent,
    const byte* rsaPriv, word32 rsaPrivSz)
{
    return wolfTPM2_LoadRsaPrivateKey_ex(dev, parentKey, key, rsaPub, rsaPubSz,
        exponent, rsaPriv, rsaPrivSz, TPM_ALG_NULL, TPM_ALG_NULL);
}

int wolfTPM2_LoadEccPublicKey(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key, int curveId,
    const byte* eccPubX, word32 eccPubXSz, const byte* eccPubY, word32 eccPubYSz)
{
    TPM2B_PUBLIC pub;

    if (dev == NULL || key == NULL || eccPubX == NULL || eccPubY == NULL)
        return BAD_FUNC_ARG;
    if (eccPubXSz > sizeof(pub.publicArea.unique.ecc.x.buffer))
        return BUFFER_E;
    if (eccPubYSz > sizeof(pub.publicArea.unique.ecc.y.buffer))
        return BUFFER_E;

    XMEMSET(&pub, 0, sizeof(pub));
    pub.publicArea.type = TPM_ALG_ECC;
    pub.publicArea.nameAlg = WOLFTPM2_WRAP_DIGEST;
    pub.publicArea.objectAttributes = TPMA_OBJECT_sign | TPMA_OBJECT_noDA;
    pub.publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
    pub.publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_ECDSA;
    pub.publicArea.parameters.eccDetail.scheme.details.ecdsa.hashAlg =
        WOLFTPM2_WRAP_DIGEST;
    pub.publicArea.parameters.eccDetail.curveID = curveId;
    pub.publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
    pub.publicArea.unique.ecc.x.size = eccPubXSz;
    XMEMCPY(pub.publicArea.unique.ecc.x.buffer, eccPubX, eccPubXSz);
    pub.publicArea.unique.ecc.y.size = eccPubYSz;
    XMEMCPY(pub.publicArea.unique.ecc.y.buffer, eccPubY, eccPubYSz);

    return wolfTPM2_LoadPublicKey(dev, key, &pub);
}

int wolfTPM2_ImportEccPrivateKey(WOLFTPM2_DEV* dev, const WOLFTPM2_KEY* parentKey,
    WOLFTPM2_KEYBLOB* keyBlob, int curveId,
    const byte* eccPubX, word32 eccPubXSz,
    const byte* eccPubY, word32 eccPubYSz,
    const byte* eccPriv, word32 eccPrivSz)
{
    TPM2B_PUBLIC pub;
    TPM2B_SENSITIVE sens;

    if (dev == NULL || keyBlob == NULL || eccPubX == NULL || eccPubY == NULL ||
        eccPriv == NULL) {
        return BAD_FUNC_ARG;
    }
    if (eccPubXSz > sizeof(pub.publicArea.unique.ecc.x.buffer))
        return BUFFER_E;
    if (eccPubYSz > sizeof(pub.publicArea.unique.ecc.y.buffer))
        return BUFFER_E;
    if (eccPrivSz > sizeof(sens.sensitiveArea.sensitive.ecc.buffer))
        return BUFFER_E;

    /* Set up public key */
    XMEMSET(&pub, 0, sizeof(pub));
    pub.publicArea.type = TPM_ALG_ECC;
    pub.publicArea.nameAlg = WOLFTPM2_WRAP_DIGEST;
    pub.publicArea.objectAttributes = TPMA_OBJECT_sign | TPMA_OBJECT_decrypt |
        TPMA_OBJECT_userWithAuth | TPMA_OBJECT_noDA;
    pub.publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
    pub.publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_NULL;
    pub.publicArea.parameters.eccDetail.scheme.details.ecdsa.hashAlg =
        WOLFTPM2_WRAP_DIGEST;
    pub.publicArea.parameters.eccDetail.curveID = curveId;
    pub.publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
    pub.publicArea.unique.ecc.x.size = eccPubXSz;
    XMEMCPY(pub.publicArea.unique.ecc.x.buffer, eccPubX, eccPubXSz);
    pub.publicArea.unique.ecc.y.size = eccPubYSz;
    XMEMCPY(pub.publicArea.unique.ecc.y.buffer, eccPubY, eccPubYSz);

    /* Set up private key */
    XMEMSET(&sens, 0, sizeof(sens));
    sens.sensitiveArea.sensitiveType = TPM_ALG_ECC;
    if (keyBlob->handle.auth.size > 0) {
        sens.sensitiveArea.authValue.size = keyBlob->handle.auth.size;
        XMEMCPY(sens.sensitiveArea.authValue.buffer, keyBlob->handle.auth.buffer,
            keyBlob->handle.auth.size);
    }
    sens.sensitiveArea.sensitive.ecc.size = eccPrivSz;
    XMEMCPY(sens.sensitiveArea.sensitive.ecc.buffer, eccPriv, eccPrivSz);

    return wolfTPM2_ImportPrivateKey(dev, parentKey, keyBlob, &pub, &sens);
}

int wolfTPM2_LoadEccPrivateKey(WOLFTPM2_DEV* dev, const WOLFTPM2_KEY* parentKey,
    WOLFTPM2_KEY* key, int curveId,
    const byte* eccPubX, word32 eccPubXSz,
    const byte* eccPubY, word32 eccPubYSz,
    const byte* eccPriv, word32 eccPrivSz)
{
    int rc;
    WOLFTPM2_KEYBLOB keyBlob;

    if (dev == NULL || key == NULL || eccPubX == NULL || eccPubY == NULL ||
        eccPriv == NULL) {
        return BAD_FUNC_ARG;
    }

    XMEMCPY(&keyBlob, key, sizeof(WOLFTPM2_KEY));
    rc = wolfTPM2_ImportEccPrivateKey(dev, parentKey, &keyBlob, curveId,
        eccPubX, eccPubXSz, eccPubY, eccPubYSz, eccPriv, eccPrivSz);
    if (rc == 0) {
        rc = wolfTPM2_LoadKey(dev, &keyBlob, (WOLFTPM2_HANDLE*)&parentKey->handle);
    }

    /* return loaded key */
    XMEMCPY(key, &keyBlob, sizeof(WOLFTPM2_KEY));

    return rc;
}

int wolfTPM2_ReadPublicKey(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    const TPM_HANDLE handle)
{
    int rc;
    ReadPublic_In  readPubIn;
    ReadPublic_Out readPubOut;

    if (dev == NULL || key == NULL)
        return BAD_FUNC_ARG;

    /* Read public key */
    XMEMSET(&readPubIn, 0, sizeof(readPubIn));
    readPubIn.objectHandle = handle;
    rc = TPM2_ReadPublic(&readPubIn, &readPubOut);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_ReadPublic failed %d: %s\n", rc, wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }

    key->handle.hndl = readPubIn.objectHandle;
    key->handle.symmetric = readPubOut.outPublic.publicArea.parameters.asymDetail.symmetric;
    key->handle.name = readPubOut.name;
    key->pub = readPubOut.outPublic;

#ifdef DEBUG_WOLFTPM
    printf("TPM2_ReadPublic Handle 0x%x: pub %d, name %d, qualifiedName %d\n",
        (word32)readPubIn.objectHandle,
        readPubOut.outPublic.size, readPubOut.name.size,
        readPubOut.qualifiedName.size);
#endif

    return rc;
}

#ifndef WOLFTPM2_NO_WOLFCRYPT
#ifndef NO_RSA
int wolfTPM2_RsaKey_TpmToWolf(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* tpmKey,
    RsaKey* wolfKey)
{
    int rc;
    word32  exponent;
    byte    e[sizeof(exponent)];
    byte    n[WOLFTPM2_WRAP_RSA_KEY_BITS / 8];
    word32  eSz = sizeof(e);
    word32  nSz = sizeof(n);

    if (dev == NULL || tpmKey == NULL || wolfKey == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(e, 0, sizeof(e));
    XMEMSET(n, 0, sizeof(n));

    /* load exponent */
    exponent = tpmKey->pub.publicArea.parameters.rsaDetail.exponent;
    if (exponent == 0)
        exponent = RSA_DEFAULT_PUBLIC_EXPONENT;
    e[3] = (exponent >> 24) & 0xFF;
    e[2] = (exponent >> 16) & 0xFF;
    e[1] = (exponent >> 8)  & 0xFF;
    e[0] =  exponent        & 0xFF;
    eSz = e[3] ? 4 : e[2] ? 3 : e[1] ? 2 : e[0] ? 1 : 0; /* calc size */

    /* load public key */
    nSz = tpmKey->pub.publicArea.unique.rsa.size;
    XMEMCPY(n, tpmKey->pub.publicArea.unique.rsa.buffer, nSz);

    /* load public key portion into wolf RsaKey */
    rc = wc_RsaPublicKeyDecodeRaw(n, nSz, e, eSz, wolfKey);

    return rc;
}

static word32 wolfTPM2_RsaKey_Exponent(byte* e, word32 eSz)
{
    word32 exponent = 0, i;
    for (i=0; i<eSz && i<sizeof(word32); i++) {
        exponent |= ((word32)e[i]) << (i*8);
    }
    return exponent;
}

int wolfTPM2_RsaKey_WolfToTpm_ex(WOLFTPM2_DEV* dev, const WOLFTPM2_KEY* parentKey,
    RsaKey* wolfKey, WOLFTPM2_KEY* tpmKey)
{
    int rc;
    word32  exponent;
    byte    e[sizeof(exponent)];
    byte    n[WOLFTPM2_WRAP_RSA_KEY_BITS / 8];
    word32  eSz = sizeof(e);
    word32  nSz = sizeof(n);

    if (dev == NULL || tpmKey == NULL || wolfKey == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(e, 0, sizeof(e));
    XMEMSET(n, 0, sizeof(n));

    if (parentKey && wolfKey->type == RSA_PRIVATE) {
        byte    d[WOLFTPM2_WRAP_RSA_KEY_BITS / 8];
        byte    p[WOLFTPM2_WRAP_RSA_KEY_BITS / 8];
        byte    q[WOLFTPM2_WRAP_RSA_KEY_BITS / 8];
        word32  dSz = sizeof(d);
        word32  pSz = sizeof(p);
        word32  qSz = sizeof(q);

        XMEMSET(d, 0, sizeof(d));
        XMEMSET(p, 0, sizeof(p));
        XMEMSET(q, 0, sizeof(q));

        /* export the raw private and public RSA as unsigned binary */
        rc = wc_RsaExportKey(wolfKey, e, &eSz, n, &nSz,
            d, &dSz, p, &pSz, q, &qSz);
        if (rc == 0) {
            exponent = wolfTPM2_RsaKey_Exponent(e, eSz);
            rc = wolfTPM2_LoadRsaPrivateKey(dev, parentKey, tpmKey, n, nSz,
                exponent, q, qSz);
        }

        /* not used */
        (void)p;
    }
    else {
        /* export the raw public RSA portion */
        rc = wc_RsaFlattenPublicKey(wolfKey, e, &eSz, n, &nSz);
        if (rc == 0) {
            exponent = wolfTPM2_RsaKey_Exponent(e, eSz);
            rc = wolfTPM2_LoadRsaPublicKey(dev, tpmKey, n, nSz, exponent);
        }
    }

    return rc;
}
int wolfTPM2_RsaKey_WolfToTpm(WOLFTPM2_DEV* dev, RsaKey* wolfKey,
    WOLFTPM2_KEY* tpmKey)
{
    return wolfTPM2_RsaKey_WolfToTpm_ex(dev, NULL, wolfKey, tpmKey);
}
#endif /* !NO_RSA */

#ifdef HAVE_ECC
#ifdef HAVE_ECC_KEY_IMPORT
int wolfTPM2_EccKey_TpmToWolf(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* tpmKey,
    ecc_key* wolfKey)
{
    int rc, curve_id;
    byte    qx[WOLFTPM2_WRAP_ECC_KEY_BITS / 8];
    byte    qy[WOLFTPM2_WRAP_ECC_KEY_BITS / 8];
    word32  qxSz = sizeof(qx);
    word32  qySz = sizeof(qy);

    if (dev == NULL || tpmKey == NULL || wolfKey == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(qx, 0, sizeof(qx));
    XMEMSET(qy, 0, sizeof(qy));

    /* load curve type */
    curve_id = tpmKey->pub.publicArea.parameters.eccDetail.curveID;
    rc = TPM2_GetWolfCurve(curve_id);
    if (rc < 0)
        return rc;
    curve_id = rc;

    /* load public key */
    qxSz = tpmKey->pub.publicArea.unique.ecc.x.size;
    XMEMCPY(qx, tpmKey->pub.publicArea.unique.ecc.x.buffer, qxSz);
    qySz = tpmKey->pub.publicArea.unique.ecc.y.size;
    XMEMCPY(qy, tpmKey->pub.publicArea.unique.ecc.y.buffer, qySz);

    /* load public key portion into wolf ecc_key */
    rc = wc_ecc_import_unsigned(wolfKey, qx, qy, NULL, curve_id);

    return rc;
}
#endif /* HAVE_ECC_KEY_IMPORT */
#ifdef HAVE_ECC_KEY_EXPORT
int wolfTPM2_EccKey_WolfToTpm_ex(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* parentKey,
    ecc_key* wolfKey, WOLFTPM2_KEY* tpmKey)
{
    int rc, curve_id = 0;
    byte    qx[WOLFTPM2_WRAP_ECC_KEY_BITS / 8];
    byte    qy[WOLFTPM2_WRAP_ECC_KEY_BITS / 8];
    word32  qxSz = sizeof(qx);
    word32  qySz = sizeof(qy);

    if (dev == NULL || tpmKey == NULL || wolfKey == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(tpmKey, 0, sizeof(*tpmKey));
    XMEMSET(qx, 0, sizeof(qx));
    XMEMSET(qy, 0, sizeof(qy));

    if (wolfKey->dp)
        curve_id = wolfKey->dp->id;

    rc = TPM2_GetTpmCurve(curve_id);
    if (rc < 0)
        return rc;
    curve_id = rc;

    if (parentKey && wolfKey->type == ECC_PRIVATEKEY) {
        byte    d[WOLFTPM2_WRAP_ECC_KEY_BITS / 8];
        word32  dSz = sizeof(d);

        XMEMSET(d, 0, sizeof(d));

        /* export the raw private/public ECC portions */
        rc = wc_ecc_export_private_raw(wolfKey, qx, &qxSz, qy, &qySz, d, &dSz);
        if (rc == 0) {
            rc = wolfTPM2_LoadEccPrivateKey(dev, parentKey, tpmKey, curve_id,
                qx, qxSz, qy, qySz, d, dSz);
        }
    }
    else {
        /* export the raw public ECC portion */
        rc = wc_ecc_export_public_raw(wolfKey, qx, &qxSz, qy, &qySz);
        if (rc == 0) {
            rc = wolfTPM2_LoadEccPublicKey(dev, tpmKey, curve_id, qx, qxSz, qy, qySz);
        }
    }

    return rc;
}
int wolfTPM2_EccKey_WolfToTpm(WOLFTPM2_DEV* dev, ecc_key* wolfKey,
    WOLFTPM2_KEY* tpmKey)
{
    return wolfTPM2_EccKey_WolfToTpm_ex(dev, NULL, wolfKey, tpmKey);
}

int wolfTPM2_EccKey_WolfToPubPoint(WOLFTPM2_DEV* dev, ecc_key* wolfKey,
    TPM2B_ECC_POINT* pubPoint)
{
    int rc;
    word32 xSz, ySz;

    if (dev == NULL || wolfKey == NULL || pubPoint == NULL)
        return BAD_FUNC_ARG;

    xSz = sizeof(pubPoint->point.x.buffer);;
    ySz = sizeof(pubPoint->point.y.buffer);;

    /* load wolf ECC public key into TPM2B_ECC_POINT */
    rc = wc_ecc_export_public_raw(wolfKey,
        pubPoint->point.x.buffer, &xSz,
        pubPoint->point.y.buffer, &ySz);
    if (rc == 0) {
        pubPoint->point.x.size = xSz;
        pubPoint->point.y.size = ySz;
    }

    return rc;
}
#endif /* HAVE_ECC_KEY_EXPORT */
#endif /* HAVE_ECC */
#endif /* !WOLFTPM2_NO_WOLFCRYPT */


/* primaryHandle must be owner or platform hierarchy */
/* Owner    Persistent Handle Range: 0x81000000 to 0x817FFFFF */
/* Platform Persistent Handle Range: 0x81800000 to 0x81FFFFFF */
int wolfTPM2_NVStoreKey(WOLFTPM2_DEV* dev, TPM_HANDLE primaryHandle,
    WOLFTPM2_KEY* key, TPM_HANDLE persistentHandle)
{
    int rc;
    EvictControl_In in;

    if (dev == NULL || key == NULL ||
        (primaryHandle != TPM_RH_OWNER && primaryHandle != TPM_RH_PLATFORM) ||
        persistentHandle < PERSISTENT_FIRST ||
        persistentHandle > PERSISTENT_LAST) {
        return BAD_FUNC_ARG;
    }

    /* if key is already persistent then just return success */
    if (key->handle.hndl == persistentHandle)
        return TPM_RC_SUCCESS;

    /* set session auth to blank */
    wolfTPM2_SetAuthPassword(dev, 0, NULL);

    /* Move key into NV to persist */
    XMEMSET(&in, 0, sizeof(in));
    in.auth = primaryHandle;
    in.objectHandle = key->handle.hndl;
    in.persistentHandle = persistentHandle;

    rc = TPM2_EvictControl(&in);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_EvictControl failed %d: %s\n", rc,
            wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }

#ifdef DEBUG_WOLFTPM
    printf("TPM2_EvictControl Auth 0x%x, Key 0x%x, Persistent 0x%x\n",
        (word32)in.auth, (word32)in.objectHandle, (word32)in.persistentHandle);
#endif

    /* unload transient handle */
    wolfTPM2_UnloadHandle(dev, &key->handle);

    /* replace handle with persistent one */
    key->handle.hndl = persistentHandle;

    return rc;
}

int wolfTPM2_NVDeleteKey(WOLFTPM2_DEV* dev, TPM_HANDLE primaryHandle,
    WOLFTPM2_KEY* key)
{
    int rc;
    EvictControl_In in;

    if (dev == NULL || key == NULL || primaryHandle == 0) {
        return BAD_FUNC_ARG;
    }

    /* if key is not persistent then just return success */
    if (key->handle.hndl < PERSISTENT_FIRST ||
            key->handle.hndl > PERSISTENT_LAST)
        return TPM_RC_SUCCESS;

    /* remove key from NV */
    XMEMSET(&in, 0, sizeof(in));
    in.auth = primaryHandle;
    in.objectHandle = key->handle.hndl;
    in.persistentHandle = key->handle.hndl;

    rc = TPM2_EvictControl(&in);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_EvictControl failed %d: %s\n", rc,
            wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }

#ifdef DEBUG_WOLFTPM
    printf("TPM2_EvictControl Auth 0x%x, Key 0x%x, Persistent 0x%x\n",
        (word32)in.auth, (word32)in.objectHandle, (word32)in.persistentHandle);
#endif

    /* indicate no handle */
    key->handle.hndl = TPM_RH_NULL;

    return rc;
}

/* sigAlg: TPM_ALG_RSASSA, TPM_ALG_RSAPSS, TPM_ALG_ECDSA or TPM_ALG_ECDAA */
/* hashAlg: TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_ALG_SHA384 or TPM_ALG_SHA512 */
int wolfTPM2_SignHashScheme(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    const byte* digest, int digestSz, byte* sig, int* sigSz,
    TPMI_ALG_SIG_SCHEME sigAlg, TPMI_ALG_HASH hashAlg)
{
    int rc;
    Sign_In  signIn;
    Sign_Out signOut;
    int curveSize = 0;

    if (dev == NULL || key == NULL || digest == NULL || sig == NULL ||
                                                            sigSz == NULL) {
        return BAD_FUNC_ARG;
    }

    if (key->pub.publicArea.type == TPM_ALG_ECC) {
        /* get curve size */
        curveSize = wolfTPM2_GetCurveSize(
            key->pub.publicArea.parameters.eccDetail.curveID);
        if (curveSize <= 0 || *sigSz < (curveSize * 2)) {
            return BAD_FUNC_ARG;
        }
    }
    else if (key->pub.publicArea.type == TPM_ALG_RSA) {
        if (*sigSz < (int)sizeof(signOut.signature.signature.rsassa.sig.buffer)) {
            return BAD_FUNC_ARG;
        }
    }

    if (dev->ctx.session) {
        /* set session auth for key */
        wolfTPM2_SetAuthHandle(dev, 0, &key->handle);
    }

    XMEMSET(&signIn, 0, sizeof(signIn));
    signIn.keyHandle = key->handle.hndl;
    signIn.digest.size = digestSz;
    XMEMCPY(signIn.digest.buffer, digest, signIn.digest.size);
    signIn.inScheme.scheme = sigAlg;
    signIn.inScheme.details.any.hashAlg = hashAlg;
    signIn.validation.tag = TPM_ST_HASHCHECK;
    signIn.validation.hierarchy = TPM_RH_NULL;
    rc = TPM2_Sign(&signIn, &signOut);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_Sign failed %d: %s\n", rc, wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }

    if (key->pub.publicArea.type == TPM_ALG_ECC) {
        /* Assemble R and S into signature (R then S) */
        *sigSz = signOut.signature.signature.ecdsa.signatureR.size +
                signOut.signature.signature.ecdsa.signatureS.size;
        XMEMCPY(sig, signOut.signature.signature.ecdsa.signatureR.buffer,
            signOut.signature.signature.ecdsa.signatureR.size);
        XMEMCPY(sig + signOut.signature.signature.ecdsa.signatureR.size,
            signOut.signature.signature.ecdsa.signatureS.buffer,
            signOut.signature.signature.ecdsa.signatureS.size);
    }
    else if (key->pub.publicArea.type == TPM_ALG_RSA) {
        /* RSA signature size and buffer (with padding depending on scheme) */
        *sigSz = signOut.signature.signature.rsassa.sig.size;
        XMEMCPY(sig, signOut.signature.signature.rsassa.sig.buffer,
            signOut.signature.signature.rsassa.sig.size);
    }

#ifdef DEBUG_WOLFTPM
    printf("TPM2_Sign: %s %d\n",
        TPM2_GetAlgName(signIn.inScheme.scheme), *sigSz);
#endif

    return rc;
}

int wolfTPM2_SignHash(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    const byte* digest, int digestSz, byte* sig, int* sigSz)
{
    TPM_ALG_ID sigAlg = TPM_ALG_NULL;

    if (dev == NULL || key == NULL || digest == NULL || sig == NULL) {
        return BAD_FUNC_ARG;
    }

    if (key->pub.publicArea.type == TPM_ALG_ECC) {
        sigAlg = key->pub.publicArea.parameters.eccDetail.scheme.scheme;
    }
    else if (key->pub.publicArea.type == TPM_ALG_RSA) {
        sigAlg = key->pub.publicArea.parameters.rsaDetail.scheme.scheme;
    }

    return wolfTPM2_SignHashScheme(dev, key, digest, digestSz, sig, sigSz,
        sigAlg, WOLFTPM2_WRAP_DIGEST);
}

/* sigAlg: TPM_ALG_RSASSA, TPM_ALG_RSAPSS, TPM_ALG_ECDSA or TPM_ALG_ECDAA */
/* hashAlg: TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_ALG_SHA384 or TPM_ALG_SHA512 */
int wolfTPM2_VerifyHashScheme(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    const byte* sig, int sigSz, const byte* digest, int digestSz,
    TPMI_ALG_SIG_SCHEME sigAlg, TPMI_ALG_HASH hashAlg)
{
    int rc;
    VerifySignature_In  verifySigIn;
    VerifySignature_Out verifySigOut;
    int curveSize = 0;

    if (dev == NULL || key == NULL || digest == NULL || sig == NULL) {
        return BAD_FUNC_ARG;
    }

    if (key->pub.publicArea.type == TPM_ALG_ECC) {
        /* get curve size */
        curveSize = wolfTPM2_GetCurveSize(
            key->pub.publicArea.parameters.eccDetail.curveID);
        if (curveSize <= 0 || sigSz < (curveSize * 2)) {
            return BAD_FUNC_ARG;
        }
        /* verify curvesize cannot exceed buffer */
        if (curveSize > (int)sizeof(verifySigIn.signature.signature.ecdsa.signatureR.buffer))
            return BAD_FUNC_ARG;

        /* hash cannot be larger than key size for TPM */
        if (digestSz > curveSize)
            digestSz = curveSize;
    }
    else if (key->pub.publicArea.type == TPM_ALG_RSA) {
        if (sigSz > (int)sizeof(verifySigIn.signature.signature.rsassa.sig.buffer))
            return BAD_FUNC_ARG;
    }

    /* verify input cannot exceed buffer */
    if (digestSz > (int)sizeof(verifySigIn.digest.buffer))
        digestSz = (int)sizeof(verifySigIn.digest.buffer);

    /* set session auth for key */
    wolfTPM2_SetAuthHandle(dev, 0, &key->handle);

    XMEMSET(&verifySigIn, 0, sizeof(verifySigIn));
    verifySigIn.keyHandle = key->handle.hndl;
    verifySigIn.digest.size = digestSz;
    XMEMCPY(verifySigIn.digest.buffer, digest, digestSz);
    verifySigIn.signature.sigAlg = sigAlg;
    verifySigIn.signature.signature.any.hashAlg = hashAlg;
    if (key->pub.publicArea.type == TPM_ALG_ECC) {
        /* Signature is R then S */
        verifySigIn.signature.signature.ecdsa.signatureR.size = curveSize;
        XMEMCPY(verifySigIn.signature.signature.ecdsa.signatureR.buffer,
            sig, curveSize);
        verifySigIn.signature.signature.ecdsa.signatureS.size = curveSize;
        XMEMCPY(verifySigIn.signature.signature.ecdsa.signatureS.buffer,
            sig + curveSize, curveSize);
    }
    else if (key->pub.publicArea.type == TPM_ALG_RSA) {
        verifySigIn.signature.signature.rsassa.sig.size = sigSz;
        XMEMCPY(verifySigIn.signature.signature.rsassa.sig.buffer, sig, sigSz);
    }

    rc = TPM2_VerifySignature(&verifySigIn, &verifySigOut);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_VerifySignature failed %d: %s\n", rc,
            wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }
#ifdef DEBUG_WOLFTPM
    printf("TPM2_VerifySignature: Tag %d\n", verifySigOut.validation.tag);
#endif

    return rc;
}

int wolfTPM2_VerifyHash_ex(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    const byte* sig, int sigSz, const byte* digest, int digestSz,
    int hashAlg)
{
    TPM_ALG_ID sigAlg = TPM_ALG_NULL;

    if (dev == NULL || key == NULL || digest == NULL || sig == NULL) {
        return BAD_FUNC_ARG;
    }

    if (key->pub.publicArea.type == TPM_ALG_ECC) {
        sigAlg = key->pub.publicArea.parameters.eccDetail.scheme.scheme;
    }
    else if (key->pub.publicArea.type == TPM_ALG_RSA) {
        sigAlg = key->pub.publicArea.parameters.rsaDetail.scheme.scheme;
    }
    return wolfTPM2_VerifyHashScheme(dev, key, sig, sigSz, digest, digestSz,
        sigAlg, hashAlg);
}

int wolfTPM2_VerifyHash(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    const byte* sig, int sigSz, const byte* digest, int digestSz)
{
    return wolfTPM2_VerifyHash_ex(dev, key, sig, sigSz, digest, digestSz,
        WOLFTPM2_WRAP_DIGEST);
}

/* Generate ECC key-pair with NULL hierarchy and load (populates handle) */
int wolfTPM2_ECDHGenKey(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* ecdhKey, int curve_id,
    const byte* auth, int authSz)
{
    int rc;
    TPMT_PUBLIC publicTemplate;
    WOLFTPM2_HANDLE nullParent;

    if (dev == NULL || ecdhKey == NULL) {
        return BAD_FUNC_ARG;
    }

    XMEMSET(&nullParent, 0, sizeof(nullParent));
    nullParent.hndl = TPM_RH_NULL;

    /* Create and load ECC key for DH */
    rc = wolfTPM2_GetKeyTemplate_ECC(&publicTemplate,
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_decrypt | TPMA_OBJECT_noDA,
        curve_id, TPM_ALG_ECDH);
    if (rc == 0) {
        rc = wolfTPM2_CreatePrimaryKey(dev, ecdhKey, TPM_RH_NULL,
            &publicTemplate, auth, authSz);
    }

    return rc;
}

/* Generate ephemeral key and compute Z (shared secret) */
/* One shot API using private key handle to generate key-pair and return
    pub-point and shared secret */
int wolfTPM2_ECDHGen(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* privKey,
    TPM2B_ECC_POINT* pubPoint, byte* out, int* outSz)
{
    int rc;
    ECDH_KeyGen_In  ecdhIn;
    ECDH_KeyGen_Out ecdhOut;
    int curveSize;

    if (dev == NULL || privKey == NULL || pubPoint == NULL || out == NULL ||
                                                                outSz == NULL) {
        return BAD_FUNC_ARG;
    }

    /* get curve size to verify output is large enough */
    curveSize = wolfTPM2_GetCurveSize(
        privKey->pub.publicArea.parameters.eccDetail.curveID);
    if (curveSize <= 0 || *outSz < curveSize) {
        return BAD_FUNC_ARG;
    }

    /* set session auth for key */
    wolfTPM2_SetAuthHandle(dev, 0, &privKey->handle);

    XMEMSET(&ecdhIn, 0, sizeof(ecdhIn));
    ecdhIn.keyHandle = privKey->handle.hndl;
    rc = TPM2_ECDH_KeyGen(&ecdhIn, &ecdhOut);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_ECDH_KeyGen failed %d: %s\n", rc,
            wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }

    *pubPoint = ecdhOut.pubPoint;
    *outSz = ecdhOut.zPoint.point.x.size;
    XMEMCPY(out, ecdhOut.zPoint.point.x.buffer, ecdhOut.zPoint.point.x.size);

#ifdef DEBUG_WOLFTPM
    printf("TPM2_ECDH_KeyGen: zPt %d, pubPt %d\n",
        ecdhOut.zPoint.size,
        ecdhOut.pubPoint.size);
#endif

    return rc;
}

/* Compute Z (shared secret) using pubPoint and loaded private ECC key */
int wolfTPM2_ECDHGenZ(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* privKey,
    const TPM2B_ECC_POINT* pubPoint, byte* out, int* outSz)
{
    int rc;
    ECDH_ZGen_In  ecdhZIn;
    ECDH_ZGen_Out ecdhZOut;
    int curveSize;

    if (dev == NULL || privKey == NULL || pubPoint == NULL || out == NULL ||
                                                                outSz == NULL) {
        return BAD_FUNC_ARG;
    }

    /* get curve size to verify output is large enough */
    curveSize = wolfTPM2_GetCurveSize(
        privKey->pub.publicArea.parameters.eccDetail.curveID);
    if (curveSize <= 0 || *outSz < curveSize) {
        return BAD_FUNC_ARG;
    }

    /* set session auth for key */
    if (dev->ctx.session) {
        wolfTPM2_SetAuthHandle(dev, 0, &privKey->handle);
    }

    XMEMSET(&ecdhZIn, 0, sizeof(ecdhZIn));
    ecdhZIn.keyHandle = privKey->handle.hndl;
    ecdhZIn.inPoint = *pubPoint;
    rc = TPM2_ECDH_ZGen(&ecdhZIn, &ecdhZOut);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_ECDH_ZGen failed %d: %s\n", rc,
            wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }

    *outSz = ecdhZOut.outPoint.point.x.size;
    XMEMCPY(out, ecdhZOut.outPoint.point.x.buffer,
        ecdhZOut.outPoint.point.x.size);

#ifdef DEBUG_WOLFTPM
    printf("TPM2_ECDH_ZGen: zPt %d\n", ecdhZOut.outPoint.size);
#endif

    return rc;
}


/* Generate ephemeral ECC key and return array index (2 phase method) */
/* One time use key */
int wolfTPM2_ECDHEGenKey(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* ecdhKey, int curve_id)
{
    int rc;
    EC_Ephemeral_In in;
    EC_Ephemeral_Out out;

    if (dev == NULL || ecdhKey == NULL) {
        return BAD_FUNC_ARG;
    }

    XMEMSET(&in, 0, sizeof(in));
    in.curveID = curve_id;
    rc = TPM2_EC_Ephemeral(&in, &out);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_EC_Ephemeral failed %d: %s\n", rc,
            wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }

    /* Save the point and counter (commit ID) into ecdhKey */
    ecdhKey->pub.publicArea.unique.ecc = out.Q.point;
    ecdhKey->handle.hndl = (UINT32)out.counter;

    return rc;
}

/* Compute Z (shared secret) using pubPoint and counter (2 phase method) */
/* The counter / array ID can only be used one time */
int wolfTPM2_ECDHEGenZ(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* parentKey,
    WOLFTPM2_KEY* ecdhKey, const TPM2B_ECC_POINT* pubPoint,
    byte* out, int* outSz)
{
    int rc;
    ZGen_2Phase_In  inZGen2Ph;
    ZGen_2Phase_Out outZGen2Ph;
    int curveSize;

    if (dev == NULL || parentKey == NULL || ecdhKey == NULL ||
        pubPoint == NULL || out == NULL || outSz == NULL) {
        return BAD_FUNC_ARG;
    }

    /* get curve size to verify output is large enough */
    curveSize = wolfTPM2_GetCurveSize(
        parentKey->pub.publicArea.parameters.eccDetail.curveID);
    if (curveSize <= 0 || *outSz < curveSize) {
        return BAD_FUNC_ARG;
    }

    /* set session auth for key */
    if (dev->ctx.session) {
        wolfTPM2_SetAuthHandle(dev, 0, &parentKey->handle);
    }

    XMEMSET(&inZGen2Ph, 0, sizeof(inZGen2Ph));
    inZGen2Ph.keyA = ecdhKey->handle.hndl;
    ecdhKey->handle.hndl = TPM_RH_NULL;
    inZGen2Ph.inQsB = *pubPoint;
    inZGen2Ph.inQeB = *pubPoint;
    inZGen2Ph.inScheme = TPM_ALG_ECDH;
    inZGen2Ph.counter = (UINT16)ecdhKey->handle.hndl;

    rc = TPM2_ZGen_2Phase(&inZGen2Ph, &outZGen2Ph);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_ZGen_2Phase failed %d: %s\n", rc,
            wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }

    *outSz = outZGen2Ph.outZ2.point.x.size;
    XMEMCPY(out, outZGen2Ph.outZ2.point.x.buffer,
        outZGen2Ph.outZ2.point.x.size);

#ifdef DEBUG_WOLFTPM
    printf("TPM2_ZGen_2Phase: zPt %d\n", outZGen2Ph.outZ2.size);
#endif

    return rc;
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
    if (dev->ctx.session) {
        wolfTPM2_SetAuthHandle(dev, 0, &key->handle);
    }

    /* RSA Encrypt */
    XMEMSET(&rsaEncIn, 0, sizeof(rsaEncIn));
    rsaEncIn.keyHandle = key->handle.hndl;
    rsaEncIn.message.size = msgSz;
    XMEMCPY(rsaEncIn.message.buffer, msg, msgSz);
    /* TPM_ALG_NULL, TPM_ALG_OAEP, TPM_ALG_RSASSA or TPM_ALG_RSAPSS */
    rsaEncIn.inScheme.scheme = padScheme;
    rsaEncIn.inScheme.details.anySig.hashAlg = WOLFTPM2_WRAP_DIGEST;

#if 0
    /* Optional label */
    rsaEncIn.label.size = sizeof(label); /* Null term required */
    XMEMCPY(rsaEncIn.label.buffer, label, rsaEncIn.label.size);
#endif

    rc = TPM2_RSA_Encrypt(&rsaEncIn, &rsaEncOut);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_RSA_Encrypt failed %d: %s\n", rc,
            wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }

    *outSz = rsaEncOut.outData.size;
    XMEMCPY(out, rsaEncOut.outData.buffer, *outSz);

#ifdef DEBUG_WOLFTPM
    printf("TPM2_RSA_Encrypt: %d\n", rsaEncOut.outData.size);
#endif

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
    if (dev->ctx.session) {
        wolfTPM2_SetAuthHandle(dev, 0, &key->handle);
    }

    /* RSA Decrypt */
    XMEMSET(&rsaDecIn, 0, sizeof(rsaDecIn));
    rsaDecIn.keyHandle = key->handle.hndl;
    rsaDecIn.cipherText.size = inSz;
    XMEMCPY(rsaDecIn.cipherText.buffer, in, inSz);
    /* TPM_ALG_NULL, TPM_ALG_OAEP, TPM_ALG_RSASSA or TPM_ALG_RSAPSS */
    rsaDecIn.inScheme.scheme = padScheme;
    rsaDecIn.inScheme.details.anySig.hashAlg = WOLFTPM2_WRAP_DIGEST;

#if 0
    /* Optional label */
    rsaDecIn.label.size = sizeof(label); /* Null term required */
    XMEMCPY(rsaDecIn.label.buffer, label, rsaEncIn.label.size);
#endif

    rc = TPM2_RSA_Decrypt(&rsaDecIn, &rsaDecOut);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_RSA_Decrypt failed %d: %s\n", rc,
            wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }

    *msgSz = rsaDecOut.message.size;
    XMEMCPY(msg, rsaDecOut.message.buffer, *msgSz);

#ifdef DEBUG_WOLFTPM
    printf("TPM2_RSA_Decrypt: %d\n", rsaDecOut.message.size);
#endif

    return rc;
}


int wolfTPM2_ReadPCR(WOLFTPM2_DEV* dev, int pcrIndex, int hashAlg, byte* digest,
    int* pDigestLen)
{
    int rc;
    PCR_Read_In  pcrReadIn;
    PCR_Read_Out pcrReadOut;
    int digestLen;

    if (dev == NULL)
        return BAD_FUNC_ARG;

    /* set session auth to blank */
    if (dev->ctx.session) {
        wolfTPM2_SetAuthPassword(dev, 0, NULL);
    }

    wolfTPM2_SetupPCRSel(&pcrReadIn.pcrSelectionIn, hashAlg, pcrIndex);
    rc = TPM2_PCR_Read(&pcrReadIn, &pcrReadOut);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_PCR_Read failed %d: %s\n", rc, wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }

    digestLen = (int)pcrReadOut.pcrValues.digests[0].size;
    if (digest)
        XMEMCPY(digest, pcrReadOut.pcrValues.digests[0].buffer, digestLen);

#ifdef DEBUG_WOLFTPM
    printf("TPM2_PCR_Read: Index %d, Digest Sz %d, Update Counter %d\n",
        pcrIndex, digestLen, (int)pcrReadOut.pcrUpdateCounter);
    TPM2_PrintBin(digest, digestLen);
#endif

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

    XMEMSET(&pcrExtend, 0, sizeof(pcrExtend));
    pcrExtend.pcrHandle = pcrIndex;
    pcrExtend.digests.count = 1;
    pcrExtend.digests.digests[0].hashAlg = hashAlg;
    XMEMCPY(pcrExtend.digests.digests[0].digest.H, digest, digestLen);
    rc = TPM2_PCR_Extend(&pcrExtend);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_PCR_Extend failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
    #endif
    }

#ifdef DEBUG_WOLFTPM
    printf("TPM2_PCR_Extend: Index %d, Digest Sz %d\n", pcrIndex, digestLen);
#endif

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
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_FlushContext failed %d: %s\n", rc,
            wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }

#ifdef DEBUG_WOLFTPM
    printf("TPM2_FlushContext: Closed handle 0x%x\n", (word32)handle->hndl);
#endif

    handle->hndl = TPM_RH_NULL;

    return TPM_RC_SUCCESS;
}

/* nv is the populated handle and auth */
/* auth and authSz are optional NV authentication */
int wolfTPM2_NVCreateAuth(WOLFTPM2_DEV* dev, WOLFTPM2_HANDLE* parent,
    WOLFTPM2_NV* nv, word32 nvIndex, word32 nvAttributes, word32 maxSize,
    const byte* auth, int authSz)
{
    int rc;
    NV_DefineSpace_In in;
    TPM2B_NAME name;

    if (dev == NULL || nv == NULL)
        return BAD_FUNC_ARG;

    /* set session auth for key */
    if (dev->ctx.session) {
        wolfTPM2_SetAuthHandle(dev, 0, parent);
    }

    XMEMSET(&name, 0, sizeof(name));
    XMEMSET(&in, 0, sizeof(in));
    in.authHandle = parent->hndl;
    if (auth && authSz > 0) {
        if (authSz > (int)sizeof(in.auth.buffer))
            authSz = (int)sizeof(in.auth.buffer);
        in.auth.size = authSz;
        XMEMCPY(in.auth.buffer, auth, in.auth.size);
    }
    in.publicInfo.nvPublic.nvIndex = nvIndex;
    in.publicInfo.nvPublic.nameAlg = TPM_ALG_SHA256;
    in.publicInfo.nvPublic.attributes = nvAttributes;
    in.publicInfo.nvPublic.dataSize = (UINT16)maxSize;

    rc = TPM2_NV_DefineSpace(&in);
    if (rc == TPM_RC_NV_DEFINED) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_NV_DefineSpace: handle already exists\n");
    #endif
    }
    else if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_NV_DefineSpace failed %d: %s\n", rc,
            wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }

    /* Compute NV Index name in case of parameter encryption */
    rc = TPM2_HashNvPublic(&in.publicInfo.nvPublic, name.name, &name.size);

    /* return new NV handle */
    XMEMSET(nv, 0, sizeof(*nv));
    nv->handle.hndl = (TPM_HANDLE)nvIndex;
    nv->handle.auth = in.auth;
    nv->handle.name.size = name.size;
    XMEMCPY(&nv->handle.name.name, name.name, nv->handle.name.size);

#ifdef DEBUG_WOLFTPM
    printf("TPM2_NV_DefineSpace: Auth 0x%x, Idx 0x%x, Attribs 0x%d, Size %d\n",
        (word32)in.authHandle,
        (word32)in.publicInfo.nvPublic.nvIndex,
        (word32)in.publicInfo.nvPublic.attributes,
        in.publicInfo.nvPublic.dataSize);
#endif

    return rc;
}

/* older API kept for compatibility, recommend using wolfTPM2_NVCreateAuth */
int wolfTPM2_NVCreate(WOLFTPM2_DEV* dev, TPM_HANDLE authHandle,
    word32 nvIndex, word32 nvAttributes, word32 maxSize,
    const byte* auth, int authSz)
{
    WOLFTPM2_NV nv;
    WOLFTPM2_HANDLE parent;

    XMEMSET(&nv, 0, sizeof(nv));
    XMEMSET(&parent, 0, sizeof(parent));
    parent.hndl = authHandle;
    return wolfTPM2_NVCreateAuth(dev, &parent, &nv, nvIndex, nvAttributes,
        maxSize, auth, authSz);
}

int wolfTPM2_NVWriteAuth(WOLFTPM2_DEV* dev, WOLFTPM2_NV* nv,
    word32 nvIndex, byte* dataBuf, word32 dataSz, word32 offset)
{
    int rc = TPM_RC_SUCCESS;
    word32 pos = 0, towrite;
    NV_Write_In in;
    NV_ReadPublic_In inPublic;
    NV_ReadPublic_Out outPublic;

    if (dev == NULL || nv == NULL)
        return BAD_FUNC_ARG;

    /* set session auth for key */
    if (dev->ctx.session) {
        wolfTPM2_SetAuthHandle(dev, 0, &nv->handle);
    }

    XMEMSET((byte*)&inPublic, 0, sizeof(inPublic));
    XMEMSET((byte*)&outPublic, 0, sizeof(outPublic));
    /* Read the NV Index publicArea to have up to date NV Index Name */
    inPublic.nvIndex = nv->handle.hndl;
    rc = TPM2_NV_ReadPublic(&inPublic, &outPublic);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("Failed to read fresh NvPublic\n");
    #endif
        return TPM_RC_FAILURE;
    }

    /* Compute NV Index name in case of parameter encryption */
    rc = TPM2_HashNvPublic(&outPublic.nvPublic.nvPublic,
                            (byte*)&nv->handle.name.name,
                            &nv->handle.name.size);

    /* Necessary, because NVWrite has two handles, second is NV Index */
    wolfTPM2_SetNameHandle(dev, 0, &nv->handle);
    wolfTPM2_SetNameHandle(dev, 1, &nv->handle);

    while (dataSz > 0) {
        towrite = dataSz;
        if (towrite > MAX_NV_BUFFER_SIZE)
            towrite = MAX_NV_BUFFER_SIZE;

        XMEMSET(&in, 0, sizeof(in));
        in.authHandle = nv->handle.hndl;
        in.nvIndex = nvIndex;
        in.offset = offset+pos;
        in.data.size = towrite;
        if (dataBuf)
            XMEMCPY(in.data.buffer, &dataBuf[pos], towrite);

        rc = TPM2_NV_Write(&in);
        if (rc != TPM_RC_SUCCESS) {
        #ifdef DEBUG_WOLFTPM
            printf("TPM2_NV_Write failed %d: %s\n", rc,
                wolfTPM2_GetRCString(rc));
        #endif
            return rc;
        }

    #ifdef DEBUG_WOLFTPM
        printf("TPM2_NV_Write: Auth 0x%x, Idx 0x%x, Offset %d, Size %d\n",
            (word32)in.authHandle, (word32)in.nvIndex,
            in.offset, in.data.size);
    #endif

        pos += towrite;
        dataSz -= towrite;
    }

    return rc;
}

/* older API kept for compatibility, recommend using wolfTPM2_NVWriteAuth */
int wolfTPM2_NVWrite(WOLFTPM2_DEV* dev, TPM_HANDLE authHandle,
    word32 nvIndex, byte* dataBuf, word32 dataSz, word32 offset)
{
    WOLFTPM2_NV nv;
    XMEMSET(&nv, 0, sizeof(nv));
    nv.handle.hndl = authHandle;
    return wolfTPM2_NVWriteAuth(dev, &nv, nvIndex, dataBuf, dataSz, offset);
}

int wolfTPM2_NVReadAuth(WOLFTPM2_DEV* dev, WOLFTPM2_NV* nv,
    word32 nvIndex, byte* dataBuf, word32* pDataSz, word32 offset)
{
    int rc = TPM_RC_SUCCESS;
    word32 pos = 0, toread, dataSz;
    NV_Read_In in;
    NV_Read_Out out;
    NV_ReadPublic_In inPublic;
    NV_ReadPublic_Out outPublic;

    if (dev == NULL || nv == NULL || pDataSz == NULL)
        return BAD_FUNC_ARG;

    /* set session auth for key */
    if (dev->ctx.session) {
        wolfTPM2_SetAuthHandle(dev, 0, &nv->handle);
    }

    XMEMSET((byte*)&inPublic, 0, sizeof(inPublic));
    XMEMSET((byte*)&outPublic, 0, sizeof(outPublic));
    /* Read the NV Index publicArea to have up to date NV Index Name */
    inPublic.nvIndex = nv->handle.hndl;
    rc = TPM2_NV_ReadPublic(&inPublic, &outPublic);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("Failed to read fresh NvPublic\n");
    #endif
        return TPM_RC_FAILURE;
    }

    /* Compute NV Index name in case of parameter encryption */
    rc = TPM2_HashNvPublic(&outPublic.nvPublic.nvPublic,
                            (byte*)&nv->handle.name.name,
                            &nv->handle.name.size);

    /* Necessary, because NVWrite has two handles, second is NV Index */
    wolfTPM2_SetNameHandle(dev, 0, &nv->handle);
    wolfTPM2_SetNameHandle(dev, 1, &nv->handle);

    dataSz = *pDataSz;

    while (dataSz > 0) {
        toread = dataSz;
        if (toread > MAX_NV_BUFFER_SIZE)
            toread = MAX_NV_BUFFER_SIZE;

        XMEMSET(&in, 0, sizeof(in));
        in.authHandle = nv->handle.hndl;
        in.nvIndex = nvIndex;
        in.offset = offset+pos;
        in.size = toread;

        rc = TPM2_NV_Read(&in, &out);
        if (rc != TPM_RC_SUCCESS) {
        #ifdef DEBUG_WOLFTPM
            printf("TPM2_NV_Read failed %d: %s\n", rc,
                wolfTPM2_GetRCString(rc));
        #endif
            return rc;
        }

        toread = out.data.size;
        if (dataBuf) {
            XMEMCPY(&dataBuf[pos], out.data.buffer, toread);
        }

    #ifdef DEBUG_WOLFTPM
        printf("TPM2_NV_Read: Auth 0x%x, Idx 0x%x, Offset %d, Size %d\n",
            (word32)in.authHandle, (word32)in.nvIndex, in.offset, out.data.size);
    #endif

        /* if we are done reading, exit loop */
        if (toread == 0)
            break;

        pos += toread;
        dataSz -= toread;
    }

    *pDataSz = pos;

    return rc;
}

/* older API kept for compatibility, recommend using wolfTPM2_NVReadAuth */
int wolfTPM2_NVRead(WOLFTPM2_DEV* dev, TPM_HANDLE authHandle,
    word32 nvIndex, byte* dataBuf, word32* pDataSz, word32 offset)
{
    WOLFTPM2_NV nv;
    XMEMSET(&nv, 0, sizeof(nv));
    nv.handle.hndl = authHandle;
    return wolfTPM2_NVReadAuth(dev, &nv, nvIndex, dataBuf, pDataSz, offset);
}

int wolfTPM2_NVReadPublic(WOLFTPM2_DEV* dev, word32 nvIndex,
    TPMS_NV_PUBLIC* nvPublic)
{
    int rc;
    NV_ReadPublic_In  in;
    NV_ReadPublic_Out out;

    if (dev == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(&in, 0, sizeof(in));
    in.nvIndex = nvIndex;
    rc = TPM2_NV_ReadPublic(&in, &out);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_NV_ReadPublic failed %d: %s\n", rc,
            wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }

#ifdef DEBUG_WOLFTPM
    printf("TPM2_NV_ReadPublic: Sz %d, Idx 0x%x, nameAlg %d, Attr 0x%x, "
            "authPol %d, dataSz %d, name %d\n",
        out.nvPublic.size,
        (word32)out.nvPublic.nvPublic.nvIndex,
        out.nvPublic.nvPublic.nameAlg,
        (word32)out.nvPublic.nvPublic.attributes,
        out.nvPublic.nvPublic.authPolicy.size,
        out.nvPublic.nvPublic.dataSize,
        out.nvName.size);
#endif

    if (nvPublic) {
        XMEMCPY(nvPublic, &out.nvPublic.nvPublic, sizeof(*nvPublic));
    }
    /* TODO: For HMAC calc out.nvName will need captured */

    return rc;
}

int wolfTPM2_NVDeleteAuth(WOLFTPM2_DEV* dev, WOLFTPM2_HANDLE* parent,
    word32 nvIndex)
{
    int rc;
    NV_UndefineSpace_In in;

    if (dev == NULL || parent == NULL)
        return BAD_FUNC_ARG;

    /* set session auth for key */
    if (dev->ctx.session) {
        wolfTPM2_SetAuthHandle(dev, 0, parent);
        /* Make sure no other auth sessions exist */
        wolfTPM2_UnsetAuth(dev, 1);
        wolfTPM2_UnsetAuth(dev, 2);
    }

    XMEMSET(&in, 0, sizeof(in));
    in.authHandle = parent->hndl;
    in.nvIndex = nvIndex;

    rc = TPM2_NV_UndefineSpace(&in);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_NV_UndefineSpace failed %d: %s\n", rc,
            wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }

#ifdef DEBUG_WOLFTPM
    printf("TPM2_NV_UndefineSpace: Auth 0x%x, Idx 0x%x\n",
        (word32)in.authHandle, (word32)in.nvIndex);
#endif

    return rc;
}

/* older API kept for compatibility, recommend using wolfTPM2_NVDeleteAuth */
int wolfTPM2_NVDelete(WOLFTPM2_DEV* dev, TPM_HANDLE authHandle,
    word32 nvIndex)
{
    WOLFTPM2_HANDLE parent;
    XMEMSET(&parent, 0, sizeof(parent));
    parent.hndl = authHandle;
    return wolfTPM2_NVDeleteAuth(dev, &parent, nvIndex);
}

#ifndef WOLFTPM2_NO_WOLFCRYPT
struct WC_RNG* wolfTPM2_GetRng(WOLFTPM2_DEV* dev)
{
#ifdef WOLFTPM2_USE_WOLF_RNG
    if (dev) {
        return &dev->ctx.rng;
    }
#endif
    return NULL;
}
#endif

int wolfTPM2_GetRandom(WOLFTPM2_DEV* dev, byte* buf, word32 len)
{
    int rc = TPM_RC_SUCCESS;
    GetRandom_In in;
    GetRandom_Out out;
    word32 sz, pos = 0;

    if (dev == NULL || buf == NULL)
        return BAD_FUNC_ARG;

    while (pos < len) {
        /* caclulate size to get */
        sz = len - pos;
        if (sz > MAX_RNG_REQ_SIZE)
            sz = MAX_RNG_REQ_SIZE;

        XMEMSET(&in, 0, sizeof(in));
        in.bytesRequested = sz;
        rc = TPM2_GetRandom(&in, &out);
        if (rc != TPM_RC_SUCCESS) {
        #ifdef DEBUG_WOLFTPM
            printf("TPM2_GetRandom failed 0x%x: %s\n", rc,
                TPM2_GetRCString(rc));
        #endif
            break;
        }

        sz = out.randomBytes.size; /* use actual returned size */
        if (sz > MAX_RNG_REQ_SIZE) {
        #ifdef DEBUG_WOLFTPM
            printf("wolfTPM2_GetRandom out size error\n");
        #endif
            rc = BAD_FUNC_ARG;
            break;
        }

        XMEMCPY(&buf[pos], out.randomBytes.buffer, sz);
        pos += sz;
    }
    return rc;
}

int wolfTPM2_Clear(WOLFTPM2_DEV* dev)
{
    int rc;
    Clear_In in;

    if (dev == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(&in, 0, sizeof(in));
    in.authHandle = TPM_RH_LOCKOUT;

    rc = TPM2_Clear(&in);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_Clear failed %d: %s\n", rc,
            wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }

#ifdef DEBUG_WOLFTPM
    printf("TPM2_Clear Auth 0x%x\n", (word32)in.authHandle);
#endif

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

    if (dev == NULL || hash == NULL || hashAlg == TPM_ALG_NULL) {
        return BAD_FUNC_ARG;
    }

    /* Capture usage auth */
    if (usageAuthSz > sizeof(hash->handle.auth.buffer))
        usageAuthSz = sizeof(hash->handle.auth.buffer);
    XMEMSET(hash, 0, sizeof(WOLFTPM2_HASH));
    hash->handle.auth.size = usageAuthSz;
    XMEMCPY(hash->handle.auth.buffer, usageAuth, usageAuthSz);

    XMEMSET(&in, 0, sizeof(in));
    in.auth = hash->handle.auth;
    in.hashAlg = hashAlg;
    rc = TPM2_HashSequenceStart(&in, &out);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_HashSequenceStart failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
    #endif
        return rc;
    }

    /* Capture hash sequence handle */
    hash->handle.hndl = out.sequenceHandle;

#ifdef DEBUG_WOLFTPM
    printf("wolfTPM2_HashStart: Handle 0x%x\n",
        (word32)out.sequenceHandle);
#endif

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
    if (dev->ctx.session) {
        wolfTPM2_SetAuthHandle(dev, 0, &hash->handle);
    }

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
        #ifdef DEBUG_WOLFTPM
            printf("TPM2_SequenceUpdate failed 0x%x: %s\n", rc,
                TPM2_GetRCString(rc));
        #endif
            return rc;
        }
        pos += hashSz;
    }

#ifdef DEBUG_WOLFTPM
    printf("wolfTPM2_HashUpdate: Handle 0x%x, DataSz %d\n",
        (word32)in.sequenceHandle, dataSz);
#endif

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
    if (dev->ctx.session) {
        wolfTPM2_SetAuthHandle(dev, 0, &hash->handle);
    }

    XMEMSET(&in, 0, sizeof(in));
    in.sequenceHandle = hash->handle.hndl;
    in.hierarchy = TPM_RH_NULL;
    rc = TPM2_SequenceComplete(&in, &out);

    /* mark hash handle as done */
    hash->handle.hndl = TPM_RH_NULL;

    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_SequenceComplete failed 0x%x: %s: Handle 0x%x\n", rc,
            TPM2_GetRCString(rc), (word32)in.sequenceHandle);
    #endif
        return rc;
    }

    if (out.result.size > *digestSz)
        out.result.size = *digestSz;
    *digestSz = out.result.size;
    XMEMCPY(digest, out.result.buffer, *digestSz);

#ifdef DEBUG_WOLFTPM
    printf("wolfTPM2_HashFinish: Handle 0x%x, DigestSz %d\n",
        (word32)in.sequenceHandle, *digestSz);
#endif

    return rc;
}


static int wolfTPM2_ComputeSymmetricUnique(WOLFTPM2_DEV* dev, int hashAlg,
    const TPMT_SENSITIVE* sensitive, TPM2B_DIGEST* unique)
{
    int rc;

#ifdef WOLFTPM_USE_SYMMETRIC
    WOLFTPM2_HASH hash;
#elif !defined(WOLFTPM2_NO_WOLFCRYPT)
    wc_HashAlg hash;
    enum wc_HashType hashType;
    int hashSz;
#endif

    if (dev == NULL || sensitive == NULL || unique == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLFTPM_USE_SYMMETRIC
    rc = wolfTPM2_HashStart(dev, &hash, hashAlg, NULL, 0);
    if (rc == 0) {
        /* sensitive seed */
        rc = wolfTPM2_HashUpdate(dev, &hash, sensitive->seedValue.buffer,
            sensitive->seedValue.size);
        if (rc == 0) {
            /* sensitive value */
            rc = wolfTPM2_HashUpdate(dev, &hash, sensitive->sensitive.any.buffer,
                sensitive->sensitive.any.size);
        }
        if (rc == 0) {
            word32 uniqueSz = TPM2_GetHashDigestSize(hashAlg);
            rc = wolfTPM2_HashFinish(dev, &hash, unique->buffer, &uniqueSz);
            unique->size = uniqueSz;
        }
        else {
            /* Make sure hash if free'd on failure */
            wolfTPM2_UnloadHandle(dev, &hash.handle);
        }
    }
#elif !defined(WOLFTPM2_NO_WOLFCRYPT)
    rc = TPM2_GetHashType(hashAlg);
    hashType = (enum wc_HashType)rc;
    rc = wc_HashGetDigestSize(hashType);
    if (rc < 0)
        return rc;
    hashSz = rc;

    /* Hash of data (name) goes into remainder */
    rc = wc_HashInit(&hash, hashType);
    if (rc == 0) {
        /* sensitive seed */
        rc = wc_HashUpdate(&hash, hashType, sensitive->seedValue.buffer,
            sensitive->seedValue.size);
        if (rc == 0) {
            /* sensitive value */
            rc = wc_HashUpdate(&hash, hashType, sensitive->sensitive.any.buffer,
                sensitive->sensitive.any.size);
        }
        if (rc == 0) {
            rc = wc_HashFinal(&hash, hashType, unique->buffer);
            if (rc == 0)
                unique->size = hashSz;
        }
        wc_HashFree(&hash, hashType);
    }
#else
    (void)hashAlg;
    rc = NOT_COMPILED_IN;
#endif

    return rc;
}

int wolfTPM2_LoadSymmetricKey(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key, int alg,
    const byte* keyBuf, word32 keySz)
{
    int rc;
    LoadExternal_In  loadExtIn;
    LoadExternal_Out loadExtOut;
    int hashAlg, hashAlgDigSz;

    if (dev == NULL || key == NULL || keyBuf == NULL || (keySz != 16 && keySz != 32)) {
        return BAD_FUNC_ARG;
    }
    if (keySz > sizeof(loadExtIn.inPrivate.sensitiveArea.sensitive.sym.buffer)) {
        return BUFFER_E;
    }

    hashAlg = (keySz == 32) ? TPM_ALG_SHA256 : TPM_ALG_SHA1;
    hashAlgDigSz = TPM2_GetHashDigestSize(hashAlg);

    /* Setup load command */
    XMEMSET(&loadExtIn, 0, sizeof(loadExtIn));
    loadExtIn.hierarchy = TPM_RH_NULL;

    /* Setup private key */
    loadExtIn.inPrivate.sensitiveArea.sensitiveType = TPM_ALG_SYMCIPHER;
    if (key->handle.auth.size > 0) {
        loadExtIn.inPrivate.sensitiveArea.authValue.size = key->handle.auth.size;
        XMEMCPY(loadExtIn.inPrivate.sensitiveArea.authValue.buffer,
            key->handle.auth.buffer, key->handle.auth.size);
    }
    loadExtIn.inPrivate.sensitiveArea.seedValue.size = hashAlgDigSz;
    rc = wolfTPM2_GetRandom(dev,
        loadExtIn.inPrivate.sensitiveArea.seedValue.buffer,
        loadExtIn.inPrivate.sensitiveArea.seedValue.size);
    if (rc != 0)
        goto exit;

    loadExtIn.inPrivate.sensitiveArea.sensitive.sym.size = keySz;
    XMEMCPY(loadExtIn.inPrivate.sensitiveArea.sensitive.sym.buffer,
        keyBuf, keySz);

    /* Setup public key */
    rc = wolfTPM2_GetKeyTemplate_Symmetric(&loadExtIn.inPublic.publicArea,
        keySz * 8, alg, YES, YES);
    if (rc != 0)
        goto exit;
    loadExtIn.inPublic.publicArea.nameAlg = hashAlg;
    loadExtIn.inPublic.publicArea.unique.sym.size = hashAlgDigSz;
    rc = wolfTPM2_ComputeSymmetricUnique(dev, hashAlg,
        &loadExtIn.inPrivate.sensitiveArea,
        &loadExtIn.inPublic.publicArea.unique.sym);
    if (rc != 0)
        goto exit;

    /* Load private key */
    rc = TPM2_LoadExternal(&loadExtIn, &loadExtOut);
    if (rc == TPM_RC_SUCCESS) {
        key->handle.hndl = loadExtOut.objectHandle;
        key->handle.symmetric = loadExtIn.inPublic.publicArea.parameters.asymDetail.symmetric;
        key->pub = loadExtIn.inPublic;

    #ifdef DEBUG_WOLFTPM
        printf("wolfTPM2_LoadSymmetricKey: 0x%x\n", (word32)loadExtOut.objectHandle);
    #endif
        return rc;
    }

exit:

    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_LoadExternal: failed %d: %s\n", rc,
            wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }

    return rc;
}

/* EncryptDecrypt */
int wolfTPM2_EncryptDecryptBlock(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    const byte* in, byte* out, word32 inOutSz, byte* iv, word32 ivSz,
    int isDecrypt)
{
    int rc;
    EncryptDecrypt2_In encDecIn;
    EncryptDecrypt2_Out encDecOut;

    if (dev == NULL || key == NULL || in == NULL || out == NULL || inOutSz == 0) {
        return BAD_FUNC_ARG;
    }

    /* set session auth for key */
    if (dev->ctx.session) {
        wolfTPM2_SetAuthHandle(dev, 0, &key->handle);
    }

    XMEMSET(&encDecIn, 0, sizeof(encDecIn));
    encDecIn.keyHandle = key->handle.hndl;
    if (iv == NULL || ivSz == 0) {
        encDecIn.ivIn.size = MAX_AES_BLOCK_SIZE_BYTES; /* zeros */
    }
    else {
        encDecIn.ivIn.size = ivSz;
        XMEMCPY(encDecIn.ivIn.buffer, iv, ivSz);
    }
    encDecIn.decrypt = isDecrypt;
    /* use symmetric algorithm from key */
    encDecIn.mode = key->pub.publicArea.parameters.symDetail.sym.mode.aes;

    encDecIn.inData.size = inOutSz;
    XMEMCPY(encDecIn.inData.buffer, in, inOutSz);

    /* make sure its multiple of block size */
    encDecIn.inData.size = (encDecIn.inData.size +
        MAX_AES_BLOCK_SIZE_BYTES - 1) & ~(MAX_AES_BLOCK_SIZE_BYTES - 1);

    rc = TPM2_EncryptDecrypt2(&encDecIn, &encDecOut);
    if (rc == TPM_RC_COMMAND_CODE) { /* some TPM's may not support command */
        /* try to enable support */
        rc = wolfTPM2_SetCommand(dev, TPM_CC_EncryptDecrypt2, YES);
        if (rc == TPM_RC_SUCCESS) {
            /* try command again */
            rc = TPM2_EncryptDecrypt2(&encDecIn, &encDecOut);
        }
    }

    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_EncryptDecrypt2 failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
    #endif
        return rc;
    }

    /* update IV */
    if (iv) {
        if (ivSz < encDecOut.ivOut.size)
            ivSz = encDecOut.ivOut.size;
        XMEMCPY(iv, encDecOut.ivOut.buffer, ivSz);
    }

    /* return block */
    if (inOutSz > encDecOut.outData.size)
        inOutSz = encDecOut.outData.size;
    XMEMCPY(out, encDecOut.outData.buffer, inOutSz);

    return rc;
}

int wolfTPM2_EncryptDecrypt(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    const byte* in, byte* out, word32 inOutSz,
    byte* iv, word32 ivSz, int isDecrypt)
{
    int rc = 0;
    word32 pos = 0, xfer;

    while (pos < inOutSz) {
        xfer = inOutSz - pos;
        if (xfer > MAX_DIGEST_BUFFER)
            xfer = MAX_DIGEST_BUFFER;

        rc = wolfTPM2_EncryptDecryptBlock(dev, key, &in[pos], &out[pos],
            xfer, iv, ivSz, isDecrypt);
        if (rc != TPM_RC_SUCCESS)
            break;

        pos += xfer;
    }

#ifdef DEBUG_WOLFTPM
    printf("wolfTPM2_EncryptDecrypt: 0x%x: %s, %d bytes\n",
        rc, TPM2_GetRCString(rc), inOutSz);
#endif

    return rc;
}


int wolfTPM2_SetCommand(WOLFTPM2_DEV* dev, TPM_CC commandCode, int enableFlag)
{
    int rc = TPM_RC_COMMAND_CODE; /* not supported */
#if defined(WOLFTPM_ST33) || defined(WOLFTPM_AUTODETECT)
    if (TPM2_GetVendorID() == TPM_VENDOR_STM) {
        SetCommandSet_In in;

        /* Enable commands (like TPM2_EncryptDecrypt2) */
        XMEMSET(&in, 0, sizeof(in));
        in.authHandle = TPM_RH_PLATFORM;
        in.commandCode = commandCode;
        in.enableFlag = enableFlag;
        rc = TPM2_SetCommandSet(&in);
        if (rc != TPM_RC_SUCCESS) {
        #ifdef DEBUG_WOLFTPM
            printf("TPM2_SetCommandSet failed 0x%x: %s\n", rc,
                TPM2_GetRCString(rc));
        #endif
        }
    }
#else
    (void)commandCode;
    (void)enableFlag;
#endif
    (void)dev;
    return rc;
}



/* HMAC */
int wolfTPM2_LoadKeyedHashKey(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    WOLFTPM2_HANDLE* parent, int hashAlg, const byte* keyBuf, word32 keySz,
    const byte* usageAuth, word32 usageAuthSz)
{
    int rc;
    Create_In  createIn;
    Create_Out createOut;
    Load_In  loadIn;
    Load_Out loadOut;
    int hashAlgDigSz;

    if (dev == NULL || key == NULL || parent == NULL || keyBuf == NULL) {
        return BAD_FUNC_ARG;
    }
    if (keySz == 0 || keySz > MAX_SYM_DATA) {
        return BUFFER_E;
    }
    hashAlgDigSz = TPM2_GetHashDigestSize(hashAlg);
    if (hashAlgDigSz <= 0) {
        return BAD_FUNC_ARG;
    }

    /* clear output key buffer */
    XMEMSET(key, 0, sizeof(WOLFTPM2_KEY));

    /* set session auth for parent key */
    if (dev->ctx.session) {
        wolfTPM2_SetAuthHandle(dev, 0, parent);
    }

    XMEMSET(&createIn, 0, sizeof(createIn));
    createIn.parentHandle = parent->hndl;
    if (usageAuth) {
        createIn.inSensitive.sensitive.userAuth.size = usageAuthSz;
        XMEMCPY(createIn.inSensitive.sensitive.userAuth.buffer, usageAuth,
            createIn.inSensitive.sensitive.userAuth.size);
    }
    createIn.inSensitive.sensitive.data.size = keySz;
    XMEMCPY(createIn.inSensitive.sensitive.data.buffer, keyBuf, keySz);

    rc = wolfTPM2_GetKeyTemplate_KeyedHash(&createIn.inPublic.publicArea,
        hashAlg, YES, NO);
    if (rc != 0) {
        return rc;
    }

    rc = TPM2_Create(&createIn, &createOut);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_Create key failed %d: %s\n", rc, wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }

#ifdef DEBUG_WOLFTPM
    printf("TPM2_Create key: pub %d, priv %d\n", createOut.outPublic.size,
        createOut.outPrivate.size);
#endif
    key->handle.symmetric = createOut.outPublic.publicArea.parameters.asymDetail.symmetric;
    key->pub = createOut.outPublic;

    /* Load new key */
    XMEMSET(&loadIn, 0, sizeof(loadIn));
    loadIn.parentHandle = parent->hndl;
    loadIn.inPrivate = createOut.outPrivate;
    loadIn.inPublic = key->pub;
    rc = TPM2_Load(&loadIn, &loadOut);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_Load key failed %d: %s\n", rc, wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }
    key->handle.hndl = loadOut.objectHandle;
    key->handle.auth = createIn.inSensitive.sensitive.userAuth;
    key->handle.name = loadOut.name;

#ifdef DEBUG_WOLFTPM
    printf("wolfTPM2_LoadKeyedHashKey Key Handle 0x%x\n",
        (word32)key->handle.hndl);
#endif

    return rc;
}

int wolfTPM2_HmacStart(WOLFTPM2_DEV* dev, WOLFTPM2_HMAC* hmac,
    WOLFTPM2_HANDLE* parent, TPMI_ALG_HASH hashAlg, const byte* keyBuf, word32 keySz,
    const byte* usageAuth, word32 usageAuthSz)
{
    int rc;
    HMAC_Start_In in;
    HMAC_Start_Out out;

    if (dev == NULL || hmac == NULL || hashAlg == TPM_ALG_NULL) {
        return BAD_FUNC_ARG;
    }

    /* Capture usage auth */
    if (usageAuthSz > sizeof(hmac->hash.handle.auth.buffer))
        usageAuthSz = sizeof(hmac->hash.handle.auth.buffer);
    hmac->hash.handle.auth.size = usageAuthSz;
    XMEMCPY(hmac->hash.handle.auth.buffer, usageAuth, usageAuthSz);

    if (!hmac->hmacKeyLoaded || hmac->key.handle.hndl == TPM_RH_NULL) {
        /* Load Keyed Hash Key */
        rc = wolfTPM2_LoadKeyedHashKey(dev, &hmac->key, parent, hashAlg, keyBuf, keySz,
            usageAuth, usageAuthSz);
        if (rc != 0) {
            return rc;
        }
        hmac->hmacKeyLoaded = 1;
    }

    /* set session auth for hmac key */
    if (dev->ctx.session) {
        wolfTPM2_SetAuthHandle(dev, 0, &hmac->hash.handle);
    }

    /* Setup HMAC start command */
    XMEMSET(&in, 0, sizeof(in));
    in.handle = hmac->key.handle.hndl;
    in.auth = hmac->hash.handle.auth;
    in.hashAlg = hashAlg;
    rc = TPM2_HMAC_Start(&in, &out);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_HMAC_Start failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
    #endif
        return rc;
    }

    /* Capture hash sequence handle */
    hmac->hash.handle.hndl = out.sequenceHandle;

#ifdef DEBUG_WOLFTPM
    printf("wolfTPM2_HmacStart: Handle 0x%x\n",
        (word32)out.sequenceHandle);
#endif

    return rc;
}

int wolfTPM2_HmacUpdate(WOLFTPM2_DEV* dev, WOLFTPM2_HMAC* hmac,
    const byte* data, word32 dataSz)
{
    if (dev == NULL || hmac == NULL) {
        return BAD_FUNC_ARG;
    }

    return wolfTPM2_HashUpdate(dev, &hmac->hash, data, dataSz);
}

int wolfTPM2_HmacFinish(WOLFTPM2_DEV* dev, WOLFTPM2_HMAC* hmac,
    byte* digest, word32* digestSz)
{
    int rc;

    if (dev == NULL || hmac == NULL) {
        return BAD_FUNC_ARG;
    }

    rc = wolfTPM2_HashFinish(dev, &hmac->hash, digest, digestSz);

    if (!hmac->hmacKeyKeep) {
        /* unload HMAC key */
        wolfTPM2_UnloadHandle(dev, &hmac->key.handle);
        hmac->hmacKeyLoaded = 0;
    }

    return rc;
}

/* performs a reset sequence */
int wolfTPM2_Shutdown(WOLFTPM2_DEV* dev, int doStartup)
{
    int rc;
    Shutdown_In shutdownIn;
    Startup_In startupIn;

    if (dev == NULL) {
        return BAD_FUNC_ARG;
    }

    /* shutdown */
    XMEMSET(&shutdownIn, 0, sizeof(shutdownIn));
    shutdownIn.shutdownType = TPM_SU_CLEAR;
    rc = TPM2_Shutdown(&shutdownIn);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_Shutdown failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
    #endif
    }

    /* startup */
    if (doStartup) {
        XMEMSET(&startupIn, 0, sizeof(startupIn));
        startupIn.startupType = TPM_SU_CLEAR;
        rc = TPM2_Startup(&startupIn);
        if (rc != TPM_RC_SUCCESS) {
        #ifdef DEBUG_WOLFTPM
            printf("TPM2_Startup failed %d: %s\n", rc, wolfTPM2_GetRCString(rc));
        #endif
            return rc;
        }
    }

#ifdef DEBUG_WOLFTPM
    printf("wolfTPM2_Shutdown complete\n");
#endif

    return rc;
}

int wolfTPM2_UnloadHandles(WOLFTPM2_DEV* dev, word32 handleStart, word32 handleCount)
{
    int rc = TPM_RC_SUCCESS;
    word32 hndl;
    WOLFTPM2_HANDLE handle;
    if (dev == NULL) {
        return BAD_FUNC_ARG;
    }
    XMEMSET(&handle, 0, sizeof(handle));
    handle.auth = dev->session[0].auth;
    for (hndl=handleStart; hndl < handleStart+handleCount; hndl++) {
        handle.hndl = hndl;
        /* ignore return code failures */
        (void)wolfTPM2_UnloadHandle(dev, &handle);
    }
    return rc;
}

int wolfTPM2_UnloadHandles_AllTransient(WOLFTPM2_DEV* dev)
{
    return wolfTPM2_UnloadHandles(dev, TRANSIENT_FIRST, MAX_HANDLE_NUM);
}


/******************************************************************************/
/* --- END Wrapper Device Functions-- */
/******************************************************************************/


/******************************************************************************/
/* --- BEGIN Utility Functions -- */
/******************************************************************************/

static int GetKeyTemplateRSA(TPMT_PUBLIC* publicTemplate,
    TPM_ALG_ID nameAlg, TPMA_OBJECT objectAttributes, int keyBits, int exponent,
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
    publicTemplate->parameters.rsaDetail.exponent = exponent;
    publicTemplate->parameters.rsaDetail.scheme.scheme = sigScheme;
    publicTemplate->parameters.rsaDetail.scheme.details.anySig.hashAlg = sigHash;
    if (objectAttributes & TPMA_OBJECT_fixedTPM) {
        publicTemplate->parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
        publicTemplate->parameters.rsaDetail.symmetric.keyBits.aes = 128;
        publicTemplate->parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_CFB;
    }
    else {
        publicTemplate->parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
    }

    return TPM_RC_SUCCESS;
}

static int GetKeyTemplateECC(TPMT_PUBLIC* publicTemplate,
    TPM_ALG_ID nameAlg, TPMA_OBJECT objectAttributes, TPM_ECC_CURVE curve,
    TPM_ALG_ID sigScheme, TPM_ALG_ID sigHash)
{
    int curveSz = TPM2_GetCurveSize(curve);

    if (publicTemplate == NULL || curveSz == 0)
        return BAD_FUNC_ARG;

    XMEMSET(publicTemplate, 0, sizeof(TPMT_PUBLIC));
    publicTemplate->type = TPM_ALG_ECC;
    publicTemplate->nameAlg = nameAlg;
    publicTemplate->unique.ecc.x.size = curveSz / 8;
    publicTemplate->unique.ecc.y.size = curveSz / 8;
    publicTemplate->objectAttributes = objectAttributes;
    if (objectAttributes & TPMA_OBJECT_fixedTPM) {
        publicTemplate->parameters.eccDetail.symmetric.algorithm = TPM_ALG_AES;
        publicTemplate->parameters.eccDetail.symmetric.keyBits.aes = 128;
        publicTemplate->parameters.eccDetail.symmetric.mode.aes = TPM_ALG_CFB;
    }
    else {
        publicTemplate->parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
    }
    /* TPM_ALG_ECDSA or TPM_ALG_ECDH */
    publicTemplate->parameters.eccDetail.scheme.scheme = sigScheme;
    publicTemplate->parameters.eccDetail.scheme.details.ecdsa.hashAlg = sigHash;
    publicTemplate->parameters.eccDetail.curveID = curve;
    publicTemplate->parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;

    return TPM_RC_SUCCESS;
}

int wolfTPM2_GetKeyTemplate_RSA(TPMT_PUBLIC* publicTemplate,
    TPMA_OBJECT objectAttributes)
{
    return GetKeyTemplateRSA(publicTemplate, WOLFTPM2_WRAP_DIGEST,
        objectAttributes, WOLFTPM2_WRAP_RSA_KEY_BITS, WOLFTPM2_WRAP_RSA_EXPONENT,
        TPM_ALG_NULL, WOLFTPM2_WRAP_DIGEST);
}

int wolfTPM2_GetKeyTemplate_ECC(TPMT_PUBLIC* publicTemplate,
    TPMA_OBJECT objectAttributes, TPM_ECC_CURVE curve, TPM_ALG_ID sigScheme)
{
    return GetKeyTemplateECC(publicTemplate, WOLFTPM2_WRAP_DIGEST,
        objectAttributes, curve, sigScheme, WOLFTPM2_WRAP_DIGEST);
}

int wolfTPM2_GetKeyTemplate_Symmetric(TPMT_PUBLIC* publicTemplate, int keyBits,
    TPM_ALG_ID algMode, int isSign, int isDecrypt)
{
    if (publicTemplate == NULL)
        return BAD_FUNC_ARG;

#ifdef WOLFTPM_MCHP
    isSign = 0; /* Microchip TPM does not like "sign" set for symmetric keys */
#endif

    XMEMSET(publicTemplate, 0, sizeof(TPMT_PUBLIC));
    publicTemplate->type = TPM_ALG_SYMCIPHER;
    publicTemplate->nameAlg = WOLFTPM2_WRAP_DIGEST;
    publicTemplate->unique.sym.size = keyBits / 8;
    publicTemplate->objectAttributes = (
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_noDA | (isSign ? TPMA_OBJECT_sign : 0) |
        (isDecrypt ? TPMA_OBJECT_decrypt : 0));
    publicTemplate->parameters.symDetail.sym.algorithm = TPM_ALG_AES;
    publicTemplate->parameters.symDetail.sym.keyBits.sym = keyBits;
    publicTemplate->parameters.symDetail.sym.mode.sym = algMode;

    return TPM_RC_SUCCESS;
}

int wolfTPM2_GetKeyTemplate_KeyedHash(TPMT_PUBLIC* publicTemplate,
    TPM_ALG_ID hashAlg, int isSign, int isDecrypt)
{
    if (publicTemplate == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(publicTemplate, 0, sizeof(TPMT_PUBLIC));
    publicTemplate->type = TPM_ALG_KEYEDHASH;
    publicTemplate->nameAlg = WOLFTPM2_WRAP_DIGEST;
    publicTemplate->objectAttributes = (
        TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_noDA |
        (isSign ? TPMA_OBJECT_sign : 0) |
        (isDecrypt ? TPMA_OBJECT_decrypt : 0));
    publicTemplate->parameters.keyedHashDetail.scheme.scheme = TPM_ALG_HMAC;
    publicTemplate->parameters.keyedHashDetail.scheme.details.hmac.hashAlg = hashAlg;

    return TPM_RC_SUCCESS;
}

int wolfTPM2_GetKeyTemplate_RSA_EK(TPMT_PUBLIC* publicTemplate)
{
    int ret;
    TPMA_OBJECT objectAttributes = (
        TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent |
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_adminWithPolicy |
        TPMA_OBJECT_restricted | TPMA_OBJECT_decrypt);

    ret = GetKeyTemplateRSA(publicTemplate, TPM_ALG_SHA256,
        objectAttributes, 2048, 0, TPM_ALG_NULL, TPM_ALG_NULL);
    if (ret == 0) {
        publicTemplate->authPolicy.size = sizeof(TPM_20_EK_AUTH_POLICY);
        XMEMCPY(publicTemplate->authPolicy.buffer,
            TPM_20_EK_AUTH_POLICY, publicTemplate->authPolicy.size);
    }
    return ret;
}

int wolfTPM2_GetKeyTemplate_ECC_EK(TPMT_PUBLIC* publicTemplate)
{
    int ret;
    TPMA_OBJECT objectAttributes = (
        TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent |
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_adminWithPolicy |
        TPMA_OBJECT_restricted | TPMA_OBJECT_decrypt);

    ret = GetKeyTemplateECC(publicTemplate, TPM_ALG_SHA256,
        objectAttributes, TPM_ECC_NIST_P256, TPM_ALG_NULL, TPM_ALG_NULL);
    if (ret == 0) {
        publicTemplate->authPolicy.size = sizeof(TPM_20_EK_AUTH_POLICY);
        XMEMCPY(publicTemplate->authPolicy.buffer,
            TPM_20_EK_AUTH_POLICY, publicTemplate->authPolicy.size);
    }
    return ret;
}

int wolfTPM2_GetKeyTemplate_RSA_SRK(TPMT_PUBLIC* publicTemplate)
{
    TPMA_OBJECT objectAttributes = (
        TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent |
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_restricted | TPMA_OBJECT_decrypt | TPMA_OBJECT_noDA);

    return GetKeyTemplateRSA(publicTemplate, TPM_ALG_SHA256,
        objectAttributes, 2048, 0, TPM_ALG_NULL, TPM_ALG_NULL);
}

int wolfTPM2_GetKeyTemplate_ECC_SRK(TPMT_PUBLIC* publicTemplate)
{
    TPMA_OBJECT objectAttributes = (
        TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent |
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_restricted | TPMA_OBJECT_decrypt | TPMA_OBJECT_noDA);

    return GetKeyTemplateECC(publicTemplate, TPM_ALG_SHA256,
        objectAttributes, TPM_ECC_NIST_P256, TPM_ALG_NULL, TPM_ALG_NULL);
}

int wolfTPM2_GetKeyTemplate_RSA_AIK(TPMT_PUBLIC* publicTemplate)
{
    int ret;
    TPMA_OBJECT objectAttributes = (
        TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent |
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_restricted | TPMA_OBJECT_sign | TPMA_OBJECT_noDA);

    ret = GetKeyTemplateRSA(publicTemplate, TPM_ALG_SHA256,
        objectAttributes, 2048, 0, TPM_ALG_RSASSA, TPM_ALG_SHA256);
    if (ret == 0) {
        publicTemplate->parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
    }
    return ret;
}

int wolfTPM2_GetKeyTemplate_ECC_AIK(TPMT_PUBLIC* publicTemplate)
{
    int ret;
    TPMA_OBJECT objectAttributes = (
        TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent |
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_restricted | TPMA_OBJECT_sign | TPMA_OBJECT_noDA);

    ret = GetKeyTemplateECC(publicTemplate, TPM_ALG_SHA256,
        objectAttributes, TPM_ECC_NIST_P256, TPM_ALG_ECDSA, TPM_ALG_SHA256);
    if (ret == 0) {
        publicTemplate->parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
    }
    return ret;
}

int wolfTPM2_GetNvAttributesTemplate(TPM_HANDLE auth, word32* nvAttributes)
{
    if (nvAttributes == NULL)
        return BAD_FUNC_ARG;

    *nvAttributes = (
        TPMA_NV_AUTHWRITE  |    /* password or HMAC can authorize writing */
        TPMA_NV_AUTHREAD   |    /* password or HMAC can authorize reading */
        TPMA_NV_OWNERWRITE |    /* Owner Hierarchy auth can be used also */
        TPMA_NV_OWNERREAD  |    /* Owner Hierarchy auth for read */
        TPMA_NV_NO_DA           /* Don't increment dictionary attack counter */
    );

    if (auth == TPM_RH_PLATFORM) {
        *nvAttributes |= (
            TPMA_NV_PPWRITE | TPMA_NV_PPREAD
        );
    }

    return 0;
}

int wolfTPM2_CreateEK(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* ekKey, TPM_ALG_ID alg)
{
    int rc;
    TPMT_PUBLIC publicTemplate;

    if (alg == TPM_ALG_RSA) {
        rc = wolfTPM2_GetKeyTemplate_RSA_EK(&publicTemplate);
    }
    else if (alg == TPM_ALG_ECC) {
        rc = wolfTPM2_GetKeyTemplate_ECC_EK(&publicTemplate);
    }
    else {
        /* Supported algorithms for EK are only RSA 2048-bit& ECC P256 */
        return BAD_FUNC_ARG;
    }
    /* GetKeyTemplate check */
    if (rc != 0)
        return rc;

    rc = wolfTPM2_CreatePrimaryKey(dev, ekKey, TPM_RH_ENDORSEMENT,
        &publicTemplate, NULL, 0);

    return rc;
}

int wolfTPM2_CreateSRK(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* srkKey, TPM_ALG_ID alg,
    const byte* auth, int authSz)
{
    int rc;
    TPMT_PUBLIC publicTemplate;

    /* Supported algorithms for SRK are only 2048bit RSA & ECC */
    if (alg == TPM_ALG_RSA) {
        rc = wolfTPM2_GetKeyTemplate_RSA_SRK(&publicTemplate);
    }
    else if (alg == TPM_ALG_ECC) {
        rc = wolfTPM2_GetKeyTemplate_ECC_SRK(&publicTemplate);
    }
    else {
        /* Supported algorithms for SRK are only RSA 2048-bit & ECC P256 */
        return BAD_FUNC_ARG;
    }
    /* GetKeyTemplate check */
    if (rc != 0)
        return rc;

    rc = wolfTPM2_CreatePrimaryKey(dev, srkKey, TPM_RH_OWNER,
        &publicTemplate, auth, authSz);

    return rc;
}

int wolfTPM2_CreateAndLoadAIK(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* aikKey,
    TPM_ALG_ID alg, WOLFTPM2_KEY* srkKey, const byte* auth, int authSz)
{
    int rc;
    TPMT_PUBLIC publicTemplate;

    if (alg == TPM_ALG_RSA) {
        rc = wolfTPM2_GetKeyTemplate_RSA_AIK(&publicTemplate);
    }
    else if (alg == TPM_ALG_ECC) {
        rc = wolfTPM2_GetKeyTemplate_ECC_AIK(&publicTemplate);
    }
    else {
        return BAD_FUNC_ARG;
    }
    /* GetKeyTemplate check */
    if (rc != 0)
        return rc;

    rc = wolfTPM2_CreateAndLoadKey(dev, aikKey, &srkKey->handle,
        &publicTemplate, auth, authSz);

    return rc;
}

int wolfTPM2_GetTime(WOLFTPM2_KEY* aikKey, GetTime_Out* getTimeOut)
{
    int rc;
    GetTime_In getTimeCmd;

    if(getTimeOut == NULL) return BAD_FUNC_ARG;

    /* GetTime */
    XMEMSET(&getTimeCmd, 0, sizeof(getTimeCmd));
    XMEMSET(getTimeOut, 0, sizeof(*getTimeOut));
    getTimeCmd.privacyAdminHandle = TPM_RH_ENDORSEMENT;
    /* TPM_RH_NULL is a valid handle for NULL signature */
    getTimeCmd.signHandle = aikKey->handle.hndl;
    /* TPM_ALG_NULL is a valid handle for  NULL signature */
    getTimeCmd.inScheme.scheme = TPM_ALG_RSASSA;
    getTimeCmd.inScheme.details.rsassa.hashAlg = TPM_ALG_SHA256;
    getTimeCmd.qualifyingData.size = 0; /* optional */
    rc = TPM2_GetTime(&getTimeCmd, getTimeOut);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_GetTime failed 0x%x: %s\n", rc, wolfTPM2_GetRCString(rc));
    #endif
    }

    return rc;
}


/******************************************************************************/
/* --- END Utility Functions -- */
/******************************************************************************/


#if !defined(WOLFTPM2_NO_WOLFCRYPT) && (defined(WOLF_CRYPTO_DEV) || defined(WOLF_CRYPTO_CB))
/******************************************************************************/
/* --- BEGIN wolf Crypto Device Support -- */
/******************************************************************************/

/* Internal structure for tracking hash state */
typedef struct WOLFTPM2_HASHCTX {
    TPM_HANDLE handle;
#ifdef WOLFTPM_USE_SYMMETRIC
    byte*  cacheBuf;   /* buffer */
    word32 cacheBufSz; /* buffer size */
    word32 cacheSz;    /* filled size */
#endif
} WOLFTPM2_HASHCTX;

#ifdef WOLFTPM_USE_SYMMETRIC
    #ifndef WOLFTPM2_HASH_BLOCK_SZ
        #define WOLFTPM2_HASH_BLOCK_SZ 256
    #endif
    static int wolfTPM2_HashUpdateCache(WOLFTPM2_HASHCTX* hashCtx,
        const byte* in, word32 inSz)
    {
        int ret = 0;

        /* allocate new cache buffer */
        if (hashCtx->cacheBuf == NULL) {
            hashCtx->cacheSz = 0;
            hashCtx->cacheBufSz = (inSz + WOLFTPM2_HASH_BLOCK_SZ - 1)
                & ~(WOLFTPM2_HASH_BLOCK_SZ - 1);
            if (hashCtx->cacheBufSz == 0)
                hashCtx->cacheBufSz = WOLFTPM2_HASH_BLOCK_SZ;
            hashCtx->cacheBuf = (byte*)XMALLOC(hashCtx->cacheBufSz,
                NULL, DYNAMIC_TYPE_TMP_BUFFER);
            if (hashCtx->cacheBuf == NULL) {
                return MEMORY_E;
            }
        }
        /* determine if we need to grow buffer */
        else if ((hashCtx->cacheSz + inSz) > hashCtx->cacheBufSz) {
            byte* oldIn = hashCtx->cacheBuf;
            hashCtx->cacheBufSz = (hashCtx->cacheSz + inSz +
                WOLFTPM2_HASH_BLOCK_SZ - 1) & ~(WOLFTPM2_HASH_BLOCK_SZ - 1);
             hashCtx->cacheBuf = (byte*)XMALLOC(hashCtx->cacheBufSz,
                NULL, DYNAMIC_TYPE_TMP_BUFFER);
            if (hashCtx->cacheBuf == NULL) {
                return MEMORY_E;
            }
            XMEMCPY(hashCtx->cacheBuf, oldIn, hashCtx->cacheSz);
            XFREE(oldIn, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }

        /* copy input to new buffer */
        XMEMCPY(&hashCtx->cacheBuf[hashCtx->cacheSz], in, inSz);
        hashCtx->cacheSz += inSz;

        return ret;
    }
#endif /* WOLFTPM_USE_SYMMETRIC */

int wolfTPM2_CryptoDevCb(int devId, wc_CryptoInfo* info, void* ctx)
{
    int rc = CRYPTOCB_UNAVAILABLE;
    int exit_rc;
    TpmCryptoDevCtx* tlsCtx = (TpmCryptoDevCtx*)ctx;

    if (info == NULL || ctx == NULL || tlsCtx->dev == NULL)
        return BAD_FUNC_ARG;

    /* for FIPS mode default error is not allowed, otherwise try and fallback
        to software crypto */
    exit_rc = tlsCtx->useFIPSMode ? FIPS_NOT_ALLOWED_E : CRYPTOCB_UNAVAILABLE;

    (void)devId;

    if (info->algo_type == WC_ALGO_TYPE_RNG) {
    #ifndef WC_NO_RNG
    #ifdef DEBUG_WOLFTPM
        printf("CryptoDevCb RNG: Sz %d\n", info->rng.sz);
    #endif
        rc = wolfTPM2_GetRandom(tlsCtx->dev, info->rng.out, info->rng.sz);
    #endif /* !WC_NO_RNG */
    }
#if !defined(NO_RSA) || defined(HAVE_ECC)
    else if (info->algo_type == WC_ALGO_TYPE_PK) {
        int isWolfKeyValid = 1;

    #ifdef DEBUG_WOLFTPM
        printf("CryptoDevCb Pk: Type %d\n", info->pk.type);
    #endif

        /* optional callback to check key to determine if TPM should be used */
        if (tlsCtx->checkKeyCb) {
            /* this is useful to check the provided key for dummy key
                cases like TLS server */
            if (tlsCtx->checkKeyCb(info, tlsCtx) != 0) {
                isWolfKeyValid = 0;
            #ifdef DEBUG_WOLFTPM
                printf("CryptoDevCb: Detected dummy key\n");
            #endif
            }
        }
    #ifndef NO_RSA
        /* RSA */
        if (info->pk.type == WC_PK_TYPE_RSA_KEYGEN) {
            /* TODO: Add crypto callback RSA keygen support */
            #if 0
            RsaKey* key;
            int     size;
            long    e;
            WC_RNG* rng;
            #endif
            rc = exit_rc;
        }
        else if (info->pk.type == WC_PK_TYPE_RSA) {
            switch (info->pk.rsa.type) {
                case RSA_PUBLIC_ENCRYPT:
                case RSA_PUBLIC_DECRYPT:
                {
                    /* public operations */
                    WOLFTPM2_KEY rsaPub;

                    if (!isWolfKeyValid && tlsCtx->rsaKey) {
                        /* use already loaded TPM handle for operation */
                        rc = wolfTPM2_RsaEncrypt(tlsCtx->dev, tlsCtx->rsaKey,
                            TPM_ALG_NULL, /* no padding */
                            info->pk.rsa.in, info->pk.rsa.inLen,
                            info->pk.rsa.out, (int*)info->pk.rsa.outLen);
                        break;
                    }
                    /* otherwise load public key and perform public op */

                    /* load public key into TPM */
                    XMEMSET(&rsaPub, 0, sizeof(rsaPub));
                    rc = wolfTPM2_RsaKey_WolfToTpm(tlsCtx->dev,
                        info->pk.rsa.key, &rsaPub);
                    if (rc != 0) {
                        /* A failure of TPM_RC_KEY can happen due to unsupported
                            RSA exponents. In those cases return NOT_COMPILED_IN
                            and use software */
                        rc = exit_rc;
                        break;
                    }

                    /* public operations */
                    rc = wolfTPM2_RsaEncrypt(tlsCtx->dev, &rsaPub,
                        TPM_ALG_NULL, /* no padding */
                        info->pk.rsa.in, info->pk.rsa.inLen,
                        info->pk.rsa.out, (int*)info->pk.rsa.outLen);

                    wolfTPM2_UnloadHandle(tlsCtx->dev, &rsaPub.handle);
                    break;
                }
                case RSA_PRIVATE_ENCRYPT:
                case RSA_PRIVATE_DECRYPT:
                {
                    /* private operations */
                    rc = wolfTPM2_RsaDecrypt(tlsCtx->dev, tlsCtx->rsaKey,
                        TPM_ALG_NULL, /* no padding */
                        info->pk.rsa.in, info->pk.rsa.inLen,
                        info->pk.rsa.out, (int*)info->pk.rsa.outLen);
                    break;
                }
            }
        }
    #endif /* !NO_RSA */
    #ifdef HAVE_ECC
        if (info->pk.type == WC_PK_TYPE_EC_KEYGEN) {
        #ifdef WOLFTPM2_USE_SW_ECDHE
            rc = exit_rc;
        #else
            int curve_id;

            /* Make sure an ECDH key has been set and curve is supported */
            rc = TPM2_GetTpmCurve(info->pk.eckg.curveId);
            if (rc < 0 || tlsCtx->ecdhKey == NULL || tlsCtx->eccKey == NULL) {
                return exit_rc;
            }
            curve_id = rc;

            /* Generate ephemeral key */
            rc = wolfTPM2_ECDHGenKey(tlsCtx->dev, tlsCtx->ecdhKey, curve_id,
                (byte*)tlsCtx->eccKey->handle.auth.buffer,
                tlsCtx->eccKey->handle.auth.size);
            if (rc == 0) {
                /* Export public key info to wolf ecc_key */
                rc = wolfTPM2_EccKey_TpmToWolf(tlsCtx->dev, tlsCtx->ecdhKey,
                    info->pk.eckg.key);
                if (rc != 0) {
                    /* if failure, release key */
                    wolfTPM2_UnloadHandle(tlsCtx->dev, &tlsCtx->ecdhKey->handle);
                }
            }
            else if (rc & TPM_RC_CURVE) {
                /* if the curve is not supported on TPM, then fall-back to software */
                rc = exit_rc;
                /* Make sure ECDHE key indicates nothing loaded */
                tlsCtx->ecdhKey->handle.hndl = TPM_RH_NULL;
            }
        #endif /* WOLFTPM2_USE_SW_ECDHE */
        }
        else if (info->pk.type == WC_PK_TYPE_ECDSA_SIGN) {
            byte sigRS[MAX_ECC_BYTES*2];
            byte *r = sigRS, *s;
            word32 rsLen = sizeof(sigRS), rLen, sLen;
            word32 inlen = info->pk.eccsign.inlen;

            /* truncate input to match key size */
            rLen = wc_ecc_size(info->pk.eccsign.key);
            if (inlen > rLen)
                inlen = rLen;

            rc = wolfTPM2_SignHash(tlsCtx->dev, tlsCtx->eccKey,
                info->pk.eccsign.in, inlen, sigRS, (int*)&rsLen);
            if (rc == 0) {
                /* Encode ECDSA Header */
                rLen = sLen = rsLen / 2;
                s = &sigRS[rLen];
                rc = wc_ecc_rs_raw_to_sig(r, rLen, s, sLen,
                    info->pk.eccsign.out, info->pk.eccsign.outlen);
            }
        }
        else if (info->pk.type == WC_PK_TYPE_ECDSA_VERIFY) {
            WOLFTPM2_KEY eccPub;
            byte sigRS[MAX_ECC_BYTES*2];
            byte *r = sigRS, *s = &sigRS[MAX_ECC_BYTES];
            word32 rLen = MAX_ECC_BYTES, sLen = MAX_ECC_BYTES;
            XMEMSET(&eccPub, 0, sizeof(eccPub));

            /* Decode ECDSA Header */
            rc = wc_ecc_sig_to_rs(info->pk.eccverify.sig,
                info->pk.eccverify.siglen, r, &rLen, s, &sLen);
            if (rc == 0) {
                /* load public key into TPM */
                rc = wolfTPM2_EccKey_WolfToTpm(tlsCtx->dev,
                    info->pk.eccverify.key, &eccPub);
                if (rc == 0) {
                    /* combine R and S */
                    XMEMCPY(sigRS + rLen, s, sLen);
                    rc = wolfTPM2_VerifyHash(tlsCtx->dev, &eccPub,
                        sigRS, rLen + sLen,
                        info->pk.eccverify.hash, info->pk.eccverify.hashlen);

                    if (rc == 0 && info->pk.eccverify.res) {
                        *info->pk.eccverify.res = 1;
                    }

                    wolfTPM2_UnloadHandle(tlsCtx->dev, &eccPub.handle);
                }
                else if (rc & TPM_RC_CURVE) {
                    /* if the curve is not supported on TPM, then fall-back to software */
                    rc = exit_rc;
                }
            }
        }
        else if (info->pk.type == WC_PK_TYPE_ECDH) {
        #ifdef WOLFTPM2_USE_SW_ECDHE
            rc = exit_rc;
        #else
            TPM2B_ECC_POINT pubPoint;

            /* Make sure an ECDH key has been set */
            if (tlsCtx->ecdhKey == NULL || tlsCtx->eccKey == NULL ||
            		tlsCtx->ecdhKey->handle.hndl == TPM_RH_NULL) {
                return exit_rc;
            }

            rc = wolfTPM2_EccKey_WolfToPubPoint(tlsCtx->dev,
                info->pk.ecdh.public_key, &pubPoint);
            if (rc == 0) {
                /* Compute shared secret and compare results */
                rc = wolfTPM2_ECDHGenZ(tlsCtx->dev, tlsCtx->ecdhKey,
                    &pubPoint, info->pk.ecdh.out, (int*)info->pk.ecdh.outlen);
            }

            /* done with ephemeral key */
            wolfTPM2_UnloadHandle(tlsCtx->dev, &tlsCtx->ecdhKey->handle);
        #endif /* !WOLFTPM2_USE_SW_ECDHE */
        }
    #endif /* HAVE_ECC */
        (void)isWolfKeyValid;
    }
#endif /* !NO_RSA || HAVE_ECC */
#ifndef NO_AES
    else if (info->algo_type == WC_ALGO_TYPE_CIPHER) {
    #ifdef DEBUG_WOLFTPM
        printf("CryptoDevCb Cipher: Type %d\n", info->cipher.type);
    #endif
        if (info->cipher.type != WC_CIPHER_AES_CBC) {
            return exit_rc;
        }

    #ifdef WOLFTPM_USE_SYMMETRIC
        if (info->cipher.aescbc.aes) {
            WOLFTPM2_KEY symKey;
            Aes* aes = info->cipher.aescbc.aes;

            if (aes == NULL) {
                return BAD_FUNC_ARG;
            }

            if (!tlsCtx->useSymmetricOnTPM) {
                return exit_rc;
            }

            /* load key */
            XMEMSET(&symKey, 0, sizeof(symKey));
            rc = wolfTPM2_LoadSymmetricKey(tlsCtx->dev, &symKey,
                TPM_ALG_CBC, (byte*)aes->devKey, aes->keylen);
            if (rc == 0) {
                /* perform symmetric encrypt/decrypt */
                rc = wolfTPM2_EncryptDecrypt(tlsCtx->dev, &symKey,
                    info->cipher.aescbc.in,
                    info->cipher.aescbc.out,
                    info->cipher.aescbc.sz,
                    (byte*)aes->reg, MAX_AES_BLOCK_SIZE_BYTES,
                    info->cipher.enc ? WOLFTPM2_ENCRYPT : WOLFTPM2_DECRYPT);

                /* done with handle */
                wolfTPM2_UnloadHandle(tlsCtx->dev, &symKey.handle);
            }
        }
    #endif /* WOLFTPM_USE_SYMMETRIC */
    }
#endif /* !NO_AES */
#if !defined(NO_SHA) || !defined(NO_SHA256)
    else if (info->algo_type == WC_ALGO_TYPE_HASH) {
    #ifdef WOLFTPM_USE_SYMMETRIC
        WOLFTPM2_HASH hash;
        WOLFTPM2_HASHCTX* hashCtx = NULL;
        TPM_ALG_ID hashAlg = TPM_ALG_ERROR;
        word32 hashFlags = 0;
    #endif

    #ifdef DEBUG_WOLFTPM
        printf("CryptoDevCb Hash: Type %d\n", info->hash.type);
    #endif
        if (info->hash.type != WC_HASH_TYPE_SHA &&
            info->hash.type != WC_HASH_TYPE_SHA256) {
            return exit_rc;
        }

    #ifdef WOLFTPM_USE_SYMMETRIC
        if (!tlsCtx->useSymmetricOnTPM) {
            return exit_rc;
        }

    #ifndef NO_SHA
        if (info->hash.type == WC_HASH_TYPE_SHA) {
            hashAlg = TPM_ALG_SHA1;
            if (info->hash.sha1) {
                hashCtx = (WOLFTPM2_HASHCTX*)info->hash.sha1->devCtx;
                hashFlags = info->hash.sha1->flags;
            }
        }
    #endif
    #ifndef NO_SHA256
        if (info->hash.type == WC_HASH_TYPE_SHA256) {
            hashAlg = TPM_ALG_SHA256;
            if (info->hash.sha256) {
                hashCtx = (WOLFTPM2_HASHCTX*)info->hash.sha256->devCtx;
                hashFlags = info->hash.sha256->flags;
            }
        }
    #endif
        if (hashAlg == TPM_ALG_ERROR) {
            return exit_rc;
        }

        XMEMSET(&hash, 0, sizeof(hash));
        if (hashCtx)
            hash.handle.hndl = hashCtx->handle;

        if (info->hash.in != NULL) { /* Update */
            rc = 0;
            /* If not single shot (update and final) then allocate context */
            if (hashCtx == NULL && info->hash.digest == NULL) {
                hashCtx = (WOLFTPM2_HASHCTX*)XMALLOC(sizeof(*hashCtx), NULL,
                    DYNAMIC_TYPE_TMP_BUFFER);
                if (hashCtx == NULL) {
                    return MEMORY_E;
                }
                XMEMSET(hashCtx, 0, sizeof(*hashCtx));
            }
            if (rc == 0) {
                if (hashCtx && (hashFlags & WC_HASH_FLAG_WILLCOPY)) {
                    rc = wolfTPM2_HashUpdateCache(hashCtx,
                        info->hash.in, info->hash.inSz);
                }
                else {
                    if (hash.handle.hndl == 0) {
                        rc = wolfTPM2_HashStart(tlsCtx->dev, &hash, hashAlg,
                            NULL, 0);
                        if (rc == 0) {
                            /* save new handle to hash context */
                            if (hashCtx)
                                hashCtx->handle = hash.handle.hndl;
                        }
                    }
                    if (rc == 0) {
                        rc = wolfTPM2_HashUpdate(tlsCtx->dev, &hash,
                            info->hash.in, info->hash.inSz);
                    }
                }
            }
        }
        if (info->hash.digest != NULL) { /* Final */
            word32 digestSz = TPM2_GetHashDigestSize(hashAlg);
            if (hashCtx && (hashFlags & WC_HASH_FLAG_WILLCOPY)) {
                if (hash.handle.hndl == 0) {
                    rc = wolfTPM2_HashStart(tlsCtx->dev, &hash, hashAlg,
                        NULL, 0);
                    if (rc == 0) {
                        /* save new handle to hash context */
                        if (hashCtx)
                            hashCtx->handle = hash.handle.hndl;
                    }
                }
                if (rc == 0) {
                    rc = wolfTPM2_HashUpdate(tlsCtx->dev, &hash,
                            hashCtx->cacheBuf, hashCtx->cacheSz);
                }
            }
            if (rc == 0) {
                rc = wolfTPM2_HashFinish(tlsCtx->dev, &hash, info->hash.digest,
                    &digestSz);
            }
        }
        /* if final or failure cleanup */
        if (info->hash.digest != NULL || rc != 0) {
            if (hashCtx) {
                hashCtx->handle = 0; /* clear hash handle */
                if ((hashFlags & WC_HASH_FLAG_ISCOPY) == 0) {
                    if (hashCtx->cacheBuf) {
                        XFREE(hashCtx->cacheBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                        hashCtx->cacheBuf = NULL;
                    }
                    XFREE(hashCtx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                }
                hashCtx = NULL;
            }
            /* Make sure hash if free'd in case of failure */
            wolfTPM2_UnloadHandle(tlsCtx->dev, &hash.handle);
        }

        /* save hashCtx to hash structure */
    #ifndef NO_SHA
        if (info->hash.type == WC_HASH_TYPE_SHA && info->hash.sha1)
            info->hash.sha1->devCtx = hashCtx;
    #endif
    #ifndef NO_SHA256
        if (info->hash.type == WC_HASH_TYPE_SHA256 && info->hash.sha256)
            info->hash.sha256->devCtx = hashCtx;
    #endif
    #endif /* WOLFTPM_USE_SYMMETRIC */
    }
#endif /* !NO_SHA || !NO_SHA256 */
#ifndef NO_HMAC
    else if (info->algo_type == WC_ALGO_TYPE_HMAC) {
    #ifdef WOLFTPM_USE_SYMMETRIC
        WOLFTPM2_HMAC* hmacCtx;
        TPM_ALG_ID hashAlg = TPM_ALG_ERROR;
    #endif

    #ifdef DEBUG_WOLFTPM
        printf("CryptoDevCb HMAC: Type %d\n", info->hmac.macType);
    #endif
        if (info->hmac.macType != WC_HASH_TYPE_SHA &&
            info->hmac.macType != WC_HASH_TYPE_SHA256) {
            return exit_rc;
        }
        if (info->hmac.hmac == NULL) {
            /* make sure HMAC context exists */
            return exit_rc;
        }

    #ifdef WOLFTPM_USE_SYMMETRIC
        if (!tlsCtx->useSymmetricOnTPM) {
            return exit_rc;
        }

    #ifndef NO_SHA
        if (info->hmac.macType == WC_HASH_TYPE_SHA) {
            hashAlg = TPM_ALG_SHA1;
        }
    #endif
    #ifndef NO_SHA256
        if (info->hmac.macType == WC_HASH_TYPE_SHA256) {
            hashAlg = TPM_ALG_SHA256;
        }
    #endif
        if (hashAlg == TPM_ALG_ERROR) {
            return exit_rc;
        }

        hmacCtx = (WOLFTPM2_HMAC*)info->hmac.hmac->devCtx;
        if (hmacCtx && hmacCtx->hash.handle.hndl == 0) {
        #ifdef DEBUG_WOLFTPM
            printf("Error: HMAC context invalid!\n");
            return BAD_FUNC_ARG;
        #endif
        }

        if (info->hmac.in != NULL) { /* Update */
            rc = 0;
            if (hmacCtx == NULL) {
                const byte* keyBuf = info->hmac.hmac->keyRaw;
                word32 keySz = info->hmac.hmac->keyLen;

                hmacCtx = (WOLFTPM2_HMAC*)XMALLOC(sizeof(*hmacCtx), NULL,
                    DYNAMIC_TYPE_TMP_BUFFER);
                if (hmacCtx == NULL) {
                    return MEMORY_E;
                }
                XMEMSET(hmacCtx, 0, sizeof(*hmacCtx));

                rc = wolfTPM2_HmacStart(tlsCtx->dev, hmacCtx,
                    tlsCtx->storageKey ? &tlsCtx->storageKey->handle : NULL,
                    hashAlg, keyBuf, keySz, NULL, 0);
            }
            if (rc == 0) {
                rc = wolfTPM2_HmacUpdate(tlsCtx->dev, hmacCtx,
                    info->hmac.in, info->hmac.inSz);
            }
        }
        if (info->hmac.digest != NULL) { /* Final */
            word32 digestSz = TPM2_GetHashDigestSize(hashAlg);
            rc = wolfTPM2_HmacFinish(tlsCtx->dev, hmacCtx, info->hmac.digest,
                &digestSz);
        }

        /* clean hmac context */
        if (rc != 0 || info->hmac.digest != NULL) {
            wolfTPM2_UnloadHandle(tlsCtx->dev, &hmacCtx->hash.handle);
            wolfTPM2_UnloadHandle(tlsCtx->dev, &hmacCtx->key.handle);
            XFREE(hmacCtx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            hmacCtx = NULL;
        }
        info->hmac.hmac->devCtx = hmacCtx;
    #endif /* WOLFTPM_USE_SYMMETRIC */
    }
#endif /* !NO_HMAC */

    /* need to return negative here for error */
    if (rc != TPM_RC_SUCCESS && rc != exit_rc) {
    #ifdef DEBUG_WOLFTPM
        printf("wolfTPM2_CryptoDevCb failed rc = %d\n", rc);
    #endif
        rc = WC_HW_E;
    }

    return rc;
}

int wolfTPM2_SetCryptoDevCb(WOLFTPM2_DEV* dev, CryptoDevCallbackFunc cb,
    TpmCryptoDevCtx* tpmCtx, int* pDevId)
{
    int rc;
    int devId = INVALID_DEVID;

    if (dev == NULL || cb == NULL || tpmCtx == NULL) {
        return BAD_FUNC_ARG;
    }

    /* register a crypto device callback for TPM private key */
    rc = wolfTPM2_GetTpmDevId(dev);
    if (rc >= 0) {
        devId = rc;
        tpmCtx->dev = dev;

        rc = wc_CryptoDev_RegisterDevice(devId, cb, tpmCtx);
    }

    if (pDevId) {
        *pDevId = devId;
    }

    return rc;
}

int wolfTPM2_ClearCryptoDevCb(WOLFTPM2_DEV* dev, int devId)
{
    int rc = 0;

    if (dev == NULL) {
        return BAD_FUNC_ARG;
    }

    /* get device Id */
    if (devId == INVALID_DEVID) {
        rc = wolfTPM2_GetTpmDevId(dev);
        if (rc >= 0) {
            devId = rc;
            rc = 0;
        }
    }
    if (devId != INVALID_DEVID) {
        wc_CryptoCb_UnRegisterDevice(devId);
    }

    return rc;
}

/******************************************************************************/
/* --- END wolf Crypto Device Support -- */
/******************************************************************************/

#endif /* !WOLFTPM2_NO_WOLFCRYPT && (WOLF_CRYPTO_DEV || WOLF_CRYPTO_CB) */


#endif /* !WOLFTPM2_NO_WRAPPER */
