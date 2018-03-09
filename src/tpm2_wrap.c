/* tpm2_wrap.c
 *
 * Copyright (C) 2006-2018 wolfSSL Inc.
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

#ifndef WOLFTPM2_NO_WRAPPER


/* Defines the default digest algo type to use for the wrapper functions */
#ifndef WOLFTPM2_WRAP_DIGEST
    #define WOLFTPM2_WRAP_DIGEST TPM_ALG_SHA256
#endif
/* Defines the default RSA key bits for the wrapper functions */
#ifndef WOLFTPM2_WRAP_RSA_KEY_BITS
    #define WOLFTPM2_WRAP_RSA_KEY_BITS MAX_RSA_KEY_BITS
#endif


/******************************************************************************/
/* --- BEGIN Wrapper Device Functions -- */
/******************************************************************************/

int wolfTPM2_Init(WOLFTPM2_DEV* dev, TPM2HalIoCb ioCb, void* userCtx)
{
    int rc;
    Startup_In startupIn;

    if (dev == NULL)
        return BAD_FUNC_ARG;

    rc = TPM2_Init(&dev->ctx, ioCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_Init failed %d: %s\n", rc, wolfTPM2_GetRCString(rc));
        return rc;
    }

#ifdef DEBUG_WOLFTPM
    printf("TPM2: Caps 0x%08x, Did 0x%04x, Vid 0x%04x, Rid 0x%2x \n",
        dev->ctx.caps,
        dev->ctx.did_vid >> 16,
        dev->ctx.did_vid & 0xFFFF,
        dev->ctx.rid);
#endif

    /* define the default session auth */
    XMEMSET(dev->session, 0, sizeof(dev->session));
    dev->session[0].sessionHandle = TPM_RS_PW; /* default */
    TPM2_SetSessionAuth(dev->session);

    XMEMSET(&startupIn, 0, sizeof(Startup_In));
    startupIn.startupType = TPM_SU_CLEAR;
    rc = TPM2_Startup(&startupIn);
    if (rc != TPM_RC_SUCCESS &&
        rc != TPM_RC_INITIALIZE /* TPM_RC_INITIALIZE = Already started */ ) {
        printf("TPM2_Startup failed %d: %s\n", rc, wolfTPM2_GetRCString(rc));
        return rc;
    }
#ifdef DEBUG_WOLFTPM
    printf("TPM2_Startup pass\n");
#endif

    return TPM_RC_SUCCESS;
}

int wolfTPM2_Cleanup(WOLFTPM2_DEV* dev)
{
    int rc;
    Shutdown_In shutdownIn;

    if (dev == NULL)
        return BAD_FUNC_ARG;

    shutdownIn.shutdownType = TPM_SU_CLEAR;
    rc = TPM2_Shutdown(&shutdownIn);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_Shutdown failed %d: %s\n", rc, wolfTPM2_GetRCString(rc));
        return rc;
    }

    TPM2_Cleanup(&dev->ctx);

    return rc;
}


int wolfTPM2_StartSession(WOLFTPM2_DEV* dev, WOLFTPM2_SESSION* session,
    WOLFTPM2_KEY* tpmKey, WOLFTPM2_HANDLE* bind, TPM_SE sesType,
    int useEncrypDecrypt)
{
    int rc;
    StartAuthSession_In  authSesIn;
    StartAuthSession_Out authSesOut;

    if (dev == NULL || session == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(&authSesIn, 0, sizeof(authSesIn));
    authSesIn.tpmKey = tpmKey ? tpmKey->handle.hndl : TPM_RH_NULL;
    authSesIn.bind =     bind ? bind->hndl          : TPM_RH_NULL;
    authSesIn.sessionType = sesType;
    if (useEncrypDecrypt) {
        authSesIn.symmetric.algorithm = TPM_ALG_AES;
        authSesIn.symmetric.keyBits.aes = 128;
        authSesIn.symmetric.mode.aes = TPM_ALG_CFB;
    }
    else {
        authSesIn.symmetric.algorithm = TPM_ALG_NULL;
    }
    authSesIn.authHash = WOLFTPM2_WRAP_DIGEST;
    authSesIn.nonceCaller.size = TPM2_GetHashDigestSize(WOLFTPM2_WRAP_DIGEST);
    rc = TPM2_GetNonce(authSesIn.nonceCaller.buffer,
                       authSesIn.nonceCaller.size);
    if (rc < 0) {
        printf("TPM2_GetNonce failed %d: %s\n", rc, wolfTPM2_GetRCString(rc));
        return rc;
    }
    rc = TPM2_StartAuthSession(&authSesIn, &authSesOut);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_StartAuthSession failed %d: %s\n", rc, wolfTPM2_GetRCString(rc));
        return rc;
    }

    session->handle.hndl = authSesOut.sessionHandle;
    session->nonceTPM = authSesOut.nonceTPM;

#ifdef DEBUG_WOLFTPM
    printf("TPM2_StartAuthSession: handle 0x%x\n", session->handle.hndl);
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

    /* clear output key buffer */
    XMEMSET(key, 0, sizeof(WOLFTPM2_KEY));

    XMEMSET(&createPriIn, 0, sizeof(createPriIn));
    createPriIn.primaryHandle = primaryHandle; /* TPM_RH_OWNER, TPM_RH_ENDORSEMENT or TPM_RH_PLATFORM */
    if (auth && authSz > 0) {
        createPriIn.inSensitive.sensitive.userAuth.size = authSz;
        XMEMCPY(createPriIn.inSensitive.sensitive.userAuth.buffer,
            auth, createPriIn.inSensitive.sensitive.userAuth.size);
    }
    XMEMCPY(&createPriIn.inPublic.publicArea, publicTemplate, sizeof(TPMT_PUBLIC));
    rc = TPM2_CreatePrimary(&createPriIn, &createPriOut);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_CreatePrimary: failed %d: %s\n", rc,
            wolfTPM2_GetRCString(rc));
        return rc;
    }
    key->handle.hndl = createPriOut.objectHandle;
    key->handle.auth = createPriIn.inSensitive.sensitive.userAuth;

    key->public = createPriOut.outPublic;
    key->name = createPriOut.name;

#ifdef DEBUG_WOLFTPM
    printf("TPM2_CreatePrimary: 0x%x (%d bytes)\n",
        key->handle.hndl, key->public.size);
#endif

    return rc;
}

int wolfTPM2_CreateAndLoadKey(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    WOLFTPM2_HANDLE* parent, TPMT_PUBLIC* publicTemplate,
    const byte* auth, int authSz)
{
    int rc;
    Create_In  createIn;
    Create_Out createOut;
    Load_In  loadIn;
    Load_Out loadOut;

    if (dev == NULL || key == NULL || parent == NULL || publicTemplate == NULL)
        return BAD_FUNC_ARG;

    /* clear output key buffer */
    XMEMSET(key, 0, sizeof(WOLFTPM2_KEY));

    /* set session auth for key */
    dev->session[0].auth = parent->auth;

    XMEMSET(&createIn, 0, sizeof(createIn));
    createIn.parentHandle = parent->hndl;
    if (auth) {
        createIn.inSensitive.sensitive.userAuth.size = authSz;
        XMEMCPY(createIn.inSensitive.sensitive.userAuth.buffer, auth,
            createIn.inSensitive.sensitive.userAuth.size);
    }
    XMEMCPY(&createIn.inPublic.publicArea, publicTemplate, sizeof(TPMT_PUBLIC));

    //createIn.outsideInfo.size = createNoneSz;
    //XMEMCPY(createIn.outsideInfo.buffer, createNonce, createIn.outsideInfo.size);

    rc = TPM2_Create(&createIn, &createOut);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_Create key failed %d: %s\n", rc, wolfTPM2_GetRCString(rc));
        return rc;
    }

#ifdef DEBUG_WOLFTPM
    printf("TPM2_Create key: pub %d, priv %d\n", createOut.outPublic.size,
        createOut.outPrivate.size);
#endif
    key->public = createOut.outPublic;
    key->private = createOut.outPrivate;

    /* Load new key */
    XMEMSET(&loadIn, 0, sizeof(loadIn));
    loadIn.parentHandle = parent->hndl;
    loadIn.inPrivate = key->private;
    loadIn.inPublic = key->public;
    rc = TPM2_Load(&loadIn, &loadOut);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_Load key failed %d: %s\n", rc, wolfTPM2_GetRCString(rc));
        return rc;
    }
    key->handle.hndl = loadOut.objectHandle;
    key->handle.auth = createIn.inSensitive.sensitive.userAuth;

#ifdef DEBUG_WOLFTPM
    printf("TPM2_Load Key Handle 0x%x\n", key->handle.hndl);
#endif

    return rc;
}

int wolfTPM2_LoadPublicKey(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    const TPM2B_PUBLIC* public)
{
    int rc;
    LoadExternal_In  loadExtIn;
    LoadExternal_Out loadExtOut;

    if (dev == NULL || key == NULL || public == NULL)
        return BAD_FUNC_ARG;

    /* Loading public key */
    XMEMSET(&loadExtIn, 0, sizeof(loadExtIn));
    loadExtIn.inPublic = *public;
    loadExtIn.hierarchy = TPM_RH_NULL;
    rc = TPM2_LoadExternal(&loadExtIn, &loadExtOut);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_LoadExternal: failed %d: %s\n", rc, wolfTPM2_GetRCString(rc));
        return rc;
    }
    key->handle.hndl = loadExtOut.objectHandle;
    key->public = loadExtIn.inPublic;

#ifdef DEBUG_WOLFTPM
    printf("TPM2_LoadExternal: 0x%x\n", loadExtOut.objectHandle);
#endif

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
        printf("TPM2_ReadPublic failed %d: %s\n", rc, wolfTPM2_GetRCString(rc));
        return rc;
    }

    key->handle.hndl = readPubIn.objectHandle;
    key->public = readPubOut.outPublic;

#ifdef DEBUG_WOLFTPM
    printf("TPM2_ReadPublic Handle 0x%x: pub %d, name %d, qualifiedName %d\n",
        readPubIn.objectHandle,
        readPubOut.outPublic.size, readPubOut.name.size,
        readPubOut.qualifiedName.size);
#endif

    return rc;
}


int wolfTPM2_SignHash(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    const byte* digest, int digestSz, byte* sig, int* sigSz)
{
    int rc;
    Sign_In  signIn;
    Sign_Out signOut;
    int curveSize;

    if (dev == NULL || key == NULL || digest == NULL || sig == NULL ||
                                                            sigSz == NULL) {
        return BAD_FUNC_ARG;
    }

    /* get curve size */
    curveSize = wolfTPM2_GetCurveSize(
        key->public.publicArea.parameters.eccDetail.curveID);
    if (curveSize <= 0 || *sigSz < (curveSize * 2)) {
        return BAD_FUNC_ARG;
    }

    /* set session auth for key */
    dev->session[0].auth = key->handle.auth;
    dev->session[0].symmetric = key->public.publicArea.parameters.eccDetail.symmetric;

    /* Sign with ECC key */
    XMEMSET(&signIn, 0, sizeof(signIn));
    signIn.keyHandle = key->handle.hndl;
    signIn.digest.size = digestSz;
    XMEMCPY(signIn.digest.buffer, digest, signIn.digest.size);
    signIn.inScheme.scheme = TPM_ALG_ECDSA;
    signIn.inScheme.details.ecdsa.hashAlg = WOLFTPM2_WRAP_DIGEST;
    signIn.validation.tag = TPM_ST_HASHCHECK;
    signIn.validation.hierarchy = TPM_RH_NULL;
    rc = TPM2_Sign(&signIn, &signOut);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_Sign failed %d: %s\n", rc, wolfTPM2_GetRCString(rc));
        return rc;
    }

    /* Assemble R and S into signature (R then S) */
    *sigSz = signOut.signature.signature.ecdsa.signatureR.size +
             signOut.signature.signature.ecdsa.signatureS.size;
    XMEMCPY(sig, signOut.signature.signature.ecdsa.signatureR.buffer,
        signOut.signature.signature.ecdsa.signatureR.size);
    XMEMCPY(sig + signOut.signature.signature.ecdsa.signatureR.size,
        signOut.signature.signature.ecdsa.signatureS.buffer,
        signOut.signature.signature.ecdsa.signatureS.size);

#ifdef DEBUG_WOLFTPM
    printf("TPM2_Sign: ECC R %d, S %d\n",
        signOut.signature.signature.ecdsa.signatureR.size,
        signOut.signature.signature.ecdsa.signatureS.size);
#endif

    return rc;
}

int wolfTPM2_VerifyHash(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    const byte* sig, int sigSz, const byte* digest, int digestSz)
{
    int rc;
    VerifySignature_In  verifySigIn;
    VerifySignature_Out verifySigOut;
    int curveSize;

    if (dev == NULL || key == NULL || digest == NULL || sig == NULL) {
        return BAD_FUNC_ARG;
    }

    /* get curve size */
    curveSize = wolfTPM2_GetCurveSize(
        key->public.publicArea.parameters.eccDetail.curveID);
    if (curveSize <= 0 || sigSz < (curveSize * 2)) {
        return BAD_FUNC_ARG;
    }

    /* set session auth for key */
    dev->session[0].auth = key->handle.auth;
    dev->session[0].symmetric = key->public.publicArea.parameters.eccDetail.symmetric;

    XMEMSET(&verifySigIn, 0, sizeof(verifySigIn));
    verifySigIn.keyHandle = key->handle.hndl;
    verifySigIn.digest.size = digestSz;
    XMEMCPY(verifySigIn.digest.buffer, digest, digestSz);
    verifySigIn.signature.sigAlgo =
        key->public.publicArea.parameters.eccDetail.scheme.scheme;
    verifySigIn.signature.signature.ecdsa.hash = WOLFTPM2_WRAP_DIGEST;

    /* Signature is R then S */
    verifySigIn.signature.signature.ecdsa.signatureR.size = curveSize;
    XMEMCPY(verifySigIn.signature.signature.ecdsa.signatureR.buffer,
        sig, curveSize);
    verifySigIn.signature.signature.ecdsa.signatureS.size = curveSize;
    XMEMCPY(verifySigIn.signature.signature.ecdsa.signatureS.buffer,
        sig + curveSize, curveSize);

    rc = TPM2_VerifySignature(&verifySigIn, &verifySigOut);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_VerifySignature failed %d: %s\n", rc, wolfTPM2_GetRCString(rc));
        return rc;
    }
#ifdef DEBUG_WOLFTPM
    printf("TPM2_VerifySignature: Tag %d\n", verifySigOut.validation.tag);
#endif

    return rc;
}

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

    /* get curve size */
    curveSize = wolfTPM2_GetCurveSize(
        privKey->public.publicArea.parameters.eccDetail.curveID);
    if (curveSize <= 0 || *outSz < curveSize) {
        return BAD_FUNC_ARG;
    }

    /* set session auth for key */
    dev->session[0].auth = privKey->handle.auth;
    dev->session[0].symmetric = privKey->public.publicArea.parameters.eccDetail.symmetric;

    XMEMSET(&ecdhIn, 0, sizeof(ecdhIn));
    ecdhIn.keyHandle = privKey->handle.hndl;
    rc = TPM2_ECDH_KeyGen(&ecdhIn, &ecdhOut);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_ECDH_KeyGen failed %d: %s\n", rc, wolfTPM2_GetRCString(rc));
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


int wolfTPM2_RsaEncrypt(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key, TPM_ALG_ID padScheme,
    const byte* msg, int msgSz, byte* out, int* outSz)
{
    int rc;
    RSA_Encrypt_In  rsaEncIn;
    RSA_Encrypt_Out rsaEncOut;

    if (dev == NULL || key == NULL || msg == NULL || out == NULL || outSz == NULL)
        return BAD_FUNC_ARG;

    /* set session auth for key */
    dev->session[0].auth = key->handle.auth;
    dev->session[0].symmetric = key->public.publicArea.parameters.rsaDetail.symmetric;

    /* RSA Encrypt */
    XMEMSET(&rsaEncIn, 0, sizeof(rsaEncIn));
    rsaEncIn.keyHandle = key->handle.hndl;
    rsaEncIn.message.size = msgSz;
    XMEMCPY(rsaEncIn.message.buffer, msg, msgSz);
    rsaEncIn.inScheme.scheme = padScheme; /* TPM_ALG_OAEP or TPM_ALG_RSAPSS */
    rsaEncIn.inScheme.details.oaep.hashAlg = WOLFTPM2_WRAP_DIGEST;
    //rsaEncIn.label.size = sizeof(label); /* Null term required */
    //XMEMCPY(rsaEncIn.label.buffer, label, rsaEncIn.label.size);

    rc = TPM2_RSA_Encrypt(&rsaEncIn, &rsaEncOut);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_RSA_Encrypt failed %d: %s\n", rc, wolfTPM2_GetRCString(rc));
        return rc;
    }

    *outSz = rsaEncOut.outData.size;
    XMEMCPY(out, rsaEncOut.outData.buffer, *outSz);

#ifdef DEBUG_WOLFTPM
    printf("TPM2_RSA_Encrypt: %d\n", rsaEncOut.outData.size);
#endif

    return rc;
}

int wolfTPM2_RsaDecrypt(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key, TPM_ALG_ID padScheme,
    const byte* in, int inSz, byte* msg, int* msgSz)
{
    int rc;
    RSA_Decrypt_In  rsaDecIn;
    RSA_Decrypt_Out rsaDecOut;

    if (dev == NULL || key == NULL || in == NULL || msg == NULL || msgSz == NULL)
        return BAD_FUNC_ARG;

    /* set session auth for key */
    dev->session[0].auth = key->handle.auth;
    dev->session[0].symmetric = key->public.publicArea.parameters.rsaDetail.symmetric;

    /* RSA Decrypt */
    XMEMSET(&rsaDecIn, 0, sizeof(rsaDecIn));
    rsaDecIn.keyHandle = key->handle.hndl;
    rsaDecIn.cipherText.size = inSz;
    XMEMCPY(rsaDecIn.cipherText.buffer, in, inSz);
    rsaDecIn.inScheme.scheme = padScheme;
    rsaDecIn.inScheme.details.oaep.hashAlg = WOLFTPM2_WRAP_DIGEST;
    //rsaDecIn.label.size = sizeof(label); /* Null term required */
    //XMEMCPY(rsaDecIn.label.buffer, label, rsaEncIn.label.size);

    rc = TPM2_RSA_Decrypt(&rsaDecIn, &rsaDecOut);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_RSA_Decrypt failed %d: %s\n", rc, wolfTPM2_GetRCString(rc));
        return rc;
    }

    *msgSz = rsaDecOut.message.size;
    XMEMCPY(msg, rsaDecOut.message.buffer, *msgSz);

#ifdef DEBUG_WOLFTPM
    printf("TPM2_RSA_Decrypt: %d\n", rsaDecOut.message.size);
#endif
    return rc;
}


int wolfTPM2_ReadPCR(WOLFTPM2_DEV* dev, int pcrIndex, int alg, byte* digest,
    int* digest_len)
{
    int rc;
    PCR_Read_In  pcrReadIn;
    PCR_Read_Out pcrReadOut;

    if (dev == NULL)
        return BAD_FUNC_ARG;

    wolfTPM2_SetupPCRSel(&pcrReadIn.pcrSelectionIn, alg, pcrIndex);
    rc = TPM2_PCR_Read(&pcrReadIn, &pcrReadOut);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_PCR_Read failed %d: %s\n", rc, wolfTPM2_GetRCString(rc));
        return rc;
    }

    if (digest_len)
        *digest_len = (int)pcrReadOut.pcrValues.digests[0].size;
    if (digest)
        XMEMCPY(digest, pcrReadOut.pcrValues.digests[0].buffer,
            pcrReadOut.pcrValues.digests[0].size);

#ifdef DEBUG_WOLFTPM
    printf("TPM2_PCR_Read: Index %d, Digest Sz %d, Update Counter %d\n",
        pcrIndex, *digest_len, (int)pcrReadOut.pcrUpdateCounter);
    TPM2_PrintBin(digest, *digest_len);
#endif

    return rc;
}

int wolfTPM2_UnloadHandle(WOLFTPM2_DEV* dev, WOLFTPM2_HANDLE* handle)
{
    int rc;
    FlushContext_In flushCtxIn;

    if (dev == NULL || handle == NULL)
        return BAD_FUNC_ARG;

    if (handle->hndl != 0 && handle->hndl != TPM_RH_NULL) {
        flushCtxIn.flushHandle = handle->hndl;
        rc = TPM2_FlushContext(&flushCtxIn);
        if (rc != TPM_RC_SUCCESS) {
            printf("TPM2_FlushContext failed %d: %s\n", rc, wolfTPM2_GetRCString(rc));
            return rc;
        }

    #ifdef DEBUG_WOLFTPM
        printf("TPM2_FlushContext: Closed handle 0x%x\n", handle->hndl);
    #endif

        handle->hndl = TPM_RH_NULL;
    }

    return TPM_RC_SUCCESS;
}

int wolfTPM2_NVReadPublic(WOLFTPM2_DEV* dev, word32 nvIndex)
{
    int rc;
    NV_ReadPublic_In  in;
    NV_ReadPublic_Out out;

    if (dev == NULL)
        return BAD_FUNC_ARG;

    in.nvIndex = nvIndex;
    rc = TPM2_NV_ReadPublic(&in, &out);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_NV_ReadPublic failed %d: %s\n", rc, wolfTPM2_GetRCString(rc));
        return rc;
    }

#ifdef DEBUG_WOLFTPM
    printf("TPM2_NV_ReadPublic: Sz %d, Idx 0x%x, nameAlg %d, Attr 0x%x, authPol %d, dataSz %d, name %d\n",
        out.nvPublic.size,
        out.nvPublic.nvPublic.nvIndex,
        out.nvPublic.nvPublic.nameAlg,
        out.nvPublic.nvPublic.attributes,
        out.nvPublic.nvPublic.authPolicy.size,
        out.nvPublic.nvPublic.dataSize,
        out.nvName.size);
#endif

    return rc;
}

/******************************************************************************/
/* --- END Wrapper Device Functions-- */
/******************************************************************************/


/******************************************************************************/
/* --- BEGIN Utility Functions -- */
/******************************************************************************/

int wolfTPM2_GetKeyTemplate_RSA(TPMT_PUBLIC* publicTemplate,
    TPMA_OBJECT objectAttributes)
{
    if (publicTemplate == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(publicTemplate, 0, sizeof(TPMT_PUBLIC));
    publicTemplate->type = TPM_ALG_RSA;
    publicTemplate->unique.rsa.size = WOLFTPM2_WRAP_RSA_KEY_BITS / 8;
    publicTemplate->nameAlg = WOLFTPM2_WRAP_DIGEST;
    publicTemplate->objectAttributes = objectAttributes;
    publicTemplate->parameters.rsaDetail.keyBits = WOLFTPM2_WRAP_RSA_KEY_BITS;
    publicTemplate->parameters.rsaDetail.exponent = 0;
    publicTemplate->parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
    if (objectAttributes & TPMA_OBJECT_fixedTPM) {
        publicTemplate->parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
        publicTemplate->parameters.rsaDetail.symmetric.keyBits.aes = 128;
        publicTemplate->parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_CFB;
    }
    else {
        publicTemplate->parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
    }

    return 0;
}

int wolfTPM2_GetKeyTemplate_ECC(TPMT_PUBLIC* publicTemplate,
    TPMA_OBJECT objectAttributes, TPM_ECC_CURVE curve, TPM_ALG_ID sigScheme)
{
    if (publicTemplate == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(publicTemplate, 0, sizeof(TPMT_PUBLIC));
    publicTemplate->type = TPM_ALG_ECC;
    publicTemplate->nameAlg = WOLFTPM2_WRAP_DIGEST;
    publicTemplate->objectAttributes = objectAttributes;
    if (objectAttributes & TPMA_OBJECT_fixedTPM) {
        publicTemplate->parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
        publicTemplate->parameters.rsaDetail.symmetric.keyBits.aes = 128;
        publicTemplate->parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_CFB;
    }
    else {
        publicTemplate->parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
    }
    publicTemplate->parameters.eccDetail.scheme.scheme = sigScheme;
                                            /* TPM_ALG_ECDSA or TPM_ALG_ECDH */
    publicTemplate->parameters.eccDetail.scheme.details.ecdsa.hashAlg =
        WOLFTPM2_WRAP_DIGEST;
    publicTemplate->parameters.eccDetail.curveID = curve;
    publicTemplate->parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;

    return 0;
}

const char* wolfTPM2_GetAlgName(TPM_ALG_ID alg)
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

#define TPM_RC_STRINGIFY(rc) #rc
#ifdef DEBUG_WOLFTPM
    #define TPM_RC_STR(rc, desc) case rc: return TPM_RC_STRINGIFY(rc) ": " desc
#else
    #define TPM_RC_STR(rc, desc) case rc: return TPM_RC_STRINGIFY(rc)
#endif

const char* wolfTPM2_GetRCString(int rc)
{
    /* for negative return codes use wolfCrypt */
    if (rc < 0) {
        return wc_GetErrorString(rc);
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

void wolfTPM2_SetupPCRSel(TPML_PCR_SELECTION* pcr, TPM_ALG_ID alg, int pcrIndex)
{
    if (pcr) {
        pcr->count = 1;
        pcr->pcrSelections[0].hash = alg;
        pcr->pcrSelections[0].sizeofSelect = PCR_SELECT_MIN;
        XMEMSET(pcr->pcrSelections[0].pcrSelect, 0, PCR_SELECT_MIN);
        pcr->pcrSelections[0].pcrSelect[pcrIndex >> 3] = (1 << (pcrIndex & 0x7));
    }
}

int wolfTPM2_GetCurveSize(TPM_ECC_CURVE curveID)
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

/******************************************************************************/
/* --- END Utility Functions -- */
/******************************************************************************/

#endif /* !WOLFTPM2_NO_WRAPPER */
