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
    wolfTPM2_SetAuth(dev, 0, TPM_RS_PW, NULL, 0);

    /* startup */
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

int wolfTPM2_SetAuth(WOLFTPM2_DEV* dev, int index,
    TPM_HANDLE sessionHandle, const byte* auth, int authSz)
{
    if (dev == NULL || index >= MAX_SESSION_NUM) {
        return BAD_FUNC_ARG;
    }

    /* define the default session auth */
    dev->session[index].sessionHandle = sessionHandle;
    dev->session[index].auth.size = authSz;
    if (auth && authSz > 0)
        XMEMCPY(dev->session[index].auth.buffer, auth, authSz);

    TPM2_SetSessionAuth(dev->session);

    return 0;
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
        printf("TPM2_StartAuthSession failed %d: %s\n", rc,
            wolfTPM2_GetRCString(rc));
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
    /* TPM_RH_OWNER, TPM_RH_ENDORSEMENT or TPM_RH_PLATFORM */
    createPriIn.primaryHandle = primaryHandle;
    if (auth && authSz > 0) {
        createPriIn.inSensitive.sensitive.userAuth.size = authSz;
        XMEMCPY(createPriIn.inSensitive.sensitive.userAuth.buffer,
            auth, createPriIn.inSensitive.sensitive.userAuth.size);
    }
    XMEMCPY(&createPriIn.inPublic.publicArea, publicTemplate,
        sizeof(TPMT_PUBLIC));
    rc = TPM2_CreatePrimary(&createPriIn, &createPriOut);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_CreatePrimary: failed %d: %s\n", rc,
            wolfTPM2_GetRCString(rc));
        return rc;
    }
    key->handle.hndl = createPriOut.objectHandle;
    key->handle.auth = createPriIn.inSensitive.sensitive.userAuth;

    key->pub = createPriOut.outPublic;
    key->name = createPriOut.name;

#ifdef DEBUG_WOLFTPM
    printf("TPM2_CreatePrimary: 0x%x (%d bytes)\n",
        key->handle.hndl, key->pub.size);
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

#if 0
    /* Optional creation nonce */
    createIn.outsideInfo.size = createNoneSz;
    XMEMCPY(createIn.outsideInfo.buffer, createNonce, createIn.outsideInfo.size);
#endif

    rc = TPM2_Create(&createIn, &createOut);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_Create key failed %d: %s\n", rc, wolfTPM2_GetRCString(rc));
        return rc;
    }

#ifdef DEBUG_WOLFTPM
    printf("TPM2_Create key: pub %d, priv %d\n", createOut.outPublic.size,
        createOut.outPrivate.size);
#endif
    key->pub = createOut.outPublic;
    key->priv = createOut.outPrivate;

    /* Load new key */
    XMEMSET(&loadIn, 0, sizeof(loadIn));
    loadIn.parentHandle = parent->hndl;
    loadIn.inPrivate = key->priv;
    loadIn.inPublic = key->pub;
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
        printf("TPM2_LoadExternal: failed %d: %s\n", rc,
            wolfTPM2_GetRCString(rc));
        return rc;
    }
    key->handle.hndl = loadExtOut.objectHandle;
    key->pub = loadExtIn.inPublic;

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
    key->pub = readPubOut.outPublic;

#ifdef DEBUG_WOLFTPM
    printf("TPM2_ReadPublic Handle 0x%x: pub %d, name %d, qualifiedName %d\n",
        readPubIn.objectHandle,
        readPubOut.outPublic.size, readPubOut.name.size,
        readPubOut.qualifiedName.size);
#endif

    return rc;
}

/* primaryHandle must be owner or platform hierarchy */
/* Owner    Persistent Handle Range: 0x81000000 to 0x817FFFFF */
/* Platform Persistent Handle Range: 0x81800000 to 0x81FFFFFF */
int wolfTPM2_NVStoreKey(WOLFTPM2_DEV* dev, TPM_HANDLE primaryHandle,
    WOLFTPM2_KEY* key, TPM_HANDLE persistentHandle)
{
    int rc;
    EvictControl_In in;

    if (dev == NULL || key == NULL || primaryHandle == 0 || persistentHandle == 0) {
        return BAD_FUNC_ARG;
    }

    /* if key is already persistent then just return success */
    if (key->handle.hndl == persistentHandle)
        return TPM_RC_SUCCESS;

    /* Move key into NV to persist */
    XMEMSET(&in, 0, sizeof(in));
    in.auth = primaryHandle;
    in.objectHandle = key->handle.hndl;
    in.persistentHandle = persistentHandle;

    rc = TPM2_EvictControl(&in);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_EvictControl failed %d: %s\n", rc, wolfTPM2_GetRCString(rc));
        return rc;
    }

#ifdef DEBUG_WOLFTPM
    printf("TPM2_EvictControl Auth 0x%x, Key 0x%x, Persistent 0x%x\n",
        in.auth, in.objectHandle, in.persistentHandle);
#endif

    /* replace handle with persistent one */
    key->handle.hndlPersistent = persistentHandle;

    return rc;
}

int wolfTPM2_NVDeleteKey(WOLFTPM2_DEV* dev, TPM_HANDLE primaryHandle, WOLFTPM2_KEY* key)
{
    int rc;
    EvictControl_In in;

    if (dev == NULL || key == NULL || primaryHandle == 0) {
        return BAD_FUNC_ARG;
    }

    /* if key is not persistent then just return success */
    if (key->handle.hndl < PERSISTENT_FIRST || key->handle.hndl > PERSISTENT_LAST)
        return TPM_RC_SUCCESS;

    /* Move key into NV to persist */
    XMEMSET(&in, 0, sizeof(in));
    in.auth = primaryHandle;
    in.objectHandle = key->handle.hndl;
    in.persistentHandle = key->handle.hndl;

    rc = TPM2_EvictControl(&in);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_EvictControl failed %d: %s\n", rc, wolfTPM2_GetRCString(rc));
        return rc;
    }

#ifdef DEBUG_WOLFTPM
    printf("TPM2_EvictControl Auth 0x%x, Key 0x%x, Persistent 0x%x\n",
        in.auth, in.objectHandle, in.persistentHandle);
#endif

    /* indicate no persistent handle */
    key->handle.hndlPersistent = TPM_RH_NULL;

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
        key->pub.publicArea.parameters.eccDetail.curveID);
    if (curveSize <= 0 || *sigSz < (curveSize * 2)) {
        return BAD_FUNC_ARG;
    }

    /* set session auth for key */
    dev->session[0].auth = key->handle.auth;
    dev->session[0].symmetric =
        key->pub.publicArea.parameters.eccDetail.symmetric;

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
        key->pub.publicArea.parameters.eccDetail.curveID);
    if (curveSize <= 0 || sigSz < (curveSize * 2)) {
        return BAD_FUNC_ARG;
    }

    /* set session auth for key */
    dev->session[0].auth = key->handle.auth;
    dev->session[0].symmetric =
        key->pub.publicArea.parameters.eccDetail.symmetric;

    XMEMSET(&verifySigIn, 0, sizeof(verifySigIn));
    verifySigIn.keyHandle = key->handle.hndl;
    verifySigIn.digest.size = digestSz;
    XMEMCPY(verifySigIn.digest.buffer, digest, digestSz);
    verifySigIn.signature.sigAlgo =
        key->pub.publicArea.parameters.eccDetail.scheme.scheme;
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
        printf("TPM2_VerifySignature failed %d: %s\n", rc,
            wolfTPM2_GetRCString(rc));
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
        privKey->pub.publicArea.parameters.eccDetail.curveID);
    if (curveSize <= 0 || *outSz < curveSize) {
        return BAD_FUNC_ARG;
    }

    /* set session auth for key */
    dev->session[0].auth = privKey->handle.auth;
    dev->session[0].symmetric =
        privKey->pub.publicArea.parameters.eccDetail.symmetric;

    XMEMSET(&ecdhIn, 0, sizeof(ecdhIn));
    ecdhIn.keyHandle = privKey->handle.hndl;
    rc = TPM2_ECDH_KeyGen(&ecdhIn, &ecdhOut);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_ECDH_KeyGen failed %d: %s\n", rc,
            wolfTPM2_GetRCString(rc));
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
    dev->session[0].auth = key->handle.auth;
    dev->session[0].symmetric =
        key->pub.publicArea.parameters.rsaDetail.symmetric;

    /* RSA Encrypt */
    XMEMSET(&rsaEncIn, 0, sizeof(rsaEncIn));
    rsaEncIn.keyHandle = key->handle.hndl;
    rsaEncIn.message.size = msgSz;
    XMEMCPY(rsaEncIn.message.buffer, msg, msgSz);
    rsaEncIn.inScheme.scheme = padScheme; /* TPM_ALG_OAEP or TPM_ALG_RSAPSS */
    rsaEncIn.inScheme.details.oaep.hashAlg = WOLFTPM2_WRAP_DIGEST;

#if 0
    /* Optional label */
    rsaEncIn.label.size = sizeof(label); /* Null term required */
    XMEMCPY(rsaEncIn.label.buffer, label, rsaEncIn.label.size);
#endif

    rc = TPM2_RSA_Encrypt(&rsaEncIn, &rsaEncOut);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_RSA_Encrypt failed %d: %s\n", rc,
            wolfTPM2_GetRCString(rc));
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

    /* set session auth for key */
    dev->session[0].auth = key->handle.auth;
    dev->session[0].symmetric =
        key->pub.publicArea.parameters.rsaDetail.symmetric;

    /* RSA Decrypt */
    XMEMSET(&rsaDecIn, 0, sizeof(rsaDecIn));
    rsaDecIn.keyHandle = key->handle.hndl;
    rsaDecIn.cipherText.size = inSz;
    XMEMCPY(rsaDecIn.cipherText.buffer, in, inSz);
    rsaDecIn.inScheme.scheme = padScheme;
    rsaDecIn.inScheme.details.oaep.hashAlg = WOLFTPM2_WRAP_DIGEST;

#if 0
    /* Optional label */
    rsaDecIn.label.size = sizeof(label); /* Null term required */
    XMEMCPY(rsaDecIn.label.buffer, label, rsaEncIn.label.size);
#endif

    rc = TPM2_RSA_Decrypt(&rsaDecIn, &rsaDecOut);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_RSA_Decrypt failed %d: %s\n", rc,
            wolfTPM2_GetRCString(rc));
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
        printf("TPM2_FlushContext failed %d: %s\n", rc,
            wolfTPM2_GetRCString(rc));
        return rc;
    }

#ifdef DEBUG_WOLFTPM
    printf("TPM2_FlushContext: Closed handle 0x%x\n", handle->hndl);
#endif

    handle->hndl = TPM_RH_NULL;

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
        printf("TPM2_NV_ReadPublic failed %d: %s\n", rc,
            wolfTPM2_GetRCString(rc));
        return rc;
    }

#ifdef DEBUG_WOLFTPM
    printf("TPM2_NV_ReadPublic: Sz %d, Idx 0x%x, nameAlg %d, Attr 0x%x, "
            "authPol %d, dataSz %d, name %d\n",
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

/******************************************************************************/
/* --- END Utility Functions -- */
/******************************************************************************/

#endif /* !WOLFTPM2_NO_WRAPPER */
