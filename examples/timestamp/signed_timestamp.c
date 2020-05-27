/* signed_timestamp.c
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* This example shows how to use extended authorization sessions (TPM2.0) and
 * generate a signed timestamp from the TPM using a Attestation Identity Key.
 */

#include <wolftpm/tpm2.h>

#include <examples/timestamp/signed_timestamp.h>
#include <examples/tpm_io.h>
#include <examples/tpm_test.h>

#include <stdio.h>


/******************************************************************************/
/* --- BEGIN TPM Timestamp Test -- */
/******************************************************************************/

typedef struct tpmKey {
    TPM_HANDLE          handle;
    TPM2B_AUTH          auth;
    TPM2B_PRIVATE       priv;
    TPM2B_PUBLIC        pub;
    TPM2B_NAME          name;
} TpmKey; /* Type used to store the output from Key generation */


int TPM2_Timestamp_Test(void* userCtx)
{
    int rc;
    TPM2_CTX tpm2Ctx;
    TPMS_TIME_ATTEST_INFO* attestedTime = NULL;

    union {
        GetTime_In getTime;
        /* For creating keys */
        CreatePrimary_In createPri;
        Create_In create;
        /* For managing TPM session */
        StartAuthSession_In authSes;
        PolicySecret_In policySecret;
        /* Loading a key and removing objects */
        Load_In load;
        FlushContext_In flushCtx;
        byte maxInput[MAX_COMMAND_SIZE];
    } cmdIn;
    union {
        ReadClock_Out readClock;
        GetTime_Out getTime;
        /* Output from creating keys */
        CreatePrimary_Out createPri;
        Create_Out create;
        /* Output from session operations */
        StartAuthSession_Out authSes;
        PolicySecret_Out policySecret;
        /* Output from loading a key into the TPM */
        Load_Out load;
        byte maxOutput[MAX_RESPONSE_SIZE];
    } cmdOut;

    TPM_HANDLE sessionHandle = TPM_RH_NULL;

    TpmKey endorse = { .handle = TPM_RH_NULL }; /* EK  */
    TpmKey storage = { .handle = TPM_RH_NULL }; /* SRK */
    TpmKey rsaKey = { .handle = TPM_RH_NULL };  /* AIK */

    const char storagePwd[] = "WolfTPMpassword";
    const char usageAuth[] = "ThisIsASecretUsageAuth";
    const char keyCreationNonce[] = "RandomServerPickedCreationNonce";

    TPMS_AUTH_COMMAND session[MAX_SESSION_NUM];


    printf("TPM2 Demo of generating signed timestamp from the TPM\n");
    rc = TPM2_Init(&tpm2Ctx, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_Init failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }


    /* Define the default session auth that has NULL password */
    XMEMSET(session, 0, sizeof(session));
    session[0].sessionHandle = TPM_RS_PW;
    session[0].auth.size = 0; /* NULL Password */
    TPM2_SetSessionAuth(session);


    /* ReadClock for quick test of the TPM communication */
    XMEMSET(&cmdOut.readClock, 0, sizeof(cmdOut.readClock));
    rc = TPM2_ReadClock(&cmdOut.readClock);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_ReadClock failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_ReadClock: success\n");


    /* Create Primary (Endorsement Key, also called EK) */
    XMEMSET(&cmdIn.createPri, 0, sizeof(cmdIn.createPri));
    cmdIn.createPri.primaryHandle = TPM_RH_ENDORSEMENT;
    /* Policy for creating the EK */
    cmdIn.createPri.inPublic.publicArea.authPolicy.size =
        sizeof(TPM_20_EK_AUTH_POLICY);
    XMEMCPY(cmdIn.createPri.inPublic.publicArea.authPolicy.buffer,
        TPM_20_EK_AUTH_POLICY,
        cmdIn.createPri.inPublic.publicArea.authPolicy.size);
    /* Parameters of the EK */
    cmdIn.createPri.inPublic.publicArea.type = TPM_ALG_RSA;
    cmdIn.createPri.inPublic.publicArea.unique.rsa.size = MAX_RSA_KEY_BITS / 8;
    cmdIn.createPri.inPublic.publicArea.nameAlg = TPM_ALG_SHA256;
    cmdIn.createPri.inPublic.publicArea.objectAttributes = (
        TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent |
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_adminWithPolicy |
        TPMA_OBJECT_restricted | TPMA_OBJECT_decrypt);
    cmdIn.createPri.inPublic.publicArea.parameters.rsaDetail.keyBits = MAX_RSA_KEY_BITS;
    cmdIn.createPri.inPublic.publicArea.parameters.rsaDetail.exponent = 0;
    cmdIn.createPri.inPublic.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
    cmdIn.createPri.inPublic.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
    cmdIn.createPri.inPublic.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
    cmdIn.createPri.inPublic.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_CFB;
    /* Ready to create the EK */
    rc = TPM2_CreatePrimary(&cmdIn.createPri, &cmdOut.createPri);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_CreatePrimary: Endorsement failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    /* Store the EK */
    endorse.handle = cmdOut.createPri.objectHandle;
    endorse.auth = cmdIn.createPri.inPublic.publicArea.authPolicy;
    endorse.pub = cmdOut.createPri.outPublic;
    endorse.name = cmdOut.createPri.name;
    printf("TPM2_CreatePrimary: Endorsement 0x%x (%d bytes)\n",
        (word32)endorse.handle, endorse.pub.size);


    /* Create Primary (Storage Key, also called SRK) */
    XMEMSET(&cmdIn.createPri, 0, sizeof(cmdIn.createPri));
    cmdIn.createPri.primaryHandle = TPM_RH_OWNER;
    /* Set auth required for using SRK */
    cmdIn.createPri.inSensitive.sensitive.userAuth.size = sizeof(storagePwd)-1;
    XMEMCPY(cmdIn.createPri.inSensitive.sensitive.userAuth.buffer,
        storagePwd, cmdIn.createPri.inSensitive.sensitive.userAuth.size);
    /* Parameters for the SRK */
    cmdIn.createPri.inPublic.publicArea.type = TPM_ALG_RSA;
    cmdIn.createPri.inPublic.publicArea.unique.rsa.size = MAX_RSA_KEY_BITS / 8;
    cmdIn.createPri.inPublic.publicArea.nameAlg = TPM_ALG_SHA256;
    cmdIn.createPri.inPublic.publicArea.objectAttributes = (
        TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent |
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_restricted | TPMA_OBJECT_decrypt | TPMA_OBJECT_noDA);
    cmdIn.createPri.inPublic.publicArea.parameters.rsaDetail.keyBits = MAX_RSA_KEY_BITS;
    cmdIn.createPri.inPublic.publicArea.parameters.rsaDetail.exponent = 0;
    cmdIn.createPri.inPublic.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
    cmdIn.createPri.inPublic.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
    cmdIn.createPri.inPublic.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
    cmdIn.createPri.inPublic.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_CFB;
    /* Create the SRK */
    rc = TPM2_CreatePrimary(&cmdIn.createPri, &cmdOut.createPri);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_CreatePrimary: Storage failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    storage.handle = cmdOut.createPri.objectHandle;
    storage.pub = cmdOut.createPri.outPublic;
    storage.name = cmdOut.createPri.name;
    printf("TPM2_CreatePrimary: Storage 0x%x (%d bytes)\n",
        (word32)storage.handle, storage.pub.size);


    /* Start Auth Session */
    XMEMSET(&cmdIn.authSes, 0, sizeof(cmdIn.authSes));
    cmdIn.authSes.sessionType = TPM_SE_POLICY;
    cmdIn.authSes.tpmKey = TPM_RH_NULL;
    cmdIn.authSes.bind = TPM_RH_NULL;
    cmdIn.authSes.symmetric.algorithm = TPM_ALG_NULL;
    cmdIn.authSes.authHash = TPM_ALG_SHA256;
    cmdIn.authSes.nonceCaller.size = TPM_SHA256_DIGEST_SIZE;
    rc = TPM2_GetNonce(cmdIn.authSes.nonceCaller.buffer,
                       cmdIn.authSes.nonceCaller.size);
    if (rc < 0) {
        printf("TPM2_GetNonce failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    rc = TPM2_StartAuthSession(&cmdIn.authSes, &cmdOut.authSes);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_StartAuthSession failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    sessionHandle = cmdOut.authSes.sessionHandle;
    printf("TPM2_StartAuthSession: sessionHandle 0x%x\n", (word32)sessionHandle);


    /* Set PolicySecret for our session to enable use of the Endoresment Hierarchy */
    XMEMSET(&cmdIn.policySecret, 0, sizeof(cmdIn.policySecret));
    cmdIn.policySecret.authHandle = TPM_RH_ENDORSEMENT;
    cmdIn.policySecret.policySession = sessionHandle;
    rc = TPM2_PolicySecret(&cmdIn.policySecret, &cmdOut.policySecret);
    if (rc != TPM_RC_SUCCESS) {
        printf("policySecret failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_policySecret success\n"); /* No use of the output */


    /* At this stage, the EK is created and NULL password has alredy been set
     * The EH is enabled through policySecret over the active TPM session and
     * the creation of Attestation Identity Key under the EH can take place.
     */


    /* set session auth for storage key */
    session[0].auth.size = sizeof(storagePwd)-1;
    XMEMCPY(session[0].auth.buffer, storagePwd, session[0].auth.size);


    /* Create an RSA key for Attestation purposes */
    XMEMSET(&cmdIn.create, 0, sizeof(cmdIn.create));
    cmdIn.create.parentHandle = storage.handle;
    /* Set auth required for using the AIK later */
    cmdIn.create.inSensitive.sensitive.userAuth.size = sizeof(usageAuth)-1;
    XMEMCPY(cmdIn.create.inSensitive.sensitive.userAuth.buffer, usageAuth,
        cmdIn.create.inSensitive.sensitive.userAuth.size);
    /* AIK parameters */
    cmdIn.create.inPublic.publicArea.type = TPM_ALG_RSA;
    cmdIn.create.inPublic.publicArea.unique.rsa.size = MAX_RSA_KEY_BITS / 8;
    cmdIn.create.inPublic.publicArea.nameAlg = TPM_ALG_SHA256;
    cmdIn.create.inPublic.publicArea.objectAttributes = (
        TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent | TPMA_OBJECT_restricted |
        TPMA_OBJECT_sensitiveDataOrigin |
        TPMA_OBJECT_userWithAuth | TPMA_OBJECT_sign | TPMA_OBJECT_noDA);
    cmdIn.create.inPublic.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
    cmdIn.create.inPublic.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_RSASSA;
    cmdIn.create.inPublic.publicArea.parameters.rsaDetail.scheme.details.anySig.hashAlg = TPM_ALG_SHA256;
    cmdIn.create.inPublic.publicArea.parameters.rsaDetail.keyBits = MAX_RSA_KEY_BITS;
    cmdIn.create.outsideInfo.size = sizeof(keyCreationNonce)-1;
    XMEMCPY(cmdIn.create.outsideInfo.buffer, keyCreationNonce,
        cmdIn.create.outsideInfo.size);
    /* Create the AIK */
    rc = TPM2_Create(&cmdIn.create, &cmdOut.create);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_Create RSA failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_Create: New RSA Key: pub %d, priv %d\n",
        cmdOut.create.outPublic.size,
        cmdOut.create.outPrivate.size);
    /* Store the AIK */
    rsaKey.pub = cmdOut.create.outPublic;
    rsaKey.priv = cmdOut.create.outPrivate;


    /* Load new key */
    XMEMSET(&cmdIn.load, 0, sizeof(cmdIn.load));
    cmdIn.load.parentHandle = storage.handle;
    cmdIn.load.inPrivate = rsaKey.priv;
    cmdIn.load.inPublic = rsaKey.pub;
    rc = TPM2_Load(&cmdIn.load, &cmdOut.load);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_Load RSA key failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    rsaKey.handle = cmdOut.load.objectHandle;
    printf("TPM2_Load RSA Key Handle 0x%x\n", (word32)rsaKey.handle);


    /* set NULL password auth for using EK */
    session[0].auth.size = 0;

    /* set auth for using the AIK */
    session[1].sessionHandle = TPM_RS_PW;
    session[1].auth.size = sizeof(usageAuth)-1;
    XMEMCPY(session[1].auth.buffer, usageAuth, session[1].auth.size);


    /* At this stage: The EK is created, AIK is created and loaded,
     * Endorsement Hierarchy is enabled through policySecret,
     * the use of the loaded AIK is enabled through its usageAuth.
     * Invoking attestation of the TPM time structure can take place.
     */

    /* GetTime */
    XMEMSET(&cmdIn.getTime, 0, sizeof(cmdIn.getTime));
    XMEMSET(&cmdOut.getTime, 0, sizeof(cmdOut.getTime));
    cmdIn.getTime.privacyAdminHandle = TPM_RH_ENDORSEMENT;
    /* TPM_RH_NULL is a valid handle for NULL signature */
    cmdIn.getTime.signHandle = rsaKey.handle;
    /* TPM_ALG_NULL is a valid hanle for  NULL signature */
    cmdIn.getTime.inScheme.scheme = TPM_ALG_RSASSA;
    cmdIn.getTime.inScheme.details.rsassa.hashAlg = TPM_ALG_SHA256;
    cmdIn.getTime.qualifyingData.size = 0; /* optional */
    rc = TPM2_GetTime(&cmdIn.getTime, &cmdOut.getTime);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_GetTime failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_GetTime: success\n");
    /* Print result in human friendly way */
    attestedTime = (TPMS_TIME_ATTEST_INFO*)cmdOut.getTime.timeInfo.attestationData;
    printf("TPM2_GetTime: TPMS_TIME_ATTEST_INFO with signature attests:\n");
    printf("* TPM Uptime (in ms) since power-up = %lu\n", attestedTime->time.clockInfo.clock);

exit:

    /* Close session */
    if (sessionHandle != TPM_RH_NULL) {
        cmdIn.flushCtx.flushHandle = sessionHandle;
        TPM2_FlushContext(&cmdIn.flushCtx);
    }

    /* Close object handle */
    if (rsaKey.handle != TPM_RH_NULL) {
        cmdIn.flushCtx.flushHandle = rsaKey.handle;
        TPM2_FlushContext(&cmdIn.flushCtx);
    }

    /* Cleanup key handles */
    if (endorse.handle != TPM_RH_NULL) {
        cmdIn.flushCtx.flushHandle = endorse.handle;
        TPM2_FlushContext(&cmdIn.flushCtx);
    }

    /* Cleanup key handles */
    if (storage.handle != TPM_RH_NULL) {
        cmdIn.flushCtx.flushHandle = storage.handle;
        TPM2_FlushContext(&cmdIn.flushCtx);
    }

    TPM2_Cleanup(&tpm2Ctx);

#ifdef TPM2_SPI_DEV
    /* close handle */
    if (gSpiDev >= 0)
        close(gSpiDev);
#endif

    return rc;
}

/******************************************************************************/
/* --- END TPM Timestamp Test -- */
/******************************************************************************/


#ifndef NO_MAIN_DRIVER
int main(void)
{
    int rc;

    rc = TPM2_Timestamp_Test(NULL);

    return rc;
}
#endif
