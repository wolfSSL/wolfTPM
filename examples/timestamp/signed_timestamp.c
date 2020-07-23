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

#include <wolftpm/tpm2_wrap.h>

#include <examples/timestamp/signed_timestamp.h>
#include <examples/tpm_io.h>
#include <examples/tpm_test.h>

#include <stdio.h>


/******************************************************************************/
/* --- BEGIN TPM Timestamp Test -- */
/******************************************************************************/

int TPM2_Timestamp_Test(void* userCtx)
{
    int rc;
    WOLFTPM2_DEV dev;
    TPMS_ATTEST attestedData;

    union {
        /* For managing TPM session */
        StartAuthSession_In authSes;
        PolicySecret_In policySecret;
        /* For removing keys after use */
        FlushContext_In flushCtx;
        byte maxInput[MAX_COMMAND_SIZE];
    } cmdIn;
    union {
        ReadClock_Out readClock;
        GetTime_Out getTime;
        /* Output from session operations */
        StartAuthSession_Out authSes;
        PolicySecret_Out policySecret;
        byte maxOutput[MAX_RESPONSE_SIZE];
    } cmdOut;

    TPM_HANDLE sessionHandle = TPM_RH_NULL;

    WOLFTPM2_KEY endorse; /* EK  */
    WOLFTPM2_KEY storage; /* SRK */
    WOLFTPM2_KEY rsaKey;  /* AIK */

    TPMS_AUTH_COMMAND session[MAX_SESSION_NUM];

    XMEMSET(&endorse, 0, sizeof(endorse));
    XMEMSET(&storage, 0, sizeof(storage));
    XMEMSET(&rsaKey, 0, sizeof(rsaKey));

    printf("TPM2 Demo of generating signed timestamp from the TPM\n");
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_Init failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    printf("wolfTPM2_Init: success\n");


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


    /* Create Endorsement Key, also called EK */
    rc = wolfTPM2_CreateEK(&dev, &endorse, TPM_ALG_RSA);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_CreateEK: Endorsement failed 0x%x: %s\n",
            rc, TPM2_GetRCString(rc));
        goto exit;
    }
    printf("wolfTPM2_CreateEK: Endorsement 0x%x (%d bytes)\n",
        (word32)endorse.handle.hndl, endorse.pub.size);


    /* Create RSA Storage Key, also called SRK */
    /* See if SRK already exists */
    rc = wolfTPM2_ReadPublicKey(&dev, &storage, TPM2_DEMO_STORAGE_KEY_HANDLE);
#ifdef TEST_WRAP_DELETE_KEY
    if (rc == 0) {
        storage.handle.hndl = TPM2_DEMO_STORAGE_KEY_HANDLE;
        rc = wolfTPM2_NVDeleteKey(&dev, TPM_RH_OWNER, &storage);
        if (rc != 0) goto exit;
        rc = TPM_RC_HANDLE; /* mark handle as missing */
    }
#endif
    if (rc != 0) {
        /* Create primary storage key (RSA) */
        rc = wolfTPM2_CreateSRK(&dev, &storage, TPM_ALG_RSA, 
            (byte*)gStorageKeyAuth, sizeof(gStorageKeyAuth)-1);

        /* Move storage key into persistent NV */
        rc = wolfTPM2_NVStoreKey(&dev, TPM_RH_OWNER, &storage,
            TPM2_DEMO_STORAGE_KEY_HANDLE);
        if (rc != 0) {
            wolfTPM2_UnloadHandle(&dev, &storage.handle);
            goto exit;
        }

        printf("Created new RSA Primary Storage Key at 0x%x\n",
            TPM2_DEMO_STORAGE_KEY_HANDLE);
    }
    else {
        /* specify auth password for storage key */
        storage.handle.auth.size = sizeof(gStorageKeyAuth)-1;
        XMEMCPY(storage.handle.auth.buffer, gStorageKeyAuth,
            storage.handle.auth.size);
    }
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_CreateSRK: Storage failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    printf("wolfTPM2_CreateSRK: Storage 0x%x (%d bytes)\n",
        (word32)storage.handle.hndl, storage.pub.size);


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


    /* Set PolicySecret for our session to enable use of the Endorsement Hierarchy */
    XMEMSET(&cmdIn.policySecret, 0, sizeof(cmdIn.policySecret));
    cmdIn.policySecret.authHandle = TPM_RH_ENDORSEMENT;
    cmdIn.policySecret.policySession = sessionHandle;
    rc = TPM2_PolicySecret(&cmdIn.policySecret, &cmdOut.policySecret);
    if (rc != TPM_RC_SUCCESS) {
        printf("policySecret failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_policySecret success\n"); /* No use of the output */


    /* At this stage, the EK is created and NULL password has already been set
     * The EH is enabled through policySecret over the active TPM session and
     * the creation of Attestation Identity Key (AIK) under the EH can take place.
     */


    /* set session auth for storage key */
    session[0].auth.size = sizeof(gStorageKeyAuth)-1;
    XMEMCPY(session[0].auth.buffer, gStorageKeyAuth, session[0].auth.size);


    /* Create an Attestation RSA key (AIK) */
    rc = wolfTPM2_CreateAndLoadAIK(&dev, &rsaKey, TPM_ALG_RSA, &storage,
        (const byte*)gAiKeyAuth, sizeof(gAiKeyAuth)-1);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_CreateAndLoadAIK failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    printf("wolfTPM2_CreateAndLoadAIK: AIK 0x%x (%d bytes)\n",
        (word32)rsaKey.handle.hndl, rsaKey.pub.size);


    /* set NULL password auth for using EK */
    session[0].auth.size = 0;

    /* set auth for using the AIK */
    session[1].sessionHandle = TPM_RS_PW;
    session[1].auth.size = sizeof(gAiKeyAuth)-1;
    XMEMCPY(session[1].auth.buffer, gAiKeyAuth, session[1].auth.size);


    /* At this stage: The EK is created, AIK is created and loaded,
     * Endorsement Hierarchy is enabled through policySecret,
     * the use of the loaded AIK is enabled through its usageAuth.
     * Invoking attestation of the TPM time structure can take place.
     */

    /* Get signed by the TPM timestamp using the AIK key */
    rc = wolfTPM2_GetTime(&rsaKey, &cmdOut.getTime);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_GetTime failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    printf("wolfTPM2_GetTime: success\n");

    rc = TPM2_ParseAttest(&cmdOut.getTime.timeInfo, &attestedData);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_Packet_ParseAttest failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    if (attestedData.magic != TPM_GENERATED_VALUE) {
        printf("\tError, attested data not generated by the TPM = 0x%X\n",
            attestedData.magic);
    }

    printf("TPM with signature attests (type 0x%x):\n", attestedData.type);
    /* time value in milliseconds that advances while the TPM is powered */
    printf("\tTPM uptime since last power-up(in ms): %lu\n",
        (unsigned long)attestedData.attested.time.time.time);
    /* time value in milliseconds that advances while the TPM is powered */
    printf("\tTPM clock, total time the TPM has been on(in ms): %lu\n",
        (unsigned long)attestedData.attested.time.time.clockInfo.clock);
    /* number of occurrences of TPM Reset since the last TPM2_Clear() */
    printf("\tReset Count: %u\n",
        attestedData.attested.time.time.clockInfo.resetCount);
    /* number of times that TPM2_Shutdown() or _TPM_Hash_Start have occurred since the last TPM Reset or TPM2_Clear(). */
    printf("\tRestart Count: %u\n",
        attestedData.attested.time.time.clockInfo.restartCount);
    /* This parameter is set to YES when the value reported in Clock is guaranteed to be unique for the current Owner */
    printf("\tClock Safe: %u\n",
        attestedData.attested.time.time.clockInfo.safe);
    /* a TPM vendor-specific value indicating the version number of the firmware */
    printf("\tFirmware Version(vendor specific): 0x%lX\n",
        (unsigned long)attestedData.attested.time.firmwareVersion);

exit:

    if (rc != 0) {
        printf("Failure 0x%x: %s\n", rc, wolfTPM2_GetRCString(rc));
    }

    /* Close session */
    if (sessionHandle != TPM_RH_NULL) {
        cmdIn.flushCtx.flushHandle = sessionHandle;
        TPM2_FlushContext(&cmdIn.flushCtx);
    }

    /* Close key handles */
    wolfTPM2_UnloadHandle(&dev, &rsaKey.handle);
    wolfTPM2_UnloadHandle(&dev, &endorse.handle);

    wolfTPM2_Cleanup(&dev);
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
