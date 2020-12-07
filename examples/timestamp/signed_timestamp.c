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

#ifndef WOLFTPM2_NO_WRAPPER

#include <examples/tpm_io.h>
#include <examples/tpm_test.h>
#include <examples/tpm_test_keys.h>
#include "signed_timestamp.h"

#include <stdio.h>


/******************************************************************************/
/* --- BEGIN TPM Timestamp Test -- */
/******************************************************************************/

static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/timestamp/signed_timestamp [-ecc] [-aes/xor]\n");
    printf("* -ecc: Use RSA or ECC for EK/AIK\n");
    printf("* -aes/xor: Use Parameter Encryption\n");
}

int TPM2_Timestamp_Test(void* userCtx)
{
    return TPM2_Timestamp_TestArgs(userCtx, 0, NULL);
}
int TPM2_Timestamp_TestArgs(void* userCtx, int argc, char *argv[])
{
    int rc;
    WOLFTPM2_DEV dev;
    TPMS_ATTEST attestedData;
    union {
        PolicySecret_In policySecret;
        byte maxInput[MAX_COMMAND_SIZE];
    } cmdIn;
    union {
        ReadClock_Out readClock;
        GetTime_Out getTime;
        PolicySecret_Out policySecret;
        byte maxOutput[MAX_RESPONSE_SIZE];
    } cmdOut;
    WOLFTPM2_KEY endorse; /* EK  */
    WOLFTPM2_KEY storage; /* SRK */
    WOLFTPM2_KEY aik;  /* AIK */
    TPMI_ALG_PUBLIC alg = TPM_ALG_RSA; /* TPM_ALG_ECC */
    TPM_ALG_ID paramEncAlg = TPM_ALG_NULL;
    WOLFTPM2_SESSION tpmSession;
    TPMA_SESSION sessionAttributes;

    XMEMSET(&endorse, 0, sizeof(endorse));
    XMEMSET(&storage, 0, sizeof(storage));
    XMEMSET(&aik, 0, sizeof(aik));
    XMEMSET(&tpmSession, 0, sizeof(tpmSession));

    if (argc >= 2) {
        if (XSTRNCMP(argv[1], "-?", 2) == 0 ||
            XSTRNCMP(argv[1], "-h", 2) == 0 ||
            XSTRNCMP(argv[1], "--help", 6) == 0) {
            usage();
            return 0;
        }
    }
    while (argc > 1) {
        if (XSTRNCMP(argv[argc-1], "-ecc", 4) == 0) {
            alg = TPM_ALG_ECC;
        }
        if (XSTRNCMP(argv[argc-1], "-aes", 4) == 0) {
            paramEncAlg = TPM_ALG_CFB;
        }
        if (XSTRNCMP(argv[argc-1], "-xor", 4) == 0) {
            paramEncAlg = TPM_ALG_XOR;
        }
        argc--;
    }

    printf("TPM2 Demo of generating signed timestamp from the TPM\n");
    printf("\tUse %s SRK/AIK\n", TPM2_GetAlgName(alg));
    printf("\tUse Parameter Encryption: %s\n", TPM2_GetAlgName(paramEncAlg));


    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_Init failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    printf("wolfTPM2_Init: success\n");

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
    rc = wolfTPM2_CreateEK(&dev, &endorse, alg);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_CreateEK: Endorsement failed 0x%x: %s\n",
            rc, TPM2_GetRCString(rc));
        goto exit;
    }
    printf("wolfTPM2_CreateEK: Endorsement 0x%x (%d bytes)\n",
        (word32)endorse.handle.hndl, endorse.pub.size);


    /* Create Storage Key, also called SRK */
    rc = getPrimaryStoragekey(&dev, &storage, alg);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_CreateSRK: Storage failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    printf("wolfTPM2_CreateSRK: Storage 0x%x (%d bytes)\n",
        (word32)storage.handle.hndl, storage.pub.size);

    /* Start an authenticated session (salted / unbound) */
    rc = wolfTPM2_StartSession(&dev, &tpmSession, NULL, NULL,
        TPM_SE_POLICY, paramEncAlg);
    if (rc != 0) goto exit;
    printf("TPM2_StartAuthSession: sessionHandle 0x%x\n",
        (word32)tpmSession.handle.hndl);

    /* Set the endorsement password (blank) */
    rc = wolfTPM2_SetAuthPassword(&dev, 0, NULL);
    if (rc != 0) goto exit;

    /* Set PolicySecret for our session to enable use of the Endorsement Hierarchy */
    XMEMSET(&cmdIn.policySecret, 0, sizeof(cmdIn.policySecret));
    cmdIn.policySecret.authHandle = TPM_RH_ENDORSEMENT;
    cmdIn.policySecret.policySession = tpmSession.handle.hndl;
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

    /* Create an Attestation key (AIK) */
    rc = wolfTPM2_CreateAndLoadAIK(&dev, &aik, alg, &storage,
        (const byte*)gAiKeyAuth, sizeof(gAiKeyAuth)-1);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_CreateAndLoadAIK failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    printf("wolfTPM2_CreateAndLoadAIK: AIK 0x%x (%d bytes)\n",
        (word32)aik.handle.hndl, aik.pub.size);


    /* set NULL password auth for using EK */
    wolfTPM2_SetAuthPassword(&dev, 0, NULL);

    /* set auth for using the AIK */
    wolfTPM2_SetAuthHandle(&dev, 1, &aik.handle);

    /* set session for authorization of the storage key */
    sessionAttributes = TPMA_SESSION_continueSession;
    if (paramEncAlg != TPM_ALG_NULL) {
        sessionAttributes |= (TPMA_SESSION_decrypt | TPMA_SESSION_encrypt);
    }
#if 0
    /* TODO: Investigate param enc with signed timestamp */
    rc = wolfTPM2_SetAuthSession(&dev, 2, &tpmSession, sessionAttributes);
    if (rc != 0) goto exit;
#else
    (void)sessionAttributes;
#endif

    /* At this stage: The EK is created, AIK is created and loaded,
     * Endorsement Hierarchy is enabled through policySecret,
     * the use of the loaded AIK is enabled through its usageAuth.
     * Invoking attestation of the TPM time structure can take place.
     */

    /* Get signed by the TPM timestamp using the AIK key */
    rc = wolfTPM2_GetTime(&aik, &cmdOut.getTime);
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
    printf("\tTPM uptime since last power-up (in ms): %lu\n",
        (unsigned long)attestedData.attested.time.time.time);
    /* time value in milliseconds that advances while the TPM is powered */
    printf("\tTPM clock, total time the TPM has been on (in ms): %lu\n",
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
    printf("\tFirmware Version (vendor specific): 0x%lX\n",
        (unsigned long)attestedData.attested.time.firmwareVersion);

exit:

    if (rc != 0) {
        printf("Failure 0x%x: %s\n", rc, wolfTPM2_GetRCString(rc));
    }

    wolfTPM2_UnloadHandle(&dev, &aik.handle);
    wolfTPM2_UnloadHandle(&dev, &endorse.handle);
    wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);

    wolfTPM2_Cleanup(&dev);
    return rc;
}

/******************************************************************************/
/* --- END TPM Timestamp Test -- */
/******************************************************************************/

#endif /* !WOLFTPM2_NO_WRAPPER */


#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = NOT_COMPILED_IN;

#ifndef WOLFTPM2_NO_WRAPPER
    rc = TPM2_Timestamp_TestArgs(NULL, argc, argv);
#else
    printf("Wrapper code not compiled in\n");
    (void)argc;
    (void)argv;
#endif /* !WOLFTPM2_NO_WRAPPER */

    return rc;
}
#endif
