/* quote.c
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

/* This example shows how to generate a TPM2.0 Quote that holds a signed
 * PCR measurement. PCR values are used as basis for system integrity.
 */

#include <wolftpm/tpm2_wrap.h>

#include <examples/pcr/quote.h>
#include <examples/tpm_io.h>
#include <examples/tpm_test.h>

#include <stdio.h>
#include <stdlib.h> /* atoi */

const char defaultFilename[] = "quote.blob\0";

/******************************************************************************/
/* --- BEGIN TPM2.0 Quote Test -- */
/******************************************************************************/

static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/pcr/quote [pcr] [filename]\n");
    printf("* pcr is a PCR index between 0-23 (default %d)\n", TPM2_TEST_PCR);
    printf("* filename for saving the TPMS_ATTEST structure to a file\n");
    printf("Demo usage without parameters, generates quote over PCR%d and\n"
           "saves the output TPMS_ATTEST structure to \"quote.blob\" file.\n",
           TPM2_TEST_PCR);
}

int TPM2_Quote_Test(void* userCtx, int argc, char *argv[])
{
    int pcrIndex, rc = -1;
    const char *filename = NULL;
    BYTE *data = NULL;
    FILE *quoteBlob = NULL;
    WOLFTPM2_DEV dev;
    TPMS_ATTEST attestedData;
    TPM_HANDLE sessionHandle = TPM_RH_NULL;

    WOLFTPM2_KEY endorse; /* EK  */
    WOLFTPM2_KEY storage; /* SRK */
    WOLFTPM2_KEY rsaKey;  /* AIK */

    TPMS_AUTH_COMMAND session[MAX_SESSION_NUM];


    union {
        Quote_In quoteAsk;
        /* For managing TPM session */
        StartAuthSession_In authSes;
        PolicySecret_In policySecret;
        /* For removing keys after use */
        FlushContext_In flushCtx;
        byte maxInput[MAX_COMMAND_SIZE];
    } cmdIn;
    union {
        Quote_Out quoteResult;
        /* Output from session operations */
        StartAuthSession_Out authSes;
        PolicySecret_Out policySecret;
        byte maxOutput[MAX_RESPONSE_SIZE];
    } cmdOut;

    XMEMSET(&endorse, 0, sizeof(endorse));
    XMEMSET(&storage, 0, sizeof(storage));
    XMEMSET(&rsaKey, 0, sizeof(rsaKey));


    if (argc == 1) {
        /* Demo usage */
        pcrIndex = TPM2_TEST_PCR;
        filename = defaultFilename;
    }
    else if (argc == 3) {
        /* Advanced usage */
        pcrIndex = atoi(argv[1]);
        if (pcrIndex < 0 || pcrIndex > 23 || *argv[1] < '0' || *argv[1] > '9') {
            printf("PCR index is out of range (0-23)\n");
            usage();
            goto exit_badargs;
        }
        filename = argv[2];
    }
    else {
        printf("Incorrect arguments\n");
        usage();
        goto exit_badargs;
    }

    quoteBlob = fopen(filename, "wb");
    if (quoteBlob == NULL) {
        printf("Error opening file %s\n", filename);
        usage();
        goto exit_badargs;
    }

    printf("Demo of generating signed PCR measurement (TPM2.0 Quote)\n");
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


    /* set session auth for storage key */
    session[0].auth.size = sizeof(gStorageKeyAuth)-1;
    XMEMCPY(session[0].auth.buffer, gStorageKeyAuth, session[0].auth.size);


    /* Create an RSA key for Attestation purposes */
    rc = wolfTPM2_CreateAndLoadAIK(&dev, &rsaKey, TPM_ALG_RSA, &storage,
        (const byte*)gUsageAuth, sizeof(gUsageAuth)-1);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_CreateAndLoadAIK failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    printf("wolfTPM2_CreateAndLoadAIK: AIK 0x%x (%d bytes)\n",
        (word32)rsaKey.handle.hndl, rsaKey.pub.size);


    /* set auth for using the AIK */
    session[0].auth.size = sizeof(gUsageAuth)-1;
    XMEMCPY(session[0].auth.buffer, gUsageAuth, session[0].auth.size);

    /* Prepare Quote request */
    XMEMSET(&cmdIn.quoteAsk, 0, sizeof(cmdIn.quoteAsk));
    XMEMSET(&cmdOut.quoteResult, 0, sizeof(cmdOut.quoteResult));
    cmdIn.quoteAsk.signHandle = rsaKey.handle.hndl;
    cmdIn.quoteAsk.inScheme.scheme = TPM_ALG_RSASSA;
    cmdIn.quoteAsk.inScheme.details.rsassa.hashAlg = TPM_ALG_SHA256;
    cmdIn.quoteAsk.qualifyingData.size = 0; /* optional */
    /* Choose PCR for signing */
    TPM2_SetupPCRSel(&cmdIn.quoteAsk.PCRselect, TPM_ALG_SHA256, pcrIndex);


    /* Get the PCR measurement signed by the TPM using the AIK key */
    rc = TPM2_Quote(&cmdIn.quoteAsk, &cmdOut.quoteResult);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_Quote failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_Quote: success\n");

    rc = TPM2_ParseAttest(&cmdOut.quoteResult.quoted, &attestedData);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_Packet_ParseAttest failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    if (attestedData.magic != TPM_GENERATED_VALUE) {
        printf("\tError, attested data not generated by the TPM = 0x%X\n",
            attestedData.magic);
    }

    if(quoteBlob) {
        data = (UINT8*)&cmdOut.quoteResult.quoted;
        data += 2; /* skip the size field of TPMS_ATTEST */
        if(fwrite(data, sizeof(TPMS_ATTEST)-2, 1, quoteBlob) != 1) {
            printf("Error while writing to a %s file\n", filename);
        }
    }

    printf("TPM with signature attests (type 0x%x):\n", attestedData.type);
    printf("\tTPM signed %lu count of PCRs\n",
        (unsigned long)attestedData.attested.quote.pcrSelect.count);
#ifdef DEBUG_WOLFTPM
    printf("\tPCR digest:\n");
    TPM2_PrintBin(attestedData.attested.quote.pcrDigest.buffer,
        attestedData.attested.quote.pcrDigest.size);
    printf("\tTPM generated signature:\n");
    TPM2_PrintBin(cmdOut.quoteResult.signature.signature.rsassa.sig.buffer,
        cmdOut.quoteResult.signature.signature.rsassa.sig.size);
#endif

exit:

    /* Close session */
    if (sessionHandle != TPM_RH_NULL) {
        cmdIn.flushCtx.flushHandle = sessionHandle;
        TPM2_FlushContext(&cmdIn.flushCtx);
    }

    /* Close key handles */
    wolfTPM2_UnloadHandle(&dev, &rsaKey.handle);
    wolfTPM2_UnloadHandle(&dev, &storage.handle);
    wolfTPM2_UnloadHandle(&dev, &endorse.handle);

    wolfTPM2_Cleanup(&dev);

exit_badargs:

    if (quoteBlob != NULL) {
        fclose(quoteBlob);
    }

    return rc;
}

/******************************************************************************/
/* --- END TPM2.0 Quote Test -- */
/******************************************************************************/


#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc;

    rc = TPM2_Quote_Test(NULL, argc, argv);

    return rc;
}
#endif
