/* quote_paramenc.c
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

static const char defaultFilename[] = "quote.blob";
static const char userData[] = "ThisIsData";

/******************************************************************************/
/* --- BEGIN TPM2.0 Quote Test with Parameter Encryption over user data   --- */
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
#if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_FILESYSTEM)
    BYTE *data = NULL;
    XFILE quoteBlob = NULL;
#endif
    WOLFTPM2_DEV dev;
    TPMS_ATTEST attestedData;

    WOLFTPM2_KEY storage; /* SRK */
    WOLFTPM2_KEY rsaKey;  /* AIK */

    TPMS_AUTH_COMMAND session[MAX_SESSION_NUM];
    TPM_HANDLE sessionHandle = TPM_RH_NULL;

    union {
        Quote_In quoteAsk;
        StartAuthSession_In authSes;
        FlushContext_In flushCtx;
        byte maxInput[MAX_COMMAND_SIZE];
    } cmdIn;
    union {
        Quote_Out quoteResult;
        StartAuthSession_Out authSes;
        byte maxOutput[MAX_RESPONSE_SIZE];
    } cmdOut;

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

#if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_FILESYSTEM)
    quoteBlob = XFOPEN(filename, "wb");
    if (quoteBlob == XBADFILE) {
        printf("Error opening file %s\n", filename);
        usage();
        goto exit_badargs;
    }
#endif

    printf("Demo of TPM2.0 Quote with parameter encryption over user data\n");
    printf("\tFilename: %s\n", filename);
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


    /* Create RSA Storage Key, also called SRK */
    rc = wolfTPM2_CreateSRK(&dev, &storage, TPM_ALG_RSA,
        (byte*)gStorageKeyAuth, sizeof(gStorageKeyAuth)-1);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_CreateSRK: Storage failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    printf("wolfTPM2_CreateSRK: Storage 0x%x (%d bytes)\n",
        (word32)storage.handle.hndl, storage.pub.size);


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


   /* Start Auth Session - Unbounded, Unsalted */
    XMEMSET(&cmdIn.authSes, 0, sizeof(cmdIn.authSes));
    cmdIn.authSes.sessionType = TPM_SE_POLICY;
    cmdIn.authSes.tpmKey = TPM_RH_NULL;
    cmdIn.authSes.bind = TPM_RH_NULL;
    cmdIn.authSes.symmetric.algorithm = TPM_ALG_XOR;
    cmdIn.authSes.symmetric.keyBits.xorr = TPM_ALG_SHA256;
    cmdIn.authSes.symmetric.mode.sym = TPM_ALG_NULL;
    cmdIn.authSes.encryptedSalt.size = 0;
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
        printf("\nTPM2_StartAuthSession failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    sessionHandle = cmdOut.authSes.sessionHandle;
    printf("TPM2_StartAuthSession: sessionHandle 0x%x\n", (word32)sessionHandle);


    /* set auth for using the AIK */
    session[0].auth.size = sizeof(gUsageAuth)-1;
    XMEMCPY(session[0].auth.buffer, gUsageAuth, session[0].auth.size);

    /* set session for XOR parameter encryption of the TPM Command */
    session[1].sessionHandle = sessionHandle;
    session[1].sessionAttributes = TPMA_SESSION_decrypt |
                                   TPMA_SESSION_encrypt |
                                   TPMA_SESSION_continueSession;
    session[1].symmetric.algorithm = TPM_ALG_XOR;
    session[1].symmetric.keyBits.xorr = TPM_ALG_SHA256;
    session[1].authHash = TPM_ALG_SHA256;
    session[1].auth.size = sizeof(gXorAuth)-1;
    XMEMCPY(session[1].auth.buffer, gXorAuth, session[1].auth.size);
    session[1].nonceCaller.size = TPM_SHA256_DIGEST_SIZE;
    rc = TPM2_GetNonce(session[1].nonceCaller.buffer,
                       session[1].nonceCaller.size);
    if (rc < 0) {
        printf("TPM2_GetNonce failed\n");
        goto exit;
    }

    /* Prepare Quote request */
    XMEMSET(&cmdIn.quoteAsk, 0, sizeof(cmdIn.quoteAsk));
    XMEMSET(&cmdOut.quoteResult, 0, sizeof(cmdOut.quoteResult));
    cmdIn.quoteAsk.signHandle = rsaKey.handle.hndl;
    cmdIn.quoteAsk.inScheme.scheme = TPM_ALG_RSASSA;
    cmdIn.quoteAsk.inScheme.details.rsassa.hashAlg = TPM_ALG_SHA256;
    /* This specifies the size of the parameter that will be encrypted */
    cmdIn.quoteAsk.qualifyingData.size = sizeof(userData);
    /* This is the data that will be encrypted */
    XMEMCPY(cmdIn.quoteAsk.qualifyingData.buffer, userData,
            cmdIn.quoteAsk.qualifyingData.size);
   /* Choose PCR for signing */
    TPM2_SetupPCRSel(&cmdIn.quoteAsk.PCRselect, TPM_ALG_SHA256, pcrIndex);

#ifdef WOLFTPM_DEBUG_VERBOSE
    printf("\n\tCommand with ParamEnc\n");
#endif

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

#if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_FILESYSTEM)
    if (quoteBlob != XBADFILE) {
        data = (UINT8*)&cmdOut.quoteResult.quoted;
        data += 2; /* skip the size field of TPMS_ATTEST */
        if (XFWRITE(data, 1, sizeof(TPMS_ATTEST)-2, quoteBlob) != sizeof(TPMS_ATTEST)-2) {
            printf("Error while writing to a %s file\n", filename);
        }
    }
#endif

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

    /* Close key handles */
    wolfTPM2_UnloadHandle(&dev, &rsaKey.handle);
    wolfTPM2_UnloadHandle(&dev, &storage.handle);

   /* Close session */
    if (sessionHandle != TPM_RH_NULL) {
        cmdIn.flushCtx.flushHandle = sessionHandle;
        TPM2_FlushContext(&cmdIn.flushCtx);
    }

    wolfTPM2_Cleanup(&dev);

exit_badargs:

#if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_FILESYSTEM)
    if (quoteBlob != NULL) {
        XFCLOSE(quoteBlob);
    }
#endif

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
