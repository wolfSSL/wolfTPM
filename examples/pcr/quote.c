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

#ifndef WOLFTPM2_NO_WRAPPER
#include <examples/pcr/quote.h>
#include <examples/tpm_io.h>
#include <examples/tpm_test.h>
#include <examples/tpm_test_keys.h>

#include <stdio.h>
#include <stdlib.h> /* atoi */

/******************************************************************************/
/* --- BEGIN TPM2.0 Quote Test -- */
/******************************************************************************/

static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/pcr/quote [pcr] [filename] [-ecc] [-aes/xor]\n");
    printf("* pcr: PCR index between 0-23 (default %d)\n", TPM2_TEST_PCR);
    printf("* filename: for saving the TPMS_ATTEST structure to a file\n");
    printf("* -ecc: Use RSA or ECC for EK/AIK\n");
    printf("* -aes/xor: Use Parameter Encryption\n");
    printf("Demo usage without parameters, generates quote over PCR%d and\n"
           "saves the output TPMS_ATTEST structure to \"quote.blob\" file.\n",
           TPM2_TEST_PCR);
}

int TPM2_Quote_Test(void* userCtx, int argc, char *argv[])
{
    int pcrIndex = TPM2_TEST_PCR, rc = -1;
    const char *outputFile = "quote.blob";
    BYTE *data = NULL;
    int dataSz;
    WOLFTPM2_DEV dev;
    TPMS_ATTEST attestedData;
    TPMI_ALG_PUBLIC alg = TPM_ALG_RSA; /* TPM_ALG_ECC */
    WOLFTPM2_KEY endorse; /* EK  */
    WOLFTPM2_KEY storage; /* SRK */
    WOLFTPM2_KEY aik;  /* AIK */
    union {
        Quote_In quoteAsk;
        byte maxInput[MAX_COMMAND_SIZE];
    } cmdIn;
    union {
        Quote_Out quoteResult;
        byte maxOutput[MAX_RESPONSE_SIZE];
    } cmdOut;
    TPM_ALG_ID paramEncAlg = TPM_ALG_NULL;
    WOLFTPM2_SESSION tpmSession;
#if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_FILESYSTEM)
    XFILE f;
#endif

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

        /* Advanced usage */
        if (argv[1][0] != '-') {
            if (pcrIndex < 0 || pcrIndex > 23 || *argv[1] < '0' || *argv[1] > '9') {
                printf("PCR index is out of range (0-23)\n");
                usage();
                return 0;
            }
            pcrIndex = atoi(argv[1]);
        }
        if (argc >= 3 && argv[2][0] != '-')
            outputFile = argv[2];
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

    printf("PCR Quote example - Demo of signed PCR measurement\n");
    printf("\tOutput file: %s\n", outputFile);
    printf("\tPCR Index: %d\n", pcrIndex);
    printf("\tUse %s SRK/AIK\n", TPM2_GetAlgName(alg));
    printf("\tUse Parameter Encryption: %s\n", TPM2_GetAlgName(paramEncAlg));

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_Init failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    printf("wolfTPM2_Init: success\n");

    /* Create Endorsement Key, also called EK */
    rc = wolfTPM2_CreateEK(&dev, &endorse, alg);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_CreateEK: Endorsement failed 0x%x: %s\n",
            rc, TPM2_GetRCString(rc));
        goto exit;
    }
    printf("wolfTPM2_CreateEK: Endorsement 0x%x (%d bytes)\n",
        (word32)endorse.handle.hndl, endorse.pub.size);

    /* get SRK */
    rc = getPrimaryStoragekey(&dev, &storage, alg);
    if (rc != 0) goto exit;

    /* Create key for Attestation purposes */
    rc = wolfTPM2_CreateAndLoadAIK(&dev, &aik, alg, &storage,
        (const byte*)gUsageAuth, sizeof(gUsageAuth)-1);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_CreateAndLoadAIK failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    printf("wolfTPM2_CreateAndLoadAIK: AIK 0x%x (%d bytes)\n",
        (word32)aik.handle.hndl, aik.pub.size);

    if (paramEncAlg != TPM_ALG_NULL) {
        /* Start an authenticated session (salted / unbound) with parameter encryption */
        rc = wolfTPM2_StartSession(&dev, &tpmSession, &storage, NULL,
            TPM_SE_HMAC, paramEncAlg);
        if (rc != 0) goto exit;
        printf("TPM2_StartAuthSession: sessionHandle 0x%x\n",
            (word32)tpmSession.handle.hndl);

        /* set session for authorization of the storage key */
        rc = wolfTPM2_SetAuthSession(&dev, 1, &tpmSession,
            (TPMA_SESSION_decrypt | TPMA_SESSION_encrypt | TPMA_SESSION_continueSession));
        if (rc != 0) goto exit;
    }

    /* set auth for using the AIK */
    wolfTPM2_SetAuthHandle(&dev, 0, &aik.handle);

    /* Prepare Quote request */
    XMEMSET(&cmdIn.quoteAsk, 0, sizeof(cmdIn.quoteAsk));
    XMEMSET(&cmdOut.quoteResult, 0, sizeof(cmdOut.quoteResult));
    cmdIn.quoteAsk.signHandle = aik.handle.hndl;
    cmdIn.quoteAsk.inScheme.scheme = alg == TPM_ALG_RSA ? TPM_ALG_RSASSA : TPM_ALG_ECDSA;
    cmdIn.quoteAsk.inScheme.details.any.hashAlg = TPM_ALG_SHA256;
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

    /* Save quote blob to the disk */
    data = (UINT8*)&cmdOut.quoteResult.quoted;
    data += sizeof(UINT16); /* skip the size field of TPMS_ATTEST */
    dataSz = (int)sizeof(TPMS_ATTEST) - sizeof(UINT16);
#if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_FILESYSTEM)
    f = XFOPEN(outputFile, "wb");
    if (f != XBADFILE) {
        dataSz = (int)XFWRITE(data, 1, dataSz, f);
        XFCLOSE(f);
    }
    printf("Wrote %d bytes to %s\n", dataSz, outputFile);
#else
    printf("Quote Blob %d\n", dataSz);
    TPM2_PrintBin(data, dataSz);
    (void)data;
    (void)dataSz;
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
    wolfTPM2_UnloadHandle(&dev, &aik.handle);
    wolfTPM2_UnloadHandle(&dev, &storage.handle);
    wolfTPM2_UnloadHandle(&dev, &endorse.handle);
    wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);

    wolfTPM2_Cleanup(&dev);
    return rc;
}

/******************************************************************************/
/* --- END TPM2.0 Quote Test -- */
/******************************************************************************/

#endif /* !WOLFTPM2_NO_WRAPPER */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = -1;

#ifndef WOLFTPM2_NO_WRAPPER
    rc = TPM2_Quote_Test(NULL, argc, argv);
#else
    printf("Wrapper code not compiled in\n");
    (void)argc;
    (void)argv;
#endif /* !WOLFTPM2_NO_WRAPPER */
    return rc;
}
#endif
