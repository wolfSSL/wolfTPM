/* reset.c
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

/* This is a helper tool for reseting the value of a TPM2.0 PCR */

#include <wolftpm/tpm2_wrap.h>

#ifndef WOLFTPM2_NO_WRAPPER

#include <examples/pcr/reset.h>
#include <examples/tpm_io.h>
#include <examples/tpm_test.h>

#include <stdio.h>
#include <stdlib.h> /* atoi */


/******************************************************************************/
/* --- BEGIN TPM2.0 PCR Reset example tool  -- */
/******************************************************************************/

static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/pcr/reset [pcr]\n");
    printf("* pcr is a PCR index between 0-23 (default %d)\n", TPM2_TEST_PCR);
    printf("Demo usage without parameters, resets PCR%d.\n", TPM2_TEST_PCR);
}

int TPM2_Reset_Test(void* userCtx, int argc, char *argv[])
{
    int pcrIndex = TPM2_TEST_PCR, rc = -1;
    WOLFTPM2_DEV dev;

    union {
#ifdef DEBUG_WOLFTPM
        PCR_Read_In pcrRead;
#endif
        PCR_Reset_In pcrReset;
        byte maxInput[MAX_COMMAND_SIZE];
    } cmdIn;
#ifdef DEBUG_WOLFTPM
    union {
        PCR_Read_Out pcrRead;
        byte maxOutput[MAX_RESPONSE_SIZE];
    } cmdOut;
#endif

    if (argc == 2) {
        pcrIndex = atoi(argv[1]);
        if (pcrIndex < 0 || pcrIndex > 23 || *argv[1] < '0' || *argv[1] > '9') {
            printf("PCR index is out of range (0-23)\n");
            usage();
            goto exit_badargs;
        }
    }
    else if (argc == 1) {
        pcrIndex = TPM2_TEST_PCR;
    }
    else {
        printf("Incorrect arguments\n");
        usage();
        goto exit_badargs;
    }

    printf("Demo how to reset a PCR (clear PCR value)\n");
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_Init failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    printf("wolfTPM2_Init: success\n");

    /* Prepare PCR Reset command */
    XMEMSET(&cmdIn.pcrReset, 0, sizeof(cmdIn.pcrReset));
    cmdIn.pcrReset.pcrHandle = pcrIndex;
    printf("Trying to reset PCR%d...\n", cmdIn.pcrReset.pcrHandle);
    rc = TPM2_PCR_Reset(&cmdIn.pcrReset);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_PCR_Reset failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_PCR_Reset success\n");

#ifdef DEBUG_WOLFTPM
    XMEMSET(&cmdIn.pcrRead, 0, sizeof(cmdIn.pcrRead));
    TPM2_SetupPCRSel(&cmdIn.pcrRead.pcrSelectionIn,
        TEST_WRAP_DIGEST, pcrIndex);
    rc = TPM2_PCR_Read(&cmdIn.pcrRead, &cmdOut.pcrRead);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_PCR_Read failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }

    printf("PCR%d digest:\n", pcrIndex);
    TPM2_PrintBin(cmdOut.pcrRead.pcrValues.digests[0].buffer,
                  cmdOut.pcrRead.pcrValues.digests[0].size);
#endif

exit:

    wolfTPM2_Cleanup(&dev);

exit_badargs:

    return rc;
}

/******************************************************************************/
/* --- END TPM2.0 PCR Reset example tool -- */
/******************************************************************************/
#endif /* !WOLFTPM2_NO_WRAPPER */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = -1;

#ifndef WOLFTPM2_NO_WRAPPER
    rc = TPM2_Reset_Test(NULL, argc, argv);
#else
    printf("Wrapper code not compiled in\n");
    (void)argc;
    (void)argv;
#endif /* !WOLFTPM2_NO_WRAPPER */

    return rc;
}
#endif
