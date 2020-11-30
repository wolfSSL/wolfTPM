/* extend.c
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

/* This is a helper tool for extending hash into a TPM2.0 PCR */

#include <wolftpm/tpm2_wrap.h>

#ifndef WOLFTPM2_NO_WRAPPER

#ifndef WOLFTPM2_NO_WOLFCRYPT
#include <wolfssl/wolfcrypt/hash.h>
#endif

#include <examples/pcr/extend.h>
#include <examples/tpm_io.h>
#include <examples/tpm_test.h>

#include <stdio.h>
#include <stdlib.h> /* atoi */


/******************************************************************************/
/* --- BEGIN TPM2.0 PCR Extend example tool  -- */
/******************************************************************************/

static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/pcr/extend [pcr] [filename]\n");
    printf("* pcr: PCR index between 0-23 (default %d)\n", TPM2_TEST_PCR);
    printf("* filename: points to file(data) to measure\n");
    printf("\tIf wolfTPM is built with --disable-wolfcrypt the file\n"
           "\tmust contain SHA256 digest ready for extend operation.\n"
           "\tOtherwise, the extend tool computes the hash using wolfcrypt.\n");
    printf("Demo usage without parameters, extends PCR%d with known hash.\n",
        TPM2_TEST_PCR);
}

int TPM2_Extend_Test(void* userCtx, int argc, char *argv[])
{
    int i, pcrIndex = TPM2_TEST_PCR, rc = -1;
    WOLFTPM2_DEV dev;
    /* Arbitrary user data provided through a file */
    const char *filename = "input.data";
#if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_FILESYSTEM)
    XFILE fp = NULL;
    size_t len;
    BYTE hash[TPM_SHA256_DIGEST_SIZE];
    #if !defined(NO_SHA256)
    /* Using wolfcrypt to hash input data */
    BYTE dataBuffer[1024];
    wc_Sha256 sha256;
    #endif
#endif

    union {
#ifdef DEBUG_WOLFTPM
        PCR_Read_In pcrRead;
#endif
        PCR_Extend_In pcrExtend;
        byte maxInput[MAX_COMMAND_SIZE];
    } cmdIn;
#ifdef DEBUG_WOLFTPM
    union {
        PCR_Read_Out pcrRead;
        byte maxOutput[MAX_RESPONSE_SIZE];
    } cmdOut;
#endif

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
            filename = argv[2];
    }

    printf("Demo how to extend data into a PCR (TPM2.0 measurement)\n");
    printf("\tData file: %s\n", filename);
    printf("\tPCR Index: %d\n", pcrIndex);

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_Init failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    printf("wolfTPM2_Init: success\n");

    /* Prepare PCR Extend command */
    XMEMSET(&cmdIn.pcrExtend, 0, sizeof(cmdIn.pcrExtend));
    cmdIn.pcrExtend.pcrHandle = pcrIndex;
    cmdIn.pcrExtend.digests.count = 1;
    cmdIn.pcrExtend.digests.digests[0].hashAlg = TPM_ALG_SHA256;

    /* Prepare the hash from user file or predefined value */
#if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_FILESYSTEM)
    if (filename) {
        fp = XFOPEN(filename, "rb");
    }
    if (filename && fp) {
#if !defined(NO_SHA256)
        wc_InitSha256(&sha256);
        while (!XFEOF(fp)) {
            len = XFREAD(dataBuffer, 1, sizeof(dataBuffer), fp);
            if (len) {
                wc_Sha256Update(&sha256, dataBuffer, (int)len);
            }
        }
        wc_Sha256Final(&sha256, hash);
#else
        len = XFREAD(hash, 1, TPM_SHA256_DIGEST_SIZE, fp);
        if (len != TPM_SHA256_DIGEST_SIZE) {
            printf("Error while reading SHA256 digest from file.\n");
            goto exit;
        }
#endif
        XMEMCPY(cmdIn.pcrExtend.digests.digests[0].digest.H,
                hash, TPM_SHA256_DIGEST_SIZE);
    }
    else
#endif /* !WOLFTPM2_NO_WOLFCRYPT && !NO_FILESYSTEM */
    {
        printf("Error loading file %s, using test data\n", filename);
        for (i=0; i<TPM_SHA256_DIGEST_SIZE; i++) {
            cmdIn.pcrExtend.digests.digests[0].digest.H[i] = i;
        }
    }

    printf("Hash to be used for measurement:\n");
    for (i=0; i < TPM_SHA256_DIGEST_SIZE; i++)
        printf("%02X", cmdIn.pcrExtend.digests.digests[0].digest.H[i]);
    printf("\n");

    rc = TPM2_PCR_Extend(&cmdIn.pcrExtend);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_PCR_Extend failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_PCR_Extend success\n");

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

    return rc;
}

/******************************************************************************/
/* --- END TPM2.0 PCR Extend example tool -- */
/******************************************************************************/

#endif /* !WOLFTPM2_NO_WRAPPER */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = -1;

#ifndef WOLFTPM2_NO_WRAPPER
    rc = TPM2_Extend_Test(NULL, argc, argv);
#else
    printf("Wrapper code not compiled in\n");
    (void)argc;
    (void)argv;
#endif /* !WOLFTPM2_NO_WRAPPER */

    return rc;
}
#endif
