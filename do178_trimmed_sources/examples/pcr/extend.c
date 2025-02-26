/* extend.c
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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

/* This is a helper tool for extending hash into a TPM2.0 PCR */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2_wrap.h>

#ifndef WOLFTPM2_NO_WRAPPER

#ifndef WOLFTPM2_NO_WOLFCRYPT
#include <wolfssl/wolfcrypt/hash.h>
#endif

#include <examples/pcr/pcr.h>
#include <examples/tpm_test.h>
#include <hal/tpm_io.h>

#include <stdio.h>


/******************************************************************************/
/* --- BEGIN TPM2.0 PCR Extend example tool  -- */
/******************************************************************************/

static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/pcr/extend [-sha1/-sha256/-sha384/-sha512] [pcr] [filename]\n");
    printf("* pcr: PCR index between 0-23 (default %d)\n", TPM2_TEST_PCR);
    printf("* filename: points to file(data) to measure\n");
    printf("\tIf wolfTPM is built with --disable-wolfcrypt the file\n"
           "\tmust contain SHA256 digest ready for extend operation.\n"
           "\tOtherwise, the extend tool computes the hash using wolfcrypt.\n");
    printf("Demo usage without parameters, extends PCR%d with known hash.\n",
        TPM2_TEST_PCR);
}

int TPM2_PCR_Extend_Test(void* userCtx, int argc, char *argv[])
{
    int i, j, pcrIndex = TPM2_TEST_PCR, rc = -1;
    WOLFTPM2_DEV dev;
    TPM_ALG_ID alg = TPM_ALG_SHA256;
    /* Arbitrary user data provided through a file */
    const char *filename = "input.data";
    int  hashSz;
#if !defined(NO_FILESYSTEM) && !defined(NO_WRITE_TEMP_FILES) && !defined(WOLFTPM2_NO_WOLFCRYPT)
    XFILE fp = NULL;
    size_t len;
    BYTE hash[TPM_MAX_DIGEST_SIZE];

    BYTE dataBuffer[1024];
    enum wc_HashType hashType;
    wc_HashAlg dig;
#endif

    union {
        PCR_Read_In pcrRead;
        PCR_Extend_In pcrExtend;
        byte maxInput[MAX_COMMAND_SIZE];
    } cmdIn;
    union {
        PCR_Read_Out pcrRead;
        byte maxOutput[MAX_RESPONSE_SIZE];
    } cmdOut;

    if (argc >= 2) {
        if (XSTRCMP(argv[1], "-?") == 0 ||
            XSTRCMP(argv[1], "-h") == 0 ||
            XSTRCMP(argv[1], "--help") == 0) {
            usage();
            return 0;
        }
    }

    while (argc > 1) {
        if (XSTRCMP(argv[argc-1], "-sha1") == 0) {
            alg = TPM_ALG_SHA;
        }
        else if (XSTRCMP(argv[argc-1], "-sha256") == 0) {
            alg = TPM_ALG_SHA256;
        }
        else if (XSTRCMP(argv[argc-1], "-sha384") == 0) {
            alg = TPM_ALG_SHA384;
        }
        else if (XSTRCMP(argv[argc-1], "-sha512") == 0) {
            alg = TPM_ALG_SHA512;
        }

        else if (*argv[argc-1] >= '0' && *argv[argc-1] <= '9') {
            pcrIndex = XATOI(argv[argc-1]);
            if (pcrIndex < 0 || pcrIndex > 23) {
                printf("PCR index is out of range (0-23)\n");
                usage();
                return 0;
            }
        }
        else if (*argv[argc-1] != '-') {
            filename = argv[argc-1];
        }
        else {
            printf("Warning: Unrecognized option: %s\n", argv[argc-1]);
        }
        argc--;
    }

    hashSz = TPM2_GetHashDigestSize(alg);

    printf("Demo how to extend data into a PCR (TPM2.0 measurement)\n");
    printf("\tHash Algorithm: %s (sz %d)\n", TPM2_GetAlgName(alg), hashSz);
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
    cmdIn.pcrExtend.digests.digests[0].hashAlg = alg;

    /* Prepare the hash from user file or predefined value */
#if !defined(NO_FILESYSTEM) && !defined(NO_WRITE_TEMP_FILES) && !defined(WOLFTPM2_NO_WOLFCRYPT)
    if (filename) {
        fp = XFOPEN(filename, "rb");
    }
    if (filename && fp != XBADFILE) {
        rc = TPM2_GetHashType(alg);
        hashType = (enum wc_HashType)rc;
        wc_HashInit(&dig, hashType);
        while (!XFEOF(fp)) {
            len = XFREAD(dataBuffer, 1, sizeof(dataBuffer), fp);
            if (len) {
                wc_HashUpdate(&dig, hashType, dataBuffer, (int)len);
            }
        }
        wc_HashFinal(&dig, hashType, hash);

        XMEMCPY(cmdIn.pcrExtend.digests.digests[0].digest.H,
                hash, hashSz);
    }
    else
#endif /* !WOLFTPM2_NO_WOLFCRYPT && !NO_FILESYSTEM */
    {
        printf("Error loading file %s, using test data\n", filename);
        for (i=0; i<hashSz; i++) {
            cmdIn.pcrExtend.digests.digests[0].digest.H[i] = i;
        }
    }

    printf("Hash to be used for measurement:\n");
    for (i=0; i < hashSz; i++)
        printf("%02X", cmdIn.pcrExtend.digests.digests[0].digest.H[i]);
    printf("\n");

    rc = TPM2_PCR_Extend(&cmdIn.pcrExtend);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_PCR_Extend failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_PCR_Extend success\n");

    XMEMSET(&cmdIn.pcrRead, 0, sizeof(cmdIn.pcrRead));
    TPM2_SetupPCRSel(&cmdIn.pcrRead.pcrSelectionIn, alg, pcrIndex);
    rc = TPM2_PCR_Read(&cmdIn.pcrRead, &cmdOut.pcrRead);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_PCR_Read failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    for (i=0; i < (int)cmdOut.pcrRead.pcrValues.count; i++) {
        printf("PCR%d (idx %d) digest:\n", pcrIndex, i);
        for (j=0; j < cmdOut.pcrRead.pcrValues.digests[i].size; j++)
            printf("%02X", cmdOut.pcrRead.pcrValues.digests[i].buffer[j]);
        printf("\n");
    }

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
    rc = TPM2_PCR_Extend_Test(NULL, argc, argv);
#else
    printf("Wrapper code not compiled in\n");
    (void)argc;
    (void)argv;
#endif /* !WOLFTPM2_NO_WRAPPER */

    return rc;
}
#endif
