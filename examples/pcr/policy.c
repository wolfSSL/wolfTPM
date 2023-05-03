/* policy.c
 *
 * Copyright (C) 2006-2022 wolfSSL Inc.
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

/* This is a helper tool for setting policies on a TPM 2.0 PCR */

#include <wolftpm/tpm2_wrap.h>

#include <stdio.h>

#ifndef WOLFTPM2_NO_WRAPPER

#ifndef WOLFTPM2_NO_WOLFCRYPT
#include <wolfssl/wolfcrypt/hash.h>
#endif

#include "hal/tpm_io.h"
#include <examples/pcr/pcr.h>
#include <examples/tpm_test.h>

static signed char HexCharToByte(signed char ch)
{
    signed char ret = (signed char)ch;
    if (ret >= '0' && ret <= '9')
        ret -= '0';
    else if (ret >= 'A' && ret <= 'F')
        ret -= 'A' - 10;
    else if (ret >= 'a' && ret <= 'f')
        ret -= 'a' - 10;
    else
        ret = -1; /* error case - return code must be signed */
    return ret;
}
static int HexToByte(const char *hex, unsigned char *output, unsigned long sz)
{
    word32 i;
    for (i = 0; i < sz; i++) {
        signed char ch1, ch2;
        ch1 = HexCharToByte(hex[i * 2]);
        ch2 = HexCharToByte(hex[i * 2 + 1]);
        if ((ch1 < 0) || (ch2 < 0)) {
            return -1;
        }
        output[i] = (unsigned char)((ch1 << 4) + ch2);
    }
    return (int)sz;
}


/******************************************************************************/
/* --- BEGIN TPM2.0 PCR Policy example tool  -- */
/******************************************************************************/

static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/pcr/policy [-aes/xor] [-digest=HEXSTR] [pcr]\n");
    printf("* pcr: PCR index between 0-23 (default %d)\n", TPM2_TEST_PCR);
    printf("* -aes/xor: Use Parameter Encryption\n");
    printf("* -digest=[HEXSTR]: SHA-1 or SHA2-256 hash of expected PCR's\n");
}

int TPM2_PCR_Policy_Test(void* userCtx, int argc, char *argv[])
{
    int rc = -1;
    int pcrIndex = TPM2_TEST_PCR;
    WOLFTPM2_DEV dev;
    TPM_ALG_ID paramEncAlg = TPM_ALG_NULL;
    WOLFTPM2_SESSION tpmSession;
    int i;
    byte digest[32];
    word32 digestLen = 0;
    union {
        PolicyPCR_In pcrPolicy;
        PolicyGetDigest_In policyGetDigest;
        PolicyAuthorize_In policyAuth;
        byte maxInput[MAX_COMMAND_SIZE];
    } cmdIn;
    union {
        PolicyGetDigest_Out policyGetDigest;
        byte maxOutput[MAX_RESPONSE_SIZE];
    } cmdOut;

    XMEMSET(&cmdIn, 0, sizeof(cmdIn));
    XMEMSET(&cmdOut, 0, sizeof(cmdOut));
    XMEMSET(&tpmSession, 0, sizeof(tpmSession));

    if (argc >= 2) {
        if (XSTRCMP(argv[1], "-?") == 0 ||
            XSTRCMP(argv[1], "-h") == 0 ||
            XSTRCMP(argv[1], "--help") == 0) {
            usage();
            return 0;
        }
    }
    while (argc > 1) {
        if (XSTRCMP(argv[argc-1], "-aes") == 0) {
            paramEncAlg = TPM_ALG_CFB;
        }
        else if (XSTRCMP(argv[argc-1], "-xor") == 0) {
            paramEncAlg = TPM_ALG_XOR;
        }
        else if (XMEMCMP(argv[argc-1], "-digest=", XSTRLEN("-digest=")) == 0) {
            const char *digestStr, *end;
            digestStr = argv[argc-1] + XSTRLEN("-digest=");
            end = XSTRSTR(digestStr, " ");
            if (end != NULL) {
                digestLen = (word32)(size_t)(end - digestStr);
            }
            else {
                digestLen = (word32)XSTRLEN(digestStr);
            }
            if (digestLen > sizeof(digest)*2) {
                printf("Invalid digest! Must be 16 or 32 bytes of hex like 01020304050607080910111213141516\n");
                usage();
                return 0;
            }
            digestLen = HexToByte(digestStr, digest, digestLen / 2);
        }
        else if (argv[argc-1][0] != '-') {
            /* TODO: Allow selection of multiple PCR's SHA-1 or SHA2-256 */
            pcrIndex = XATOI(argv[argc-1]);
            if (pcrIndex < (int)PCR_FIRST || pcrIndex > (int)PCR_LAST) {
                printf("PCR index is out of range (0-23)\n");
                usage();
                return 0;
            }
        }
        else {
            printf("Warning: Unrecognized option: %s\n", argv[argc-1]);
        }
        argc--;
    }

    printf("Example for setting PCR policies\n");
    printf("\tPCR Index: %d\n", pcrIndex);
    printf("\tDigest Len: %d\n", digestLen);
    printf("\tUse Parameter Encryption: %s\n", TPM2_GetAlgName(paramEncAlg));

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_Init failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    printf("wolfTPM2_Init: success\n");

    if (paramEncAlg != TPM_ALG_NULL) {
        /* Start an authenticated policy session (salted / unbound) */
        rc = wolfTPM2_StartSession(&dev, &tpmSession, NULL, NULL,
            TPM_SE_POLICY, paramEncAlg);
        if (rc != 0) goto exit;
        printf("TPM2_StartAuthSession: sessionHandle 0x%x\n",
            (word32)tpmSession.handle.hndl);

        /* set session for authorization of the storage key */
        rc = wolfTPM2_SetAuthSession(&dev, 0, &tpmSession,
            (TPMA_SESSION_decrypt | TPMA_SESSION_encrypt | TPMA_SESSION_continueSession));
        if (rc != 0) goto exit;
    }

    /* TODO Add wrappers for these API's */
    cmdIn.pcrPolicy.policySession = tpmSession.handle.hndl;
    cmdIn.pcrPolicy.pcrDigest.size = digestLen;
    if (digestLen > 0) {
        XMEMCPY(cmdIn.pcrPolicy.pcrDigest.buffer, digest, digestLen);
    }
    TPM2_SetupPCRSel(&cmdIn.pcrPolicy.pcrs, TPM_ALG_SHA256, pcrIndex);
    //TPM2_SetupPCRSel(&cmdIn.pcrPolicy.pcrs, TPM_ALG_SHA384, pcrIndex);
    rc = TPM2_PolicyPCR(&cmdIn.pcrPolicy);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_PolicyPCR failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_PolicyPCR Set\n");

    /* Policy Get Digest */
    XMEMSET(&cmdIn.policyGetDigest, 0, sizeof(cmdIn.policyGetDigest));
    cmdIn.policyGetDigest.policySession = tpmSession.handle.hndl;
    rc = TPM2_PolicyGetDigest(&cmdIn.policyGetDigest, &cmdOut.policyGetDigest);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_PolicyGetDigest failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }

    printf("TPM2_PolicyGetDigest: size %d\n",
        cmdOut.policyGetDigest.policyDigest.size);
    for (i=0; i < cmdOut.policyGetDigest.policyDigest.size; i++)
        printf("%02X", cmdOut.policyGetDigest.policyDigest.buffer[i]);
    printf("\n");
exit:

    if (rc != 0) {
        printf("Failure 0x%x: %s\n", rc, wolfTPM2_GetRCString(rc));
    }

    wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);
    wolfTPM2_Cleanup(&dev);

    return rc;
}

/******************************************************************************/
/* --- END TPM2.0 PCR Policy example tool -- */
/******************************************************************************/

#endif /* !WOLFTPM2_NO_WRAPPER */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = -1;

#ifndef WOLFTPM2_NO_WRAPPER
    rc = TPM2_PCR_Policy_Test(NULL, argc, argv);
#else
    printf("Wrapper code not compiled in\n");
    (void)argc;
    (void)argv;
#endif /* !WOLFTPM2_NO_WRAPPER */

    return rc;
}
#endif



