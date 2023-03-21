/* seal_policy_auth_nv.c
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
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

#ifndef WOLFTPM2_NO_WRAPPER

#ifndef WOLFTPM2_NO_WOLFCRYPT
#include <wolfssl/wolfcrypt/hash.h>
#endif

#include <examples/nvram/nvram.h>
#include <hal/tpm_io.h>
#include <examples/tpm_test.h>
#include <examples/tpm_test_keys.h>

#include <stdio.h>

/******************************************************************************/
/* --- BEGIN TPM2.0 PCR Policy example tool  -- */
/******************************************************************************/

static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/pcr/policy [-aes/xor] [-digest=HEXSTR] [pcr]\n");
    printf("* pcr: PCR index between 0-23 (default %d)\n", 16);
    printf("* -aes/xor: Use Parameter Encryption\n");
}

static const word32 sealNvIndex = TPM2_DEMO_NV_TEST_INDEX;
static const word32 policyDigestNvIndex = TPM2_DEMO_NV_TEST_INDEX + 1;

int TPM2_PCR_Seal_With_Policy_Auth_NV_Test(void* userCtx, int argc, char *argv[])
{
    int i;
    int rc = -1;
    WOLFTPM2_NV nv;
    WOLFTPM2_DEV dev;
    WOLFTPM2_SESSION tpmSession;
    /* default to aes since parm encryption is required */
    TPM_ALG_ID paramEncAlg = TPM_ALG_CFB;
    word32 pcrIndex = 16;
    word32 pcrArray[256];
    word32 pcrArraySz = 0;
    byte secret[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    byte secretOut[16];
    word32 secretOutSz = sizeof(secretOut);

    XMEMSET(&dev, 0, sizeof(WOLFTPM2_DEV));
    XMEMSET(&tpmSession, 0, sizeof(WOLFTPM2_SESSION));
    XMEMSET(&nv, 0, sizeof(nv));

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
        else if (argv[argc-1][0] != '-') {
            /* TODO: Allow selection of multiple PCR's SHA-1 or SHA2-256 */
            pcrIndex = XATOI(argv[argc-1]);
            if (pcrIndex > PCR_LAST) {
                printf("PCR index is out of range (0-23)\n");
                usage();
                return 0;
            }
            pcrArray[pcrArraySz] = pcrIndex;
            pcrArraySz++;
        }
        else {
            printf("Warning: Unrecognized option: %s\n", argv[argc-1]);
        }
        argc--;
    }

    if (pcrArraySz == 0) {
        pcrArray[pcrArraySz] = 16;
        pcrArraySz++;
    }

    printf("Example for sealing data to NV memory with policy authorization\n");
    printf("\tPCR Indicies:");

    for (i = 0; i < (int)pcrArraySz; i++) {
        printf("%d ", pcrArray[i]);
    }

    printf("\n");

    printf("\tUse Parameter Encryption: %s\n", TPM2_GetAlgName(paramEncAlg));

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_Init failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    printf("wolfTPM2_Init: success\n");

    /* session is required for pcr authorization */
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

    /* seal the secret */
    rc = wolfTPM2_SealWithAuthPolicyNV(&dev,
        tpmSession.handle.hndl, TPM_ALG_SHA256, TPM_ALG_SHA256, pcrArray,
        pcrArraySz, secret, sizeof(secret),
        sealNvIndex, policyDigestNvIndex);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_SealWithAuthPolicyNV failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }

    /* reset our session */
    wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);
    wolfTPM2_Cleanup(&dev);
    XMEMSET(&dev, 0, sizeof(WOLFTPM2_DEV));
    XMEMSET(&tpmSession, 0, sizeof(WOLFTPM2_SESSION));

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_Init failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    printf("wolfTPM2_Init: success\n");

    rc = wolfTPM2_StartSession(&dev, &tpmSession, NULL, NULL,
        TPM_SE_POLICY, paramEncAlg);
    if (rc != 0) goto exit;
    printf("TPM2_StartAuthSession: sessionHandle 0x%x\n",
        (word32)tpmSession.handle.hndl);

    /* set session for authorization of the storage key */
    rc = wolfTPM2_SetAuthSession(&dev, 0, &tpmSession,
        (TPMA_SESSION_decrypt | TPMA_SESSION_encrypt | TPMA_SESSION_continueSession));
    if (rc != 0) goto exit;

    nv.handle.hndl = sealNvIndex;

    /* try to unseal with the regular command, should fail */
    rc = wolfTPM2_NVReadAuth(&dev, &nv, sealNvIndex,
        secretOut, &secretOutSz, 0);
    if (rc == TPM_RC_SUCCESS) {
        printf("wolfTPM2_NVReadAuth failed, it should not have allowed a read without PolicyAuthorizeNV 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }

    /* unseal the secret */
    rc = wolfTPM2_UnsealWithAuthPolicyNV(&dev,
        tpmSession.handle.hndl, TPM_ALG_SHA256, pcrArray,
        pcrArraySz, sealNvIndex,
        policyDigestNvIndex, secretOut, &secretOutSz);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_UnsealWithAuthPolicyNV failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }

    if (XMEMCMP(secret, secretOut, sizeof(secret)) != 0) {
        printf("Usealed secret does not match\n");
        goto exit;
    }
    else {
        printf("Usealed secret matches!\n");
    }

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
    rc = TPM2_PCR_Seal_With_Policy_Auth_NV_Test(NULL, argc, argv);
#else
    printf("Wrapper code not compiled in\n");
    (void)argc;
    (void)argv;
#endif /* !WOLFTPM2_NO_WRAPPER */

    return rc;
}
#endif
