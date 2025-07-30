/* policy_nv.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfTPM.
 *
 * wolfTPM is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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

/* Tool and example for storing a TPM key into the TPM's NVRAM
 *
 * NB: This example uses Parameter Encryption to protect the password of the
 *     TPM NVRAM Index, where the private and public parts of a TPM key is stored
 *
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2_wrap.h>

#include <stdio.h>

#ifndef WOLFTPM2_NO_WRAPPER

#include <examples/nvram/nvram.h>
#include <hal/tpm_io.h>
#include <examples/tpm_test.h>
#include <examples/tpm_test_keys.h>

/******************************************************************************/
/* --- BEGIN TPM NVRAM Policy NV Example -- */
/******************************************************************************/

#if 1
#define TPM2_DEMO_POLICY_NVINDEX 0x1500001
#define TPM2_DEMO_POLICY_AUTH    TPM_RH_OWNER
#else
#define TPM2_DEMO_POLICY_NVINDEX 0x1000000
#define TPM2_DEMO_POLICY_AUTH    TPM_RH_PLATFORM
#endif


static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/nvram/policy_nv [-data=] [-nvindex] [-aes/-xor]\n");
    printf("* -data=[filename]: data store (default 1 byte = 0xAA)\n");
    printf("* -nvindex=[handle] (default 0x%x)\n", TPM2_DEMO_POLICY_NVINDEX);
    printf("* -aes/xor: Use Parameter Encryption\n");
}

int TPM2_NVRAM_PolicyNV_Example(void* userCtx, int argc, char *argv[])
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_SESSION tpmSession;
    WOLFTPM2_HANDLE parent;
    WOLFTPM2_NV nv;
    word32 nvAttributes;
    TPMI_RH_NV_AUTH authHandle = TPM2_DEMO_POLICY_AUTH;
    int paramEncAlg = TPM_ALG_NULL;
    word32 nvIndex = TPM2_DEMO_POLICY_NVINDEX;
    TPMA_SESSION sessionAttributes;
    byte* buf = NULL;
    size_t bufLen = 0;
    PolicyNV_In policyNvIn;
    const byte testData[1] = {0xAA};
    const char* filename = NULL;
    TPM2B_AUTH auth;

    if (argc >= 2) {
        if (XSTRCMP(argv[1], "-?") == 0 ||
            XSTRCMP(argv[1], "-h") == 0 ||
            XSTRCMP(argv[1], "--help") == 0) {
            usage();
            return 0;
        }
    }
    while (argc > 1) {
        if (XSTRNCMP(argv[argc-1], "-nvindex=", XSTRLEN("-nvindex=")) == 0) {
            const char* nvIndexStr = argv[argc-1] + XSTRLEN("-nvindex=");
            nvIndex = (word32)XSTRTOUL(nvIndexStr, NULL, 0);
            if (!(authHandle == TPM_RH_PLATFORM && (
                    nvIndex > TPM_20_PLATFORM_MFG_NV_SPACE &&
                    nvIndex < TPM_20_OWNER_NV_SPACE)) &&
                !(authHandle == TPM_RH_OWNER && (
                    nvIndex > TPM_20_OWNER_NV_SPACE &&
                    nvIndex < TPM_20_TCG_NV_SPACE)))
            {
                fprintf(stderr, "Invalid NV Index %s\n", nvIndexStr);
                fprintf(stderr, "\tPlatform Range: 0x%x -> 0x%x\n",
                    TPM_20_PLATFORM_MFG_NV_SPACE, TPM_20_OWNER_NV_SPACE);
                fprintf(stderr, "\tOwner Range: 0x%x -> 0x%x\n",
                    TPM_20_OWNER_NV_SPACE, TPM_20_TCG_NV_SPACE);
                usage();
                return -1;
            }
        }
        else if (XSTRCMP(argv[argc-1], "-aes") == 0) {
            paramEncAlg = TPM_ALG_CFB;
        }
        else if (XSTRCMP(argv[argc-1], "-xor") == 0) {
            paramEncAlg = TPM_ALG_XOR;
        }
        else if (XSTRNCMP(argv[argc-1], "-data=",
                XSTRLEN("-data=")) == 0) {
            filename = argv[argc-1] + XSTRLEN("-data=");
        }
        else {
            printf("Warning: Unrecognized option: %s\n", argv[argc-1]);
        }
        argc--;
    };

    if (paramEncAlg == TPM_ALG_CFB) {
        printf("Parameter Encryption: Enabled. (AES CFB)\n\n");
    }
    else if (paramEncAlg == TPM_ALG_XOR) {
        printf("Parameter Encryption: Enabled. (XOR)\n\n");
    }
    else {
        printf("Parameter Encryption: Not enabled (try -aes or -xor).\n\n");
    }

    XMEMSET(&tpmSession, 0, sizeof(tpmSession));
    XMEMSET(&parent, 0, sizeof(parent));
    XMEMSET(&auth, 0, sizeof(auth));

    auth.size = sizeof(gNvAuth)-1;
    if (auth.size > sizeof(auth.buffer))
        auth.size = sizeof(auth.buffer);
    XMEMCPY(auth.buffer, gNvAuth, auth.size);

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("\nwolfTPM2_Init failed\n");
        goto exit;
    }

    /* Start TPM session and optional parameter encryption */
    rc = wolfTPM2_StartSession(&dev, &tpmSession, NULL, NULL,
            TPM_SE_HMAC, paramEncAlg);
    if (rc != 0) goto exit;
    printf("TPM2_StartAuthSession: sessionHandle 0x%x\n",
        (word32)tpmSession.handle.hndl);

    /* set session for authorization of the storage key */
    sessionAttributes = TPMA_SESSION_continueSession;
    if (paramEncAlg != TPM_ALG_NULL) {
        sessionAttributes |= (TPMA_SESSION_decrypt | TPMA_SESSION_encrypt);
    }

    /* Set TPM session attributes for parameter encryption */
    rc = wolfTPM2_SetAuthSession(&dev, 0, &tpmSession, sessionAttributes);
    if (rc != 0) goto exit;

    if (filename != NULL) {
        rc = loadFile(filename, &buf, &bufLen);
        if (rc != 0) goto exit;
    }
    else {
        buf = (byte*)testData;
        bufLen = (word32)sizeof(testData);
    }
    if (bufLen > (word32)sizeof(policyNvIn.operandB.buffer)) {
        bufLen = (word32)sizeof(policyNvIn.operandB.buffer);
    }

    /* Prepare NV_AUTHWRITE and NV_AUTHREAD attributes necessary for password */
    parent.hndl = authHandle;
    rc = wolfTPM2_GetNvAttributesTemplate(parent.hndl, &nvAttributes);
    if (rc != 0) goto exit;

    /* Our wolfTPM2 wrapper for NV_Define */
    rc = wolfTPM2_NVCreateAuth(&dev, &parent, &nv, nvIndex,
        nvAttributes, (word32)bufLen, auth.buffer, auth.size);
    if (rc != 0 && rc != TPM_RC_NV_DEFINED) goto exit;

    wolfTPM2_SetAuthHandle(&dev, 0, &nv.handle);

    printf("Storing data at TPM NV index 0x%x with password protection\n\n",
        nvIndex);

    rc = wolfTPM2_NVWriteAuth(&dev, &nv, nvIndex, buf, (word32)bufLen, 0);
    if (rc != 0) goto exit;

    printf("Write %d bytes to NV index 0x%x\n", (int)bufLen, nvIndex);

    /* Close session */
    wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);
    wolfTPM2_UnsetAuth(&dev, 1);


    /* BEGIN TPM2_PolicyNV test */

    /* Start TPM policy session and optional parameter encryption */
    rc = wolfTPM2_StartSession(&dev, &tpmSession, NULL, NULL,
            TPM_SE_POLICY, paramEncAlg);
    if (rc != 0) goto exit;
    printf("TPM2_StartAuthSession: sessionHandle 0x%x\n",
        (word32)tpmSession.handle.hndl);

    /* Setup PolicyNV Command */
    XMEMSET(&policyNvIn, 0, sizeof(policyNvIn));
    wolfTPM2_SetAuthHandle(&dev, 0, &parent);
    policyNvIn.authHandle = parent.hndl;
    wolfTPM2_SetAuthHandleName(&dev, 1, &nv.handle);
    policyNvIn.nvIndex = nvIndex;
    policyNvIn.policySession = tpmSession.handle.hndl;
    rc = wolfTPM2_SetAuthSession(&dev, 2, &tpmSession, sessionAttributes);
    if (rc != 0) goto exit;

    policyNvIn.offset = 0;
    policyNvIn.operation = TPM_EO_EQ;
    policyNvIn.operandB.size = bufLen;
    XMEMCPY(policyNvIn.operandB.buffer, buf, bufLen);

    rc = TPM2_PolicyNV(&policyNvIn);
    if (rc != 0) goto exit;

    wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);

    /* Test again and it should fail! */
    /* Start TPM policy session and optional parameter encryption */
    rc = wolfTPM2_StartSession(&dev, &tpmSession, NULL, NULL,
            TPM_SE_POLICY, paramEncAlg);
    if (rc != 0) goto exit;
    printf("TPM2_StartAuthSession: sessionHandle 0x%x\n",
        (word32)tpmSession.handle.hndl);
    /* Set TPM session attributes for parameter encryption */
    rc = wolfTPM2_SetAuthSession(&dev, 2, &tpmSession, sessionAttributes);
    if (rc != 0) goto exit;

    /* Setup PolicyNV Command */
    XMEMSET(&policyNvIn, 0, sizeof(policyNvIn));
    wolfTPM2_SetAuthHandle(&dev, 0, &parent);
    policyNvIn.authHandle = parent.hndl;
    wolfTPM2_SetAuthHandleName(&dev, 1, &nv.handle);
    policyNvIn.nvIndex = nvIndex;
    policyNvIn.policySession = tpmSession.handle.hndl;
    rc = wolfTPM2_SetAuthSession(&dev, 2, &tpmSession, sessionAttributes);
    if (rc != 0) goto exit;

    policyNvIn.offset = 0;
    policyNvIn.operation = TPM_EO_EQ;
    policyNvIn.operandB.size = 1;
    policyNvIn.operandB.buffer[0] = 0xBB;
    rc = TPM2_PolicyNV(&policyNvIn);
    if (rc == TPM_RC_POLICY) {
        /* policy failure is expected here */
        rc = 0;
    }
    else {
        printf("The policy NV should have failed here!\n");
        rc = TPM_RC_POLICY;
        goto exit;
    }
    /* END TPM2_PolicyNV test */

    printf("TPM2_PolicyNV test passed\n");

exit:

    if (rc != 0) {
        printf("\nFailure 0x%x: %s\n\n", rc, wolfTPM2_GetRCString(rc));
    }

    if (buf != testData) {
        XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);
    wolfTPM2_Cleanup(&dev);

    return rc;
}

/******************************************************************************/
/* --- END TPM NVRAM Policy NV Example -- */
/******************************************************************************/
#endif /* !WOLFTPM2_NO_WRAPPER */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = NOT_COMPILED_IN;

#ifndef WOLFTPM2_NO_WRAPPER
    rc = TPM2_NVRAM_PolicyNV_Example(NULL, argc, argv);
#else
    printf("NVRAM code not compiled in\n");
    (void)argc;
    (void)argv;
#endif

    return rc;
}
#endif
