/* nvauth.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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

/* Example for an NV Index that can be read without a password, while write
 * and delete require the owner hierarchy authorization.
 *
 * Read uses TPMA_NV_AUTHREAD with an empty NV Index auth.
 * Write uses TPMA_NV_OWNERWRITE (owner password), or with -policy
 * TPMA_NV_POLICYWRITE with PolicyCommandCode(NV_Write) + PolicySecret(owner).
 * Delete (NV_UndefineSpace) always requires the owner hierarchy auth.
 *
 * The owner auth can be rotated with TPM2_HierarchyChangeAuth using only the
 * current owner auth. The NV Index is bound to the owner hierarchy handle, not
 * its auth value, so it is not affected by rotation (see -rotate).
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

/******************************************************************************/
/* --- BEGIN TPM NVRAM Owner Auth Example -- */
/******************************************************************************/
static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/nvram/nvauth [-ownerauth=<pw>] [-rotate=<newpw>] "
           "[-policy] [-aes/-xor]\n");
    printf("* -ownerauth=<pw>: Current owner hierarchy auth (default empty)\n");
    printf("* -rotate=<newpw>: Change the owner auth after the first write, "
           "write again, then restore it\n");
    printf("* -policy: Use a policy (PolicySecret owner) for write instead of "
           "OWNERWRITE\n");
    printf("* -aes/xor: Use Parameter Encryption\n");
}

/* volatile so the compiler cannot drop the clearing of auth values */
static void ForceZero(void* mem, word32 len)
{
    volatile byte* p = (volatile byte*)mem;
    while (len--) {
        *p++ = 0;
    }
}

static int SetOwnerAuth(WOLFTPM2_DEV* dev, WOLFTPM2_HANDLE* owner,
    const char* newAuth)
{
    int rc;
    HierarchyChangeAuth_In in;

    wolfTPM2_SetAuthHandle(dev, 0, owner);

    XMEMSET(&in, 0, sizeof(in));
    in.authHandle = TPM_RH_OWNER;
    in.newAuth.size = (UINT16)XSTRLEN(newAuth);
    XMEMCPY(in.newAuth.buffer, newAuth, in.newAuth.size);
    rc = TPM2_HierarchyChangeAuth(&in);
    if (rc == TPM_RC_SUCCESS) {
        owner->auth.size = in.newAuth.size;
        XMEMCPY(owner->auth.buffer, in.newAuth.buffer, owner->auth.size);
        printf("Owner auth changed (%d bytes)\n", owner->auth.size);
    }
    ForceZero(&in, sizeof(in));
    return rc;
}

#ifndef WOLFTPM2_NO_WOLFCRYPT
/* policyDigest = PolicyCommandCode(TPM_CC_NV_Write) + PolicySecret(owner) */
static int BuildWritePolicy(byte* digest, word32* digestSz)
{
    int rc;
    byte ownerName[4];

    rc = wolfTPM2_PolicyCommandCodeMake(WOLFTPM2_WRAP_DIGEST, digest, digestSz,
        TPM_CC_NV_Write);
    if (rc == 0) {
        /* Name of a permanent handle is the handle value (big-endian) */
        ownerName[0] = (byte)((TPM_RH_OWNER >> 24) & 0xFF);
        ownerName[1] = (byte)((TPM_RH_OWNER >> 16) & 0xFF);
        ownerName[2] = (byte)((TPM_RH_OWNER >> 8) & 0xFF);
        ownerName[3] = (byte)(TPM_RH_OWNER & 0xFF);
        rc = wolfTPM2_PolicyHash(WOLFTPM2_WRAP_DIGEST, digest, digestSz,
            TPM_CC_PolicySecret, ownerName, sizeof(ownerName));
    }
    if (rc == 0) {
        /* empty policyRef */
        rc = wolfTPM2_PolicyRefMake(WOLFTPM2_WRAP_DIGEST, digest, digestSz,
            NULL, 0);
    }
    return rc;
}
#endif

static int WriteData(WOLFTPM2_DEV* dev, WOLFTPM2_HANDLE* owner, word32 nvIndex,
    int usePolicy, const char* data)
{
    int rc;
    WOLFTPM2_NV nv;
    word32 dataSz = (word32)XSTRLEN(data);

    XMEMSET(&nv, 0, sizeof(nv));
    rc = wolfTPM2_NVOpen(dev, &nv, nvIndex, NULL, 0);
    if (rc != TPM_RC_SUCCESS) {
        return rc;
    }

    if (!usePolicy) {
        /* authHandle is the owner hierarchy, not the NV Index */
        nv.handle.hndl = TPM_RH_OWNER;
        XMEMCPY(&nv.handle.auth, &owner->auth, sizeof(nv.handle.auth));
        rc = wolfTPM2_NVWriteAuth(dev, &nv, nvIndex, (byte*)data, dataSz, 0);
    }
    else {
        WOLFTPM2_SESSION policySession;
        PolicySecret_In secIn;
        PolicySecret_Out secOut;

        rc = wolfTPM2_StartSession(dev, &policySession, NULL, NULL,
            TPM_SE_POLICY, TPM_ALG_NULL);
        if (rc != TPM_RC_SUCCESS) {
            return rc;
        }
        /* Must match the order used in BuildWritePolicy */
        rc = wolfTPM2_PolicyCommandCode(dev, &policySession, TPM_CC_NV_Write);
        if (rc == TPM_RC_SUCCESS) {
            /* PolicySecret is authorized with the owner auth (slot 0) */
            wolfTPM2_SetAuthHandle(dev, 0, owner);
            XMEMSET(&secIn, 0, sizeof(secIn));
            secIn.authHandle = TPM_RH_OWNER;
            secIn.policySession = policySession.handle.hndl;
            rc = TPM2_PolicySecret(&secIn, &secOut);
        }
        if (rc == TPM_RC_SUCCESS) {
            rc = wolfTPM2_SetAuthSession(dev, 0, &policySession,
                TPMA_SESSION_continueSession);
        }
        if (rc == TPM_RC_SUCCESS) {
            /* No PCR's, the policy session is already satisfied */
            rc = wolfTPM2_NVWriteAuthPolicy(dev, &policySession, TPM_ALG_NULL,
                NULL, 0, &nv, nvIndex, (byte*)data, dataSz, 0);
        }
        wolfTPM2_SetAuthPassword(dev, 0, NULL);
        wolfTPM2_UnloadHandle(dev, &policySession.handle);
    }
    if (rc == TPM_RC_SUCCESS) {
        printf("Wrote %d bytes to NV index 0x%x\n", dataSz, nvIndex);
    }
    ForceZero(&nv, sizeof(nv));
    return rc;
}

static int ReadData(WOLFTPM2_DEV* dev, word32 nvIndex, const char* expected)
{
    int rc;
    WOLFTPM2_NV nv;
    byte buf[64];
    word32 bufSz = (word32)XSTRLEN(expected);

    if (bufSz >= sizeof(buf)) {
        return BUFFER_E;
    }
    /* No password: TPMA_NV_AUTHREAD with an empty NV Index auth */
    wolfTPM2_SetAuthPassword(dev, 0, NULL);
    XMEMSET(&nv, 0, sizeof(nv));
    rc = wolfTPM2_NVOpen(dev, &nv, nvIndex, NULL, 0);
    if (rc == TPM_RC_SUCCESS) {
        rc = wolfTPM2_NVReadAuth(dev, &nv, nvIndex, buf, &bufSz, 0);
    }
    if (rc == TPM_RC_SUCCESS) {
        buf[bufSz] = '\0';
        printf("Read %d bytes from NV index 0x%x (no auth): %s\n",
            bufSz, nvIndex, buf);
        if (XSTRCMP((char*)buf, expected) != 0) {
            printf("NV data mismatch\n");
            rc = TPM_RC_FAILURE;
        }
    }
    return rc;
}

int TPM2_NVRAM_Auth_Example(void* userCtx, int argc, char *argv[])
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_SESSION tpmSession;
    WOLFTPM2_HANDLE owner;
    WOLFTPM2_NV nv;
    word32 nvIndex = TPM2_DEMO_NVRAM_AUTH_INDEX;
    word32 nvAttributes;
    const char* ownerAuthStr = "";
    const char* rotateAuthStr = NULL;
    int usePolicy = 0;
    int rotated = 0;
    int paramEncAlg = TPM_ALG_NULL;
    byte policyDigest[TPM_MAX_DIGEST_SIZE];
    word32 policyDigestSz = 0;

    if (argc >= 2) {
        if (XSTRCMP(argv[1], "-?") == 0 ||
            XSTRCMP(argv[1], "-h") == 0 ||
            XSTRCMP(argv[1], "--help") == 0) {
            usage();
            return 0;
        }
    }
    while (argc > 1) {
        if (XSTRNCMP(argv[argc-1], "-ownerauth=",
                XSTRLEN("-ownerauth=")) == 0) {
            ownerAuthStr = argv[argc-1] + XSTRLEN("-ownerauth=");
        }
        else if (XSTRNCMP(argv[argc-1], "-rotate=",
                XSTRLEN("-rotate=")) == 0) {
            rotateAuthStr = argv[argc-1] + XSTRLEN("-rotate=");
        }
        else if (XSTRCMP(argv[argc-1], "-policy") == 0) {
            usePolicy = 1;
        }
        else if (XSTRCMP(argv[argc-1], "-aes") == 0) {
            paramEncAlg = TPM_ALG_CFB;
        }
        else if (XSTRCMP(argv[argc-1], "-xor") == 0) {
            paramEncAlg = TPM_ALG_XOR;
        }
        else {
            printf("Warning: Unrecognized option: %s\n", argv[argc-1]);
        }
        argc--;
    }
    if (XSTRLEN(ownerAuthStr) > sizeof(owner.auth.buffer) ||
        (rotateAuthStr != NULL &&
            XSTRLEN(rotateAuthStr) > sizeof(owner.auth.buffer))) {
        printf("Owner auth too long\n");
        return BAD_FUNC_ARG;
    }
#ifdef WOLFTPM2_NO_WOLFCRYPT
    if (usePolicy) {
        printf("Policy mode requires wolfCrypt\n");
        return NOT_COMPILED_IN;
    }
#endif

    printf("NV Index 0x%x: read without auth, %s write, owner auth delete\n",
        nvIndex, usePolicy ? "policy (PolicySecret owner)" : "owner auth");
    printf("\tParameter Encryption: %s\n", TPM2_GetAlgName(paramEncAlg));

    XMEMSET(&tpmSession, 0, sizeof(tpmSession));
    XMEMSET(&owner, 0, sizeof(owner));

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("\nwolfTPM2_Init failed\n");
        return rc;
    }

    owner.hndl = TPM_RH_OWNER;
    owner.auth.size = (UINT16)XSTRLEN(ownerAuthStr);
    XMEMCPY(owner.auth.buffer, ownerAuthStr, owner.auth.size);

    if (paramEncAlg != TPM_ALG_NULL) {
        /* Start an unbound, unsalted session for parameter encryption */
        rc = wolfTPM2_StartSession(&dev, &tpmSession, NULL, NULL,
            TPM_SE_HMAC, paramEncAlg);
        if (rc == TPM_RC_SUCCESS) {
            rc = wolfTPM2_SetAuthSession(&dev, 1, &tpmSession,
                (TPMA_SESSION_decrypt | TPMA_SESSION_encrypt |
                 TPMA_SESSION_continueSession));
        }
        if (rc != TPM_RC_SUCCESS) goto exit;
    }

    nvAttributes = (TPMA_NV_AUTHREAD | TPMA_NV_NO_DA | TPM_NT_ORDINARY);
    if (usePolicy) {
    #ifndef WOLFTPM2_NO_WOLFCRYPT
        policyDigestSz = (word32)sizeof(policyDigest);
        rc = BuildWritePolicy(policyDigest, &policyDigestSz);
        if (rc != 0) goto exit;
    #endif
        nvAttributes |= TPMA_NV_POLICYWRITE;
    }
    else {
        nvAttributes |= TPMA_NV_OWNERWRITE;
    }

    /* Create the NV Index with an empty auth, re-creating any prior one */
    wolfTPM2_SetAuthHandle(&dev, 0, &owner);
    rc = wolfTPM2_NVCreateAuthPolicy(&dev, &owner, &nv, nvIndex, nvAttributes,
        64, NULL, 0, policyDigest, (int)policyDigestSz);
    if (rc == TPM_RC_NV_DEFINED) {
        rc = wolfTPM2_NVDeleteAuth(&dev, &owner, nvIndex);
        if (rc == TPM_RC_SUCCESS) {
            rc = wolfTPM2_NVCreateAuthPolicy(&dev, &owner, &nv, nvIndex,
                nvAttributes, 64, NULL, 0, policyDigest, (int)policyDigestSz);
        }
    }
    if (rc != TPM_RC_SUCCESS) goto exit;
    printf("Created NV index 0x%x, attributes 0x%x\n", nvIndex, nvAttributes);

    rc = WriteData(&dev, &owner, nvIndex, usePolicy, "first");
    if (rc == TPM_RC_SUCCESS) {
        rc = ReadData(&dev, nvIndex, "first");
    }
    if (rc == TPM_RC_SUCCESS && rotateAuthStr != NULL) {
        rc = SetOwnerAuth(&dev, &owner, rotateAuthStr);
        if (rc == TPM_RC_SUCCESS) {
            rotated = 1;
            rc = WriteData(&dev, &owner, nvIndex, usePolicy, "rotated");
        }
        if (rc == TPM_RC_SUCCESS) {
            rc = ReadData(&dev, nvIndex, "rotated");
        }
    }
    if (rc == TPM_RC_SUCCESS) {
        wolfTPM2_SetAuthHandle(&dev, 0, &owner);
        rc = wolfTPM2_NVDeleteAuth(&dev, &owner, nvIndex);
        if (rc == TPM_RC_SUCCESS) {
            printf("Deleted NV index 0x%x (owner auth)\n", nvIndex);
        }
    }

exit:

    if (rotated) {
        /* restore the original owner auth */
        int rcRestore = SetOwnerAuth(&dev, &owner, ownerAuthStr);
        if (rcRestore != TPM_RC_SUCCESS) {
            printf("Owner auth restore failed 0x%x: %s\n", rcRestore,
                wolfTPM2_GetRCString(rcRestore));
            if (rc == TPM_RC_SUCCESS) {
                rc = rcRestore;
            }
        }
    }

    if (rc != 0) {
        printf("\nFailure 0x%x: %s\n\n", rc, wolfTPM2_GetRCString(rc));
    }

    ForceZero(&owner, sizeof(owner));
    wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);
    wolfTPM2_Cleanup(&dev);

    return rc;
}

/******************************************************************************/
/* --- END TPM NVRAM Owner Auth Example -- */
/******************************************************************************/
#endif /* !WOLFTPM2_NO_WRAPPER */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = NOT_COMPILED_IN;

#ifndef WOLFTPM2_NO_WRAPPER
    rc = TPM2_NVRAM_Auth_Example(NULL, argc, argv);
#else
    printf("NVRAM code not compiled in\n");
    (void)argc;
    (void)argv;
#endif

    return rc;
}
#endif
