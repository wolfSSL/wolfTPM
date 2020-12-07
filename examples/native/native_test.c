/* native_test.c
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

/* This example shows using the TPM2_ specification API's in TPM2_Native_Test() */

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_param_enc.h>

#include <examples/native/native_test.h>
#include <examples/tpm_io.h>
#include <examples/tpm_test.h>

#include <stdio.h>

/******************************************************************************/
/* --- BEGIN TPM Native API Tests -- */
/******************************************************************************/

typedef struct tpmKey {
    TPM_HANDLE          handle;
    TPM2B_AUTH          auth;
    TPMT_SYM_DEF_OBJECT symmetric; /* used for parameter encrypt/decrypt */
    TPM2B_PRIVATE       priv;
    TPM2B_PUBLIC        pub;
    TPM2B_NAME          name;
} TpmKey;

typedef TpmKey TpmRsaKey;
typedef TpmKey TpmEccKey;
typedef TpmKey TpmHmacKey;
typedef TpmKey TpmSymKey;

typedef struct tmpHandle {
    TPM_HANDLE         handle;
    TPM2B_AUTH         auth;
} TpmHandle;


int TPM2_Native_Test(void* userCtx)
{
    return TPM2_Native_TestArgs(userCtx, 0, NULL);
}
int TPM2_Native_TestArgs(void* userCtx, int argc, char *argv[])
{
    int rc;
    TPM2_CTX tpm2Ctx;

    union {
        Startup_In startup;
        Shutdown_In shutdown;
        SelfTest_In selfTest;
        GetRandom_In getRand;
        StirRandom_In stirRand;
        GetCapability_In cap;
        IncrementalSelfTest_In incSelfTest;
        PCR_Read_In pcrRead;
        PCR_Extend_In pcrExtend;
        PCR_Reset_In pcrReset;
        CreatePrimary_In createPri;
        Create_In create;
        EvictControl_In evict;
        ReadPublic_In readPub;
        StartAuthSession_In authSes;
        Load_In load;
        LoadExternal_In loadExt;
        FlushContext_In flushCtx;
        Unseal_In unseal;
        PolicyGetDigest_In policyGetDigest;
        PolicyPCR_In policyPCR;
        PolicyRestart_In policyRestart;
        PolicyCommandCode_In policyCC;
        Clear_In clear;
        HashSequenceStart_In hashSeqStart;
        SequenceUpdate_In seqUpdate;
        SequenceComplete_In seqComp;
        MakeCredential_In makeCred;
        ObjectChangeAuth_In objChgAuth;
        NV_ReadPublic_In nvReadPub;
        NV_DefineSpace_In nvDefine;
        NV_UndefineSpace_In nvUndefine;
        RSA_Encrypt_In rsaEnc;
        RSA_Decrypt_In rsaDec;
        Sign_In sign;
        VerifySignature_In verifySign;
        ECC_Parameters_In eccParam;
        ECDH_KeyGen_In ecdh;
        ECDH_ZGen_In ecdhZ;
        EncryptDecrypt2_In encDec;
        HMAC_In hmac;
        HMAC_Start_In hmacStart;
#if defined(WOLFTPM_ST33) || defined(WOLFTPM_AUTODETECT)
        SetCommandSet_In setCmdSet;
#endif
        byte maxInput[MAX_COMMAND_SIZE];
    } cmdIn;
    union {
        GetCapability_Out cap;
        GetRandom_Out getRand;
        GetTestResult_Out tr;
        IncrementalSelfTest_Out incSelfTest;
        ReadClock_Out readClock;
        PCR_Read_Out pcrRead;
        CreatePrimary_Out createPri;
        Create_Out create;
        ReadPublic_Out readPub;
        StartAuthSession_Out authSes;
        Load_Out load;
        LoadExternal_Out loadExt;
        Unseal_Out unseal;
        PolicyGetDigest_Out policyGetDigest;
        HashSequenceStart_Out hashSeqStart;
        SequenceComplete_Out seqComp;
        MakeCredential_Out makeCred;
        ObjectChangeAuth_Out objChgAuth;
        NV_ReadPublic_Out nvReadPub;
        RSA_Encrypt_Out rsaEnc;
        RSA_Decrypt_Out rsaDec;
        Sign_Out sign;
        VerifySignature_Out verifySign;
        ECC_Parameters_Out eccParam;
        ECDH_KeyGen_Out ecdh;
        ECDH_ZGen_Out ecdhZ;
        EncryptDecrypt2_Out encDec;
        HMAC_Out hmac;
        HMAC_Start_Out hmacStart;
        byte maxOutput[MAX_RESPONSE_SIZE];
    } cmdOut;

    int pcrCount, pcrIndex, i;
    TPML_TAGGED_TPM_PROPERTY* tpmProp;
    TPM_HANDLE handle = TPM_RH_NULL;
    TPM_HANDLE sessionHandle = TPM_RH_NULL;
    TPMI_RH_NV_INDEX nvIndex;
    TPM2B_PUBLIC_KEY_RSA message;

#ifndef WOLFTPM2_NO_WOLFCRYPT
    byte pcr[TPM_SHA256_DIGEST_SIZE];
    int pcr_len = TPM_SHA256_DIGEST_SIZE;
    byte hash[TPM_SHA256_DIGEST_SIZE];
    int hash_len = TPM_SHA256_DIGEST_SIZE;
#endif

    TpmRsaKey endorse;
    TpmRsaKey storage;
    TpmHmacKey hmacKey;
    TpmEccKey eccKey;
    TpmRsaKey rsaKey;
    TpmSymKey aesKey;

    const char storagePwd[] = "WolfTPMPassword";
    const char usageAuth[] = "ThisIsASecretUsageAuth";
    const char userKey[] = "ThisIsMyKey";
    const char label[] = "ThisIsMyLabel";
    const char keyCreationNonce[] = "RandomServerPickedCreationNonce";

    const char* hashTestData =
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    const char* hashTestDig =
        "\x24\x8D\x6A\x61\xD2\x06\x38\xB8\xE5\xC0\x26\x93\x0C\x3E\x60"
        "\x39\xA3\x3C\xE4\x59\x64\xFF\x21\x67\xF6\xEC\xED\xD4\x19\xDB"
        "\x06\xC1";

    TPM2_AUTH_SESSION session[MAX_SESSION_NUM];
#ifndef WOLFTPM2_NO_WOLFCRYPT
    TPM2B_AUTH sessionAuth;
#endif

    (void)argc;
    (void)argv;

    printf("TPM2 Demo using Native API's\n");

    endorse.handle = TPM_RH_NULL;
    storage.handle = TPM_RH_NULL;
    hmacKey.handle = TPM_RH_NULL;
    eccKey.handle = TPM_RH_NULL;
    rsaKey.handle = TPM_RH_NULL;
    aesKey.handle = TPM_RH_NULL;

    message.size = TPM_SHA256_DIGEST_SIZE;
    XMEMSET(message.buffer, 0x11, message.size);


    rc = TPM2_Init(&tpm2Ctx, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_Init failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }

    printf("TPM2: Caps 0x%08x, Did 0x%04x, Vid 0x%04x, Rid 0x%2x \n",
        tpm2Ctx.caps,
        tpm2Ctx.did_vid >> 16,
        tpm2Ctx.did_vid & 0xFFFF,
        tpm2Ctx.rid);

    /* define the default session auth */
    XMEMSET(session, 0, sizeof(session));
    session[0].sessionHandle = TPM_RS_PW;
    TPM2_SetSessionAuth(session);

    XMEMSET(&cmdIn.startup, 0, sizeof(cmdIn.startup));
    cmdIn.startup.startupType = TPM_SU_CLEAR;
    rc = TPM2_Startup(&cmdIn.startup);
    if (rc != TPM_RC_SUCCESS &&
        rc != TPM_RC_INITIALIZE /* TPM_RC_INITIALIZE = Already started */ ) {
        printf("TPM2_Startup failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_Startup pass\n");


    /* Full self test */
    XMEMSET(&cmdIn.selfTest, 0, sizeof(cmdIn.selfTest));
    cmdIn.selfTest.fullTest = YES;
    rc = TPM2_SelfTest(&cmdIn.selfTest);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_SelfTest failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_SelfTest pass\n");

    /* Get Test Result */
    rc = TPM2_GetTestResult(&cmdOut.tr);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_GetTestResult failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_GetTestResult: Size %d, Rc 0x%x\n", cmdOut.tr.outData.size,
        cmdOut.tr.testResult);
    TPM2_PrintBin(cmdOut.tr.outData.buffer, cmdOut.tr.outData.size);

    /* Incremental Test */
    XMEMSET(&cmdIn.incSelfTest, 0, sizeof(cmdIn.incSelfTest));
    cmdIn.incSelfTest.toTest.count = 1;
    cmdIn.incSelfTest.toTest.algorithms[0] = TPM_ALG_RSA;
	rc = TPM2_IncrementalSelfTest(&cmdIn.incSelfTest, &cmdOut.incSelfTest);
	printf("TPM2_IncrementalSelfTest: Rc 0x%x, Alg 0x%x (Todo %d)\n",
			rc, cmdIn.incSelfTest.toTest.algorithms[0],
            (int)cmdOut.incSelfTest.toDoList.count);


    /* Get Capability for Property */
    XMEMSET(&cmdIn.cap, 0, sizeof(cmdIn.cap));
    cmdIn.cap.capability = TPM_CAP_TPM_PROPERTIES;
    cmdIn.cap.property = TPM_PT_FAMILY_INDICATOR;
    cmdIn.cap.propertyCount = 1;
    rc = TPM2_GetCapability(&cmdIn.cap, &cmdOut.cap);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_GetCapability failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    tpmProp = &cmdOut.cap.capabilityData.data.tpmProperties;
    printf("TPM2_GetCapability: Property FamilyIndicator 0x%08x\n",
        (unsigned int)tpmProp->tpmProperty[0].value);

    cmdIn.cap.capability = TPM_CAP_TPM_PROPERTIES;
    cmdIn.cap.property = TPM_PT_PCR_COUNT;
    cmdIn.cap.propertyCount = 1;
    rc = TPM2_GetCapability(&cmdIn.cap, &cmdOut.cap);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_GetCapability failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    tpmProp = &cmdOut.cap.capabilityData.data.tpmProperties;
    pcrCount = tpmProp->tpmProperty[0].value;
    printf("TPM2_GetCapability: Property PCR Count %d\n", pcrCount);


    /* Get Capability for Firmware */
    XMEMSET(&cmdIn.cap, 0, sizeof(cmdIn.cap));
    cmdIn.cap.capability = TPM_CAP_TPM_PROPERTIES;
    cmdIn.cap.property = TPM_PT_FIRMWARE_VERSION_1;
    cmdIn.cap.propertyCount = 1;
    rc = TPM2_GetCapability(&cmdIn.cap, &cmdOut.cap);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_GetCapability failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    tpmProp = &cmdOut.cap.capabilityData.data.tpmProperties;
    printf("TPM2_GetCapability: Property FIRMWARE_VERSION_1 0x%08x\n",
        (unsigned int)tpmProp->tpmProperty[0].value);

    cmdIn.cap.capability = TPM_CAP_TPM_PROPERTIES;
    cmdIn.cap.property = TPM_PT_FIRMWARE_VERSION_2;
    cmdIn.cap.propertyCount = 1;
    rc = TPM2_GetCapability(&cmdIn.cap, &cmdOut.cap);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_GetCapability failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    tpmProp = &cmdOut.cap.capabilityData.data.tpmProperties;
    printf("TPM2_GetCapability: Property FIRMWARE_VERSION_2 0x%08x\n",
        (unsigned int)tpmProp->tpmProperty[0].value);


    /* Random */
    XMEMSET(&cmdIn.getRand, 0, sizeof(cmdIn.getRand));
    cmdIn.getRand.bytesRequested = MAX_RNG_REQ_SIZE;
    rc = TPM2_GetRandom(&cmdIn.getRand, &cmdOut.getRand);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_GetRandom failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    if (cmdOut.getRand.randomBytes.size != MAX_RNG_REQ_SIZE) {
        printf("TPM2_GetRandom length mismatch %d != %d\n",
            cmdOut.getRand.randomBytes.size, MAX_RNG_REQ_SIZE);
        goto exit;
    }
    printf("TPM2_GetRandom: Got %d bytes\n", cmdOut.getRand.randomBytes.size);
    TPM2_PrintBin(cmdOut.getRand.randomBytes.buffer,
                   cmdOut.getRand.randomBytes.size);


    /* Stir Random */
    XMEMSET(&cmdIn.stirRand, 0, sizeof(cmdIn.stirRand));
    cmdIn.stirRand.inData.size = cmdOut.getRand.randomBytes.size;
    XMEMCPY(cmdIn.stirRand.inData.buffer,
        cmdOut.getRand.randomBytes.buffer, cmdIn.stirRand.inData.size);
    rc = TPM2_StirRandom(&cmdIn.stirRand);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_StirRandom failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_StirRandom: success\n");


    /* ReadClock */
    XMEMSET(&cmdOut.readClock, 0, sizeof(cmdOut.readClock));
    rc = TPM2_ReadClock(&cmdOut.readClock);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_ReadClock failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_ReadClock: success\n");


    /* PCR Read */
    for (i=0; i<pcrCount; i++) {
        pcrIndex = i;
        XMEMSET(&cmdIn.pcrRead, 0, sizeof(cmdIn.pcrRead));
        TPM2_SetupPCRSel(&cmdIn.pcrRead.pcrSelectionIn,
            TEST_WRAP_DIGEST, pcrIndex);
        rc = TPM2_PCR_Read(&cmdIn.pcrRead, &cmdOut.pcrRead);
        if (rc != TPM_RC_SUCCESS) {
            printf("TPM2_PCR_Read failed 0x%x: %s\n", rc,
                TPM2_GetRCString(rc));
            goto exit;
        }
        printf("TPM2_PCR_Read: Index %d, Count %d\n",
            pcrIndex, (int)cmdOut.pcrRead.pcrValues.count);
        if (cmdOut.pcrRead.pcrValues.count > 0) {
            printf("TPM2_PCR_Read: Index %d, Digest Sz %d, Update Counter %d\n",
                pcrIndex,
                (int)cmdOut.pcrRead.pcrValues.digests[0].size,
                (int)cmdOut.pcrRead.pcrUpdateCounter);
            TPM2_PrintBin(cmdOut.pcrRead.pcrValues.digests[0].buffer,
                          cmdOut.pcrRead.pcrValues.digests[0].size);
        }
    }

    /* PCR Extend and Verify */
    /* Working with PCR16 because of next PCR Reset test */
    pcrIndex = TPM2_TEST_PCR;
    XMEMSET(&cmdIn.pcrExtend, 0, sizeof(cmdIn.pcrExtend));
    cmdIn.pcrExtend.pcrHandle = pcrIndex;
    cmdIn.pcrExtend.digests.count = 1;
    cmdIn.pcrExtend.digests.digests[0].hashAlg = TEST_WRAP_DIGEST;
    for (i=0; i<TPM_SHA256_DIGEST_SIZE; i++) {
        cmdIn.pcrExtend.digests.digests[0].digest.H[i] = i;
    }
    rc = TPM2_PCR_Extend(&cmdIn.pcrExtend);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_PCR_Extend failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_PCR_Extend success\n");

    XMEMSET(&cmdIn.pcrRead, 0, sizeof(cmdIn.pcrRead));
    TPM2_SetupPCRSel(&cmdIn.pcrRead.pcrSelectionIn,
        TEST_WRAP_DIGEST, pcrIndex);
    rc = TPM2_PCR_Read(&cmdIn.pcrRead, &cmdOut.pcrRead);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_PCR_Read failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_PCR_Read: Index %d, Count %d\n",
            pcrIndex, (int)cmdOut.pcrRead.pcrValues.count);
    if (cmdOut.pcrRead.pcrValues.count > 0) {
        printf("TPM2_PCR_Read: Index %d, Digest Sz %d, Update Counter %d\n",
            pcrIndex,
            (int)cmdOut.pcrRead.pcrValues.digests[0].size,
            (int)cmdOut.pcrRead.pcrUpdateCounter);
        TPM2_PrintBin(cmdOut.pcrRead.pcrValues.digests[0].buffer,
                      cmdOut.pcrRead.pcrValues.digests[0].size);
    }

    /* PCR Reset
        Only PCR16(DEBUG) and PCR23(Application specific) can be reset
        in locality 0. This is the only locality supported by wolfTPM.
    */
    pcrIndex = TPM2_TEST_PCR;
    XMEMSET(&cmdIn.pcrReset, 0, sizeof(cmdIn.pcrReset));
    cmdIn.pcrReset.pcrHandle = pcrIndex;
    rc = TPM2_PCR_Reset(&cmdIn.pcrReset);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_PCR_Reset failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_PCR_Reset command success\n");

    /* Read out the PCR and show it is indeed cleared */
    printf("PCR Reset: PCR%d value check after reset\n", pcrIndex);
    XMEMSET(&cmdIn.pcrRead, 0, sizeof(cmdIn.pcrRead));
    TPM2_SetupPCRSel(&cmdIn.pcrRead.pcrSelectionIn,
        TEST_WRAP_DIGEST, pcrIndex);
    rc = TPM2_PCR_Read(&cmdIn.pcrRead, &cmdOut.pcrRead);
    if (rc != TPM_RC_SUCCESS) {
        printf("PCR Reset: Read failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    printf("PCR Reset: PCR%d read successfully after reset\n", pcrIndex);
    if (cmdOut.pcrRead.pcrValues.count > 0) {
        TPM2_PrintBin(cmdOut.pcrRead.pcrValues.digests[0].buffer,
                      cmdOut.pcrRead.pcrValues.digests[0].size);
    }


    /* Start Auth Session */
    XMEMSET(&cmdIn.authSes, 0, sizeof(cmdIn.authSes));
    cmdIn.authSes.tpmKey = TPM_RH_NULL;
    cmdIn.authSes.bind = TPM_RH_NULL;
    cmdIn.authSes.sessionType = TPM_SE_POLICY;
#ifndef WOLFTPM2_NO_WOLFCRYPT
    cmdIn.authSes.symmetric.algorithm = TPM_ALG_AES;
    cmdIn.authSes.symmetric.keyBits.aes = 128;
    cmdIn.authSes.symmetric.mode.aes = TPM_ALG_CFB;
#else
    cmdIn.authSes.symmetric.algorithm = TPM_ALG_NULL;
#endif
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
    session[0].nonceTPM = cmdOut.authSes.nonceTPM;

#ifndef WOLFTPM2_NO_WOLFCRYPT
    /* calculate session key */
    sessionAuth.size = TPM2_GetHashDigestSize(cmdIn.authSes.authHash);
    rc = TPM2_KDFa(cmdIn.authSes.authHash, NULL, "ATH",
            &cmdOut.authSes.nonceTPM, &cmdIn.authSes.nonceCaller,
            sessionAuth.buffer, sessionAuth.size);
    if (rc != sessionAuth.size) {
        printf("KDFa ATH Gen Error %d\n", rc);
        rc = TPM_RC_FAILURE;
        goto exit;
    }
#endif
    printf("TPM2_StartAuthSession: sessionHandle 0x%x\n", (word32)sessionHandle);

    /* Policy Get Digest */
    XMEMSET(&cmdIn.policyGetDigest, 0, sizeof(cmdIn.policyGetDigest));
    cmdIn.policyGetDigest.policySession = sessionHandle;
    rc = TPM2_PolicyGetDigest(&cmdIn.policyGetDigest, &cmdOut.policyGetDigest);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_PolicyGetDigest failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_PolicyGetDigest: size %d\n",
        cmdOut.policyGetDigest.policyDigest.size);
    TPM2_PrintBin(cmdOut.policyGetDigest.policyDigest.buffer,
        cmdOut.policyGetDigest.policyDigest.size);

    /* Read PCR[0] SHA1 */
    pcrIndex = 0;
    XMEMSET(&cmdIn.pcrRead, 0, sizeof(cmdIn.pcrRead));
    TPM2_SetupPCRSel(&cmdIn.pcrRead.pcrSelectionIn, TPM_ALG_SHA1, pcrIndex);
    rc = TPM2_PCR_Read(&cmdIn.pcrRead, &cmdOut.pcrRead);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_PCR_Read failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_PCR_Read: Index %d, Digest Sz %d, Update Counter %d\n",
        pcrIndex,
        (int)cmdOut.pcrRead.pcrValues.digests[0].size,
        (int)cmdOut.pcrRead.pcrUpdateCounter);
    TPM2_PrintBin(cmdOut.pcrRead.pcrValues.digests[0].buffer,
                   cmdOut.pcrRead.pcrValues.digests[0].size);

#ifndef WOLFTPM2_NO_WOLFCRYPT
    /* Hash SHA256 PCR[0] */
    rc = wc_Hash(WC_HASH_TYPE_SHA256, pcr, pcr_len, hash, hash_len);
    if (rc < 0) {
        printf("wc_Hash failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    printf("wc_Hash of PCR[0]: size %d\n", hash_len);
    TPM2_PrintBin(hash, hash_len);

    /* Set Auth Session index 0 */
    session[0].sessionHandle = sessionHandle;
    session[0].sessionAttributes = (TPMA_SESSION_decrypt | TPMA_SESSION_encrypt |
        TPMA_SESSION_continueSession);
    session[0].authHash = WOLFTPM2_WRAP_DIGEST;
    session[0].symmetric.algorithm = TPM_ALG_AES;
    session[0].symmetric.keyBits.aes = 128;
    session[0].symmetric.mode.aes = TPM_ALG_CFB;
    session[0].nonceCaller.size = TPM2_GetHashDigestSize(WOLFTPM2_WRAP_DIGEST);
    session[0].auth = sessionAuth;

    /* Policy PCR */
    pcrIndex = 0;
    XMEMSET(&cmdIn.policyPCR, 0, sizeof(cmdIn.policyPCR));
    cmdIn.policyPCR.policySession = sessionHandle;
    cmdIn.policyPCR.pcrDigest.size = hash_len;
    XMEMCPY(cmdIn.policyPCR.pcrDigest.buffer, hash, hash_len);
    TPM2_SetupPCRSel(&cmdIn.policyPCR.pcrs, TPM_ALG_SHA1, pcrIndex);
    rc = TPM2_PolicyPCR(&cmdIn.policyPCR);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_PolicyPCR failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        //goto exit; /* TODO: Fix failure on TPM2_PolicyPCR */
    }
    else {
        printf("TPM2_PolicyPCR: Updated\n");
    }
    XMEMSET(&session[0], 0, sizeof(TPM2_AUTH_SESSION));
    session[0].sessionHandle = TPM_RS_PW;
#endif

    /* Policy Restart (for session) */
    XMEMSET(&cmdIn.policyRestart, 0, sizeof(cmdIn.policyRestart));
    cmdIn.policyRestart.sessionHandle = sessionHandle;
    rc = TPM2_PolicyRestart(&cmdIn.policyRestart);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_PolicyRestart failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_PolicyRestart: Done\n");


    /* Hashing */
    XMEMSET(&cmdIn.hashSeqStart, 0, sizeof(cmdIn.hashSeqStart));
    cmdIn.hashSeqStart.auth.size = sizeof(usageAuth)-1;
    XMEMCPY(cmdIn.hashSeqStart.auth.buffer, usageAuth,
        cmdIn.hashSeqStart.auth.size);
    cmdIn.hashSeqStart.hashAlg = TPM_ALG_SHA256;
    rc = TPM2_HashSequenceStart(&cmdIn.hashSeqStart, &cmdOut.hashSeqStart);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_HashSequenceStart failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    handle = cmdOut.hashSeqStart.sequenceHandle;
    printf("TPM2_HashSequenceStart: sequenceHandle 0x%x\n", (word32)handle);

    /* set auth for hashing handle */
    session[0].auth.size = sizeof(usageAuth)-1;
    XMEMCPY(session[0].auth.buffer, usageAuth, session[0].auth.size);

    XMEMSET(&cmdIn.seqUpdate, 0, sizeof(cmdIn.seqUpdate));
    cmdIn.seqUpdate.sequenceHandle = handle;
    cmdIn.seqUpdate.buffer.size = XSTRLEN(hashTestData);
    XMEMCPY(cmdIn.seqUpdate.buffer.buffer, hashTestData,
        cmdIn.seqUpdate.buffer.size);
    rc = TPM2_SequenceUpdate(&cmdIn.seqUpdate);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_SequenceUpdate failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }

    XMEMSET(&cmdIn.seqComp, 0, sizeof(cmdIn.seqComp));
    cmdIn.seqComp.sequenceHandle = handle;
    cmdIn.seqComp.hierarchy = TPM_RH_NULL;
    rc = TPM2_SequenceComplete(&cmdIn.seqComp, &cmdOut.seqComp);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_SequenceComplete failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    if (cmdOut.seqComp.result.size != TPM_SHA256_DIGEST_SIZE &&
        XMEMCMP(cmdOut.seqComp.result.buffer, hashTestDig,
                                                TPM_SHA256_DIGEST_SIZE) != 0) {
        printf("Hash SHA256 test failed, result not as expected!\n");
        goto exit;
    }
    printf("Hash SHA256 test success\n");

    /* clear session auth */
    session[0].auth.size = 0;
    XMEMSET(session[0].auth.buffer, 0, sizeof(session[0].auth.buffer));



#if 0
    /* Clear Owner */
    cmdIn.clear.authHandle = TPM_RH_PLATFORM;
    rc = TPM2_Clear(&cmdIn.clear);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_Clear failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_Clear Owner\n");
#endif


    /* Create Primary (Endorsement) */
    XMEMSET(&cmdIn.createPri, 0, sizeof(cmdIn.createPri));
    cmdIn.createPri.primaryHandle = TPM_RH_ENDORSEMENT;
    cmdIn.createPri.inPublic.publicArea.authPolicy.size =
        sizeof(TPM_20_EK_AUTH_POLICY);
    XMEMCPY(cmdIn.createPri.inPublic.publicArea.authPolicy.buffer,
        TPM_20_EK_AUTH_POLICY,
        cmdIn.createPri.inPublic.publicArea.authPolicy.size);
    cmdIn.createPri.inPublic.publicArea.type = TPM_ALG_RSA;
    cmdIn.createPri.inPublic.publicArea.unique.rsa.size = MAX_RSA_KEY_BITS / 8;
    cmdIn.createPri.inPublic.publicArea.nameAlg = TPM_ALG_SHA256;
    cmdIn.createPri.inPublic.publicArea.objectAttributes = (
        TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent |
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_adminWithPolicy |
        TPMA_OBJECT_restricted | TPMA_OBJECT_decrypt);
    cmdIn.createPri.inPublic.publicArea.parameters.rsaDetail.keyBits = MAX_RSA_KEY_BITS;
    cmdIn.createPri.inPublic.publicArea.parameters.rsaDetail.exponent = 0;
    cmdIn.createPri.inPublic.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
    cmdIn.createPri.inPublic.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
    cmdIn.createPri.inPublic.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
    cmdIn.createPri.inPublic.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_CFB;
    rc = TPM2_CreatePrimary(&cmdIn.createPri, &cmdOut.createPri);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_CreatePrimary: Endorsement failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    endorse.handle = cmdOut.createPri.objectHandle;
    endorse.auth = cmdIn.createPri.inPublic.publicArea.authPolicy;
    endorse.pub = cmdOut.createPri.outPublic;
    endorse.name = cmdOut.createPri.name;
    endorse.symmetric = cmdIn.createPri.inPublic.publicArea.parameters.rsaDetail.symmetric;
    printf("TPM2_CreatePrimary: Endorsement 0x%x (%d bytes)\n",
        (word32)endorse.handle, endorse.pub.size);


    /* Create Primary (Storage) */
    XMEMSET(&cmdIn.createPri, 0, sizeof(cmdIn.createPri));
    cmdIn.createPri.primaryHandle = TPM_RH_OWNER;
    cmdIn.createPri.inSensitive.sensitive.userAuth.size = sizeof(storagePwd)-1;
    XMEMCPY(cmdIn.createPri.inSensitive.sensitive.userAuth.buffer,
        storagePwd, cmdIn.createPri.inSensitive.sensitive.userAuth.size);
    cmdIn.createPri.inPublic.publicArea.type = TPM_ALG_RSA;
    cmdIn.createPri.inPublic.publicArea.unique.rsa.size = MAX_RSA_KEY_BITS / 8;
    cmdIn.createPri.inPublic.publicArea.nameAlg = TPM_ALG_SHA256;
    cmdIn.createPri.inPublic.publicArea.objectAttributes = (
        TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent |
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_restricted | TPMA_OBJECT_decrypt | TPMA_OBJECT_noDA);
    cmdIn.createPri.inPublic.publicArea.parameters.rsaDetail.keyBits = MAX_RSA_KEY_BITS;
    cmdIn.createPri.inPublic.publicArea.parameters.rsaDetail.exponent = 0;
    cmdIn.createPri.inPublic.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
    cmdIn.createPri.inPublic.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
    cmdIn.createPri.inPublic.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
    cmdIn.createPri.inPublic.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_CFB;
    rc = TPM2_CreatePrimary(&cmdIn.createPri, &cmdOut.createPri);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_CreatePrimary: Storage failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    storage.handle = cmdOut.createPri.objectHandle;
    storage.pub = cmdOut.createPri.outPublic;
    storage.name = cmdOut.createPri.name;
    printf("TPM2_CreatePrimary: Storage 0x%x (%d bytes)\n",
        (word32)storage.handle, storage.pub.size);

#if 0
    /* Move new primary key into NV to persist */
    cmdIn.evict.auth = endorse.handle;
    cmdIn.evict.objectHandle = storage.handle;
    cmdIn.evict.persistentHandle;
    rc = TPM2_EvictControl(&cmdIn.evict);
#endif


    /* set session auth for storage key */
    session[0].auth.size = sizeof(storagePwd)-1;
    XMEMCPY(session[0].auth.buffer, storagePwd, session[0].auth.size);


    /* Load public key */
    XMEMSET(&cmdIn.loadExt, 0, sizeof(cmdIn.loadExt));
    cmdIn.loadExt.inPublic = endorse.pub;
    cmdIn.loadExt.hierarchy = TPM_RH_NULL;
    rc = TPM2_LoadExternal(&cmdIn.loadExt, &cmdOut.loadExt);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_LoadExternal: failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    handle = cmdOut.loadExt.objectHandle;
    printf("TPM2_LoadExternal: 0x%x\n", (word32)handle);

    /* Make a credential */
    XMEMSET(&cmdIn.makeCred, 0, sizeof(cmdIn.makeCred));
    cmdIn.makeCred.handle = handle;
    cmdIn.makeCred.credential.size = TPM_SHA256_DIGEST_SIZE;
    XMEMSET(cmdIn.makeCred.credential.buffer, 0x11,
        cmdIn.makeCred.credential.size);
    cmdIn.makeCred.objectName = endorse.name;
    rc = TPM2_MakeCredential(&cmdIn.makeCred, &cmdOut.makeCred);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_MakeCredential: failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_MakeCredential: credentialBlob %d, secret %d\n",
        cmdOut.makeCred.credentialBlob.size,
        cmdOut.makeCred.secret.size);


    /* Read public key */
    XMEMSET(&cmdIn.readPub, 0, sizeof(cmdIn.readPub));
    cmdIn.readPub.objectHandle = handle;
    rc = TPM2_ReadPublic(&cmdIn.readPub, &cmdOut.readPub);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_ReadPublic failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_ReadPublic Handle 0x%x: pub %d, name %d, qualifiedName %d\n",
        (word32)cmdIn.readPub.objectHandle,
        cmdOut.readPub.outPublic.size, cmdOut.readPub.name.size,
        cmdOut.readPub.qualifiedName.size);

    cmdIn.flushCtx.flushHandle = handle;
    handle = TPM_RH_NULL;
    TPM2_FlushContext(&cmdIn.flushCtx);


    /* HMAC Example */
    /* set session auth for storage key */
    session[0].auth.size = sizeof(storagePwd)-1;
    XMEMCPY(session[0].auth.buffer, storagePwd, session[0].auth.size);

    /* Create an HMAC-SHA256 Key */
    XMEMSET(&cmdIn.create, 0, sizeof(cmdIn.create));
    cmdIn.create.parentHandle = storage.handle;
    cmdIn.create.inSensitive.sensitive.userAuth.size = sizeof(usageAuth)-1;
    XMEMCPY(cmdIn.create.inSensitive.sensitive.userAuth.buffer, usageAuth,
        cmdIn.create.inSensitive.sensitive.userAuth.size);
    cmdIn.create.inSensitive.sensitive.data.size = sizeof(userKey)-1;
    XMEMCPY(cmdIn.create.inSensitive.sensitive.data.buffer, userKey,
        cmdIn.create.inSensitive.sensitive.data.size);
    cmdIn.create.inPublic.publicArea.type = TPM_ALG_KEYEDHASH;
    cmdIn.create.inPublic.publicArea.nameAlg = TPM_ALG_SHA256;
    cmdIn.create.inPublic.publicArea.objectAttributes = (
        TPMA_OBJECT_userWithAuth | TPMA_OBJECT_sign | TPMA_OBJECT_noDA);
    cmdIn.create.inPublic.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM_ALG_HMAC;
    cmdIn.create.inPublic.publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg = TPM_ALG_SHA256;
    rc = TPM2_Create(&cmdIn.create, &cmdOut.create);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_Create HMAC failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    hmacKey.pub = cmdOut.create.outPublic;
    hmacKey.priv = cmdOut.create.outPrivate;
    printf("Create HMAC-SHA256 Key success, public %d, Private %d\n",
        hmacKey.pub.size, hmacKey.priv.size);

    XMEMSET(&cmdIn.load, 0, sizeof(cmdIn.load));
    cmdIn.load.parentHandle = storage.handle;
    cmdIn.load.inPrivate = hmacKey.priv;
    cmdIn.load.inPublic = hmacKey.pub;
    rc = TPM2_Load(&cmdIn.load, &cmdOut.load);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_Load failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    hmacKey.handle = cmdOut.load.objectHandle;
    printf("TPM2_Load New HMAC Key Handle 0x%x\n", (word32)hmacKey.handle);

    /* set auth for HMAC handle */
    session[0].auth.size = sizeof(usageAuth)-1;
    XMEMCPY(session[0].auth.buffer, usageAuth, session[0].auth.size);

    /* TODO: Add simple HMAC test */
#if 0
    rc = TPM2_HMAC(&cmdIn.hmac, &cmdOut.hmac);
    rc = TPM2_HMAC_Start(&cmdIn.hmacStart, &cmdOut.hmacStart);
#endif


    /* Allow object change auth */
    XMEMSET(&cmdIn.policyCC, 0, sizeof(cmdIn.policyCC));
    cmdIn.policyCC.policySession = sessionHandle;
    cmdIn.policyCC.code = TPM_CC_ObjectChangeAuth;
    rc = TPM2_PolicyCommandCode(&cmdIn.policyCC);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_PolicyCommandCode failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_PolicyCommandCode: success\n");

    /* Change Object Auth */
    XMEMSET(&cmdIn.objChgAuth, 0, sizeof(cmdIn.objChgAuth));
    cmdIn.objChgAuth.objectHandle = hmacKey.handle;
    cmdIn.objChgAuth.parentHandle = storage.handle;
    cmdIn.objChgAuth.newAuth.size = TPM_SHA256_DIGEST_SIZE;
    rc = TPM2_GetNonce(cmdIn.objChgAuth.newAuth.buffer,
                       cmdIn.objChgAuth.newAuth.size);
    if (rc < 0) {
        printf("TPM2_GetNonce failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    rc = TPM2_ObjectChangeAuth(&cmdIn.objChgAuth, &cmdOut.objChgAuth);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_ObjectChangeAuth failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        //goto exit;
    }
    hmacKey.priv = cmdOut.objChgAuth.outPrivate;
    printf("TPM2_ObjectChangeAuth: private %d\n", hmacKey.priv.size);

    /* done with hmac handle */
    cmdIn.flushCtx.flushHandle = hmacKey.handle;
    hmacKey.handle = TPM_RH_NULL;
    TPM2_FlushContext(&cmdIn.flushCtx);



    /* set session auth for storage key */
    session[0].auth.size = sizeof(storagePwd)-1;
    XMEMCPY(session[0].auth.buffer, storagePwd, session[0].auth.size);


    /* Get a curve's parameters */
    XMEMSET(&cmdIn.eccParam, 0, sizeof(cmdIn.eccParam));
    cmdIn.eccParam.curveID = TPM_ECC_NIST_P256;
    rc = TPM2_ECC_Parameters(&cmdIn.eccParam, &cmdOut.eccParam);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_ECC_Parameters failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_ECC_Parameters: CurveID %d, sz %d, p %d, a %d, b %d, "
            "gX %d, gY %d, n %d, h %d\n",
        cmdOut.eccParam.parameters.curveID,
        cmdOut.eccParam.parameters.keySize,
        cmdOut.eccParam.parameters.p.size,
        cmdOut.eccParam.parameters.a.size,
        cmdOut.eccParam.parameters.b.size,
        cmdOut.eccParam.parameters.gX.size,
        cmdOut.eccParam.parameters.gY.size,
        cmdOut.eccParam.parameters.n.size,
        cmdOut.eccParam.parameters.h.size);


    /* Create an ECDSA key */
    XMEMSET(&cmdIn.create, 0, sizeof(cmdIn.create));
    cmdIn.create.parentHandle = storage.handle;
    cmdIn.create.inSensitive.sensitive.userAuth.size = sizeof(usageAuth)-1;
    XMEMCPY(cmdIn.create.inSensitive.sensitive.userAuth.buffer, usageAuth,
        cmdIn.create.inSensitive.sensitive.userAuth.size);
    cmdIn.create.inPublic.publicArea.type = TPM_ALG_ECC;
    cmdIn.create.inPublic.publicArea.nameAlg = TPM_ALG_SHA256;
    cmdIn.create.inPublic.publicArea.objectAttributes = (
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_sign | TPMA_OBJECT_noDA);
    cmdIn.create.inPublic.publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
    cmdIn.create.inPublic.publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_ECDSA;
    cmdIn.create.inPublic.publicArea.parameters.eccDetail.scheme.details.ecdsa.hashAlg = TPM_ALG_SHA256;
    cmdIn.create.inPublic.publicArea.parameters.eccDetail.curveID = TPM_ECC_NIST_P256;
    cmdIn.create.inPublic.publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
    rc = TPM2_Create(&cmdIn.create, &cmdOut.create);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_Create ECDSA failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_Create: New ECDSA Key: pub %d, priv %d\n",
        cmdOut.create.outPublic.size,
        cmdOut.create.outPrivate.size);
    eccKey.pub = cmdOut.create.outPublic;
    eccKey.priv = cmdOut.create.outPrivate;

    /* Load new key */
    XMEMSET(&cmdIn.load, 0, sizeof(cmdIn.load));
    cmdIn.load.parentHandle = storage.handle;
    cmdIn.load.inPrivate = eccKey.priv;
    cmdIn.load.inPublic = eccKey.pub;
    rc = TPM2_Load(&cmdIn.load, &cmdOut.load);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_Load ECDSA failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    eccKey.handle = cmdOut.load.objectHandle;
    printf("TPM2_Load ECDSA Key Handle 0x%x\n", (word32)eccKey.handle);

    /* set session auth for ecc key */
    session[0].auth.size = sizeof(usageAuth)-1;
    XMEMCPY(session[0].auth.buffer, usageAuth, session[0].auth.size);

    /* Sign with ECC key */
    XMEMSET(&cmdIn.sign, 0, sizeof(cmdIn.sign));
    cmdIn.sign.keyHandle = eccKey.handle;
    cmdIn.sign.digest.size = message.size;
    XMEMCPY(cmdIn.sign.digest.buffer, message.buffer, message.size);
    cmdIn.sign.inScheme.scheme = TPM_ALG_ECDSA;
    cmdIn.sign.inScheme.details.ecdsa.hashAlg = TPM_ALG_SHA256;
    cmdIn.sign.validation.tag = TPM_ST_HASHCHECK;
    cmdIn.sign.validation.hierarchy = TPM_RH_NULL;
    rc = TPM2_Sign(&cmdIn.sign, &cmdOut.sign);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_Sign failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_Sign: ECC S %d, R %d\n",
        cmdOut.sign.signature.signature.ecdsa.signatureS.size,
        cmdOut.sign.signature.signature.ecdsa.signatureR.size);

    /* Verify with ECC key */
    XMEMSET(&cmdIn.verifySign, 0, sizeof(cmdIn.verifySign));
    cmdIn.verifySign.keyHandle = eccKey.handle;
    cmdIn.verifySign.digest.size = message.size;
    XMEMCPY(cmdIn.verifySign.digest.buffer, message.buffer, message.size);
    cmdIn.verifySign.signature = cmdOut.sign.signature;
    rc = TPM2_VerifySignature(&cmdIn.verifySign, &cmdOut.verifySign);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_VerifySignature failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_VerifySignature: Tag %d\n", cmdOut.verifySign.validation.tag);

    cmdIn.flushCtx.flushHandle = eccKey.handle;
    eccKey.handle = TPM_RH_NULL;
    TPM2_FlushContext(&cmdIn.flushCtx);


    /* set session auth for storage key */
    session[0].auth.size = sizeof(storagePwd)-1;
    XMEMCPY(session[0].auth.buffer, storagePwd, session[0].auth.size);

    /* Create an ECC key for ECDH */
    XMEMSET(&cmdIn.create, 0, sizeof(cmdIn.create));
    cmdIn.create.parentHandle = storage.handle;
    cmdIn.create.inSensitive.sensitive.userAuth.size = sizeof(usageAuth)-1;
    XMEMCPY(cmdIn.create.inSensitive.sensitive.userAuth.buffer, usageAuth,
        cmdIn.create.inSensitive.sensitive.userAuth.size);
    cmdIn.create.inPublic.publicArea.type = TPM_ALG_ECC;
    cmdIn.create.inPublic.publicArea.nameAlg = TPM_ALG_SHA256;
    cmdIn.create.inPublic.publicArea.objectAttributes = (
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_decrypt | TPMA_OBJECT_noDA);
    cmdIn.create.inPublic.publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
    cmdIn.create.inPublic.publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_ECDH;
    cmdIn.create.inPublic.publicArea.parameters.eccDetail.scheme.details.ecdsa.hashAlg = TPM_ALG_SHA256;
    cmdIn.create.inPublic.publicArea.parameters.eccDetail.curveID = TPM_ECC_NIST_P256;
    cmdIn.create.inPublic.publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
    rc = TPM2_Create(&cmdIn.create, &cmdOut.create);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_Create ECDH failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_Create: New ECDH Key: pub %d, priv %d\n",
        cmdOut.create.outPublic.size,
        cmdOut.create.outPrivate.size);
    eccKey.pub = cmdOut.create.outPublic;
    eccKey.priv = cmdOut.create.outPrivate;

    /* Load new key */
    XMEMSET(&cmdIn.load, 0, sizeof(cmdIn.load));
    cmdIn.load.parentHandle = storage.handle;
    cmdIn.load.inPrivate = eccKey.priv;
    cmdIn.load.inPublic = eccKey.pub;
    rc = TPM2_Load(&cmdIn.load, &cmdOut.load);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_Load ECDH key failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    eccKey.handle = cmdOut.load.objectHandle;
    printf("TPM2_Load ECDH Key Handle 0x%x\n", (word32)eccKey.handle);

    /* set session auth for ecc key */
    session[0].auth.size = sizeof(usageAuth)-1;
    XMEMCPY(session[0].auth.buffer, usageAuth, session[0].auth.size);

    /* ECDH Key Gen (gen public point and shared secret) */
    XMEMSET(&cmdIn.ecdh, 0, sizeof(cmdIn.ecdh));
    cmdIn.ecdh.keyHandle = eccKey.handle;
    rc = TPM2_ECDH_KeyGen(&cmdIn.ecdh, &cmdOut.ecdh);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_ECDH_KeyGen failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_ECDH_KeyGen: zPt %d, pubPt %d\n",
        cmdOut.ecdh.zPoint.size,
        cmdOut.ecdh.pubPoint.size);
    message.size = cmdOut.ecdh.zPoint.size;
    XMEMCPY(message.buffer, &cmdOut.ecdh.zPoint.point, message.size);

    /* ECDH ZGen (compute shared secret) */
    XMEMSET(&cmdIn.ecdhZ, 0, sizeof(cmdIn.ecdhZ));
    cmdIn.ecdhZ.keyHandle = eccKey.handle;
    cmdIn.ecdhZ.inPoint = cmdOut.ecdh.pubPoint;
    rc = TPM2_ECDH_ZGen(&cmdIn.ecdhZ, &cmdOut.ecdhZ);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_ECDH_KeyGen failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_ECDH_ZGen: zPt %d\n",
        cmdOut.ecdhZ.outPoint.size);

    /* verify shared secret is the same */
    if (message.size != cmdOut.ecdhZ.outPoint.size ||
        XMEMCMP(message.buffer, &cmdOut.ecdhZ.outPoint.point, message.size) != 0) {
        rc = -1; /* fail */
    }
    printf("TPM2 ECC Shared Secret %s\n", rc == 0 ? "Pass" : "Fail");

    cmdIn.flushCtx.flushHandle = eccKey.handle;
    eccKey.handle = TPM_RH_NULL;
    TPM2_FlushContext(&cmdIn.flushCtx);


    /* set session auth for storage key */
    session[0].auth.size = sizeof(storagePwd)-1;
    XMEMCPY(session[0].auth.buffer, storagePwd, session[0].auth.size);

    /* Create an RSA key for encrypt/decrypt */
    XMEMSET(&cmdIn.create, 0, sizeof(cmdIn.create));
    cmdIn.create.parentHandle = storage.handle;
    cmdIn.create.inSensitive.sensitive.userAuth.size = sizeof(usageAuth)-1;
    XMEMCPY(cmdIn.create.inSensitive.sensitive.userAuth.buffer, usageAuth,
        cmdIn.create.inSensitive.sensitive.userAuth.size);
    cmdIn.create.inPublic.publicArea.type = TPM_ALG_RSA;
    cmdIn.create.inPublic.publicArea.unique.rsa.size = MAX_RSA_KEY_BITS / 8;
    cmdIn.create.inPublic.publicArea.nameAlg = TPM_ALG_SHA256;
    cmdIn.create.inPublic.publicArea.objectAttributes = (
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_decrypt | TPMA_OBJECT_sign | TPMA_OBJECT_noDA);
    cmdIn.create.inPublic.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
    cmdIn.create.inPublic.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
    cmdIn.create.inPublic.publicArea.parameters.rsaDetail.keyBits = MAX_RSA_KEY_BITS;
    cmdIn.create.outsideInfo.size = sizeof(keyCreationNonce)-1;
    XMEMCPY(cmdIn.create.outsideInfo.buffer, keyCreationNonce,
        cmdIn.create.outsideInfo.size);
    rc = TPM2_Create(&cmdIn.create, &cmdOut.create);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_Create RSA failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_Create: New RSA Key: pub %d, priv %d\n",
        cmdOut.create.outPublic.size,
        cmdOut.create.outPrivate.size);
    rsaKey.pub = cmdOut.create.outPublic;
    rsaKey.priv = cmdOut.create.outPrivate;

    /* Load new key */
    XMEMSET(&cmdIn.load, 0, sizeof(cmdIn.load));
    cmdIn.load.parentHandle = storage.handle;
    cmdIn.load.inPrivate = rsaKey.priv;
    cmdIn.load.inPublic = rsaKey.pub;
    rc = TPM2_Load(&cmdIn.load, &cmdOut.load);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_Load RSA key failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    rsaKey.handle = cmdOut.load.objectHandle;
    printf("TPM2_Load RSA Key Handle 0x%x\n", (word32)rsaKey.handle);

    /* set session auth for RSA key */
    session[0].auth.size = sizeof(usageAuth)-1;
    XMEMCPY(session[0].auth.buffer, usageAuth, session[0].auth.size);


    /* RSA Encrypt */
    XMEMSET(&cmdIn.rsaEnc, 0, sizeof(cmdIn.rsaEnc));
    cmdIn.rsaEnc.keyHandle = rsaKey.handle;
    cmdIn.rsaEnc.message = message;
    cmdIn.rsaEnc.inScheme.scheme = TPM_ALG_OAEP;
    cmdIn.rsaEnc.inScheme.details.oaep.hashAlg = TPM_ALG_SHA256;
    cmdIn.rsaEnc.label.size = sizeof(label); /* Null term required */
    XMEMCPY(cmdIn.rsaEnc.label.buffer, label, cmdIn.rsaEnc.label.size);
    rc = TPM2_RSA_Encrypt(&cmdIn.rsaEnc, &cmdOut.rsaEnc);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_RSA_Encrypt failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_RSA_Encrypt: %d\n", cmdOut.rsaEnc.outData.size);

    /* RSA Decrypt */
    XMEMSET(&cmdIn.rsaDec, 0, sizeof(cmdIn.rsaDec));
    cmdIn.rsaDec.keyHandle = rsaKey.handle;
    cmdIn.rsaDec.cipherText = cmdOut.rsaEnc.outData;
    cmdIn.rsaDec.inScheme.scheme = TPM_ALG_OAEP;
    cmdIn.rsaDec.inScheme.details.oaep.hashAlg = TPM_ALG_SHA256;
    cmdIn.rsaDec.label.size = sizeof(label); /* Null term required */
    XMEMCPY(cmdIn.rsaDec.label.buffer, label, cmdIn.rsaEnc.label.size);
    rc = TPM2_RSA_Decrypt(&cmdIn.rsaDec, &cmdOut.rsaDec);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_RSA_Decrypt failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_RSA_Decrypt: %d\n", cmdOut.rsaDec.message.size);

    if (cmdOut.rsaDec.message.size != message.size ||
        XMEMCMP(cmdOut.rsaDec.message.buffer, message.buffer,
            cmdOut.rsaDec.message.size)) {
        printf("RSA Test failed!\n");
    }
    else {
        printf("RSA Encrypt/Decrypt test passed\n");
    }

    cmdIn.flushCtx.flushHandle = rsaKey.handle;
    rsaKey.handle = TPM_RH_NULL;
    TPM2_FlushContext(&cmdIn.flushCtx);


    /* NVRAM Access */

    /* Clear auth buffer */
    session[0].auth.size = 0;
    XMEMSET(session[0].auth.buffer, 0, sizeof(session[0].auth.buffer));

    /* Define new NV */
    nvIndex = TPM_20_OWNER_NV_SPACE + 0x003FFFFF; /* Last owner Index */
    XMEMSET(&cmdIn.nvDefine, 0, sizeof(cmdIn.nvDefine));
    cmdIn.nvDefine.authHandle = TPM_RH_OWNER;
    cmdIn.nvDefine.auth.size = sizeof(usageAuth)-1;
    XMEMCPY(cmdIn.nvDefine.auth.buffer, usageAuth, cmdIn.nvDefine.auth.size);
    cmdIn.nvDefine.publicInfo.nvPublic.nvIndex = nvIndex;
    cmdIn.nvDefine.publicInfo.nvPublic.nameAlg = TPM_ALG_SHA256;
    cmdIn.nvDefine.publicInfo.nvPublic.attributes = (
        TPMA_NV_OWNERWRITE | TPMA_NV_OWNERREAD | TPMA_NV_NO_DA);
    cmdIn.nvDefine.publicInfo.nvPublic.dataSize = TPM_SHA256_DIGEST_SIZE;
    rc = TPM2_NV_DefineSpace(&cmdIn.nvDefine);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_NV_DefineSpace failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_NV_DefineSpace: 0x%x\n", (word32)nvIndex);

    /* Read NV */
    XMEMSET(&cmdIn.nvReadPub, 0, sizeof(cmdIn.nvReadPub));
    cmdIn.nvReadPub.nvIndex = nvIndex;
    rc = TPM2_NV_ReadPublic(&cmdIn.nvReadPub, &cmdOut.nvReadPub);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_NV_ReadPublic failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_NV_ReadPublic: Sz %d, Idx 0x%x, nameAlg %d, Attr 0x%x, "
            "authPol %d, dataSz %d, name %d\n",
        cmdOut.nvReadPub.nvPublic.size,
		(word32)cmdOut.nvReadPub.nvPublic.nvPublic.nvIndex,
        cmdOut.nvReadPub.nvPublic.nvPublic.nameAlg,
		(word32)cmdOut.nvReadPub.nvPublic.nvPublic.attributes,
        cmdOut.nvReadPub.nvPublic.nvPublic.authPolicy.size,
        cmdOut.nvReadPub.nvPublic.nvPublic.dataSize,
        cmdOut.nvReadPub.nvName.size);

    /* Undefine NV */
    XMEMSET(&cmdIn.nvUndefine, 0, sizeof(cmdIn.nvUndefine));
    cmdIn.nvUndefine.authHandle = TPM_RH_OWNER;
    cmdIn.nvUndefine.nvIndex = nvIndex;
    rc = TPM2_NV_UndefineSpace(&cmdIn.nvUndefine);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_NV_UndefineSpace failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }


    /* Example for Encrypt/Decrypt */

    /* Clear auth buffer */
    session[0].auth.size = 0;
    XMEMSET(session[0].auth.buffer, 0, sizeof(session[0].auth.buffer));

#if defined(WOLFTPM_ST33) || defined(WOLFTPM_AUTODETECT)
    if (TPM2_GetVendorID() == TPM_VENDOR_STM) {
        /* Enable TPM2_EncryptDecrypt2 command */
        XMEMSET(&cmdIn.setCmdSet, 0, sizeof(cmdIn.setCmdSet));
        cmdIn.setCmdSet.authHandle = TPM_RH_PLATFORM;
        cmdIn.setCmdSet.commandCode = TPM_CC_EncryptDecrypt2;
        cmdIn.setCmdSet.enableFlag = 1;
        rc = TPM2_SetCommandSet(&cmdIn.setCmdSet);
        if (rc != TPM_RC_SUCCESS) {
            printf("TPM2_SetCommandSet failed 0x%x: %s\n", rc,
                TPM2_GetRCString(rc));
            goto exit;
        }
    }
#endif

    /* set session auth for storage key */
    session[0].auth.size = sizeof(storagePwd)-1;
    XMEMCPY(session[0].auth.buffer, storagePwd, session[0].auth.size);

    /* Create a symmetric key */
    XMEMSET(&cmdIn.create, 0, sizeof(cmdIn.create));
    cmdIn.create.parentHandle = storage.handle;
    cmdIn.create.inSensitive.sensitive.userAuth.size = sizeof(usageAuth)-1;
    XMEMCPY(cmdIn.create.inSensitive.sensitive.userAuth.buffer, usageAuth,
        cmdIn.create.inSensitive.sensitive.userAuth.size);
    cmdIn.create.inPublic.publicArea.type = TPM_ALG_SYMCIPHER;
    cmdIn.create.inPublic.publicArea.nameAlg = TPM_ALG_SHA256;
    cmdIn.create.inPublic.publicArea.objectAttributes = (
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_noDA | TPMA_OBJECT_decrypt | TPMA_OBJECT_sign);
    cmdIn.create.inPublic.publicArea.parameters.symDetail.sym.algorithm = TPM_ALG_AES;
    cmdIn.create.inPublic.publicArea.parameters.symDetail.sym.keyBits.aes = MAX_AES_KEY_BITS;
    cmdIn.create.inPublic.publicArea.parameters.symDetail.sym.mode.aes = TEST_AES_MODE;

    rc = TPM2_Create(&cmdIn.create, &cmdOut.create);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_Create symmetric failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    aesKey.pub = cmdOut.create.outPublic;
    aesKey.priv = cmdOut.create.outPrivate;
    printf("Create AES%d CFB Key success, public %d, Private %d\n",
        MAX_AES_KEY_BITS, aesKey.pub.size, aesKey.priv.size);

    XMEMSET(&cmdIn.load, 0, sizeof(cmdIn.load));
    cmdIn.load.parentHandle = storage.handle;
    cmdIn.load.inPrivate = aesKey.priv;
    cmdIn.load.inPublic = aesKey.pub;
    rc = TPM2_Load(&cmdIn.load, &cmdOut.load);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_Load failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    aesKey.handle = cmdOut.load.objectHandle;
    printf("TPM2_Load New AES Key Handle 0x%x\n", (word32)aesKey.handle);

    /* set auth for AES handle */
    session[0].auth.size = sizeof(usageAuth)-1;
    XMEMCPY(session[0].auth.buffer, usageAuth, session[0].auth.size);

    /* Test data */
    message.size = MAX_AES_BLOCK_SIZE_BYTES;
    for (i=0; i<message.size; i++)
        message.buffer[i] = (byte)(i & 0xff);

    /* Perform encrypt of data */
    /* Note: TPM2_EncryptDecrypt2 is used to allow parameter encryption for data */
    XMEMSET(&cmdIn.encDec, 0, sizeof(cmdIn.encDec));
    cmdIn.encDec.keyHandle = aesKey.handle;
    cmdIn.encDec.ivIn.size = MAX_AES_BLOCK_SIZE_BYTES; /* zeros */
    cmdIn.encDec.inData.size = message.size;
    XMEMCPY(cmdIn.encDec.inData.buffer, message.buffer, cmdIn.encDec.inData.size);
    cmdIn.encDec.decrypt = NO;
    cmdIn.encDec.mode = TEST_AES_MODE;
    rc = TPM2_EncryptDecrypt2(&cmdIn.encDec, &cmdOut.encDec);
    if (rc == TPM_RC_COMMAND_CODE) { /* some TPM's may not support command */
        printf("TPM2_EncryptDecrypt2: Is not a supported feature without enabling due to export controls\n");
    }
    else if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_EncryptDecrypt2 failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }

    /* Perform decrypt of data */
    XMEMSET(&cmdIn.encDec, 0, sizeof(cmdIn.encDec));
    cmdIn.encDec.keyHandle = aesKey.handle;
    cmdIn.encDec.ivIn.size = MAX_AES_BLOCK_SIZE_BYTES; /* zeros */
    cmdIn.encDec.inData.size = cmdOut.encDec.outData.size;
    XMEMCPY(cmdIn.encDec.inData.buffer, cmdOut.encDec.outData.buffer,
        cmdOut.encDec.outData.size);
    cmdIn.encDec.decrypt = YES;
    cmdIn.encDec.mode = TEST_AES_MODE;
    rc = TPM2_EncryptDecrypt2(&cmdIn.encDec, &cmdOut.encDec);
    if (rc == TPM_RC_COMMAND_CODE) { /* some TPM's may not support command */
        printf("TPM2_EncryptDecrypt2: Is not a supported feature without enabling due to export controls\n");
    }
    else if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_EncryptDecrypt2 failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }

    /* Verify plain and decrypted data are the same */
    if (rc == TPM_RC_SUCCESS &&
        cmdOut.encDec.outData.size == MAX_AES_BLOCK_SIZE_BYTES &&
         XMEMCMP(cmdOut.encDec.outData.buffer, message.buffer,
            cmdOut.encDec.outData.size) == 0) {
        printf("Encrypt/Decrypt test success\n");
    }
    else if (rc != TPM_RC_COMMAND_CODE) {
        printf("Encrypt/Decrypt test failed, result not as expected!\n");
        goto exit;
    }

exit:

    /* Close session */
    if (sessionHandle != TPM_RH_NULL) {
        cmdIn.flushCtx.flushHandle = sessionHandle;
        TPM2_FlushContext(&cmdIn.flushCtx);
    }

    /* Close object handle */
    if (handle != TPM_RH_NULL) {
        cmdIn.flushCtx.flushHandle = handle;
        TPM2_FlushContext(&cmdIn.flushCtx);
    }
    if (eccKey.handle != TPM_RH_NULL) {
        cmdIn.flushCtx.flushHandle = eccKey.handle;
        TPM2_FlushContext(&cmdIn.flushCtx);
    }
    if (hmacKey.handle != TPM_RH_NULL) {
        cmdIn.flushCtx.flushHandle = hmacKey.handle;
        TPM2_FlushContext(&cmdIn.flushCtx);
    }
    if (aesKey.handle != TPM_RH_NULL) {
        cmdIn.flushCtx.flushHandle = aesKey.handle;
        TPM2_FlushContext(&cmdIn.flushCtx);
    }
    if (rsaKey.handle != TPM_RH_NULL) {
        cmdIn.flushCtx.flushHandle = rsaKey.handle;
        TPM2_FlushContext(&cmdIn.flushCtx);
    }

    /* Cleanup key handles */
    if (endorse.handle != TPM_RH_NULL) {
        cmdIn.flushCtx.flushHandle = endorse.handle;
        TPM2_FlushContext(&cmdIn.flushCtx);
    }
    if (storage.handle != TPM_RH_NULL) {
        cmdIn.flushCtx.flushHandle = storage.handle;
        TPM2_FlushContext(&cmdIn.flushCtx);
    }

    /* Shutdown */
    cmdIn.shutdown.shutdownType = TPM_SU_CLEAR;
    if (TPM2_Shutdown(&cmdIn.shutdown) != TPM_RC_SUCCESS) {
        printf("TPM2_Shutdown failed\n");
    }

    TPM2_Cleanup(&tpm2Ctx);

#ifdef TPM2_SPI_DEV
    /* close handle */
    if (gSpiDev >= 0)
        close(gSpiDev);
#endif

    return rc;
}

/******************************************************************************/
/* --- BEGIN TPM Native API Tests -- */
/******************************************************************************/


#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc;

    rc = TPM2_Native_TestArgs(NULL, argc, argv);

    return rc;
}
#endif
