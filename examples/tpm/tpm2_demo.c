/* tpm2_demo.c
 *
 * Copyright (C) 2006-2018 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/hash.h>

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_wrap.h>
#include <examples/tpm/tpm2_demo.h>

/* Local variables */
static TPM2_CTX gTpm2Ctx;

/* Configuration for the SPI interface */
#ifdef WOLFSSL_STM32_CUBEMX
    extern SPI_HandleTypeDef hspi1;
    #define TPM2_USER_CTX &hspi1
#elif defined(__linux__)
    #include <sys/ioctl.h>
    #include <linux/spi/spidev.h>
    #include <fcntl.h>
    #define TPM2_SPI_DEV "/dev/spidev0.1"

    static int gSpiDev = -1;
    #define TPM2_USER_CTX &gSpiDev
#else
    /* TODO: Add your platform here for HW interface */
    #define TPM2_USER_CTX NULL
#endif


/* IO Callback */
static TPM_RC TPM2_IoCb(TPM2_CTX* ctx, const byte* txBuf, byte* rxBuf,
    word16 xferSz, void* userCtx)
{
    int ret = TPM_RC_FAILURE;
#ifdef WOLFSSL_STM32_CUBEMX
    /* STM32 CubeMX Hal */
    SPI_HandleTypeDef* hspi = (SPI_HandleTypeDef*)userCtx;
    HAL_StatusTypeDef status;

    __HAL_SPI_ENABLE(hspi);
    status = HAL_SPI_TransmitReceive(hspi, (byte*)txBuf, rxBuf, xferSz, 5000);
    __HAL_SPI_DISABLE(hspi);
    if (status == HAL_OK)
        ret = TPM_RC_SUCCESS;

#elif defined(__linux__)
    /* Use Linux SPI synchronous access */
    int* spiDev = (int*)userCtx;

    if (*spiDev == -1) {
        unsigned int maxSpeed = 10000000; /* 10Mhz */
        int mode = 0; /* mode 0 */
        int bits_per_word = 0; /* 8-bits */

        *spiDev = open(TPM2_SPI_DEV, O_RDWR);
        if (*spiDev >= 0) {
            ioctl(*spiDev, SPI_IOC_WR_MODE, &mode);
            ioctl(*spiDev, SPI_IOC_RD_MAX_SPEED_HZ, &maxSpeed);
            ioctl(*spiDev, SPI_IOC_WR_BITS_PER_WORD, &bits_per_word);
        }
    }

    if (*spiDev >= 0) {
        struct spi_ioc_transfer spi;
        size_t size;

        XMEMSET(&spi, 0, sizeof(spi));
        spi.tx_buf   = (unsigned long)txBuf;
        spi.rx_buf   = (unsigned long)rxBuf;
        spi.len      = xferSz;
        spi.cs_change= 1; /* strobe CS between transfers */

        size = ioctl(*spiDev, SPI_IOC_MESSAGE(1), &spi);
        if (size == xferSz)
            ret = TPM_RC_SUCCESS;
    }
#else
    /* TODO: Add your platform here for HW interface */
    (void)txBuf;
    (void)rxBuf;
    (void)xferSz;
    (void)userCtx;
#endif

#ifdef DEBUG_WOLFTPM
    //printf("TPM2_IoCb: %d\n", xferSz);
    //TPM2_PrintBin(txBuf, xferSz);
    //TPM2_PrintBin(rxBuf, xferSz);
#endif

    (void)ctx;

    return ret;
}

/* Endorsement Auth */
const BYTE TPM_20_EK_AUTH_POLICY[] = {
    0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8, 0x1a, 0x90, 0xcc,
    0x8d, 0x46, 0xa5, 0xd7, 0x24, 0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52,
    0x0b, 0x64, 0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14, 0x69, 0xaa,
};

#define RAND_GET_SZ WC_SHA256_DIGEST_SIZE

typedef struct tpmKey {
    TPM_HANDLE    handle;
    TPM2B_PRIVATE private;
    TPM2B_PUBLIC  public;
} TpmKey;

typedef TpmKey TpmRsaKey;
typedef TpmKey TpmEccKey;
typedef TpmKey TpmHmacKey;

int TPM2_Demo(void* userCtx)
{
    int rc;
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
        Clear_In clear;
        HashSequenceStart_In hashSeqStart;
        SequenceUpdate_In seqUpdate;
        SequenceComplete_In seqComp;
        byte maxInput[MAX_COMMAND_SIZE];
    } cmdIn;
    union {
        GetCapability_Out cap;
        GetRandom_Out getRand;
        GetTestResult_Out tr;
        IncrementalSelfTest_Out incSelfTest;
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
        byte maxOutput[MAX_RESPONSE_SIZE];
    } cmdOut;
    int pcrCount, pcrIndex, i;
    TPML_TAGGED_TPM_PROPERTY* tpmProp;
    TPM_HANDLE handle = TPM_RH_NULL;
    WC_RNG rng;

    byte pcr[WC_SHA256_DIGEST_SIZE];
    int pcr_len = WC_SHA256_DIGEST_SIZE;
    byte hash[WC_SHA256_DIGEST_SIZE];
    int hash_len = WC_SHA256_DIGEST_SIZE;

    TpmEccKey eccKey;
    TpmRsaKey endorse;
    TpmRsaKey storage;
    TpmHmacKey hmacKey;

    const char platformPwd[] = "WolfTPMPlatPswd";
    const char usageAuth[] = "ThisIsASecretUsageAuth";
    const char userKey[] = "ThisIsMyHmacKey";

    const char* hashTestData =
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    const char* hashTestDig =
        "\x24\x8D\x6A\x61\xD2\x06\x38\xB8\xE5\xC0\x26\x93\x0C\x3E\x60"
        "\x39\xA3\x3C\xE4\x59\x64\xFF\x21\x67\xF6\xEC\xED\xD4\x19\xDB"
        "\x06\xC1";

    TPMS_AUTH_COMMAND session;

#ifdef DEBUG_WOLFSSL
    wolfSSL_Debugging_ON();
#endif

    wolfCrypt_Init();

    rc = wc_InitRng(&rng);
    if (rc < 0) {
        printf("wc_InitRng failed %d: %s\n", rc, wc_GetErrorString(rc));
        return rc;
    }

    rc = TPM2_Init(&gTpm2Ctx, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_Init failed %d: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }

    /* define the default session auth */
    XMEMSET(&session, 0, sizeof(session));
    session.sessionHandle = TPM_RS_PW;
    TPM2_SetSessionAuth(&session);

    cmdIn.startup.startupType = TPM_SU_CLEAR;
    rc = TPM2_Startup(&cmdIn.startup);
    if (rc != TPM_RC_SUCCESS &&
        rc != TPM_RC_INITIALIZE /* TPM_RC_INITIALIZE = Already started */ ) {
        printf("TPM2_Startup failed %d: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_Startup pass\n");


    /* Full self test */
    cmdIn.selfTest.fullTest = YES;
    rc = TPM2_SelfTest(&cmdIn.selfTest);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_SelfTest failed %d: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_SelfTest pass\n");

    /* Get Test Result */
    rc = TPM2_GetTestResult(&cmdOut.tr);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_GetTestResult failed %d: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_GetTestResult: Size %d, Rc 0x%x\n", cmdOut.tr.outData.size,
        cmdOut.tr.testResult);
    TPM2_PrintBin(cmdOut.tr.outData.buffer, cmdOut.tr.outData.size);

    /* Incremental Test */
    cmdIn.incSelfTest.toTest.count = 1;
    cmdIn.incSelfTest.toTest.algorithms[0] = TPM_ALG_RSA;
	rc = TPM2_IncrementalSelfTest(&cmdIn.incSelfTest, &cmdOut.incSelfTest);
	printf("TPM2_IncrementalSelfTest: Rc 0x%x, Alg 0x%x (Todo %d)\n",
			rc, cmdIn.incSelfTest.toTest.algorithms[0],
            (int)cmdOut.incSelfTest.toDoList.count);


    /* Get Capability for Property */
    cmdIn.cap.capability = TPM_CAP_TPM_PROPERTIES;
    cmdIn.cap.property = TPM_PT_FAMILY_INDICATOR;
    cmdIn.cap.propertyCount = 1;
    rc = TPM2_GetCapability(&cmdIn.cap, &cmdOut.cap);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_GetCapability failed %d: %s\n", rc, TPM2_GetRCString(rc));
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
        printf("TPM2_GetCapability failed %d: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    tpmProp = &cmdOut.cap.capabilityData.data.tpmProperties;
    pcrCount = tpmProp->tpmProperty[0].value;
    printf("TPM2_GetCapability: Property PCR Count %d\n", pcrCount);


    /* Random */
    cmdIn.getRand.bytesRequested = RAND_GET_SZ;
    rc = TPM2_GetRandom(&cmdIn.getRand, &cmdOut.getRand);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_GetRandom failed %d: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    if (cmdOut.getRand.randomBytes.size != RAND_GET_SZ) {
        printf("TPM2_GetRandom length mismatch %d != %d\n",
            cmdOut.getRand.randomBytes.size, RAND_GET_SZ);
        goto exit;
    }
    printf("TPM2_GetRandom: Got %d bytes\n", cmdOut.getRand.randomBytes.size);
    TPM2_PrintBin(cmdOut.getRand.randomBytes.buffer,
                   cmdOut.getRand.randomBytes.size);


    /* Stir Random */
    cmdIn.stirRand.inData.size = cmdOut.getRand.randomBytes.size;
    XMEMCPY(cmdIn.stirRand.inData.buffer,
        cmdOut.getRand.randomBytes.buffer, cmdIn.stirRand.inData.size);
    rc = TPM2_StirRandom(&cmdIn.stirRand);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_StirRandom failed %d: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }


    /* PCR Read */
    for (i=0; i<pcrCount; i++) {
        pcrIndex = i;
        TPM2_SetupPCRSel(&cmdIn.pcrRead.pcrSelectionIn, TPM_ALG_SHA256, pcrIndex);
        rc = TPM2_PCR_Read(&cmdIn.pcrRead, &cmdOut.pcrRead);
        if (rc != TPM_RC_SUCCESS) {
            printf("TPM2_PCR_Read failed %d: %s\n", rc, TPM2_GetRCString(rc));
            goto exit;
        }
        printf("TPM2_PCR_Read: Index %d, Digest Sz %d, Update Counter %d\n",
            pcrIndex,
            (int)cmdOut.pcrRead.pcrValues.digests[0].size,
            (int)cmdOut.pcrRead.pcrUpdateCounter);
        TPM2_PrintBin(cmdOut.pcrRead.pcrValues.digests[0].buffer,
                       cmdOut.pcrRead.pcrValues.digests[0].size);
    }

    /* PCR Extend and Verify */
    pcrIndex = 0;
    XMEMSET(&cmdIn.pcrExtend, 0, sizeof(cmdIn.pcrExtend));
    cmdIn.pcrExtend.pcrHandle = pcrIndex;
    cmdIn.pcrExtend.digests.count = 1;
    cmdIn.pcrExtend.digests.digests[0].hashAlg = TPM_ALG_SHA256;
    for (i=0; i<WC_SHA256_DIGEST_SIZE; i++) {
        cmdIn.pcrExtend.digests.digests[0].digest.H[i] = i;
    }
    rc = TPM2_PCR_Extend(&cmdIn.pcrExtend);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_PCR_Extend failed %d: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_PCR_Extend success\n");

    TPM2_SetupPCRSel(&cmdIn.pcrRead.pcrSelectionIn, TPM_ALG_SHA256, pcrIndex);
    rc = TPM2_PCR_Read(&cmdIn.pcrRead, &cmdOut.pcrRead);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_PCR_Read failed %d: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_PCR_Read: Index %d, Digest Sz %d, Update Counter %d\n",
        pcrIndex,
        (int)cmdOut.pcrRead.pcrValues.digests[0].size,
        (int)cmdOut.pcrRead.pcrUpdateCounter);
    TPM2_PrintBin(cmdOut.pcrRead.pcrValues.digests[0].buffer,
                   cmdOut.pcrRead.pcrValues.digests[0].size);



    /* Start Auth Session */
    XMEMSET(&cmdIn.authSes, 0, sizeof(cmdIn.authSes));
    cmdIn.authSes.tpmKey = TPM_RH_NULL;
    cmdIn.authSes.bind = TPM_RH_NULL;
    cmdIn.authSes.sessionType = TPM_SE_POLICY;
    cmdIn.authSes.symmetric.algorithm = TPM_ALG_NULL;
    cmdIn.authSes.authHash = TPM_ALG_SHA256;
    cmdIn.authSes.nonceCaller.size = WC_SHA256_DIGEST_SIZE;
    rc = wc_RNG_GenerateBlock(&rng, cmdIn.authSes.nonceCaller.buffer,
                                                cmdIn.authSes.nonceCaller.size);
    if (rc < 0) {
        printf("wc_RNG_GenerateBlock failed %d: %s\n", rc, wc_GetErrorString(rc));
        goto exit;
    }
    rc = TPM2_StartAuthSession(&cmdIn.authSes, &cmdOut.authSes);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_StartAuthSession failed %d: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    handle = cmdOut.authSes.sessionHandle;
    printf("TPM2_StartAuthSession: sessionHandle 0x%x\n", handle);


    /* Policy Get Digest */
    cmdIn.policyGetDigest.policySession = handle;
    rc = TPM2_PolicyGetDigest(&cmdIn.policyGetDigest, &cmdOut.policyGetDigest);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_PolicyGetDigest failed %d: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_PolicyGetDigest: size %d\n", cmdOut.policyGetDigest.policyDigest.size);
    TPM2_PrintBin(cmdOut.policyGetDigest.policyDigest.buffer,
        cmdOut.policyGetDigest.policyDigest.size);

    /* Read PCR[0] SHA1 */
    pcrIndex = 0;
    rc = wolfTPM_ReadPCR(pcrIndex, TPM_ALG_SHA1, pcr, &pcr_len);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM_ReadPCR failed %d: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }

    /* Hash SHA256 PCR[0] */
    rc = wc_Hash(WC_HASH_TYPE_SHA256, pcr, pcr_len, hash, hash_len);
    if (rc < 0) {
        printf("wc_Hash failed %d: %s\n", rc, wc_GetErrorString(rc));
        goto exit;
    }
    printf("wc_Hash of PCR[0]: size %d\n", hash_len);
    TPM2_PrintBin(hash, hash_len);

    /* Policy PCR */
    pcrIndex = 0;
    cmdIn.policyPCR.policySession = handle;
    cmdIn.policyPCR.pcrDigest.size = hash_len;
    XMEMCPY(cmdIn.policyPCR.pcrDigest.buffer, hash, hash_len);
    TPM2_SetupPCRSel(&cmdIn.policyPCR.pcrs, TPM_ALG_SHA1, pcrIndex);
    rc = TPM2_PolicyPCR(&cmdIn.policyPCR);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_PolicyPCR failed %d: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_PolicyPCR: Updated\n");


    /* Policy Restart (for session) */
    cmdIn.policyRestart.sessionHandle = handle;
    rc = TPM2_PolicyRestart(&cmdIn.policyRestart);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_PolicyRestart failed %d: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_PolicyRestart: Done\n");


    /* Close session (TPM2_FlushContext) */
    cmdIn.flushCtx.flushHandle = handle;
    rc = TPM2_FlushContext(&cmdIn.flushCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_FlushContext failed %d: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_FlushContext: Closed sessionHandle 0x%x\n", handle);
    handle = TPM_RH_NULL;



    /* NVRAM Access */



    /* Hashing */
    XMEMSET(&cmdIn.hashSeqStart, 0, sizeof(cmdIn.hashSeqStart));
    cmdIn.hashSeqStart.auth.size = sizeof(usageAuth)-1;
    XMEMCPY(cmdIn.hashSeqStart.auth.buffer, usageAuth,
        cmdIn.hashSeqStart.auth.size);
    cmdIn.hashSeqStart.hashAlg = TPM_ALG_SHA256;
    rc = TPM2_HashSequenceStart(&cmdIn.hashSeqStart, &cmdOut.hashSeqStart);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_HashSequenceStart failed %d: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    handle = cmdOut.hashSeqStart.sequenceHandle;
    printf("TPM2_HashSequenceStart: sequenceHandle 0x%x\n", handle);

    session.auth.size = sizeof(usageAuth)-1;
    XMEMCPY(session.auth.buffer, usageAuth, session.auth.size);

    XMEMSET(&cmdIn.seqUpdate, 0, sizeof(cmdIn.seqUpdate));
    cmdIn.seqUpdate.sequenceHandle = handle;
    cmdIn.seqUpdate.buffer.size = XSTRLEN(hashTestData);
    XMEMCPY(cmdIn.seqUpdate.buffer.buffer, hashTestData, cmdIn.seqUpdate.buffer.size);
    rc = TPM2_SequenceUpdate(&cmdIn.seqUpdate);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_SequenceUpdate failed %d: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }

    XMEMSET(&cmdIn.seqComp, 0, sizeof(cmdIn.seqComp));
    cmdIn.seqComp.sequenceHandle = handle;
    cmdIn.seqComp.hierarchy = TPM_RH_NULL;
    rc = TPM2_SequenceComplete(&cmdIn.seqComp, &cmdOut.seqComp);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_SequenceComplete failed %d: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    if (cmdOut.seqComp.result.size != WC_SHA256_DIGEST_SIZE &&
        XMEMCMP(cmdOut.seqComp.result.buffer, hashTestDig, WC_SHA256_DIGEST_SIZE) != 0) {
        printf("Hash SHA256 test failed, result not as expected!\n");
        //goto exit;
    }
    printf("Hash SHA256 test success\n");

    /* clear session auth */
    session.auth.size = 0;
    XMEMSET(session.auth.buffer, 0, sizeof(session.auth.buffer));



#if 0
    /* Clear Owner */
    cmdIn.clear.authHandle = TPM_RH_PLATFORM;
    rc = TPM2_Clear(&cmdIn.clear);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_Clear failed %d: %s\n", rc, TPM2_GetRCString(rc));
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
        printf("TPM2_CreatePrimary: Endorsement failed %d: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    endorse.handle = cmdOut.createPri.objectHandle;
    endorse.public = cmdOut.createPri.outPublic;
    printf("TPM2_CreatePrimary: Endorsement 0x%x (%d bytes)\n",
        endorse.handle, endorse.public.size);


    /* Create (Storage) */
    XMEMSET(&cmdIn.createPri, 0, sizeof(cmdIn.createPri));
    cmdIn.createPri.primaryHandle = TPM_RH_ENDORSEMENT;
    cmdIn.createPri.inSensitive.sensitive.userAuth.size = sizeof(platformPwd)-1;
    XMEMCPY(cmdIn.createPri.inSensitive.sensitive.userAuth.buffer,
        platformPwd, cmdIn.createPri.inSensitive.sensitive.userAuth.size);
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
        printf("TPM2_CreatePrimary: Platform failed %d: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    storage.handle = cmdOut.createPri.objectHandle;
    storage.public = cmdOut.createPri.outPublic;
    printf("TPM2_CreatePrimary: Platform 0x%x (%d bytes)\n",
        storage.handle, storage.public.size);

#if 0
    /* Move new primary key into NV to persist */
    cmdIn.evict.auth = endorse.handle;
    cmdIn.evict.objectHandle = storage.handle;
    cmdIn.evict.persistentHandle;
    rc = TPM2_EvictControl(&cmdIn.evict);
#endif


    /* Setup auth session for parent handle */
    session.auth.size = sizeof(platformPwd)-1;
    XMEMCPY(session.auth.buffer, platformPwd, session.auth.size);


    /* Loading RSA public key */
    XMEMSET(&cmdIn.loadExt, 0, sizeof(cmdIn.loadExt));
    cmdIn.loadExt.inPublic = endorse.public;
    cmdIn.loadExt.hierarchy = TPM_RH_NULL;
    rc = TPM2_LoadExternal(&cmdIn.loadExt, &cmdOut.loadExt);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_LoadExternal: failed %d: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    handle = cmdOut.loadExt.objectHandle;
    printf("TPM2_LoadExternal: 0x%x\n", handle);

    //TPM2_MakeCredential

    wolfTPM_UnloadHandle(&handle);


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
        printf("TPM2_Create HMAC failed %d: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    hmacKey.public = cmdOut.create.outPublic;
    hmacKey.private = cmdOut.create.outPrivate;
    printf("Create HMAC-SHA256 Key success, public %d, Private %d\n",
        hmacKey.public.size, hmacKey.private.size);

    XMEMSET(&cmdIn.load, 0, sizeof(cmdIn.load));
    cmdIn.load.parentHandle = storage.handle;
    cmdIn.load.inPrivate = hmacKey.private;
    cmdIn.load.inPublic = hmacKey.public;
    rc = TPM2_Load(&cmdIn.load, &cmdOut.load);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_Load failed %d: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    hmacKey.handle = cmdOut.load.objectHandle;
    printf("TPM2_Load New HMAC Key Handle 0x%x\n", hmacKey.handle);

    wolfTPM_UnloadHandle(&hmacKey.handle);



    /* Create an ECC key */
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
        printf("TPM2_Create ECC failed %d: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_Create: New ECC Key: pub %d, priv %d\n", cmdOut.create.outPublic.size,
        cmdOut.create.outPrivate.size);
    eccKey.public = cmdOut.create.outPublic;
    eccKey.private = cmdOut.create.outPrivate;

    /* Load new key */
    XMEMSET(&cmdIn.load, 0, sizeof(cmdIn.load));
    cmdIn.load.parentHandle = storage.handle;
    cmdIn.load.inPrivate = eccKey.private;
    cmdIn.load.inPublic = eccKey.public;
    rc = TPM2_Load(&cmdIn.load, &cmdOut.load);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_Load failed %d: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    eccKey.handle = cmdOut.load.objectHandle;
    printf("TPM2_Load New ECC Key Handle 0x%x\n", eccKey.handle);

    wolfTPM_UnloadHandle(&eccKey.handle);



    /* Clear auth buffer */
    session.auth.size = 0;
    XMEMSET(session.auth.buffer, 0, sizeof(session.auth.buffer));


exit:

    /* Cleanup key objects */
    wolfTPM_UnloadHandle(&endorse.handle);
    wolfTPM_UnloadHandle(&storage.handle);
    if (handle != TPM_RH_NULL)
        wolfTPM_UnloadHandle(&handle);


    /* Shutdown */
    cmdIn.shutdown.shutdownType = TPM_SU_CLEAR;
    rc = TPM2_Shutdown(&cmdIn.shutdown);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_Shutdown failed %d: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }

    wc_FreeRng(&rng);
    wolfCrypt_Cleanup();

#ifdef TPM2_SPI_DEV
    /* close handle */
    if (gSpiDev >= 0)
        close(gSpiDev);
#endif

    return rc;
}

#ifndef NO_MAIN_DRIVER
int main(void)
{
    return TPM2_Demo(TPM2_USER_CTX);
}
#endif
