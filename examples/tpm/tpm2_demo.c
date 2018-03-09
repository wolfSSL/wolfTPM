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

/* This demo shows using the TPM2_ specification API's in TPM2_Demo() and
    the TPM2 wrapper API's in TPM2_Wrapper_Demo() below. */

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


/******************************************************************************/
/* --- BEGIN IO Callback Logic -- */
/******************************************************************************/

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
static int TPM2_IoCb(TPM2_CTX* ctx, const byte* txBuf, byte* rxBuf,
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
        /* 33Mhz - PI has issue with 5-10Mhz on packets sized over 130 */
        unsigned int maxSpeed = 33000000;
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

/******************************************************************************/
/* --- END IO Callback Logic -- */
/******************************************************************************/



/******************************************************************************/
/* --- BEGIN Wrapper API Demo -- */
/******************************************************************************/

#ifndef WOLFTPM2_NO_WRAPPER
int TPM2_Wrapper_Demo(void* userCtx)
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY storageKey;
    WOLFTPM2_KEY rsaKey;
    WOLFTPM2_KEY eccKey;
    WOLFTPM2_BUFFER message;
    WOLFTPM2_BUFFER cipher;
    WOLFTPM2_BUFFER plain;
    TPMT_PUBLIC publicTemplate;
    TPM2B_ECC_POINT pubPoint;
    const char storageKeyAuth[] = "ThisIsMyStorageKeyAuth";
    const char keyAuth[] = "ThisIsMyKeyAuth";

    printf("TPM2 Demo for Wrapper API's\n");


    /* Init the TPM2 device */
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != 0) return rc;

    /* Create primary storage key */
    rc = wolfTPM2_GetKeyTemplate_RSA(&publicTemplate,
        TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent |
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_restricted | TPMA_OBJECT_decrypt | TPMA_OBJECT_noDA);
    if (rc != 0) goto exit;
    rc = wolfTPM2_CreatePrimaryKey(&dev, &storageKey, TPM_RH_OWNER,
        &publicTemplate, (byte*)storageKeyAuth, sizeof(storageKeyAuth)-1);
    if (rc != 0) goto exit;


    /* Create RSA key for encrypt/decrypt */
    rc = wolfTPM2_GetKeyTemplate_RSA(&publicTemplate,
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_decrypt | TPMA_OBJECT_sign | TPMA_OBJECT_noDA);
    if (rc != 0) goto exit;
    rc = wolfTPM2_CreateAndLoadKey(&dev, &rsaKey, &storageKey.handle,
        &publicTemplate, (byte*)keyAuth, sizeof(keyAuth)-1);
    if (rc != 0) goto exit;

    /* Perform RSA encrypt / decrypt */
    message.size = WC_SHA256_DIGEST_SIZE; /* test message 0x11,0x11,etc */
    XMEMSET(message.buffer, 0x11, message.size);
    cipher.size = sizeof(cipher.buffer); /* encrypted data */
    rc = wolfTPM2_RsaEncrypt(&dev, &rsaKey, TPM_ALG_OAEP,
        message.buffer, message.size, cipher.buffer, &cipher.size);
    if (rc != 0) goto exit;

    plain.size = sizeof(plain.buffer);
    rc = wolfTPM2_RsaDecrypt(&dev, &rsaKey, TPM_ALG_OAEP,
        cipher.buffer, cipher.size, plain.buffer, &plain.size);
    if (rc != 0) goto exit;

    rc = wolfTPM2_UnloadHandle(&dev, &rsaKey.handle);
    if (rc != 0) goto exit;

    /* Validate encrypt / decrypt */
    if (message.size != plain.size ||
                    XMEMCMP(message.buffer, plain.buffer, message.size) != 0) {
        rc = TPM_RC_TESTING; goto exit;
    }
    printf("RSA Encrypt Test Passed\n");


    /* Create an ECC key for ECDSA */
    rc = wolfTPM2_GetKeyTemplate_ECC(&publicTemplate,
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_sign | TPMA_OBJECT_noDA,
        TPM_ECC_NIST_P256, TPM_ALG_ECDSA);
    if (rc != 0) goto exit;
    rc = wolfTPM2_CreateAndLoadKey(&dev, &eccKey, &storageKey.handle,
        &publicTemplate, (byte*)keyAuth, sizeof(keyAuth)-1);
    if (rc != 0) goto exit;

    /* Perform sign / verify */
    message.size = WC_SHA256_DIGEST_SIZE; /* test message 0x11,0x11,etc */
    XMEMSET(message.buffer, 0x11, message.size);
    cipher.size = sizeof(cipher.buffer); /* signature */
    rc = wolfTPM2_SignHash(&dev, &eccKey, message.buffer, message.size,
        cipher.buffer, &cipher.size);
    if (rc != 0) goto exit;

    rc = wolfTPM2_VerifyHash(&dev, &eccKey, cipher.buffer, cipher.size,
        message.buffer, message.size);
    if (rc != 0) goto exit;

    rc = wolfTPM2_UnloadHandle(&dev, &eccKey.handle);
    if (rc != 0) goto exit;

    printf("ECC Sign/Verify Passed\n");


    /* Create an ECC key for DH */
    rc = wolfTPM2_GetKeyTemplate_ECC(&publicTemplate,
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_decrypt | TPMA_OBJECT_noDA,
        TPM_ECC_NIST_P256, TPM_ALG_ECDH);
    if (rc != 0) goto exit;
    rc = wolfTPM2_CreateAndLoadKey(&dev, &eccKey, &storageKey.handle,
        &publicTemplate, (byte*)keyAuth, sizeof(keyAuth)-1);
    if (rc != 0) goto exit;

    /* Create ephemeral ECC key and generate a shared secret */
    cipher.size = sizeof(cipher.buffer);
    rc = wolfTPM2_ECDHGen(&dev, &eccKey, &pubPoint,
        cipher.buffer, &cipher.size);
    if (rc != 0) goto exit;

    rc = wolfTPM2_UnloadHandle(&dev, &eccKey.handle);
    if (rc != 0) goto exit;

    printf("ECC DH Generation Passed\n");


exit:

    if (rc != 0) {
        printf("Failure 0x%x: %s\n", rc, wolfTPM2_GetRCString(rc));
    }

    wolfTPM2_UnloadHandle(&dev, &rsaKey.handle);
    wolfTPM2_UnloadHandle(&dev, &eccKey.handle);
    wolfTPM2_UnloadHandle(&dev, &storageKey.handle);
    wolfTPM2_Cleanup(&dev);

    return rc;
}
#endif /* !WOLFTPM2_NO_WRAPPER */

/******************************************************************************/
/* --- END Wrapper API Demo -- */
/******************************************************************************/




/******************************************************************************/
/* --- BEGIN TPM Native API Demo -- */
/******************************************************************************/


#define TPM_20_TPM_MFG_NV_SPACE        ((TPM_HT_NV_INDEX << 24) | (0x00 << 22))
#define TPM_20_PLATFORM_MFG_NV_SPACE   ((TPM_HT_NV_INDEX << 24) | (0x01 << 22))
#define TPM_20_OWNER_NV_SPACE          ((TPM_HT_NV_INDEX << 24) | (0x02 << 22))
#define TPM_20_TCG_NV_SPACE            ((TPM_HT_NV_INDEX << 24) | (0x03 << 22))


#define TPM_20_NV_INDEX_EK_CERTIFICATE (TPM_20_PLATFORM_MFG_NV_SPACE + 2)
#define TPM_20_NV_INDEX_EK_NONCE       (TPM_20_PLATFORM_MFG_NV_SPACE + 3)
#define TPM_20_NV_INDEX_EK_TEMPLATE    (TPM_20_PLATFORM_MFG_NV_SPACE + 4)


typedef struct tpmKey {
    TPM_HANDLE          handle;
    TPM2B_AUTH          auth;
    TPMT_SYM_DEF_OBJECT symmetric; /* used for parameter encrypt/decrypt */
    TPM2B_PRIVATE       private;
    TPM2B_PUBLIC        public;
    TPM2B_NAME          name;
} TpmKey;

typedef TpmKey TpmRsaKey;
typedef TpmKey TpmEccKey;
typedef TpmKey TpmHmacKey;

typedef struct tmpHandle {
    TPM_HANDLE         handle;
    TPM2B_AUTH         auth;
} TpmHandle;


int TPM2_Demo(void* userCtx)
{
    int rc;
    TPM2_CTX tpm2Ctx;

    const BYTE TPM_20_EK_AUTH_POLICY[] = {
        0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8, 0x1a, 0x90, 0xcc,
        0x8d, 0x46, 0xa5, 0xd7, 0x24, 0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52,
        0x0b, 0x64, 0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14, 0x69, 0xaa,
    };

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
        byte maxOutput[MAX_RESPONSE_SIZE];
    } cmdOut;

    int pcrCount, pcrIndex, i;
    TPML_TAGGED_TPM_PROPERTY* tpmProp;
    TPM_HANDLE handle = TPM_RH_NULL;
    TPM_HANDLE sessionHandle = TPM_RH_NULL;
    TPMI_RH_NV_INDEX nvIndex;
    TPM2B_PUBLIC_KEY_RSA message;

    byte pcr[WC_SHA256_DIGEST_SIZE];
    int pcr_len = WC_SHA256_DIGEST_SIZE;
    byte hash[WC_SHA256_DIGEST_SIZE];
    int hash_len = WC_SHA256_DIGEST_SIZE;

    TpmRsaKey endorse;
    TpmRsaKey storage;
    TpmHmacKey hmacKey;
    TpmEccKey eccKey;
    TpmRsaKey rsaKey;

    const char storagePwd[] = "WolfTPMPassword";
    const char usageAuth[] = "ThisIsASecretUsageAuth";
    const char userKey[] = "ThisIsMyHmacKey";
    const char label[] = "ThisIsMyLabel";
    const char keyCreationNonce[] = "RandomServerPickedCreationNonce";

    const char* hashTestData =
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    const char* hashTestDig =
        "\x24\x8D\x6A\x61\xD2\x06\x38\xB8\xE5\xC0\x26\x93\x0C\x3E\x60"
        "\x39\xA3\x3C\xE4\x59\x64\xFF\x21\x67\xF6\xEC\xED\xD4\x19\xDB"
        "\x06\xC1";

    TPMS_AUTH_COMMAND session[MAX_SESSION_NUM];


    printf("TPM2 Demo using Native API's\n");

    endorse.handle = TPM_RH_NULL;
    storage.handle = TPM_RH_NULL;
    hmacKey.handle = TPM_RH_NULL;
    eccKey.handle = TPM_RH_NULL;

    message.size = WC_SHA256_DIGEST_SIZE;
    XMEMSET(message.buffer, 0x11, message.size);


    rc = TPM2_Init(&tpm2Ctx, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_Init failed 0x%x: %s\n", rc, wolfTPM2_GetRCString(rc));
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
        printf("TPM2_Startup failed 0x%x: %s\n", rc, wolfTPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_Startup pass\n");


    /* Full self test */
    XMEMSET(&cmdIn.selfTest, 0, sizeof(cmdIn.selfTest));
    cmdIn.selfTest.fullTest = YES;
    rc = TPM2_SelfTest(&cmdIn.selfTest);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_SelfTest failed 0x%x: %s\n", rc, wolfTPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_SelfTest pass\n");

    /* Get Test Result */
    rc = TPM2_GetTestResult(&cmdOut.tr);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_GetTestResult failed 0x%x: %s\n", rc,
            wolfTPM2_GetRCString(rc));
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
            wolfTPM2_GetRCString(rc));
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
            wolfTPM2_GetRCString(rc));
        goto exit;
    }
    tpmProp = &cmdOut.cap.capabilityData.data.tpmProperties;
    pcrCount = tpmProp->tpmProperty[0].value;
    printf("TPM2_GetCapability: Property PCR Count %d\n", pcrCount);


    /* Random */
    XMEMSET(&cmdIn.getRand, 0, sizeof(cmdIn.getRand));
    cmdIn.getRand.bytesRequested = WC_SHA256_DIGEST_SIZE;
    rc = TPM2_GetRandom(&cmdIn.getRand, &cmdOut.getRand);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_GetRandom failed 0x%x: %s\n", rc,
            wolfTPM2_GetRCString(rc));
        goto exit;
    }
    if (cmdOut.getRand.randomBytes.size != WC_SHA256_DIGEST_SIZE) {
        printf("TPM2_GetRandom length mismatch %d != %d\n",
            cmdOut.getRand.randomBytes.size, WC_SHA256_DIGEST_SIZE);
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
            wolfTPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_StirRandom: success\n");


    /* PCR Read */
    for (i=0; i<pcrCount; i++) {
        pcrIndex = i;
        XMEMSET(&cmdIn.pcrRead, 0, sizeof(cmdIn.pcrRead));
        wolfTPM2_SetupPCRSel(&cmdIn.pcrRead.pcrSelectionIn,
            TPM_ALG_SHA256, pcrIndex);
        rc = TPM2_PCR_Read(&cmdIn.pcrRead, &cmdOut.pcrRead);
        if (rc != TPM_RC_SUCCESS) {
            printf("TPM2_PCR_Read failed 0x%x: %s\n", rc,
                wolfTPM2_GetRCString(rc));
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
        printf("TPM2_PCR_Extend failed 0x%x: %s\n", rc,
            wolfTPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_PCR_Extend success\n");

    XMEMSET(&cmdIn.pcrRead, 0, sizeof(cmdIn.pcrRead));
    wolfTPM2_SetupPCRSel(&cmdIn.pcrRead.pcrSelectionIn,
        TPM_ALG_SHA256, pcrIndex);
    rc = TPM2_PCR_Read(&cmdIn.pcrRead, &cmdOut.pcrRead);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_PCR_Read failed 0x%x: %s\n", rc, wolfTPM2_GetRCString(rc));
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
    rc = TPM2_GetNonce(cmdIn.authSes.nonceCaller.buffer,
                       cmdIn.authSes.nonceCaller.size);
    if (rc < 0) {
        printf("wc_RNG_GenerateBlock failed 0x%x: %s\n", rc,
            wc_GetErrorString(rc));
        goto exit;
    }
    rc = TPM2_StartAuthSession(&cmdIn.authSes, &cmdOut.authSes);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_StartAuthSession failed 0x%x: %s\n", rc,
            wolfTPM2_GetRCString(rc));
        goto exit;
    }
    sessionHandle = cmdOut.authSes.sessionHandle;
    printf("TPM2_StartAuthSession: sessionHandle 0x%x\n", sessionHandle);


    /* Policy Get Digest */
    XMEMSET(&cmdIn.policyGetDigest, 0, sizeof(cmdIn.policyGetDigest));
    cmdIn.policyGetDigest.policySession = sessionHandle;
    rc = TPM2_PolicyGetDigest(&cmdIn.policyGetDigest, &cmdOut.policyGetDigest);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_PolicyGetDigest failed 0x%x: %s\n", rc,
            wolfTPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_PolicyGetDigest: size %d\n",
        cmdOut.policyGetDigest.policyDigest.size);
    TPM2_PrintBin(cmdOut.policyGetDigest.policyDigest.buffer,
        cmdOut.policyGetDigest.policyDigest.size);

    /* Read PCR[0] SHA1 */
    pcrIndex = 0;
    XMEMSET(&cmdIn.pcrRead, 0, sizeof(cmdIn.pcrRead));
    wolfTPM2_SetupPCRSel(&cmdIn.pcrRead.pcrSelectionIn, TPM_ALG_SHA1, pcrIndex);
    rc = TPM2_PCR_Read(&cmdIn.pcrRead, &cmdOut.pcrRead);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_PCR_Read failed 0x%x: %s\n", rc,
            wolfTPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_PCR_Read: Index %d, Digest Sz %d, Update Counter %d\n",
        pcrIndex,
        (int)cmdOut.pcrRead.pcrValues.digests[0].size,
        (int)cmdOut.pcrRead.pcrUpdateCounter);
    TPM2_PrintBin(cmdOut.pcrRead.pcrValues.digests[0].buffer,
                   cmdOut.pcrRead.pcrValues.digests[0].size);

    /* Hash SHA256 PCR[0] */
    rc = wc_Hash(WC_HASH_TYPE_SHA256, pcr, pcr_len, hash, hash_len);
    if (rc < 0) {
        printf("wc_Hash failed 0x%x: %s\n", rc, wc_GetErrorString(rc));
        goto exit;
    }
    printf("wc_Hash of PCR[0]: size %d\n", hash_len);
    TPM2_PrintBin(hash, hash_len);

    /* Policy PCR */
    pcrIndex = 0;
    XMEMSET(&cmdIn.policyPCR, 0, sizeof(cmdIn.policyPCR));
    cmdIn.policyPCR.policySession = sessionHandle;
    cmdIn.policyPCR.pcrDigest.size = hash_len;
    XMEMCPY(cmdIn.policyPCR.pcrDigest.buffer, hash, hash_len);
    wolfTPM2_SetupPCRSel(&cmdIn.policyPCR.pcrs, TPM_ALG_SHA1, pcrIndex);
    rc = TPM2_PolicyPCR(&cmdIn.policyPCR);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_PolicyPCR failed 0x%x: %s\n", rc,
            wolfTPM2_GetRCString(rc));
        //goto exit;
    }
    printf("TPM2_PolicyPCR: Updated\n");


    /* Policy Restart (for session) */
    XMEMSET(&cmdIn.policyRestart, 0, sizeof(cmdIn.policyRestart));
    cmdIn.policyRestart.sessionHandle = sessionHandle;
    rc = TPM2_PolicyRestart(&cmdIn.policyRestart);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_PolicyRestart failed 0x%x: %s\n", rc,
            wolfTPM2_GetRCString(rc));
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
            wolfTPM2_GetRCString(rc));
        goto exit;
    }
    handle = cmdOut.hashSeqStart.sequenceHandle;
    printf("TPM2_HashSequenceStart: sequenceHandle 0x%x\n", handle);

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
            wolfTPM2_GetRCString(rc));
        goto exit;
    }

    XMEMSET(&cmdIn.seqComp, 0, sizeof(cmdIn.seqComp));
    cmdIn.seqComp.sequenceHandle = handle;
    cmdIn.seqComp.hierarchy = TPM_RH_NULL;
    rc = TPM2_SequenceComplete(&cmdIn.seqComp, &cmdOut.seqComp);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_SequenceComplete failed 0x%x: %s\n", rc,
            wolfTPM2_GetRCString(rc));
        goto exit;
    }
    if (cmdOut.seqComp.result.size != WC_SHA256_DIGEST_SIZE &&
        XMEMCMP(cmdOut.seqComp.result.buffer, hashTestDig,
                                                WC_SHA256_DIGEST_SIZE) != 0) {
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
        printf("TPM2_Clear failed 0x%x: %s\n", rc, wolfTPM2_GetRCString(rc));
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
        printf("TPM2_CreatePrimary: Endorsement failed 0x%x: %s\n", rc, wolfTPM2_GetRCString(rc));
        goto exit;
    }
    endorse.handle = cmdOut.createPri.objectHandle;
    endorse.auth = cmdIn.createPri.inPublic.publicArea.authPolicy;
    endorse.public = cmdOut.createPri.outPublic;
    endorse.name = cmdOut.createPri.name;
    endorse.symmetric = cmdIn.createPri.inPublic.publicArea.parameters.rsaDetail.symmetric;
    printf("TPM2_CreatePrimary: Endorsement 0x%x (%d bytes)\n",
        endorse.handle, endorse.public.size);


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
            wolfTPM2_GetRCString(rc));
        goto exit;
    }
    storage.handle = cmdOut.createPri.objectHandle;
    storage.public = cmdOut.createPri.outPublic;
    storage.name = cmdOut.createPri.name;
    printf("TPM2_CreatePrimary: Storage 0x%x (%d bytes)\n",
        storage.handle, storage.public.size);

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
    cmdIn.loadExt.inPublic = endorse.public;
    cmdIn.loadExt.hierarchy = TPM_RH_NULL;
    rc = TPM2_LoadExternal(&cmdIn.loadExt, &cmdOut.loadExt);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_LoadExternal: failed 0x%x: %s\n", rc,
            wolfTPM2_GetRCString(rc));
        goto exit;
    }
    handle = cmdOut.loadExt.objectHandle;
    printf("TPM2_LoadExternal: 0x%x\n", handle);

    /* Make a credential */
    XMEMSET(&cmdIn.makeCred, 0, sizeof(cmdIn.makeCred));
    cmdIn.makeCred.handle = handle;
    cmdIn.makeCred.credential.size = WC_SHA256_DIGEST_SIZE;
    XMEMSET(cmdIn.makeCred.credential.buffer, 0x11,
        cmdIn.makeCred.credential.size);
    cmdIn.makeCred.objectName = endorse.name;
    rc = TPM2_MakeCredential(&cmdIn.makeCred, &cmdOut.makeCred);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_MakeCredential: failed 0x%x: %s\n", rc,
            wolfTPM2_GetRCString(rc));
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
            wolfTPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_ReadPublic Handle 0x%x: pub %d, name %d, qualifiedName %d\n",
        cmdIn.readPub.objectHandle,
        cmdOut.readPub.outPublic.size, cmdOut.readPub.name.size,
        cmdOut.readPub.qualifiedName.size);

    cmdIn.flushCtx.flushHandle = handle;
    TPM2_FlushContext(&cmdIn.flushCtx);



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
        printf("TPM2_Create HMAC failed 0x%x: %s\n", rc, wolfTPM2_GetRCString(rc));
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
        printf("TPM2_Load failed 0x%x: %s\n", rc, wolfTPM2_GetRCString(rc));
        goto exit;
    }
    hmacKey.handle = cmdOut.load.objectHandle;
    printf("TPM2_Load New HMAC Key Handle 0x%x\n", hmacKey.handle);



    /* Allow object change auth */
    XMEMSET(&cmdIn.policyCC, 0, sizeof(cmdIn.policyCC));
    cmdIn.policyCC.policySession = sessionHandle;
    cmdIn.policyCC.code = TPM_CC_ObjectChangeAuth;
    rc = TPM2_PolicyCommandCode(&cmdIn.policyCC);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_PolicyCommandCode failed 0x%x: %s\n", rc,
            wolfTPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_PolicyCommandCode: success\n");

    /* Change Object Auth */
    XMEMSET(&cmdIn.objChgAuth, 0, sizeof(cmdIn.objChgAuth));
    cmdIn.objChgAuth.objectHandle = hmacKey.handle;
    cmdIn.objChgAuth.parentHandle = storage.handle;
    cmdIn.objChgAuth.newAuth.size = WC_SHA256_DIGEST_SIZE;
    rc = TPM2_GetNonce(cmdIn.objChgAuth.newAuth.buffer,
                       cmdIn.objChgAuth.newAuth.size);
    if (rc < 0) {
        printf("wc_RNG_GenerateBlock failed 0x%x: %s\n", rc,
            wc_GetErrorString(rc));
        goto exit;
    }
    rc = TPM2_ObjectChangeAuth(&cmdIn.objChgAuth, &cmdOut.objChgAuth);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_ObjectChangeAuth failed 0x%x: %s\n", rc,
            wolfTPM2_GetRCString(rc));
        //goto exit;
    }
    hmacKey.private = cmdOut.objChgAuth.outPrivate;
    printf("TPM2_ObjectChangeAuth: private %d\n", hmacKey.private.size);

    cmdIn.flushCtx.flushHandle = hmacKey.handle;
    TPM2_FlushContext(&cmdIn.flushCtx);



    /* Get a curve's parameters */
    XMEMSET(&cmdIn.eccParam, 0, sizeof(cmdIn.eccParam));
    cmdIn.eccParam.curveID = TPM_ECC_NIST_P256;
    rc = TPM2_ECC_Parameters(&cmdIn.eccParam, &cmdOut.eccParam);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_ECC_Parameters failed 0x%x: %s\n", rc,
            wolfTPM2_GetRCString(rc));
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
            wolfTPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_Create: New ECDSA Key: pub %d, priv %d\n",
        cmdOut.create.outPublic.size,
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
        printf("TPM2_Load ECDSA failed 0x%x: %s\n", rc,
            wolfTPM2_GetRCString(rc));
        goto exit;
    }
    eccKey.handle = cmdOut.load.objectHandle;
    printf("TPM2_Load ECDSA Key Handle 0x%x\n", eccKey.handle);

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
        printf("TPM2_Sign failed 0x%x: %s\n", rc, wolfTPM2_GetRCString(rc));
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
            wolfTPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_VerifySignature: Tag %d\n", cmdOut.verifySign.validation.tag);

    cmdIn.flushCtx.flushHandle = eccKey.handle;
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
        printf("TPM2_Create ECDH failed 0x%x: %s\n", rc, wolfTPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_Create: New ECDH Key: pub %d, priv %d\n",
        cmdOut.create.outPublic.size,
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
        printf("TPM2_Load ECDH key failed 0x%x: %s\n", rc,
            wolfTPM2_GetRCString(rc));
        goto exit;
    }
    eccKey.handle = cmdOut.load.objectHandle;
    printf("TPM2_Load ECDH Key Handle 0x%x\n", eccKey.handle);

    /* set session auth for ecc key */
    session[0].auth.size = sizeof(usageAuth)-1;
    XMEMCPY(session[0].auth.buffer, usageAuth, session[0].auth.size);

    /* ECDH Key Gen (gen public point and shared secret) */
    XMEMSET(&cmdIn.ecdh, 0, sizeof(cmdIn.ecdh));
    cmdIn.ecdh.keyHandle = eccKey.handle;
    rc = TPM2_ECDH_KeyGen(&cmdIn.ecdh, &cmdOut.ecdh);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_ECDH_KeyGen failed 0x%x: %s\n", rc,
            wolfTPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_ECDH_KeyGen: zPt %d, pubPt %d\n",
        cmdOut.ecdh.zPoint.size,
        cmdOut.ecdh.pubPoint.size);


#if 0
    XMEMSET(&cmdIn.ecdhZ, 0, sizeof(cmdIn.ecdhZ));
    cmdIn.ecdhZ.keyHandle = eccKey.handle;
    cmdIn.ecdhZ.inPoint = cmdOut.ecdh.pubPoint;
    rc = TPM2_ECDH_ZGen(&cmdIn.ecdhZ, &cmdOut.ecdhZ);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_ECDH_KeyGen failed 0x%x: %s\n", rc,
            wolfTPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_ECDH_KeyGen: zPt %d\n",
        cmdOut.ecdhZ.outPoint.size);

    /* verify shared secret is the same */
#endif

    cmdIn.flushCtx.flushHandle = eccKey.handle;
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
            wolfTPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_Create: New RSA Key: pub %d, priv %d\n",
        cmdOut.create.outPublic.size,
        cmdOut.create.outPrivate.size);
    rsaKey.public = cmdOut.create.outPublic;
    rsaKey.private = cmdOut.create.outPrivate;

    /* Load new key */
    XMEMSET(&cmdIn.load, 0, sizeof(cmdIn.load));
    cmdIn.load.parentHandle = storage.handle;
    cmdIn.load.inPrivate = rsaKey.private;
    cmdIn.load.inPublic = rsaKey.public;
    rc = TPM2_Load(&cmdIn.load, &cmdOut.load);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_Load RSA key failed 0x%x: %s\n", rc,
            wolfTPM2_GetRCString(rc));
        goto exit;
    }
    rsaKey.handle = cmdOut.load.objectHandle;
    printf("TPM2_Load RSA Key Handle 0x%x\n", rsaKey.handle);

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
            wolfTPM2_GetRCString(rc));
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
            wolfTPM2_GetRCString(rc));
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
    TPM2_FlushContext(&cmdIn.flushCtx);


    /* set session auth for storage key */
    session[0].auth.size = sizeof(storagePwd)-1;
    XMEMCPY(session[0].auth.buffer, storagePwd, session[0].auth.size);


    /* NVRAM Access */

    for (nvIndex=TPM_20_TPM_MFG_NV_SPACE; nvIndex<TPM_20_TPM_MFG_NV_SPACE+10; nvIndex++) {
        XMEMSET(&cmdIn.nvReadPub, 0, sizeof(cmdIn.nvReadPub));
        cmdIn.nvReadPub.nvIndex = nvIndex;
        rc = TPM2_NV_ReadPublic(&cmdIn.nvReadPub, &cmdOut.nvReadPub);
        if (rc != TPM_RC_SUCCESS) {
            printf("TPM2_NV_ReadPublic failed 0x%x: %s\n", rc,
                wolfTPM2_GetRCString(rc));
            //goto exit;
        }
        else if (cmdOut.nvReadPub.nvPublic.size > 0) {
            printf("TPM2_NV_ReadPublic: Sz %d, Idx 0x%x, nameAlg %d, Attr 0x%x,"
                    " authPol %d, dataSz %d, name %d\n",
                cmdOut.nvReadPub.nvPublic.size,
                cmdOut.nvReadPub.nvPublic.nvPublic.nvIndex,
                cmdOut.nvReadPub.nvPublic.nvPublic.nameAlg,
                cmdOut.nvReadPub.nvPublic.nvPublic.attributes,
                cmdOut.nvReadPub.nvPublic.nvPublic.authPolicy.size,
                cmdOut.nvReadPub.nvPublic.nvPublic.dataSize,
                cmdOut.nvReadPub.nvName.size);
        }
    }

    /* Define new NV */
    nvIndex = TPM_20_OWNER_NV_SPACE + 0x003FFFFF; /* Last owner Index */
    XMEMSET(&cmdIn.nvDefine, 0, sizeof(cmdIn.nvDefine));
    cmdIn.nvDefine.authHandle = storage.handle;
    cmdIn.nvDefine.auth.size = sizeof(usageAuth)-1;
    XMEMCPY(cmdIn.nvDefine.auth.buffer, usageAuth, cmdIn.nvDefine.auth.size);
    cmdIn.nvDefine.publicInfo.nvPublic.nvIndex = nvIndex;
    cmdIn.nvDefine.publicInfo.nvPublic.nameAlg = TPM_ALG_SHA256;
    cmdIn.nvDefine.publicInfo.nvPublic.attributes = (
        TPMA_NV_OWNERWRITE | TPMA_NV_OWNERREAD | TPMA_NV_NO_DA | TPMA_NV_ORDERLY);
    cmdIn.nvDefine.publicInfo.nvPublic.dataSize = WC_SHA256_DIGEST_SIZE;
    rc = TPM2_NV_DefineSpace(&cmdIn.nvDefine);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_NV_DefineSpace failed 0x%x: %s\n", rc,
            wolfTPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_NV_DefineSpace: 0x%x\n", nvIndex);

    /* Read NV */
    XMEMSET(&cmdIn.nvReadPub, 0, sizeof(cmdIn.nvReadPub));
    cmdIn.nvReadPub.nvIndex = nvIndex;
    rc = TPM2_NV_ReadPublic(&cmdIn.nvReadPub, &cmdOut.nvReadPub);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_NV_ReadPublic failed 0x%x: %s\n", rc,
            wolfTPM2_GetRCString(rc));
        //goto exit;
    }
    printf("TPM2_NV_ReadPublic: Sz %d, Idx 0x%x, nameAlg %d, Attr 0x%x, "
            "authPol %d, dataSz %d, name %d\n",
        cmdOut.nvReadPub.nvPublic.size,
        cmdOut.nvReadPub.nvPublic.nvPublic.nvIndex,
        cmdOut.nvReadPub.nvPublic.nvPublic.nameAlg,
        cmdOut.nvReadPub.nvPublic.nvPublic.attributes,
        cmdOut.nvReadPub.nvPublic.nvPublic.authPolicy.size,
        cmdOut.nvReadPub.nvPublic.nvPublic.dataSize,
        cmdOut.nvReadPub.nvName.size);

    /* Undefine NV */
    XMEMSET(&cmdIn.nvUndefine, 0, sizeof(cmdIn.nvUndefine));
    cmdIn.nvUndefine.authHandle = storage.handle;
    cmdIn.nvUndefine.nvIndex = nvIndex;
    rc = TPM2_NV_UndefineSpace(&cmdIn.nvUndefine);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_NV_UndefineSpace failed 0x%x: %s\n", rc,
            wolfTPM2_GetRCString(rc));
        goto exit;
    }



    /* Clear auth buffer */
    session[0].auth.size = 0;
    XMEMSET(session[0].auth.buffer, 0, sizeof(session[0].auth.buffer));


exit:

    /* Close session */
    if (sessionHandle != TPM_RH_NULL) {
        cmdIn.flushCtx.flushHandle = sessionHandle;
        TPM2_FlushContext(&cmdIn.flushCtx);
    }

    /* Close object handle */
    cmdIn.flushCtx.flushHandle = handle;
    TPM2_FlushContext(&cmdIn.flushCtx);
    cmdIn.flushCtx.flushHandle = eccKey.handle;
    TPM2_FlushContext(&cmdIn.flushCtx);
    cmdIn.flushCtx.flushHandle = hmacKey.handle;
    TPM2_FlushContext(&cmdIn.flushCtx);
    cmdIn.flushCtx.flushHandle = rsaKey.handle;
    TPM2_FlushContext(&cmdIn.flushCtx);

    /* Cleanup key handles */
    cmdIn.flushCtx.flushHandle = endorse.handle;
    TPM2_FlushContext(&cmdIn.flushCtx);
    cmdIn.flushCtx.flushHandle = storage.handle;
    TPM2_FlushContext(&cmdIn.flushCtx);


    /* Shutdown */
    cmdIn.shutdown.shutdownType = TPM_SU_CLEAR;
    rc = TPM2_Shutdown(&cmdIn.shutdown);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_Shutdown failed 0x%x: %s\n", rc, wolfTPM2_GetRCString(rc));
        goto exit;
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
/* --- BEGIN TPM Native API Demo -- */
/******************************************************************************/


#ifndef NO_MAIN_DRIVER
int main(void)
{
    int rc;

#ifndef WOLFTPM2_NO_WRAPPER
    rc = TPM2_Wrapper_Demo(TPM2_USER_CTX);
    if (rc != 0)
        return rc;
#endif

    rc = TPM2_Demo(TPM2_USER_CTX);

    return rc;
}
#endif
