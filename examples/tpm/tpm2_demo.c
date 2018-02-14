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

#include <wolftpm/tpm2.h>
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

/* Util / Debug */
#ifdef DEBUG_WOLFTPM
#define LINE_LEN 16
static void print_bin(const byte* buffer, word32 length)
{
    word32 i;
    char line[80];

    if (!buffer) {
        printf("\tNULL");
        return;
    }

    sprintf(line, "\t");

    for (i = 0; i < LINE_LEN; i++) {
        if (i < length)
            sprintf(line + 1 + i * 3,"%02x ", buffer[i]);
        else
            sprintf(line + 1 + i * 3, "   ");
    }

    sprintf(line + 1 + LINE_LEN * 3, "| ");

    for (i = 0; i < LINE_LEN; i++)
        if (i < length)
            sprintf(line + 3 + LINE_LEN * 3 + i,
                 "%c", 31 < buffer[i] && buffer[i] < 127 ? buffer[i] : '.');

    printf("%s\n", line);

    if (length > LINE_LEN)
        print_bin(buffer + LINE_LEN, length - LINE_LEN);
}
#else
static void print_bin(const byte* buffer, word32 length) {
    (void)buffer;
    (void)length;
    return;
}
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

        memset(&spi, 0, sizeof(spi));
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
    //print_bin(txBuf, xferSz);
    //print_bin(rxBuf, xferSz);
#endif

    (void)ctx;

    return ret;
}

#define RAND_GET_SZ 32

int TPM2_Demo(void* userCtx)
{
    int rc;
    union {
        Startup_In startup;
        Shutdown_In shutdown;
        SelfTest_In selfTest;
        GetRandom_In getRand;
        GetCapability_In cap;
        IncrementalSelfTest_In incSelfTest;
        PCR_Read_In pcrRead;
        PCR_Extend_In pcrExtend;
        CreatePrimary_In create;
        EvictControl_In evict;
        ReadPublic_In readPub;
        StartAuthSession_In authSes;
        Load_In load;
        FlushContext_In flushCtx;
        Unseal_In unseal;
        byte maxInput[MAX_COMMAND_SIZE];
    } cmdIn;
    union {
        GetCapability_Out cap;
        GetRandom_Out getRand;
        GetTestResult_Out tr;
        IncrementalSelfTest_Out incSelfTest;
        PCR_Read_Out pcrRead;
        CreatePrimary_Out create;
        ReadPublic_Out readPub;
        StartAuthSession_Out authSes;
        Load_Out load;
        Unseal_Out unseal;
        byte maxOutput[MAX_RESPONSE_SIZE];
    } cmdOut;
    int pcrCount, pcrIndex, i;
    TPML_TAGGED_TPM_PROPERTY* tpmProp;
    TPMI_SH_POLICY sessionHandle;
    WC_RNG rng;

#ifdef DEBUG_WOLFSSL
    wolfSSL_Debugging_ON();
#endif

    wolfCrypt_Init();

    rc = wc_InitRng(&rng);
    if (rc < 0) {
        printf("wc_InitRng failed: %d\n", rc);
        return rc;
    }

    rc = TPM2_Init(&gTpm2Ctx, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_Init failed %d: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }


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
    print_bin(cmdOut.tr.outData.buffer, cmdOut.tr.outData.size);

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
    print_bin(cmdOut.getRand.randomBytes.buffer,
                   cmdOut.getRand.randomBytes.size);


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
        print_bin(cmdOut.pcrRead.pcrValues.digests[0].buffer,
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
    print_bin(cmdOut.pcrRead.pcrValues.digests[0].buffer,
                   cmdOut.pcrRead.pcrValues.digests[0].size);


    /* Start Auth Session */
    XMEMSET(&cmdIn.authSes, 0, sizeof(cmdIn.authSes));
    cmdIn.authSes.tpmKey = TPM_RH_NULL;
    cmdIn.authSes.bind = TPM_RH_NULL;
    cmdIn.authSes.nonceCaller.size = WC_SHA256_DIGEST_SIZE;
    rc = wc_RNG_GenerateBlock(&rng, cmdIn.authSes.nonceCaller.buffer,
                                                cmdIn.authSes.nonceCaller.size);
    if (rc < 0) {
        printf("wc_RNG_GenerateBlock failed %d: %s\n", rc, wc_GetErrorString(rc));
        goto exit;
    }
    cmdIn.authSes.sessionType = TPM_SE_POLICY;
    cmdIn.authSes.symmetric.algorithm = TPM_ALG_NULL;
    cmdIn.authSes.authHash = TPM_ALG_SHA256;
    rc = TPM2_StartAuthSession(&cmdIn.authSes, &cmdOut.authSes);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_StartAuthSession failed %d: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    sessionHandle = cmdOut.authSes.sessionHandle;
    printf("TPM2_StartAuthSession: sessionHandle 0x%x\n", sessionHandle);


    /* TODO: Add tests for API's */
    //rc = TPM2_CreatePrimary(&cmdIn.create, &cmdOut.create);
    //rc = TPM2_ReadPublic(&cmdIn.readPub, &cmdOut.readPub);
    //TPM_RC TPM2_Load(Load_In* in, Load_Out* out);
    //TPM_RC TPM2_FlushContext(FlushContext_In* in);
    //TPM_RC TPM2_Unseal(Unseal_In* in, Unseal_Out* out);


    /* Shutdown */
    cmdIn.shutdown.shutdownType = TPM_SU_CLEAR;
    rc = TPM2_Shutdown(&cmdIn.shutdown);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_Shutdown failed %d: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }

exit:

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
