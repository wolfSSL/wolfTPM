/* tpm_io.c
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

/* This example shows IO interfaces for Linux Kernel or STM32 CubeMX HAL */


#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_tis.h>
#include "tpm_io.h"


/******************************************************************************/
/* --- BEGIN IO Callback Logic -- */
/******************************************************************************/
#if ! (defined(WOLFTPM_LINUX_DEV) || \
       defined(WOLFTPM_SWTPM) ||     \
       defined(WOLFTPM_WINAPI) )

/* Configuration for the SPI interface */
/* SPI Requirement: Mode 0 (CPOL=0, CPHA=0) */

/* Use the max speed by default - see tpm2_types.h for chip specific max values */
#ifndef TPM2_SPI_HZ
    #define TPM2_SPI_HZ TPM2_SPI_MAX_HZ
#endif

#if defined(__linux__)
    #include <sys/ioctl.h>
    #ifdef WOLFTPM_I2C
        #include <linux/types.h>
        #include <linux/i2c.h>
        #include <linux/i2c-dev.h>
        #include <sys/ioctl.h>
        #include <sys/types.h>
        #include <sys/stat.h>
    #else
        #include <linux/spi/spidev.h>
    #endif
    #include <fcntl.h>
    #include <unistd.h>

    #ifdef WOLFTPM_I2C
        /* I2C - (Only tested with ST33HTPH I2C) */
        #define TPM2_I2C_ADDR 0x2e
        #define TPM2_I2C_DEV  "/dev/i2c-1"
        #define TPM2_I2C_HZ   400000 /* 400kHz */
    #else
        /* SPI */
        #ifdef WOLFTPM_MCHP
            /* Microchip ATTPM20 uses CE0 */
            #define TPM2_SPI_DEV_CS "0"
        #elif defined(WOLFTPM_ST33)
            /* STM ST33HTPH SPI uses CE0 */
            #define TPM2_SPI_DEV_CS "0"
        #elif defined(WOLFTPM_NUVOTON)
            /* Nuvoton NPCT75x uses CE0 */
            #define TPM2_SPI_DEV_CS "0"
        #else
            /* OPTIGA SLB9670 and LetsTrust TPM use CE1 */
            #define TPM2_SPI_DEV_CS "1"
        #endif

        #ifdef WOLFTPM_AUTODETECT
            #undef TPM2_SPI_DEV
            /* this will try incrementing spidev chip selects */
            static char TPM2_SPI_DEV[] = "/dev/spidev0.0";
            #define MAX_SPI_DEV_CS '4'
            static int foundSpiDev = 0;
        #else
            #define TPM2_SPI_DEV "/dev/spidev0."TPM2_SPI_DEV_CS
        #endif
    #endif


#elif defined(WOLFSSL_STM32_CUBEMX)

#elif defined(WOLFSSL_ATMEL)
    #include "asf.h"

#elif defined(__BAREBOX__)
    #include <spi/spi.h>
    #include <spi/spi_gpio.h>

#elif defined(__XILINX__)

    #include "xspips.h"
    static int SpiInitDone;
    static XSpiPs SpiInstance;
    #ifndef TPM2_SPI_CHIPSELECT
    #define TPM2_SPI_CHIPSELECT 0x00
    #endif
    #ifndef TPM2_SPI_DEVID
    #define TPM2_SPI_DEVID      XPAR_XSPIPS_1_DEVICE_ID
    #endif

#else
    /* TODO: Add your platform here for HW interface */

#endif


#if defined(__linux__)
#if defined(WOLFTPM_I2C)
    #define TPM_I2C_TRIES 10
    static int i2c_read(int fd, word32 reg, byte* data, int len)
    {
        int rc;
        struct i2c_rdwr_ioctl_data rdwr;
        struct i2c_msg msgs[2];
        unsigned char buf[2];
        int timeout = TPM_I2C_TRIES;

        rdwr.msgs = msgs;
        rdwr.nmsgs = 2;
        buf[0] = (reg & 0xFF); /* address */

        msgs[0].flags = 0;
        msgs[0].buf = buf;
        msgs[0].len = 1;
        msgs[0].addr = TPM2_I2C_ADDR;

        msgs[1].flags = I2C_M_RD;
        msgs[1].buf =  data;
        msgs[1].len =  len;
        msgs[1].addr = TPM2_I2C_ADDR;

        /* The I2C device may hold clock low to indicate busy, which results in
         * ioctl failure here. Typically the retry completes in 1-3 retries.
         * Its important to keep device open during these retries */
        do {
            rc = ioctl(fd, I2C_RDWR, &rdwr);
            if (rc != -1)
                break;
        } while (--timeout > 0);

        return (rc == -1) ? TPM_RC_FAILURE : TPM_RC_SUCCESS;
    }

    static int i2c_write(int fd, word32 reg, byte* data, int len)
    {
        int rc;
        struct i2c_rdwr_ioctl_data rdwr;
        struct i2c_msg msgs[1];
        byte buf[MAX_SPI_FRAMESIZE+1];
        int timeout = TPM_I2C_TRIES;

        /* TIS layer should never provide a buffer larger than this,
           but double check for good coding practice */
        if (len > MAX_SPI_FRAMESIZE)
            return BAD_FUNC_ARG;

        rdwr.msgs = msgs;
        rdwr.nmsgs = 1;
        buf[0] = (reg & 0xFF); /* address */
        XMEMCPY(buf + 1, data, len);

        msgs[0].flags = 0;
        msgs[0].buf = buf;
        msgs[0].len = len + 1;
        msgs[0].addr = TPM2_I2C_ADDR;

        /* The I2C device may hold clock low to indicate busy, which results in
         * ioctl failure here. Typically the retry completes in 1-3 retries.
         * Its important to keep device open during these retries */
        do {
            rc = ioctl(fd, I2C_RDWR, &rdwr);
            if (rc != -1)
                break;
        } while (--timeout > 0);

        return (rc == -1) ? TPM_RC_FAILURE : TPM_RC_SUCCESS;
    }

    /* Use Linux I2C */
    static int TPM2_IoCb_Linux_I2C(TPM2_CTX* ctx, int isRead, word32 addr, byte* buf,
        word16 size, void* userCtx)
    {
        int ret = TPM_RC_FAILURE;
        int i2cDev = open(TPM2_I2C_DEV, O_RDWR);
        if (i2cDev >= 0) {
            if (isRead)
                ret = i2c_read(i2cDev, addr, buf, size);
            else
                ret = i2c_write(i2cDev, addr, buf, size);

            close(i2cDev);
        }

        (void)ctx;
        (void)userCtx;

        return ret;
    }

#else
    /* Use Linux SPI synchronous access */
    static int TPM2_IoCb_Linux_SPI(TPM2_CTX* ctx, const byte* txBuf, byte* rxBuf,
        word16 xferSz, void* userCtx)
    {
        int ret = TPM_RC_FAILURE;
        int spiDev;
    #ifdef WOLFTPM_CHECK_WAIT_STATE
        int timeout = TPM_SPI_WAIT_RETRY;
    #endif

        /* Note: PI has issue with 5-10Mhz on packets sized over 130 bytes */
        unsigned int maxSpeed = TPM2_SPI_HZ;
        int mode = 0; /* Mode 0 (CPOL=0, CPHA=0) */
        int bits_per_word = 8; /* 8-bits */

    #ifdef WOLFTPM_AUTODETECT
    tryagain:
    #endif

        spiDev = open(TPM2_SPI_DEV, O_RDWR);
        if (spiDev >= 0) {
            struct spi_ioc_transfer spi;
            size_t size;

            ioctl(spiDev, SPI_IOC_WR_MODE, &mode);
            ioctl(spiDev, SPI_IOC_WR_MAX_SPEED_HZ, &maxSpeed);
            ioctl(spiDev, SPI_IOC_WR_BITS_PER_WORD, &bits_per_word);

            XMEMSET(&spi, 0, sizeof(spi));
            spi.cs_change = 1; /* strobe CS between transfers */

    #ifdef WOLFTPM_CHECK_WAIT_STATE
            /* Send Header */
            spi.tx_buf   = (unsigned long)txBuf;
            spi.rx_buf   = (unsigned long)rxBuf;
            spi.len      = TPM_TIS_HEADER_SZ;
            size = ioctl(spiDev, SPI_IOC_MESSAGE(1), &spi);
            if (size != TPM_TIS_HEADER_SZ) {
                close(spiDev);
                return TPM_RC_FAILURE;
            }

            /* Handle SPI wait states (ST33 typical wait is 2 bytes) */
            if ((rxBuf[TPM_TIS_HEADER_SZ-1] & TPM_TIS_READY_MASK) == 0) {
                do {
                    /* Check for SPI ready */
                    spi.len = 1;
                    size = ioctl(spiDev, SPI_IOC_MESSAGE(1), &spi);
                    if (rxBuf[0] & TPM_TIS_READY_MASK)
                        break;
                } while (size == 1 && --timeout > 0);
            #ifdef WOLFTPM_DEBUG_TIMEOUT
                printf("SPI Ready Timeout %d\n", TPM_SPI_WAIT_RETRY - timeout);
            #endif
                if (size == 1 && timeout > 0) {
                    ret = TPM_RC_SUCCESS;
                }
            }
            else {
                ret = TPM_RC_SUCCESS;
            }

            if (ret == TPM_RC_SUCCESS) {
                /* Remainder of message */
                spi.tx_buf   = (unsigned long)&txBuf[TPM_TIS_HEADER_SZ];
                spi.rx_buf   = (unsigned long)&rxBuf[TPM_TIS_HEADER_SZ];
                spi.len      = xferSz - TPM_TIS_HEADER_SZ;
                size = ioctl(spiDev, SPI_IOC_MESSAGE(1), &spi);

                if (size == (size_t)xferSz - TPM_TIS_HEADER_SZ)
                    ret = TPM_RC_SUCCESS;
            }
    #else
            /* Send Entire Message - no wait states */
            spi.tx_buf   = (unsigned long)txBuf;
            spi.rx_buf   = (unsigned long)rxBuf;
            spi.len      = xferSz;
            size = ioctl(spiDev, SPI_IOC_MESSAGE(1), &spi);
            if (size == (size_t)xferSz)
                ret = TPM_RC_SUCCESS;
    #endif /* WOLFTPM_CHECK_WAIT_STATE */

            close(spiDev);
        }

    #ifdef WOLFTPM_AUTODETECT
        /* if response is not 0xFF then we "found" something */
        if (!foundSpiDev) {
            if (ret == TPM_RC_SUCCESS && rxBuf[0] != 0xFF) {
        #ifdef DEBUG_WOLFTPM
                printf("Found TPM @ %s\n", TPM2_SPI_DEV);
        #endif
                foundSpiDev = 1;
            }
            else {
                int devLen = (int)XSTRLEN(TPM2_SPI_DEV);
                /* tries spidev0.[0-4] */
                if (TPM2_SPI_DEV[devLen-1] <= MAX_SPI_DEV_CS) {
                    TPM2_SPI_DEV[devLen-1]++;
                    goto tryagain;
                }
            }
        }
    #endif

        (void)ctx;
        (void)userCtx;

        return ret;
    }
#endif /* WOLFTPM_I2C */

#elif defined(WOLFSSL_STM32_CUBEMX)
    /* STM32 CubeMX Hal */
    #define STM32_CUBEMX_SPI_TIMEOUT 250
    static int TPM2_IoCb_STCubeMX_SPI(TPM2_CTX* ctx, const byte* txBuf, byte* rxBuf,
        word16 xferSz, void* userCtx)
    {
        int ret = TPM_RC_FAILURE;
        SPI_HandleTypeDef* hspi = (SPI_HandleTypeDef*)userCtx;
        HAL_StatusTypeDef status;
    #ifdef WOLFTPM_CHECK_WAIT_STATE
        int timeout = TPM_SPI_WAIT_RETRY;
    #endif

        __HAL_SPI_ENABLE(hspi);
    #ifndef USE_HW_SPI_CS
        HAL_GPIO_WritePin(GPIOA, GPIO_PIN_15, GPIO_PIN_RESET); /* active low */
    #endif

    #ifdef WOLFTPM_CHECK_WAIT_STATE
        /* Send Header */
        status = HAL_SPI_TransmitReceive(hspi, (byte*)txBuf, rxBuf,
            TPM_TIS_HEADER_SZ, STM32_CUBEMX_SPI_TIMEOUT);
        if (status != HAL_OK) {
        #ifndef USE_HW_SPI_CS
            HAL_GPIO_WritePin(GPIOA, GPIO_PIN_15, GPIO_PIN_SET);
        #endif
            __HAL_SPI_DISABLE(hspi);
            return TPM_RC_FAILURE;
        }

        /* Check for wait states */
        if ((rxBuf[TPM_TIS_HEADER_SZ-1] & TPM_TIS_READY_MASK) == 0) {
            do {
                /* Check for SPI ready */
                status = HAL_SPI_TransmitReceive(hspi, (byte*)txBuf, rxBuf, 1,
                    STM32_CUBEMX_SPI_TIMEOUT);
                if (rxBuf[0] & TPM_TIS_READY_MASK)
                    break;
            } while (status == HAL_OK && --timeout > 0);
        #ifdef WOLFTPM_DEBUG_TIMEOUT
            printf("SPI Ready Wait %d\n", TPM_SPI_WAIT_RETRY - timeout);
        #endif
            if (timeout <= 0) {
            #ifndef USE_HW_SPI_CS
                HAL_GPIO_WritePin(GPIOA, GPIO_PIN_15, GPIO_PIN_SET);
            #endif
                __HAL_SPI_DISABLE(hspi);
                return TPM_RC_FAILURE;
            }
        }

        /* Send remainder of payload */
        status = HAL_SPI_TransmitReceive(hspi,
            (byte*)&txBuf[TPM_TIS_HEADER_SZ],
            &rxBuf[TPM_TIS_HEADER_SZ],
            xferSz - TPM_TIS_HEADER_SZ, STM32_CUBEMX_SPI_TIMEOUT);
    #else
        /* Send Entire Message - no wait states */
        status = HAL_SPI_TransmitReceive(hspi, (byte*)txBuf, rxBuf, xferSz,
            STM32_CUBEMX_SPI_TIMEOUT);
    #endif /* WOLFTPM_CHECK_WAIT_STATE */

    #ifndef USE_HW_SPI_CS
        HAL_GPIO_WritePin(GPIOA, GPIO_PIN_15, GPIO_PIN_SET);
    #endif
        __HAL_SPI_DISABLE(hspi);

        if (status == HAL_OK)
            ret = TPM_RC_SUCCESS;

        (void)ctx;

        return ret;
    }

#elif defined(WOLFSSL_ATMEL)
    /* Atmel ASF */
    #define SPI_BAUD_RATE_4M    21
    #define CS_SPI_TPM          2

    /* Atmel ATSAM3X8EA Chip Selects */
    static const byte Spi_CS[] =  {    0,    1,    2,    3 };
    static const byte Spi_PCS[] = { 0x0E, 0x0D, 0x0B, 0x07 };

    static inline byte GetSPI_PCS(byte pcs)
    {
        if (pcs < sizeof(Spi_PCS))
            return Spi_PCS[pcs];
        return 0;
    }

    static inline byte GetSPI_CS(byte cs)
    {
        if (cs < sizeof(Spi_CS))
            return Spi_CS[cs];
        return 0;
    }

    static byte InitSPI_TPM(byte cs, byte baudRate, byte delay1, byte delay2)
    {
        byte csIdx, pcs;

        /* Get CS/PCS */
        csIdx = GetSPI_CS(cs);
        pcs = GetSPI_PCS(cs);

        SPI0->SPI_CR = SPI_CR_SPIDIS;

        SPI0->SPI_CSR[csIdx] = SPI_CSR_DLYBCT(delay2) | SPI_CSR_DLYBS(delay1) |
            SPI_CSR_BITS_8_BIT | SPI_CSR_SCBR(baudRate) | SPI_CSR_CSAAT |
            SPI_CSR_NCPHA;
        SPI0->SPI_MR = SPI_MR_MSTR | SPI_MR_MODFDIS | SPI_MR_PCS(pcs);
        SPI0->SPI_CR = SPI_CR_SPIEN;

        return pcs;
    }

    static int XferSPI_TPM(byte pcs, const byte* pSendBuf, byte* pReadBuf, word16 wLen)
    {
        int ret = TPM_RC_SUCCESS;
        word16 i;

        for (i = 0; i < wLen; i++) {
            while ((SPI0->SPI_SR & SPI_SR_TXEMPTY) == 0);
                SPI0->SPI_TDR = (word16)pSendBuf[i] | (pcs << 16);
            while ((SPI0->SPI_SR & SPI_SR_TDRE) == 0);
            while ((SPI0->SPI_SR & SPI_SR_RDRF) == 0);
            pReadBuf[i] = SPI0->SPI_RDR & 0x00FF;
        }

        return ret;
    }

    static int TPM2_IoCb_Atmel_SPI(TPM2_CTX* ctx, const byte* txBuf, byte* rxBuf,
        word16 xferSz, void* userCtx)
    {
        int ret;
        byte pcs;
    #ifdef WOLFTPM_CHECK_WAIT_STATE
        int timeout = TPM_SPI_WAIT_RETRY;
    #endif

        /* Setup SPI */
        pcs = InitSPI_TPM(CS_SPI_TPM, SPI_BAUD_RATE_4M, 0x02, 0x02);

    #ifdef WOLFTPM_CHECK_WAIT_STATE
        /* Send Header */
        ret = XferSPI_TPM(pcs, txBuf, rxBuf, TPM_TIS_HEADER_SZ);
        if (ret != TPM_RC_SUCCESS) {
            SPI0->SPI_CR = SPI_CR_SPIDIS;
            return ret;
        }

        /* Check for wait states */
        if ((rxBuf[TPM_TIS_HEADER_SZ-1] & TPM_TIS_READY_MASK) == 0) {
            do {
                /* Check for SPI ready */
                ret = XferSPI_TPM(pcs, txBuf, rxBuf, 1);
                if (rxBuf[0] & TPM_TIS_READY_MASK)
                    break;
            } while (ret == TPM_RC_SUCCESS && --timeout > 0);
        #ifdef WOLFTPM_DEBUG_TIMEOUT
            printf("SPI Ready Wait %d\n", TPM_SPI_WAIT_RETRY - timeout);
        #endif
            if (timeout <= 0) {
                SPI0->SPI_CR = SPI_CR_SPIDIS;
                return TPM_RC_FAILURE;
            }
        }

        /* Send remainder of payload */
        ret = XferSPI_TPM(pcs,
            &txBuf[TPM_TIS_HEADER_SZ],
            &rxBuf[TPM_TIS_HEADER_SZ],
            xferSz - TPM_TIS_HEADER_SZ);
    #else
        /* Send Entire Message - no wait states */
        ret = XferSPI_TPM(pcs, txBuf, rxBuf, xferSz);
    #endif /* WOLFTPM_CHECK_WAIT_STATE */

        /* Disable SPI */
        SPI0->SPI_CR = SPI_CR_SPIDIS;

        (void)ctx;
        (void)userCtx;

        return ret;
    }

#elif defined(__BAREBOX__)
    /* Barebox (barebox.org) support */
    static int TPM2_IoCb_Barebox_SPI(TPM2_CTX* ctx, const byte* txBuf,
        byte* rxBuf, word16 xferSz, void* userCtx)
    {
        int ret = TPM_RC_FAILURE;
        struct spi_device spi;
        int bus = 0;
        struct spi_transfer t;
        struct spi_message m;

    #ifdef WOLFTPM_CHECK_WAIT_STATE
        #error SPI check wait state logic not supported for BareBox
    #endif

        XMEMSET(&spi, 0, sizeof(spi));
        spi.master = spi_get_master(bus);   /* get bus 0 master */
        spi.max_speed_hz = 1 * 1000 * 1000; /* 1 MHz */
        spi.mode = 0;                       /* Mode 0 (CPOL=0, CPHA=0) */
        spi.bits_per_word = 8;              /* 8-bits */
        spi.chip_select = 0;                /* Use CS 0 */

        /* setup SPI master */
        ret = spi.master->setup(&spi);

        /* setup transfer */
        XMEMSET(&t, 0, sizeof(t));
        t.tx_buf = txBuf;
        t.rx_buf = rxBuf;
        t.len    = xferSz;
        spi_message_init(&m);
        spi_message_add_tail(&t, &m);
        ret = spi_sync(&spi, &m);
        if (ret == 0)
            ret = TPM_RC_SUCCESS;

        (void)userCtx;
        (void)ctx;

        return ret;
    }

#elif defined(__XILINX__)

    #define XSpiPs_SendByte(BaseAddress, Data) \
        XSpiPs_Out32((BaseAddress) + (u32)XSPIPS_TXD_OFFSET, (u32)(Data))
    #define XSpiPs_RecvByte(BaseAddress) \
        XSpiPs_In32((u32)((BaseAddress) + (u32)XSPIPS_RXD_OFFSET))

    /* Modified version of XSpiPs_PolledTransfer that allows enable and CS to
     * be used across multiple transfers */
    static s32 TPM2_IoCb_Xilinx_SPITransfer(XSpiPs *InstancePtr, u8 *SendBufPtr,
        u8 *RecvBufPtr, u32 ByteCount)
    {
        u32 StatusReg;
        u32 ConfigReg;
        u32 TransCount;
        u32 CheckTransfer;
        u8 TempData;

        /* Set up buffer pointers */
        InstancePtr->SendBufferPtr = SendBufPtr;
        InstancePtr->RecvBufferPtr = RecvBufPtr;
        InstancePtr->RequestedBytes = ByteCount;
        InstancePtr->RemainingBytes = ByteCount;

        while((InstancePtr->RemainingBytes > (u32)0U) ||
              (InstancePtr->RequestedBytes > (u32)0U))
        {
            TransCount = 0U;

            /* Fill the TXFIFO with as many bytes as it will take (or as
             * many as we have to send). */
            while ((InstancePtr->RemainingBytes > (u32)0U) &&
                ((u32)TransCount < (u32)XSPIPS_FIFO_DEPTH))
            {
                XSpiPs_SendByte(InstancePtr->Config.BaseAddress,
                    *InstancePtr->SendBufferPtr);
                InstancePtr->SendBufferPtr += 1;
                InstancePtr->RemainingBytes--;
                ++TransCount;
            }

            /* If master mode and manual start mode, issue manual start
             * command to start the transfer. */
            if ((XSpiPs_IsManualStart(InstancePtr) == TRUE) &&
                (XSpiPs_IsMaster(InstancePtr) == TRUE))
            {
                ConfigReg = XSpiPs_ReadReg(InstancePtr->Config.BaseAddress,
                    XSPIPS_CR_OFFSET);
                ConfigReg |= XSPIPS_CR_MANSTRT_MASK;
                XSpiPs_WriteReg(InstancePtr->Config.BaseAddress,
                    XSPIPS_CR_OFFSET, ConfigReg);
            }

            /* Wait for the transfer to finish by polling Tx fifo status. */
            CheckTransfer = (u32)0U;
            while (CheckTransfer == 0U) {
                StatusReg = XSpiPs_ReadReg(InstancePtr->Config.BaseAddress,
                    XSPIPS_SR_OFFSET);
                if ((StatusReg & XSPIPS_IXR_MODF_MASK) != 0U) {
                    /* Clear the mode fail bit */
                    XSpiPs_WriteReg(InstancePtr->Config.BaseAddress,
                        XSPIPS_SR_OFFSET, XSPIPS_IXR_MODF_MASK);
                    return (s32)XST_SEND_ERROR;
                }
                CheckTransfer = (StatusReg & XSPIPS_IXR_TXOW_MASK);
            }

            /*
             * A transmit has just completed. Process received data and
             * check for more data to transmit.
             * First get the data received as a result of the transmit
             * that just completed. Receive data based on the
             * count obtained while filling tx fifo. Always get the
             * received data, but only fill the receive buffer if it
             * points to something (the upper layer software may not
             * care to receive data).
             */
            while (TransCount != (u32)0U) {
                TempData = (u8)XSpiPs_RecvByte(InstancePtr->Config.BaseAddress);
                if (InstancePtr->RecvBufferPtr != NULL) {
                    *(InstancePtr->RecvBufferPtr) = TempData;
                    InstancePtr->RecvBufferPtr += 1;
                }
                InstancePtr->RequestedBytes--;
                --TransCount;
            }
        }

        return (s32)XST_SUCCESS;
    }

    static int TPM2_IoCb_Xilinx_SPI(TPM2_CTX* ctx, const byte* txBuf,
        byte* rxBuf, word16 xferSz, void* userCtx)
    {
        int ret = TPM_RC_FAILURE;
        int status;
        XSpiPs_Config *SpiConfig;
    #ifdef WOLFTPM_CHECK_WAIT_STATE
        int timeout = TPM_SPI_WAIT_RETRY;
    #endif

        if (!SpiInitDone) {
            /* Initialize the SPI driver so that it's ready to use */
            SpiConfig = XSpiPs_LookupConfig(TPM2_SPI_DEVID);
            if (SpiConfig == NULL) {
                return TPM_RC_FAILURE;
            }
            status = XSpiPs_CfgInitialize(&SpiInstance, SpiConfig,
                SpiConfig->BaseAddress);
            if (status != XST_SUCCESS) {
                return TPM_RC_FAILURE;
            }

            /* Set the SPI device as a master */
            XSpiPs_SetOptions(&SpiInstance, XSPIPS_MASTER_OPTION |
                XSPIPS_FORCE_SSELECT_OPTION | XSPIPS_MANUAL_START_OPTION);
            XSpiPs_SetClkPrescaler(&SpiInstance, XSPIPS_CLK_PRESCALE_8);

            SpiInitDone = 1;
        }

        XSpiPs_Enable(&SpiInstance);
        XSpiPs_SetSlaveSelect(&SpiInstance, TPM2_SPI_CHIPSELECT);

    #ifdef WOLFTPM_CHECK_WAIT_STATE
        /* Send Header */
        status = TPM2_IoCb_Xilinx_SPITransfer(&SpiInstance,
            (byte*)txBuf, rxBuf, TPM_TIS_HEADER_SZ);
        if (status != XST_SUCCESS) {
            XSpiPs_SetSlaveSelect(&SpiInstance, 0xF); /* deselect CS (set high) */
            XSpiPs_Disable(&SpiInstance);
            return ret;
        }

        /* Check for wait states */
        if ((rxBuf[TPM_TIS_HEADER_SZ-1] & TPM_TIS_READY_MASK) == 0) {
            do {
                /* Check for SPI ready */
                status = TPM2_IoCb_Xilinx_SPITransfer(&SpiInstance,
                    (byte*)txBuf, rxBuf, 1);
                if (status == XST_SUCCESS && rxBuf[0] & TPM_TIS_READY_MASK)
                    break;
            } while (ret == TPM_RC_SUCCESS && --timeout > 0);
        #ifdef WOLFTPM_DEBUG_TIMEOUT
            printf("SPI Ready Wait %d\n", TPM_SPI_WAIT_RETRY - timeout);
        #endif
            if (timeout <= 0) {
                XSpiPs_SetSlaveSelect(&SpiInstance, 0xF); /* deselect CS (set high) */
                XSpiPs_Disable(&SpiInstance);
                return TPM_RC_FAILURE;
            }
        }

        /* Send remainder of payload */
        status = TPM2_IoCb_Xilinx_SPITransfer(&SpiInstance,
            (byte*)&txBuf[TPM_TIS_HEADER_SZ],
            &rxBuf[TPM_TIS_HEADER_SZ],
            xferSz - TPM_TIS_HEADER_SZ);
    #else
        /* Send Entire Message - no wait states */
        status = TPM2_IoCb_Xilinx_SPITransfer(&SpiInstance,
            (byte*)txBuf, rxBuf, xferSz);
    #endif /* WOLFTPM_CHECK_WAIT_STATE */
        if (status == XST_SUCCESS) {
            ret = TPM_RC_SUCCESS;
        }

        XSpiPs_SetSlaveSelect(&SpiInstance, 0xF); /* deselect CS (set high) */
        XSpiPs_Disable(&SpiInstance);

        (void)userCtx;
        (void)ctx;

        return ret;
    }


#endif


#if !defined(WOLFTPM_I2C)
static int TPM2_IoCb_SPI(TPM2_CTX* ctx, const byte* txBuf, byte* rxBuf,
    word16 xferSz, void* userCtx)
{
    int ret = TPM_RC_FAILURE;

#if defined(__linux__)
    ret = TPM2_IoCb_Linux_SPI(ctx, txBuf, rxBuf, xferSz, userCtx);
#elif defined(WOLFSSL_STM32_CUBEMX)
    ret = TPM2_IoCb_STCubeMX_SPI(ctx, txBuf, rxBuf, xferSz, userCtx);
#elif defined(WOLFSSL_ATMEL)
    ret = TPM2_IoCb_Atmel_SPI(ctx, txBuf, rxBuf, xferSz, userCtx);
#elif defined(__BAREBOX__)
    ret = TPM2_IoCb_Barebox_SPI(ctx, txBuf, rxBuf, xferSz, userCtx);
#elif defined(__XILINX__)
    ret = TPM2_IoCb_Xilinx_SPI(ctx, txBuf, rxBuf, xferSz, userCtx);
#else

    /* TODO: Add your platform here for HW SPI interface */
    printf("Add your platform here for HW SPI interface\n");
    (void)txBuf;
    (void)rxBuf;
    (void)xferSz;
    (void)userCtx;
#endif

    (void)ctx;

    return ret;
}
#endif /* !WOLFTPM_I2C */


#ifdef WOLFTPM_ADV_IO
int TPM2_IoCb(TPM2_CTX* ctx, int isRead, word32 addr, byte* buf, word16 size,
    void* userCtx)
{
    int ret = TPM_RC_FAILURE;
#ifndef WOLFTPM_I2C
    byte txBuf[MAX_SPI_FRAMESIZE+TPM_TIS_HEADER_SZ];
    byte rxBuf[MAX_SPI_FRAMESIZE+TPM_TIS_HEADER_SZ];
#endif

#ifdef WOLFTPM_DEBUG_IO
    printf("TPM2_IoCb (Adv): Read %d, Addr %x, Size %d\n",
        isRead ? 1 : 0, addr, size);
    if (!isRead) {
        printf("Write Size %d\n", size);
        TPM2_PrintBin(buf, size);
    }
#endif

#if defined(WOLFTPM_I2C)
    #if defined(__linux__)
        /* Use Linux I2C */
        ret = TPM2_IoCb_Linux_I2C(ctx, isRead, addr, buf, size, userCtx);
    #else
        /* TODO: Add your platform here for HW I2C interface */
        printf("Add your platform here for HW I2C interface\n");
        (void)isRead;
        (void)addr;
        (void)buf;
        (void)size;
        (void)userCtx;
    #endif
#else
    /* Build SPI format buffer */
    if (isRead) {
        txBuf[0] = TPM_TIS_READ | ((size & 0xFF) - 1);
        txBuf[1] = (addr>>16) & 0xFF;
        txBuf[2] = (addr>>8)  & 0xFF;
        txBuf[3] = (addr)     & 0xFF;
        txBuf[4] = 0x00;
        XMEMSET(&txBuf[TPM_TIS_HEADER_SZ], 0, size);
    }
    else {
        txBuf[0] = TPM_TIS_WRITE | ((size & 0xFF) - 1);
        txBuf[1] = (addr>>16) & 0xFF;
        txBuf[2] = (addr>>8)  & 0xFF;
        txBuf[3] = (addr)     & 0xFF;
        txBuf[4] = 0x00;
        XMEMCPY(&txBuf[TPM_TIS_HEADER_SZ], buf, size);
    }

    ret = TPM2_IoCb_SPI(ctx, txBuf, rxBuf, size + TPM_TIS_HEADER_SZ, userCtx);

    if (isRead) {
        XMEMCPY(buf, &rxBuf[TPM_TIS_HEADER_SZ], size);
    }
#endif


#ifdef WOLFTPM_DEBUG_IO
    if (isRead) {
        printf("Read Size %d\n", size);
        TPM2_PrintBin(buf, size);
    }
#endif

    (void)ctx;

    return ret;
}

#else

/* IO Callback */
int TPM2_IoCb(TPM2_CTX* ctx, const byte* txBuf, byte* rxBuf,
    word16 xferSz, void* userCtx)
{
    int ret = TPM_RC_FAILURE;

#if !defined(WOLFTPM_I2C)
    ret = TPM2_IoCb_SPI(ctx, txBuf, rxBuf, xferSz, userCtx);
#else
    #error Hardware interface for I2C only supported with WOLFTPM_ADV_IO
#endif

#ifdef WOLFTPM_DEBUG_IO
    printf("TPM2_IoCb: Ret %d, Sz %d\n", ret, xferSz);
    TPM2_PrintBin(txBuf, xferSz);
    TPM2_PrintBin(rxBuf, xferSz);
#endif

    (void)ctx;

    return ret;
}

#endif /* WOLFTPM_ADV_IO */
#endif /* !(WOLFTPM_LINUX_DEV || WOLFTPM_SWTPM || WOLFTPM_WINAPI) */

/******************************************************************************/
/* --- END IO Callback Logic -- */
/******************************************************************************/
