/* tpm_io.c
 *
 * Copyright (C) 2006-2018 wolfSSL Inc.
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
#include <examples/tpm_io.h>


/******************************************************************************/
/* --- BEGIN IO Callback Logic -- */
/******************************************************************************/

/* Configuration for the SPI interface */
/* SPI Requirement: Mode 0 (CPOL=0, CPHA=0), Speed up to 50Mhz */

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
    #else
        /* SPI */
        #ifdef WOLFTPM_ST33
            /* ST33HTPH SPI uses CE0 */
            #define TPM2_SPI_DEV "/dev/spidev0.0"

            /* ST33 requires wait state support */
            #ifndef WOLFTPM_CHECK_WAIT_STATE
                #define WOLFTPM_CHECK_WAIT_STATE
            #endif
        #else
            /* OPTIGA SLB9670 and LetsTrust TPM use CE1 */
            #define TPM2_SPI_DEV "/dev/spidev0.1"
        #endif
    #endif


#elif defined(WOLFSSL_STM32_CUBEMX)
    extern SPI_HandleTypeDef hspi1;

#elif defined(WOLFSSL_ATMEL)
    #include "asf.h"

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

        /* 1Mhz - PI has issue with 5-10Mhz on packets sized over 130 */
        unsigned int maxSpeed = 1000000;
        int mode = 0; /* mode 0 */
        int bits_per_word = 8; /* 8-bits */

        spiDev = open(TPM2_SPI_DEV, O_RDWR);
        if (spiDev >= 0) {
            struct spi_ioc_transfer spi;
            size_t size;

            ioctl(spiDev, SPI_IOC_WR_MODE, &mode);
            ioctl(spiDev, SPI_IOC_WR_MAX_SPEED_HZ, &maxSpeed);
            ioctl(spiDev, SPI_IOC_WR_BITS_PER_WORD, &bits_per_word);

            XMEMSET(&spi, 0, sizeof(spi));
            spi.cs_change= 1; /* strobe CS between transfers */

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
                if (size != 1 || timeout <= 0) {
                    close(spiDev);
                    return TPM_RC_FAILURE;
                }
            }

            /* Remainder of message */
            spi.tx_buf   = (unsigned long)&txBuf[TPM_TIS_HEADER_SZ];
            spi.rx_buf   = (unsigned long)&rxBuf[TPM_TIS_HEADER_SZ];
            spi.len      = xferSz - TPM_TIS_HEADER_SZ;
            size = ioctl(spiDev, SPI_IOC_MESSAGE(1), &spi);

            if (size == (size_t)xferSz - TPM_TIS_HEADER_SZ)
                ret = TPM_RC_SUCCESS;
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
        SPI_HandleTypeDef* hspi = (SPI_HandleTypeDef*)&hspi1;
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
        if (status == HAL_OK) {
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
        (void)userCtx;

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

#ifdef WOLFTPM_DEBUG_VERBOSE
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


#ifdef WOLFTPM_DEBUG_VERBOSE
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

#ifdef WOLFTPM_DEBUG_VERBOSE
    printf("TPM2_IoCb: Ret %d, Sz %d\n", ret, xferSz);
    TPM2_PrintBin(txBuf, xferSz);
    TPM2_PrintBin(rxBuf, xferSz);
#endif

    (void)ctx;

    return ret;
}

#endif /* WOLFTPM_ADV_IO */

/******************************************************************************/
/* --- END IO Callback Logic -- */
/******************************************************************************/
