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
#include <examples/tpm_io.h>


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

void* TPM2_IoGetUserCtx(void)
{
    return TPM2_USER_CTX;
}

/* IO Callback */
int TPM2_IoCb(TPM2_CTX* ctx, const byte* txBuf, byte* rxBuf,
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
        /* 10Mhz - PI has issue with 5-10Mhz on packets sized over 130 */
        unsigned int maxSpeed = 1000000;
        int mode = 0; /* mode 0 */
        int bits_per_word = 8; /* 8-bits */

        *spiDev = open(TPM2_SPI_DEV, O_RDWR);
        if (*spiDev >= 0) {
            ioctl(*spiDev, SPI_IOC_WR_MODE, &mode);
            ioctl(*spiDev, SPI_IOC_WR_MAX_SPEED_HZ, &maxSpeed);
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
    #error Add your platform here for HW interface
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
