/* tpm_io_st.c
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/* This example shows IO interfaces for STM32 CubeMX HAL */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_tis.h>
#include "tpm_io.h"

/******************************************************************************/
/* --- BEGIN IO Callback Logic -- */
/******************************************************************************/

/* Included via tpm_io.c if WOLFTPM_INCLUDE_IO_FILE is defined */
#ifdef WOLFTPM_INCLUDE_IO_FILE

#if ! (defined(WOLFTPM_LINUX_DEV) || \
       defined(WOLFTPM_SWTPM) ||     \
       defined(WOLFTPM_WINAPI) )

#if defined(WOLFSSL_STM32_CUBEMX)
#ifdef WOLFTPM_I2C
    #ifndef TPM_I2C_TRIES
    #define TPM_I2C_TRIES 10
    #endif
    #ifndef TPM2_I2C_ADDR
    #define TPM2_I2C_ADDR 0x2e
    #endif
    #ifndef STM32_CUBEMX_I2C_TIMEOUT
    #define STM32_CUBEMX_I2C_TIMEOUT 250 /* ticks/ms */
    #endif

    /* STM32 CubeMX HAL I2C */
    static int i2c_read(void* userCtx, word32 reg, byte* data, int len)
    {
        int ret = TPM_RC_FAILURE;
        HAL_StatusTypeDef status;
        I2C_HandleTypeDef* hi2c = (I2C_HandleTypeDef*)userCtx;
        int i2cAddr = (TPM2_I2C_ADDR << 1) | 0x01; /* For I2C read LSB is 1 */
        int timeout = TPM_I2C_TRIES;
        byte buf[1];

        /* TIS layer should never provide a buffer larger than this,
           but double check for good coding practice */
        if (len > MAX_SPI_FRAMESIZE)
            return BAD_FUNC_ARG;

        buf[0] = (reg & 0xFF); /* convert to simple 8-bit address for I2C */

        /* The I2C takes about 80us to wake up and will NAK until it is ready */
        do {
            /* Write address to read from - retry until ack  */
            status = HAL_I2C_Master_Transmit(hi2c, i2cAddr, buf, sizeof(buf),
                STM32_CUBEMX_I2C_TIMEOUT);
            HAL_Delay(1); /* guard time - should be 250us */
        } while (status != HAL_OK && --timeout > 0);
        if (status == HAL_OK) {
            timeout = TPM_I2C_TRIES;
            /* Perform read with retry */
            do {
                status = HAL_I2C_Master_Receive(hi2c, i2cAddr, data, len,
                    STM32_CUBEMX_I2C_TIMEOUT);
                if (status != HAL_OK)
                    HAL_Delay(1); /* guard time - should be 250us */
            } while (status != HAL_OK && --timeout > 0);
        }
        if (status == HAL_OK) {
            ret = TPM_RC_SUCCESS;
        }
        else {
            printf("I2C Read failure %d (tries %d)\n",
                status, TPM_I2C_TRIES - timeout);
        }
        return ret;
    }

    static int i2c_write(void* userCtx, word32 reg, byte* data, int len)
    {
        int ret = TPM_RC_FAILURE;
        HAL_StatusTypeDef status;
        I2C_HandleTypeDef* hi2c = (I2C_HandleTypeDef*)userCtx;
        int i2cAddr = (TPM2_I2C_ADDR << 1); /* I2C write operation, LSB is 0 */
        int timeout = TPM_I2C_TRIES;
        byte buf[MAX_SPI_FRAMESIZE+1];

        /* TIS layer should never provide a buffer larger than this,
           but double check for good coding practice */
        if (len > MAX_SPI_FRAMESIZE)
            return BAD_FUNC_ARG;

        /* Build packet with TPM register and data */
        buf[0] = (reg & 0xFF); /* convert to simple 8-bit address for I2C */
        XMEMCPY(buf + 1, data, len);

        /* The I2C takes about 80us to wake up and will NAK until it is ready */
        do {
            status = HAL_I2C_Master_Transmit(hi2c, i2cAddr, buf, len+1,
                STM32_CUBEMX_I2C_TIMEOUT);
            if (status != HAL_OK)
                HAL_Delay(1); /* guard time - should be 250us */
        } while (status != HAL_OK && --timeout > 0);
        if (status == HAL_OK) {
            ret = TPM_RC_SUCCESS;
        }
        else {
            printf("I2C Write failure %d\n", status);
        }
        return ret;
    }

    int TPM2_IoCb_STCubeMX_I2C(TPM2_CTX* ctx, int isRead, word32 addr,
        byte* buf, word16 size, void* userCtx)
    {
        int ret = TPM_RC_FAILURE;

        if (userCtx != NULL) {
            if (isRead)
                ret = i2c_read(userCtx, addr, buf, size);
            else
                ret = i2c_write(userCtx, addr, buf, size);
        }

        (void)ctx;

        return ret;
    }

#else /* STM32 CubeMX Hal SPI */
    #ifndef STM32_CUBEMX_SPI_TIMEOUT
    #define STM32_CUBEMX_SPI_TIMEOUT 250
    #endif
    #ifndef USE_SPI_CS_PORT
    #define USE_SPI_CS_PORT GPIOA
    #endif
    #ifndef USE_SPI_CS_PIN
    #define USE_SPI_CS_PIN 15
    #endif
    int TPM2_IoCb_STCubeMX_SPI(TPM2_CTX* ctx, const byte* txBuf, byte* rxBuf,
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
        HAL_GPIO_WritePin(USE_SPI_CS_PORT, (1 << USE_SPI_CS_PIN), GPIO_PIN_RESET); /* active low */
    #endif

    #ifdef WOLFTPM_CHECK_WAIT_STATE
        /* Send Header */
        status = HAL_SPI_TransmitReceive(hspi, (byte*)txBuf, rxBuf,
            TPM_TIS_HEADER_SZ, STM32_CUBEMX_SPI_TIMEOUT);
        if (status != HAL_OK) {
        #ifndef USE_HW_SPI_CS
            HAL_GPIO_WritePin(USE_SPI_CS_PORT, (1 << USE_SPI_CS_PIN), GPIO_PIN_SET);
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
                HAL_GPIO_WritePin(USE_SPI_CS_PORT, (1 << USE_SPI_CS_PIN), GPIO_PIN_SET);
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
        HAL_GPIO_WritePin(USE_SPI_CS_PORT, (1 << USE_SPI_CS_PIN), GPIO_PIN_SET);
    #endif
        __HAL_SPI_DISABLE(hspi);

        if (status == HAL_OK)
            ret = TPM_RC_SUCCESS;
#ifdef WOLFTPM_DEBUG_VERBOSE
        else {
            printf("SPI Failed: Xfer %d, Status=0x%x\n", xferSz, status);
        }
#endif

        (void)ctx;

        return ret;
    }
#endif /* WOLFTPM_I2C */
#endif
#endif /* !(WOLFTPM_LINUX_DEV || WOLFTPM_SWTPM || WOLFTPM_WINAPI) */
#endif /* WOLFTPM_INCLUDE_IO_FILE */

/******************************************************************************/
/* --- END IO Callback Logic -- */
/******************************************************************************/
