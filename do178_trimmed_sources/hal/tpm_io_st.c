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

#if ! (defined(WOLFTPM_LINUX_DEV) || defined(WOLFTPM_SWTPM) || defined(WOLFTPM_WINAPI) )

#if defined(WOLFSSL_STM32_CUBEMX)
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
        int timeout = TPM_SPI_WAIT_RETRY;

        __HAL_SPI_ENABLE(hspi);
    #ifndef USE_HW_SPI_CS
        HAL_GPIO_WritePin(USE_SPI_CS_PORT, (1 << USE_SPI_CS_PIN), GPIO_PIN_RESET); /* active low */
    #endif

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

    #ifndef USE_HW_SPI_CS
        HAL_GPIO_WritePin(USE_SPI_CS_PORT, (1 << USE_SPI_CS_PIN), GPIO_PIN_SET);
    #endif
        __HAL_SPI_DISABLE(hspi);

        if (status == HAL_OK)
            ret = TPM_RC_SUCCESS;

        (void)ctx;

        return ret;
    }
#endif
#endif /* !(WOLFTPM_LINUX_DEV || WOLFTPM_SWTPM || WOLFTPM_WINAPI) */
#endif /* WOLFTPM_INCLUDE_IO_FILE */

/******************************************************************************/
/* --- END IO Callback Logic -- */
/******************************************************************************/
