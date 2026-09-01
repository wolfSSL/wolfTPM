/* tpm_io_wolfhal.c
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

/* This example shows IO interfaces for wolfHAL */

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

#if defined(WOLFTPM_WOLFHAL)

/* Only pull in wolfHAL and the board definitions when this backend is
 * selected, so the file compiles to nothing when built directly on a
 * platform that does not have wolfHAL available. */
#include <wolfHAL/wolfHAL.h>
#include "wolfHAL_board.h"

#ifdef WOLFTPM_I2C
    /* wolfHAL_board.h is supplied by the application, not by wolfTPM. It must
     * describe how this board reaches the TPM. */
    #ifndef BOARD_I2C_DEV
    #error "wolfHAL: wolfHAL_board.h must define BOARD_I2C_DEV (whal_I2c*)"
    #endif
    /* Carries the TPM target address (typically 0x2e) and bus speed. */
    #ifndef BOARD_I2C_COM_CFG
    #error "wolfHAL: wolfHAL_board.h must define BOARD_I2C_COM_CFG (whal_I2c_ComCfg*)"
    #endif
    #ifdef TPM2_I2C_ADDR
    #error "wolfHAL: TPM2_I2C_ADDR is unused, set addr in BOARD_I2C_COM_CFG"
    #endif

    #ifndef TPM_I2C_TRIES
    #define TPM_I2C_TRIES 10
    #endif

    /* wolfHAL I2C */
    int TPM2_IoCb_Wolfhal_I2C(TPM2_CTX* ctx, int isRead, word32 addr,
        byte* buf, word16 size, void* userCtx)
    {
        int ret = TPM_RC_FAILURE;
        whal_Error status;
        int tries = TPM_I2C_TRIES;
        /* wolfHAL takes an 8-bit register, the TIS layer hands us the full
         * address. Narrow it explicitly rather than relying on conversion. */
        uint8_t reg = (uint8_t)(addr & 0xFF);

        /* Open the session. This applies the TPM target address and bus
         * speed, and must precede any transfer. */
        status = whal_I2c_StartCom(BOARD_I2C_DEV, BOARD_I2C_COM_CFG);
        if (status != WHAL_SUCCESS) {
        #ifdef WOLFTPM_DEBUG_VERBOSE
            printf("I2C StartCom Failed: Status=%d\n", status);
        #endif
            return TPM_RC_FAILURE;
        }

        /* The TPM takes about 80us to wake up and NAKs until it is ready, so
         * retry the transfer. StartCom only configures the peripheral, the
         * NAK surfaces here where the bus is actually driven. */
        do {
            if (isRead) {
                status = whal_I2c_ReadReg(BOARD_I2C_DEV, reg, buf, size);
            }
            else {
                status = whal_I2c_WriteReg(BOARD_I2C_DEV, reg, buf, size);
            }
            if (status == WHAL_SUCCESS) {
                break;
            }
            XSLEEP_MS(1);
        } while (--tries > 0);

        if (status == WHAL_SUCCESS) {
            ret = TPM_RC_SUCCESS;
        }
    #ifdef WOLFTPM_DEBUG_VERBOSE
        else {
            printf("I2C %s Failed: Reg 0x%x, Sz %d, Status=%d (tries %d)\n",
                isRead ? "Read" : "Write", reg, size, status,
                TPM_I2C_TRIES - tries);
        }
    #endif

        /* Always end the session, including on the error path above. A
         * teardown failure leaves the bus in an unknown state, so it
         * downgrades an otherwise successful transfer. */
        status = whal_I2c_EndCom(BOARD_I2C_DEV);
        if (status != WHAL_SUCCESS) {
        #ifdef WOLFTPM_DEBUG_VERBOSE
            printf("I2C EndCom Failed: Status=%d\n", status);
        #endif
            ret = TPM_RC_FAILURE;
        }

        (void)ctx;
        (void)userCtx;

        return ret;
    }

#else /* wolfHAL SPI */
    /* wolfHAL_board.h is supplied by the application, not by wolfTPM. It must
     * describe how this board reaches the TPM. */
    #ifndef BOARD_SPI_DEV
    #error "wolfHAL: wolfHAL_board.h must define BOARD_SPI_DEV (whal_Spi*)"
    #endif
    #ifndef BOARD_SPI_COM_CFG
    #error "wolfHAL: wolfHAL_board.h must define BOARD_SPI_COM_CFG (whal_Spi_ComCfg*)"
    #endif
    #ifndef BOARD_GPIO_DEV
    #error "wolfHAL: wolfHAL_board.h must define BOARD_GPIO_DEV (whal_Gpio*) for chip select"
    #endif
    #ifndef BOARD_CS_PIN
    #error "wolfHAL: wolfHAL_board.h must define BOARD_CS_PIN (chip select pin, active low)"
    #endif

    int TPM2_IoCb_Wolfhal_SPI(TPM2_CTX* ctx, const byte* txBuf, byte* rxBuf,
        word16 xferSz, void* userCtx)
    {
        int ret = TPM_RC_FAILURE;
        whal_Error status;
    #ifdef WOLFTPM_CHECK_WAIT_STATE
        int timeout = TPM_SPI_WAIT_RETRY;
    #endif

        /* Open the transaction */
        status = whal_Spi_StartCom(BOARD_SPI_DEV, BOARD_SPI_COM_CFG);
        if (status != WHAL_SUCCESS) {
        #ifdef WOLFTPM_DEBUG_VERBOSE
            printf("SPI StartCom Failed: Status=%d\n", status);
        #endif
            return TPM_RC_FAILURE;
        }

        /* Assert chip select (active low) */
        status = whal_Gpio_Set(BOARD_GPIO_DEV, BOARD_CS_PIN, 0);
        if (status != WHAL_SUCCESS) {
        #ifdef WOLFTPM_DEBUG_VERBOSE
            printf("SPI CS assert Failed: Status=%d\n", status);
        #endif
            (void)whal_Spi_EndCom(BOARD_SPI_DEV);
            return TPM_RC_FAILURE;
        }

    #ifdef WOLFTPM_CHECK_WAIT_STATE
        /* Send Header */
        status = whal_Spi_SendRecv(BOARD_SPI_DEV, txBuf, TPM_TIS_HEADER_SZ,
                                   rxBuf, TPM_TIS_HEADER_SZ);
        if (status != WHAL_SUCCESS)
            goto exit;

        /* Check for wait states */
        if ((rxBuf[TPM_TIS_HEADER_SZ-1] & TPM_TIS_READY_MASK) == 0) {
            do {
                /* Check for SPI ready */
                status = whal_Spi_SendRecv(BOARD_SPI_DEV, txBuf, 1,
                                           rxBuf, 1);
                if (status != WHAL_SUCCESS)
                    goto exit;
                if (rxBuf[0] & TPM_TIS_READY_MASK)
                    break;
            } while (--timeout > 0);
        #ifdef WOLFTPM_DEBUG_TIMEOUT
            printf("SPI Ready Wait %d\n", TPM_SPI_WAIT_RETRY - timeout);
        #endif
            if (timeout <= 0) {
            #ifdef WOLFTPM_DEBUG_VERBOSE
                printf("SPI Ready timeout after %d tries\n",
                    TPM_SPI_WAIT_RETRY);
            #endif
                goto exit; /* ret stays TPM_RC_FAILURE */
            }
        }

        /* Send remainder of payload */
        status = whal_Spi_SendRecv(BOARD_SPI_DEV,
            &txBuf[TPM_TIS_HEADER_SZ], xferSz - TPM_TIS_HEADER_SZ,
            &rxBuf[TPM_TIS_HEADER_SZ], xferSz - TPM_TIS_HEADER_SZ);
    #else
        /* Send Entire Message - no wait states */
        status = whal_Spi_SendRecv(BOARD_SPI_DEV, txBuf, xferSz, rxBuf, xferSz);
    #endif /* WOLFTPM_CHECK_WAIT_STATE */

        if (status == WHAL_SUCCESS) {
            ret = TPM_RC_SUCCESS;
        }
    #ifdef WOLFTPM_DEBUG_VERBOSE
        else {
            printf("SPI Failed: Xfer %d, Status=%d\n", xferSz, status);
        }
    #endif

    #ifdef WOLFTPM_CHECK_WAIT_STATE
    exit: /* only the wait state path bails out early */
    #endif
        /* Always tear down, including on the error paths above. A teardown
         * failure leaves the bus in an unknown state, so it downgrades an
         * otherwise successful transfer. */
        status = whal_Gpio_Set(BOARD_GPIO_DEV, BOARD_CS_PIN, 1);
        if (status != WHAL_SUCCESS) {
        #ifdef WOLFTPM_DEBUG_VERBOSE
            printf("SPI CS release Failed: Status=%d\n", status);
        #endif
            ret = TPM_RC_FAILURE;
        }
        status = whal_Spi_EndCom(BOARD_SPI_DEV);
        if (status != WHAL_SUCCESS) {
        #ifdef WOLFTPM_DEBUG_VERBOSE
            printf("SPI EndCom Failed: Status=%d\n", status);
        #endif
            ret = TPM_RC_FAILURE;
        }

        (void)ctx;
        (void)userCtx;

        return ret;
    }
#endif /* WOLFTPM_I2C */
#endif
#endif /* !(WOLFTPM_LINUX_DEV || WOLFTPM_SWTPM || WOLFTPM_WINAPI) */
#endif /* WOLFTPM_INCLUDE_IO_FILE */

/******************************************************************************/
/* --- END IO Callback Logic -- */
/******************************************************************************/
