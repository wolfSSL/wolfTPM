/* tpm_io_infineon.c
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* This example shows IO interfaces for Infineon CyHal or TriCore hardware:
 * - PSoC6 CyHal set automatically with `CY_USING_HAL`.
 * - TC2XX/TC3XX using macro: `WOLFTPM_INFINEON_TRICORE`.
 */

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

#ifdef WOLFTPM_I2C
    #ifndef TPM_I2C_TRIES
        #define TPM_I2C_TRIES 10
    #endif
    #ifndef TPM2_I2C_ADDR
        #define TPM2_I2C_ADDR 0x2e
    #endif

    #if defined(CY_USING_HAL)
    #include "cyhal_i2c.h"

    static int tpm_ifx_i2c_read(void* userCtx, word32 reg, byte* data, int len)
    {
        int ret = TPM_RC_FAILURE;
        cy_rslt_t result;
        cyhal_i2c_t* i2c = (cyhal_i2c_t*)userCtx;
        int timeout = TPM_I2C_TRIES;
        byte buf[1];

        /* TIS layer should never provide a buffer larger than this,
         * but double check for good coding practice */
        if (i2c == NULL || len > MAX_SPI_FRAMESIZE)
            return BAD_FUNC_ARG;

        buf[0] = (reg & 0xFF); /* convert to simple 8-bit address for I2C */

        /* The I2C takes about 80us to wake up and will NAK until it is ready */
        do {
            /* Write address to read from - retry until ack  */
            result = cyhal_i2c_master_write(i2c, TPM2_I2C_ADDR, buf, sizeof(buf),
                0, true);
            /* for read we always need this guard time (success wake or real read) */
            XSLEEP_MS(1); /* guard time - should be 250us */
        } while (result != CY_RSLT_SUCCESS && --timeout > 0);

        if (result == CY_RSLT_SUCCESS) {
            timeout = TPM_I2C_TRIES;
            do {
                result = cyhal_i2c_master_read(i2c, TPM2_I2C_ADDR, data, len,
                    0, true);
                if (result != CY_RSLT_SUCCESS) {
                    XSLEEP_MS(1); /* guard time - should be 250us */
                }
            } while (result != CY_RSLT_SUCCESS && --timeout > 0);
        }
        if (result == CY_RSLT_SUCCESS) {
            ret = TPM_RC_SUCCESS;
        }
        else {
            printf("CyHAL I2C Read failure %d (tries %d)\n",
                (int)result, TPM_I2C_TRIES - timeout);
        }
        return ret;
    }

    static int tpm_ifx_i2c_write(void* userCtx, word32 reg, byte* data, int len)
    {
        int ret = TPM_RC_FAILURE;
        cy_rslt_t result;
        cyhal_i2c_t* i2c = (cyhal_i2c_t*)userCtx;
        int timeout = TPM_I2C_TRIES;
        byte buf[MAX_SPI_FRAMESIZE+1];

        /* TIS layer should never provide a buffer larger than this,
         * but double check for good coding practice */
        if (i2c == NULL || len > MAX_SPI_FRAMESIZE)
            return BAD_FUNC_ARG;

        /* Build packet with TPM register and data */
        buf[0] = (reg & 0xFF); /* convert to simple 8-bit address for I2C */
        XMEMCPY(buf + 1, data, len);

        /* The I2C takes about 80us to wake up and will NAK until it is ready */
        do {
            result = cyhal_i2c_master_write(i2c, TPM2_I2C_ADDR, buf, len+1,
                0, true);
            if (result != CY_RSLT_SUCCESS) {
                XSLEEP_MS(1); /* guard time - should be 250us */
            }
        } while (result != CY_RSLT_SUCCESS && --timeout > 0);
        if (result == CY_RSLT_SUCCESS) {
            ret = TPM_RC_SUCCESS;
        }
        else {
            printf("CyHAL I2C Write failure %d\n", (int)result);
        }
        return ret;
    }

    int TPM2_IoCb_Infineon_I2C(TPM2_CTX* ctx, int isRead, word32 addr,
        byte* buf, word16 size, void* userCtx)
    {
        int ret = TPM_RC_FAILURE;
        if (userCtx != NULL) {
            if (isRead)
                ret = tpm_ifx_i2c_read(userCtx, addr, buf, size);
            else
                ret = tpm_ifx_i2c_write(userCtx, addr, buf, size);
        }
        (void)ctx;
        return ret;
    }

    #else
        #error Infineon I2C support on this platform not supported yet
    #endif /* CY_USING_HAL or WOLFTPM_INFINEON_TRICORE */

#else /* SPI */

    #ifndef TPM2_SPI_HZ
        /* Use the max speed by default
         * See tpm2_types.h for chip specific max values */
        #define TPM2_SPI_HZ TPM2_SPI_MAX_HZ
    #endif
    #ifdef WOLFTPM_CHECK_WAIT_STATE
        #error SPI check wait state logic not supported
    #endif

    #if defined(CY_USING_HAL)
    int TPM2_IoCb_Infineon_SPI(TPM2_CTX* ctx, const byte* txBuf,
        byte* rxBuf, word16 xferSz, void* userCtx)
    {

    }
    #elif defined(WOLFTPM_INFINEON_TRICORE)

    #include <Ifx_Types.h>
    #include <Qspi/SpiMaster/IfxQspi_SpiMaster.h>

    /* externally declared SPI master channel */
    extern IfxQspi_SpiMaster_Channel spiMasterChannel

    static int TPM2_IoCb_Infineon_TriCore_SPI(TPM2_CTX* ctx, const byte* txBuf,
        byte* rxBuf, word16 xferSz, void* userCtx)
    {
        int ret = TPM_RC_FAILURE;

        /* wait for SPI not busy */
        while (IfxQspi_SpiMaster_getStatus(&spiMasterChannel) ==
                                                          SpiIf_Status_busy) {};

        /* synchronously send data */
        if (IfxQspi_SpiMaster_exchange(&spiMasterChannel, txBuf, rxBuf,
                                                   xferSz) == SpiIf_Status_ok) {
            ret = TPM_RC_SUCCESS;
        }

        (void)userCtx;
        (void)ctx;

        return ret;
    }
    #else
        #error Infineon I2C support on this platform not supported yet
    #endif /* CY_USING_HAL or WOLFTPM_INFINEON_TRICORE */
#endif /* SPI or I2C */

#endif /* !(WOLFTPM_LINUX_DEV || WOLFTPM_SWTPM || WOLFTPM_WINAPI) */
#endif /* WOLFTPM_INCLUDE_IO_FILE */

/******************************************************************************/
/* --- END IO Callback Logic -- */
/******************************************************************************/
