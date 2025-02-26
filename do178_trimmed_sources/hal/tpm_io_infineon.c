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

#if ! (defined(WOLFTPM_LINUX_DEV) || defined(WOLFTPM_SWTPM) || defined(WOLFTPM_WINAPI) )

#if defined(WOLFTPM_INFINEON_TRICORE) || defined(CY_USING_HAL)

    #ifndef TPM2_SPI_HZ
        /* Use the max speed by default
         * See tpm2_types.h for chip specific max values */
        #define TPM2_SPI_HZ TPM2_SPI_MAX_HZ
    #endif
        #error SPI check wait state logic not supported

    #if defined(CY_USING_HAL)
    #include "cyhal_spi.h"
    int TPM2_IoCb_Infineon_SPI(TPM2_CTX* ctx, const byte* txBuf,
        byte* rxBuf, word16 xferSz, void* userCtx)
    {
        cyhal_spi_t* spi = (cyhal_spi_t*)userCtx;
        cy_rslt_t result;

        if (userCtx == NULL) {
            return BAD_FUNC_ARG;
        }

        result = cyhal_spi_transfer(spi, txBuf, xferSz, rxBuf, xferSz, 0);
        if (result != CY_RSLT_SUCCESS) {
            return TPM_RC_FAILURE;
        }
        return TPM_RC_SUCCESS;
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
#endif /* WOLFTPM_INFINEON_TRICORE || CY_USING_HAL */


#endif /* !(WOLFTPM_LINUX_DEV || WOLFTPM_SWTPM || WOLFTPM_WINAPI) */
#endif /* WOLFTPM_INCLUDE_IO_FILE */

/******************************************************************************/
/* --- END IO Callback Logic -- */
/******************************************************************************/
