/* tpm_io_infineon.c
 *
 * Copyright (C) 2006-2022 wolfSSL Inc.
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

/* This example shows IO interfaces for Infineon TriCore hardware:
 * - TC2XX/TC3XX using macro: `WOLFTPM_INFINEON_TRICORE`.
 */


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

/* Use the max speed by default - see tpm2_types.h for chip specific max values */
#ifndef TPM2_SPI_HZ
    #define TPM2_SPI_HZ TPM2_SPI_MAX_HZ
#endif

#if defined(WOLFTPM_INFINEON_TRICORE)

    #include <Ifx_Types.h>
    #include <Qspi/SpiMaster/IfxQspi_SpiMaster.h>

    /* externally declared SPI master channel */
    extern IfxQspi_SpiMaster_Channel spiMasterChannel

    static int TPM2_IoCb_Infineon_TriCore_SPI(TPM2_CTX* ctx, const byte* txBuf,
        byte* rxBuf, word16 xferSz, void* userCtx)
    {
        int ret = TPM_RC_FAILURE;

    #ifdef WOLFTPM_CHECK_WAIT_STATE
        #error SPI check wait state logic not supported
    #endif

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

#endif /* WOLFTPM_INFINEON_TRICORE */
#endif /* !(WOLFTPM_LINUX_DEV || WOLFTPM_SWTPM || WOLFTPM_WINAPI) */
#endif /* WOLFTPM_INCLUDE_IO_FILE */

/******************************************************************************/
/* --- END IO Callback Logic -- */
/******************************************************************************/
