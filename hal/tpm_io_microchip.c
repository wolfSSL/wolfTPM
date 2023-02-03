/* tpm_io_microchip.c
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
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

/* This example shows IO interfaces for Microchip micro-controllers using
 * MPLAB X and Harmony */


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

#if defined(WOLFTPM_MICROCHIP_HARMONY)

#ifdef WOLFTPM_CHECK_WAIT_STATE
    #error This driver does not support check wait state yet
#endif

#include "configuration.h"
#include "definitions.h"

/* TPM Chip Select Pin (default PC5) */
#ifndef TPM_SPI_PIN
#define SYS_PORT_PIN_PC5
#endif

int TPM2_IoCb_Microchip_SPI(TPM2_CTX* ctx, const byte* txBuf, byte* rxBuf,
    word16 xferSz, void* userCtx)
{
    int ret = TPM_RC_FAILURE;
    DRV_HANDLE handle = DRV_HANDLE_INVALID;
    DRV_SPI_TRANSFER_SETUP setup;

    /* Setup SPI */
    handle = DRV_SPI_Open(DRV_SPI_INDEX_0, DRV_IO_INTENT_EXCLUSIVE);
    if (handle == DRV_HANDLE_INVALID) {
        return TPM_RC_FAILURE;
    }

    memset(&setup, 0, sizeof(setup));
    setup.baudRateInHz = TPM2_SPI_HZ;
    setup.clockPhase = DRV_SPI_CLOCK_PHASE_VALID_TRAILING_EDGE;
    setup.clockPolarity = DRV_SPI_CLOCK_POLARITY_IDLE_LOW;
    setup.dataBits = DRV_SPI_DATA_BITS_8;
    setup.chipSelect = TPM_SPI_PIN;
    setup.csPolarity = DRV_SPI_CS_POLARITY_ACTIVE_LOW;
    DRV_SPI_TransferSetup(handle, &setup);

    /* Send Entire Message blocking - no wait states */
    if (DRV_SPI_WriteReadTransfer(handle, (byte*)txBuf, xferSz, rxBuf,
                                                              xferSz) == true) {
        ret = TPM_RC_SUCCESS
    }

    (void)ctx;
    (void)userCtx;

    DRV_SPI_Close(handle);
    handle = DRV_HANDLE_INVALID;

    return ret;
}

#endif /* WOLFTPM_MICROCHIP_HARMONY */
#endif /* !(WOLFTPM_LINUX_DEV || WOLFTPM_SWTPM || WOLFTPM_WINAPI) */
#endif /* WOLFTPM_INCLUDE_IO_FILE */

/******************************************************************************/
/* --- END IO Callback Logic -- */
/******************************************************************************/
