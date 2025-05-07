/* tpm_io_uboot.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

/* This example shows IO interfaces for U-boot */

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

#if defined(__UBOOT__)
    #include <config.h>
    int TPM2_IoCb_Uboot_SPI(TPM2_CTX* ctx, const byte* txBuf,
        byte* rxBuf, word16 xferSz, void* userCtx)
    {
        int ret = 0;
        struct udevice *dev;

        /* Get the TPM device */
        if (ret == 0) {
            ret = tcg2_platform_get_tpm2(&dev);
            if ( ret != 0 || dev == NULL) {
            #ifdef DEBUG_WOLFTPM
                printf("Failed to get TPM device with error: %d\n", ret);
            #endif
                return TPM_RC_FAILURE;
            }
        }

        /* Transfer the device data using tpm_xfer */
        if (ret == 0) {
            ret = tpm_xfer(dev, txBuf, xferSz, rxBuf, &xferSz);
            if (ret != 0) {
            #ifdef DEBUG_WOLFTPM
                printf("tpm_xfer failed with error: %d\n", ret);
            #endif
                return TPM_RC_FAILURE;
            }
        }

        return TPM_RC_SUCCESS;
    }
#endif /* __UBOOT__ */
#endif /* WOLFTPM_LINUX_DEV || WOLFTPM_SWTPM || WOLFTPM_WINAPI */
#endif /* WOLFTPM_INCLUDE_IO_FILE */

/******************************************************************************/
/* --- END IO Callback Logic -- */
/******************************************************************************/
