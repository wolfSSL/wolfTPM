/* tpm_io_uboot.c
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
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

/* This example shows IO interfaces for Uboot */


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

#ifndef CONFIG_DEFAULT_SPI_BUS
    #define CONFIG_DEFAULT_SPI_BUS	1
    #define CONFIG_DEFAULT_SPI_CS 	0
    #define CONFIG_DEFAULT_SPI_FREQ 1000000
    #define CONFIG_DEFAULT_SPI_MODE	SPI_MODE_3
    #define CONFIG_DEFAULT_SPI_NAME "generic_1:0\0"
#endif

#if defined(__UBOOT__)
    #include <common.h>
    #include <dm.h>
    #include <spi.h>

    int TPM2_IoCb_Uboot_SPI(TPM2_CTX* ctx, const byte* txBuf,
        byte* rxBuf, word16 xferSz, void* userCtx)
    {
        int ret = TPM_RC_FAILURE;
        struct udevice *udev = NULL; /* u-boot device */
        struct spi_slave *slave = NULL;

    #ifdef WOLFTPM_CHECK_WAIT_STATE
        #error SPI check wait state logic not supported for U-boot
    #endif

        if (userCtx == NULL) {
        #ifdef DEBUG_WOLFTPM
            printf("userCtx is NULL, can not acccess udev\n");
        #endif
            return TPM_RC_FAILURE;
        }

        #if CONFIG_IS_ENABLED(DM_SPI)
        /* If Driver-model is enabled, we can acquire SPI udevice using bus number */
        ret = spi_get_bus_and_cs(CONFIG_DEFAULT_SPI_BUS, CONFIG_DEFAULT_SPI_CS,
                             CONFIG_DEFAULT_SPI_FREQ, CONFIG_DEFAULT_SPI_MODE,
                             "spi_generic_drv", CONFIG_DEFAULT_SPI_NAME,
                             &dev, &slave);
        if (ret) {
            return ret;
        }

        #else
        /* Acquire the SPI bus from manually passed udevice through wolfTPM2_Init */
        udev = (struct udevice*)userCtx;
        slave = dev_get_parent_priv(dev);
        #endif

        ret = spi_claim_bus(slave);
        if (ret < 0) {
        #ifdef DEBUG_WOLFTPM
            printf("Failed to acquire access to u-boot spi bus\n");
            return ret;
        #endif
        }

        ret = spi_xfer(slave, xferSz * 8, tx_buf, rx_buf,
                    SPI_XFER_BEGIN | /* Assert CS before transfer */
                    SPI_XFER_END); /* Deassert CS after transfer */
        #ifdef DEBUG_WOLFTPM
        if (ret < 0) {
            printf("Failed to transmit data over the SPI bus\n");
        }
        #endif

        /* Regardless of the SPI operation outcome, release the SPI bus */
        spi_release_bus(slave);

        if (ret == 0) {
            ret = TPM_RC_SUCCESS;
        }

        (void)ctx;

        return ret;
    }

#endif
#endif /* !(WOLFTPM_LINUX_DEV || WOLFTPM_SWTPM || WOLFTPM_WINAPI) */
#endif /* WOLFTPM_INCLUDE_IO_FILE */

/******************************************************************************/
/* --- END IO Callback Logic -- */
/******************************************************************************/
