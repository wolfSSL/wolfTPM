/* tpm_io_uboot.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* This example shows IO interfaces for U-boot using raw SPI */

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
    #include <spi.h>
    #include <dm/device.h>
    #include <dm/uclass.h>

    /* SPI bus and chip select configuration for TPM
     * These can be overridden in user_settings.h or board config */
    #ifndef TPM_SPI_BUS
        #define TPM_SPI_BUS 0
    #endif
    #ifndef TPM_SPI_CS
        #define TPM_SPI_CS 0
    #endif
    #ifndef TPM_SPI_MAX_HZ
        #define TPM_SPI_MAX_HZ 1000000  /* 1 MHz - safe default */
    #endif
    #define TPM_SPI_MODE SPI_MODE_0  /* Mode 0 (CPOL=0, CPHA=0) */

    /* Maximum SPI frame size */
    #define MAX_SPI_FRAMESIZE 64

    /* Static SPI device handles */
    static struct udevice *g_spi_bus = NULL;
    static struct spi_slave *g_spi_slave = NULL;
    static int g_spi_initialized = 0;

    /* Initialize SPI for TPM communication */
    static int uboot_spi_init(void)
    {
        int ret;

        if (g_spi_initialized) {
            return 0;  /* Already initialized */
        }

        /* Get SPI bus and slave device */
        ret = spi_get_bus_and_cs(TPM_SPI_BUS, TPM_SPI_CS,
                                 &g_spi_bus, &g_spi_slave);
        if (ret != 0) {
        #ifdef DEBUG_WOLFTPM
            printf("Failed to get SPI bus %d cs %d: %d\n",
                   TPM_SPI_BUS, TPM_SPI_CS, ret);
        #endif
            return ret;
        }

        g_spi_initialized = 1;

    #ifdef DEBUG_WOLFTPM
        printf("TPM SPI initialized: bus %d, cs %d\n", TPM_SPI_BUS, TPM_SPI_CS);
    #endif

        return 0;
    }

    /* Raw SPI transfer for wolfTPM TIS layer
     * This is called by wolfTPM's TIS implementation for register read/write.
     * The txBuf/rxBuf contain TIS-formatted SPI data including the 4-byte header.
     */
    int TPM2_IoCb_Uboot_SPI(TPM2_CTX* ctx, const byte* txBuf,
        byte* rxBuf, word16 xferSz, void* userCtx)
    {
        int ret;
    #ifdef WOLFTPM_CHECK_WAIT_STATE
        int timeout = TPM_SPI_WAIT_RETRY;
        byte tmp_rx;
    #endif

        (void)ctx;
        (void)userCtx;

        /* Initialize SPI if needed */
        ret = uboot_spi_init();
        if (ret != 0) {
            return TPM_RC_FAILURE;
        }

        /* Claim the SPI bus */
        ret = spi_claim_bus(g_spi_slave);
        if (ret != 0) {
        #ifdef DEBUG_WOLFTPM
            printf("Failed to claim SPI bus: %d\n", ret);
        #endif
            return TPM_RC_FAILURE;
        }

    #ifdef WOLFTPM_CHECK_WAIT_STATE
        /* Send TIS header first (4 bytes) with CS held */
        ret = spi_xfer(g_spi_slave, TPM_TIS_HEADER_SZ * 8,
                       txBuf, rxBuf, SPI_XFER_BEGIN);
        if (ret != 0) {
        #ifdef DEBUG_WOLFTPM
            printf("SPI header xfer failed: %d\n", ret);
        #endif
            goto cleanup;
        }

        /* Check for wait state - TPM holds ready bit low if busy */
        if ((rxBuf[TPM_TIS_HEADER_SZ - 1] & TPM_TIS_READY_MASK) == 0) {
            /* Poll for ready */
            do {
                ret = spi_xfer(g_spi_slave, 8, NULL, &tmp_rx, 0);
                if (ret != 0) {
                    break;
                }
                if (tmp_rx & TPM_TIS_READY_MASK) {
                    break;
                }
            } while (--timeout > 0);

            if (timeout <= 0 || ret != 0) {
            #ifdef DEBUG_WOLFTPM
                printf("SPI wait state timeout\n");
            #endif
                /* Deassert CS */
                spi_xfer(g_spi_slave, 0, NULL, NULL, SPI_XFER_END);
                ret = TPM_RC_FAILURE;
                goto cleanup;
            }
        }

        /* Transfer remainder of data with CS deasserted at end */
        if (xferSz > TPM_TIS_HEADER_SZ) {
            ret = spi_xfer(g_spi_slave, (xferSz - TPM_TIS_HEADER_SZ) * 8,
                           &txBuf[TPM_TIS_HEADER_SZ],
                           &rxBuf[TPM_TIS_HEADER_SZ],
                           SPI_XFER_END);
        } else {
            /* Just deassert CS if no more data */
            ret = spi_xfer(g_spi_slave, 0, NULL, NULL, SPI_XFER_END);
        }

    #else
        /* No wait state handling - send entire message at once
         * This works for Infineon TPMs (SLB9670/SLB9672) which guarantee
         * no wait states */
        ret = spi_xfer(g_spi_slave, xferSz * 8, txBuf, rxBuf,
                       SPI_XFER_BEGIN | SPI_XFER_END);
    #endif /* WOLFTPM_CHECK_WAIT_STATE */

        if (ret != 0) {
        #ifdef DEBUG_WOLFTPM
            printf("SPI xfer failed: %d\n", ret);
        #endif
            ret = TPM_RC_FAILURE;
        } else {
            ret = TPM_RC_SUCCESS;
        }

    #ifdef WOLFTPM_CHECK_WAIT_STATE
    cleanup:
    #endif
        spi_release_bus(g_spi_slave);

        return ret;
    }

#endif /* __UBOOT__ */
#endif /* WOLFTPM_LINUX_DEV || WOLFTPM_SWTPM || WOLFTPM_WINAPI */
#endif /* WOLFTPM_INCLUDE_IO_FILE */

/******************************************************************************/
/* --- END IO Callback Logic -- */
/******************************************************************************/
