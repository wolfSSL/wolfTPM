/* tpm_io_microchip.c
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

/* This example shows IO interfaces for Microchip micro-controllers using
 * MPLAB X and Harmony
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

/* Use the max speed by default - see tpm2_types.h for chip specific max values */
#ifndef TPM2_SPI_HZ
    #define TPM2_SPI_HZ TPM2_SPI_MAX_HZ
#endif

#if defined(WOLFTPM_MICROCHIP_HARMONY)

#include "configuration.h"
#include "definitions.h"

#ifdef WOLFTPM_I2C /* Microchip Harmony Hal I2C */
    /* We are using the I2C bit-bang library. */
    #include <i2cbb/i2c_bb.h>
    /* Use sys_time to implement delay. */
    #include "system/time/sys_time.h"

    #ifndef TPM_I2C_TRIES
    #define TPM_I2C_TRIES 10
    #endif
    #ifndef TPM2_I2C_ADDR
    #define TPM2_I2C_ADDR 0x2e
    #endif

    static uintptr_t dummy_context;

    /* Staging buffers stay at file scope: a busy-timeout bail-out returns
     * while the bit-bang engine is still clocking data in or out of them, so
     * they must outlive the call that queued the transfer. Reads stage here
     * too, so a timeout cannot leave the engine writing into the caller's
     * (often stack-local) buffer. */
    static byte i2cRegBuf[1];
    static byte i2cXferBuf[MAX_SPI_FRAMESIZE+1];
    static byte i2cRdBuf[MAX_SPI_FRAMESIZE];
    /* Set when a busy timeout leaves plaintext in a staging buffer that could
     * not be scrubbed; cleared on completion or once polling finds idle. */
    static volatile int i2cXferDirty = 0;

    /* Scrub staging left dirty by a previous busy timeout. Only safe once the
     * engine is idle, so callers must check I2C_BB_IsBusy() first. */
    static void i2c_scrub_stale(void)
    {
        if (i2cXferDirty) {
            TPM2_ForceZero(i2cXferBuf, sizeof(i2cXferBuf));
            TPM2_ForceZero(i2cRdBuf, sizeof(i2cRdBuf));
            i2cXferDirty = 0;
        }
    }

    static void i2c_completion_callback(uintptr_t context)
    {
        (void) context;
        /* Successful transfers leave this clear. A timed-out transfer sets
         * it while the engine still owns the staging buffers. */
        i2c_scrub_stale();
    }

    /* Wait for time_ms using Microchip Harmony SYS_TIME API. */
    static void microchip_wait(uint32_t time_ms)
    {
        /* Microchip Harmony example from documentation.
         * SYS_TIME_DelayMS will internally create the timer,
         * and SYS_TIME_DelayIsComplete will delete it when
         * the delay has completed. */
        SYS_TIME_HANDLE timer = SYS_TIME_HANDLE_INVALID;

        if (SYS_TIME_DelayMS(time_ms, &timer) != SYS_TIME_SUCCESS) {
            printf("error: microchip_wait: SYS_TIME_DelayMS failed\n");
        }
        else if(SYS_TIME_DelayIsComplete(timer) != true) {
            /* Loop until delay is complete. */
            while (SYS_TIME_DelayIsComplete(timer) == false);
        }

        return;
    }

    static void i2c_timeout_cleanup(void)
    {
        int busy_retry = TPM_I2C_TRIES;

        while (i2cXferDirty && I2C_BB_IsBusy() && --busy_retry > 0) {
            microchip_wait(250);
        }
        if (!I2C_BB_IsBusy()) {
            i2c_scrub_stale();
        }
    }

    /* Microchip Harmony I2C */
    static int i2c_read(void* userCtx, word32 reg, byte* data, int len)
    {
        int         ret = TPM_RC_FAILURE;
        I2CBB_ERROR status = I2CBB_ERROR_NONE;
        bool        queued = false;
        int         timeout = TPM_I2C_TRIES;
        int         busy_retry = TPM_I2C_TRIES;
        byte*       buf = i2cRegBuf;

        if (I2C_BB_IsBusy()) {
            printf("error: i2c_read: already busy\n");
            return -1;
        }
        i2c_scrub_stale();

        /* TIS layer should never provide a buffer larger than this,
           but double check for good coding practice */
        if (len > MAX_SPI_FRAMESIZE) {
            printf("error: i2c_read: len too large: %d\n", len);
            return BAD_FUNC_ARG;
        }

        buf[0] = (reg & 0xFF); /* convert to simple 8-bit address for I2C */

        do {
            /* Queue the write with I2C_BB. */
            queued = I2C_BB_Write(TPM2_I2C_ADDR, buf, sizeof(i2cRegBuf));

            if (!queued) {
                printf("error: i2c_read: I2C_BB_Write failed\n");
                return -1;
            }

            busy_retry = TPM_I2C_TRIES;

            while (I2C_BB_IsBusy() && --busy_retry > 0) {
                microchip_wait(250);
            }

            if (I2C_BB_IsBusy()) {
                printf("error: i2c_read: busy wait timed out\n");
                return -1;
            }

            status = I2C_BB_ErrorGet();
            if (status == I2CBB_ERROR_NAK) {
                microchip_wait(250);
            }
        } while (status == I2CBB_ERROR_NAK && --timeout > 0);

        if (status != I2CBB_ERROR_NONE) {
            if (status == I2CBB_ERROR_NAK) {
                printf("error: i2c_read: I2C_BB_Write failed with NAK: %d\n",
                       status);
            }
            else {
                printf("error: i2c_read: I2C_BB_Write failed: %d\n", status);
            }

            return -1;
        }

        timeout = TPM_I2C_TRIES;

        do {
            /* Queue the read with I2C_BB. */
            queued = I2C_BB_Read(TPM2_I2C_ADDR, i2cRdBuf, len);

            if (!queued) {
                printf("error: i2c_read: I2C_BB_Read failed\n");
                return -1;
            }

            busy_retry = TPM_I2C_TRIES;

            while (I2C_BB_IsBusy() && --busy_retry > 0) {
                microchip_wait(250);
            }

            if (I2C_BB_IsBusy()) {
                /* Engine still owns i2cRdBuf; it cannot be scrubbed here, so
                 * defer scrubbing until the completion callback. */
                i2cXferDirty = 1;
                if (!I2C_BB_IsBusy()) {
                    i2c_scrub_stale();
                }
                printf("error: i2c_read: busy wait timed out\n");
                return -1;
            }

            status = I2C_BB_ErrorGet();
            if (status == I2CBB_ERROR_NAK) {
                microchip_wait(250);
            }
        } while (status == I2CBB_ERROR_NAK && --timeout > 0);

        if (status == I2CBB_ERROR_NONE) {
            XMEMCPY(data, i2cRdBuf, len);
            ret = TPM_RC_SUCCESS;
        }
        else {
            printf("error: I2C Read failure %d (tries %d)\n",
                status, TPM_I2C_TRIES - timeout);
        }

        TPM2_ForceZero(i2cRdBuf, sizeof(i2cRdBuf));
        return ret;
    }

    static int i2c_write(void* userCtx, word32 reg, byte* data, int len)
    {
        int         ret = TPM_RC_FAILURE;
        I2CBB_ERROR status = I2CBB_ERROR_NONE;
        bool        queued = false;
        int         timeout = TPM_I2C_TRIES;
        int         busy_retry = TPM_I2C_TRIES;
        byte*       buf = i2cXferBuf;

        /* TIS layer should never provide a buffer larger than this,
           but double check for good coding practice */
        if (len > MAX_SPI_FRAMESIZE) {
            printf("error: i2c_write: len too large: %d\n", len);
            return BAD_FUNC_ARG;
        }

        if (I2C_BB_IsBusy()) {
            printf("error: i2c_write: already busy\n");
            return -1;
        }
        i2c_scrub_stale();

        /* Build packet with TPM register and data. The engine is idle here,
         * so clear any residue a previous busy-timeout bail-out left */
        TPM2_ForceZero(buf, sizeof(i2cXferBuf));
        buf[0] = (reg & 0xFF); /* convert to simple 8-bit address for I2C */
        XMEMCPY(buf + 1, data, len);

        do {
            /* Queue the write with I2C_BB. */
            queued = I2C_BB_Write(TPM2_I2C_ADDR, buf, len + 1);

            if (!queued) {
                printf("error: i2c_write: I2C_BB_Write failed: %d\n", status);
                TPM2_ForceZero(buf, sizeof(i2cXferBuf));
                return -1;
            }

            busy_retry = TPM_I2C_TRIES;

            while (I2C_BB_IsBusy() && --busy_retry > 0) {
                microchip_wait(250);
            }

            if (I2C_BB_IsBusy()) {
                /* Engine is still clocking out i2cXferBuf, so it cannot be
                 * scrubbed here; defer until the completion callback. */
                i2cXferDirty = 1;
                if (!I2C_BB_IsBusy()) {
                    i2c_scrub_stale();
                }
                printf("error: i2c_write: busy wait timed out\n");
                return -1;
            }

            status = I2C_BB_ErrorGet();

            if (status == I2CBB_ERROR_NAK) {
                microchip_wait(250);
            }
        } while (status == I2CBB_ERROR_NAK && --timeout > 0);

        if (status == I2CBB_ERROR_NONE) {
            ret = TPM_RC_SUCCESS;
        }
        else {
            printf("I2C Write failure %d\n", status);
        }
        TPM2_ForceZero(buf, sizeof(i2cXferBuf));
        return ret;
    }

    int TPM2_IoCb_MicrochipHarmony_I2C(TPM2_CTX* ctx, int isRead, word32 addr,
        byte* buf, word16 size, void* userCtx)
    {
        int ret = TPM_RC_FAILURE;

        /* Set callback to null to do time based polling of
         * I2C_BB_IsBusy instead.
         *
         * Note: Apparently a callback is actually required,
         * even if not used.
         * */
        I2C_BB_Initialize();
        I2C_BB_CallbackRegister(i2c_completion_callback, dummy_context);

        if (isRead) {
            ret = i2c_read(userCtx, addr, buf, size);
        }
        else {
            ret = i2c_write(userCtx, addr, buf, size);
        }

        /* A timed-out transfer may complete after i2c_read/write returns.
         * Poll once more here; the registered callback handles completion
         * after this bounded cleanup wait. */
        if (i2cXferDirty) {
            i2c_timeout_cleanup();
        }

        (void)userCtx;
        (void)ctx;

        return ret;
    }
#else /* Microchip Harmony Hal SPI */

#ifdef WOLFTPM_CHECK_WAIT_STATE
    #error This driver does not support check wait state yet
#endif

/* TPM Chip Select Pin (default PC5) */
#ifndef TPM_SPI_PIN
#define TPM_SPI_PIN SYS_PORT_PIN_PC5
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
        ret = TPM_RC_SUCCESS;
    }

    (void)ctx;
    (void)userCtx;

    DRV_SPI_Close(handle);
    handle = DRV_HANDLE_INVALID;

    return ret;
}

#endif /* WOLFTPM_I2C */
#endif /* WOLFTPM_MICROCHIP_HARMONY */
#endif /* !(WOLFTPM_LINUX_DEV || WOLFTPM_SWTPM || WOLFTPM_WINAPI) */
#endif /* WOLFTPM_INCLUDE_IO_FILE */

/******************************************************************************/
/* --- END IO Callback Logic -- */
/******************************************************************************/
