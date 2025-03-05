/* tpm_io_zephyr.c
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/* This example shows IO interfaces for Zephyr-based micro-controllers
 * using Zephyr's kernel and drivers
 */

/*****************************************************************************/
/* --- BEGIN IO Callback Logic -- */
/*****************************************************************************/

/* Included via tpm_io.c if WOLFTPM_INCLUDE_IO_FILE is defined */
#ifdef WOLFTPM_INCLUDE_IO_FILE

#ifdef WOLFTPM_ZEPHYR

/* Zephyr Inlcudes Start */
#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/drivers/i2c.h>
/* Zephyr Includes End */

#ifdef WOLFTPM_I2C

/* Zephyr Configurations */

/* I2C master clock frequency */
/* Zephyr DTSI Defines this as I2C_BITRATE_STANDARD */
/* This means we have a clock rate of 100 khz */


/* Infineon 9673 I2C at 0x2e */
#define TPM2_INFINEON_9673_ADDR     0x2e

#if defined(WOLFTPM_I2C_CUST_ADDR)
    #define TPM2_I2C_ADDR           WOLFTPM_I2C_CUST_ADDR
#elif defined(WOLFTPM_SLB9673)
    #define TPM2_I2C_ADDR           TPM2_INFINEON_9673_ADDR
#else
    #error Set WOLFTPM_I2C_CUST_ADDR to i2c device ID or use supported device
#endif

/* Set to slowest speed supported in zephyr */
#if !defined(WOLFTPM_ZEPHYR_I2C_SPEED)
    #warning WOLFTPM_ZEPHYR_I2C_SPEED set to slowest Zephyr supports
    #define WOLFTPM_ZEPHYR_I2C_SPEED I2C_SPEED_STANDARD
#endif

#if !defined(WOLFTPM_ZEPHYR_I2C_BUS)
    #error Set WOLFTPM_ZEPHYR_I2C_BUS to devicetree node label for i2c bus
#endif

/* Init to False */
static int _is_initialized_i2c = 0;

/* Grab pointer from device tree label */
const struct device *i2c_dev = \
                DEVICE_DT_GET(DT_NODELABEL(WOLFTPM_ZEPHYR_I2C_BUS));


/* Setup the i2c tmp device */
/* Pass in pointer to the target */
int TPM2_I2C_Zephyr_Init(void)
{
    int ret = 0;
    uint32_t config = 0;

    config = I2C_MODE_CONTROLLER | I2C_SPEED_SET(WOLFTPM_ZEPHYR_I2C_SPEED);
    ret = i2c_configure(i2c_dev, config);

    return ret;
}

int TPM2_IoCb_Zephyr_I2C(TPM2_CTX* ctx, int isRead, word32 addr,
                            byte* buf, word16 size, void* userCtx)
{
    int ret = 0;
    byte* tempBuf = NULL;

    if (buf == NULL) {
        printf("Buffer passed is NULL");
        return -1;
    }

    if (i2c_dev == NULL) {
        printf("I2C device not found in Device Tree!\n");
        return -1;
    }

    /* Confirm i2c bus is ready */
    if (!device_is_ready(i2c_dev)) {
        printf("Device is not ready");
        return -1;
    }

    if (userCtx == NULL) {
        //printf("UserCtx Cannot be NULL\n");
    }


    /* Init Zephyr I2C Driver */
    if (_is_initialized_i2c == 0) {
        if (TPM2_I2C_Zephyr_Init() != 0) {
            printf("Could Not Init\n");
            return -1;
        }
        _is_initialized_i2c = 1;
    }

    if (isRead) {
        tempBuf = (byte*)XMALLOC(1, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (tempBuf == NULL) {
            printf("Failed to allocate temp buffer\n");
        }

        tempBuf[0] = (byte)(addr & 0xFF);

        // Read operation: First send register address, then read data
        ret = i2c_write_read(i2c_dev, TPM2_I2C_ADDR, tempBuf, 1, buf, size);
        if (ret < 0) {
            printf("Failed to read from TPM at register 0x%02X! Error: %d\n", addr, ret);
        }

        XFREE(tempBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    else {
        // Write operation: Register address + Data

        tempBuf = (byte*)XMALLOC(size + 1, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (tempBuf == NULL) {
            printf("Failed to allocate temp buffer\n");
        }

        tempBuf[0] = (byte)(addr & 0xFF);
        XMEMCPY((tempBuf + 1), buf, size);

        ret = i2c_write(i2c_dev, tempBuf, size + 1, TPM2_I2C_ADDR);
        if (ret < 0) {
            printf("Failed to write to TPM at register 0x%02X! Error: %d\n", addr, ret);
        }

        XFREE(tempBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    if (ret != 0) {
        printf("Could not perform operation: %d\n", ret);
        if (ret == -EIO) {
            printf("Input/Output Error\n");
        }
    }



    (void)ctx;
    return ret;
}

/* end WOLFTPM_I2C */

#else /* If not I2C, it must be SPI  */
    /* TODO implement SPI */
    #error TPM2 SPI support on zephyr yet
#endif

#endif /* WOLFSSL_ZEPHYR */
#endif /* WOLFTPM_INCLUDE_IO_FILE */

/******************************************************************************/
/* --- END IO Callback Logic -- */
/******************************************************************************/
