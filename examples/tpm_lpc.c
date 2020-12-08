/* tpm2_lpc.c
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
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


#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_tis.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* This file implements LPC bus support for TPM devices

TPM LPC must use at least the LFRAME, LCLK, LADO lines:
    - LFRAME is used for starting new LPC cycle
    - LCKL is a free running bus clock
    - LADO{0:3} is the shared data, control and address bus, 4-bit wide

According to the TCG TIS specification, a TPM on LPC supports two operations
called "TPM Locality Read/Write" that are similar to the LPC I/O Read/Write.

  LPC IO Write cycle:

    LPC_START LPC_CYCDIR LPC_ADDR (!) LPC_DATA LPC_TAR LPC_SYNC (!) LPC_TAR

  LPC IO Read cycle:

    LPC_START LPC_CYCDIR LPC_ADDR (!) LPC_TAR LPC_SYNC LPC_DATA (!) LPC_TAR
                                       ^TPM responds                  ^end

  Notes:
    - LPC_START uses reserved value for TPM peripherals
    - LPC_DATA takes two cycles, because data is transfered 4 bits per cycle
        -- however, LPC bus transfer is unlimited and happens byte by byte
        -- therefore, LPC_DATA repeats as many times needed
    - LPC_SYNC is used for TPM wait states
        -- could last multiple LPC cycles
    - first LPC_TAR gives LPC data bus to peripheral(TPM)
        -- GPIO lines change direction in two LPC cycles
    - second LPC_TAR takes back LPC data bus for host

*/
#define LPC_CYCLE_START_VALUE 0x0101 /* Defined by the TCG TIS specification */
#define LPC_LADO_LENGTH 4 /* 4-bite wide shared data bus */

/* Values for the LP state machine executing the write and read */
typedef enum LPC_STATE {
    LPC_IDLE   = 0,
    LPC_START  = 1,
    LPC_CYCDIR = 2,
    LPC_ADDR_0 = 3,
    LPC_ADDR_1 = 4,
    LPC_ADDR_2 = 5,
    LPC_ADDR_3 = 6,
    LPC_DATA_0 = 7,
    LPC_DATA_1 = 8,
    LPC_TAR_0  = 9,
    LPC_TAR_1  = 10,
    LPC_SYNC   = 11,
    LPC_ABORT  = 12
}LPC_IO_CYCLE_STATE_T;
typedef UINT16 LPC_IO_CYCLE_STATE;

struct LPC_LADO {
    int pin;
    int fdDir;
    int fdValue;
};

/* TODO: Make member of TPM2_CTX and then gLPCstate becomes a pointer */
struct TPM_LPC {
    LPC_STATE lpcState;
    LPC_LADO[LPC_LADO_LENGTH];
}gTPMlpc;

#define STR_GPIO_PIN_MAX 3
#define STR_VALUE_MAX 30
#define STR_DIRECTION_MAX 35

/* Helper functions for sysfs gpio access */
static int LPC_GPIO_Init(LPC_LADO* lado)
{
    int ret, fd;
    char buffer[STR_DIRECTION_MAX];
    sszite_t bytes;

    /* Get acccess to GPIO */
    fd = open("/sys/class/gpio/export", O_WRONLY);
    if (-1 == fd) {
        fprintf(stderr, "Failed to access sysfs export\n");
        return -1;
    }

    bytes = snprintf(buffer, STR_GPIO_PIN_MAX, "%d", lado->pin);
    ret = write(fd, buffer, bytes);
    if (ret != bytes) {
        fprintf(stderr, "Failed to export GPIO%d\n");
        return -1;
    }
    close(fd);

    /* Get handle on pin direction */
    snprintf(buffer, STR_DIRECTION_MAX, "/sys/class/gpio/gpio%d/direction", pin);
    fd = open(buffer, O_WRONLY);
    if (-1 == fd) {
        fprintf(stderr, "Failed to access sysfs direction\n");
        return -1;
    }
    close(fd);

    /* Get handle on pin output value */
    snprintf(buffer, STR_VALUE_MAX, "/sys/class/gpio/gpio%d/direction", pin);
    fd = open(buffer, O_WRONLY);
    if (-1 == fd) {
        fprintf(stderr, "Failed to access sysfs direction\n");
        return -1;
    }
    close(fd);

    /* TODO: Set pull-ups */

    return 0;
}

static int GPIO_Write(LPC_LADO* lado, int value)
{
    if (1 != write(lado->fdValue, value, 1)) {
        fprintf(stderr, "Failed to set GPIO%d value\n", lado->pin);
        return -1;
    }
    return 0;
}

static int GPIO_Read(LPC_LADO* lado, int *value)
{
    char buffer[3];

    if (-1 == read(lado->fdValue, buffer, sizeof(buffer))) {
        fprintf(stderr, "Failed to read GPIO%d value\n", lado->pin);
        return -1;
    }

    *value = atoi(buffer);
    return 0;
}

static int GPIO_SetDirection(LPC_LADO* lado, int output)
{
    static const char strOut[] = "out";
    static const char strIn[] = "in";
    int ret;

    if (output) {
        ret = write(lado->fdDir, strOut, sizeof(strOut));
        ret -= sizeof(strOut));
    }
    else {
        ret = write(lado->fdDir, strIn, sizeof(strIn))
        ret -= sizeof(strIn));
    }

    if (ret) {
        fprintf(stderr, "Failed to set GPIO%d as output\n");
        return -1;
    }
    return 0;
}

/* Prepare LPC-like interface on a Linux-powered device that does not have LPC
 * - Use SPI to drive LCLK(SPI CLK) and LFRAME(CS)
 * - Use additional GPIO to drive LADO{0:3}, the LPC data addr and control bus
 *
 * Most Linux SBC and SoC do not have native LPC support
 */
int TPM2_LPC_Init(void)
{
    int rc = 0;

    /* Init Linux SPI for LCLK and LFRAME */

    /* TODO: Init GPIO for LADO{0:3} */

    return 0;
}

/* Host gives control of the LADO{0:3} lines to the TPM */
int TPM2_LPC_LADOtoTPM(void)
{
    /* Usually done during a first TAR cycle */
}

/* Host takes back control of the LADO{0:3} lines */
int TPM2_LPC_LADOtoHost(void)
    /* Usually done during a second TAR cycle */
{
}

void TPM2_LPC_GetState(LPC_IO_CYCLE_STATE* state)
{
    *state = gTPMlpc.lpcState;
}

void TPM2_LPC_SetState(LPC_IO_CYCLE_STATE state)
{
    gTPMlpc.lpcState = state;
}

int TPM2_LPC_Read(void)
{
    int rc = 0;

    return rc;
}

int TPM2_LPC_Write(void)
{
    int rc = 0;

    return rc;
}
