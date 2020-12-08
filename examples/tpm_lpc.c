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

/* This file implements LPC bus support for TPM devices

TPM LPC must use LFRAME, LCLK, LADO

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

/* TODO: Make member of TPM2_CTX and then gLPCstate becomes a pointer */
static LPC_IO_CYCLE_STATE gLPCstate = LPC_IDLE;

/* Prepare LPC-like interface on a Linux-powered device that does not have LPC
 * - Use SPI to drive LCLK(SPI CLK) and LFRAME(CS)
 * - Use additional GPIO to drive LADO{0:3}, the LPC data addr and control bus
 *
 * Most Linux SBC and SoC do not have native LPC support
 */
int TPM2_LPC_Init(void)
{
    int rc = 0;

    /* Init Linux SPI */

    /* TODO: Init GPIO for LADO{0:3} */

    /* TODO: Pull-ups required on LADO lines */

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
    *state = gLPCstate;
}

void TPM2_LPC_SetState(LPC_IO_CYCLE_STATE state)
{
    gLPCstate = state;
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
