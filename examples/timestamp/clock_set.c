/* clock_set.c
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* This example shows how to increment the TPM2 clock */

#include <wolftpm/tpm2_wrap.h>

#ifndef WOLFTPM2_NO_WRAPPER

#include <examples/tpm_io.h>
#include <examples/tpm_test.h>
#include "clock_set.h"

#include <stdio.h>
#include <stdlib.h>

/******************************************************************************/
/* --- BEGIN TPM Clock Set Example -- */
/******************************************************************************/

static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/clock/clock_set [time]\n");
    printf("* time is a value in miliseconds used as increment (optional)\n");
    printf("* Default time value is 50000 ms (50 seconds)\n");
    printf("\tThe TPM clock can be set only forward.\n");
    printf("\tThe TPM clock can be set only forward.\n");
    printf("\tThe TPM clock shows the total time the TPM was ever powered.\n");
    printf("\tThe TPM clock is different and always higher than the\n");
    printf("\tcurrent uptime. The TPM uptime can not be tampered with.\n");
}

int TPM2_ClockSet_Test(void* userCtx, int argc, char *argv[])
{
    int rc = 0;
    WOLFTPM2_DEV dev;

    union {
        ClockSet_In clockSet;
        byte maxInput[MAX_COMMAND_SIZE];
    } cmdIn;
    union {
        ReadClock_Out readClock;
        byte maxOutput[MAX_RESPONSE_SIZE];
    } cmdOut;

    UINT64 oldClock, newClock;

    if (argc == 2) {
        if(*argv[1] == '?') {
            usage();
            goto exit_badargs;
        }
        /* Otherwise we have the [time] optional argument */
        newClock = atoi(argv[1]);
    }
    else if (argc == 1) {
        newClock = 0;
    }
    else {
        printf("Incorrect arguments\n");
        usage();
        goto exit_badargs;
    }

    printf("TPM2 Demo of setting the TPM clock forward\n");
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_Init failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    printf("wolfTPM2_Init: success\n");

    /* ReadClock the current TPM uptime */
    XMEMSET(&cmdOut.readClock, 0, sizeof(cmdOut.readClock));
    rc = TPM2_ReadClock(&cmdOut.readClock);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_ReadClock failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_ReadClock: success\n");
#ifdef DEBUG_WOLFTPM
    printf("TPM2_ReadClock: (uptime) time=%lu\n",
            (long unsigned int)cmdOut.readClock.currentTime.time);
    printf("TPM2_ReadClock: (total)  clock=%lu\n",
            (long unsigned int)cmdOut.readClock.currentTime.clockInfo.clock);
#endif
    oldClock = cmdOut.readClock.currentTime.clockInfo.clock;

    /* Set the TPM clock forward */
    cmdIn.clockSet.auth = TPM_RH_OWNER;
    if (newClock)
        cmdIn.clockSet.newTime = newClock;
    else
        cmdIn.clockSet.newTime = oldClock + 50000;
    rc = TPM2_ClockSet(&cmdIn.clockSet);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_clockSet failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_ClockSet: success\n");

    /* ReadClock to check the new clock time is set */
    XMEMSET(&cmdOut.readClock, 0, sizeof(cmdOut.readClock));
    rc = TPM2_ReadClock(&cmdOut.readClock);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_ReadClock failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_ReadClock: success\n");
#ifdef DEBUG_WOLFTPM
    printf("TPM2_ReadClock: (uptime) time=%lu\n",
            (long unsigned int)cmdOut.readClock.currentTime.time);
    printf("TPM2_ReadClock: (total)  clock=%lu\n",
            (long unsigned int)cmdOut.readClock.currentTime.clockInfo.clock);
#endif
    newClock = cmdOut.readClock.currentTime.clockInfo.clock;

    printf("\n\t oldClock=%lu \n\t newClock=%lu \n\n",
        (long unsigned int)oldClock, (long unsigned int)newClock);

exit:

    if (rc != 0) {
        printf("Failure 0x%x: %s\n", rc, wolfTPM2_GetRCString(rc));
    }

    wolfTPM2_Cleanup(&dev);

exit_badargs:

    return rc;
}

/******************************************************************************/
/* --- END TPM Clock Set Example -- */
/******************************************************************************/

#endif /* !WOLFTPM2_NO_WRAPPER */


#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = -1;

#ifndef WOLFTPM2_NO_WRAPPER
    rc = TPM2_ClockSet_Test(NULL, argc, argv);
#else
    printf("Wrapper code not compiled in\n");
    (void)argc;
    (void)argv;
#endif /* !WOLFTPM2_NO_WRAPPER */

    return rc;
}
#endif
