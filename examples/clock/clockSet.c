/* clockSet.c
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

#include <examples/clock/clockSet.h>
#include <examples/tpm_io.h>
#include <examples/tpm_test.h>

#include <stdio.h>


/******************************************************************************/
/* --- BEGIN TPM clockSet Test -- */
/******************************************************************************/

int TPM2_ClockSet_Test(void* userCtx)
{
    int rc;
    WOLFTPM2_DEV dev;

    union {
        ClockSet_In clockSet;
        byte maxInput[MAX_COMMAND_SIZE];
    } cmdIn;
    union {
        ReadClock_Out readClock;
        byte maxOutput[MAX_RESPONSE_SIZE];
    } cmdOut;

    TPMS_AUTH_COMMAND session[MAX_SESSION_NUM];

    UINT64 oldClock, newClock;

    printf("TPM2 Demo of setting the TPM clock forward\n");
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_Init failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    printf("wolfTPM2_Init: success\n");


    /* Define the default session auth that has NULL password */
    XMEMSET(session, 0, sizeof(session));
    session[0].sessionHandle = TPM_RS_PW;
    session[0].auth.size = 0; /* NULL Password */
    TPM2_SetSessionAuth(session);


    /* ReadClock the current TPM uptime */
    XMEMSET(&cmdOut.readClock, 0, sizeof(cmdOut.readClock));
    rc = TPM2_ReadClock(&cmdOut.readClock);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_ReadClock failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_ReadClock: success\n");
    printf("TPM2_ReadClock: (total)  time=%lu\n",
            cmdOut.readClock.currentTime.time);
    printf("TPM2_ReadClock: (uptime) clock=%lu\n",
            cmdOut.readClock.currentTime.clockInfo.clock);
    oldClock = cmdOut.readClock.currentTime.clockInfo.clock;

    /* Set Clock forward by 50 seconds */
    cmdIn.clockSet.auth = TPM_RH_OWNER;
    cmdIn.clockSet.newTime = oldClock + 50000;
    rc = TPM2_ClockSet(&cmdIn.clockSet);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_clockSet failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_clockSet: success\n");

    /* ReadClock to check the new clock time is set */
    XMEMSET(&cmdOut.readClock, 0, sizeof(cmdOut.readClock));
    rc = TPM2_ReadClock(&cmdOut.readClock);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_ReadClock failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_ReadClock: success\n");
    printf("TPM2_ReadClock: (total)  time=%lu\n",
            cmdOut.readClock.currentTime.time);
    printf("TPM2_ReadClock: (uptime) clock=%lu\n",
            cmdOut.readClock.currentTime.clockInfo.clock);
    newClock = cmdOut.readClock.currentTime.clockInfo.clock;

    printf("\n\t oldClock=%lu \n\t newClock=%lu \n\n", oldClock, newClock);

exit:

    if (rc != 0) {
        printf("Failure 0x%x: %s\n", rc, wolfTPM2_GetRCString(rc));
    }

    wolfTPM2_Cleanup(&dev);
    return rc;
}

/******************************************************************************/
/* --- END TPM Timestamp Test -- */
/******************************************************************************/

#endif /* !WOLFTPM2_NO_WRAPPER */


#ifndef NO_MAIN_DRIVER
int main(void)
{
    int rc = -1;

#ifndef WOLFTPM2_NO_WRAPPER
    rc = TPM2_ClockSet_Test(NULL);
#else
    printf("Wrapper code not compiled in\n");
#endif /* !WOLFTPM2_NO_WRAPPER */

    return rc;
}
#endif
