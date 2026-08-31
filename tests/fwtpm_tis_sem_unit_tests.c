/* fwtpm_tis_sem_unit_tests.c
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2_types.h>
#include <wolftpm/fwtpm/fwtpm_tis.h>

#include <stdio.h>
#include <string.h>

static int TestSemNames(void)
{
    const UINT64 uidA = 17U;
    const UINT64 uidB = 18U;
    char cmdA[FWTPM_TIS_SEM_NAME_SIZE];
    char rspA[FWTPM_TIS_SEM_NAME_SIZE];
    char cmdB[FWTPM_TIS_SEM_NAME_SIZE];
    char rspB[FWTPM_TIS_SEM_NAME_SIZE];
    char expectedCmd[FWTPM_TIS_SEM_NAME_SIZE];
    char expectedRsp[FWTPM_TIS_SEM_NAME_SIZE];

    if (FWTPM_TIS_MakeSemNames(uidA, cmdA, sizeof(cmdA), rspA,
            sizeof(rspA)) != 0 ||
            FWTPM_TIS_MakeSemNames(uidB, cmdB, sizeof(cmdB), rspB,
                sizeof(rspB)) != 0) {
        printf("FAIL: could not derive semaphore names\n");
        return 1;
    }
    /* Pinned vector for uid 17: do not recompute the production hash here. */
    (void)XSNPRINTF(expectedCmd, sizeof(expectedCmd), "%s-%s",
        FWTPM_TIS_SEM_CMD, "81af14c9e4a872f7");
    (void)XSNPRINTF(expectedRsp, sizeof(expectedRsp), "%s-%s",
        FWTPM_TIS_SEM_RSP, "81af14c9e4a872f7");
    if (strcmp(cmdA, expectedCmd) != 0 || strcmp(rspA, expectedRsp) != 0) {
        printf("FAIL: semaphore name has the wrong UID suffix\n");
        return 1;
    }
    if (strcmp(cmdA, cmdB) == 0 || strcmp(rspA, rspB) == 0) {
        printf("FAIL: different UIDs produced the same semaphore names\n");
        return 1;
    }

    printf("fwTPM TIS semaphore tests: passed\n");
    return 0;
}

int main(void)
{
    return TestSemNames();
}
