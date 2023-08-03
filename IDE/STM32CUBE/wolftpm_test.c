/* wolftpm_test.c
 *
 * Copyright (C) 2014-2023 wolfSSL Inc.
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
 * along with wolfTPM.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "wolftpm_test.h"

#ifndef SINGLE_THREADED
    #include <cmsis_os.h>

    #ifdef WOLFSSL_DEBUG_MEMORY
        /* for memory debugging */
        #include <task.h>
    #endif
#endif

#include <stdio.h>
#include <string.h>

extern int TPM2_Wrapper_Test(void* userCtx);

#ifdef CMSIS_OS2_H_
void wolfTPMTest(void* argument)
#else
void wolfTPMTest(const void* argument)
#endif
{
    int ret = 0;

    printf("Running wolfTPM Wrap Test...\n");

    /* Run wolfTPM wrap test */
    ret = TPM2_Wrapper_Test(NULL);

    printf("wolfTPM wrap test: Return code %d\n", ret);

}
