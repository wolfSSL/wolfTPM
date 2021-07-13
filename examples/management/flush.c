/* flush.c
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

/* This is a helper tool for reseting the value of a TPM2.0 PCR */

#include <wolftpm/tpm2_wrap.h>

#include <examples/management/flush.h>
#include <examples/tpm_io.h>
#include <examples/tpm_test.h>

#include <stdio.h>
#include <stdlib.h> /* atoi */

#ifndef WOLFTPM2_NO_WRAPPER
/******************************************************************************/
/* --- BEGIN TPM2.0 Flush tool  -- */
/******************************************************************************/

static void usage(void)
{
    printf("Expected usage:\n");
    printf("./tool/management/flush [handle]\n");
    printf("* handle is a valid TPM2.0 handle index\n");
    printf("Note: Default behavior, without parameters, the tool flushes\n"
           "\tcommon transient TPM2.0 objects, including:\n"
           "- Transient Key handles 0x8000000\n"
           "- Transient Policy sessions 0x0300000x\n"
           "- Transient HMAC sessions 0x0200000x\n");
}

int TPM2_Flush_Tool(void* userCtx, int argc, char *argv[])
{
    int rc = TPM_RC_FAILURE;
    int allTransientObjects = 0, handle = 0;
    WOLFTPM2_DEV dev;
    FlushContext_In flushCtx;

    if (argc == 2) {
        /* TODO: Parse input parameter as 8 digit hex value */
        (void)argv;
        if(1) {
            printf("Input value does not look like a TPM handle\n");
            usage();
            return 0;
        }
    }
    else if (argc == 1) {
        allTransientObjects = 1;
    }
    else {
        printf("Incorrect arguments\n");
        usage();
        return 0;
    }

    printf("Preparing to free TPM2.0 Resources\n");
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_Init failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        return rc;
    }
    printf("wolfTPM2_Init: success\n");

    if (allTransientObjects) {
        /* Flush key objects */
        for (handle=0x80000000; handle < (int)0x8000000A; handle++) {
            flushCtx.flushHandle = handle;
            printf("Freeing %X object\n", handle);
            TPM2_FlushContext(&flushCtx);
        }
        /* Flush policy sessions */
        for (handle=0x3000000; handle < (int)0x3000004; handle++) {
            flushCtx.flushHandle = handle;
            printf("Freeing %X object\n", handle);
            TPM2_FlushContext(&flushCtx);
        }
        /* Flush hmac sessions */
        for (handle=0x3000000; handle < (int)0x3000004; handle++) {
            flushCtx.flushHandle = handle;
            printf("Freeing %X object\n", handle);
            TPM2_FlushContext(&flushCtx);
        }
    }
    else {
        flushCtx.flushHandle = handle;
        printf("Freeing %X object\n", handle);
        TPM2_FlushContext(&flushCtx);
    }

    wolfTPM2_Cleanup(&dev);
    return rc;
}

/******************************************************************************/
/* --- END TPM2.0 PCR Reset example tool -- */
/******************************************************************************/
#endif /* !WOLFTPM2_NO_WRAPPER */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = NOT_COMPILED_IN;

#ifndef WOLFTPM2_NO_WRAPPER
    rc = TPM2_Flush_Tool(NULL, argc, argv);
#else
    printf("Flush tool not compiled in\n");
    (void)argc;
    (void)argv;
#endif

    return rc;
}
#endif
