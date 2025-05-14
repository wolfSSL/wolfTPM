/* tpmclear.c
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

/* This is a tool for performing a TPM2_Clear call to reset the NV */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2_wrap.h>
#include <examples/management/management.h>
#include <hal/tpm_io.h>
#include <examples/tpm_test.h>

#include <stdio.h>

#ifndef WOLFTPM2_NO_WRAPPER
int TPM2_Clear_Tool(void* userCtx, int argc, char *argv[])
{
    int rc = TPM_RC_FAILURE;
    WOLFTPM2_DEV dev;

    (void)argc;
    (void)argv;

    printf("Preparing to clear TPM\n");
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_Init failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        return rc;
    }

    /* reset all content on TPM and reseed */
    rc = wolfTPM2_Clear(&dev);
    if (rc == 0) {
        printf("TPM Clear success\n");
    }

    if (rc != 0) {
        printf("Failure 0x%x: %s\n", rc, wolfTPM2_GetRCString(rc));
    }
    wolfTPM2_Cleanup(&dev);
    return rc;
}
#endif /* !WOLFTPM2_NO_WRAPPER */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = NOT_COMPILED_IN;

#ifndef WOLFTPM2_NO_WRAPPER
    rc = TPM2_Clear_Tool(NULL, argc, argv);
#else
    printf("Flush tool not compiled in\n");
    (void)argc;
    (void)argv;
#endif

    return rc;
}
#endif
