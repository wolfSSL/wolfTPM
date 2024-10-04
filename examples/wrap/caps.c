/* caps.
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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

/* Simple test to get capabilities from TPM */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_wrap.h>

#include <stdio.h>

#ifndef WOLFTPM2_NO_WRAPPER

#include <hal/tpm_io.h>
#include <examples/tpm_test.h>
#include <examples/wrap/wrap_test.h>


/******************************************************************************/
/* --- BEGIN Capabilities API example -- */
/******************************************************************************/

static void usage(void)
{
    printf("Expected Usage:\n");
    printf("./examples/wrap/caps\n");

}

int TPM2_Wrapper_Caps(void* userCtx)
{
    return TPM2_Wrapper_CapsArgs(userCtx, 0, NULL);
}
int TPM2_Wrapper_CapsArgs(void* userCtx, int argc, char *argv[])
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_CAPS caps;

    if (argc > 1) {
        if (XSTRCMP(argv[1], "-?") == 0 ||
            XSTRCMP(argv[1], "-h") == 0 ||
            XSTRCMP(argv[1], "--help") == 0) {
            usage();
            return 0;
        }
    }

    printf("TPM2 Get Capabilities\n");

    /* Init the TPM2 device */
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != 0) return rc;

    rc = wolfTPM2_GetCapabilities(&dev, &caps);
    if (rc != 0) goto exit;

    printf("Mfg %s (%d), Vendor %s, Fw %u.%u (0x%x), "
        "FIPS 140-2 %d, CC-EAL4 %d\n",
        caps.mfgStr, caps.mfg, caps.vendorStr, caps.fwVerMajor,
        caps.fwVerMinor, caps.fwVerVendor, caps.fips140_2, caps.cc_eal4);
#if defined(WOLFTPM_SLB9672) || defined(WOLFTPM_SLB9673)
    printf("\tKeyGroupId 0x%x, Operational Mode 0x%x, FwCounter %d (%d same)\n",
        caps.keyGroupId, caps.opMode, caps.fwCounter, caps.fwCounterSame);
#endif

    /* List the active persistent handles */
    rc = wolfTPM2_GetHandles(PERSISTENT_FIRST, NULL);
    if (rc >= 0) {
        printf("Found %d persistent handles\n", rc);
    }

exit:
    wolfTPM2_Shutdown(&dev, 0); /* 0=just shutdown, no startup */

    wolfTPM2_Cleanup(&dev);

    return rc;
}

/******************************************************************************/
/* --- END Capabilities API example -- */
/******************************************************************************/

#endif /* !WOLFTPM2_NO_WRAPPER */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = -1;

    (void)argc;
    (void)argv;

#ifndef WOLFTPM2_NO_WRAPPER
    rc = TPM2_Wrapper_CapsArgs(NULL, argc, argv);
#else
    printf("Wrapper code not compiled in\n");
#endif

    return rc;
}
#endif /* !NO_MAIN_DRIVER */
