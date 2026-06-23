/* getrandom.c
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

/* Example for getting random bytes from the TPM */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2_wrap.h>

#ifndef WOLFTPM2_NO_WRAPPER

#include <hal/tpm_io.h>
#include <examples/tpm_test.h>
#include <examples/wrap/wrap_test.h>

#include <stdio.h>

/* Default and maximum number of random bytes to request */
#define GETRANDOM_DEFAULT_BYTES 32
#define GETRANDOM_MAX_BYTES     256

/******************************************************************************/
/* --- BEGIN TPM2 Get Random example -- */
/******************************************************************************/

static void usage(void)
{
    printf("Expected Usage:\n");
    printf("./examples/wrap/getrandom [bytes]\n");
    printf("* bytes is the number of random bytes to request "
        "(default %d, max %d)\n", GETRANDOM_DEFAULT_BYTES, GETRANDOM_MAX_BYTES);
}

int TPM2_GetRandom_Example(void* userCtx, int argc, char* argv[])
{
    int rc;
    WOLFTPM2_DEV dev;
    byte buf[GETRANDOM_MAX_BYTES];
    word32 len = GETRANDOM_DEFAULT_BYTES;
    word32 i;

    if (argc > 1) {
        if (XSTRCMP(argv[1], "-?") == 0 ||
            XSTRCMP(argv[1], "-h") == 0 ||
            XSTRCMP(argv[1], "--help") == 0) {
            usage();
            return 0;
        }
        len = (word32)XATOI(argv[1]);
        if (len == 0) {
            len = GETRANDOM_DEFAULT_BYTES;
        }
        if (len > GETRANDOM_MAX_BYTES) {
            len = GETRANDOM_MAX_BYTES;
        }
    }

    printf("TPM2 Get Random Example (%u bytes)\n", len);

    XMEMSET(buf, 0, sizeof(buf));

    /* Init the TPM2 device */
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != 0) {
        printf("wolfTPM2_Init failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        return rc;
    }

    rc = wolfTPM2_GetRandom(&dev, buf, len);
    if (rc != 0) {
        printf("wolfTPM2_GetRandom failed 0x%x: %s\n", rc,
            wolfTPM2_GetRCString(rc));
        goto exit;
    }

    printf("Random bytes:\n");
    for (i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");

exit:

    wolfTPM2_Cleanup(&dev);

    return rc;
}

/******************************************************************************/
/* --- END TPM2 Get Random example -- */
/******************************************************************************/

#endif /* !WOLFTPM2_NO_WRAPPER */

#ifndef NO_MAIN_DRIVER
int main(int argc, char* argv[])
{
    int rc = -1;

#ifndef WOLFTPM2_NO_WRAPPER
    rc = TPM2_GetRandom_Example(NULL, argc, argv);
#else
    (void)argc;
    (void)argv;
    printf("Wrapper code not compiled in\n");
#endif

    return rc;
}
#endif /* !NO_MAIN_DRIVER */
