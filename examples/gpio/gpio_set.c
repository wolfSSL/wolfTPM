/* set.c
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

/* Example for setting the voltage level of TPM's GPIO
 *
 * Note: GPIO must be first configured using gpio/config
 *
 */

#include <wolftpm/tpm2_wrap.h>

#include <examples/gpio/gpio.h>
#include <examples/tpm_io.h>
#include <examples/tpm_test.h>

#include <stdio.h>
#include <stdlib.h>

#ifndef WOLFTPM2_NO_WRAPPER

/******************************************************************************/
/* --- BEGIN TPM GPIO Set Example -- */
/******************************************************************************/
static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/gpio/gpio_set [num] [-high/-low]\n");
    printf("* num is a GPIO number between %d-%d (default %d)\n", GPIO_NUM_MIN, GPIO_NUM_MAX, TPM_GPIO_A);
    printf("Example usage, without parameters, set GPIO%d high\n", TPM_GPIO_A);
}

int TPM2_GPIO_Set_Example(void* userCtx, int argc, char *argv[])
{
    int rc, pin = 0;
    WOLFTPM2_DEV dev;
    WOLFTPM2_NV nv;
    WOLFTPM2_HANDLE parent;
    TPM_HANDLE nvIndex = TPM_NV_GPIO_SPACE;
    word32 writeSize;
    BYTE pinState = 0x01;

    if (argc >= 2) {
        if (XSTRNCMP(argv[1], "-?", 2) == 0 ||
            XSTRNCMP(argv[1], "-h", 2) == 0 ||
            XSTRNCMP(argv[1], "--help", 6) == 0) {
            usage();
            return 0;
        }
        pin = atoi(argv[1]);
        if(pin < GPIO_NUM_MIN || pin > GPIO_NUM_MAX) {
            usage();
            return 0;
        }
        nvIndex += pin;
    }
    while (argc > 1) {
        if (XSTRNCMP(argv[argc-1], "-high", 5) == 0) {
            pinState = 0x01;
        }
        if (XSTRNCMP(argv[argc-1], "-low", 4) == 0) {
            pinState = 0x00;
        }
        argc--;
    };

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("\nwolfTPM2_Init failed\n");
        goto exit;
    }

    XMEMSET(&nv, 0, sizeof(nv));
    XMEMSET(&parent, 0, sizeof(parent));
    /* Prep NV Index and its auth */
    nv.handle.hndl = nvIndex;
    nv.handle.auth.size = sizeof(gNvAuth)-1;
    XMEMCPY(nv.handle.auth.buffer, (byte*)gNvAuth, nv.handle.auth.size);
    parent.hndl = TPM_RH_OWNER;
    /* Read GPIO state */
    writeSize = sizeof(pinState);
    rc = wolfTPM2_NVWriteAuth(&dev, &nv, nvIndex, &pinState, writeSize, 0);
    if (rc != 0) {
            printf("Error while setting GPIO state\n");
            goto exit;
    }

    if (pinState) {
        printf("GPIO%d set to high level\n", pin);
    }
    else {
        printf("GPIO%d set to low level\n", pin);
    }

exit:

    if (rc != 0) {
        printf("\nFailure 0x%x: %s\n\n", rc, wolfTPM2_GetRCString(rc));
    }

    wolfTPM2_Cleanup(&dev);
    return rc;
}

/******************************************************************************/
/* --- END TPM GPIO Set Example -- */
/******************************************************************************/
#endif /* !WOLFTPM2_NO_WRAPPER */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = NOT_COMPILED_IN;

#ifndef WOLFTPM2_NO_WRAPPER
    rc = TPM2_GPIO_Set_Example(NULL, argc, argv);
#else
    printf("GPIO code not compiled in\n");
    (void)argc;
    (void)argv;
#endif

    return rc;
}
#endif
