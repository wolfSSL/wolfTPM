/* read.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

/* Example for reading the voltage level of TPM's GPIO
 *
 * Note: GPIO must be first configured using gpio/gpio_config
 *
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2_wrap.h>

#include <examples/gpio/gpio.h>
#include <hal/tpm_io.h>
#include <examples/tpm_test.h>

#include <stdio.h>

#if !defined(WOLFTPM2_NO_WRAPPER) && \
    (defined(WOLFTPM_ST33) || defined(WOLFTPM_NUVOTON))

/******************************************************************************/
/* --- BEGIN TPM GPIO Read Example -- */
/******************************************************************************/
static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/gpio/gpio_read [num]\n");
    printf("* num is a GPIO number between %d-%d (default %d)\n", TPM_GPIO_NUM_MIN, TPM_GPIO_NUM_MAX, TPM_GPIO_A);
    printf("Example usage, without parameters, read GPIO%d\n", TPM_GPIO_A);
}

int TPM2_GPIO_Read_Example(void* userCtx, int argc, char *argv[])
{
    int rc, pin = TPM_GPIO_A;
    word32 readSize;
    WOLFTPM2_DEV dev;
    WOLFTPM2_HANDLE parent;
    WOLFTPM2_NV nv;
    TPM_HANDLE nvIndex;
    BYTE pinState;

    if (argc >= 2) {
        if (XSTRCMP(argv[1], "-?") == 0 ||
            XSTRCMP(argv[1], "-h") == 0 ||
            XSTRCMP(argv[1], "--help") == 0) {
            usage();
            return 0;
        }
        pin = XATOI(argv[1]);
        if (pin < TPM_GPIO_NUM_MIN || pin > TPM_GPIO_NUM_MAX) {
            usage();
            return 0;
        }
    }
    nvIndex = TPM_NV_GPIO_SPACE + (pin-TPM_GPIO_NUM_MIN);

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
#ifdef WOLFTPM_NUVOTON
    parent.hndl = TPM_RH_PLATFORM;
#else
    parent.hndl = TPM_RH_OWNER;
#endif
    /* Read GPIO state */
    readSize = sizeof(pinState);
    rc = wolfTPM2_NVReadAuth(&dev, &nv, nvIndex, &pinState, &readSize, 0);
    if (rc != TPM_RC_SUCCESS) {
        printf("Error while reading GPIO state\n");
        printf("Make sure GPIO has been configured with './examples/gpio/gpio_config'\n");
        goto exit;
    }

    if (pinState == 0x01) {
        printf("GPIO%d is High.\n", pin);
    }
    else if (pinState == 0x00) {
        printf("GPIO%d is Low.\n", pin);
    }
    else {
        printf("GPIO%d level read, invalid value = 0x%X\n", pin, pinState);
    }

exit:

    if (rc != TPM_RC_SUCCESS) {
        printf("\nFailure 0x%x: %s\n\n", rc, wolfTPM2_GetRCString(rc));
    }

    wolfTPM2_Cleanup(&dev);
    return rc;
}

/******************************************************************************/
/* --- END TPM GPIO Store Example -- */
/******************************************************************************/
#endif /* !WOLFTPM2_NO_WRAPPER && (WOLFTPM_ST33 || WOLFTPM_NUVOTON) */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = NOT_COMPILED_IN;

#if !defined(WOLFTPM2_NO_WRAPPER) && \
    (defined(WOLFTPM_ST33) || defined(WOLFTPM_NUVOTON))
    rc = TPM2_GPIO_Read_Example(NULL, argc, argv);
#else
    printf("GPIO configuration requires a STM ST33 or Nuvoton NPCT750 TPM 2.0 module built\n");
    (void)argc;
    (void)argv;
#endif

    return rc;
}
#endif
