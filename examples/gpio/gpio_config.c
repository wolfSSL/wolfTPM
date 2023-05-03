/* gpio_config.c
 *
 * Copyright (C) 2006-2022 wolfSSL Inc.
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

/* This examples demonstrates the use of GPIO available on some TPM modules.
 * Support tested with STM ST33 and Nuvoton NPCT750 FW 7.2.3.0 or later */

#include <wolftpm/tpm2_wrap.h>

#include <stdio.h>

#if !defined(WOLFTPM2_NO_WRAPPER) && \
    (defined(WOLFTPM_ST33) || defined(WOLFTPM_NUVOTON))

#include <examples/gpio/gpio.h>
#include <hal/tpm_io.h>
#include <examples/tpm_test.h>

/******************************************************************************/
/* --- BEGIN TPM2.0 GPIO Configuration example  -- */
/******************************************************************************/

static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/gpio/gpio_config [num] [mode]\n");
    printf("* num is a GPIO number between %d-%d (default %d)\n", TPM_GPIO_NUM_MIN, TPM_GPIO_NUM_MAX, TPM_GPIO_A);
    printf("* mode is a number selecting the GPIO mode between 0-%d (default %d):\n", TPM_GPIO_MODE_MAX, TPM_GPIO_MODE_DEFAULT);
    printf("\t0. standard - reset to the GPIO's default mode\n");
#ifdef WOLFTPM_ST33
    printf("\t1. floating - input in floating configuration.\n");
    printf("\t2. pullup   - input with pull up enabled\n");
    printf("\t3. pulldown - input with pull down enabled\n");
    printf("\t4. opendrain - output in open drain configuration\n");
    printf("\t5. pushpull  - output in push pull configuration\n");
    printf("\t6. unconfigure - delete the NV index for the selected GPIO\n");
#elif defined(WOLFTPM_NUVOTON)
    printf("\t1. pushpull  - output in push pull configuration\n");
    printf("\t2. opendrain - output in open drain configuration\n");
    printf("\t3. pullup - output in open drain with pull-up enabled\n");
    printf("\t4. unconfig - delete NV index for GPIO access\n");
#endif
    printf("Example usage, without parameters, configures GPIO%d as input with a pull down.\n", TPM_GPIO_A);
}

int TPM2_GPIO_Config_Example(void* userCtx, int argc, char *argv[])
{
    int rc = -1;
    int gpioNum = 0;
    int gpioInput = 0;
    WOLFTPM2_DEV dev;
    WOLFTPM2_CAPS caps;
    WOLFTPM2_NV nv;
    WOLFTPM2_HANDLE parent;
    TPMI_GPIO_MODE gpioMode = TPM_GPIO_MODE_DEFAULT;
    TPM_HANDLE nvIndex = TPM_NV_GPIO_SPACE;
    word32 nvAttributes;

    /* Vendor specific structures */
#ifdef WOLFTPM_ST33
    GpioConfig_In gpio;
    SetCommandSet_In setCmdSet;
#elif defined(WOLFTPM_NUVOTON)
    CFG_STRUCT newConfig;
    NTC2_GetConfig_Out getConfig;
    NTC2_PreConfig_In preConfig;
    /* Required for NV Index deletion */
    PolicyCommandCode_In policyCC;
    PolicySecret_In policySecretIn;
    PolicySecret_Out policySecretOut;
    NV_UndefineSpaceSpecial_In undefSpecial;
    WOLFTPM2_SESSION tpmSessionIndex, tpmSessionPlatform;
#endif

   if (argc >= 2) {
        if (XSTRCMP(argv[1], "-?") == 0 ||
            XSTRCMP(argv[1], "-h") == 0 ||
            XSTRCMP(argv[1], "--help") == 0) {
            usage();
            return 0;
        }
        if (argc == 3) {
            gpioMode = XATOI(argv[2]);
            if (gpioMode > TPM_GPIO_MODE_MAX) {
                printf("GPIO mode is out of range (0-%d)\n", TPM_GPIO_MODE_MAX);
                usage();
                goto exit_badargs;
            }
            /* Check if mode is for GPIO Input to perform extra config step */
            if (gpioMode >= TPM_GPIO_MODE_INPUT_MIN &&
                gpioMode <= TPM_GPIO_MODE_INPUT_MAX) {
                /* GPIO Input mode */
                gpioInput = 1;
            }
            /* Preparing to process next argument */
            argc--;
        }
        if (argc == 2) {
            gpioNum = XATOI(argv[1]);
            if (gpioNum < TPM_GPIO_NUM_MIN || gpioNum > TPM_GPIO_NUM_MAX) {
                printf("GPIO is out of range (%d-%d)\n", TPM_GPIO_NUM_MIN, TPM_GPIO_NUM_MAX);
                usage();
                goto exit_badargs;
            }
            /* calculate GPIO NV index */
            nvIndex = TPM_NV_GPIO_SPACE + (gpioNum-TPM_GPIO_NUM_MIN);
            /* all arguments processed */
        }
    }
    else if (argc == 1) {
        /* Default behavior, without arguments */
        gpioMode = TPM_GPIO_MODE_DEFAULT;
        gpioNum = TPM_GPIO_A;
    }
    else {
        printf("Incorrect arguments\n");
        usage();
        goto exit_badargs;
    }

    printf("Example for GPIO configuration on a TPM 2.0 module\n");

    printf("GPIO number: %d\n", gpioNum);
    printf("GPIO mode: %d\n", gpioMode);

#ifdef WOLFTPM_ST33
    /* Sanity check TPM_GPIO_B can be used only as input */
    if (gpioNum == TPM_GPIO_B &&
        (gpioMode == TPM_GPIO_MODE_PUSHPULL ||
        gpioMode == TPM_GPIO_MODE_OPENDRAIN)) {
        printf("Warning: TPM_GPIO_B can be used only as an input.\n");
        usage();
        return 0;
    }
#elif defined(WOLFTPM_NUVOTON)
    XMEMSET(&tpmSessionIndex, 0, sizeof(tpmSessionIndex));
    XMEMSET(&tpmSessionPlatform, 0, sizeof(tpmSessionPlatform));
#endif

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_Init failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }

    /* Get TPM capabilities, to discover the TPM vendor */
    rc = wolfTPM2_GetCapabilities(&dev, &caps);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_GetCapabilities failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
    }

    /* Confirm the TPM vendor */
#ifdef WOLFTPM_ST33
    if (caps.mfg != TPM_MFG_STM) {
        printf("TPM vendor mismatch. GPIO support requires an ST33 TPM 2.0 module\n");
        goto exit;
    }

    /* Make sure NV Index for this GPIO is cleared before use
     * This way we make sure a new GPIO config can be set */
#ifdef DEBUG_WOLFTPM
    printf("Trying to remove NV index 0x%8.8X used for GPIO\n", nvIndex);
#endif
    rc = wolfTPM2_NVDelete(&dev, TPM_RH_OWNER, nvIndex);
    if (rc == TPM_RC_SUCCESS) {
        printf("NV Index undefined\n");
    }
    else if (rc == (TPM_RC_HANDLE | TPM_RC_2)) {
        printf("NV Index is available for GPIO use\n");
    }
    else {
        printf("NV Index delete failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
    }

    /* GPIO un-configuration is done using NVDelete, no further action needed */
    if (gpioMode == TPM_GPIO_MODE_UNCONFIG) {
        goto exit;
    }

    XMEMSET(&setCmdSet, 0, sizeof(setCmdSet));
    setCmdSet.authHandle = TPM_RH_PLATFORM;
    setCmdSet.commandCode = TPM_CC_GPIO_Config;
    setCmdSet.enableFlag = 1;
    rc = TPM2_SetCommandSet(&setCmdSet);
    if (rc != TPM_RC_SUCCESS) {
        printf("Enable GPIO config command failed 0x%x: %s\n",
            rc, TPM2_GetRCString(rc));
        goto exit;
    }

    /* Configuring a TPM GPIO requires a PLATFORM authorization. Afterwards,
     * using that GPIO is up to the user. Therefore, NV Indexes are operated
     * using OWNER authorization. See below NVCreateAuth. */
    XMEMSET(&gpio, 0, sizeof(gpio));
    gpio.authHandle = TPM_RH_PLATFORM;
    gpio.config.count = 1;
    gpio.config.gpio[0].name = gpioNum;
    gpio.config.gpio[0].mode = gpioMode;
    gpio.config.gpio[0].index = nvIndex;
    printf("Trying to configure GPIO%d...\n", gpio.config.gpio[0].name);
    rc = TPM2_GPIO_Config(&gpio);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_GPIO_Config failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_GPIO_Config success\n");

    /* Configure NV Index for access to this GPIO */
    XMEMSET(&nv, 0, sizeof(nv));
    XMEMSET(&parent, 0, sizeof(parent));
    /* Prep NV attributes */
    parent.hndl = TPM_RH_OWNER;
    rc = wolfTPM2_GetNvAttributesTemplate(parent.hndl, &nvAttributes);
    if (rc != TPM_RC_SUCCESS) {
        printf("Setting NV attributes failed\n");
        goto exit;
    }
    /* Define NV Index for GPIO */
    rc = wolfTPM2_NVCreateAuth(&dev, &parent, &nv, nvIndex, nvAttributes,
                               sizeof(BYTE), (byte*)gNvAuth, sizeof(gNvAuth)-1);
    if (rc != 0 && rc != TPM_RC_NV_DEFINED) {
        printf("Creating NV Index for GPIO acccess failed\n");
        goto exit;
    }
    printf("NV Index for GPIO access created\n");

    /* GPIO configured as an input, requires an extra configuration step */
    if (gpioInput) {
        BYTE dummy = 0;
        /* Writing a dummy byte has no impact on the input, but is required */
        rc = wolfTPM2_NVWriteAuth(&dev, &nv, nvIndex, &dummy, sizeof(dummy), 0);
        if (rc != TPM_RC_SUCCESS) {
            printf("Error while configuring the GPIO as an Input.\n");
        }
    }

#elif defined(WOLFTPM_NUVOTON)

    if (caps.mfg != TPM_MFG_NUVOTON) {
        printf("TPM vendor mismatch. GPIO support requires Nuvoton NPCT7xx TPM 2.0 module\n");
        goto exit;
    }

    /* GPIO un-configuration is done using NVDelete, no further action needed */
    /* Nuvoton can reconfigure any GPIO without deleting the created NV index */
    if (gpioMode == TPM_GPIO_MODE_UNCONFIG) {
        printf("Deleting GPIO NV Index\n");

        /* This procedure requires CommandCode policy and EK Auth policy */
        rc = wolfTPM2_StartSession(&dev, &tpmSessionIndex, NULL, NULL,
                                   TPM_SE_POLICY, TPM_ALG_NULL);
        if (rc != TPM_RC_SUCCESS) {
            printf("wolfTPM2_StartSession index failed 0x%x: %s\n", rc,
                TPM2_GetRCString(rc));
            goto exit;
        }
        rc = wolfTPM2_StartSession(&dev, &tpmSessionPlatform, NULL, NULL,
                                   TPM_SE_POLICY, TPM_ALG_NULL);
        if (rc != TPM_RC_SUCCESS) {
            printf("wolfTPM2_StartSession policy failed 0x%x: %s\n", rc,
                TPM2_GetRCString(rc));
            goto exit;
        }

    #ifdef DEBUG_WOLFTPM
        printf("TPM2_StartAuthSession: tpmSessionIndex 0x%x\n",
                (word32)tpmSessionIndex.handle.hndl);
        printf("TPM2_StartAuthSession: tpmSessionPlatforme 0x%x\n",
                (word32)tpmSessionPlatform.handle.hndl);
    #endif

        /* Allow object change auth */
        XMEMSET(&policyCC, 0, sizeof(policyCC));
        policyCC.policySession = tpmSessionIndex.handle.hndl;
        policyCC.code = TPM_CC_NV_UndefineSpaceSpecial;
        rc = TPM2_PolicyCommandCode(&policyCC);
        if (rc != TPM_RC_SUCCESS) {
            printf("TPM2_PolicyCommandCode failed 0x%x: %s\n", rc,
                TPM2_GetRCString(rc));
            goto exit;
        }
        printf("TPM2_PolicyCommandCode: success\n");

        /* Provide Endorsement Auth using PolicySecret */
        XMEMSET(&policySecretIn, 0, sizeof(policySecretIn));
        policySecretIn.authHandle = TPM_RH_ENDORSEMENT;
        policySecretIn.policySession = tpmSessionIndex.handle.hndl;
        rc = TPM2_PolicySecret(&policySecretIn, &policySecretOut);
        if (rc != TPM_RC_SUCCESS) {
            printf("TPM2_PolicySecret failed 0x%x: %s\n", rc,
                TPM2_GetRCString(rc));
            goto exit;
        }
        printf("TPM2_PolicySecret: success\n");

        /* Slot 0 for Index */
        rc = wolfTPM2_SetAuthSession(&dev, 0, &tpmSessionIndex, 0);
        if (rc != TPM_RC_SUCCESS) {
            printf("Failure to set Index auth session (0x%x: %s)\n", rc,
                TPM2_GetRCString(rc));
            goto exit;
        }
        /* Slot 1 for Platform */
        rc = wolfTPM2_SetAuthSession(&dev, 1, &tpmSessionPlatform, 0);
        if (rc != TPM_RC_SUCCESS) {
            printf("Failure to set Platform auth session (0x%x: %s)\n", rc,
                TPM2_GetRCString(rc));
            goto exit;
        }

        undefSpecial.nvIndex = nvIndex;
        undefSpecial.platform = TPM_RH_PLATFORM;
        rc = TPM2_NV_UndefineSpaceSpecial(&undefSpecial);
        if (rc == TPM_RC_SUCCESS) {
            printf("GPIO NV Index deleted\n");
        }
        else {
            printf("Deleting the NV Index failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        }

        /* Procedure for mode 4 (delete GPIO NV index) ends here */
        goto exit;
    }

    XMEMSET(&newConfig, 0, sizeof(newConfig));
    XMEMSET(&getConfig, 0, sizeof(getConfig));
    rc = TPM2_NTC2_GetConfig(&getConfig);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_NTC2_GetConfig failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    printf("Successfully read the current configuration\n");
    XMEMCPY(&newConfig, &getConfig.preConfig, sizeof(newConfig));

#ifdef WOLFTPM_DEBUG_VERBOSE
    printf("getConfig CFG_CONFIG structure:\n");
    TPM2_PrintBin((byte*)&getConfig.preConfig, sizeof(getConfig.preConfig));
#endif

    /* Prepare GPIO configuration according to Nuvoton requirements */
    if(gpioMode == TPM_GPIO_MODE_PUSHPULL) {
        /* For NUVOTON_GPIO_MODE_PUSHPULL */
        newConfig.GpioPushPull |= (1 << gpioNum);
    }
    else {
        /* For TPM_GPIO_MODE_OPENDRAIN or TPM_GPIO_MODE_PULLUP */
        newConfig.GpioPushPull &= ~(1 << gpioNum);
    }

    /* Set pull-up to disabled by default, configure below only if requested */
    newConfig.GpioPullUp &= ~(1 << gpioNum);

    /* Extra step for open-drain with pull-up mode */
    if (gpioMode == TPM_GPIO_MODE_PULLUP) {
        newConfig.GpioPullUp &= ~(1 << gpioNum);
    }

#ifdef WOLFTPM_DEBUG_VERBOSE
    printf("newConfig CFG_CONFIG structure:\n");
    TPM2_PrintBin((byte*)&newConfig, sizeof(newConfig));
#endif

    /* Configuring a TPM GPIO requires a PLATFORM authorization. Afterwards,
     * using that GPIO is up to the user. Therefore, NV Indexes are operated
     * using OWNER authorization. See below NVCreateAuth. */
    XMEMSET(&preConfig, 0, sizeof(preConfig));
    preConfig.authHandle = TPM_RH_PLATFORM;
    XMEMCPY(&preConfig.preConfig, &newConfig, sizeof(newConfig));
    rc = TPM2_NTC2_PreConfig(&preConfig);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_NTC2_PreConfig failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    printf("Successfully wrote new configuration\n");

    /* Configure NV Index for access to this GPIO */
    XMEMSET(&nv, 0, sizeof(nv));
    XMEMSET(&parent, 0, sizeof(parent));
    /* Initial NV attributes */
    parent.hndl = TPM_RH_PLATFORM;
    rc = wolfTPM2_GetNvAttributesTemplate(parent.hndl, &nvAttributes);
    /* Add NV attributes required by Nuvoton specification */
    nvAttributes |= (TPMA_NV_PLATFORMCREATE | TPMA_NV_POLICY_DELETE);
    nvAttributes |= (TPM_NT_ORDINARY & TPMA_NV_TPM_NT);
    if (rc != TPM_RC_SUCCESS) {
        printf("Setting NV attributes failed\n");
        goto exit;
    }
#ifdef DEBUG_WOLFTPM
    printf("nvAttributes = 0x%8.8X\n", nvAttributes);
#endif

    /* Define NV Index for GPIO */
    rc = wolfTPM2_NVCreateAuth(&dev, &parent, &nv, nvIndex, nvAttributes,
                               sizeof(BYTE), (byte*)gNvAuth, sizeof(gNvAuth)-1);
    if (rc != 0 && rc != TPM_RC_NV_DEFINED) {
        printf("Creating NV Index for GPIO acccess failed\n");
        goto exit;
    }
    printf("NV Index for GPIO access created\n");

    (void)gpioInput; /* not used */
#endif /* WOLFTPM_NUVOTON */

exit:

#if defined(WOLFTPM_NUVOTON) && !defined(WOLFTPM_ST33)
    wolfTPM2_UnloadHandle(&dev, &tpmSessionIndex.handle);
    wolfTPM2_UnloadHandle(&dev, &tpmSessionPlatform.handle);
#endif
    wolfTPM2_Cleanup(&dev);

exit_badargs:

    return rc;
}

/******************************************************************************/
/* --- END TPM2.0 GPIO Configuration example -- */
/******************************************************************************/
#endif /* !WOLFTPM2_NO_WRAPPER && (WOLFTPM_ST33 || WOLFTPM_NUVOTON) */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = -1;

#if !defined(WOLFTPM2_NO_WRAPPER) && \
    (defined(WOLFTPM_ST33) || defined(WOLFTPM_NUVOTON))
    rc = TPM2_GPIO_Config_Example(NULL, argc, argv);
#else
    printf("GPIO configuration requires a STM ST33 or Nuvoton NPCT750 TPM 2.0 module built\n");
    (void)argc;
    (void)argv;
#endif /* WOLFTPM_ST33 || WOLFTPM_NUVOTON */

    return rc;
}
#endif /* !NO_MAIN_DRIVER */
