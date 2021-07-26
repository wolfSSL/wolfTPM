/* gpio_nuvoton.c
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

/* This examples demonstrates the use of GPIO available on
 * Nuvoton TPM 2.0 Modules, e.g. NPCT750 with FW version 7.2.3
 */

#include <wolftpm/tpm2_wrap.h>

#if defined(WOLFTPM_NUVOTON)

#include <examples/gpio/gpio.h>
#include <examples/tpm_io.h>
#include <examples/tpm_test.h>

#include <stdio.h>
#include <stdlib.h> /* atoi */


/******************************************************************************/
/* --- BEGIN TPM2.0 GPIO Configuration example  -- */
/******************************************************************************/

static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/gpio/gpio_nuvoton [num] [mode]\n");
    printf("* num is a GPIO number between 3 and 4 (default %d)\n", GPIO_NUM_MIN);
    printf("* mode is either push-pull, open-drain or open-drain with pull-up\n");
    printf("\t1. pushpull  - output in push pull configuration\n");
    printf("\t2. opendrain - output in open drain configuration\n");
    printf("\t3. pullup - output in open drain with pull-up enabled\n");
    printf("\t4. unconfig - delete NV index for GPIO access\n");
    printf("Example usage, without parameters, configures GPIO3 as push-pull output.\n");
}

int TPM2_GPIO_Nuvoton_Example(void* userCtx, int argc, char *argv[])
{
    int rc = -1;
    WOLFTPM2_DEV dev;
    WOLFTPM2_CAPS caps;
    WOLFTPM2_NV nv;
    WOLFTPM2_HANDLE parent;
    WOLFTPM2_SESSION tpmSessionIndex, tpmSessionPlatform;
    TPM_HANDLE nvIndex = TPM_NV_GPIO_SPACE;
    word32 nvAttributes;
    int gpioNum = 0;
    int gpioMode = NUVOTON_GPIO_MODE_PUSHPULL;
    /* Nuvoton specific structures */
    CFG_STRUCT newConfig;
    NTC2_GetConfig_Out getConfig;
    NTC2_PreConfig_In preConfig;
    /* Required for NV Index deletion */
    PolicyCommandCode_In policyCC;
    PolicySecret_In policySecretIn;
    PolicySecret_Out policySecretOut;
    NV_UndefineSpaceSpecial_In undefSpecial;

   if (argc >= 2) {
        if (XSTRNCMP(argv[1], "-?", 2) == 0 ||
            XSTRNCMP(argv[1], "-h", 2) == 0 ||
            XSTRNCMP(argv[1], "--help", 6) == 0) {
            usage();
            return 0;
        }
        if (argc == 3) {
            gpioMode = atoi(argv[2]);
            if (gpioMode > NUVOTON_GPIO_MODE_MAX) {
                printf("GPIO mode is out of range (1-3)\n");
                usage();
                goto exit_badargs;
            }
            /* Preparing to process next argument */
            argc--;
        }
        if (argc == 2) {
            gpioNum = atoi(argv[1]);
            if (gpioNum < GPIO_NUM_MIN || gpioNum > GPIO_NUM_MAX) {
                printf("GPIO is out of range (%d-%d)\n", GPIO_NUM_MIN, GPIO_NUM_MAX);
                usage();
                goto exit_badargs;
            }
            nvIndex = TPM_NV_GPIO_SPACE + (gpioNum-GPIO_NUM_MIN);
            /* all arguments processed */
        }
    }
    else if (argc == 1) {
        /* Default behavior, without arguments: GPIO 3 as pushpull output */
        gpioMode = NUVOTON_GPIO_MODE_PUSHPULL;
        gpioNum = GPIO_NUM_MIN;
    }
    else {
        printf("Incorrect arguments\n");
        usage();
        goto exit_badargs;
    }

    printf("Example for GPIO configuration of a NPTC7xx TPM 2.0 module\n");

    printf("GPIO number: %d\n", gpioNum);
    printf("GPIO mode: %d\n", gpioMode);

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_Init failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    printf("wolfTPM2_Init: success\n");

    /* Get TPM capabilities, to discover the TPM vendor */
    rc = wolfTPM2_GetCapabilities(&dev, &caps);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_GetCapabilities failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
    }

    /* Confirm the TPM vendor */
    if (caps.mfg != TPM_MFG_NUVOTON) {
        printf("TPM model mismatch. GPIO support requires a Nuvoton NPCT7xx TPM 2.0 module\n");
        goto exit;
    }

    /* GPIO un-configuration is done using NVDelete, no further action needed */
    /* Nuvoton can reconfigure any GPIO without deleting the created NV index */
    if (gpioMode == NUVOTON_GPIO_MODE_UNCONFIG) {
        printf("Deleting GPIO NV Index\n");

        XMEMSET(&tpmSessionIndex, 0, sizeof(tpmSessionIndex));
        XMEMSET(&tpmSessionPlatform, 0, sizeof(tpmSessionPlatform));

        /* This procedure requires CommandCode policy and EK Auth policy */
        rc = wolfTPM2_StartSession(&dev, &tpmSessionIndex, NULL, NULL,
                                   TPM_SE_POLICY, TPM_ALG_NULL);
        if (rc == TPM_RC_SUCCESS) {
            printf("index ok\n");
        }

        rc = wolfTPM2_StartSession(&dev, &tpmSessionPlatform, NULL, NULL,
                                   TPM_SE_POLICY, TPM_ALG_NULL);

        if (rc == TPM_RC_SUCCESS) {
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
            if (rc == TPM_RC_SUCCESS) {
                printf("TPM2_PolicySecret: success\n");
            }
        }

        /* Slot 0 for Index */
        rc = wolfTPM2_SetAuthSession(&dev, 0, &tpmSessionIndex, 0);
        if (rc != TPM_RC_SUCCESS) {
            printf("Failure to set Index auth session\n");
            goto exit;
        }
        /* Slot 1 for Platform */
        rc = wolfTPM2_SetAuthSession(&dev, 1, &tpmSessionPlatform, 0);
        if (rc != TPM_RC_SUCCESS) {
            printf("Failure to set Platform auth session\n");
            goto exit;
        }

        undefSpecial.nvIndex = nvIndex;
        undefSpecial.platform = TPM_RH_PLATFORM;
        printf("UndefSpecial\n\n\n");
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
    if(gpioMode == NUVOTON_GPIO_MODE_PUSHPULL) {
        /* For NUVOTON_GPIO_MODE_PUSHPULL */
        newConfig.GpioPushPull |= (1 << gpioNum);
    }
    else {
        /* For NUVOTON_GPIO_MODE_OPENDRAIN or NUVOTON_GPIO_MODE_PULLUP */
        newConfig.GpioPushPull &= ~(1 << gpioNum);
    }

    /* Set pull-up to disabled by default, configure below only if requested */
    newConfig.GpioPullUp &= ~(1 << gpioNum);

    /* Extra step for open-drain with pull-up mode */
    if (gpioMode == NUVOTON_GPIO_MODE_PULLUP) {
        newConfig.GpioPullUp &= ~(1 << gpioNum);
    }

#ifdef WOLFTPM_DEBUG_VERBOSE
    printf("newConfig CFG_CONFIG structure:\n");
    TPM2_PrintBin((byte*)&newConfig, sizeof(newConfig));
#endif

    /* Configuring a TPM GPIO requires a PLATFORM authorization. Afterwards,
     * using that GPIO is up to the user. Therefore, NV Indexes are operated
     * using OWNER authorization. See below NVCreateAuth.
     */
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
    if (rc != 0) {
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

exit:

    wolfTPM2_UnloadHandle(&dev, &tpmSessionIndex.handle);
    wolfTPM2_UnloadHandle(&dev, &tpmSessionPlatform.handle);
    wolfTPM2_Cleanup(&dev);

exit_badargs:

    return rc;
}

/******************************************************************************/
/* --- END TPM2.0 GPIO Configuration example -- */
/******************************************************************************/
#endif /* WOLFTPM_NUVOTON */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = -1;

#if defined(WOLFTPM_NUVOTON)
    rc = TPM2_GPIO_Nuvoton_Example(NULL, argc, argv);
#else
    printf("GPIO configuration requires a Nuvoton NPCT75x TPM 2.0 module built with WOLFTPM_NUVOTON or --enable-nuvoton.\n");
    (void)argc;
    (void)argv;
#endif /* WOLFTPM_NUVOTON */

    return rc;
}
#endif
