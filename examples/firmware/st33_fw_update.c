/* st33_fw_update.c
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

/* This tool will perform a firmware update on STMicroelectronics ST33KTPM
 * TPM 2.0 module */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2_wrap.h>

#if defined(WOLFTPM_FIRMWARE_UPGRADE) && \
    (defined(WOLFTPM_ST33) || defined(WOLFTPM_AUTODETECT))

#include <examples/tpm_test_keys.h>
#include <hal/tpm_io.h>

/******************************************************************************/
/* --- BEGIN ST33 TPM2.0 Firmware Update tool  -- */
/******************************************************************************/

static void usage(void)
{
    printf("ST33 Firmware Update Usage:\n");
    printf("\t./st33_fw_update (get info)\n");
    printf("\t./st33_fw_update --abandon (cancel)\n");
    printf("\t./st33_fw_update <manifest_file> <firmware_file>\n");
    printf("\nNote: For firmware versions >= 915, LMS signature support is required.\n");
    printf("      The current API does not support LMS signature - this will need\n");
    printf("      to be extended for post-915 firmware updates.\n");
}

typedef struct {
    byte*  manifest_buf;
    byte*  firmware_buf;
    size_t manifest_bufSz;
    size_t firmware_bufSz;
} fw_info_t;

static int TPM2_ST33_FwData_Cb(uint8_t* data, uint32_t data_req_sz,
    uint32_t offset, void* cb_ctx)
{
    fw_info_t* fwinfo = (fw_info_t*)cb_ctx;
    if (offset > fwinfo->firmware_bufSz) {
        return BUFFER_E;
    }
    if (offset + data_req_sz > (uint32_t)fwinfo->firmware_bufSz) {
        data_req_sz = (uint32_t)fwinfo->firmware_bufSz - offset;
    }
    if (data_req_sz > 0) {
        XMEMCPY(data, &fwinfo->firmware_buf[offset], data_req_sz);
    }
    return data_req_sz;
}

static void TPM2_ST33_PrintInfo(WOLFTPM2_CAPS* caps)
{
    printf("Mfg %s (%d), Vendor %s, Fw %u.%u (0x%x)\n",
        caps->mfgStr, caps->mfg, caps->vendorStr, caps->fwVerMajor,
        caps->fwVerMinor, caps->fwVerVendor);
    printf("Firmware version details: Major=%u, Minor=%u, Vendor=0x%x\n",
        caps->fwVerMajor, caps->fwVerMinor, caps->fwVerVendor);
    if (caps->fwVerMinor < 915) {
        printf("Firmware update mode: Pre-915 (no LMS signature required)\n");
    }
    else {
        printf("Firmware update mode: Post-915 (LMS signature required)\n");
        printf("Warning: LMS signature support not yet implemented in this API\n");
    }
}

/* Forward declaration */
int TPM2_ST33_Firmware_Update(void* userCtx, int argc, char *argv[]);

int TPM2_ST33_Firmware_Update(void* userCtx, int argc, char *argv[])
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_CAPS caps;
    const char* manifest_file = NULL;
    const char* firmware_file = NULL;
    fw_info_t fwinfo;
    int abandon = 0;

    XMEMSET(&fwinfo, 0, sizeof(fwinfo));

    if (argc >= 2) {
        if (XSTRCMP(argv[1], "-?") == 0 ||
            XSTRCMP(argv[1], "-h") == 0 ||
            XSTRCMP(argv[1], "--help") == 0) {
            usage();
            return 0;
        }
        if (XSTRCMP(argv[1], "--abandon") == 0) {
            abandon = 1;
        }
        else {
            manifest_file = argv[1];
            if (argc >= 3) {
                firmware_file = argv[2];
            }
        }
    }

    printf("ST33 Firmware Update Tool\n");
    if (manifest_file != NULL)
        printf("\tManifest File: %s\n", manifest_file);
    if (firmware_file != NULL)
        printf("\tFirmware File: %s\n", firmware_file);

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_Init failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }

    rc = wolfTPM2_GetCapabilities(&dev, &caps);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_GetCapabilities failed 0x%x: %s\n",
            rc, TPM2_GetRCString(rc));
        goto exit;
    }
    
    TPM2_ST33_PrintInfo(&caps);
    
    /* Verify this is an ST33 TPM */
    if (caps.mfg != TPM_MFG_STM) {
        printf("Error: This tool is for STMicroelectronics ST33 TPMs only!\n");
        printf("Detected manufacturer: %s (%d)\n", caps.mfgStr, caps.mfg);
        rc = TPM_RC_COMMAND_CODE;
        goto exit;
    }

    if (abandon) {
        printf("Firmware Update Abandon:\n");
        rc = wolfTPM2_FirmwareUpgradeCancel(&dev);
        if (rc != 0) {
            printf("Abandon failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        }
        else {
            printf("Success: Please reset or power cycle TPM\n");
        }
        return rc;
    }

    if (manifest_file == NULL || firmware_file == NULL) {
        if (argc > 1) {
            printf("Manifest file or firmware file arguments missing!\n");
        }
        goto exit;
    }

    /* Check firmware version and warn about LMS signature requirement */
    if (caps.fwVerMinor >= 915) {
        printf("\nWarning: Firmware version >= 915 requires LMS signature.\n");
        printf("Current API implementation does not support LMS signature.\n");
        printf("Firmware update may fail for post-915 firmware.\n\n");
    }

    /* load manifest and data files */
    rc = loadFile(manifest_file,
        &fwinfo.manifest_buf, &fwinfo.manifest_bufSz);
    if (rc == 0) {
        rc = loadFile(firmware_file,
            &fwinfo.firmware_buf, &fwinfo.firmware_bufSz);
    }
    if (rc == 0) {
        printf("Firmware Update:\n");
        rc = wolfTPM2_FirmwareUpgrade(&dev,
            fwinfo.manifest_buf, (uint32_t)fwinfo.manifest_bufSz,
            TPM2_ST33_FwData_Cb, &fwinfo);
    }
    if (rc == 0) {
        printf("\nFirmware update completed successfully.\n");
        printf("Please reset or power cycle the TPM.\n");
        /* Get updated capabilities */
        rc = wolfTPM2_GetCapabilities(&dev, &caps);
        if (rc == 0) {
            TPM2_ST33_PrintInfo(&caps);
        }
    }

exit:

    if (rc != 0) {
        printf("ST33 firmware update failed 0x%x: %s\n",
            rc, TPM2_GetRCString(rc));
    }

    XFREE(fwinfo.firmware_buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(fwinfo.manifest_buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    wolfTPM2_Cleanup(&dev);

    return rc;
}

/******************************************************************************/
/* --- END ST33 TPM2.0 Firmware Update tool  -- */
/******************************************************************************/
#endif /* WOLFTPM_FIRMWARE_UPGRADE && (WOLFTPM_ST33 || WOLFTPM_AUTODETECT) */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = -1;

#if defined(WOLFTPM_FIRMWARE_UPGRADE) && \
    (defined(WOLFTPM_ST33) || defined(WOLFTPM_AUTODETECT))
    rc = TPM2_ST33_Firmware_Update(NULL, argc, argv);
#else
    printf("Support for ST33 firmware upgrade not compiled in!\n"
        "See --enable-firmware or WOLFTPM_FIRMWARE_UPGRADE\n");
    printf("This tool is for the STMicroelectronics ST33KTPM TPMs only\n"
        "\t--enable-st33 (WOLFTPM_ST33)\n");
    (void)argc;
    (void)argv;
#endif

    return rc;
}
#endif /* !NO_MAIN_DRIVER */

