/* ifx_fw_update.c
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

/* This tool will perform a firmware update on Infineon SLB9672 or SLB9673
 * TPM 2.0 module */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2_wrap.h>

#ifdef WOLFTPM_FIRMWARE_UPGRADE

#include <examples/firmware/ifx_fw_update.h>
#include <examples/tpm_test_keys.h>
#include <hal/tpm_io.h>

/******************************************************************************/
/* --- BEGIN TPM2.0 Firmware Update tool  -- */
/******************************************************************************/

static void usage(void)
{
    printf("Infineon Firmware Update Usage:\n");
    printf("\t./ifx_fw_update (get info)\n");
    printf("\t./ifx_fw_update --abandon (cancel)\n");
    printf("\t./ifx_fw_update <manifest_file> <firmware_file>\n");
}

typedef struct {
    byte*  manifest_buf;
    byte*  firmware_buf;
    size_t manifest_bufSz;
    size_t firmware_bufSz;
} fw_info_t;

static int TPM2_IFX_FwData_Cb(uint8_t* data, uint32_t data_req_sz,
    uint32_t offset, void* cb_ctx)
{
    fw_info_t* fwinfo = (fw_info_t*)cb_ctx;
    if (offset + data_req_sz > (uint32_t)fwinfo->firmware_bufSz) {
        data_req_sz = (uint32_t)fwinfo->firmware_bufSz - offset;
    }
    if (data_req_sz > 0) {
        XMEMCPY(data, &fwinfo->firmware_buf[offset], data_req_sz);
    }
    return data_req_sz;
}

static int TPM2_IFX_PrintInfo(WOLFTPM2_DEV* dev)
{
    int rc;
    WOLFTPM2_CAPS caps;
    rc = wolfTPM2_GetCapabilities(dev, &caps);
    if (rc == TPM_RC_SUCCESS) {
        printf("Mfg %s (%d), Vendor %s, Fw %u.%u (0x%x), "
               "KeyGroupId 0x%x, OpMode 0x%x\n",
            caps.mfgStr, caps.mfg, caps.vendorStr, caps.fwVerMajor,
            caps.fwVerMinor, caps.fwVerVendor, caps.keyGroupId, caps.opMode);
        if (caps.keyGroupId == 0) {
            printf("Error getting key group id from TPM!\n");
            rc = -1;
        }
    }
    return rc;
}

int TPM2_IFX_Firmware_Update(void* userCtx, int argc, char *argv[])
{
    int rc;
    WOLFTPM2_DEV dev;
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

    printf("Infineon Firmware Update Tool\n");
    if (manifest_file != NULL)
        printf("\tManifest File: %s\n", manifest_file);
    if (firmware_file != NULL)
        printf("\tFirmware File: %s\n", firmware_file);

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_Init failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }

    rc = TPM2_IFX_PrintInfo(&dev);
    if (rc != 0) {
        goto exit;
    }

    if (abandon) {
        printf("Firmware Update Abandon:\n");
        rc = wolfTPM2_FirmwareUpgradeCancel(&dev);
        goto exit;
    }

    if (manifest_file == NULL || firmware_file == NULL) {
        printf("Manifest file or firmware file arguments missing!\n");
        goto exit;
    }

    /* load manifest and data files */
    rc = loadFile(manifest_file,
        &fwinfo.manifest_buf, &fwinfo.manifest_bufSz);
    if (rc == 0) {
        rc = loadFile(firmware_file,
            &fwinfo.firmware_buf, &fwinfo.firmware_bufSz);
    }
    if (rc == 0) {
        rc = wolfTPM2_FirmwareUpgrade(&dev,
            fwinfo.manifest_buf, (uint32_t)fwinfo.manifest_bufSz,
            TPM2_IFX_FwData_Cb, &fwinfo);
    }
    if (rc == 0) {
        rc = TPM2_IFX_PrintInfo(&dev);
    }

exit:

    if (rc != 0) {
        printf("Infineon firmware update failed 0x%x: %s\n",
            rc, TPM2_GetRCString(rc));
    }

    XFREE(fwinfo.firmware_buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(fwinfo.manifest_buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    wolfTPM2_Cleanup(&dev);

    return rc;
}

/******************************************************************************/
/* --- END TPM2.0 Firmware Update tool  -- */
/******************************************************************************/

#endif /* WOLFTPM_FIRMWARE_UPGRADE */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = -1;

#ifdef WOLFTPM_FIRMWARE_UPGRADE
    rc = TPM2_IFX_Firmware_Update(NULL, argc, argv);
#else
    printf("Support for firmware upgrade not compiled in! "
        "See --enable-firmware or WOLFTPM_FIRMWARE_UPGRADE\n");
    (void)argc;
    (void)argv;
#endif /* WOLFTPM_FIRMWARE_UPGRADE */

    return rc;
}
#endif
