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

/* Manifest sizes per ST33 firmware format */
#define ST33_BLOB0_SIZE_NON_LMS  177   /* Non-LMS manifest size */
#define ST33_BLOB0_SIZE_LMS      2697  /* LMS manifest size (includes embedded signature) */

static void usage(void)
{
    printf("ST33 Firmware Update Usage:\n");
    printf("\t./st33_fw_update (get info)\n");
    printf("\t./st33_fw_update --abandon (cancel)\n");
    printf("\t./st33_fw_update <firmware.fi> [--lms]\n");
    printf("\nOptions:\n");
    printf("      --lms: Use LMS format (2697 byte manifest with embedded signature)\n");
    printf("             Default is non-LMS format (177 byte manifest)\n");
    printf("\nNote: LMS format requirements:\n");
    printf("      - Firmware < 512: Non-LMS format required (legacy firmware, e.g., 9.257)\n");
    printf("      - Firmware >= 512: LMS format required (modern firmware, e.g., 9.512)\n");
    printf("\nFirmware file format:\n");
    printf("      - Non-LMS (.fi V1): First 177 bytes = manifest, rest = firmware data\n");
    printf("      - LMS (.fi V2): First 2697 bytes = manifest (with LMS sig), rest = firmware\n");
}

typedef struct {
    byte*  fi_buf;         /* Full .fi file buffer */
    byte*  manifest_buf;   /* Points into fi_buf */
    byte*  firmware_buf;   /* Points into fi_buf */
    size_t fi_bufSz;
    size_t manifest_bufSz;
    size_t firmware_bufSz;
    int    use_lms;        /* 1 = LMS format, 0 = non-LMS format */
    int    in_upgrade_mode; /* 1 = continuing from upgrade mode */
} fw_info_t;

/* Send firmware data blobs directly - used when continuing from upgrade mode */
static int TPM2_ST33_SendFirmwareData(fw_info_t* fwinfo)
{
    int rc;
    uint32_t offset = 0;
    uint8_t blob_header[3];
    uint8_t* blob_buf = NULL;
    uint32_t blob_len;
    uint32_t blob_total;
    int blob_count = 0;

    /* Allocate buffer for largest possible blob */
    blob_buf = (uint8_t*)XMALLOC(2048 + 3, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (blob_buf == NULL) {
        return MEMORY_E;
    }

    while (offset < fwinfo->firmware_bufSz) {
        /* Read blob header: type (1 byte) + length (2 bytes big-endian) */
        if (offset + 3 > fwinfo->firmware_bufSz) {
            rc = TPM_RC_SUCCESS; /* End of data */
            break;
        }
        XMEMCPY(blob_header, &fwinfo->firmware_buf[offset], 3);

        /* Check for end marker (type byte = 0) */
        if (blob_header[0] == 0) {
            rc = TPM_RC_SUCCESS;
            break;
        }

        /* Parse blob length from bytes 1-2 (big-endian) */
        blob_len = ((uint32_t)blob_header[1] << 8) | blob_header[2];
        blob_total = blob_len + 3;

        if (offset + blob_total > fwinfo->firmware_bufSz) {
            printf("Error: Incomplete blob at offset %u\n", offset);
            rc = BUFFER_E;
            break;
        }

        /* Copy complete blob (header + data) */
        XMEMCPY(blob_buf, &fwinfo->firmware_buf[offset], blob_total);

        /* Send blob to TPM */
        rc = TPM2_ST33_FieldUpgradeCommand(TPM_CC_FieldUpgradeDataVendor_ST33,
            blob_buf, blob_total);
        if (rc != TPM_RC_SUCCESS) {
            printf("FieldUpgradeData failed at blob %d, offset %u: 0x%x\n",
                blob_count, offset, rc);
            break;
        }

        blob_count++;
        offset += blob_total;

        /* Progress indication */
        if (blob_count % 100 == 0) {
            printf("  Sent %d blobs, %u/%zu bytes...\n", blob_count, offset,
                fwinfo->firmware_bufSz);
        }
    }

    printf("Sent %d firmware blobs, %u bytes total\n", blob_count, offset);
    XFREE(blob_buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return rc;
}

/* Callback function for firmware data access
 * Returns the actual number of bytes copied (may be less than requested at end of buffer)
 * Returns BUFFER_E on error (offset out of bounds) */
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
    if (caps->fwVerMinor < 512) {
        printf("Hardware: ST33K (legacy firmware, Generation 1)\n");
        printf("Firmware update: Non-LMS format required\n");
    }
    else {
        printf("Hardware: ST33K (modern firmware, Generation 2)\n");
        printf("Firmware update: LMS format required\n");
    }
}

/* Forward declaration */
int TPM2_ST33_Firmware_Update(void* userCtx, int argc, char *argv[]);

int TPM2_ST33_Firmware_Update(void* userCtx, int argc, char *argv[])
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_CAPS caps;
    const char* fi_file = NULL;
    fw_info_t fwinfo;
    int abandon = 0;
    int lms_state = 0; /* 0=UNSUPPORTED, 1=CAPABLE, 2=REQUIRED */
    int i;
    size_t blob0_size;

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
            fi_file = argv[1];
            /* Parse optional --lms flag */
            for (i = 2; i < argc; i++) {
                if (XSTRCMP(argv[i], "--lms") == 0) {
                    fwinfo.use_lms = 1;
                }
            }
        }
    }

    printf("ST33 Firmware Update Tool\n");
    if (fi_file != NULL) {
        printf("\tFirmware File: %s\n", fi_file);
        printf("\tFormat: %s\n", fwinfo.use_lms ? "LMS (V2)" : "Non-LMS (V1)");
    }

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc == TPM_RC_UPGRADE) {
        /* TPM is in firmware upgrade mode */
        printf("TPM is in firmware upgrade mode\n");
        if (abandon) {
            uint8_t cmd[2] = {0, 0}; /* data size = 0 */
            printf("Firmware Update Abandon:\n");
            /* Call cancel command directly - can't use wolfTPM2_FirmwareUpgradeCancel
             * because GetCapabilities also fails in upgrade mode */
            rc = TPM2_ST33_FieldUpgradeCommand(TPM_CC_FieldUpgradeAbandonVendor_ST33,
                cmd, sizeof(cmd));
            if (rc != 0) {
                printf("Abandon failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
                printf("Power cycle TPM to reset\n");
            }
            else {
                printf("Success: Please reset or power cycle TPM\n");
            }
            wolfTPM2_Cleanup(&dev);
            return rc;
        }
        if (fi_file != NULL) {
            /* Continue firmware update - TPM already in upgrade mode */
            printf("Continuing firmware update...\n");
            fwinfo.in_upgrade_mode = 1;
            /* Skip to firmware data loading, the start was already done */
            goto load_firmware;
        }
        printf("Use --abandon to cancel firmware upgrade, or power cycle TPM\n");
        goto exit;
    }
    else if (rc != TPM_RC_SUCCESS) {
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

    /* Two-state model: < 512 requires non-LMS (legacy firmware, e.g., 9.257),
     * >= 512 requires LMS (modern firmware, LMS required, e.g., 9.512) */
    if (caps.fwVerMinor < 512) {
        lms_state = 0;  /* Non-LMS path only (legacy firmware, Generation 1) */
    }
    else {
        lms_state = 1;  /* LMS path only (modern firmware, LMS required, Generation 2) */
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

    if (fi_file == NULL) {
        if (argc > 1) {
            printf("Firmware file argument missing!\n");
        }
        goto exit;
    }

    /* Handle LMS signature requirements (skip check in upgrade mode) */
    if (!fwinfo.in_upgrade_mode) {
        if (lms_state == 0) {
            /* Legacy firmware (< 512): reject LMS format */
            if (fwinfo.use_lms) {
                printf("\nError: LMS format specified but firmware "
                       "version < 512 requires non-LMS.\n");
                printf("This device (fwVerMinor < 512) must use "
                       "non-LMS firmware format.\n");
                rc = BAD_FUNC_ARG;
                goto exit;
            }
        }
        else {
            /* Modern firmware (>= 512): require LMS format */
            if (!fwinfo.use_lms) {
                printf("\nError: Firmware version >= 512 requires LMS format.\n");
                printf("Please use --lms option with LMS firmware file.\n");
                rc = BAD_FUNC_ARG;
                goto exit;
            }
        }
    }

load_firmware:
    /* Determine blob0 (manifest) size based on format */
    blob0_size = fwinfo.use_lms ? ST33_BLOB0_SIZE_LMS : ST33_BLOB0_SIZE_NON_LMS;

    /* Load the complete .fi file */
    rc = loadFile(fi_file, &fwinfo.fi_buf, &fwinfo.fi_bufSz);
    if (rc != 0) {
        printf("Failed to load firmware file: %s\n", fi_file);
        goto exit;
    }

    /* Validate file size */
    if (fwinfo.fi_bufSz <= blob0_size) {
        printf("Error: Firmware file too small. Expected > %zu bytes, got %zu bytes.\n",
            blob0_size, fwinfo.fi_bufSz);
        rc = BAD_FUNC_ARG;
        goto exit;
    }

    /* Split .fi file into manifest (blob0) and firmware data */
    fwinfo.manifest_buf = fwinfo.fi_buf;
    fwinfo.manifest_bufSz = blob0_size;
    fwinfo.firmware_buf = fwinfo.fi_buf + blob0_size;
    fwinfo.firmware_bufSz = fwinfo.fi_bufSz - blob0_size;

    printf("Firmware Update:\n");
    printf("\tTotal file size: %zu bytes\n", fwinfo.fi_bufSz);
    printf("\tManifest (blob0): %zu bytes\n", fwinfo.manifest_bufSz);
    printf("\tFirmware data: %zu bytes\n", fwinfo.firmware_bufSz);

    if (fwinfo.in_upgrade_mode) {
        /* Continuing from upgrade mode - just send firmware data */
        printf("Sending firmware data (TPM already in upgrade mode)...\n");
        rc = TPM2_ST33_SendFirmwareData(&fwinfo);
    }
    else if (fwinfo.use_lms) {
        /* LMS path - manifest contains embedded LMS signature */
        rc = wolfTPM2_FirmwareUpgradeWithLMS(&dev,
            fwinfo.manifest_buf, (uint32_t)fwinfo.manifest_bufSz,
            TPM2_ST33_FwData_Cb, &fwinfo,
            fwinfo.manifest_buf, (uint32_t)fwinfo.manifest_bufSz);
    }
    else {
        /* Non-LMS path */
        rc = wolfTPM2_FirmwareUpgrade(&dev,
            fwinfo.manifest_buf, (uint32_t)fwinfo.manifest_bufSz,
            TPM2_ST33_FwData_Cb, &fwinfo);
    }
    if (rc == 0) {
        printf("\nFirmware update completed successfully.\n");
        printf("Please reset or power cycle the TPM.\n");
        /* Get updated capabilities - may fail if still in special mode */
        rc = wolfTPM2_GetCapabilities(&dev, &caps);
        if (rc == 0) {
            TPM2_ST33_PrintInfo(&caps);
        }
        else {
            printf("Power cycle TPM to complete update.\n");
            rc = 0; /* Update was successful, just need power cycle */
        }
    }

exit:

    if (rc != 0) {
        printf("ST33 firmware update failed 0x%x: %s\n",
            rc, TPM2_GetRCString(rc));
    }

    /* Only free the main fi_buf - manifest_buf and firmware_buf point into it */
    XFREE(fwinfo.fi_buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
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

