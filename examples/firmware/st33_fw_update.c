/* st33_fw_update.c
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

/* This tool will perform a firmware update on STMicroelectronics ST33KTPM
 * TPM 2.0 module */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2_wrap.h>

/* wolfTPM2_FirmwareUpgrade_ex hashes the manifest with SHA-384, so it is only
 * built with wolfCrypt. This tool has no other way to drive an upgrade. */
#if defined(WOLFTPM_FIRMWARE_UPGRADE) && \
    (defined(WOLFTPM_ST33) || defined(WOLFTPM_AUTODETECT)) && \
    !defined(WOLFTPM2_NO_WOLFCRYPT)

#include <examples/firmware/firmware_policy.h>
#include <examples/tpm_test_keys.h>
#include <hal/tpm_io.h>

/* WOLFTPM_HAVE_FW_POLICY comes from firmware_policy.h, which owns the
 * condition so the two firmware examples cannot drift. */

/* Caller-supplied policy authorization modes */
#define ST33_POLICY_NONE     0 /* default password (TPM_RS_PW) auth */
#define ST33_POLICY_CMDCODE  1 /* --policy:   single PolicyCommandCode */
#define ST33_POLICY_OR       2 /* --policyor: multi-branch PolicyOR */

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
    printf("\t./st33_fw_update --policytest (safe policy auth self-test)\n");
    printf("\t./st33_fw_update [policy opts] <firmware.fi>\n");
    printf("\t./st33_fw_update <firmware.fi> (default password auth)\n");
    printf("Policy options (caller-supplied authorization):\n");
    printf("\t--policy    provision+satisfy a PolicyCommandCode\n");
    printf("\t--policyor  provision+satisfy a PolicyOR (multi-branch)\n");
    printf("\t--sha256|--sha384|--sha512  policy hash (default SHA-256)\n");
    printf("\nFirmware format is auto-detected from the TPM firmware version.\n");
    printf("Just provide the correct .fi file for your TPM and it will be handled automatically.\n");
}

typedef struct {
    byte*  fi_buf;         /* Full .fi file buffer */
    byte*  manifest_buf;   /* Points into fi_buf */
    byte*  firmware_buf;   /* Points into fi_buf */
    size_t fi_bufSz;
    size_t manifest_bufSz;
    size_t firmware_bufSz;
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

        if (blob_len > 2048) {
            printf("Error: Blob length %u exceeds maximum 2048 at offset %u\n",
                blob_len, offset);
            rc = BUFFER_E;
            break;
        }

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
    size_t blob0_size;
    int i;
#ifdef WOLFTPM_HAVE_FW_POLICY
    int policytest = 0;
    int policyMode = ST33_POLICY_NONE;
    TPMI_ALG_HASH policyHash = TPM_ALG_SHA256;
    WOLFTPM2_SESSION policySession;
    FirmwarePolicyCtx policyCtx;
    int clearRc;
#endif

    XMEMSET(&fwinfo, 0, sizeof(fwinfo));
    XMEMSET(&caps, 0, sizeof(caps));
#ifdef WOLFTPM_HAVE_FW_POLICY
    XMEMSET(&policySession, 0, sizeof(policySession));
    XMEMSET(&policyCtx, 0, sizeof(policyCtx));
#endif

    for (i = 1; i < argc; i++) {
        if (XSTRCMP(argv[i], "-?") == 0 ||
            XSTRCMP(argv[i], "-h") == 0 ||
            XSTRCMP(argv[i], "--help") == 0) {
            usage();
            return 0;
        }
        else if (XSTRCMP(argv[i], "--abandon") == 0) {
            abandon = 1;
        }
#ifdef WOLFTPM_HAVE_FW_POLICY
        else if (XSTRCMP(argv[i], "--policytest") == 0) {
            policytest = 1;
        }
        else if (XSTRCMP(argv[i], "--policy") == 0) {
            policyMode = ST33_POLICY_CMDCODE;
        }
        else if (XSTRCMP(argv[i], "--policyor") == 0) {
            policyMode = ST33_POLICY_OR;
        }
        else if (XSTRCMP(argv[i], "--sha256") == 0) {
            policyHash = TPM_ALG_SHA256;
        }
        else if (XSTRCMP(argv[i], "--sha384") == 0) {
            policyHash = TPM_ALG_SHA384;
        }
        else if (XSTRCMP(argv[i], "--sha512") == 0) {
            policyHash = TPM_ALG_SHA512;
        }
#endif /* WOLFTPM_HAVE_FW_POLICY */
        else if (argv[i][0] == '-') {
            printf("Unrecognized option: %s\n", argv[i]);
            usage();
            return BAD_FUNC_ARG;
        }
        else if (fi_file == NULL) {
            fi_file = argv[i];
        }
        else {
            printf("Unexpected extra argument: %s\n", argv[i]);
            usage();
            return BAD_FUNC_ARG;
        }
    }

    printf("ST33 Firmware Update Tool\n");
    if (fi_file != NULL) {
        printf("\tFirmware File: %s\n", fi_file);
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
        #ifdef WOLFTPM_HAVE_FW_POLICY
            /* FieldUpgradeStart already ran, so there is no command left for a
             * caller-supplied session to authorize. Continuing here would
             * silently downgrade to the default authorization - exactly what
             * these flags exist to make explicit - so refuse instead. */
            if (policyMode != ST33_POLICY_NONE || policytest) {
                printf("Cannot apply policy authorization: the TPM is already "
                       "in\n");
                printf("  firmware upgrade mode, so FieldUpgradeStart has "
                       "already run.\n");
                printf("  Re-run without --policy/--policyor/--policytest to "
                       "continue,\n");
                printf("  or --abandon and power cycle to start over.\n");
                rc = BAD_FUNC_ARG;
                goto exit;
            }
        #endif
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

#ifdef WOLFTPM_HAVE_FW_POLICY
    if (policytest) {
        /* Non-destructive validation of caller-supplied policy authorization.
         * Runs SHA2-256/384/512 PolicyOR digest checks (a hash the TPM does
         * not support is reported and skipped). Does not touch firmware
         * upgrade state. */
        rc = firmware_policy_selftest_all(&dev);
        wolfTPM2_Cleanup(&dev);
        return rc;
    }
#endif

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
        goto exit;
    }

    if (fi_file == NULL) {
        if (argc > 1) {
            printf("Firmware file argument missing!\n");
        }
        goto exit;
    }

load_firmware:
    /* Determine blob0 (manifest) size based on firmware version.
     * In upgrade mode (caps not available), auto-detect from file size. */
    if (fwinfo.in_upgrade_mode) {
        /* In upgrade mode, we don't have caps. Load file first to detect format. */
        rc = loadFile(fi_file, &fwinfo.fi_buf, &fwinfo.fi_bufSz);
        if (rc != 0) {
            printf("Failed to load firmware file: %s\n", fi_file);
            goto exit;
        }
        /* Auto-detect format from file size: LMS files are larger due to
         * 2697 byte manifest vs 177 byte manifest */
        if (fwinfo.fi_bufSz > ST33_BLOB0_SIZE_LMS + 1000) {
            /* File large enough to potentially be LMS format.
             * Check if blob header at LMS offset looks valid. */
            if (fwinfo.fi_buf[ST33_BLOB0_SIZE_LMS] != 0 &&
                fwinfo.fi_buf[ST33_BLOB0_SIZE_LMS] != 0xFF) {
                blob0_size = ST33_BLOB0_SIZE_LMS;
                printf("\tFormat: LMS (auto-detected from file)\n");
            }
            else {
                blob0_size = ST33_BLOB0_SIZE_NON_LMS;
                printf("\tFormat: Non-LMS (auto-detected from file)\n");
            }
        }
        else {
            blob0_size = ST33_BLOB0_SIZE_NON_LMS;
            printf("\tFormat: Non-LMS (auto-detected from file)\n");
        }
    }
    else {
        /* Normal mode: determine format from firmware version */
        blob0_size = (caps.fwVerMinor >= 512) ?
            ST33_BLOB0_SIZE_LMS : ST33_BLOB0_SIZE_NON_LMS;
        printf("\tFormat: %s (from TPM firmware version)\n",
            (caps.fwVerMinor >= 512) ? "LMS" : "Non-LMS");

        /* Load the complete .fi file */
        rc = loadFile(fi_file, &fwinfo.fi_buf, &fwinfo.fi_bufSz);
        if (rc != 0) {
            printf("Failed to load firmware file: %s\n", fi_file);
            goto exit;
        }
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
    else {
        WOLFTPM2_SESSION* startSess = NULL;
    #ifdef WOLFTPM_HAVE_FW_POLICY
        /* When a policy mode is requested, provision the platform authPolicy
         * and build a session that satisfies it, then drive the upgrade under
         * that caller-supplied session instead of the default password auth. */
        if (policyMode != ST33_POLICY_NONE) {
            rc = firmware_policy_session_setup(&dev, &policyCtx, policyHash,
                (policyMode == ST33_POLICY_OR),
                TPM_CC_FieldUpgradeStartVendor_ST33, &policySession);
            if (rc == 0) {
                printf("Using caller-supplied policy session\n");
                startSess = &policySession;
            }
        }
    #endif
        /* Normal mode - unified API auto-detects format from manifest size */
        if (rc == 0) {
            rc = wolfTPM2_FirmwareUpgrade_ex(&dev,
                fwinfo.manifest_buf, (uint32_t)fwinfo.manifest_bufSz,
                TPM2_ST33_FwData_Cb, &fwinfo, startSess);
        }
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

#ifdef WOLFTPM_HAVE_FW_POLICY
    /* On a successful start the TPM consumes the session and the library sets
     * handle.hndl to TPM_RH_NULL (0x40000007), which is non-zero - so this
     * guard does not distinguish consumed from live. It does not need to:
     * wolfTPM2_UnloadHandle is a no-op on TPM_RH_NULL, so the call only ever
     * flushes a session that is still loaded. */
    if (policySession.handle.hndl != 0) {
        wolfTPM2_UnloadHandle(&dev, &policySession.handle);
    }
    /* Clear the platform policy if the upgrade did not complete. Gated on
     * policyCtx.provisioned inside the helper, so an early failure cannot wipe
     * a policy this example never installed.
     *
     * Skip the attempt once the start has succeeded: the TPM consumed the
     * session (handle set to TPM_RH_NULL) and reset into firmware-upgrade
     * mode, where it will not service TPM2_SetPrimaryPolicy - and the
     * mandatory TPM reset clears the policy anyway. */
    if (rc != 0 && policySession.handle.hndl != TPM_RH_NULL) {
        clearRc = firmware_policy_clear(&dev, &policyCtx);
        /* Report a failed rollback, but never overwrite the upgrade error that
         * explains why this run failed - that rc is the process exit status
         * and the only machine-readable diagnostic a script sees. */
        if (clearRc != 0 && rc == 0) {
            rc = clearRc;
        }
    }
#endif
    /* Only free the main fi_buf - manifest_buf and firmware_buf point into it */
    XFREE(fwinfo.fi_buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    wolfTPM2_Cleanup(&dev);

    return rc;
}

/******************************************************************************/
/* --- END ST33 TPM2.0 Firmware Update tool  -- */
/******************************************************************************/
#endif /* WOLFTPM_FIRMWARE_UPGRADE && (WOLFTPM_ST33 || WOLFTPM_AUTODETECT) &&
        * !WOLFTPM2_NO_WOLFCRYPT */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = -1;

#if defined(WOLFTPM_FIRMWARE_UPGRADE) && \
    (defined(WOLFTPM_ST33) || defined(WOLFTPM_AUTODETECT)) && \
    !defined(WOLFTPM2_NO_WOLFCRYPT)
    rc = TPM2_ST33_Firmware_Update(NULL, argc, argv);
#else
    printf("Support for ST33 firmware upgrade not compiled in!\n"
        "See --enable-firmware or WOLFTPM_FIRMWARE_UPGRADE\n");
    printf("This tool is for the STMicroelectronics ST33KTPM TPMs only\n"
        "\t--enable-st33 (WOLFTPM_ST33)\n");
    printf("Firmware upgrade also requires wolfCrypt "
        "(not WOLFTPM2_NO_WOLFCRYPT)\n");
    (void)argc;
    (void)argv;
#endif

    return rc;
}
#endif /* !NO_MAIN_DRIVER */

