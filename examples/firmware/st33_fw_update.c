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
#include <examples/firmware/st33_blob0.h>
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
    printf("\nFirmware format is auto-detected from TPM firmware version "
        "and the file:\n");
    printf("      - Generation 1 (e.g. 1.771): Non-LMS format "
        "(321 byte manifest)\n");
    printf("      - Generation 9 below 512: Non-LMS format "
        "(177 byte manifest)\n");
    printf("      - Generation 9 at 512 and above: LMS format "
        "(2697 byte manifest)\n");
    printf("\nThe field upgrade command codes come from the TPM: its "
        "TPM_CAP_COMMANDS list\nsays whether it implements the standard TPM "
        "codes or the ST33KTPM vendor\ncodes. Only when that does not settle "
        "it, as in firmware upgrade mode, is\nST's version rule used - the "
        "standard codes when the running firmware minor\nversion is below 256 "
        "or the image targets generation 2.\n");
}

/* Field upgrade command codes come from the library, so the codes this tool
 * reports, and binds a PolicyCommandCode to, are the ones that will be sent.
 * In firmware upgrade mode the capabilities cannot be read, so caps is passed
 * as NULL and the image's own target version decides. Returns 1 when the TPM
 * decided, 0 when the codes came from the firmware version rule. */
static int TPM2_ST33_PickOrdinals(const WOLFTPM2_CAPS* caps, int haveCaps,
    word16 manifestMajor, TPM_CC* ccStart, TPM_CC* ccData)
{
    int fromTpm = 0;

    (void)wolfTPM2_ST33_GetFwUpgradeCommands(haveCaps ? caps : NULL,
        manifestMajor, ccStart, ccData, &fromTpm);
    return fromTpm;
}

/* ST33 vendor product information. Two parts of the same model and firmware
 * revision are otherwise indistinguishable over the standard capabilities, so
 * this is what tells one physical unit from another. Read-only.
 * Layout per TPM2_GetProductInfo: serial 7B, pad 1B, Product ID (PIN) 2B,
 * Master Product ID (MPIN) 2B, internal revision 1B, pad 3B, kernel ver 4B. */
static void TPM2_ST33_PrintProductInfo(void)
{
    uint8_t info[20];
    int rc, i;

    XMEMSET(info, 0, sizeof(info));
    rc = TPM2_GetProductInfo(info, (uint16_t)sizeof(info));
    if (rc != TPM_RC_SUCCESS) {
        printf("Product info: unavailable (0x%x: %s)\n", rc,
            TPM2_GetRCString(rc));
        return;
    }
    printf("Serial:");
    for (i = 0; i < 7; i++) {
        printf(" %02x", info[i]);
    }
    printf("\n");
    printf("Product ID (PIN) 0x%02x%02x, Master (MPIN) 0x%02x%02x, "
        "internal rev 0x%02x\n", info[8], info[9], info[10], info[11],
        info[12]);
    printf("Firmware kernel version: %02x %02x %02x %02x\n",
        info[16], info[17], info[18], info[19]);
}

/* Print which of the four field upgrade command codes this part implements.
 * Purely diagnostic - it changes no TPM state and drives no upgrade. */
static void TPM2_ST33_PrintCommandSet(void)
{
    static const TPM_CC fuCmds[4] = {
        TPM_CC_FieldUpgradeStart,
        TPM_CC_FieldUpgradeData,
        TPM_CC_FieldUpgradeStartVendor_ST33,
        TPM_CC_FieldUpgradeDataVendor_ST33
    };
    static const char* fuNames[4] = {
        "FieldUpgradeStart       (standard)",
        "FieldUpgradeData        (standard)",
        "FieldUpgradeStartVendor (ST33KTPM)",
        "FieldUpgradeDataVendor  (ST33KTPM)"
    };
    int i, isImpl, rc;

    printf("Field upgrade command set:\n");
    for (i = 0; i < 4; i++) {
        rc = wolfTPM2_ST33_CmdImplemented(fuCmds[i], &isImpl);
        if (rc != TPM_RC_SUCCESS) {
            printf("\t0x%08x %s: query failed 0x%x: %s\n",
                (unsigned int)fuCmds[i], fuNames[i], rc, TPM2_GetRCString(rc));
        }
        else {
            printf("\t0x%08x %s: %s\n", (unsigned int)fuCmds[i], fuNames[i],
                isImpl ? "implemented" : "not implemented");
        }
    }
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
/* The other half of the pair, for the resume-path retry below */
static TPM_CC TPM2_ST33_AltDataCmd(TPM_CC ccData)
{
    return (ccData == TPM_CC_FieldUpgradeDataVendor_ST33) ?
        (TPM_CC)TPM_CC_FieldUpgradeData :
        (TPM_CC)TPM_CC_FieldUpgradeDataVendor_ST33;
}

static int TPM2_ST33_SendFirmwareData(fw_info_t* fwinfo, TPM_CC ccData,
    int ccFromTpm)
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
        rc = TPM2_ST33_FieldUpgradeCommand(ccData, blob_buf, blob_total);
        /* Resuming into a TPM already in upgrade mode, the running firmware
         * version cannot be read, so the code may have been inferred from the
         * image alone. The TPM ignores a command code it does not implement,
         * so the first blob can safely be re-sent with the other pair rather
         * than forcing an --abandon and a full restart. */
        if (rc == TPM_RC_COMMAND_CODE && blob_count == 0 && !ccFromTpm) {
            ccData = TPM2_ST33_AltDataCmd(ccData);
            printf("FieldUpgradeData rejected, retrying with 0x%08x\n",
                (unsigned int)ccData);
            rc = TPM2_ST33_FieldUpgradeCommand(ccData, blob_buf, blob_total);
        }
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

/* The firmware major version tracks the part and interface line. ST33TPHF2X
 * parts report a binary vendor string, so the name never comes from
 * TPM_PT_VENDOR_STRING_1..4 the way it does on an ST33KTPM. */
static const char* TPM2_ST33_PartLine(word16 fwVerMajor)
{
    switch (fwVerMajor) {
        case 1:  return "ST33TPHF2X (SPI firmware line)";
        case 2:  return "ST33TPHF2X (I2C firmware line)";
        case 74: return "ST33TPHF2X (older firmware line)";
        case 9:  return "ST33KTPM2X";
        case 10: return "ST33KTPM2A";
        /* Named for display only, and left out of the family classifiers */
        case 11: return "ST33KTPMQ";
        default: return "unrecognized ST33 firmware line";
    }
}

static void TPM2_ST33_PrintInfo(const WOLFTPM2_CAPS* caps)
{
    size_t i;
    size_t expected;

    printf("Mfg %s (%d), Vendor %s, Fw %u.%u (0x%x)\n",
        caps->mfgStr, caps->mfg, caps->vendorStr, caps->fwVerMajor,
        caps->fwVerMinor, caps->fwVerVendor);
    /* The vendor string is binary on ST33TPHF2X, so %s above shows nothing.
     * Print the raw bytes too, they are part of the device identity. */
    printf("Vendor string bytes:");
    for (i = 0; i < sizeof(caps->vendorStr) - 1; i++) {
        printf(" %02x", (unsigned char)caps->vendorStr[i]);
    }
    printf("\n");
    printf("Firmware version details: Major=%u, Minor=%u, Vendor=0x%x\n",
        caps->fwVerMajor, caps->fwVerMinor, caps->fwVerVendor);
    printf("Part line: %s\n", TPM2_ST33_PartLine(caps->fwVerMajor));
    expected = st33_expected_blob0(caps->fwVerMajor, caps->fwVerMinor);
    if (expected == 0) {
        printf("Firmware update: manifest size unknown for this firmware "
            "line, taken from the image\n");
    }
    else {
        printf("Firmware update: %s format required (%zu byte manifest)\n",
            (expected == ST33_BLOB0_SIZE_LMS) ? "LMS" : "Non-LMS", expected);
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
    size_t cand[ST33_BLOB0_SIZE_CNT];
    size_t candCnt;
    word16 manifestMajor = 0, manifestMinor = 0;
    TPM_CC ccStart = TPM_CC_FieldUpgradeStartVendor_ST33;
    TPM_CC ccData = TPM_CC_FieldUpgradeDataVendor_ST33;
    int ccFromTpm = 0;
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

    /* ST33 specific, so only meaningful once the manufacturer is confirmed */
    TPM2_ST33_PrintProductInfo();
    TPM2_ST33_PrintCommandSet();

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
    /* Load the complete .fi file, then determine the blob0 (manifest) size.
     * In upgrade mode caps are unavailable, so no size is preferred and the
     * block chain alone decides. */
    rc = loadFile(fi_file, &fwinfo.fi_buf, &fwinfo.fi_bufSz);
    if (rc != 0) {
        printf("Failed to load firmware file: %s\n", fi_file);
        goto exit;
    }

    candCnt = st33_blob0_candidates(caps.fwVerMajor, caps.fwVerMinor,
        !fwinfo.in_upgrade_mode, cand);

    blob0_size = st33_detect_blob0(fwinfo.fi_buf, fwinfo.fi_bufSz, cand,
        candCnt);
    if (blob0_size == 0) {
        printf("Error: could not determine the manifest (blob0) size of %s\n",
            fi_file);
        printf("  The %zu byte file does not parse as an ST33 firmware image "
            "with a\n  %d, %d or %d byte manifest.\n", fwinfo.fi_bufSz,
            ST33_BLOB0_SIZE_NON_LMS_RSA, ST33_BLOB0_SIZE_NON_LMS,
            ST33_BLOB0_SIZE_LMS);
        rc = BAD_FUNC_ARG;
        goto exit;
    }
    printf("\tFormat: %s (blob0 %zu bytes, verified against the block "
        "chain)\n",
        (blob0_size == ST33_BLOB0_SIZE_LMS) ? "LMS" : "Non-LMS", blob0_size);

    /* The file parsed, but at a size this TPM will not accept. Say so here:
     * the library rejects it too, but only with a DEBUG_WOLFTPM diagnostic,
     * so on a release build the operator would see a bare error code. */
    if (!fwinfo.in_upgrade_mode &&
            st33_expected_blob0(caps.fwVerMajor, caps.fwVerMinor) != 0 &&
            blob0_size != cand[0]) {
        printf("Error: %s is for a different ST33 generation.\n", fi_file);
        printf("  Its manifest is %zu bytes, but firmware %u.%u running on "
            "this TPM\n  expects %zu bytes. Use the .fi file for this part.\n",
            blob0_size, caps.fwVerMajor, caps.fwVerMinor, cand[0]);
        rc = BAD_FUNC_ARG;
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

    /* The manifest carries the firmware line it upgrades, which together with
     * the running version selects the field upgrade command codes. */
    if (wolfTPM2_ST33_ManifestVersion(fwinfo.manifest_buf,
            (uint32_t)fwinfo.manifest_bufSz, &manifestMajor,
            &manifestMinor) != TPM_RC_SUCCESS) {
        printf("Error: manifest too small to hold a version header\n");
        rc = BAD_FUNC_ARG;
        goto exit;
    }
    ccFromTpm = TPM2_ST33_PickOrdinals(&caps, !fwinfo.in_upgrade_mode,
        manifestMajor, &ccStart, &ccData);

    printf("Firmware Update:\n");
    printf("\tTotal file size: %zu bytes\n", fwinfo.fi_bufSz);
    printf("\tManifest (blob0): %zu bytes\n", fwinfo.manifest_bufSz);
    printf("\tFirmware data: %zu bytes\n", fwinfo.firmware_bufSz);
    printf("\tImage targets firmware: %u.%u (%s)\n", manifestMajor,
        manifestMinor, TPM2_ST33_PartLine(manifestMajor));
    printf("\tCommand codes: start 0x%08x, data 0x%08x (%s)\n",
        (unsigned int)ccStart, (unsigned int)ccData,
        ccFromTpm ? "from TPM_CAP_COMMANDS" :
            "inferred from the firmware version");

    if (fwinfo.in_upgrade_mode) {
        /* Continuing from upgrade mode - just send firmware data */
        printf("Sending firmware data (TPM already in upgrade mode)...\n");
        rc = TPM2_ST33_SendFirmwareData(&fwinfo, ccData, ccFromTpm);
    }
    else {
        WOLFTPM2_SESSION* startSess = NULL;
    #ifdef WOLFTPM_HAVE_FW_POLICY
        /* When a policy mode is requested, provision the platform authPolicy
         * and build a session that satisfies it, then drive the upgrade under
         * that caller-supplied session instead of the default password auth. */
        if (policyMode != ST33_POLICY_NONE) {
            rc = firmware_policy_session_setup(&dev, &policyCtx, policyHash,
                (policyMode == ST33_POLICY_OR), ccStart, &policySession);
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

