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
    printf("\t./st33_fw_update --policytest (safe policy auth self-test)\n");
    printf("\t./st33_fw_update <firmware.fi>\n");
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

/* Build a PolicyCommandCode branch digest offline. This matches the running
 * policy digest of a fresh policy session after wolfTPM2_PolicyCommandCode. */
static int BuildPolicyCommandCode(TPMI_ALG_HASH hashAlg,
    byte* digest, word32* digestSz, TPM_CC cc)
{
    byte val[4]; /* command code in big-endian, matching the TPM wire format */
    val[0] = (byte)((cc >> 24) & 0xFF);
    val[1] = (byte)((cc >> 16) & 0xFF);
    val[2] = (byte)((cc >> 8) & 0xFF);
    val[3] = (byte)(cc & 0xFF);
    return wolfTPM2_PolicyHash(hashAlg, digest, digestSz,
        TPM_CC_PolicyCommandCode, val, sizeof(val));
}

/* Non-destructive self-test for the caller-supplied policy authorization
 * added for firmware upgrade. Exercises wolfTPM2_PolicyOR at the requested
 * hash algorithm and verifies the TPM's running policy digest matches an
 * offline computation. This does NOT invoke FieldUpgradeStart and never
 * changes TPM state persistently, so it is safe to run on a live TPM.
 * Returns 0 on match. */
static int firmware_policy_selftest(WOLFTPM2_DEV* dev, TPMI_ALG_HASH hashAlg,
    const char* name)
{
    int rc;
    WOLFTPM2_SESSION sess;
    TPML_DIGEST orList;
    word32 hsz = (word32)TPM2_GetHashDigestSize(hashAlg);
    byte branchA[TPM_MAX_DIGEST_SIZE];
    byte branchB[TPM_MAX_DIGEST_SIZE];
    byte concat[2 * TPM_MAX_DIGEST_SIZE];
    byte expected[TPM_MAX_DIGEST_SIZE];
    byte got[TPM_MAX_DIGEST_SIZE];
    word32 aSz, bSz, expSz, gotSz;

    XMEMSET(&sess, 0, sizeof(sess));
    XMEMSET(&orList, 0, sizeof(orList));

    if (hsz == 0 || hsz > TPM_MAX_DIGEST_SIZE) {
        return BAD_FUNC_ARG;
    }

    /* Offline: two distinct PolicyCommandCode branch digests */
    XMEMSET(branchA, 0, sizeof(branchA));
    aSz = hsz;
    rc = BuildPolicyCommandCode(hashAlg, branchA, &aSz, TPM_CC_NV_Read);
    if (rc == 0) {
        XMEMSET(branchB, 0, sizeof(branchB));
        bSz = hsz;
        rc = BuildPolicyCommandCode(hashAlg, branchB, &bSz, TPM_CC_Unseal);
    }
    /* Offline PolicyOR digest = H(zeros || TPM_CC_PolicyOR || A || B) */
    if (rc == 0) {
        XMEMCPY(concat, branchA, aSz);
        XMEMCPY(&concat[aSz], branchB, bSz);
        XMEMSET(expected, 0, sizeof(expected));
        expSz = hsz;
        rc = wolfTPM2_PolicyHash(hashAlg, expected, &expSz,
            TPM_CC_PolicyOR, concat, aSz + bSz);
    }

    /* On-TPM: start a policy session using the requested hash algorithm */
    if (rc == 0) {
        rc = wolfTPM2_StartSession_ex(dev, &sess, NULL, NULL,
            TPM_SE_POLICY, TPM_ALG_NULL, hashAlg);
        if (rc != 0) {
            printf("  %s: StartSession failed 0x%x: %s\n",
                name, rc, TPM2_GetRCString(rc));
            return rc;
        }
    }
    /* Satisfy branch A, then OR against {A,B} with the new wrapper */
    if (rc == 0) {
        rc = wolfTPM2_PolicyCommandCode(dev, &sess, TPM_CC_NV_Read);
    }
    if (rc == 0) {
        orList.count = 2;
        orList.digests[0].size = (UINT16)aSz;
        XMEMCPY(orList.digests[0].buffer, branchA, aSz);
        orList.digests[1].size = (UINT16)bSz;
        XMEMCPY(orList.digests[1].buffer, branchB, bSz);
        rc = wolfTPM2_PolicyOR(dev, &sess, &orList);
    }
    if (rc == 0) {
        gotSz = (word32)sizeof(got);
        rc = wolfTPM2_GetPolicyDigest(dev, sess.handle.hndl, got, &gotSz);
    }

    if (rc == 0) {
        if (gotSz == expSz && XMEMCMP(got, expected, expSz) == 0) {
            printf("  %s PolicyOR: PASS (%u byte digest matches)\n",
                name, expSz);
        }
        else {
            printf("  %s PolicyOR: FAIL (digest mismatch)\n", name);
            printf("    expected: ");
            TPM2_PrintBin(expected, expSz);
            printf("    got:      ");
            TPM2_PrintBin(got, gotSz);
            rc = -1;
        }
    }
    else {
        printf("  %s PolicyOR: ERROR 0x%x: %s\n",
            name, rc, TPM2_GetRCString(rc));
    }

    wolfTPM2_UnloadHandle(dev, &sess.handle);
    return rc;
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
    int policytest = 0;
    size_t blob0_size;

    XMEMSET(&fwinfo, 0, sizeof(fwinfo));
    XMEMSET(&caps, 0, sizeof(caps));

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
        else if (XSTRCMP(argv[1], "--policytest") == 0) {
            policytest = 1;
        }
        else {
            fi_file = argv[1];
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

    if (policytest) {
        /* Non-destructive validation of caller-supplied policy authorization.
         * Runs SHA2-256 (non-PQC) and SHA2-512 (PQC) PolicyOR digest checks.
         * Does not touch firmware upgrade state. */
        int rc256, rc512;
        printf("Firmware policy authorization self-test (no firmware changes):\n");
        rc256 = firmware_policy_selftest(&dev, TPM_ALG_SHA256, "SHA2-256");
        rc512 = firmware_policy_selftest(&dev, TPM_ALG_SHA512, "SHA2-512");
        if (rc512 != 0) {
            printf("  Note: a SHA2-512 failure may mean this TPM firmware does"
                   " not support SHA2-512 policy sessions.\n");
        }
        rc = (rc256 == 0) ? rc512 : rc256;
        wolfTPM2_Cleanup(&dev);
        return rc;
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
        /* Normal mode - use unified API which auto-detects format from manifest size */
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

