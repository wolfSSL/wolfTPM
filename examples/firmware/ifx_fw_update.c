/* ifx_fw_update.c
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

/* This tool will perform a firmware update on Infineon SLB9672 or SLB9673
 * TPM 2.0 module */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2_wrap.h>

#if defined(WOLFTPM_FIRMWARE_UPGRADE) && \
    (defined(WOLFTPM_SLB9672) || defined(WOLFTPM_SLB9673))

#include <examples/firmware/ifx_fw_update.h>
#include <examples/firmware/firmware_policy.h>
#include <examples/tpm_test_keys.h>
#include <hal/tpm_io.h>

/* The caller-supplied policy helpers require wolfCrypt (policy digest hashing) */
#ifndef WOLFTPM2_NO_WOLFCRYPT
    #define HAVE_FW_POLICY
#endif

/* Caller-supplied policy authorization modes */
#define IFX_POLICY_NONE     0 /* library-managed authorization */
#define IFX_POLICY_CMDCODE  1 /* --policy:   single PolicyCommandCode */
#define IFX_POLICY_OR       2 /* --policyor: multi-branch PolicyOR */

/* Infineon operational modes (subset used here) */
#define IFX_OPMODE_NORMAL   0x00 /* normal; FieldUpgradeStart reached */
#define IFX_OPMODE_FINALIZE 0x03 /* update done, finalize only */

/******************************************************************************/
/* --- BEGIN TPM2.0 Firmware Update tool  -- */
/******************************************************************************/

static void usage(void)
{
    printf("Infineon Firmware Update Usage:\n");
    printf("\t./ifx_fw_update (get info)\n");
    printf("\t./ifx_fw_update --abandon (cancel)\n");
    printf("\t./ifx_fw_update --policytest (safe policy auth self-test)\n");
    printf("\t./ifx_fw_update [policy opts] <manifest_file> <firmware_file>\n");
    printf("\t./ifx_fw_update <manifest_file> <firmware_file> "
           "(default auth)\n");
    printf("Policy options (caller-supplied authorization):\n");
    printf("\t--policy    provision+satisfy a PolicyCommandCode\n");
    printf("\t--policyor  provision+satisfy a PolicyOR (multi-branch)\n");
    printf("\t--sha256|--sha384|--sha512  policy hash (default SHA-256)\n");
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

static const char* TPM2_IFX_GetOpModeStr(int opMode)
{
    const char* opModeStr = "Unknown";
    switch (opMode) {
        case 0x00:
            opModeStr = "Normal TPM operational mode";
            break;
        case 0x01:
            opModeStr = "TPM firmware update mode (abandon possible)";
            break;
        case 0x02:
            opModeStr = "TPM firmware update mode (abandon not possible)";
            break;
        case 0x03:
            opModeStr = "After successful update, but before finalize";
            break;
        case 0x04:
            opModeStr = "After finalize or abandon, reboot required";
            break;
        default:
            break;
    }
    return opModeStr;
}

static void TPM2_IFX_PrintInfo(WOLFTPM2_CAPS* caps)
{
    printf("Mfg %s (%d), Vendor %s, Fw %u.%u (0x%x)\n",
        caps->mfgStr, caps->mfg, caps->vendorStr, caps->fwVerMajor,
        caps->fwVerMinor, caps->fwVerVendor);
    printf("Operational mode: %s (0x%x)\n",
        TPM2_IFX_GetOpModeStr(caps->opMode), caps->opMode);
    printf("KeyGroupId 0x%x, FwCounter %d (%d same)\n",
        caps->keyGroupId, caps->fwCounter, caps->fwCounterSame);
}

int TPM2_IFX_Firmware_Update(void* userCtx, int argc, char *argv[])
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_CAPS caps;
    const char* manifest_file = NULL;
    const char* firmware_file = NULL;
    fw_info_t fwinfo;
    int abandon = 0, recovery = 0;
    int i;
#ifdef HAVE_FW_POLICY
    int policytest = 0;
    int policyMode = IFX_POLICY_NONE;
    TPMI_ALG_HASH policyHash = TPM_ALG_SHA256;
    WOLFTPM2_SESSION policySession;
#endif

    XMEMSET(&fwinfo, 0, sizeof(fwinfo));
#ifdef HAVE_FW_POLICY
    XMEMSET(&policySession, 0, sizeof(policySession));
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
#ifdef HAVE_FW_POLICY
        else if (XSTRCMP(argv[i], "--policytest") == 0) {
            policytest = 1;
        }
        else if (XSTRCMP(argv[i], "--policy") == 0) {
            policyMode = IFX_POLICY_CMDCODE;
        }
        else if (XSTRCMP(argv[i], "--policyor") == 0) {
            policyMode = IFX_POLICY_OR;
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
#endif /* HAVE_FW_POLICY */
        else if (argv[i][0] == '-') {
            printf("Unrecognized option: %s\n", argv[i]);
            usage();
            return BAD_FUNC_ARG;
        }
        else if (manifest_file == NULL) {
            manifest_file = argv[i];
        }
        else if (firmware_file == NULL) {
            firmware_file = argv[i];
        }
        else {
            printf("Unexpected extra argument: %s\n", argv[i]);
            usage();
            return BAD_FUNC_ARG;
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

#ifdef HAVE_FW_POLICY
    if (policytest) {
        /* Non-destructive validation of caller-supplied policy authorization.
         * Does not touch firmware upgrade state. */
        rc = firmware_policy_selftest_all(&dev);
        wolfTPM2_Cleanup(&dev);
        return rc;
    }
#endif

    rc = wolfTPM2_GetCapabilities(&dev, &caps);
    if (rc != TPM_RC_SUCCESS) {
        goto exit;
    }
    TPM2_IFX_PrintInfo(&caps);
    if (caps.keyGroupId == 0) {
        printf("Error getting key group id from TPM!\n");
    }
    if (caps.opMode == 0x02 || (caps.opMode & 0x80)) {
        /* if opmode == 2 or 0x8x then we need to use recovery mode */
        recovery = 1;
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

    if (manifest_file == NULL || firmware_file == NULL) {
        if (argc > 1) {
            printf("Manifest file or firmware file arguments missing!\n");
        }
        goto exit;
    }

    /* load manifest and data files */
    rc = loadFile(manifest_file,
        &fwinfo.manifest_buf, &fwinfo.manifest_bufSz);
    if (rc == 0) {
        rc = loadFile(firmware_file,
            &fwinfo.firmware_buf, &fwinfo.firmware_bufSz);
    }
#ifdef HAVE_FW_POLICY
    /* When a policy mode is requested, provision the platform authPolicy and
     * build a session that satisfies it, then drive the upgrade under that
     * caller-supplied session instead of the library-managed authorization. */
    if (rc == 0 && policyMode != IFX_POLICY_NONE) {
        rc = firmware_policy_session_setup(&dev, policyHash,
            (policyMode == IFX_POLICY_OR), TPM_CC_FieldUpgradeStartVendor,
            &policySession);
    }
#endif
    if (rc == 0) {
        WOLFTPM2_SESSION* startSess = NULL;
    #ifdef HAVE_FW_POLICY
        if (policyMode != IFX_POLICY_NONE) {
            startSess = &policySession;
        }
    #endif
        if (recovery) {
            printf("Firmware Update (recovery mode%s):\n",
                startSess ? ", caller policy" : "");
            rc = wolfTPM2_FirmwareUpgradeRecover_ex(&dev,
                fwinfo.manifest_buf, (uint32_t)fwinfo.manifest_bufSz,
                TPM2_IFX_FwData_Cb, &fwinfo, startSess);
        }
        else {
            printf("Firmware Update (normal mode%s):\n",
                startSess ? ", caller policy" : "");
            rc = wolfTPM2_FirmwareUpgrade_ex(&dev,
                fwinfo.manifest_buf, (uint32_t)fwinfo.manifest_bufSz,
                TPM2_IFX_FwData_Cb, &fwinfo, startSess);
        }
    }
    if (rc == 0) {
        TPM2_IFX_PrintInfo(&caps);
    }

exit:

    if (rc != 0) {
        printf("Infineon firmware update failed 0x%x: %s\n",
            rc, TPM2_GetRCString(rc));
    }

#ifdef HAVE_FW_POLICY
    if (policyMode != IFX_POLICY_NONE) {
        /* The library zeroes the session handle when the TPM consumes it on a
         * successful start; a non-zero handle means it was not consumed. */
        if (policySession.handle.hndl != 0) {
            wolfTPM2_UnloadHandle(&dev, &policySession.handle);
        }
        /* Clear a provisioned platform policy if the upgrade did not complete */
        if (rc != 0) {
            firmware_policy_clear(&dev);
        }
    }
#endif
    XFREE(fwinfo.firmware_buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(fwinfo.manifest_buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    wolfTPM2_Cleanup(&dev);

    return rc;
}

/******************************************************************************/
/* --- END TPM2.0 Firmware Update tool  -- */
/******************************************************************************/
#endif /* WOLFTPM_FIRMWARE_UPGRADE && (WOLFTPM_SLB9672 || WOLFTPM_SLB9673) */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = -1;

#if defined(WOLFTPM_FIRMWARE_UPGRADE) && \
    (defined(WOLFTPM_SLB9672) || defined(WOLFTPM_SLB9673))
    rc = TPM2_IFX_Firmware_Update(NULL, argc, argv);
#else
    printf("Support for firmware upgrade not compiled in!\n"
        "See --enable-firmware or WOLFTPM_FIRMWARE_UPGRADE\n");
    printf("This tool is for the Infineon SLB9672 or SLB9673 TPMs only\n"
        "\t--enable-infineon=slb9672 (WOLFTPM_SLB9672)\n"
        "\t--enable-infineon=slb9673 --enable-i2c (WOLFTPM_SLB9673)\n");
    (void)argc;
    (void)argv;
#endif

    return rc;
}
#endif /* !NO_MAIN_DRIVER */
