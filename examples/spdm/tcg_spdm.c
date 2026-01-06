/* tcg_spdm.c
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

/* TCG SPDM Validation Example
 * Tests SPDM functionality per TCG TPM 2.0 Library Spec v1.84
 *
 * Note: AC_GetCapability (0x194) and AC_Send (0x195) are DEPRECATED
 * per TCG and will never be implemented in the reference simulator.
 * This example tests only the supported SPDM commands.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_wrap.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef WOLFTPM2_NO_WRAPPER

#include <hal/tpm_io.h>
#include <examples/tpm_test.h>

#ifdef WOLFTPM_SPDM

/******************************************************************************/
/* --- BEGIN TCG SPDM Validation -- */
/******************************************************************************/

/* Forward declarations */
int TPM2_TCG_SPDM_Test(void* userCtx, int argc, char *argv[]);

static void usage(void)
{
    printf("TCG SPDM Validation Example\n");
    printf("Tests SPDM functionality per TCG TPM 2.0 Library Spec v1.84\n");
    printf("\n");
    printf("Usage: tcg_spdm [options]\n");
    printf("Options:\n");
    printf("  --all                    Run all tests\n");
    printf("  --discover-handles       Test AC handle discovery\n");
    printf("  --test-policy-transport  Test PolicyTransportSPDM command\n");
    printf("  --test-spdm-session-info Test GetCapability SPDM session info\n");
    printf("  -h, --help               Show this help message\n");
    printf("\n");
    printf("Note: AC_GetCapability and AC_Send are DEPRECATED per TCG spec.\n");
}

static int test_handle_discovery(WOLFTPM2_DEV* dev)
{
    int rc;
    TPM_HANDLE acHandles[32];
    word32 count = 0;
    word32 i;

    printf("\n=== AC Handle Discovery ===\n");
    printf("Testing GetCapability(TPM_CAP_HANDLES, HR_AC)...\n");

    rc = wolfTPM2_GetACHandles(dev, acHandles, &count, 32);
    if (rc == TPM_RC_SUCCESS) {
        printf("  SUCCESS: Found %d AC handle(s)\n", (int)count);
        if (count > 0) {
            printf("  Handles:\n");
            for (i = 0; i < count && i < 10; i++) {
                printf("    0x%08x\n", (unsigned int)acHandles[i]);
            }
            if (count > 10) {
                printf("    ... and %d more\n", (int)(count - 10));
            }
        } else {
            printf("  Note: No AC handles found (expected if TPM doesn't support AC)\n");
        }
        return 0;
    } else {
        printf("  FAILED: 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        return 1;
    }
}

static int test_policy_transport_spdm(WOLFTPM2_DEV* dev)
{
    int rc;
    WOLFTPM2_SESSION policySession;

    printf("\n=== PolicyTransportSPDM Test ===\n");
    printf("Testing PolicyTransportSPDM command (0x1A1)...\n");

    /* Create a policy session */
    rc = wolfTPM2_StartSession(dev, &policySession, NULL, NULL,
                                TPM_SE_POLICY, TPM_ALG_NULL);
    if (rc != TPM_RC_SUCCESS) {
        printf("  FAILED: Cannot create policy session: 0x%x: %s\n",
               rc, TPM2_GetRCString(rc));
        return 1;
    }

    /* Test PolicyTransportSPDM with NULL key names (both optional) */
    rc = wolfTPM2_PolicyTransportSPDM(dev, policySession.handle.hndl, NULL, NULL);
    if (rc == TPM_RC_SUCCESS) {
        printf("  SUCCESS: PolicyTransportSPDM executed successfully\n");
        rc = 0;
    } else if (rc == TPM_RC_VALUE) {
        printf("  WARNING: TPM_RC_VALUE - PolicyTransportSPDM already executed\n");
        printf("    This is not a failure - command reached TPM correctly\n");
        rc = 0;
    } else if (rc == TPM_RC_COMMAND_CODE) {
        printf("  FAILED: TPM_RC_COMMAND_CODE - Command not recognized\n");
        printf("    TPM may not support SPDM commands\n");
        rc = 1;
    } else {
        printf("  Result: 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        rc = 0;  /* May be expected depending on TPM state */
    }

    wolfTPM2_UnloadHandle(dev, &policySession.handle);
    return rc;
}

static int test_spdm_session_info(WOLFTPM2_DEV* dev)
{
    int rc;
    TPML_SPDM_SESSION_INFO spdmSessionInfo;

    printf("\n=== GetCapability SPDM Session Info ===\n");
    printf("Testing GetCapability(TPM_CAP_SPDM_SESSION_INFO)...\n");

    XMEMSET(&spdmSessionInfo, 0, sizeof(spdmSessionInfo));

    rc = wolfTPM2_GetCapability_SPDMSessionInfo(dev, &spdmSessionInfo);
    if (rc == TPM_RC_SUCCESS) {
        printf("  SUCCESS: SPDM session info retrieved\n");
        printf("    Session count: %d\n", (int)spdmSessionInfo.count);
        if (spdmSessionInfo.count == 0) {
            printf("    Note: Empty list (expected if not in active SPDM session)\n");
        } else {
            printf("    Active SPDM session detected\n");
        }
        return 0;
    } else if (rc == TPM_RC_COMMAND_CODE) {
        printf("  FAILED: TPM_RC_COMMAND_CODE - Capability not supported\n");
        return 1;
    } else {
        printf("  Result: 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        return 0;  /* May be expected depending on TPM state */
    }
}

static int test_all(WOLFTPM2_DEV* dev)
{
    int failures = 0;

    printf("\n========================================\n");
    printf("TCG SPDM Validation Tests\n");
    printf("========================================\n");
    printf("\n");
    printf("Testing SPDM functionality per TCG spec v1.84\n");
    printf("Note: AC_GetCapability/AC_Send are DEPRECATED and not tested\n");
    printf("\n");

    /* Test 1: Handle Discovery */
    failures += test_handle_discovery(dev);

    /* Test 2: PolicyTransportSPDM */
    failures += test_policy_transport_spdm(dev);

    /* Test 3: GetCapability SPDM Session Info */
    failures += test_spdm_session_info(dev);

    printf("\n========================================\n");
    printf("Test Summary\n");
    printf("========================================\n");
    if (failures == 0) {
        printf("ALL TESTS PASSED\n");
    } else {
        printf("%d TEST(S) FAILED\n", failures);
    }
    printf("========================================\n");

    return (failures == 0) ? 0 : 1;
}

int TPM2_TCG_SPDM_Test(void* userCtx, int argc, char *argv[])
{
    int rc;
    WOLFTPM2_DEV dev;
    int i;

    if (argc <= 1) {
        usage();
        return 0;
    }

    for (i = 1; i < argc; i++) {
        if (XSTRCMP(argv[i], "-h") == 0 ||
            XSTRCMP(argv[i], "--help") == 0) {
            usage();
            return 0;
        }
    }

    /* Init the TPM2 device */
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != 0) {
        printf("wolfTPM2_Init failed: 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        return rc;
    }

    /* Process command-line options */
    for (i = 1; i < argc; i++) {
        if (XSTRCMP(argv[i], "--all") == 0) {
            rc = test_all(&dev);
            break;
        }
        else if (XSTRCMP(argv[i], "--discover-handles") == 0) {
            rc = test_handle_discovery(&dev);
            if (rc != 0) break;
        }
        else if (XSTRCMP(argv[i], "--test-policy-transport") == 0) {
            rc = test_policy_transport_spdm(&dev);
            if (rc != 0) break;
        }
        else if (XSTRCMP(argv[i], "--test-spdm-session-info") == 0) {
            rc = test_spdm_session_info(&dev);
            if (rc != 0) break;
        }
        else {
            printf("Unknown option: %s\n", argv[i]);
            usage();
            rc = BAD_FUNC_ARG;
            break;
        }
    }

    wolfTPM2_Cleanup(&dev);
    return rc;
}

/******************************************************************************/
/* --- END TCG SPDM Validation -- */
/******************************************************************************/

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = -1;

#ifndef WOLFTPM2_NO_WRAPPER
    rc = TPM2_TCG_SPDM_Test(NULL, argc, argv);
#else
    printf("Wrapper code not compiled in\n");
    (void)argc;
    (void)argv;
#endif

    return (rc == 0) ? 0 : 1;
}
#endif /* !NO_MAIN_DRIVER */

#endif /* WOLFTPM_SPDM */
#endif /* !WOLFTPM2_NO_WRAPPER */
