/* allocate.c
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

/* This is a helper tool for inspecting and changing the TPM's PCR banks */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2_wrap.h>

#ifndef WOLFTPM2_NO_WRAPPER

#include <examples/pcr/pcr.h>
#include <hal/tpm_io.h>
#include <examples/tpm_test.h>

#include <stdio.h>

/******************************************************************************/
/* --- BEGIN TPM2.0 PCR Allocate example tool  -- */
/******************************************************************************/

/* Names for the banks a TPM commonly reports; anything else prints as hex. */
static const char* bank_name(TPM_ALG_ID alg)
{
    switch (alg) {
        case TPM_ALG_SHA1:   return "SHA-1";
        case TPM_ALG_SHA256: return "SHA-256";
        case TPM_ALG_SHA384: return "SHA-384";
        case TPM_ALG_SHA512: return "SHA-512";
        default:             return NULL;
    }
}

static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/pcr/allocate [-sha1] [-sha256] [-sha384] [-sha512]\n");
    printf("                        [-restore]\n");
    printf("* no algorithm flags: report the current allocation and exit\n");
    printf("* -shaN: include that bank in the new allocation (repeatable)\n");
    printf("* -restore: put the original selection back before exiting\n");
    printf("Demo usage without parameters, reports the PCR banks.\n");
    printf("\n");
    printf("WARNING: the algorithm flags REPLACE the allocation. Banks not\n");
    printf("named are deallocated, every PolicyPCR digest changes, and blobs\n");
    printf("sealed to PCR values become unsealable. Many TPMs support only\n");
    printf("one active bank at a time.\n");
    printf("\n");
    printf("The new allocation takes effect at the next TPM reset, so power\n");
    printf("cycle the TPM (or restart the simulator) and re-run to confirm.\n");
}

/* Read the TPM's own bank list. That list, not a fixed table of algorithms,
 * is what the TPM implements, and its bitmaps are what -restore replays. */
static int read_banks(TPML_PCR_SELECTION* banks)
{
    int rc;
    GetCapability_In in;
    GetCapability_Out out;

    XMEMSET(&in, 0, sizeof(in));
    XMEMSET(&out, 0, sizeof(out));
    in.capability = TPM_CAP_PCRS;
    in.property = 0;
    in.propertyCount = HASH_COUNT;
    rc = TPM2_GetCapability(&in, &out);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_GetCapability(TPM_CAP_PCRS) failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        return rc;
    }
    if (out.capabilityData.capability != TPM_CAP_PCRS) {
        return TPM_RC_VALUE;
    }
    if (out.moreData == YES) {
        printf("The TPM reports more PCR banks than this build can hold"
            " (HASH_COUNT %d)\n", (int)HASH_COUNT);
        return TPM_RC_SIZE;
    }
    XMEMCPY(banks, &out.capabilityData.data.assignedPCR, sizeof(*banks));
    return TPM_RC_SUCCESS;
}

/* Print every bank the TPM reports, with the PCRs selected in each. */
static void print_banks(TPML_PCR_SELECTION* banks)
{
    const char* name;
    word32 i;
    int j, any;

    printf("PCR banks:\n");
    printf("  %-10s %-10s %s\n", "Bank", "Allocated", "pcrSelect");
    for (i = 0; i < banks->count; i++) {
        any = 0;
        for (j = 0; j < (int)banks->pcrSelections[i].sizeofSelect; j++) {
            if (banks->pcrSelections[i].pcrSelect[j] != 0) {
                any = 1;
            }
        }
        name = bank_name(banks->pcrSelections[i].hash);
        if (name != NULL) {
            printf("  %-10s %-10s ", name, any ? "yes" : "no");
        }
        else {
            printf("  0x%04X     %-10s ", banks->pcrSelections[i].hash,
                any ? "yes" : "no");
        }
        for (j = 0; j < (int)banks->pcrSelections[i].sizeofSelect; j++) {
            printf("%02X", banks->pcrSelections[i].pcrSelect[j]);
        }
        printf("\n");
    }
}

/* Replay a previously captured selection verbatim, bitmaps included, so a
 * partial bank comes back partial rather than expanded to every PCR. */
static int restore_banks(WOLFTPM2_DEV* dev, TPML_PCR_SELECTION* banks)
{
    int rc;
    PCR_Allocate_In in;
    PCR_Allocate_Out out;

    XMEMSET(&in, 0, sizeof(in));
    XMEMSET(&out, 0, sizeof(out));
    in.authHandle = TPM_RH_PLATFORM;
    XMEMCPY(&in.pcrAllocation, banks, sizeof(in.pcrAllocation));

    rc = wolfTPM2_SetAuthPassword(dev, 0, NULL);
    if (rc != TPM_RC_SUCCESS) {
        return rc;
    }
    dev->session[0].sessionAttributes = 0;
    rc = TPM2_PCR_Allocate(&in, &out);
    if (rc == TPM_RC_SUCCESS && out.allocationSuccess != YES) {
        rc = BUFFER_E;
    }
    return rc;
}

static void print_alloc_out(PCR_Allocate_Out* allocOut)
{
    printf("TPM reported: allocationSuccess %s, maxPCR %u, sizeNeeded %u,"
        " sizeAvailable %u\n",
        (allocOut->allocationSuccess == YES) ? "YES" : "NO",
        (unsigned int)allocOut->maxPCR,
        (unsigned int)allocOut->sizeNeeded,
        (unsigned int)allocOut->sizeAvailable);
}

int TPM2_PCR_Allocate_Test(void* userCtx, int argc, char *argv[])
{
    int i, rc = -1;
    int doRestore = 0;
    int algCount = 0;
    TPM_ALG_ID algs[HASH_COUNT];
    TPML_PCR_SELECTION origBanks;
    PCR_Allocate_Out allocOut;
    WOLFTPM2_DEV dev;

    XMEMSET(algs, 0, sizeof(algs));
    XMEMSET(&origBanks, 0, sizeof(origBanks));
    XMEMSET(&allocOut, 0, sizeof(allocOut));

    for (i = 1; i < argc; i++) {
        if (XSTRCMP(argv[i], "-?") == 0 ||
            XSTRCMP(argv[i], "-h") == 0 ||
            XSTRCMP(argv[i], "--help") == 0) {
            usage();
            return 0;
        }
        else if (XSTRCMP(argv[i], "-restore") == 0) {
            doRestore = 1;
        }
        else if (XSTRCMP(argv[i], "-sha1") == 0 ||
                 XSTRCMP(argv[i], "-sha256") == 0 ||
                 XSTRCMP(argv[i], "-sha384") == 0 ||
                 XSTRCMP(argv[i], "-sha512") == 0) {
            /* Repeatable, so bound the array before writing */
            if (algCount >= (int)(sizeof(algs)/sizeof(algs[0]))) {
                printf("Too many algorithm flags (max %d)\n",
                    (int)(sizeof(algs)/sizeof(algs[0])));
                usage();
                return -1;
            }
            if (XSTRCMP(argv[i], "-sha1") == 0) {
                algs[algCount++] = TPM_ALG_SHA1;
            }
            else if (XSTRCMP(argv[i], "-sha256") == 0) {
                algs[algCount++] = TPM_ALG_SHA256;
            }
            else if (XSTRCMP(argv[i], "-sha384") == 0) {
                algs[algCount++] = TPM_ALG_SHA384;
            }
            else {
                algs[algCount++] = TPM_ALG_SHA512;
            }
        }
        else {
            printf("Incorrect arguments\n");
            usage();
            return -1;
        }
    }

    printf("Demo how to inspect and change the TPM PCR banks\n");
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_Init failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        return rc;
    }
    printf("wolfTPM2_Init: success\n");

    rc = read_banks(&origBanks);
    if (rc != TPM_RC_SUCCESS) {
        goto exit;
    }
    print_banks(&origBanks);
    if (algCount == 0) {
        printf("No algorithm flags given, nothing changed.\n");
        goto exit;
    }

    printf("\nWARNING: replacing the PCR bank allocation. Banks not listed are\n"
           "deallocated, PCR values are zeroed at the next reset, and blobs\n"
           "sealed to PCR values become unsealable.\n\n");

    rc = wolfTPM2_AllocatePCRBanks(&dev, algs, algCount, &allocOut);
    if (rc == TPM_RC_HASH) {
        printf("The TPM does not implement one of the requested banks.\n");
        printf("Nothing was sent to the TPM and the allocation is unchanged.\n");
        goto exit;
    }
    if (WOLFTPM_RC_IS(rc, TPM_RC_PCR)) { /* mask any vendor/layer bits */
        printf("The TPM refused that PCR bank selection (TPM_RC_PCR).\n");
        printf("Parts that keep one bank active reject a multi-bank request"
            " outright - try a single -shaN flag.\n");
        goto exit;
    }
    /* Only meaningful once the TPM answered with parameters */
    if (rc == TPM_RC_SUCCESS || rc == BUFFER_E) {
        print_alloc_out(&allocOut);
    }
    if (rc == BUFFER_E) {
        if (allocOut.sizeNeeded > 0) {
            printf("The TPM does not have room for that bank set (needed %u,"
                " available %u).\n", (unsigned int)allocOut.sizeNeeded,
                (unsigned int)allocOut.sizeAvailable);
            printf("Try a single -shaN flag.\n");
        }
        else {
            /* No sizing reported means the TPM rejected the selection itself,
             * not that it ran out of room */
            printf("The TPM rejected that bank selection and reported no"
                " sizing.\n");
        }
        goto exit;
    }
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_AllocatePCRBanks failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }

    printf("PCR allocation staged. It takes effect at the next TPM reset\n"
           "(Startup(CLEAR) after a _TPM_Init) - power cycle the TPM, or\n"
           "restart the simulator process, then re-run to confirm.\n");

    if (doRestore && origBanks.count > 0) {
        printf("\nRestoring the original selection...\n");
        rc = restore_banks(&dev, &origBanks);
        if (rc != TPM_RC_SUCCESS) {
            printf("Restore failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
            goto exit;
        }
        printf("Original allocation staged.\n");
    }

exit:

    wolfTPM2_Cleanup(&dev);

    return rc;
}

/******************************************************************************/
/* --- END TPM2.0 PCR Allocate example tool -- */
/******************************************************************************/
#endif /* !WOLFTPM2_NO_WRAPPER */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = -1;

#ifndef WOLFTPM2_NO_WRAPPER
    rc = TPM2_PCR_Allocate_Test(NULL, argc, argv);
    /* TPM rc is wider than an exit status (0x100 truncates to 0) */
    if (rc != 0) {
        rc = 1;
    }
#else
    printf("Wrapper code not compiled in\n");
    (void)argc;
    (void)argv;
#endif /* !WOLFTPM2_NO_WRAPPER */

    return rc;
}
#endif
