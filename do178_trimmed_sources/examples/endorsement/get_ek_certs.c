/* get_ek_certs.c
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

/* This example will list each of the Endorsement Key certificates and attempt
 * to validate based on trusted peers in trusted_certs.h.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2_wrap.h>

#include <stdio.h>

#ifndef WOLFTPM2_NO_WRAPPER

#include <examples/endorsement/endorsement.h>
#include <hal/tpm_io.h>

/******************************************************************************/
/* --- BEGIN TPM2.0 Endorsement certificate tool  -- */
/******************************************************************************/

#ifndef MAX_CERT_SZ
#define MAX_CERT_SZ 2048
#endif

static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/endorsement/get_ek_certs\n");
}

static void dump_hex_bytes(const byte* buf, word32 sz)
{
    word32 i;
    /* Print as : separated hex bytes - max 15 bytes per line */
    printf("\t");
    for (i=0; i<sz; i++) {
        printf("%02x", buf[i]);
        if (i+1 < sz) {
            printf(":");
            if (i>0 && ((i+1)%16)==0) printf("\n\t");
        }
    }
    printf("\n");
}

/* Display EK public information */
static void show_ek_public(const TPM2B_PUBLIC* pub)
{
    printf("EK %s, Hash: %s, objAttr: 0x%X\n",
        TPM2_GetAlgName(pub->publicArea.type),
        TPM2_GetAlgName(pub->publicArea.nameAlg),
        (unsigned int)pub->publicArea.objectAttributes);

    /* parameters and unique field depend on algType */
    if (pub->publicArea.type == TPM_ALG_RSA) {
        printf("\tKeyBits: %d, exponent: 0x%X, unique size %d\n",
            pub->publicArea.parameters.rsaDetail.keyBits,
            (unsigned int)pub->publicArea.parameters.rsaDetail.exponent,
            pub->publicArea.unique.rsa.size);
        dump_hex_bytes(pub->publicArea.unique.rsa.buffer,
                       pub->publicArea.unique.rsa.size);
    }
    else if (pub->publicArea.type == TPM_ALG_ECC) {
        const char* curveName = "NULL";
        printf("\tCurveID %s (0x%x), size %d, unique X/Y size %d/%d\n",
            curveName, pub->publicArea.parameters.eccDetail.curveID,
            TPM2_GetCurveSize(pub->publicArea.parameters.eccDetail.curveID),
            pub->publicArea.unique.ecc.x.size,
            pub->publicArea.unique.ecc.y.size);
        dump_hex_bytes(pub->publicArea.unique.ecc.x.buffer,
                       pub->publicArea.unique.ecc.x.size);
        dump_hex_bytes(pub->publicArea.unique.ecc.y.buffer,
                       pub->publicArea.unique.ecc.y.size);
    }
}

int TPM2_EndorsementCert_Example(void* userCtx, int argc, char *argv[])
{
    int rc = -1, nvIdx;
    WOLFTPM2_DEV dev;
    TPML_HANDLE handles;
    TPMS_NV_PUBLIC nvPublic;
    WOLFTPM2_NV nv;
    WOLFTPM2_KEY endorse;
    WOLFTPM2_KEY certPubKey;
    uint8_t certBuf[MAX_CERT_SZ];
    uint32_t certSz;
    TPMT_PUBLIC publicTemplate;
    word32 nvIndex;
    XMEMSET(&endorse, 0, sizeof(endorse));
    XMEMSET(&handles, 0, sizeof(handles));
    XMEMSET(&nvPublic, 0, sizeof(nvPublic));
    XMEMSET(&certPubKey, 0, sizeof(certPubKey));

    if (argc >= 2) {
        if (XSTRCMP(argv[1], "-?") == 0 ||
            XSTRCMP(argv[1], "-h") == 0 ||
            XSTRCMP(argv[1], "--help") == 0) {
            usage();
            return 0;
        }
    }

    printf("Get Endorsement Certificate(s)\n");

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_Init failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }

    /* List TCG stored handles */
    rc = wolfTPM2_GetHandles(TPM_20_TCG_NV_SPACE, &handles);
    if (rc < 0) {
        goto exit;
    }
    rc = 0;
    printf("Found %d TCG handles\n", handles.count);

    for (nvIdx=0; nvIdx<(int)handles.count; nvIdx++) {
        nvIndex = handles.handle[nvIdx];

        XMEMSET(&nv, 0, sizeof(nv)); /* Must reset the NV for each read */
        XMEMSET(certBuf, 0, sizeof(certBuf));

        printf("TCG Handle 0x%x\n", nvIndex);

        /* Get Endorsement Public Key template using NV index */
        rc = wolfTPM2_GetKeyTemplate_EKIndex(nvIndex, &publicTemplate);
        if (rc != 0) {
            printf("EK Index 0x%08x not valid\n", nvIndex);
            continue;
        }

        /* Read Public portion of NV to get actual size */
        rc = wolfTPM2_NVReadPublic(&dev, nvIndex, &nvPublic);
        if (rc != 0) {
            printf("Failed to read public for NV Index 0x%08x\n", nvIndex);
        }

        /* Read data */
        if (rc == 0) {
            certSz = (uint32_t)sizeof(certBuf);
            if (certSz > nvPublic.dataSize) {
                certSz = nvPublic.dataSize;
            }
            rc = wolfTPM2_NVReadAuth(&dev, &nv, nvIndex, certBuf, &certSz, 0);
            if (rc == 0) {
            }
        }

        /* Create Endorsement Key */
        if (rc == 0) {
            /* Create Endorsement Key using EK auth policy */
            printf("Creating Endorsement Key\n");
            rc = wolfTPM2_CreatePrimaryKey(&dev, &endorse, TPM_RH_ENDORSEMENT,
                &publicTemplate, NULL, 0);
            if (rc != 0) goto exit;
            printf("Endorsement key loaded at handle 0x%08x\n",
                endorse.handle.hndl);

            /* Display EK public information */
            show_ek_public(&endorse.pub);
        }
        wolfTPM2_UnloadHandle(&dev, &endorse.handle);
        XMEMSET(&endorse, 0, sizeof(endorse));
    }

exit:

    if (rc != 0) {
        printf("Error getting EK certificates! %s (%d)\n",
            TPM2_GetRCString(rc), rc);
    }

    wolfTPM2_UnloadHandle(&dev, &endorse.handle);
    wolfTPM2_Cleanup(&dev);

    return rc;
}

/******************************************************************************/
/* --- END TPM2.0 Endorsement certificate tool  -- */
/******************************************************************************/
#endif /* !WOLFTPM2_NO_WRAPPER */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = -1;

#ifndef WOLFTPM2_NO_WRAPPER
    rc = TPM2_EndorsementCert_Example(NULL, argc, argv);
#else
    printf("Wrapper code not compiled in\n");
    (void)argc;
    (void)argv;
#endif /* !WOLFTPM2_NO_WRAPPER */

    return rc;
}
#endif
