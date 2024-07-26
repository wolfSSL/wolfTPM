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

/* This example shows how to decrypt a credential for Remote Attestation
 * and extract the secret for challenge response to an attestation server
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2_wrap.h>

#include <stdio.h>

#ifndef WOLFTPM2_NO_WRAPPER

#include <examples/endorsement/endorsement.h>
#include <hal/tpm_io.h>

#ifndef WOLFTPM2_NO_WOLFCRYPT
    #include <wolfssl/wolfcrypt/asn.h>
    #include "trusted_certs.h"
#endif

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
    #ifndef WOLFTPM2_NO_WOLFCRYPT
        curveName = wc_ecc_get_name(
            TPM2_GetWolfCurve(pub->publicArea.parameters.eccDetail.curveID));
    #endif
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

#ifndef WOLFTPM2_NO_WOLFCRYPT
static int compare_ek_public(const TPM2B_PUBLIC* ekpub,
    const TPM2B_PUBLIC* certpub)
{
    int rc = -1;
    if (ekpub->publicArea.type == TPM_ALG_RSA) {
        if (ekpub->publicArea.unique.rsa.size ==
                certpub->publicArea.unique.rsa.size) {
            rc = XMEMCMP(ekpub->publicArea.unique.rsa.buffer,
                         certpub->publicArea.unique.rsa.buffer,
                         ekpub->publicArea.unique.rsa.size);
        }
    }
    else if (ekpub->publicArea.type == TPM_ALG_ECC) {
        if (ekpub->publicArea.parameters.eccDetail.curveID ==
                certpub->publicArea.parameters.eccDetail.curveID &&
            ekpub->publicArea.unique.ecc.x.size ==
                certpub->publicArea.unique.ecc.x.size &&
            ekpub->publicArea.unique.ecc.y.size ==
                certpub->publicArea.unique.ecc.y.size) {
            rc = XMEMCMP(ekpub->publicArea.unique.ecc.x.buffer,
                         certpub->publicArea.unique.ecc.x.buffer,
                         ekpub->publicArea.unique.ecc.x.size);
            if (rc == 0) {
                rc = XMEMCMP(ekpub->publicArea.unique.ecc.y.buffer,
                            certpub->publicArea.unique.ecc.y.buffer,
                            ekpub->publicArea.unique.ecc.y.size);
            }
        }
    }
    return rc;
}
#endif

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
#ifndef WOLFTPM2_NO_WOLFCRYPT
    int i;
    #ifndef WOLFCRYPT_ONLY
    WOLFSSL_CERT_MANAGER* cm = NULL;
    #endif
    DecodedCert cert;
    #ifdef WOLFSSL_DER_TO_PEM
    char*  pem = NULL;
    word32 pemSz = 0;
    #endif
#endif

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

#if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(WOLFCRYPT_ONLY)
    /* load trusted certificates to cert manager */
    certSz = 0;
    cm = wolfSSL_CertManagerNew();
    if (cm != NULL) {
        for (i=0; i<(int)(sizeof(trusted_certs)/sizeof(const char*)); i++) {
            const char* pemCert = trusted_certs[i];
            rc = wolfSSL_CertManagerLoadCABuffer(cm,
                (const unsigned char*)pemCert, XSTRLEN(pemCert),
                WOLFSSL_FILETYPE_PEM);
            if (rc == WOLFSSL_SUCCESS) {
                certSz++;
                rc = 0;
            }
            else {
                printf("Warning: Failed to load trusted PEM at index %d\n", i);
                /* not fatal, continue loading trusted certs */
            }
        }
        printf("Loaded %d trusted certificates\n", certSz);
    }
    else {
        printf("Warning: Failed to setup a trusted certificate manager\n");
    }
#endif

    for (nvIdx=0; nvIdx<(int)handles.count; nvIdx++) {
        nvIndex = handles.handle[nvIdx];

        printf("TCG Handle 0x%x\n", nvIndex);

        /* Read Public portion of NV */
        rc = wolfTPM2_NVReadPublic(&dev, nvIndex, &nvPublic);
        if (rc != 0) {
            printf("Failed to read public for NV Index 0x%08x\n", nvIndex);
            continue;
        }

        /* Read data */
        XMEMSET(&nv, 0, sizeof(nv)); /* Must reset the NV for each read */
        XMEMSET(certBuf, 0, sizeof(certBuf));
        certSz = (uint32_t)sizeof(certBuf);
        if (certSz > nvPublic.dataSize) {
            certSz = nvPublic.dataSize;
        }
        rc = wolfTPM2_NVReadAuth(&dev, &nv, nvIndex, certBuf, &certSz, 0);
        if (rc == 0) {
        #ifdef DEBUG_WOLFTPM
            printf("EK Data: %d\n", certSz);
            TPM2_PrintBin(certBuf, certSz);
        #endif
        }

        /* Create Endorsement Key */
        if (rc == 0) {
            /* Get Endorsement Public Key template using NV index */
            rc = wolfTPM2_GetKeyTemplate_EKIndex(nvIndex, &publicTemplate);
            if (rc != 0) {
                printf("EK Index 0x%08x not valid\n", nvIndex);
                rc = BAD_FUNC_ARG;
            }
        }
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

    #ifndef WOLFTPM2_NO_WOLFCRYPT
        if (rc == 0) {
            /* Attempt to parse certificate */
            printf("Parsing certificate (%d bytes)\n", certSz);
            wc_InitDecodedCert(&cert, certBuf, certSz, NULL);
            rc = wc_ParseCert(&cert, CERT_TYPE, NO_VERIFY, NULL);
            if (rc == 0) {
                printf("\tSuccessfully parsed\n");

            #if defined(WOLFSSL_ASN_CA_ISSUER) || \
                defined(OPENSSL_ALL) || defined(WOLFSSL_QT)
                /* print the "Authority Information Access" for accessing
                 * CA Issuers */
                if (cert.extAuthInfoCaIssuerSz > 0) {
                    printf("CA Issuers: %.*s\n",
                        cert.extAuthInfoCaIssuerSz, cert.extAuthInfoCaIssuer);
                }
            #endif

                if (cert.serialSz > 0) {
                    if (cert.serialSz == 4) {
                        /* serial number is 32-bits */
                        word32 serial;
                        XMEMCPY(&serial, cert.serial, cert.serialSz);
                    #ifndef BIG_ENDIAN_ORDER
                        serial = ByteReverseWord32(serial);
                    #endif
                        printf("Serial Number: %08u (0x%08x)\n",
                            serial, serial);
                    }
                    else {
                        /* Print serial as : separated hex bytes */
                        printf("Serial Number (%d bytes)\n", cert.serialSz);
                        dump_hex_bytes(cert.serial, cert.serialSz);
                    }
                }

                /* Import certificate public key */
                rc = wolfTPM2_ImportPublicKeyBuffer(&dev,
                    endorse.pub.publicArea.type, &certPubKey,
                    ENCODING_TYPE_ASN1,
                    (const char*)cert.publicKey, cert.pubKeySize,
                    endorse.pub.publicArea.objectAttributes
                );
                if (rc == 0) {
                    /* compare public unique areas */
                    if (compare_ek_public(&endorse.pub, &certPubKey.pub) == 0) {
                        printf("Cert public key and EK public match\n");
                    }
                    else {
                        printf("Error: Cert public key != EK public!\n");
                        show_ek_public(&certPubKey.pub);
                    }
                }
                else {
                    printf("Error importing certificates public key! %d\n", rc);
                }
            }
            else {
                printf("Error parsing certificate 0x%x: %s\n",
                    rc, TPM2_GetRCString(rc));
            }
            wc_FreeDecodedCert(&cert);

        #ifndef WOLFCRYPT_ONLY
            if (rc == 0) {
                /* Validate EK certificate against trusted certificates */
                rc = wolfSSL_CertManagerVerifyBuffer(cm, certBuf, certSz,
                    WOLFSSL_FILETYPE_ASN1);
                printf("EK Certificate is %s\n",
                    (rc == WOLFSSL_SUCCESS) ? "VALID" : "INVALID");
            }
        #endif

        #ifdef WOLFSSL_DER_TO_PEM
            /* Convert certificate to PEM and display */
            rc = wc_DerToPemEx(certBuf, certSz, NULL, 0, NULL, CERT_TYPE);
            if (rc > 0) {
                pemSz = (word32)rc;
                rc = 0;

                pemSz++; /* for '\0'*/
                pem = (char*)XMALLOC(pemSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                if (pem == NULL) {
                    rc = MEMORY_E;
                }
            }
            if (rc == 0) {
                XMEMSET(pem, 0, pemSz);
                rc = wc_DerToPem(certBuf, certSz, (byte*)pem, pemSz, CERT_TYPE);
                if (rc > 0) {
                    rc = 0;
                }
            }
            if (rc == 0) {
                printf("Endorsement Cert PEM\n");
                puts(pem);
            }
        #endif /* WOLFSSL_DER_TO_PEM */
        }
    #endif /* !WOLFTPM2_NO_WOLFCRYPT */

        wolfTPM2_UnloadHandle(&dev, &endorse.handle);
        XMEMSET(&endorse, 0, sizeof(endorse));
    }

exit:

#ifndef WOLFTPM2_NO_WOLFCRYPT
    #ifdef WOLFSSL_DER_TO_PEM
    XFREE(pem, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    #endif
    #ifndef WOLFCRYPT_ONLY
    wolfSSL_CertManagerFree(cm);
    #endif
#endif
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
