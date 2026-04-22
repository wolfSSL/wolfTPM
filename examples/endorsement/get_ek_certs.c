/* get_ek_certs.c
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

#ifndef WOLFTPM2_NO_WOLFCRYPT
    #include <wolfssl/wolfcrypt/asn.h>
    #if !defined(WOLFCRYPT_ONLY)
    #include "trusted_certs.h"
    #endif
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

#ifdef DEBUG_WOLFTPM
/* Decode and display NV attributes - only in debug mode */
static void show_nv_attributes(TPMA_NV attr)
{
    printf("  Attributes:");
    if (attr & TPMA_NV_PPWRITE) printf(" PPWRITE");
    if (attr & TPMA_NV_OWNERWRITE) printf(" OWNERWRITE");
    if (attr & TPMA_NV_AUTHWRITE) printf(" AUTHWRITE");
    if (attr & TPMA_NV_POLICYWRITE) printf(" POLICYWRITE");
    if (attr & TPMA_NV_POLICY_DELETE) printf(" POLICY_DELETE");
    if (attr & TPMA_NV_WRITELOCKED) printf(" WRITELOCKED");
    if (attr & TPMA_NV_WRITEALL) printf(" WRITEALL");
    if (attr & TPMA_NV_WRITEDEFINE) printf(" WRITEDEFINE");
    if (attr & TPMA_NV_WRITE_STCLEAR) printf(" WRITE_STCLEAR");
    if (attr & TPMA_NV_GLOBALLOCK) printf(" GLOBALLOCK");
    if (attr & TPMA_NV_PPREAD) printf(" PPREAD");
    if (attr & TPMA_NV_OWNERREAD) printf(" OWNERREAD");
    if (attr & TPMA_NV_AUTHREAD) printf(" AUTHREAD");
    if (attr & TPMA_NV_POLICYREAD) printf(" POLICYREAD");
    if (attr & TPMA_NV_NO_DA) printf(" NO_DA");
    if (attr & TPMA_NV_ORDERLY) printf(" ORDERLY");
    if (attr & TPMA_NV_CLEAR_STCLEAR) printf(" CLEAR_STCLEAR");
    if (attr & TPMA_NV_READLOCKED) printf(" READLOCKED");
    if (attr & TPMA_NV_WRITTEN) printf(" WRITTEN");
    if (attr & TPMA_NV_PLATFORMCREATE) printf(" PLATFORMCREATE");
    if (attr & TPMA_NV_READ_STCLEAR) printf(" READ_STCLEAR");
    printf("\n");
}
#endif

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
        const char* curveName;
    #if !defined(WOLFTPM2_NO_WOLFCRYPT) && defined(HAVE_ECC)
        curveName = wc_ecc_get_name(
            TPM2_GetWolfCurve(pub->publicArea.parameters.eccDetail.curveID));
    #else
        curveName = "NULL";
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

#if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_ASN)
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
#if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_ASN)
    #ifndef WOLFCRYPT_ONLY
    int i;
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

#if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(WOLFCRYPT_ONLY) && \
    !defined(NO_ASN)
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
            }
            else {
                printf("Warning: Failed to load trusted PEM at index %d. "
                    "Error %s (rc %d)\n", i, TPM2_GetRCString(rc), rc);
                /* not fatal, continue loading trusted certs */
            }
            rc = 0; /* reset return code */
        }
        printf("Loaded %d trusted certificates\n", certSz);
    }
    else {
        printf("Warning: Failed to setup a trusted certificate manager\n");
    }
#endif

    for (nvIdx=0; nvIdx<(int)handles.count; nvIdx++) {
        nvIndex = handles.handle[nvIdx];

        XMEMSET(&nv, 0, sizeof(nv)); /* Reset NV handle for each index */
        XMEMSET(certBuf, 0, sizeof(certBuf));

        printf("TCG Handle 0x%x\n", nvIndex);

        /* Get Endorsement Public Key template using NV index */
        rc = wolfTPM2_GetKeyTemplate_EKIndex(nvIndex, &publicTemplate);
        if (rc != 0) {
            const char* indexType = "Unknown";
            word32 offset;
            
            /* Identify the type of NV index based on offset */
            if (nvIndex < TPM_20_TCG_NV_SPACE) {
                indexType = "Non-TCG (below TCG NV space)";
            }
            else {
                offset = nvIndex - TPM_20_TCG_NV_SPACE;
                
                if (offset >= 0x2 && offset <= 0xC) {
                    indexType = "EK Low Range";
                    if (offset == 0x2) indexType = "EK Low Range (RSA 2048 Cert)";
                    else if (offset == 0x3) indexType = "EK Low Range (RSA 2048 Nonce)";
                    else if (offset == 0x4) indexType = "EK Low Range (RSA 2048 Template)";
                    else if (offset == 0xA) indexType = "EK Low Range (ECC P256 Cert)";
                    else if (offset == 0xB) indexType = "EK Low Range (ECC P256 Nonce)";
                    else if (offset == 0xC) indexType = "EK Low Range (ECC P256 Template)";
                }
                else if (offset >= 0x12 && offset < 0x100) {
                    if (offset == 0x12) indexType = "EK High Range (RSA 2048 Cert)";
                    else if (offset == 0x14) indexType = "EK High Range (ECC P256 Cert)";
                    else if (offset == 0x16) indexType = "EK High Range (ECC P384 Cert)";
                    else if (offset == 0x18) indexType = "EK High Range (ECC P521 Cert)";
                    else if (offset == 0x1A) indexType = "EK High Range (ECC SM2 Cert)";
                    else if (offset == 0x1C) indexType = "EK High Range (RSA 3072 Cert)";
                    else if (offset == 0x1E) indexType = "EK High Range (RSA 4096 Cert)";
                    else if ((offset & 1) == 0) indexType = "EK High Range (Cert, even index)";
                    else indexType = "EK High Range (Template, odd index)";
                }
                else if (offset >= 0x100 && offset < 0x200) {
                    indexType = "EK Certificate Chain";
                }
                else if (offset == (TPM2_NV_EK_POLICY_SHA256 - TPM_20_TCG_NV_SPACE)) {
                    indexType = "EK Policy Index (SHA256)";
                }
                else if (offset == (TPM2_NV_EK_POLICY_SHA384 - TPM_20_TCG_NV_SPACE)) {
                    indexType = "EK Policy Index (SHA384)";
                }
                else if (offset == (TPM2_NV_EK_POLICY_SHA512 - TPM_20_TCG_NV_SPACE)) {
                    indexType = "EK Policy Index (SHA512)";
                }
                else if (offset == (TPM2_NV_EK_POLICY_SM3_256 - TPM_20_TCG_NV_SPACE)) {
                    indexType = "EK Policy Index (SM3_256)";
                }
                else if (nvIndex > TPM_20_TCG_NV_SPACE + 0x7FFF) {
                    indexType = "Vendor-specific (beyond TCG range)";
                }
            }
            
            printf("NV Index 0x%08x: %s (not a recognized EK certificate index)\n", 
                nvIndex, indexType);

            /* Try to read the NV public info to show what it contains */
            rc = wolfTPM2_NVReadPublic(&dev, nvIndex, &nvPublic);
            if (rc == 0) {
                const char* hashName = TPM2_GetAlgName(nvPublic.nameAlg);
                int showData = 0;
            #ifdef DEBUG_WOLFTPM
                int isPolicyDigest = 0;
            #endif
                
            #ifdef DEBUG_WOLFTPM
                printf("  NV Size: %u bytes, Attributes: 0x%08x, Name Alg: %s\n",
                    nvPublic.dataSize, (unsigned int)nvPublic.attributes, hashName);
                show_nv_attributes(nvPublic.attributes);
                showData = 1; /* Always show data in debug mode */
            #else
                printf("  NV Size: %u bytes, Name Alg: %s\n",
                    nvPublic.dataSize, hashName);
            #endif

                /* Check if this looks like a policy digest based on size and hash */
                if ((nvPublic.dataSize == 32 && nvPublic.nameAlg == TPM_ALG_SHA256) ||
                    (nvPublic.dataSize == 48 && nvPublic.nameAlg == TPM_ALG_SHA384) ||
                    (nvPublic.dataSize == 64 && nvPublic.nameAlg == TPM_ALG_SHA512) ||
                    (nvPublic.dataSize == 32 && nvPublic.nameAlg == TPM_ALG_SM3_256)) {
                    printf("  Type: Policy digest (%s hash)\n", hashName);
                #ifdef DEBUG_WOLFTPM
                    isPolicyDigest = 1;
                #endif
                    showData = 1; /* Always show policy digests */
                }
                else if (nvPublic.dataSize > 100) {
                    printf("  Type: Certificate or template\n");
                }
                else if (nvPublic.dataSize > 32) {
                    printf("  Type: Data (%u bytes)\n", nvPublic.dataSize);
                }
                else {
                    printf("  Type: Small data (%u bytes)\n", nvPublic.dataSize);
                #ifdef DEBUG_WOLFTPM
                    showData = 1;
                #endif
                }

                /* Read and display data if appropriate */
                if (showData && nvPublic.dataSize > 0) {
                    certSz = nvPublic.dataSize;
                    if (certSz > sizeof(certBuf)) {
                        certSz = sizeof(certBuf);
                    }
                    
                    rc = wolfTPM2_NVReadAuth(&dev, &nv, nvIndex, certBuf, &certSz, 0);
                    if (rc == 0) {
                        printf("  Data (%u bytes):\n", certSz);
                    #ifdef DEBUG_WOLFTPM
                        /* In debug mode, show partial data for large buffers */
                        if (certSz > 32 && !isPolicyDigest) {
                            printf("  First 32 bytes:\n");
                            dump_hex_bytes(certBuf, 32);
                        }
                        else
                    #endif
                        {
                            dump_hex_bytes(certBuf, certSz);
                        }
                    }
                }
            }

            rc = 0; /* Reset error code to continue processing */
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
            #ifdef DEBUG_WOLFTPM
                printf("EK Data: %d\n", certSz);
                TPM2_PrintBin(certBuf, certSz);
            #endif
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

    #if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_ASN)
        if (rc == 0) {
            /* Attempt to parse certificate */
            printf("Parsing certificate (%d bytes)\n", certSz);
            #ifdef WOLFSSL_TEST_CERT
            InitDecodedCert(&cert, certBuf, certSz, NULL);
            rc = ParseCert(&cert, CERT_TYPE, NO_VERIFY, NULL);
            #else
            wc_InitDecodedCert(&cert, certBuf, certSz, NULL);
            rc = wc_ParseCert(&cert, CERT_TYPE, NO_VERIFY, NULL);
            #endif
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
                    printf("Error importing certificates public key! %s (%d)\n",
                        TPM2_GetRCString(rc), rc);
                    rc = 0; /* ignore error */
                }
            }
            else {
                printf("Error parsing certificate! %s (%d)\n",
                    TPM2_GetRCString(rc), rc);
            }
        #ifdef WOLFSSL_TEST_CERT
            FreeDecodedCert(&cert);
        #else
            wc_FreeDecodedCert(&cert);
        #endif

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
            rc = wc_DerToPem(certBuf, certSz, NULL, 0, CERT_TYPE);
            if (rc > 0) { /* returns actual PEM size */
                pemSz = (word32)rc;
                pemSz++; /* for '\0'*/
                rc = 0;
            }
            if (rc == 0) {
                pem = (char*)XMALLOC(pemSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                if (pem == NULL) {
                    rc = MEMORY_E;
                }
            }
            if (rc == 0) {
                XMEMSET(pem, 0, pemSz);
                rc = wc_DerToPem(certBuf, certSz, (byte*)pem, pemSz, CERT_TYPE);
                if (rc > 0) { /* returns actual PEM size */
                    pemSz = (word32)rc;
                    rc = 0;
                }
            }
            if (rc == 0) {
                printf("Endorsement Cert PEM\n");
                puts(pem);
            }

            XFREE(pem, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            pem = NULL;
        #endif /* WOLFSSL_DER_TO_PEM */
        }
    #endif /* !WOLFTPM2_NO_WOLFCRYPT && !NO_ASN */

        wolfTPM2_UnloadHandle(&dev, &endorse.handle);
        XMEMSET(&endorse, 0, sizeof(endorse));
    }

exit:

    if (rc != 0) {
        printf("Error getting EK certificates! %s (%d)\n",
            TPM2_GetRCString(rc), rc);
    }

#if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_ASN)
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
